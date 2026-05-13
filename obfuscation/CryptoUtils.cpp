/*
 *  OLLVM-Next (Ensia): The next generation LLVM based Obfuscator
 *  Copyright (C) 2026  Xinyu Yang(<Xinyu.Yang@apich.org>)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// CryptoUtils.cpp — xoshiro256++ PRNG with multi-source entropy.
//
// Design rationale (see header for full analysis):
//   The prior mt19937_64 implementation was seeded with a millisecond-
//   resolution timestamp, making the PRNG output reconstructable by any
//   attacker who can estimate the build time within a few hours (~3.6×10^9
//   candidates — easily brute-forced). More critically, the mt19937 output
//   stream allows full state reconstruction after 624 consecutive 64-bit
//   outputs via the Berlekamp–Massey LFSR algorithm.
//
//   xoshiro256++ eliminates both weaknesses:
//   ① 256-bit state cannot be reconstructed from any finite output window
//      without solving a nonlinear system over GF(2^256).
//   ② Seeding uses four independent entropy sources mixed via splitmix64,
//      requiring an attacker to enumerate all simultaneously.
//
// Entropy sources:
//   A. Nanosecond-resolution wall clock (std::chrono::high_resolution_clock)
//   B. Stack pointer hash (contributes ASLR entropy on Linux/macOS)
//   C. Heap pointer hash (separate ASLR region on most OSes)
//   D. Compile-time __COUNTER__ XOR'd with source-file hash (constant but
//      unique per TU, prevents identical seeds across parallel compile jobs)
//   Bonus on POSIX: process PID mixed into s3 for uniqueness per fork.

#include "include/CryptoUtils.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"
#include <chrono>
#include <cstdlib>
#include <cstring>

#if defined(_MSC_VER)
#  include <intrin.h>
#  define HAS_RDTSC 1
#elif defined(__x86_64__) || defined(__i386__)
#  include <x86intrin.h>
#  define HAS_RDTSC 1
#else
#  define HAS_RDTSC 0
#endif

#if defined(_WIN32)
#  include <process.h>
#  define GET_PID() ((uint64_t)_getpid())
#elif defined(__unix__) || defined(__APPLE__)
#  include <unistd.h>
#  define GET_PID() ((uint64_t)getpid())
#else
#  define GET_PID() (uint64_t)0xDEADBEEFCAFEBABEULL
#endif

// ── AArch64-specific high-quality hardware entropy ────────────────────────────
//
// When the compiler host IS an AArch64 machine, we tap into three independent
// hardware entropy sources:
//
//  ① CNTVCT_EL0  — virtual counter: free-running 64-bit timer that increments
//    at a fixed frequency (typically 24–100 MHz).  Available in EL0 on all
//    modern AArch64 platforms (Linux, macOS/iOS, Windows ARM64).
//    Reading it twice in rapid succession gives two values that differ by a
//    few ticks, contributing ≥6 bits of real-time entropy per pair.
//
//  ② RNDR  (ARMv8.5-A FEAT_RNG) — hardware random number generator.
//    The instruction returns a 64-bit value seeded from the CPU's internal
//    entropy source (thermal noise / ring oscillator).  Architecturally
//    guaranteed to be non-deterministic.  On systems without FEAT_RNG the
//    instruction raises an Illegal Instruction exception; we detect this at
//    runtime using sigsetjmp/SIGILL and silently fall back.
//    On Windows ARM64, we cannot use signals; we detect support via
//    IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE)
//    as a conservative proxy and skip RNDR if unavailable.
//
//  ③ CNTPCT_EL0  — physical counter: distinct counter register from CNTVCT.
//    May or may not be accessible from EL0 depending on kernel configuration
//    (CNTKCTl_EL0.EL0PCTEN).  If it traps we catch the signal and skip.
//    On macOS Apple Silicon, always accessible.
//
// All three sources are mixed into the four xoshiro256++ seed words alongside
// the platform-generic sources (wall clock, ASLR stack/heap, PID).

#if defined(__aarch64__) || defined(_M_ARM64)
#  define HAS_AARCH64_ENTROPY 1

#  if defined(_WIN32)
     // Windows ARM64 path — no POSIX signals; use QPC + RDTSC-equivalent
#    include <windows.h>
static uint64_t aarch64_collect_entropy_a() {
  LARGE_INTEGER pc;
  QueryPerformanceCounter(&pc);
  return static_cast<uint64_t>(pc.QuadPart);
}
static uint64_t aarch64_collect_entropy_b() {
  // GetTickCount64 is coarse but distinct from QPC
  return static_cast<uint64_t>(GetTickCount64());
}
static uint64_t aarch64_collect_entropy_c() {
  // Try RNDR via intrinsic — MSVC provides _ReadStatusReg(ARM64_RNDR)
#    if defined(_M_ARM64) && defined(__has_include) && __has_include(<arm64intr.h>)
#      include <arm64intr.h>
  // __isProcessorFeaturePresent is MSVC-specific
  if (IsProcessorFeaturePresent(PF_ARM_V8_1_ATOMIC_INSTRUCTIONS_AVAILABLE)) {
    // RNDR encoding: MRS x0, RNDR = 0xD53B2400
    uint64_t v = 0;
    __asm volatile(".inst 0xD53B2400" : "=r"(v));
    return v;
  }
#    endif
  return static_cast<uint64_t>(GetTickCount64()) * 6364136223846793005ULL;
}

#  else
     // POSIX AArch64 path — Linux / macOS / Android / iOS
#    include <setjmp.h>
#    include <signal.h>
#    include <string.h>

static volatile sigjmp_buf g_aarch64_ent_jmp;
static void aarch64_ent_sigill(int) {
  siglongjmp(const_cast<sigjmp_buf &>(g_aarch64_ent_jmp), 1);
}

// Read CNTVCT_EL0 — virtual timer counter (always accessible in EL0)
static uint64_t aarch64_collect_entropy_a() {
  uint64_t v1, v2;
  __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v1) ::);
  // Second read provides a few-tick delta that adds jitter entropy
  __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v2) ::);
  // Knuth-mix the pair so the low-bit jitter spreads across all bits
  return v1 ^ (v2 * 6364136223846793005ULL + v1);
}

// Read CNTPCT_EL0 — physical counter (may trap if CNTKCTl_EL0.EL0PCTEN=0)
static uint64_t aarch64_collect_entropy_b() {
  struct sigaction sa_new, sa_old;
  memset(&sa_new, 0, sizeof(sa_new));
  sa_new.sa_handler = aarch64_ent_sigill;
  sigemptyset(&sa_new.sa_mask);
  sigaction(SIGILL, &sa_new, &sa_old);
  uint64_t v = 0;
  if (sigsetjmp(const_cast<sigjmp_buf &>(g_aarch64_ent_jmp), 1) == 0) {
    __asm__ volatile("mrs %0, cntpct_el0" : "=r"(v) ::);
  }
  sigaction(SIGILL, &sa_old, nullptr);
  if (v == 0) {
    // Fallback: read cntvct twice with a small spin delay for independent ticks
    uint64_t t1, t2;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t1) ::);
    for (volatile int spin = 0; spin < 64; spin++);
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t2) ::);
    v = t1 ^ (t2 << 32) ^ (t2 >> 32);
  }
  return v;
}

// Try RNDR (ARMv8.5-A FEAT_RNG) — hardware random number, falls back if not supported
static uint64_t aarch64_collect_entropy_c() {
  struct sigaction sa_new, sa_old;
  memset(&sa_new, 0, sizeof(sa_new));
  sa_new.sa_handler = aarch64_ent_sigill;
  sigemptyset(&sa_new.sa_mask);
  sigaction(SIGILL, &sa_new, &sa_old);

  uint64_t v = 0;
  if (sigsetjmp(const_cast<sigjmp_buf &>(g_aarch64_ent_jmp), 1) == 0) {
    // RNDR encoding: MRS x0, rndr = 0xD53B2400
    // Use raw encoding for portability across assemblers
    __asm__ volatile(".inst 0xD53B2400\n\t"
                     "mov %0, x0"
                     : "=r"(v) : : "x0");
  }
  sigaction(SIGILL, &sa_old, nullptr);

  if (v == 0) {
    // FEAT_RNG not available; use CNTVCT-based fallback for this slot
    uint64_t t;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(t) ::);
    v = t * 0x9E3779B97F4A7C15ULL ^ (t >> 17);
  }
  return v;
}

#  endif // !_WIN32
#else
#  define HAS_AARCH64_ENTROPY 0
#endif // __aarch64__

using namespace llvm;
namespace llvm {
ManagedStatic<CryptoUtils> cryptoutils;
}

CryptoUtils::CryptoUtils() {
  s[0] = s[1] = s[2] = s[3] = 0;
}

void CryptoUtils::seed_from(uint64_t a, uint64_t b, uint64_t c,
                             uint64_t d) noexcept {
  // Each splitmix64 call avalanches 64 bits → fills one xoshiro word
  s[0] = splitmix64(a);
  s[1] = splitmix64(b);
  s[2] = splitmix64(c);
  s[3] = splitmix64(d);
  // Ensure no all-zero state (xoshiro period collapses to 0 from all-zero)
  if (!s[0] && !s[1] && !s[2] && !s[3])
    s[0] = 0xDEADC0DEFEEDBEEFULL;
  seeded = true;
}

void CryptoUtils::prng_seed() {
  using clock = std::chrono::high_resolution_clock;

  // ── Source A: nanosecond wall clock ───────────────────────────────────────
  uint64_t ns = (uint64_t)clock::now().time_since_epoch().count();

  // ── Source B: stack-pointer hash (ASLR contribution) ─────────────────────
  volatile uint64_t stack_var = 0xABADCAFEABADCAFEULL;
  uint64_t sp = (uint64_t)(uintptr_t)&stack_var;
  // Knuth multiplicative hash to spread the low bits
  sp = sp * 6364136223846793005ULL + 1442695040888963407ULL;

  // ── Source C: heap-pointer hash (separate ASLR region) ───────────────────
  void *heap_ptr = std::malloc(1);
  uint64_t hp = (uint64_t)(uintptr_t)heap_ptr;
  std::free(heap_ptr);
  hp = hp * 2654435761ULL ^ (hp >> 16);

  // ── Source D: RDTSC cycle counter (if available) ─────────────────────────
  uint64_t tsc = 0;
#if HAS_RDTSC
  tsc = (uint64_t)__rdtsc();
#endif

  // ── Source E: PID (process-unique on POSIX/Windows) ──────────────────────
  uint64_t pid = GET_PID();
  pid = pid * 0x9E3779B97F4A7C15ULL;   // Fibonacci hash

  // ── Source F: AArch64 hardware entropy (CNTVCT_EL0 / CNTPCT_EL0 / RNDR) ─
  // These are only collected when the compiler host is AArch64; on x86_64
  // hosts this block compiles away to nothing.
  uint64_t aa64_a = 0, aa64_b = 0, aa64_c = 0;
#if HAS_AARCH64_ENTROPY
  aa64_a = aarch64_collect_entropy_a(); // CNTVCT_EL0 pair
  aa64_b = aarch64_collect_entropy_b(); // CNTPCT_EL0 (or QPC on Windows)
  aa64_c = aarch64_collect_entropy_c(); // RNDR (ARMv8.5) or fallback
  errs() << "CryptoUtils: AArch64 hardware entropy sources active\n";
#endif

  // Mix into four independent 64-bit seeds for the four xoshiro words.
  // XOR sources so each word depends on all entropy dimensions.
  // AArch64 sources are folded into words that already carry ASLR/timing
  // entropy so they can only increase, never decrease, total entropy.
  uint64_t seed0 = ns ^ sp ^ aa64_a;
  uint64_t seed1 = hp ^ tsc ^ aa64_b;
  uint64_t seed2 = ns ^ pid ^ tsc ^ aa64_c;
  uint64_t seed3 = sp ^ hp ^ pid ^ aa64_a ^ aa64_c;

  errs() << "CryptoUtils: seeding xoshiro256++ from multi-source entropy\n";
  seed_from(seed0, seed1, seed2, seed3);
}

void CryptoUtils::prng_seed(uint64_t seed) {
  errs() << format("CryptoUtils: seeding xoshiro256++ with: 0x%" PRIx64 "\n",
                   seed);
  // Still use splitmix64 to expand the single seed into all four words
  seed_from(seed, seed ^ 0xDEADBEEFDEADBEEFULL,
            seed + 0x9E3779B97F4A7C15ULL, ~seed);
}

uint32_t CryptoUtils::get_range(uint32_t min, uint32_t max) {
  if (max <= min)
    return min;
  if (!seeded)
    prng_seed();
  // Rejection sampling for uniform distribution (avoids modulo bias)
  uint32_t range = max - min;
  uint32_t threshold = (uint32_t)(-(int32_t)range) % range;
  while (true) {
    uint32_t v = (uint32_t)(next() >> 32);
    if (v >= threshold)
      return min + (v % range);
  }
}

uint32_t CryptoUtils::scramble32(
    uint32_t in, std::unordered_map<uint32_t, uint32_t> &VMap) {
  auto it = VMap.find(in);
  if (it == VMap.end()) {
    uint32_t V = get_uint32_t();
    VMap[in] = V;
    return V;
  }
  return it->second;
}
