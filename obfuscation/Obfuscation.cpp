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

// Obfuscation.cpp — OLLVM-Next master scheduler.
//
// ── Pass execution order
// ──────────────────────────────────────────────────────
//
//  1. AntiHooking & AntiClassDump (module)   — Windows/Darwin/Linux inline-hook
//  detection,
//                                              kernel fast-fail termination,
//                                              ObjC metadata scrambling
//  2. FunctionWrapper             (module)   — polymorphic proxy generation
//                                              (wraps entry points before FCO
//                                              lowers calls)
//  3. FunctionCallObfuscate       (function) — dlopen/dlsym runtime resolution
//                                              (lowers direct external calls in
//                                              callers & proxies)
//  4. AntiDebugging               (module)   — ptrace/sysctl/timing anti-debug
//  checks & violent exit
//  5. StringEncryption            (module)   — Vernam-GF(2^8) per-byte cipher +
//  volatile zeroization
//  6. ConstantEncryption          (module)   — Phase 1: encrypts programmer
//  literals before CFG transforms
//  7. Per-function (order is deliberate for maximum non-linear coupling):
//     a. Substitution                        — integer/shift instruction
//     substitution b. MBAObfuscation                      — multi-term Mixed
//     Boolean-Arithmetic + hardware barriers c. SplitBasicBlocks — slices
//     across expanded MBA chains + stack confusion d. BogusControlFlow —
//     hardware-predicate opaque edges & block cloning e. ChaosStateMachine —
//     logistic-map quadratic CFF (strongest) f. Flattening — chaos-seeded
//     classic CFF (fallback for CSM-skipped fns) g. VectorObfuscation — SIMD
//     scalar->vector lifting (lifts even CFF dispatch)
//  8. ConstantEncryption          (module)   — Phase 2: encrypts skeleton
//  constants from CSM, CFF, BCF, Vec
//  9. IndirectBranch              (function) — Knuth-hash encrypted branch
//  targets & jump tables
// 10. FeatureElimination          (module)   — strip debug/ident/names,
// scramble privates
//                                              (MUST run last so TOML policy
//                                              name-matching works)
// 11. Cleanup: remove ensia_* marker declarations
// 12. LTO Evasion: optnone + noinline attributes
//
// ── Ordering rationale
// ────────────────────────────────────────────────────────
//  • AntiHook / AntiDump establish runtime integrity baselines & execution
//  tokens. • FunctionWrapper runs BEFORE FunctionCallObfuscate: FW wraps direct
//  external calls
//    in polymorphic proxies; FCO then lowers those calls inside the proxies
//    into dynamic dlopen/dlsym calls, eliminating all static imports.
//  • ConstEnc Phase 1 encrypts developer constants so downstream CFG passes
//  tangle them. • Sub → MBA: MBA sees both original and Substitution-generated
//  ops. • MBA → Split: Split cuts through the dense MBA instruction chains,
//  distributing
//    parts of a single algebraic operation across multiple basic blocks.
//  • Split → BCF: BCF clones the split blocks and injects opaque edges.
//  • BCF → CSM: the chaotic state machine flattens all split & bogus blocks
//  into
//    disjoint dispatch states, forcing an analyst to reverse the entire chaotic
//    transition graph just to reconstruct a single arithmetic operation!
//  • CSM → Flatten: CSM stamps processed functions; Flattening skips them.
//    Inversion ensures every function gets exactly ONE CFF layer, the
//    strongest available: CSM when eligible, classic Flatten as fallback.
//  • Vec last (per-fn): SIMD-lifts even the CFF/CSM dispatch arithmetic.
//  • ConstEnc Phase 2: encrypts skeleton constants introduced by BCF/CSM/CFF.
//  • IndirBranch after ConstEnc: Knuth-hash targets include ConstEnc-injected
//  GVs.

#include "include/Obfuscation.h"
#include "include/ChaosStateMachine.h"
#include "include/MBAObfuscation.h"
#include "include/ObfConfig.h"
#include "include/Utils.h"
#include "include/VectorObfuscation.h"
#include "include/llvm_compat.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"
#include <chrono>
#include <cstdlib>
#include <mutex>

using namespace llvm;

// ── Master enable / disable
// ───────────────────────────────────────────────────

static cl::opt<bool>
    EnableIRObfusaction("ensia", cl::init(false), cl::NotHidden,
                        cl::desc("Enable IR Code Obfuscation."),
                        cl::ZeroOrMore);
static cl::opt<uint64_t> AesSeed("aesSeed", cl::init(0x1337),
                                 cl::desc("PRNG seed for the obfuscator"));

// ── Original pass flags
// ───────────────────────────────────────────────────────

static cl::opt<bool> EnableAntiClassDump("enable-acdobf", cl::init(false),
                                         cl::NotHidden,
                                         cl::desc("Enable AntiClassDump."));
static cl::opt<bool> EnableAntiHooking("enable-antihook", cl::init(false),
                                       cl::NotHidden,
                                       cl::desc("Enable AntiHooking."));
static cl::opt<bool> EnableAntiDebugging("enable-adb", cl::init(false),
                                         cl::NotHidden,
                                         cl::desc("Enable AntiDebugging."));
static cl::opt<bool>
    EnableBogusControlFlow("enable-bcfobf", cl::init(false), cl::NotHidden,
                           cl::desc("Enable BogusControlFlow."));
static cl::opt<bool> EnableFlattening("enable-cffobf", cl::init(false),
                                      cl::NotHidden,
                                      cl::desc("Enable CFF Flattening."));
static cl::opt<bool>
    EnableBasicBlockSplit("enable-splitobf", cl::init(false), cl::NotHidden,
                          cl::desc("Enable BasicBlockSplitting."));
static cl::opt<bool>
    EnableSubstitution("enable-subobf", cl::init(false), cl::NotHidden,
                       cl::desc("Enable Instruction Substitution."));
static cl::opt<bool> EnableAllObfuscation("enable-allobf", cl::init(false),
                                          cl::NotHidden,
                                          cl::desc("Enable All Obfuscation."));
static cl::opt<bool> EnableFunctionCallObfuscate("enable-fco", cl::init(false),
                                                 cl::NotHidden,
                                                 cl::desc("Enable FCO."));
static cl::opt<bool>
    EnableStringEncryption("enable-strcry", cl::init(false), cl::NotHidden,
                           cl::desc("Enable String Encryption."));
static cl::opt<bool>
    EnableConstantEncryption("enable-constenc", cl::init(false), cl::NotHidden,
                             cl::desc("Enable Constant Encryption."));
static cl::opt<bool>
    EnableIndirectBranching("enable-indibran", cl::init(false), cl::NotHidden,
                            cl::desc("Enable Indirect Branching."));
static cl::opt<bool>
    EnableFunctionWrapper("enable-funcwra", cl::init(false), cl::NotHidden,
                          cl::desc("Enable Function Wrapper."));

static cl::opt<bool> EnableChaosStateMachine(
    "enable-csmobf", cl::init(false), cl::NotHidden,
    cl::desc("Enable ChaosStateMachine (logistic-map CFF)."));
static cl::opt<bool> EnableMBAObfuscation(
    "enable-mbaobf", cl::init(false), cl::NotHidden,
    cl::desc("Enable Mixed Boolean-Arithmetic Obfuscation."));
static cl::opt<bool>
    EnableVectorObfuscation("enable-vobf", cl::init(false), cl::NotHidden,
                            cl::desc("Enable SIMD Vector-Space Obfuscation."));

// ── Extreme-mode flag
// ─────────────────────────────────────────────────────────
//
// -enable-maxobf: "maximum obfuscation" — enables every pass simultaneously
// and sets global ObfuscationMaxMode=true.  Each pass checks this flag and
// self-tunes to maximum intensity:
//
//   Pass              Max-mode effect
//   ────────────────  ─────────────────────────────────────────────────────────
//   BCF               prob=100, loop=3, entropy_chain=100%, junk-asm=true
//   Split             num=8 splits per BB, stack-confusion always on
//   Sub               3 loops, sub_prob=100 (all eligible ops substituted)
//   MBA               mba_heuristic=true (noise injection enabled)
//   Vec               vec_prob=80, vec_width=256, vec_shuffle=true,
//   vec_icmp=true CSM               nested dispatch, warmup=256 ConstEnc
//   constenc_times=3, constenc_kshare=4, constenc_feistel=true FW
//   funcwra_prob=100, funcwra_times=3 StringEnc         strcry_prob=100 (all
//   bytes encrypted) Anti-*            All three anti-analysis passes active
//
// Intended for: stress-testing toolchains, red-team deliverables, benchmarking.
// NOT for production: compile time and binary size will be substantially
// higher.
//
// ── Medium-intensity preset (-enable-medobf) ─────────────────────────────────
//
// -enable-medobf: enables a practical subset for production builds where
// compile-time overhead and binary-size growth must be bounded:
//   Sub (sub_loop=1, sub_prob=70) + MBA + ConstEnc (k-share=3, no Feistel)
//   + StringEnc (strcry_prob=100) + Flatten
//   Anti-analysis passes are NOT enabled (they require controlled
//   environments). Vec and CSM are disabled to keep binary size reasonable.
static cl::opt<bool> EnableMaxObfuscation(
    "enable-maxobf", cl::init(false), cl::NotHidden,
    cl::desc(
        "[OLLVM-Next] Maximum-intensity obfuscation: all passes at extreme "
        "settings. For stress-testing and red-team use."));
static cl::opt<bool> EnableObfVerbose(
    "obf-verbose", cl::init(false), cl::NotHidden,
    cl::desc(
        "[OLLVM-Next] Print a 'Running X On Y' line for every pass/function. "
        "Disabled by default: on large modules the output can exceed the "
        "64 KB stderr pipe buffer, causing WriteFile to block (0% CPU)."));
static cl::opt<bool> EnableObfTrace(
    "obf-trace", cl::init(false), cl::NotHidden,
    cl::desc(
        "[OLLVM-Next] Emit one step-marker before/after each major pass in the "
        "scheduler (StringEncryption, per-function loop, ConstEnc, etc.). "
        "Also prints function name + sub-pass tag for each per-function step. "
        "Max output: ~15 lines + ~7 per function. Use to diagnose 0% CPU "
        "hangs."));
static cl::opt<bool> EnableHighObfuscation(
    "enable-highobf", cl::init(false), cl::NotHidden,
    cl::desc("[OLLVM-Next] High-intensity obfuscation: all passes active with "
             "high parameters. CSM preferred over Flatten."));
static cl::opt<bool> EnableLowObfuscation(
    "enable-lowobf", cl::init(false), cl::NotHidden,
    cl::desc(
        "[OLLVM-Next] Low-intensity lightweight obfuscation: Sub+MBA+Split+"
        "BCF+StrEnc+ConstEnc."));
static cl::opt<bool> EnableMedObfuscation(
    "enable-medobf", cl::init(false), cl::NotHidden,
    cl::desc(
        "[OLLVM-Next] Medium-intensity obfuscation: Sub+MBA+ConstEnc+StrEnc+"
        "Flatten. Good for production builds."));

// ── Command-line aliases for standard OLLVM compatibility ──────────────────
static cl::alias SubAlias("sub", cl::desc("Alias for -enable-subobf"),
                          cl::aliasopt(EnableSubstitution));
static cl::alias FlaAlias("fla", cl::desc("Alias for -enable-cffobf"),
                          cl::aliasopt(EnableFlattening));
static cl::alias CffAlias("cff", cl::desc("Alias for -enable-cffobf"),
                          cl::aliasopt(EnableFlattening));
static cl::alias CffobfAlias("cffobf", cl::desc("Alias for -enable-cffobf"),
                             cl::aliasopt(EnableFlattening));
static cl::alias FlattenAlias("flatten", cl::desc("Alias for -enable-cffobf"),
                              cl::aliasopt(EnableFlattening));
static cl::alias FlatteningAlias("flattening",
                                 cl::desc("Alias for -enable-cffobf"),
                                 cl::aliasopt(EnableFlattening));
static cl::alias BcfAlias("bcf", cl::desc("Alias for -enable-bcfobf"),
                          cl::aliasopt(EnableBogusControlFlow));
static cl::alias SplitAlias("split", cl::desc("Alias for -enable-splitobf"),
                            cl::aliasopt(EnableBasicBlockSplit));
static cl::alias StrcryAlias("sobf", cl::desc("Alias for -enable-strcry"),
                             cl::aliasopt(EnableStringEncryption));
static cl::alias StrencAlias("strenc", cl::desc("Alias for -enable-strcry"),
                             cl::aliasopt(EnableStringEncryption));
static cl::alias ConstencAlias("constenc",
                               cl::desc("Alias for -enable-constenc"),
                               cl::aliasopt(EnableConstantEncryption));
static cl::alias IndibranAlias("indibran",
                               cl::desc("Alias for -enable-indibran"),
                               cl::aliasopt(EnableIndirectBranching));
static cl::alias IndibrAlias("indibr", cl::desc("Alias for -enable-indibran"),
                             cl::aliasopt(EnableIndirectBranching));
static cl::alias FuncwraAlias("funcwra", cl::desc("Alias for -enable-funcwra"),
                              cl::aliasopt(EnableFunctionWrapper));
static cl::alias FwAlias("fw", cl::desc("Alias for -enable-funcwra"),
                         cl::aliasopt(EnableFunctionWrapper));
static cl::alias CsmAlias("csm", cl::desc("Alias for -enable-csmobf"),
                          cl::aliasopt(EnableChaosStateMachine));
static cl::alias MbaAlias("mba", cl::desc("Alias for -enable-mbaobf"),
                          cl::aliasopt(EnableMBAObfuscation));
static cl::alias VobfAlias("vobf", cl::desc("Alias for -enable-vobf"),
                           cl::aliasopt(EnableVectorObfuscation));
static cl::alias VecAlias("vec", cl::desc("Alias for -enable-vobf"),
                          cl::aliasopt(EnableVectorObfuscation));
static cl::alias FcoAlias("fco", cl::desc("Alias for -enable-fco"),
                          cl::aliasopt(EnableFunctionCallObfuscate));
static cl::alias AntihookAlias("antihook",
                               cl::desc("Alias for -enable-antihook"),
                               cl::aliasopt(EnableAntiHooking));
static cl::alias AdbAlias("adb", cl::desc("Alias for -enable-adb"),
                          cl::aliasopt(EnableAntiDebugging));
static cl::alias AcdAlias("acd", cl::desc("Alias for -enable-acdobf"),
                          cl::aliasopt(EnableAntiClassDump));
static cl::alias AllobfAlias("allobf", cl::desc("Alias for -enable-allobf"),
                             cl::aliasopt(EnableAllObfuscation));
static cl::alias MaxobfAlias("maxobf", cl::desc("Alias for -enable-maxobf"),
                             cl::aliasopt(EnableMaxObfuscation));
static cl::alias HighobfAlias("highobf", cl::desc("Alias for -enable-highobf"),
                              cl::aliasopt(EnableHighObfuscation));
static cl::alias HighAlias("high", cl::desc("Alias for -enable-highobf"),
                           cl::aliasopt(EnableHighObfuscation));
static cl::alias MedobfAlias("medobf", cl::desc("Alias for -enable-medobf"),
                             cl::aliasopt(EnableMedObfuscation));
static cl::alias LowobfAlias("lowobf", cl::desc("Alias for -enable-lowobf"),
                             cl::aliasopt(EnableLowObfuscation));
static cl::alias LowAlias("low", cl::desc("Alias for -enable-lowobf"),
                          cl::aliasopt(EnableLowObfuscation));

// ── Structured preset and TOML config
// ─────────────────────────────────────────

static cl::opt<std::string> ObfPreset(
    "ensia-preset", cl::init(""), cl::NotHidden,
    cl::desc("[OLLVM-Next] Obfuscation preset: low | mid | high  "
             "(max remains -enable-maxobf for backward compat). "
             "Can be combined with -ensia-config for parameter fine-tuning."));

static cl::opt<std::string> ObfConfigFile(
    "ensia-config", cl::init(""), cl::NotHidden,
    cl::desc(
        "[OLLVM-Next] Path to TOML configuration file. "
        "Searched in order: this flag > ENSIA_CONFIG env var > ./ensia.toml"));

// ── Environment variable loader
// ───────────────────────────────────────────────

static std::optional<uint32_t> getEnvU32(const char *name) {
  if (const char *v = getenv(name)) {
    char *end = nullptr;
    unsigned long val = std::strtoul(v, &end, 0);
    if (end != v)
      return (uint32_t)val;
  }
  return std::nullopt;
}

static std::optional<uint64_t> getEnvU64(const char *name) {
  if (const char *v = getenv(name)) {
    char *end = nullptr;
    unsigned long long val = std::strtoull(v, &end, 0);
    if (end != v)
      return (uint64_t)val;
  }
  return std::nullopt;
}

static std::optional<bool> getEnvBool(const char *name) {
  if (const char *v = getenv(name)) {
    std::string s(v);
    for (char &c : s)
      c = (char)std::tolower((unsigned char)c);
    if (s == "1" || s == "true" || s == "yes" || s == "on")
      return true;
    if (s == "0" || s == "false" || s == "no" || s == "off")
      return false;
  }
  return std::nullopt;
}

static std::optional<std::string> getEnvString(const char *name) {
  if (const char *v = getenv(name)) {
    if (*v != '\0')
      return std::string(v);
  }
  return std::nullopt;
}

static void LoadEnv() {
  if (getEnvBool("ENSIA").value_or(false))
    EnableIRObfusaction = true;
  if (getenv("SPLITOBF") || getenv("SPLIT"))
    EnableBasicBlockSplit = true;
  if (getenv("SUBOBF") || getenv("SUB"))
    EnableSubstitution = true;
  if (getenv("ALLOBF") || getenv("ALL"))
    EnableAllObfuscation = true;
  if (getenv("FCO"))
    EnableFunctionCallObfuscate = true;
  if (getenv("STRCRY") || getenv("SOBF") || getenv("STRENC"))
    EnableStringEncryption = true;
  if (getenv("INDIBRAN") || getenv("INDIBR"))
    EnableIndirectBranching = true;
  if (getenv("FUNCWRA") || getenv("FW"))
    EnableFunctionWrapper = true;
  if (getenv("BCFOBF") || getenv("BCF"))
    EnableBogusControlFlow = true;
  if (getenv("ACDOBF") || getenv("ACD"))
    EnableAntiClassDump = true;
  if (getenv("CFFOBF") || getenv("CFF") || getenv("FLA"))
    EnableFlattening = true;
  if (getenv("CONSTENC"))
    EnableConstantEncryption = true;
  if (getenv("ANTIHOOK"))
    EnableAntiHooking = true;
  if (getenv("ADB"))
    EnableAntiDebugging = true;
  // OLLVM-Next new passes
  if (getenv("CSMOBF") || getenv("CSM"))
    EnableChaosStateMachine = true;
  if (getenv("MBAOBF") || getenv("MBA"))
    EnableMBAObfuscation = true;
  if (getenv("VOBF") || getenv("VEC"))
    EnableVectorObfuscation = true;
  if (getenv("MAXOBF") || getenv("MAX"))
    EnableMaxObfuscation = true;
  if (getenv("HIGHOBF") || getenv("HIGH"))
    EnableHighObfuscation = true;
  if (getenv("MEDOBF") || getenv("MED") || getenv("MID"))
    EnableMedObfuscation = true;
  if (getenv("LOWOBF") || getenv("LOW"))
    EnableLowObfuscation = true;
  if (getenv("VERBOSE") || getenv("OBF_VERBOSE"))
    EnableObfVerbose = true;
  if (getenv("TRACE") || getenv("OBF_TRACE"))
    EnableObfTrace = true;

  if (const char *p = getenv("ENSIA_PRESET"))
    ObfPreset = p;
  if (auto seed = getEnvU64("AES_SEED"))
    AesSeed = *seed;

  // Pass-specific sub-options via environment variables into GObfConfig.passes:
  auto &pc = GObfConfig.passes;
  if (auto v = getEnvU32("BCF_PROB"))
    pc.bcf.probability = *v;
  if (auto v = getEnvU32("BCF_LOOP"))
    pc.bcf.iterations = *v;
  else if (auto v2 = getEnvU32("BCF_ITERATIONS"))
    pc.bcf.iterations = *v2;
  if (auto v = getEnvU32("BCF_COND_COMPL"))
    pc.bcf.complexity = *v;
  else if (auto v2 = getEnvU32("BCF_COMPLEXITY"))
    pc.bcf.complexity = *v2;
  if (auto v = getEnvBool("BCF_ENTROPY_CHAIN"))
    pc.bcf.entropy_chain = *v;
  if (auto v = getEnvBool("BCF_JUNKASM"))
    pc.bcf.junk_asm = *v;
  else if (auto v2 = getEnvBool("BCF_JUNK_ASM"))
    pc.bcf.junk_asm = *v2;
  if (auto v = getEnvU32("BCF_JUNKASM_MINNUM"))
    pc.bcf.junk_asm_min = *v;
  if (auto v = getEnvU32("BCF_JUNKASM_MAXNUM"))
    pc.bcf.junk_asm_max = *v;
  if (auto v = getEnvBool("BCF_NESTED"))
    pc.bcf.nested = *v;
  if (auto v = getEnvBool("BCF_CREATEFUNC"))
    pc.bcf.create_func = *v;
  if (auto v = getEnvBool("BCF_ONLYJUNKASM"))
    pc.bcf.only_junk_asm = *v;

  if (auto v = getEnvU32("SUB_PROB"))
    pc.sub.probability = *v;
  if (auto v = getEnvU32("SUB_LOOP"))
    pc.sub.iterations = *v;
  else if (auto v2 = getEnvU32("SUB_ITERATIONS"))
    pc.sub.iterations = *v2;

  if (auto v = getEnvU32("MBA_PROB"))
    pc.mba.probability = *v;
  if (auto v = getEnvU32("MBA_LAYERS"))
    pc.mba.layers = *v;
  if (auto v = getEnvBool("MBA_HEURISTIC"))
    pc.mba.heuristic = *v;

  if (auto v = getEnvU32("SPLIT_NUM"))
    pc.split.splits = *v;
  else if (auto v2 = getEnvU32("SPLIT_SPLITS"))
    pc.split.splits = *v2;
  if (auto v = getEnvBool("SPLIT_STACKCONF"))
    pc.split.stack_confusion = *v;
  else if (auto v2 = getEnvBool("SPLIT_STACK_CONFUSION"))
    pc.split.stack_confusion = *v2;

  if (auto v = getEnvU32("STRCRY_PROB"))
    pc.str_enc.probability = *v;
  else if (auto v2 = getEnvU32("STR_ENC_PROB"))
    pc.str_enc.probability = *v2;
  if (auto v = getEnvBool("STRCRY_ANTIDUMP"))
    pc.str_enc.anti_dump = *v;
  else if (auto v2 = getEnvBool("STR_ENC_ANTIDUMP"))
    pc.str_enc.anti_dump = *v2;

  if (auto v = getEnvU32("CONSTENC_TIMES"))
    pc.const_enc.iterations = *v;
  else if (auto v2 = getEnvU32("CONSTENC_ITERATIONS"))
    pc.const_enc.iterations = *v2;
  if (auto v = getEnvU32("CONSTENC_KSHARE"))
    pc.const_enc.share_count = *v;
  else if (auto v2 = getEnvU32("CONSTENC_SHARE_COUNT"))
    pc.const_enc.share_count = *v2;
  if (auto v = getEnvBool("CONSTENC_FEISTEL"))
    pc.const_enc.feistel = *v;
  if (auto v = getEnvBool("CONSTENC_SUBXOR"))
    pc.const_enc.substitute_xor = *v;
  if (auto v = getEnvU32("CONSTENC_SUBXOR_PROB"))
    pc.const_enc.substitute_xor_prob = *v;
  if (auto v = getEnvBool("CONSTENC_TOGV"))
    pc.const_enc.globalize = *v;
  else if (auto v2 = getEnvBool("CONSTENC_GLOBALIZE"))
    pc.const_enc.globalize = *v2;
  if (auto v = getEnvU32("CONSTENC_TOGV_PROB"))
    pc.const_enc.globalize_prob = *v;
  else if (auto v2 = getEnvU32("CONSTENC_GLOBALIZE_PROB"))
    pc.const_enc.globalize_prob = *v2;

  if (auto v = getEnvU32("VOBF_PROB"))
    pc.vec.probability = *v;
  else if (auto v2 = getEnvU32("VEC_PROB"))
    pc.vec.probability = *v2;
  if (auto v = getEnvU32("VOBF_WIDTH"))
    pc.vec.width = *v;
  else if (auto v2 = getEnvU32("VEC_WIDTH"))
    pc.vec.width = *v2;
  if (auto v = getEnvBool("VOBF_SHUFFLE"))
    pc.vec.shuffle = *v;
  else if (auto v2 = getEnvBool("VEC_SHUFFLE"))
    pc.vec.shuffle = *v2;
  if (auto v = getEnvBool("VOBF_ICMP"))
    pc.vec.lift_comparisons = *v;
  else if (auto v2 = getEnvBool("VEC_ICMP"))
    pc.vec.lift_comparisons = *v2;
  else if (auto v3 = getEnvBool("VOBF_LIFT_COMPARISONS"))
    pc.vec.lift_comparisons = *v3;
  else if (auto v4 = getEnvBool("VEC_LIFT_COMPARISONS"))
    pc.vec.lift_comparisons = *v4;

  if (auto v = getEnvBool("CSM_NESTED"))
    pc.csm.nested_dispatch = *v;
  else if (auto v2 = getEnvBool("CSM_NESTED_DISPATCH"))
    pc.csm.nested_dispatch = *v2;
  if (auto v = getEnvU32("CSM_WARMUP"))
    pc.csm.warmup = *v;
  if (auto v = getEnvU32("CSM_MAXBLOCKS"))
    pc.csm.max_blocks = *v;
  else if (auto v2 = getEnvU32("CSM_MAX_BLOCKS"))
    pc.csm.max_blocks = *v2;

  if (auto v = getEnvBool("INDIR_USE_STACK"))
    pc.indir_branch.use_stack = *v;
  else if (auto v2 = getEnvBool("INDIBRAN_USE_STACK"))
    pc.indir_branch.use_stack = *v2;
  else if (auto v3 = getEnvBool("INDIBR_USE_STACK"))
    pc.indir_branch.use_stack = *v3;
  if (auto v = getEnvBool("INDIR_ENC_JUMP"))
    pc.indir_branch.enc_jump_target = *v;
  else if (auto v2 = getEnvBool("INDIBRAN_ENC_JUMP"))
    pc.indir_branch.enc_jump_target = *v2;
  else if (auto v3 = getEnvBool("INDIBR_ENC_JUMP"))
    pc.indir_branch.enc_jump_target = *v3;

  if (auto v = getEnvU32("FUNCWRA_PROB"))
    pc.func_wrap.probability = *v;
  else if (auto v2 = getEnvU32("FW_PROB"))
    pc.func_wrap.probability = *v2;
  if (auto v = getEnvU32("FUNCWRA_TIMES"))
    pc.func_wrap.times = *v;
  else if (auto v2 = getEnvU32("FW_TIMES"))
    pc.func_wrap.times = *v2;

  if (auto v = getEnvU64("FCO_FLAG"))
    pc.fco.flag = *v;
  if (auto v = getEnvString("FCO_CONFIG"))
    pc.fco.symbol_config_path = *v;
  else if (auto v2 = getEnvString("FCO_SYMBOL_CONFIG"))
    pc.fco.symbol_config_path = *v2;
  else if (auto v3 = getEnvString("ENSIA_SYMBOL_CONFIG"))
    pc.fco.symbol_config_path = *v3;

  if (auto v = getEnvBool("AH_INLINE"))
    pc.anti_hook.inline_aarch64 = *v;
  else if (auto v2 = getEnvBool("AH_INLINE_AARCH64"))
    pc.anti_hook.inline_aarch64 = *v2;
  if (auto v = getEnvBool("AH_INLINE_X86"))
    pc.anti_hook.inline_x86 = *v;
  if (auto v = getEnvBool("AH_INLINE_WIN"))
    pc.anti_hook.inline_win = *v;
  if (auto v = getEnvBool("AH_OBJC"))
    pc.anti_hook.objc_runtime = *v;
  else if (auto v2 = getEnvBool("AH_OBJC_RUNTIME"))
    pc.anti_hook.objc_runtime = *v2;
  if (auto v = getEnvBool("AH_ANTIREBIND"))
    pc.anti_hook.antirebind = *v;
  if (auto v = getEnvBool("AH_DIRECT_SYSCALL"))
    pc.anti_hook.direct_syscall = *v;
  if (auto v = getEnvBool("AH_INTEGRITY"))
    pc.anti_hook.check_integrity = *v;
  if (auto v = getEnvString("AH_IR_PATH"))
    pc.anti_hook.precompiled_ir_path = *v;
  else if (auto v2 = getEnvString("ENSIA_PRECOMPILED_AH"))
    pc.anti_hook.precompiled_ir_path = *v2;

  if (auto v = getEnvU32("ADB_PROB"))
    pc.anti_dbg.probability = *v;
  if (auto v = getEnvString("ADB_IR_PATH"))
    pc.anti_dbg.precompiled_ir_path = *v;
  else if (auto v2 = getEnvString("ENSIA_PRECOMPILED_ADB"))
    pc.anti_dbg.precompiled_ir_path = *v2;

  if (auto v = getEnvBool("ACD_USE_INIT"))
    pc.anti_class_dump.use_initialize = *v;
  else if (auto v2 = getEnvBool("ACD_USE_INITIALIZE"))
    pc.anti_class_dump.use_initialize = *v2;
  if (auto v = getEnvBool("ACD_RENAME_IMP"))
    pc.anti_class_dump.rename_methodimp = *v;
  else if (auto v2 = getEnvBool("ACD_RENAME_METHODIMP"))
    pc.anti_class_dump.rename_methodimp = *v2;
  if (auto v = getEnvBool("ACD_SCRAMBLE"))
    pc.anti_class_dump.scramble_methods = *v;
  else if (auto v2 = getEnvBool("ACD_SCRAMBLE_METHODS"))
    pc.anti_class_dump.scramble_methods = *v2;
  if (auto v = getEnvBool("ACD_DUMMY_SEL"))
    pc.anti_class_dump.dummy_selectors = *v;
  else if (auto v2 = getEnvBool("ACD_DUMMY_SELECTORS"))
    pc.anti_class_dump.dummy_selectors = *v2;
  if (auto v = getEnvU32("ACD_DUMMY_COUNT"))
    pc.anti_class_dump.dummy_count = *v;
  if (auto v = getEnvBool("ACD_ENCRYPT_STRINGS"))
    pc.anti_class_dump.encrypt_strings = *v;
  if (auto v = getEnvBool("ACD_ANTI_HOOK"))
    pc.anti_class_dump.anti_hook = *v;
  if (auto v = getEnvBool("ACD_OPAQUE_BARRIERS"))
    pc.anti_class_dump.opaque_barriers = *v;
}

// ── Config loading
// ────────────────────────────────────────────────────────────
//
// Final priority (highest → lowest) for per-pass parameters:
//   source annotation  >  TOML [passes.*]  >  -ensia-preset  >  [global] preset
//   >  cl::opt default
//
// Config file is searched:  -ensia-config flag  >  ENSIA_CONFIG env  >
// ./ensia.toml
static void loadObfConfig() {
  std::string path = ObfConfigFile;
  bool explicitConfig = !path.empty(); // -ensia-config was given explicitly
  if (path.empty()) {
    if (const char *env = getenv("ENSIA_CONFIG")) {
      path = env;
      explicitConfig = true; // env var also counts as explicit intent
    }
  }
  if (path.empty()) {
    if (llvm::sys::fs::exists("ensia.toml"))
      path = "ensia.toml";
    // auto-discovered ensia.toml does NOT auto-enable — it's just a parameter
    // file, not an obfuscation request.
  }

  // Step 1: load file (this applies the file's [global] preset internally,
  // then overlays [passes.*] sections on top of it).
  if (!path.empty()) {
    GObfConfig = ObfGlobalConfig::loadFromFile(path);
    // An explicit config file signals intent to obfuscate — auto-enable the
    // master gate so the user doesn't also need to pass -mllvm -ensia.
    if (explicitConfig)
      EnableIRObfusaction = true;
  } else {
    GObfConfig = ObfGlobalConfig::defaults();
  }

  // Step 2: if -ensia-preset or ENSIA_PRESET env is given, it overrides
  // the file's [global] preset while preserving explicit [passes.*] settings.
  // We rebuild as: preset_base merged with the file's explicit [passes.*]
  // overrides.
  std::string presetStr = (std::string)ObfPreset;
  if (presetStr.empty()) {
    if (const char *env = getenv("ENSIA_PRESET")) {
      presetStr = env;
      EnableIRObfusaction = true;
    }
  }
  if (!presetStr.empty()) {
    GObfConfig.preset = presetStr;
    // Extract the file's explicit [passes.*] overrides by comparing to the
    // file-preset's base (approximation: just keep GObfConfig.passes as
    // user-supplied delta and re-merge onto the CLI preset base).
    ObfPassConfig cli_preset_base = ObfGlobalConfig::presetConfig(presetStr);
    if (explicitConfig) {
      ObfGlobalConfig::merge(cli_preset_base,
                             GObfConfig.passes); // explicit file settings win
      GObfConfig.passes = cli_preset_base;
    } else {
      // Auto-discovered file is just an example template — explicit CLI preset
      // wins!
      GObfConfig.passes = cli_preset_base;
      GObfConfig.policies.clear();
    }
  }
}

static std::once_flag s_init_obf_config_flag;
static void ensureObfConfigLoaded() {
  std::call_once(s_init_obf_config_flag, []() {
    loadObfConfig();
    LoadEnv();
    if (EnableMaxObfuscation || EnableHighObfuscation || EnableMedObfuscation ||
        EnableLowObfuscation || EnableAllObfuscation || EnableAntiClassDump ||
        EnableAntiHooking || EnableAntiDebugging || EnableBogusControlFlow ||
        EnableFlattening || EnableBasicBlockSplit || EnableSubstitution ||
        EnableFunctionCallObfuscate || EnableStringEncryption ||
        EnableConstantEncryption || EnableIndirectBranching ||
        EnableFunctionWrapper || EnableChaosStateMachine ||
        EnableMBAObfuscation || EnableVectorObfuscation || !ObfPreset.empty()) {
      EnableIRObfusaction = true;
    }
  });
}

// ── Apply TOML policy metadata injection
// ────────────────────────────────────── For each function, resolve its
// effective config (global + matching policies) and inject enable/disable
// annotations as function metadata so the existing toObfuscate() mechanism can
// honour TOML-defined per-function enables. Parameter overrides are handled at
// runtime inside each pass via GObfConfig.resolve().
static void applyTomlPolicies(Module &M) {
  if (GObfConfig.policies.empty())
    return;

  StringRef modName = M.getSourceFileName();

  for (Function &F : M) {
    if (F.isDeclaration())
      continue;

    StringRef fnName = F.getName();
    ObfPassConfig eff = GObfConfig.resolve(modName, fnName);

    // Helper: write enable/disable annotation only when the policy differs from
    // the cl::opt global flag (to avoid redundant metadata).
    auto injectEnable = [&](std::optional<bool> enabled, const char *attr,
                            const char *noattr) {
      if (!enabled.has_value())
        return;
      if (*enabled)
        writeAnnotationMetadata(&F, attr);
      else
        writeAnnotationMetadata(&F, noattr);
    };

    injectEnable(eff.bcf.enabled, "bcf", "nobcf");
    injectEnable(eff.sub.enabled, "sub", "nosub");
    injectEnable(eff.mba.enabled, "mba", "nomba");
    injectEnable(eff.split.enabled, "split", "nosplit");
    injectEnable(eff.str_enc.enabled, "strenc", "nostrenc");
    injectEnable(eff.str_enc.enabled, "strcry", "nostrcry");
    injectEnable(eff.const_enc.enabled, "constenc", "noconstenc");
    injectEnable(eff.vec.enabled, "vobf", "novobf");
    injectEnable(eff.csm.enabled, "csm", "nocsm");
    injectEnable(eff.flatten.enabled, "fla", "nofla");
    injectEnable(eff.indir_branch.enabled, "indibran", "noindibran");
    injectEnable(eff.indir_branch.enabled, "indibr", "noindibr");
    injectEnable(eff.func_wrap.enabled, "fw", "nofw");
    injectEnable(eff.fco.enabled, "fco", "nofco");
    injectEnable(eff.anti_hook.enabled, "antihook", "noantihook");
    injectEnable(eff.anti_dbg.enabled, "adb", "noadb");
  }
}

// ── Feature Elimination
// ─────────────────────────────────────────────────────── Strips diagnostic
// artifacts that survive linking and help reverse engineers orient themselves
// in the binary.  Runs after all obfuscation passes so that renamed/injected
// symbols are also cleaned up.
static void runFeatureElimination(Module &M) {
  // Remove all DWARF/debug metadata (source locations, variable names, etc.)
  StripDebugInfo(M);

  // Anonymise the translation-unit path stored in the IR
  M.setSourceFileName("a");

  // Drop llvm.ident — reveals the compiler version and command line
  if (NamedMDNode *Ident = M.getNamedMetadata("llvm.ident"))
    Ident->eraseFromParent();

  // Prune informational module flags (SDK version, min-OS, branch-protection
  // notes, PGO summary).  Keep correctness-affecting flags (PIC level, etc.).
  if (NamedMDNode *Flags = M.getNamedMetadata("llvm.module.flags")) {
    SmallVector<MDNode *, 8> toKeep;
    for (MDNode *Op : Flags->operands()) {
      if (Op->getNumOperands() < 2) {
        toKeep.push_back(Op);
        continue;
      }
      if (auto *S = dyn_cast<MDString>(Op->getOperand(1))) {
        StringRef n = S->getString();
        if (n.contains("SDK Version") || n.contains("min_os") ||
            n.contains("PGO") || n.contains("branch_protection_spec") ||
            n.contains("Objective-C Class Properties") ||
            n.contains("Swift ABI") || n.contains("Swift Version"))
          continue; // discard
      }
      toKeep.push_back(Op);
    }
    Flags->clearOperands();
    for (MDNode *N : toKeep)
      Flags->addOperand(N);
  }

  // Rename all private/internal-linkage functions to unparseable hex strings.
  // Even after symbol-table stripping, decompilers reconstruct names from
  // DWARF or heuristics — replacing them before strip removes the fallback.
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    if (!F.hasPrivateLinkage() && !F.hasInternalLinkage())
      continue;
    // Don't rename our own sentinel/marker functions
    StringRef nm = F.getName();
    if (nm.starts_with("ensia_") || nm.starts_with("EnsiaBCF") ||
        nm.starts_with("ADB") || nm.starts_with("InitADB") ||
        nm.starts_with("EnsiaFW_"))
      continue;
    std::string newName;
    raw_string_ostream OS(newName);
    OS << format("_f%08x%08x", cryptoutils->get_uint32_t(),
                 cryptoutils->get_uint32_t());
    F.setName(OS.str());
  }

  // Scramble private GlobalVariable names that survived previous passes
  for (GlobalVariable &GV : M.globals()) {
    if (!GV.hasPrivateLinkage() && !GV.hasInternalLinkage())
      continue;
    StringRef nm = GV.getName();
    // Preserve BCF sentinel and our injected GVs — they're already hex-named
    if (nm.starts_with("bcf.") || nm.starts_with("LHSGV") ||
        nm.starts_with("RHSGV") || nm.starts_with("g"))
      continue;
    std::string newName;
    raw_string_ostream OS(newName);
    OS << format("_v%08x%08x", cryptoutils->get_uint32_t(),
                 cryptoutils->get_uint32_t());
    GV.setName(OS.str());
  }
}

namespace llvm {
struct Obfuscation : public ModulePass {
  static char ID;
  Obfuscation() : ModulePass(ID) {
    initializeObfuscationPass(*PassRegistry::getPassRegistry());
  }
  StringRef getPassName() const override { return "EnsiaObfuscationScheduler"; }

  bool runOnModule(Module &M) override {
    if (!EnableIRObfusaction)
      return false;

    // Propagate verbose/trace flags — must happen before any pass runs.
    ObfVerbose = EnableObfVerbose;
    ObfTrace = EnableObfTrace;

    // Normalize preset selection from CLI / config
    if (ObfPreset == "max" || GObfConfig.preset == "max") {
      EnableMaxObfuscation = true;
    } else if (ObfPreset == "high" || GObfConfig.preset == "high" ||
               EnableHighObfuscation) {
      EnableHighObfuscation = true;
    } else if (ObfPreset == "mid" || ObfPreset == "med" ||
               GObfConfig.preset == "mid" || EnableMedObfuscation) {
      EnableMedObfuscation = true;
    } else if (ObfPreset == "low" || GObfConfig.preset == "low" ||
               EnableLowObfuscation) {
      EnableLowObfuscation = true;
    }

    // ── Maximum-intensity mode: all passes + extreme tuning ──────────────
    if (EnableMaxObfuscation) {
      ObfuscationMaxMode = true;
      GObfConfig.preset = "max";
      ObfPassConfig maxPreset = ObfGlobalConfig::presetConfig("max");
      ObfGlobalConfig::merge(maxPreset, GObfConfig.passes);
      GObfConfig.passes = maxPreset;
      EnableAntiClassDump = true;
      EnableAntiHooking = true;
      EnableAntiDebugging = true;
      EnableBogusControlFlow = true;
      EnableFlattening = true;
      EnableBasicBlockSplit = true;
      EnableSubstitution = true;
      EnableFunctionCallObfuscate = true;
      EnableStringEncryption = true;
      EnableConstantEncryption = true;
      EnableIndirectBranching = true;
      EnableFunctionWrapper = true;
      EnableChaosStateMachine = true;
      EnableMBAObfuscation = true;
      EnableVectorObfuscation = true;
      errs() << "[OLLVM-Next] *** MAXIMUM OBFUSCATION MODE ACTIVE ***\n"
             << "    BCF:     prob=100, loop=3, entropy_chain=100%\n"
             << "    CSM:     nested_dispatch=true (2-level CFG explosion)\n"
             << "    MBA:     mba_heuristic=true\n"
             << "    Vec:     vec_prob=90, vec_width=512, shuffle+icmp\n"
             << "    ConstEnc:constenc_times=3, kshare=6, feistel=true\n";
    }

    // ── High-intensity mode: all passes at balanced high settings ────────
    if (EnableHighObfuscation && !EnableMaxObfuscation) {
      ObfuscationHighMode = true;
      GObfConfig.preset = "high";
      ObfPassConfig highPreset = ObfGlobalConfig::presetConfig("high");
      ObfGlobalConfig::merge(highPreset, GObfConfig.passes);
      GObfConfig.passes = highPreset;
      EnableSubstitution = true;
      EnableMBAObfuscation = true;
      EnableBasicBlockSplit = true;
      EnableBogusControlFlow = true;
      EnableStringEncryption = true;
      EnableConstantEncryption = true;
      EnableVectorObfuscation = true;
      EnableChaosStateMachine = true;
      EnableIndirectBranching = true;
      EnableFunctionWrapper = true;
      EnableFunctionCallObfuscate = true;
      EnableAntiHooking = true;
      EnableAntiDebugging = true;
      EnableAntiClassDump = true;
      errs() << "[OLLVM-Next] High obfuscation mode active: all passes at high "
                "intensity\n";
    }

    // ── Medium-intensity mode: production-safe subset ─────────────────────
    if (EnableMedObfuscation && !EnableMaxObfuscation &&
        !EnableHighObfuscation) {
      ObfuscationMedMode = true;
      GObfConfig.preset = "mid";
      ObfPassConfig midPreset = ObfGlobalConfig::presetConfig("mid");
      ObfGlobalConfig::merge(midPreset, GObfConfig.passes);
      GObfConfig.passes = midPreset;
      EnableSubstitution = true;
      EnableMBAObfuscation = true;
      EnableConstantEncryption = true;
      EnableStringEncryption = true;
      EnableFlattening = true;
      EnableBasicBlockSplit = true;
      EnableBogusControlFlow = true;
      EnableVectorObfuscation = true;
      EnableIndirectBranching = true;
      errs()
          << "[OLLVM-Next] Medium obfuscation mode: Sub+MBA+Split+BCF+ConstEnc+"
             "StrEnc+Flatten+Vec+IndirBranch\n";
    }

    // ── Low-intensity mode: lightweight subset ────────────────────────────
    if (EnableLowObfuscation && !EnableMaxObfuscation &&
        !EnableHighObfuscation && !EnableMedObfuscation) {
      ObfuscationLowMode = true;
      GObfConfig.preset = "low";
      ObfPassConfig lowPreset = ObfGlobalConfig::presetConfig("low");
      ObfGlobalConfig::merge(lowPreset, GObfConfig.passes);
      GObfConfig.passes = lowPreset;
      EnableSubstitution = true;
      EnableMBAObfuscation = true;
      EnableBasicBlockSplit = true;
      EnableBogusControlFlow = true;
      EnableStringEncryption = true;
      EnableConstantEncryption = true;
      errs() << "[OLLVM-Next] Low obfuscation mode: "
                "Sub+MBA+Split+BCF+StrEnc+ConstEnc\n";
    }

    // ── Structured preset / TOML config ───────────────────────────────────
    // Apply verbose/trace from config (cl::opt already took effect above, but
    // config file can also set them).
    if (GObfConfig.verbose)
      ObfVerbose = true;
    if (GObfConfig.trace)
      ObfTrace = true;

    // Apply preset/config enables (only if not already forced by preset mode).
    if (!EnableMaxObfuscation && !EnableHighObfuscation &&
        !EnableMedObfuscation && !EnableLowObfuscation) {
      auto &pc = GObfConfig.passes;
      if (pc.bcf.enabled.value_or(false))
        EnableBogusControlFlow = true;
      if (pc.sub.enabled.value_or(false))
        EnableSubstitution = true;
      if (pc.mba.enabled.value_or(false))
        EnableMBAObfuscation = true;
      if (pc.split.enabled.value_or(false))
        EnableBasicBlockSplit = true;
      if (pc.str_enc.enabled.value_or(false))
        EnableStringEncryption = true;
      if (pc.const_enc.enabled.value_or(false))
        EnableConstantEncryption = true;
      if (pc.vec.enabled.value_or(false))
        EnableVectorObfuscation = true;
      if (pc.csm.enabled.value_or(false))
        EnableChaosStateMachine = true;
      if (pc.flatten.enabled.value_or(false))
        EnableFlattening = true;
      if (pc.indir_branch.enabled.value_or(false))
        EnableIndirectBranching = true;
      if (pc.func_wrap.enabled.value_or(false))
        EnableFunctionWrapper = true;
      if (pc.fco.enabled.value_or(false))
        EnableFunctionCallObfuscate = true;
      if (pc.anti_hook.enabled.value_or(false))
        EnableAntiHooking = true;
      if (pc.anti_dbg.enabled.value_or(false))
        EnableAntiDebugging = true;
      if (pc.anti_class_dump.enabled.value_or(false))
        EnableAntiClassDump = true;

      if (!GObfConfig.preset.empty())
        errs() << "[OLLVM-Next] Preset '" << GObfConfig.preset << "' active\n";
    }

    ObfuscationFCOActive = EnableAllObfuscation || EnableFunctionCallObfuscate;

    auto startTime = std::chrono::steady_clock::now();

    errs() << "Running OLLVM-Next on " << M.getSourceFileName() << "  [LLVM "
           << LLVM_VERSION_MAJOR << "." << LLVM_VERSION_MINOR << ", commit "
           << GIT_COMMIT_HASH << "]\n";

    annotation2Metadata(M);
    applyTomlPolicies(M); // inject per-function enables from TOML policies

    // ── 1. AntiHooking & AntiClassDump ─────────────────────────────────────
    if (ObfTrace)
      errs() << "[OLLVM-Next][1] AntiHooking & AntiClassDump\n";
    {
      ModulePass *MP =
          createAntiHookPass(EnableAllObfuscation || EnableAntiHooking);
      MP->doInitialization(M);
      MP->runOnModule(M);
      delete MP;
    }
    if (EnableAllObfuscation || EnableAntiClassDump) {
      ModulePass *P = createAntiClassDumpPass();
      P->doInitialization(M);
      P->runOnModule(M);
      delete P;
    }
    if (ObfTrace)
      errs() << "[OLLVM-Next][1] AntiHooking & AntiClassDump: done\n";

    // ── 2. FunctionWrapper (polymorphic proxies) ───────────────────────────
    // Must run BEFORE FunctionCallObfuscate so direct calls to external
    // functions are wrapped in EnsiaFW_... proxies first. When FCO follows, it
    // finds the external call sites inside the proxy and lowers them to dynamic
    // dlsym resolution, while callers target the polymorphic proxy.
    if (ObfTrace)
      errs() << "[OLLVM-Next][2] FunctionWrapper\n";
    {
      ModulePass *MP = createFunctionWrapperPass(EnableAllObfuscation ||
                                                 EnableFunctionWrapper);
      MP->runOnModule(M);
      delete MP;
    }
    if (ObfTrace)
      errs() << "[OLLVM-Next][2] FunctionWrapper: done\n";

    // ── 3. FunctionCallObfuscate ───────────────────────────────────────────
    if (ObfTrace)
      errs() << "[OLLVM-Next][3] FunctionCallObfuscate\n";
    {
      FunctionPass *FP = createFunctionCallObfuscatePass(
          EnableAllObfuscation || EnableFunctionCallObfuscate);
      for (Function &F : M)
        if (!F.isDeclaration())
          FP->runOnFunction(F);
      delete FP;
    }
    if (ObfTrace)
      errs() << "[OLLVM-Next][3] FunctionCallObfuscate: done\n";

    // ── 4. AntiDebugging ───────────────────────────────────────────────────
    if (ObfTrace)
      errs() << "[OLLVM-Next][4] AntiDebugging\n";
    {
      ModulePass *MP =
          createAntiDebuggingPass(EnableAllObfuscation || EnableAntiDebugging);
      MP->runOnModule(M);
      delete MP;
    }
    if (ObfTrace)
      errs() << "[OLLVM-Next][4] AntiDebugging: done\n";

    // ── 5. StringEncryption ────────────────────────────────────────────────
    if (ObfTrace)
      errs() << "[OLLVM-Next][5] StringEncryption: start\n";
    {
      ModulePass *MP = createStringEncryptionPass(EnableAllObfuscation ||
                                                  EnableStringEncryption);
      MP->runOnModule(M);
      delete MP;
    }
    if (ObfTrace)
      errs() << "[OLLVM-Next][5] StringEncryption: done\n";

    // ── 6. ConstantEncryption (Phase 1: Pre-phase for user literals) ───────
    // Encrypts original programmer constants before CFG transformations so
    // BCF / MBA / CSM / Flattening tangle the constant decryption logic.
    if (ObfTrace)
      errs() << "[OLLVM-Next][6] ConstantEncryption (Phase 1: Pre-phase)\n";
    {
      ModulePass *MP = createConstantEncryptionPass(
          EnableAllObfuscation || EnableConstantEncryption,
          /*isPrePhase=*/true);
      MP->runOnModule(M);
      delete MP;
    }
    if (ObfTrace)
      errs() << "[OLLVM-Next][6] ConstantEncryption (Phase 1): done\n";

    // ── 7. Per-function passes ─────────────────────────────────────────────
    if (ObfTrace)
      errs() << "[OLLVM-Next][7] per-function loop: start\n";
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;

      if (ObfTrace)
        errs() << "[OLLVM-Next][7] F=" << F.getName() << "\n";

      // 7a. Instruction Substitution — transforms integer/shift instructions
      if (ObfTrace)
        errs() << "[OLLVM-Next][7a] sub\n";
      {
        FunctionPass *P =
            createSubstitutionPass(EnableAllObfuscation || EnableSubstitution);
        P->runOnFunction(F);
        delete P;
      }

      // 7b. MBAObfuscation — multi-term Mixed Boolean-Arithmetic on Sub output;
      //     embeds polymorphic hardware barriers into instruction chains
      if (ObfTrace)
        errs() << "[OLLVM-Next][7b] mba\n";
      {
        FunctionPass *P = createMBAObfuscationPass(EnableAllObfuscation ||
                                                   EnableMBAObfuscation);
        P->runOnFunction(F);
        delete P;
      }

      // 7c. SplitBasicBlocks — slices across expanded MBA instruction chains
      //     and injects randomized stack-confusion instructions at block
      //     entries (cuts single MBA operations across multiple basic blocks)
      if (ObfTrace)
        errs() << "[OLLVM-Next][7c] split\n";
      {
        FunctionPass *P = createSplitBasicBlockPass(EnableAllObfuscation ||
                                                    EnableBasicBlockSplit);
        P->runOnFunction(F);
        delete P;
      }

      // 7d. BogusControlFlow — inserts opaque hardware-predicate edges & clones
      //     the split blocks containing partial MBA expressions
      if (ObfTrace)
        errs() << "[OLLVM-Next][7d] bcf\n";
      {
        FunctionPass *P = createBogusControlFlowPass(EnableAllObfuscation ||
                                                     EnableBogusControlFlow);
        P->runOnFunction(F);
        delete P;
      }

      // 7e. ChaosStateMachine — logistic-map quadratic CFF on the obfuscated
      // CFG.
      //     Stamps processed functions with "ensia.csm.done" so Flattening
      //     skips them.
      if (ObfTrace)
        errs() << "[OLLVM-Next][7e] csm\n";
      {
        FunctionPass *P = createChaosStateMachinePass(EnableAllObfuscation ||
                                                      EnableChaosStateMachine);
        P->runOnFunction(F);
        delete P;
      }

      // 7f. Classic Flattening — fallback CFF for functions CSM couldn't handle
      //     (EH pads, coroutines, ≤1 block, or exceeding csm_maxblocks).
      //     Checks "ensia.csm.done" attribute and skips if CSM already ran.
      if (ObfTrace)
        errs() << "[OLLVM-Next][7f] flatten\n";
      {
        FunctionPass *P =
            createFlatteningPass(EnableAllObfuscation || EnableFlattening);
        P->runOnFunction(F);
        delete P;
      }

      // 7g. VectorObfuscation — SIMD scalar→vector lifting as final per-fn
      // step.
      //     Lifts remaining scalar arithmetic, state transition logic, and
      //     comparisons into wide SIMD vectors.
      if (ObfTrace)
        errs() << "[OLLVM-Next][7g] vec\n";
      {
        FunctionPass *P = createVectorObfuscationPass(EnableAllObfuscation ||
                                                      EnableVectorObfuscation);
        P->runOnFunction(F);
        delete P;
      }
      if (ObfTrace)
        errs() << "[OLLVM-Next][7] F=" << F.getName() << " done\n";
    }
    if (ObfTrace)
      errs() << "[OLLVM-Next][7] per-function loop: done\n";

    // ── 8. ConstantEncryption (Phase 2: Post-phase for skeleton constants) ─
    // Encrypts skeleton constants introduced by BCF, CSM, and CFF,
    // with small-constant whitelisting to eliminate combinatorial explosion.
    // Runs after all per-function passes so it also encrypts constants that
    // were injected by Sub, MBA, BCF, and Vec. Feistel tier adds a nonlinear
    // layer (26 IR instructions per constant) on top of the k-share XOR chain.
    // Must run BEFORE FeatureElimination (step 10) so TOML policy
    // module/function name regexes can still match the original source file and
    // function names.
    if (ObfTrace)
      errs() << "[OLLVM-Next][8] ConstantEncryption (Phase 2: Post-phase)\n";
    {
      ModulePass *MP = createConstantEncryptionPass(
          EnableAllObfuscation || EnableConstantEncryption,
          /*isPrePhase=*/false);
      MP->runOnModule(M);
      delete MP;
    }
    if (ObfTrace)
      errs() << "[OLLVM-Next][8] ConstantEncryption (Phase 2): done\n";

    // ── 9. IndirectBranch (Knuth-hash encrypted targets) ─────────────────
    // Also before FeatureElimination for the same naming reason.
    if (ObfTrace)
      errs() << "[OLLVM-Next][9] IndirectBranch\n";
    {
      FunctionPass *P = createIndirectBranchPass(EnableAllObfuscation ||
                                                 EnableIndirectBranching);
      for (Function &F : M)
        if (!F.isDeclaration())
          P->runOnFunction(F);
      delete P;
    }
    if (ObfTrace)
      errs() << "[OLLVM-Next][9] IndirectBranch: done\n";

    // ── 10. Feature Elimination ────────────────────────────────────────────
    // Runs LAST — after all obfuscation passes have finished — so that:
    //   • TOML policy module/function regexes can match original names in all
    //     passes above (ConstantEncryption, IndirectBranch, FunctionWrapper).
    //   • Renamed private functions (_f<hex>) and the "a" source filename don't
    //     interfere with policy resolution in any pass.
    if (ObfTrace)
      errs() << "[OLLVM-Next][10] FeatureElimination\n";
    runFeatureElimination(M);
    if (ObfTrace)
      errs() << "[OLLVM-Next][10] FeatureElimination: done\n";

    // ── 11. Cleanup marker declarations ───────────────────────────────────
    SmallVector<Function *, 8> toDelete;
    for (Function &F : M) {
      if (!F.isDeclaration() || !F.hasName())
        continue;
      if (!F.getName().starts_with("ensia_"))
        continue;
      for (User *U : F.users())
        if (Instruction *Inst = dyn_cast<Instruction>(U))
          Inst->eraseFromParent();
      toDelete.push_back(&F);
    }
    for (Function *F : toDelete)
      F->eraseFromParent();

    // ── 12. LTO Evasion ────────────────────────────────────────────────────
    // Mark all functions with optnone and noinline so that LTO's whole-program
    // pipeline doesn't optimize away our obfuscation.
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;
      turnOffOptimization(&F);
    }

    auto endTime = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = endTime - startTime;
    errs() << "OLLVM-Next done.  Wall time: " << format("%.5f", elapsed.count())
           << "s\n";
    return true;
  }
}; // struct Obfuscation

ModulePass *createObfuscationLegacyPass() {
  ensureObfConfigLoaded();
  if (!EnableIRObfusaction)
    return new Obfuscation(); // gate off — runOnModule will return false
                              // immediately

  // Config file may specify a seed; cl::opt -aesSeed overrides it.
  uint64_t seed = (AesSeed != 0x1337)
                      ? (uint64_t)AesSeed
                      : (GObfConfig.seed != 0 ? GObfConfig.seed : 0x1337);
  if (seed != 0x1337)
    cryptoutils->prng_seed(seed);
  else
    cryptoutils->prng_seed();
  errs() << "Initializing OLLVM-Next with commit:" << GIT_COMMIT_HASH << "\n";
  return new Obfuscation();
}

PreservedAnalyses ObfuscationPass::run(Module &M, ModuleAnalysisManager &) {
  if (createObfuscationLegacyPass()->runOnModule(M))
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();
}

} // namespace llvm

char llvm::Obfuscation::ID = 0;
INITIALIZE_PASS_BEGIN(Obfuscation, "obfus", "Enable OLLVM-Next Obfuscation",
                      false, false)
INITIALIZE_PASS_DEPENDENCY(AntiClassDump)
INITIALIZE_PASS_DEPENDENCY(BogusControlFlow)
INITIALIZE_PASS_DEPENDENCY(ConstantEncryption)
INITIALIZE_PASS_DEPENDENCY(Flattening)
INITIALIZE_PASS_DEPENDENCY(FunctionCallObfuscate)
INITIALIZE_PASS_DEPENDENCY(IndirectBranch)
INITIALIZE_PASS_DEPENDENCY(MBAObfuscation)
INITIALIZE_PASS_DEPENDENCY(SplitBasicBlock)
INITIALIZE_PASS_DEPENDENCY(StringEncryption)
INITIALIZE_PASS_DEPENDENCY(Substitution)
INITIALIZE_PASS_DEPENDENCY(VectorObfuscation)
INITIALIZE_PASS_END(Obfuscation, "obfus", "Enable OLLVM-Next Obfuscation",
                    false, false)

namespace llvm {

PassPluginLibraryInfo getEnsiaPluginInfo() {
  return {ENSIA_PLUGIN_API_VERSION, "OLLVM-Next", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            // ── Auto-inject via optimizer-last EP
            // ───────────────────────────────── Fires during pipeline
            // construction (including O0) so -Xclang -load is enough — the user
            // doesn't need to also spell out -passes=ensia.
            // LoadEnv()/loadObfConfig() are called here so the TOML file and
            // env vars are honoured before the pass checks EnableIRObfusaction.
            PB.registerOptimizerLastEPCallback([](ModulePassManager &MPM,
                                                  OptimizationLevel,
                                                  ThinOrFullLTOPhase Phase) {
              if (Phase == ThinOrFullLTOPhase::ThinLTOPreLink ||
                  Phase == ThinOrFullLTOPhase::FullLTOPreLink)
                return;
              ensureObfConfigLoaded();
              if (!EnableIRObfusaction)
                return;
              MPM.addPass(ObfuscationPass());
            });

            PB.registerFullLinkTimeOptimizationLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel) {
                  ensureObfConfigLoaded();
                  if (!EnableIRObfusaction)
                    return;
                  MPM.addPass(ObfuscationPass());
                });

            // ── Explicit -passes=ensia[<inner-opts>]
            // ───────────────────────────── Also supports the classic explicit
            // form so both invocation styles work.
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement> InnerPipeline) {
                  if (Name != EnableIRObfusaction.ArgStr && Name != "ensia")
                    return false;
                  EnableIRObfusaction = true;
                  for (const auto &E : InnerPipeline) {
                    auto n = E.Name;
                    if (n == EnableAntiClassDump.ArgStr || n == "acd" ||
                        n == "acdobf")
                      EnableAntiClassDump = true;
                    else if (n == EnableAntiHooking.ArgStr || n == "antihook")
                      EnableAntiHooking = true;
                    else if (n == EnableAntiDebugging.ArgStr || n == "adb")
                      EnableAntiDebugging = true;
                    else if (n == EnableBogusControlFlow.ArgStr || n == "bcf" ||
                             n == "bcfobf")
                      EnableBogusControlFlow = true;
                    else if (n == EnableFlattening.ArgStr || n == "fla" ||
                             n == "cff" || n == "cffobf")
                      EnableFlattening = true;
                    else if (n == EnableBasicBlockSplit.ArgStr ||
                             n == "split" || n == "splitobf")
                      EnableBasicBlockSplit = true;
                    else if (n == EnableSubstitution.ArgStr || n == "sub" ||
                             n == "subobf")
                      EnableSubstitution = true;
                    else if (n == EnableAllObfuscation.ArgStr ||
                             n == "allobf" || n == "all")
                      EnableAllObfuscation = true;
                    else if (n == EnableFunctionCallObfuscate.ArgStr ||
                             n == "fco")
                      EnableFunctionCallObfuscate = true;
                    else if (n == EnableStringEncryption.ArgStr ||
                             n == "strcry" || n == "sobf" || n == "strenc")
                      EnableStringEncryption = true;
                    else if (n == EnableConstantEncryption.ArgStr ||
                             n == "constenc")
                      EnableConstantEncryption = true;
                    else if (n == EnableIndirectBranching.ArgStr ||
                             n == "indibran" || n == "indibr")
                      EnableIndirectBranching = true;
                    else if (n == EnableFunctionWrapper.ArgStr ||
                             n == "funcwra" || n == "fw")
                      EnableFunctionWrapper = true;
                    else if (n == EnableChaosStateMachine.ArgStr ||
                             n == "csm" || n == "csmobf")
                      EnableChaosStateMachine = true;
                    else if (n == EnableMBAObfuscation.ArgStr || n == "mba" ||
                             n == "mbaobf")
                      EnableMBAObfuscation = true;
                    else if (n == EnableVectorObfuscation.ArgStr ||
                             n == "vobf" || n == "vec")
                      EnableVectorObfuscation = true;
                    else if (n == EnableMaxObfuscation.ArgStr ||
                             n == "maxobf" || n == "max")
                      EnableMaxObfuscation = true;
                    else if (n == EnableHighObfuscation.ArgStr ||
                             n == "highobf" || n == "high")
                      EnableHighObfuscation = true;
                    else if (n == EnableMedObfuscation.ArgStr ||
                             n == "medobf" || n == "med" || n == "mid")
                      EnableMedObfuscation = true;
                    else if (n == EnableLowObfuscation.ArgStr ||
                             n == "lowobf" || n == "low")
                      EnableLowObfuscation = true;
                  }
                  MPM.addPass(ObfuscationPass());
                  return true;
                });
          }};
}

} // namespace llvm

// llvmGetPassPluginInfo must be a top-level C symbol (not in any namespace).
// On Windows, __declspec(dllexport) is required so the linker puts it in the
// DLL export table — LLVM_ATTRIBUTE_WEAK is a no-op on MSVC/clang-cl.
#ifdef _WIN32
extern "C" __declspec(dllexport)
#else
extern "C" LLVM_ATTRIBUTE_WEAK
#endif
::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return llvm::getEnsiaPluginInfo();
}
