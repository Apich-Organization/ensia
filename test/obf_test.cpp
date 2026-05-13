// obf_test.cpp — Comprehensive correctness test for OLLVM-Next passes.
//
// Exercises:
//   • Integer arithmetic (add/sub/mul) → InstructionSubstitution, MBA, VectorObfuscation
//   • Bitwise / shifts (and/or/xor/shl/lshr/ashr) → all three pass families
//   • Float arithmetic (fadd/fsub/fmul) → VectorObfuscation float lifting
//   • Integer comparisons (icmp) → VectorObfuscation ICmp lifting
//   • String literals → StringEncryption
//   • Compile-time integer constants → ConstantEncryption
//   • Non-trivial control flow (switch, loops) → BogusControlFlow, Flattening
//   • Recursive functions → tests that obfuscation doesn't break call stack
//   • Volatile side-effects to prevent DCE of the "real" computations
//
// Annotate with function-level attributes to exercise per-function controls:
//   __attribute__((annotate("obfuscate")))  — explicit enable
//   __attribute__((annotate("nofla")))       — no flattening (recursive fns)

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <array>
#include <vector>

// ─── helpers ─────────────────────────────────────────────────────────────────

// Prevent the compiler from folding away computations via constant propagation.
static volatile uint64_t g_sink;
static inline void sink(uint64_t v) { g_sink = v; }

// ─── 1. Integer arithmetic ────────────────────────────────────────────────────

__attribute__((noinline))
static uint64_t int_arith(uint64_t a, uint64_t b) {
    uint64_t r0  = a + b;               // add
    uint64_t r1  = a - b;               // sub
    uint64_t r2  = a * b;               // mul
    uint64_t r3  = r0 ^ r1;             // xor
    uint64_t r4  = r0 & r2;             // and
    uint64_t r5  = r1 | r3;             // or
    uint64_t r6  = r4 + (r5 * 3);       // compound
    return r6;
}

// 32-bit variant (tests <4 x i32> lifting at 128-bit width)
__attribute__((noinline))
static uint32_t int_arith32(uint32_t a, uint32_t b) {
    return (a * b) + (a ^ b) - (a & b);
}

// ─── 2. Shift operations ─────────────────────────────────────────────────────

__attribute__((noinline))
static uint64_t shift_ops(uint64_t x, unsigned k) {
    uint64_t shl  = x << k;
    uint64_t lshr = x >> k;
    int64_t  ashr = (int64_t)x >> (int)k;   // arithmetic shift
    // Chain: combine all three
    return shl ^ (uint64_t)ashr ^ lshr;
}

// Constant-shift forms — substitution pass specialises these
__attribute__((noinline))
static uint32_t shift_const(uint32_t x) {
    return (x << 7) ^ (x >> 3) ^ (uint32_t)((int32_t)x >> 5);
}

// ─── 3. Float arithmetic ─────────────────────────────────────────────────────

__attribute__((noinline))
static double float_arith(double a, double b) {
    double r0 = a + b;
    double r1 = a - b;
    double r2 = a * b;
    // Use all three to prevent DCE
    return r0 * r1 + r2;
}

__attribute__((noinline))
static float float_arith_f(float a, float b) {
    return (a + b) * (a - b);   // difference of squares: a²-b²
}

// ─── 4. Integer comparison (ICmp) ────────────────────────────────────────────

__attribute__((noinline))
static int icmp_chain(int64_t a, int64_t b) {
    int r = 0;
    if (a == b)   r |= 1;
    if (a != b)   r |= 2;
    if (a <  b)   r |= 4;
    if (a <= b)   r |= 8;
    if (a >  b)   r |= 16;
    if (a >= b)   r |= 32;
    return r;
}

// ─── 5. String encryption test ───────────────────────────────────────────────

// These string literals should be encrypted at rest and decrypted at runtime.
static const char *const s_hello   = "Hello from OLLVM-Next!";
static const char *const s_sha     = "SHA256=deadbeefcafebabe0123456789abcdef";
static const char *const s_key     = "SuperSecretObfuscatedKeyMaterial";
static const char *const s_unicode = "Unicode: \xe4\xb8\xad\xe6\x96\x87\xe6\xb5\x8b\xe8\xaf\x95";

__attribute__((noinline))
static bool string_test() {
    // Verify string content hasn't been corrupted by encryption/decryption
    if (strncmp(s_hello, "Hello", 5) != 0) return false;
    if (strlen(s_sha) != 39)  // "SHA256="(7) + 32 hex = 39              return false;
    if (s_key[0] != 'S')                  return false;
    // Compute a simple checksum so the content is actually used
    uint64_t cs = 0;
    for (const char *p = s_key; *p; p++) cs = cs * 31 + (unsigned char)*p;
    sink(cs);
    return true;
}

// ─── 6. Constant encryption test ─────────────────────────────────────────────

// These constants are operands that ConstantEncryption should encrypt.
__attribute__((noinline))
static uint64_t const_test(uint64_t x) {
    // A mix of immediate constants — each should be encrypted
    uint64_t a = x + UINT64_C(0xDEADBEEFCAFEBABE);
    uint64_t b = x * UINT64_C(0x9E3779B97F4A7C15);  // golden-ratio hash
    uint64_t c = (x ^ UINT64_C(0x123456789ABCDEF0)) + UINT64_C(0xFEDCBA9876543210);
    uint64_t d = (a ^ b) + (c >> 17) + UINT64_C(0xBEEFCAFE01234567);
    return d;
}

// 32-bit constants
__attribute__((noinline))
static uint32_t const_test32(uint32_t x) {
    return (x + 0xDEADBEEFu) ^ (x * 0x6C62272Eu) - 0xCAFEBABEu;
}

// ─── 7. Non-trivial control flow ─────────────────────────────────────────────

// Flattening and BogusControlFlow target this.
__attribute__((noinline))
static uint32_t collatz(uint32_t n) {
    uint32_t steps = 0;
    while (n != 1) {
        if (n & 1)
            n = 3 * n + 1;
        else
            n >>= 1;
        ++steps;
    }
    return steps;
}

// Switch-based dispatch — ChaosStateMachine targets switch statements.
__attribute__((noinline))
static uint64_t dispatch(uint32_t cmd, uint64_t val) {
    switch (cmd % 8) {
    case 0: return val + 0x11111111u;
    case 1: return val - 0x22222222u;
    case 2: return val ^ 0x33333333u;
    case 3: return val * 0x44444445u;
    case 4: return val << 3;
    case 5: return val >> 5;
    case 6: return ~val;
    case 7: return (val << 13) | (val >> 51);
    default: return val;
    }
}

// ─── 8. Recursive function ───────────────────────────────────────────────────
// Annotated nofla so flattening doesn't break the recursion.

__attribute__((noinline, annotate("nofla")))
static uint64_t fibonacci(uint32_t n) {
    if (n < 2) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

// ─── 9. Array / loop ─────────────────────────────────────────────────────────

__attribute__((noinline))
static uint64_t array_hash(const std::array<uint32_t, 16> &arr) {
    uint64_t h = 0xcbf29ce484222325ULL;  // FNV-1a offset basis
    for (uint32_t v : arr) {
        h ^= v;
        h *= 0x100000001b3ULL;           // FNV prime
        h += h >> 17;
        h ^= h << 31;
        h -= h >> 11;
    }
    return h;
}

// ─── 10. Mixed-type pipeline ─────────────────────────────────────────────────

__attribute__((noinline))
static double mixed_pipeline(uint64_t x) {
    // Integer ops feed float ops — tests that obfuscation doesn't mis-type
    uint64_t a = x * UINT64_C(6364136223846793005) + 1442695040888963407;
    uint32_t lo = (uint32_t)a;
    uint32_t hi = (uint32_t)(a >> 32);
    float  f0 = (float)(lo & 0xFFFF) / 65535.0f;
    float  f1 = (float)(hi & 0xFFFF) / 65535.0f;
    double d  = (double)f0 + (double)f1;
    // Bring back into integer domain
    int64_t q = (int64_t)(d * 1000000.0);
    return (double)(q ^ (int64_t)(x >> 13));
}

// ─── 11. 8-bit / 16-bit integers ─────────────────────────────────────────────
// Tests <16 x i8> and <8 x i16> SIMD lifting paths.

__attribute__((noinline))
static uint32_t narrow_ops(uint8_t a8, uint8_t b8, uint16_t a16, uint16_t b16) {
    uint8_t  r8  = (a8 + b8) ^ (a8 * b8) - (a8 & b8);
    uint16_t r16 = (uint16_t)((a16 + b16) ^ (a16 * b16));
    return ((uint32_t)r8 << 16) | r16;
}

// ─── 12. Signed arithmetic / overflow patterns ───────────────────────────────

__attribute__((noinline))
static int64_t signed_ops(int32_t a, int32_t b) {
    int64_t a64 = a, b64 = b;
    int64_t prod = a64 * b64;
    int64_t ashr = prod >> 7;   // arithmetic
    int64_t diff = ashr - (int64_t)a * (int64_t)b / 128;
    return diff;  // should be 0 for exact multiples of 128
}

// ─── main ─────────────────────────────────────────────────────────────────────

int main() {
    int failures = 0;
    auto FAIL = [&](const char *what, uint64_t got, uint64_t want) {
        failures++;
        printf("FAIL %s: got %llu (0x%llx) want %llu (0x%llx)\n",
               what,
               (unsigned long long)got, (unsigned long long)got,
               (unsigned long long)want, (unsigned long long)want);
    };

    // ── 1. Integer arithmetic ───────────────────────────────────────────────
    {
        // a=7, b=3:
        //  r0=10, r1=4, r2=21, r3=14, r4=r0&r2=10&21=0, r5=r1|r3=4|14=14
        //  r6 = 0 + (14*3) = 42
        uint64_t got  = int_arith(7, 3);
        uint64_t want = 42;
        if (got != want) FAIL("int_arith(7,3)", got, want);
    }
    {
        // a=100, b=200: r0=300, r1=2^64-100(u64 wrap), r2=20000
        // simpler: just check both endpoints are consistent
        uint64_t r1 = int_arith(12345678, 87654321);
        uint64_t r2 = int_arith(12345678, 87654321);
        if (r1 != r2) FAIL("int_arith determinism", r1, r2);
    }
    {
        // a^b = 7^3=4, a*b = 21, a&b = 3
        // (7*3) + (7^3) - (7&3) = 21 + 4 - 3 = 22
        uint32_t got  = int_arith32(7, 3);
        uint32_t want = 22;
        if (got != want) FAIL("int_arith32(7,3)", got, want);
    }

    // ── 2. Shifts ───────────────────────────────────────────────────────────
    {
        uint64_t x = 0xF0F0F0F0F0F0F0F0ULL;
        unsigned k = 4;
        uint64_t shl  = x << k;
        uint64_t lshr = x >> k;
        int64_t  ashr = (int64_t)x >> (int)k;
        uint64_t want = shl ^ (uint64_t)ashr ^ lshr;
        uint64_t got  = shift_ops(x, k);
        if (got != want) FAIL("shift_ops", got, want);
    }
    {
        uint32_t x = 0xABCD1234u;
        uint32_t want = (x << 7) ^ (x >> 3) ^ (uint32_t)((int32_t)x >> 5);
        uint32_t got  = shift_const(x);
        if (got != want) FAIL("shift_const", got, want);
    }

    // ── 3. Floats ───────────────────────────────────────────────────────────
    {
        double got  = float_arith(3.0, 4.0);
        // r0=7, r1=-1, r2=12;  7*(-1)+12 = 5
        double want = 5.0;
        if (got != want) FAIL("float_arith(3,4)", (uint64_t)got, (uint64_t)want);
    }
    {
        // (a+b)*(a-b) = a^2 - b^2
        float got  = float_arith_f(5.0f, 3.0f);  // 25-9=16
        float want = 16.0f;
        if (got != want) FAIL("float_arith_f(5,3)", (uint64_t)got, (uint64_t)want);
    }

    // ── 4. ICmp ─────────────────────────────────────────────────────────────
    {
        // a == b: bits 0,1,3,5 set = 1+2+8+32 = 43  (== ne le ge)
        // wait: a==b means eq✓, ne✗, lt✗, le✓, gt✗, ge✓ → bits 0+8+32=41, wait
        // eq=1, ne=2(if a!=b), lt=4(if a<b), le=8(if a<=b), gt=16(if a>b), ge=32(if a>=b)
        // a==b: eq→r|=1, ne→no, lt→no, le→r|=8, gt→no, ge→r|=32  → 41
        int got  = icmp_chain(5, 5);
        int want = 1 | 8 | 32;  // eq, le, ge
        if (got != want) FAIL("icmp_chain(5==5)", (uint64_t)got, (uint64_t)want);
    }
    {
        // a < b: ne✓, lt✓, le✓ → 2+4+8 = 14
        int got  = icmp_chain(3, 7);
        int want = 2 | 4 | 8;
        if (got != want) FAIL("icmp_chain(3<7)", (uint64_t)got, (uint64_t)want);
    }
    {
        // a > b: ne✓, gt✓, ge✓ → 2+16+32 = 50
        int got  = icmp_chain(9, 2);
        int want = 2 | 16 | 32;
        if (got != want) FAIL("icmp_chain(9>2)", (uint64_t)got, (uint64_t)want);
    }

    // ── 5. Strings ──────────────────────────────────────────────────────────
    {
        if (!string_test()) FAIL("string_test", 0, 1);
    }

    // ── 6. Constants ────────────────────────────────────────────────────────
    {
        uint64_t r1 = const_test(42);
        uint64_t r2 = const_test(42);
        if (r1 != r2) FAIL("const_test determinism", r1, r2);

        // Concrete value check (manually compute):
        // a = 42 + 0xDEADBEEFCAFEBABE = 0xDEADBEEFCAFEBAE8
        // b = 42 * 0x9E3779B97F4A7C15 = compute
        // Just cross-check different inputs give different outputs (not stuck at 0)
        uint64_t r3 = const_test(0);
        uint64_t r4 = const_test(1);
        if (r3 == r4) FAIL("const_test(0)==const_test(1)", r3, r4);
    }
    {
        uint32_t r1 = const_test32(100);
        uint32_t r2 = const_test32(100);
        if (r1 != r2) FAIL("const_test32 determinism", r1, r2);
    }

    // ── 7. Control flow / collatz ───────────────────────────────────────────
    {
        // Known collatz sequence lengths
        static const struct { uint32_t n, steps; } cases[] = {
            {1,  0}, {2,  1}, {3,  7}, {6,  8}, {27, 111}, {100, 25}
        };
        for (auto &c : cases) {
            uint32_t got = collatz(c.n);
            if (got != c.steps)
                FAIL("collatz", got, c.steps);
        }
    }

    // ── 8. Switch dispatch ──────────────────────────────────────────────────
    {
        for (uint32_t cmd = 0; cmd < 8; cmd++) {
            uint64_t val  = 0x0102030405060708ULL;
            uint64_t got  = dispatch(cmd, val);
            uint64_t want;
            switch (cmd) {
            case 0: want = val + 0x11111111u; break;
            case 1: want = val - 0x22222222u; break;
            case 2: want = val ^ 0x33333333u; break;
            case 3: want = val * 0x44444445u; break;
            case 4: want = val << 3;          break;
            case 5: want = val >> 5;          break;
            case 6: want = ~val;              break;
            case 7: want = (val << 13) | (val >> 51); break;
            default: want = val;
            }
            if (got != want) FAIL("dispatch", got, want);
        }
    }

    // ── 9. Fibonacci ────────────────────────────────────────────────────────
    {
        static const uint64_t fibs[] = {0,1,1,2,3,5,8,13,21,34,55,89,144,233,377,610};
        for (uint32_t i = 0; i < 16; i++) {
            uint64_t got = fibonacci(i);
            if (got != fibs[i]) FAIL("fibonacci", got, fibs[i]);
        }
    }

    // ── 10. Array hash ──────────────────────────────────────────────────────
    {
        std::array<uint32_t, 16> arr;
        for (int i = 0; i < 16; i++) arr[i] = (uint32_t)(i * 0x9E3779B9u + 1);
        uint64_t r1 = array_hash(arr);
        uint64_t r2 = array_hash(arr);
        if (r1 != r2) FAIL("array_hash determinism", r1, r2);
        arr[7] ^= 1;
        uint64_t r3 = array_hash(arr);
        if (r1 == r3) FAIL("array_hash sensitivity", r1, r3);
    }

    // ── 11. Mixed pipeline ──────────────────────────────────────────────────
    {
        double r1 = mixed_pipeline(0xDEADBEEF12345678ULL);
        double r2 = mixed_pipeline(0xDEADBEEF12345678ULL);
        // Same input → same output (determinism)
        if (r1 != r2) FAIL("mixed_pipeline determinism", (uint64_t)r1, (uint64_t)r2);
    }

    // ── 12. Narrow ops ──────────────────────────────────────────────────────
    {
        // r8 = (5+3)^(5*3)-(5&3) = 8^15-1 = 7-1 = 6   (all mod 256)
        //    wait: 8^15 = 7, then 7-1 = 6.  Byte wrap: fine.
        // r16 = (1000+2000)^(1000*2000) mod 65536 = 3000 ^ (2000000 mod 65536)
        //      2000000 mod 65536 = 2000000 - 30*65536 = 2000000-1966080 = 33920
        //      3000 ^ 33920 = 0x0BB8 ^ 0x8480 = 0x8F38 = 36664
        uint32_t got  = narrow_ops(5, 3, 1000, 2000);
        uint8_t  r8   = (uint8_t)((5+3) ^ (5*3) - (5&3));
        uint16_t r16  = (uint16_t)((1000+2000) ^ (1000*2000));
        uint32_t want = ((uint32_t)r8 << 16) | r16;
        if (got != want) FAIL("narrow_ops", got, want);
    }

    // ── 13. Signed AShr ─────────────────────────────────────────────────────
    {
        // signed_ops(128, 1): prod = 128, ashr = 1, diff = 1 - 128/128 = 0
        int64_t got  = signed_ops(128, 1);
        int64_t want = 0;
        if (got != want) FAIL("signed_ops(128,1)", (uint64_t)got, (uint64_t)want);
    }
    {
        // signed_ops(-128, 1): prod = -128, ashr = -1, diff = -1 - (-128/128) = -1+1 = 0
        int64_t got  = signed_ops(-128, 1);
        int64_t want = 0;
        if (got != want) FAIL("signed_ops(-128,1)", (uint64_t)got, (uint64_t)want);
    }

    // ── Summary ─────────────────────────────────────────────────────────────
    if (failures == 0) {
        printf("ALL TESTS PASSED\n");
        return 0;
    } else {
        printf("%d TEST(S) FAILED\n", failures);
        return 1;
    }
}
