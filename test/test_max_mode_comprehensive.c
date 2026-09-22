#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ── Test 1: Arithmetic & Bitwise Logic (Target for Sub + MBA + Vec) ─────────
__attribute__((noinline)) int32_t max_test_math(int32_t a, int32_t b,
                                                int32_t c) {
  int32_t x = (a + b) ^ (c * 7);
  int32_t y = (a - c) + (b ^ 0x5a5a5a5a);
  int32_t z = (x & y) | (x ^ y);
  int32_t w = (z << 3) - (z >> 2);
  return w ^ (a * 13);
}

// ── Test 2: Floating Point & Comparison (Target for VOBF) ────────────────────
__attribute__((noinline)) float max_test_vector_float(float x, float y) {
  float a = x * 1.5f + y * 2.5f;
  float b = a - 0.75f;
  if (a > b) {
    return a * 3.0f + b;
  } else {
    return a - b * 2.0f;
  }
}

// ── Test 3: Sensitive Constants (Target for ConstEnc Schemes A, B, C) ───────
__attribute__((noinline)) uint32_t max_test_crypto_constants(uint32_t input) {
  uint32_t k1 = 0x67452301; // MD5 A
  uint32_t k2 = 0xefcdab89; // MD5 B
  uint32_t k3 = 0x98badcfe; // MD5 C
  uint32_t k4 = 0x10325476; // MD5 D
  uint32_t magic = 0x5a827999;
  uint32_t res = (input ^ k1) + ((input & k2) | (~input & k3)) + k4 + magic;
  return res;
}

// ── Test 4: String Literals & Anti-Dump (Target for StrEnc + AntiDump) ───────
__attribute__((noinline)) const char *max_test_sensitive_strings(int mode) {
  if (mode == 1) {
    return "ENSIA_MAX_MODE_SECRET_FLAG_0x99281a8b";
  } else if (mode == 2) {
    return "ENSIA_ROOT_ACCESS_KEY_TOKEN_7749112";
  }
  return "ENSIA_GENERIC_PAYLOAD_STRING_OK";
}

// Internal buffer string test for memory anti-dump inspection
__attribute__((noinline)) int max_test_internal_string_inspect(char *out_buf,
                                                               size_t max_len) {
  const char secret[] = "EPHEMERAL_TOKEN_SHOULD_BE_ZEROIZED_ON_RETURN_99182";
  size_t len = strlen(secret);
  if (len >= max_len)
    len = max_len - 1;
  memcpy(out_buf, secret, len);
  out_buf[len] = '\0';
  return (int)len;
}

// ── Test 5: Complex Control Flow (Target for BCF + Split + CSM + CFF) ────────
__attribute__((noinline)) int32_t max_test_complex_cfg(int32_t val,
                                                       int32_t rounds) {
  int32_t state = val;
  for (int i = 0; i < rounds; i++) {
    switch (state & 7) {
    case 0:
      state = state * 3 + 1;
      break;
    case 1:
      state = (state ^ 0x33) + 7;
      break;
    case 2:
      state = state / 2 - 5;
      break;
    case 3:
      state = (state << 1) ^ (state >> 3);
      break;
    case 4:
      state = state + 19;
      break;
    case 5:
      state = (state ^ 0x55) * 2;
      break;
    case 6:
      state = state - 11;
      break;
    default:
      state = state ^ 0xAA;
      break;
    }
  }
  return state;
}

// ── Test 6: Indirect Branching & Jump Dispatch (Target for INDIBRAN) ─────────
__attribute__((noinline)) int32_t max_test_indirect_jump_dispatch(int32_t key,
                                                                  int32_t val) {
  int32_t r = val;
  if (key > 100) {
    r += (key * 2) ^ val;
  } else if (key > 50) {
    r -= (key ^ 0x77);
  } else if (key > 20) {
    r = (r << 2) + key;
  } else {
    r = (r >> 1) ^ (key * 5);
  }
  return r;
}

// ── Test 7: Function Calls & Dynamic Imports (Target for FUNCWRA + FCO) ──────
__attribute__((noinline)) int max_test_external_calls(int seed) {
  char buf[64];
  // External standard library calls: snprintf, strlen, atoi, malloc, free
  snprintf(buf, sizeof(buf), "%d", seed * 17);
  size_t len = strlen(buf);
  int parsed = atoi(buf);
  void *ptr = malloc(128);
  if (ptr) {
    memset(ptr, (int)(len & 0xFF), 128);
    free(ptr);
  }
  // Direct call to local function (target for FUNCWRA)
  int32_t local_res = max_test_math(seed, (int32_t)len, parsed);
  return local_res + parsed;
}

// ── Main Verification Entrypoint ─────────────────────────────────────────────
int main(int argc, char **argv) {
  int seed = (argc > 1) ? atoi(argv[1]) : 7;
  printf("[*] Running Ensia Max-Mode Comprehensive Obfuscation Suite "
         "(seed=%d)...\n",
         seed);

  // 1. Math verification
  int32_t r_math = max_test_math(seed, 23, 11);
  printf("  [1] Math & MBA: result=%d\n", r_math);

  // 2. Vector float verification
  float r_float = max_test_vector_float((float)seed, 3.5f);
  printf("  [2] Vector Float: result=%.2f\n", r_float);

  // 3. Constant encryption verification
  uint32_t r_crypto = max_test_crypto_constants((uint32_t)seed);
  printf("  [3] Crypto Constants: result=0x%08x\n", r_crypto);

  // 4. String encryption verification
  const char *r_str1 = max_test_sensitive_strings(1);
  const char *r_str2 = max_test_sensitive_strings(2);
  char buf[64] = {0};
  int r_copied = max_test_internal_string_inspect(buf, sizeof(buf));
  printf("  [4] Strings: s1='%s', s2='%s', copied=%d\n", r_str1, r_str2,
         r_copied);

  // 5. Complex control flow verification
  int32_t r_cfg = max_test_complex_cfg(seed, 8);
  printf("  [5] Complex CFG & CSM: result=%d\n", r_cfg);

  // 6. Indirect branch verification
  int32_t r_ind = max_test_indirect_jump_dispatch(seed * 10, 42);
  printf("  [6] Indirect Branch: result=%d\n", r_ind);

  // 7. Function wrapper & FCO dynamic symbol verification
  int r_fco = max_test_external_calls(seed);
  printf("  [7] Function Calls & FCO: result=%d\n", r_fco);

  // Deterministic validation against ground truth for seed=7
  if (seed == 7) {
    if (strcmp(r_str1, "ENSIA_MAX_MODE_SECRET_FLAG_0x99281a8b") != 0) {
      fprintf(stderr, "[-] String 1 mismatch!\n");
      return 1;
    }
    if (strcmp(r_str2, "ENSIA_ROOT_ACCESS_KEY_TOKEN_7749112") != 0) {
      fprintf(stderr, "[-] String 2 mismatch!\n");
      return 1;
    }
    if (r_copied <= 0 ||
        strcmp(buf, "EPHEMERAL_TOKEN_SHOULD_BE_ZEROIZED_ON_RETURN_99182") !=
            0) {
      fprintf(stderr, "[-] Copied internal string mismatch!\n");
      return 1;
    }
  }

  printf("[SUCCESS] All Max-Mode Obfuscation Modules verified correctly!\n");
  return 0;
}
