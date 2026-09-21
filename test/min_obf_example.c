#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 1. Substitution & MBA target: arithmetic and bitwise ops
__attribute__((noinline)) int32_t test_arithmetic(int32_t a, int32_t b) {
  int32_t x = a + b;
  int32_t y = a - b;
  int32_t z = x ^ y;
  int32_t w = (x & y) | (z * 3);
  return w ^ (a << 2);
}

// 2. Constant Encryption target: various integer constants
__attribute__((noinline)) uint32_t test_constants(uint32_t x) {
  uint32_t c1 = 0x12345678;
  uint32_t c2 = 0xDEADBEEF;
  uint32_t c3 = 1337;
  return (x ^ c1) + (x * c3) - c2;
}

// 3. String Encryption target: string literals
__attribute__((noinline)) const char *test_strings(int choice) {
  if (choice == 1) {
    return "SEC_FLAG{Ensia_StrEnc_Pass_Active}";
  } else if (choice == 2) {
    return "CRITICAL_SYSTEM_TOKEN_9988";
  }
  return "DEFAULT_VERIFICATION_STRING";
}

// 4. Split Basic Blocks & Vector Obfuscation target: sequential ops & scalar
// math
__attribute__((noinline)) int32_t test_sequential_math(int32_t a, int32_t b,
                                                       int32_t c) {
  int32_t v1 = a + b;
  int32_t v2 = v1 ^ c;
  int32_t v3 = v2 * 5;
  int32_t v4 = v3 - a;
  int32_t v5 = v4 & b;
  int32_t v6 = v5 | c;
  int32_t v7 = v6 + 42;
  int32_t v8 = v7 ^ 0x55;
  return v8;
}

// 5. Control Flow: BCF, Flattening (CFF), ChaosStateMachine (CSM),
// IndirectBranch
__attribute__((noinline)) int32_t test_control_flow(int32_t val,
                                                    int32_t iters) {
  int32_t acc = val;
  for (int i = 0; i < iters; i++) {
    if (acc % 2 == 0) {
      acc = acc / 2 + 3;
    } else if (acc % 3 == 0) {
      acc = acc * 3 + 1;
    } else {
      acc = acc + 7;
    }
  }
  return acc;
}

// 6. Function Call Obfuscate & Function Wrapper target: external & direct calls
__attribute__((noinline)) int test_function_calls(int x) {
  // Calling external libc function
  printf("Called with x=%d\n", x);
  // Calling local function
  return test_arithmetic(x, 10);
}

// 7. Nested loops and complex branch target
__attribute__((noinline)) int32_t test_nested_loops(int32_t n, int32_t m) {
  int32_t total = 0;
  for (int i = 0; i < n; i++) {
    for (int j = 0; j < m; j++) {
      if ((i + j) % 2 == 0) {
        total += (i * j) ^ (i + j);
      } else {
        total -= (i ^ j) + 1;
      }
    }
  }
  return total;
}

// 8. Switch statement lowering & CSM target
__attribute__((noinline)) int32_t test_switch_dispatch(int32_t key,
                                                       int32_t val) {
  switch (key) {
  case 10:
    return val * 3 + 1;
  case 20:
    return val ^ 0x55AA55AA;
  case 30:
    return (val << 3) - (val >> 2);
  case 40:
    return val / 5 + 7;
  case 50:
    return val % 13;
  default:
    return val ^ key;
  }
}

// 9. Edge arithmetic & bitwise invariants
__attribute__((noinline)) int32_t test_edge_arithmetic(int32_t a) {
  int32_t r1 = a ^ -1;
  int32_t r2 =
      (int32_t)(((uint32_t)a << 5) | ((uint32_t)a >> 27)); // rotate left 5
  int32_t r3 = (a & 0x0F0F0F0F) * 3;
  return r1 + r2 - r3;
}

int main(int argc, char **argv) {
  int val = argc > 1 ? atoi(argv[1]) : 7;
  printf("[*] Starting Minimal Obfuscation Verification...\n");

  int32_t r_math = test_arithmetic(val, 20);
  uint32_t r_const = test_constants((uint32_t)val);
  const char *r_str = test_strings(val % 3);
  int32_t r_seq = test_sequential_math(val, 15, 25);
  int32_t r_cfg = test_control_flow(val, 5);
  int r_call = test_function_calls(val);
  int32_t r_nested = test_nested_loops(4, 5);
  int32_t r_switch = test_switch_dispatch(30, val);
  int32_t r_edge = test_edge_arithmetic(val);

  printf("Results: math=%d, const=0x%x, str=%s, seq=%d, cfg=%d, call=%d, "
         "nested=%d, switch=%d, edge=%d\n",
         r_math, r_const, r_str, r_seq, r_cfg, r_call, r_nested, r_switch,
         r_edge);

  if (val == 7) {
    if (r_math != -89 || r_const != 0x3386bc1f ||
        strcmp(r_str, "SEC_FLAG{Ensia_StrEnc_Pass_Active}") != 0 ||
        r_seq != 18 || r_cfg != 14 || r_call != -55 || r_nested != 16 ||
        r_switch != 55 || r_edge != 195) {
      fprintf(stderr, "[-] FAILED: Value mismatch during verification!\n");
      return 1;
    }
  }

  if (r_math != 0 && r_str != NULL) {
    printf("[+] All basic tests executed successfully!\n");
    return 0;
  }
  return 1;
}
