/**
 * @file test_sha3_256.c
 * @brief Benchmark test: SHA3_256
 * @note angr-timeout: 600
 */
#define SHA3_256_SUPPORT ENABLED
#define KECCAK_SUPPORT ENABLED

#include "../../hash/sha3_256.h"
#include "../common/test_harness.h"

static uint8_t g_output[32];

int main(void) {
  error_t err;
  static const uint8_t s_zeros[32] = {0};

  TEST_MARK_START();
  err = sha3_256Compute(TV_MSG_ABC, sizeof(TV_MSG_ABC), g_output);
  TEST_MARK_END();

  if (err != NO_ERROR) {
    test_print_result("SHA3_256", 0, NULL, 0);
    return 1;
  }

  /* Verify output is non-zero */
  int ok = (ct_memcmp(g_output, s_zeros, 32) != 0);
  test_print_result("SHA3_256", ok, g_output, 32);
  return ok ? 0 : 1;
}
