/**
 * @file test_sha512.c
 * @brief Benchmark test: SHA512
 * @note angr-timeout: 600
 */
#define SHA512_SUPPORT ENABLED

#include "../../hash/sha512.h"
#include "../common/test_harness.h"

static uint8_t g_output[64];

int main(void) {
  error_t err;
  static const uint8_t s_zeros[64] = {0};

  TEST_MARK_START();
  err = sha512Compute(TV_MSG_ABC, sizeof(TV_MSG_ABC), g_output);
  TEST_MARK_END();

  if (err != NO_ERROR) {
    test_print_result("SHA512", 0, NULL, 0);
    return 1;
  }

  /* Verify output is non-zero */
  int ok = (ct_memcmp(g_output, s_zeros, 64) != 0);
  test_print_result("SHA512", ok, g_output, 64);
  return ok ? 0 : 1;
}
