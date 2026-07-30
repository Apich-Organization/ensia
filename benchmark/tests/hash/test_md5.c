/**
 * @file test_md5.c
 * @brief Benchmark test: MD5
 * @note angr-timeout: 600
 */
#define MD5_SUPPORT ENABLED

#include "../../hash/md5.h"
#include "../common/test_harness.h"

static uint8_t g_output[16];

int main(void) {
  error_t err;
  static const uint8_t s_zeros[16] = {0};

  TEST_MARK_START();
  err = md5Compute(TV_MSG_ABC, sizeof(TV_MSG_ABC), g_output);
  TEST_MARK_END();

  if (err != NO_ERROR) {
    test_print_result("MD5", 0, NULL, 0);
    return 1;
  }

  /* Known-answer test for MD5("abc") */
  static const uint8_t s_expected[16] = {0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2,
                                         0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d,
                                         0x28, 0xe1, 0x7f, 0x72};
  if (ct_memcmp(g_output, s_expected, 16) != 0) {
    test_print_result("MD5", 0, g_output, 16);
    return 1;
  }

  /* Verify output is non-zero */
  int ok = (ct_memcmp(g_output, s_zeros, 16) != 0);
  test_print_result("MD5", ok, g_output, 16);
  return ok ? 0 : 1;
}
