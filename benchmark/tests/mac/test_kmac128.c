/**
 * @file test_kmac128.c
 * @brief Benchmark test: KMAC128 (NIST SP 800-185)
 * @note angr-timeout: 600
 */
#define KMAC_SUPPORT ENABLED
#define CSHAKE128_SUPPORT ENABLED
#define KECCAK_SUPPORT ENABLED

#include "../../mac/kmac.h"
#include "../common/test_harness.h"

static uint8_t g_output[32];

int main(void) {
  error_t err;
  static const uint8_t s_zeros[32] = {0};

  TEST_MARK_START();
  err = kmacCompute(128, TV_HMAC_KEY_32, sizeof(TV_HMAC_KEY_32), TV_MSG_32,
                    sizeof(TV_MSG_32), NULL, 0, g_output, sizeof(g_output));
  TEST_MARK_END();

  if (err != NO_ERROR) {
    test_print_result("KMAC128", 0, NULL, 0);
    return 1;
  }

  int ok = (ct_memcmp(g_output, s_zeros, 32) != 0);
  test_print_result("KMAC128", ok, g_output, 32);
  return ok ? 0 : 1;
}
