/**
 * @file test_cshake128.c
 * @brief Benchmark test: cSHAKE128 (NIST SP 800-185)
 * @note angr-timeout: 600
 */
#define CSHAKE128_SUPPORT ENABLED
#define KECCAK_SUPPORT ENABLED

#include "../../xof/cshake.h"
#include "../../xof/keccak.h"
#include "../common/test_harness.h"

static uint8_t g_output[32];

int main(void) {
  error_t err;
  static const uint8_t s_zeros[32] = {0};
  /* Function name string "Benchmark", customization string "" */
  static const uint8_t s_fname[] = "Benchmark";

  TEST_MARK_START();
  err =
      cshakeCompute(128, TV_MSG_32, sizeof(TV_MSG_32), (const char_t *)s_fname,
                    sizeof(s_fname) - 1, NULL, 0, g_output, sizeof(g_output));
  TEST_MARK_END();

  if (err != NO_ERROR) {
    test_print_result("CSHAKE128", 0, NULL, 0);
    return 1;
  }

  int ok = (ct_memcmp(g_output, s_zeros, 32) != 0);
  test_print_result("CSHAKE128", ok, g_output, 32);
  return ok ? 0 : 1;
}
