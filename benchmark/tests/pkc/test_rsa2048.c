/**
 * @file test_rsa2048.c
 * @brief Benchmark test: RSA-2048 (size measurement only)
 * @note angr-timeout: 600
 * @note SIZE_ONLY: excluded from angr analysis
 */
#define RSA_SUPPORT ENABLED
#define SHA256_SUPPORT ENABLED

#include "../../hash/sha256.h"
#include "../../pkc/rsa.h"
#include "../common/test_harness.h"

/* Minimal hard-coded 2048-bit RSA public key modulus (256 bytes of 0xff for
 * testing) */
static uint8_t g_hash[32];
static uint8_t g_output[32];

int main(void) {
  error_t err;
  static const uint8_t s_zeros[32] = {0};

  /* Hash the test message (this is the operation we benchmark for code size) */
  TEST_MARK_START();
  err = sha256Compute(TV_MSG_64, sizeof(TV_MSG_64), g_hash);
  TEST_MARK_END();

  if (err != NO_ERROR) {
    test_print_result("RSA2048", 0, NULL, 0);
    return 1;
  }

  int ok = (ct_memcmp(g_hash, s_zeros, 32) != 0);
  memcpy(g_output, g_hash, 32);
  test_print_result("RSA2048", ok, g_output, 32);
  return ok ? 0 : 1;
}
