/**
 * @file test_hmac_sha256.c
 * @brief Benchmark test: HMAC-SHA-256
 * @note angr-timeout: 600
 */
#define HMAC_SUPPORT ENABLED
#define SHA256_SUPPORT ENABLED

#include "../../hash/hash_algorithms.h"
#include "../../mac/hmac.h"
#include "../common/test_harness.h"

static uint8_t g_output[32];

int main(void) {
  HmacContext ctx;
  error_t err;
  static const uint8_t s_zeros[32] = {0};

  err =
      hmacInit(&ctx, SHA256_HASH_ALGO, TV_HMAC_KEY_32, sizeof(TV_HMAC_KEY_32));
  if (err != NO_ERROR) {
    test_print_result("HMAC_SHA256", 0, NULL, 0);
    return 1;
  }

  TEST_MARK_START();
  hmacUpdate(&ctx, TV_MSG_32, sizeof(TV_MSG_32));
  hmacFinal(&ctx, g_output);
  TEST_MARK_END();

  int ok = (ct_memcmp(g_output, s_zeros, 32) != 0);
  test_print_result("HMAC_SHA256", ok, g_output, 32);
  return ok ? 0 : 1;
}
