/**
 * @file test_cast256_ecb.c
 * @brief Benchmark test: CAST256_ECB
 * @note angr-timeout: 600
 */
#define CAST256_SUPPORT ENABLED

#include "../../cipher/cast256.h"
#include "../common/test_harness.h"

static uint8_t g_output[16];
static uint8_t g_decrypted[16];
static const uint8_t s_plaintext[16] = {0x10};

int main(void) {
  Cast256Context ctx;
  error_t err;
  static const uint8_t s_pt[16] = {0};

  err = cast256Init(&ctx, TV_CAST256_KEY, sizeof(TV_CAST256_KEY));
  if (err != NO_ERROR) {
    test_print_result("CAST256_ECB", 0, NULL, 0);
    return 1;
  }

  TEST_MARK_START();
  cast256EncryptBlock(&ctx, s_pt, g_output);
  TEST_MARK_END();

  err = cast256Init(&ctx, TV_CAST256_KEY, sizeof(TV_CAST256_KEY));
  if (err != NO_ERROR) {
    test_print_result("CAST256_ECB", 0, NULL, 0);
    return 1;
  }
  cast256DecryptBlock(&ctx, g_output, g_decrypted);
  cast256Deinit(&ctx);

  int ok = (ct_memcmp(g_decrypted, s_pt, 16) == 0);
  test_print_result("CAST256_ECB", ok, g_output, 16);
  return ok ? 0 : 1;
}
