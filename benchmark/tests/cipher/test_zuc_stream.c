/**
 * @file test_zuc_stream.c
 * @brief Benchmark test: ZUC stream cipher (128-EEA3)
 * @note angr-timeout: 600
 */
#define ZUC_SUPPORT ENABLED

#include "../../cipher/zuc.h"
#include "../common/test_harness.h"

static uint8_t g_output[32];
static uint8_t g_decrypted[32];

int main(void) {
  ZucContext ctx;
  error_t err;

  err = zucInit(&ctx, TV_ZUC_KEY, sizeof(TV_ZUC_KEY), TV_ZUC_IV,
                sizeof(TV_ZUC_IV));
  if (err != NO_ERROR) {
    test_print_result("ZUC_STREAM", 0, NULL, 0);
    return 1;
  }

  TEST_MARK_START();
  zucCipher(&ctx, TV_MSG_32, g_output, sizeof(TV_MSG_32));
  TEST_MARK_END();

  err = zucInit(&ctx, TV_ZUC_KEY, sizeof(TV_ZUC_KEY), TV_ZUC_IV,
                sizeof(TV_ZUC_IV));
  if (err != NO_ERROR) {
    test_print_result("ZUC_STREAM", 0, NULL, 0);
    return 1;
  }
  zucCipher(&ctx, g_output, g_decrypted, 32);
  zucDeinit(&ctx);

  int ok = (ct_memcmp(g_decrypted, TV_MSG_32, 32) == 0);
  test_print_result("ZUC_STREAM", ok, g_output, 16);
  return ok ? 0 : 1;
}
