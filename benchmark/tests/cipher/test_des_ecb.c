/**
 * @file test_des_ecb.c
 * @brief Benchmark test: DES ECB
 * @note angr-timeout: 600
 */
#define DES_SUPPORT ENABLED

#include "../../cipher/des.h"
#include "../common/test_harness.h"

static uint8_t g_output[8];
static uint8_t g_decrypted[8];
static const uint8_t s_pt[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

int main(void) {
  DesContext ctx;
  error_t err;

  err = desInit(&ctx, TV_DES_KEY, sizeof(TV_DES_KEY));
  if (err != NO_ERROR) {
    test_print_result("DES_ECB", 0, NULL, 0);
    return 1;
  }

  TEST_MARK_START();
  desEncryptBlock(&ctx, s_pt, g_output);
  TEST_MARK_END();

  err = desInit(&ctx, TV_DES_KEY, sizeof(TV_DES_KEY));
  if (err != NO_ERROR) {
    test_print_result("DES_ECB", 0, NULL, 0);
    return 1;
  }
  desDecryptBlock(&ctx, g_output, g_decrypted);
  desDeinit(&ctx);

  int ok = (ct_memcmp(g_decrypted, s_pt, 8) == 0);
  test_print_result("DES_ECB", ok, g_output, 8);
  return ok ? 0 : 1;
}
