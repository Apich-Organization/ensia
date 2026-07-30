/**
 * @file test_xtea_ecb.c
 * @brief Benchmark test: XTEA ECB (8-byte block)
 * @note angr-timeout: 600
 */
#define XTEA_SUPPORT ENABLED

#include "../../cipher/xtea.h"
#include "../common/test_harness.h"

static uint8_t g_output[8];
static uint8_t g_decrypted[8];
static const uint8_t s_pt[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

int main(void) {
  XteaContext ctx;
  error_t err;

  err = xteaInit(&ctx, TV_TEA_KEY, sizeof(TV_TEA_KEY));
  if (err != NO_ERROR) {
    test_print_result("XTEA_ECB", 0, NULL, 0);
    return 1;
  }

  TEST_MARK_START();
  xteaEncryptBlock(&ctx, s_pt, g_output);
  TEST_MARK_END();

  err = xteaInit(&ctx, TV_TEA_KEY, sizeof(TV_TEA_KEY));
  if (err != NO_ERROR) {
    test_print_result("XTEA_ECB", 0, NULL, 0);
    return 1;
  }
  xteaDecryptBlock(&ctx, g_output, g_decrypted);
  xteaDeinit(&ctx);

  int ok = (ct_memcmp(g_decrypted, s_pt, 8) == 0);
  test_print_result("XTEA_ECB", ok, g_output, 8);
  return ok ? 0 : 1;
}
