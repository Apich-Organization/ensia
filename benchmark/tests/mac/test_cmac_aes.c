/**
 * @file test_cmac_aes.c
 * @brief Benchmark test: CMAC-AES-128
 * @note angr-timeout: 600
 *
 * cmacInit(ctx, cipher, key, keyLen) — takes key directly (4 args).
 * cmacFinal(ctx, mac, macLen)        — 3 args.
 */
#define CMAC_SUPPORT ENABLED
#define AES_SUPPORT ENABLED

#include "../../cipher/aes.h"
#include "../../mac/cmac.h"
#include "../common/test_harness.h"

static uint8_t g_output[16];

int main(void) {
  CmacContext ctx;
  error_t err;
  static const uint8_t s_zeros[16] = {0};

  err = cmacInit(&ctx, AES_CIPHER_ALGO, TV_AES128_KEY, sizeof(TV_AES128_KEY));
  if (err != NO_ERROR) {
    test_print_result("CMAC_AES", 0, NULL, 0);
    return 1;
  }

  TEST_MARK_START();
  cmacUpdate(&ctx, TV_MSG_32, sizeof(TV_MSG_32));
  err = cmacFinal(&ctx, g_output, sizeof(g_output));
  TEST_MARK_END();

  int ok = (err == NO_ERROR) && (ct_memcmp(g_output, s_zeros, 16) != 0);
  test_print_result("CMAC_AES", ok, g_output, 16);
  return ok ? 0 : 1;
}
