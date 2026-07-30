/**
 * @file test_xcbc_mac.c
 * @brief Benchmark test: AES-XCBC-MAC-96 (RFC 3566)
 * @note angr-timeout: 600
 *
 * xcbcMacInit(ctx, cipher, key, keyLen) — 4 args, takes key directly.
 * xcbcMacFinal(ctx, mac, macLen)        — 3 args.
 */
#define XCBC_MAC_SUPPORT ENABLED
#define AES_SUPPORT ENABLED

#include "../../cipher/aes.h"
#include "../../mac/xcbc_mac.h"
#include "../common/test_harness.h"

static uint8_t g_output[16];

int main(void) {
  XcbcMacContext ctx;
  error_t err;
  static const uint8_t s_zeros[16] = {0};

  err =
      xcbcMacInit(&ctx, AES_CIPHER_ALGO, TV_AES128_KEY, sizeof(TV_AES128_KEY));
  if (err != NO_ERROR) {
    test_print_result("XCBC_MAC", 0, NULL, 0);
    return 1;
  }

  TEST_MARK_START();
  xcbcMacUpdate(&ctx, TV_MSG_32, sizeof(TV_MSG_32));
  err = xcbcMacFinal(&ctx, g_output, sizeof(g_output));
  TEST_MARK_END();

  int ok = (err == NO_ERROR) && (ct_memcmp(g_output, s_zeros, 16) != 0);
  test_print_result("XCBC_MAC", ok, g_output, 16);
  return ok ? 0 : 1;
}
