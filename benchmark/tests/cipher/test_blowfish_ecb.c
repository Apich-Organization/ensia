/**
 * @file test_blowfish_ecb.c
 * @brief Benchmark test: BLOWFISH_ECB
 * @note angr-timeout: 600
 */
#define BLOWFISH_SUPPORT ENABLED

#include "../../cipher/blowfish.h"
#include "../common/test_harness.h"

static uint8_t g_output[8];
static uint8_t g_decrypted[8];
static const uint8_t s_plaintext[8] = {0x08};

int main(void) {
  BlowfishContext ctx;
  error_t err;
  static const uint8_t s_pt[8] = {0};

  err = blowfishInit(&ctx, TV_BLOWFISH_KEY, sizeof(TV_BLOWFISH_KEY));
  if (err != NO_ERROR) {
    test_print_result("BLOWFISH_ECB", 0, NULL, 0);
    return 1;
  }

  TEST_MARK_START();
  blowfishEncryptBlock(&ctx, s_pt, g_output);
  TEST_MARK_END();

  err = blowfishInit(&ctx, TV_BLOWFISH_KEY, sizeof(TV_BLOWFISH_KEY));
  if (err != NO_ERROR) {
    test_print_result("BLOWFISH_ECB", 0, NULL, 0);
    return 1;
  }
  blowfishDecryptBlock(&ctx, g_output, g_decrypted);
  blowfishDeinit(&ctx);

  int ok = (ct_memcmp(g_decrypted, s_pt, 8) == 0);
  test_print_result("BLOWFISH_ECB", ok, g_output, 8);
  return ok ? 0 : 1;
}
