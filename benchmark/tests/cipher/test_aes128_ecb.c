/**
 * @file test_aes128_ecb.c
 * @brief Benchmark test: AES-128 ECB
 * @note angr-timeout: 600
 */
#define AES_SUPPORT ENABLED

#include "../../cipher/aes.h"
#include "../common/test_harness.h"

static uint8_t g_output[16];
static uint8_t g_decrypted[16];

int main(void) {
  AesContext ctx;
  error_t err;

  err = aesInit(&ctx, TV_AES128_KEY, sizeof(TV_AES128_KEY));
  if (err != NO_ERROR) {
    test_print_result("AES128_ECB", 0, NULL, 0);
    return 1;
  }

  TEST_MARK_START();
  aesEncryptBlock(&ctx, TV_AES_PLAINTEXT, g_output);
  TEST_MARK_END();

  /* Known-answer check (FIPS 197 Appendix B) */
  if (ct_memcmp(g_output, TV_AES128_ECB_CT, 16) != 0) {
    test_print_result("AES128_ECB", 0, g_output, 16);
    aesDeinit(&ctx);
    return 1;
  }

  /* Round-trip */
  err = aesInit(&ctx, TV_AES128_KEY, sizeof(TV_AES128_KEY));
  if (err != NO_ERROR) {
    test_print_result("AES128_ECB", 0, NULL, 0);
    return 1;
  }
  aesDecryptBlock(&ctx, g_output, g_decrypted);
  aesDeinit(&ctx);

  int ok = (ct_memcmp(g_decrypted, TV_AES_PLAINTEXT, 16) == 0);
  test_print_result("AES128_ECB", ok, g_output, 16);
  return ok ? 0 : 1;
}
