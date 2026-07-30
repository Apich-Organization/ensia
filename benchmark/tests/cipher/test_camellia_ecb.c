/**
 * @file test_camellia_ecb.c
 * @brief Benchmark test: CAMELLIA_ECB
 * @note angr-timeout: 600
 */
#define CAMELLIA_SUPPORT ENABLED

#include "../../cipher/camellia.h"
#include "../common/test_harness.h"

static uint8_t g_output[16];
static uint8_t g_decrypted[16];
static const uint8_t s_plaintext[16] = {0x10};

int main(void) {
  CamelliaContext ctx;
  error_t err;
  static const uint8_t s_pt[16] = {0};

  err = camelliaInit(&ctx, TV_CAMELLIA_KEY, sizeof(TV_CAMELLIA_KEY));
  if (err != NO_ERROR) {
    test_print_result("CAMELLIA_ECB", 0, NULL, 0);
    return 1;
  }

  TEST_MARK_START();
  camelliaEncryptBlock(&ctx, s_pt, g_output);
  TEST_MARK_END();

  err = camelliaInit(&ctx, TV_CAMELLIA_KEY, sizeof(TV_CAMELLIA_KEY));
  if (err != NO_ERROR) {
    test_print_result("CAMELLIA_ECB", 0, NULL, 0);
    return 1;
  }
  camelliaDecryptBlock(&ctx, g_output, g_decrypted);
  camelliaDeinit(&ctx);

  int ok = (ct_memcmp(g_decrypted, s_pt, 16) == 0);
  test_print_result("CAMELLIA_ECB", ok, g_output, 16);
  return ok ? 0 : 1;
}
