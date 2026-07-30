/**
 * @file test_rc6_ecb.c
 * @brief Benchmark test: RC6_ECB
 * @note angr-timeout: 600
 */
#define RC6_SUPPORT ENABLED

#include "../../cipher/rc6.h"
#include "../common/test_harness.h"

static uint8_t g_output[16];
static uint8_t g_decrypted[16];
static const uint8_t s_plaintext[16] = {0x10};

int main(void) {
  Rc6Context ctx;
  error_t err;
  static const uint8_t s_pt[16] = {0};

  err = rc6Init(&ctx, TV_RC6_KEY, sizeof(TV_RC6_KEY));
  if (err != NO_ERROR) {
    test_print_result("RC6_ECB", 0, NULL, 0);
    return 1;
  }

  TEST_MARK_START();
  rc6EncryptBlock(&ctx, s_pt, g_output);
  TEST_MARK_END();

  err = rc6Init(&ctx, TV_RC6_KEY, sizeof(TV_RC6_KEY));
  if (err != NO_ERROR) {
    test_print_result("RC6_ECB", 0, NULL, 0);
    return 1;
  }
  rc6DecryptBlock(&ctx, g_output, g_decrypted);
  rc6Deinit(&ctx);

  int ok = (ct_memcmp(g_decrypted, s_pt, 16) == 0);
  test_print_result("RC6_ECB", ok, g_output, 16);
  return ok ? 0 : 1;
}
