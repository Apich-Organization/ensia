/**
 * @file test_rc4_stream.c
 * @brief Benchmark test: RC4 stream cipher
 * @note angr-timeout: 600
 */
#undef RC4_SUPPORT
#define RC4_SUPPORT ENABLED

#include "../../cipher/rc4.h"
#include "../common/test_harness.h"

static uint8_t g_output[32];
static uint8_t g_decrypted[32];

int main(void) {
  Rc4Context ctx;
  error_t err;

  err = rc4Init(&ctx, TV_RC4_KEY, sizeof(TV_RC4_KEY));
  if (err != NO_ERROR) {
    test_print_result("RC4_STREAM", 0, NULL, 0);
    return 1;
  }

  TEST_MARK_START();
  rc4Cipher(&ctx, TV_MSG_32, g_output, sizeof(TV_MSG_32));
  TEST_MARK_END();

  /* Decrypt: RC4 is its own inverse when re-initialized */
  err = rc4Init(&ctx, TV_RC4_KEY, sizeof(TV_RC4_KEY));
  if (err != NO_ERROR) {
    test_print_result("RC4_STREAM", 0, NULL, 0);
    return 1;
  }
  rc4Cipher(&ctx, g_output, g_decrypted, 32);
  rc4Deinit(&ctx);

  int ok = (ct_memcmp(g_decrypted, TV_MSG_32, 32) == 0);
  test_print_result("RC4_STREAM", ok, g_output, 16);
  return ok ? 0 : 1;
}
