/**
 * @file test_ascon_aead128.c
 * @brief Benchmark test: ASCON-AEAD128 (NIST LWC winner)
 * @note angr-timeout: 600
 */
#define ASCON_SUPPORT ENABLED
#define ASCON_AEAD128_SUPPORT ENABLED

#include "../../lwc/ascon.h"
#include "../../lwc/ascon_aead128.h"
#include "../common/test_harness.h"

static uint8_t g_ct[16];
static uint8_t g_tag[16];
static uint8_t g_pt[16];
static uint8_t g_output[16];

int main(void) {
  error_t err;

  TEST_MARK_START();
  err = asconAead128Encrypt(TV_ASCON_KEY, sizeof(TV_ASCON_KEY), TV_ASCON_NONCE,
                            sizeof(TV_ASCON_NONCE), TV_AAD, sizeof(TV_AAD),
                            TV_MSG_16, g_ct, sizeof(TV_MSG_16), g_tag,
                            sizeof(g_tag));
  TEST_MARK_END();

  if (err != NO_ERROR) {
    test_print_result("ASCON_AEAD128", 0, NULL, 0);
    return 1;
  }

  err =
      asconAead128Decrypt(TV_ASCON_KEY, sizeof(TV_ASCON_KEY), TV_ASCON_NONCE,
                          sizeof(TV_ASCON_NONCE), TV_AAD, sizeof(TV_AAD), g_ct,
                          g_pt, sizeof(TV_MSG_16), g_tag, sizeof(g_tag));

  int ok = (err == NO_ERROR) && (ct_memcmp(g_pt, TV_MSG_16, 16) == 0);
  memcpy(g_output, g_tag, 16);
  test_print_result("ASCON_AEAD128", ok, g_output, 16);
  return ok ? 0 : 1;
}
