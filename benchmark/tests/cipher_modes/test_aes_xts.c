/**
 * @file test_aes_xts.c
 * @brief Benchmark test: AES-XTS (IEEE 1619)
 * @note angr-timeout: 600
 */
#define XTS_SUPPORT ENABLED
#define AES_SUPPORT ENABLED

#include "../../cipher/aes.h"
#include "../../cipher_modes/xts.h"
#include "../common/test_harness.h"

static uint8_t g_ct[32];
static uint8_t g_pt[32];
static uint8_t g_output[32];

int main(void) {
  AesContext aesCtx1, aesCtx2;
  XtsContext xtsCtx;
  error_t err;
  /* Sector number (tweak) = 128-bit little-endian sector index */
  static const uint8_t s_sector[16] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00};

  /* XTS-AES-256: TV_XTS_KEY = 32 bytes = key1[16] || key2[16] */
  err = aesInit(&aesCtx1, TV_XTS_KEY, 16);
  if (err != NO_ERROR) {
    test_print_result("AES_XTS", 0, NULL, 0);
    return 1;
  }
  err = aesInit(&aesCtx2, TV_XTS_KEY + 16, 16);
  if (err != NO_ERROR) {
    test_print_result("AES_XTS", 0, NULL, 0);
    return 1;
  }
  err = xtsInit(&xtsCtx, AES_CIPHER_ALGO, &aesCtx1, &aesCtx2);
  if (err != NO_ERROR) {
    test_print_result("AES_XTS", 0, NULL, 0);
    return 1;
  }

  TEST_MARK_START();
  err = xtsEncrypt(&xtsCtx, s_sector, TV_MSG_32, g_ct, sizeof(TV_MSG_32));
  TEST_MARK_END();

  if (err != NO_ERROR) {
    test_print_result("AES_XTS", 0, NULL, 0);
    return 1;
  }

  err = aesInit(&aesCtx1, TV_XTS_KEY, 16);
  if (err != NO_ERROR) {
    test_print_result("AES_XTS", 0, NULL, 0);
    return 1;
  }
  err = aesInit(&aesCtx2, TV_XTS_KEY + 16, 16);
  if (err != NO_ERROR) {
    test_print_result("AES_XTS", 0, NULL, 0);
    return 1;
  }
  err = xtsInit(&xtsCtx, AES_CIPHER_ALGO, &aesCtx1, &aesCtx2);
  if (err != NO_ERROR) {
    test_print_result("AES_XTS", 0, NULL, 0);
    return 1;
  }
  err = xtsDecrypt(&xtsCtx, s_sector, g_ct, g_pt, sizeof(TV_MSG_32));
  aesDeinit(&aesCtx1);
  aesDeinit(&aesCtx2);

  int ok = (err == NO_ERROR) && (ct_memcmp(g_pt, TV_MSG_32, 32) == 0);
  memcpy(g_output, g_ct, 32);
  test_print_result("AES_XTS", ok, g_output, 16);
  return ok ? 0 : 1;
}
