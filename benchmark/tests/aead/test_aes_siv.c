/**
 * @file test_aes_siv.c
 * @brief Benchmark test: AES-128-SIV AEAD (Synthetic IV)
 * @note angr-timeout: 600
 *
 * SIV API: sivEncrypt(cipher, key, kLen, ad_chunks, adChunkCount,
 *                     plaintext, ciphertext, len, siv_out) — 9 args.
 * Passes a single DataChunk for the associated data.
 */
#define AES_SUPPORT ENABLED
#define SIV_SUPPORT ENABLED
#define CMAC_SUPPORT ENABLED

#include "../../aead/siv.h"
#include "../../cipher/aes.h"
#include "../common/test_harness.h"

static uint8_t g_ct[32];
static uint8_t g_pt[32];
static uint8_t g_siv[16]; /* Synthetic IV (prepended authentication tag) */

int main(void) {
  error_t err;

  /* SIV requires a double-length key: 256 bits for AES-128-SIV */
  static const uint8_t k[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

  /* Build associated data as a single-element DataChunk array */
  DataChunk adChunks[1];
  adChunks[0].buffer = TV_AAD;
  adChunks[0].length = sizeof(TV_AAD);

  TEST_MARK_START();
  err = sivEncrypt(AES_CIPHER_ALGO, k, sizeof(k), adChunks, 1, TV_MSG_32, g_ct,
                   sizeof(TV_MSG_32), g_siv);
  TEST_MARK_END();

  if (err != NO_ERROR) {
    test_print_result("AES_SIV", 0, NULL, 0);
    return 1;
  }

  err = sivDecrypt(AES_CIPHER_ALGO, k, sizeof(k), adChunks, 1, g_ct, g_pt,
                   sizeof(TV_MSG_32), g_siv);

  int ok = (err == NO_ERROR) && (ct_memcmp(g_pt, TV_MSG_32, 32) == 0);
  test_print_result("AES_SIV", ok, g_siv, 16);
  return ok ? 0 : 1;
}
