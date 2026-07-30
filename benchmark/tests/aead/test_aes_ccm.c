/**
 * @file test_aes_ccm.c
 * @brief Benchmark test: AES-128-CCM AEAD
 * @note angr-timeout: 600
 *
 * CCM API: ccmEncrypt(cipher_algo, cipher_ctx, nonce, nLen, aad, aLen,
 *                     plaintext, ciphertext, len, tag, tLen)  — 11 args.
 * No CcmContext struct exists; CCM is stateless and takes the cipher context directly.
 */
#define AES_SUPPORT ENABLED
#define CCM_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../cipher/aes.h"
#include "../../aead/ccm.h"

static uint8_t g_ct[32];
static uint8_t g_tag[16];
static uint8_t g_pt[32];

int main(void)
{
    AesContext aesCtx;
    error_t err;

    err = aesInit(&aesCtx, TV_AES128_KEY, sizeof(TV_AES128_KEY));
    if (err != NO_ERROR) { test_print_result("AES_CCM", 0, NULL, 0); return 1; }

    TEST_MARK_START();
    err = ccmEncrypt(AES_CIPHER_ALGO, &aesCtx,
                     TV_NONCE_12, sizeof(TV_NONCE_12),
                     TV_AAD,     sizeof(TV_AAD),
                     TV_MSG_32,  g_ct, sizeof(TV_MSG_32),
                     g_tag,      sizeof(g_tag));
    TEST_MARK_END();

    if (err != NO_ERROR) { test_print_result("AES_CCM", 0, NULL, 0); return 1; }

    /* Re-init cipher context for decryption */
    err = aesInit(&aesCtx, TV_AES128_KEY, sizeof(TV_AES128_KEY));
    if (err != NO_ERROR) { test_print_result("AES_CCM", 0, NULL, 0); return 1; }

    err = ccmDecrypt(AES_CIPHER_ALGO, &aesCtx,
                     TV_NONCE_12, sizeof(TV_NONCE_12),
                     TV_AAD,     sizeof(TV_AAD),
                     g_ct,       g_pt, sizeof(TV_MSG_32),
                     g_tag,      sizeof(g_tag));

    int ok = (err == NO_ERROR) && (ct_memcmp(g_pt, TV_MSG_32, 32) == 0);
    test_print_result("AES_CCM", ok, g_tag, 16);
    return ok ? 0 : 1;
}
