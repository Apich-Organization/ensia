/**
 * @file test_aes_gcm.c
 * @brief Benchmark test: AES-128-GCM AEAD
 * @note angr-timeout: 600
 */
#define AES_SUPPORT ENABLED
#define GCM_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../cipher/aes.h"
#include "../../aead/gcm.h"

static uint8_t g_ct[32];
static uint8_t g_tag[16];
static uint8_t g_pt[32];
static uint8_t g_output[16]; /* report tag */

int main(void)
{
    AesContext aesCtx;
    GcmContext gcmCtx;
    error_t err;

    err = aesInit(&aesCtx, TV_AES128_KEY, sizeof(TV_AES128_KEY));
    if (err != NO_ERROR) { test_print_result("AES_GCM", 0, NULL, 0); return 1; }
    err = gcmInit(&gcmCtx, AES_CIPHER_ALGO, &aesCtx);
    if (err != NO_ERROR) { test_print_result("AES_GCM", 0, NULL, 0); return 1; }

    TEST_MARK_START();
    err = gcmEncrypt(&gcmCtx, TV_NONCE_12, sizeof(TV_NONCE_12),
                     TV_AAD, sizeof(TV_AAD),
                     TV_MSG_32, g_ct, sizeof(TV_MSG_32),
                     g_tag, sizeof(g_tag));
    TEST_MARK_END();

    if (err != NO_ERROR) { test_print_result("AES_GCM", 0, NULL, 0); return 1; }

    /* Re-init for decrypt */
    err = aesInit(&aesCtx, TV_AES128_KEY, sizeof(TV_AES128_KEY));
    if (err != NO_ERROR) { test_print_result("AES_GCM", 0, NULL, 0); return 1; }
    err = gcmInit(&gcmCtx, AES_CIPHER_ALGO, &aesCtx);
    if (err != NO_ERROR) { test_print_result("AES_GCM", 0, NULL, 0); return 1; }
    err = gcmDecrypt(&gcmCtx, TV_NONCE_12, sizeof(TV_NONCE_12),
                     TV_AAD, sizeof(TV_AAD),
                     g_ct, g_pt, sizeof(TV_MSG_32),
                     g_tag, sizeof(g_tag));

    int ok = (err == NO_ERROR) && (ct_memcmp(g_pt, TV_MSG_32, 32) == 0);
    memcpy(g_output, g_tag, 16);
    test_print_result("AES_GCM", ok, g_output, 16);
    return ok ? 0 : 1;
}
