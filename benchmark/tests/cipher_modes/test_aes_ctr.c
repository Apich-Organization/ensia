/**
 * @file test_aes_ctr.c
 * @brief Benchmark test: AES-CTR mode
 * @note angr-timeout: 600
 */
#define CTR_SUPPORT ENABLED
#define AES_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../cipher/aes.h"
#include "../../cipher_modes/ctr.h"

static uint8_t g_ct[32];
static uint8_t g_pt[32];
static uint8_t g_ctr_enc[16];
static uint8_t g_ctr_dec[16];
static uint8_t g_output[32];

int main(void)
{
    AesContext aesCtx;
    error_t err;

    memcpy(g_ctr_enc, TV_IV_16, 16);
    memcpy(g_ctr_dec, TV_IV_16, 16);

    err = aesInit(&aesCtx, TV_AES128_KEY, sizeof(TV_AES128_KEY));
    if (err != NO_ERROR) { test_print_result("AES_CTR", 0, NULL, 0); return 1; }

    TEST_MARK_START();
    err = ctrEncrypt(AES_CIPHER_ALGO, &aesCtx, 32, g_ctr_enc,
                     TV_MSG_32, g_ct, sizeof(TV_MSG_32));
    TEST_MARK_END();

    if (err != NO_ERROR) { test_print_result("AES_CTR", 0, NULL, 0); return 1; }

    err = aesInit(&aesCtx, TV_AES128_KEY, sizeof(TV_AES128_KEY));
    if (err != NO_ERROR) { test_print_result("AES_CTR", 0, NULL, 0); return 1; }
    err = ctrEncrypt(AES_CIPHER_ALGO, &aesCtx, 32, g_ctr_dec,
                     g_ct, g_pt, sizeof(TV_MSG_32));
    aesDeinit(&aesCtx);

    int ok = (err == NO_ERROR) && (ct_memcmp(g_pt, TV_MSG_32, 32) == 0);
    memcpy(g_output, g_ct, 32);
    test_print_result("AES_CTR", ok, g_output, 16);
    return ok ? 0 : 1;
}
