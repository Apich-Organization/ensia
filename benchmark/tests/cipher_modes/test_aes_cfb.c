/**
 * @file test_aes_cfb.c
 * @brief Benchmark test: AES_CFB
 * @note angr-timeout: 600
 */
#define CFB_SUPPORT ENABLED
#define AES_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../cipher/aes.h"
#include "../../cipher_modes/cfb.h"

static uint8_t g_ct[32];
static uint8_t g_pt[32];
static uint8_t g_output[32];

int main(void)
{
    AesContext aesCtx;
    error_t err;
    static uint8_t s_iv_enc[16];
    static uint8_t s_iv_dec[16];

    memcpy(s_iv_enc, TV_IV_16, 16);
    memcpy(s_iv_dec, TV_IV_16, 16);

    err = aesInit(&aesCtx, TV_AES128_KEY, sizeof(TV_AES128_KEY));
    if (err != NO_ERROR) { test_print_result("AES_CFB", 0, NULL, 0); return 1; }

    TEST_MARK_START();
    err = cfbEncrypt(AES_CIPHER_ALGO, &aesCtx, 128u, s_iv_enc,
                   TV_MSG_32, g_ct, sizeof(TV_MSG_32));

    TEST_MARK_END();

    if (err != NO_ERROR) { test_print_result("AES_CFB", 0, NULL, 0); return 1; }

    err = aesInit(&aesCtx, TV_AES128_KEY, sizeof(TV_AES128_KEY));
    if (err != NO_ERROR) { test_print_result("AES_CFB", 0, NULL, 0); return 1; }
    err = cfbDecrypt(AES_CIPHER_ALGO, &aesCtx, 128u, s_iv_dec,
                   g_ct, g_pt, sizeof(TV_MSG_32));

    aesDeinit(&aesCtx);

    int ok = (err == NO_ERROR) && (ct_memcmp(g_pt, TV_MSG_32, 32) == 0);
    memcpy(g_output, g_ct, 32);
    test_print_result("AES_CFB", ok, g_output, 16);
    return ok ? 0 : 1;
}
