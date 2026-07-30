/**
 * @file test_aes192_ecb.c
 * @brief Benchmark test: AES192_ECB
 * @note angr-timeout: 600
 */
#define AES_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../cipher/aes.h"

static uint8_t g_output[16];
static uint8_t g_decrypted[16];
static const uint8_t s_plaintext[16] = {
0x10 };

int main(void)
{
    AesContext ctx;
    error_t err;
    static const uint8_t s_pt[16] = {0};

    err = aesInit(&ctx, TV_AES192_KEY, sizeof(TV_AES192_KEY));
    if (err != NO_ERROR) { test_print_result("AES192_ECB", 0, NULL, 0); return 1; }

    TEST_MARK_START();
    aesEncryptBlock(&ctx, s_pt, g_output);
    TEST_MARK_END();

    err = aesInit(&ctx, TV_AES192_KEY, sizeof(TV_AES192_KEY));
    if (err != NO_ERROR) { test_print_result("AES192_ECB", 0, NULL, 0); return 1; }
    aesDecryptBlock(&ctx, g_output, g_decrypted);
    aesDeinit(&ctx);

    int ok = (ct_memcmp(g_decrypted, s_pt, 16) == 0);
    test_print_result("AES192_ECB", ok, g_output, 16);
    return ok ? 0 : 1;
}
