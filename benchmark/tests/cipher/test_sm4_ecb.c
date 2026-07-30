/**
 * @file test_sm4_ecb.c
 * @brief Benchmark test: SM4_ECB
 * @note angr-timeout: 600
 */
#define SM4_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../cipher/sm4.h"

static uint8_t g_output[16];
static uint8_t g_decrypted[16];
static const uint8_t s_plaintext[16] = {
0x10 };

int main(void)
{
    Sm4Context ctx;
    error_t err;
    static const uint8_t s_pt[16] = {0};

    err = sm4Init(&ctx, TV_SM4_KEY, sizeof(TV_SM4_KEY));
    if (err != NO_ERROR) { test_print_result("SM4_ECB", 0, NULL, 0); return 1; }

    TEST_MARK_START();
    sm4EncryptBlock(&ctx, s_pt, g_output);
    TEST_MARK_END();

    err = sm4Init(&ctx, TV_SM4_KEY, sizeof(TV_SM4_KEY));
    if (err != NO_ERROR) { test_print_result("SM4_ECB", 0, NULL, 0); return 1; }
    sm4DecryptBlock(&ctx, g_output, g_decrypted);
    sm4Deinit(&ctx);

    int ok = (ct_memcmp(g_decrypted, s_pt, 16) == 0);
    test_print_result("SM4_ECB", ok, g_output, 16);
    return ok ? 0 : 1;
}
