/**
 * @file test_tea_ecb.c
 * @brief Benchmark test: TEA ECB (8-byte block)
 * @note angr-timeout: 600
 */
#define TEA_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../cipher/tea.h"

static uint8_t g_output[8];
static uint8_t g_decrypted[8];
static const uint8_t s_pt[8] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};

int main(void)
{
    TeaContext ctx;
    error_t err;

    err = teaInit(&ctx, TV_TEA_KEY, sizeof(TV_TEA_KEY));
    if (err != NO_ERROR) { test_print_result("TEA_ECB", 0, NULL, 0); return 1; }

    TEST_MARK_START();
    teaEncryptBlock(&ctx, s_pt, g_output);
    TEST_MARK_END();

    err = teaInit(&ctx, TV_TEA_KEY, sizeof(TV_TEA_KEY));
    if (err != NO_ERROR) { test_print_result("TEA_ECB", 0, NULL, 0); return 1; }
    teaDecryptBlock(&ctx, g_output, g_decrypted);
    teaDeinit(&ctx);

    int ok = (ct_memcmp(g_decrypted, s_pt, 8) == 0);
    test_print_result("TEA_ECB", ok, g_output, 8);
    return ok ? 0 : 1;
}
