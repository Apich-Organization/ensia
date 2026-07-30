/**
 * @file test_twofish_ecb.c
 * @brief Benchmark test: TWOFISH_ECB
 * @note angr-timeout: 600
 */
#define TWOFISH_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../cipher/twofish.h"

static uint8_t g_output[16];
static uint8_t g_decrypted[16];
static const uint8_t s_plaintext[16] = {
0x10 };

int main(void)
{
    TwofishContext ctx;
    error_t err;
    static const uint8_t s_pt[16] = {0};

    err = twofishInit(&ctx, TV_TWOFISH_KEY, sizeof(TV_TWOFISH_KEY));
    if (err != NO_ERROR) { test_print_result("TWOFISH_ECB", 0, NULL, 0); return 1; }

    TEST_MARK_START();
    twofishEncryptBlock(&ctx, s_pt, g_output);
    TEST_MARK_END();

    err = twofishInit(&ctx, TV_TWOFISH_KEY, sizeof(TV_TWOFISH_KEY));
    if (err != NO_ERROR) { test_print_result("TWOFISH_ECB", 0, NULL, 0); return 1; }
    twofishDecryptBlock(&ctx, g_output, g_decrypted);
    twofishDeinit(&ctx);

    int ok = (ct_memcmp(g_decrypted, s_pt, 16) == 0);
    test_print_result("TWOFISH_ECB", ok, g_output, 16);
    return ok ? 0 : 1;
}
