/**
 * @file test_mars_ecb.c
 * @brief Benchmark test: MARS_ECB
 * @note angr-timeout: 600
 */
#define MARS_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../cipher/mars.h"

static uint8_t g_output[16];
static uint8_t g_decrypted[16];
static const uint8_t s_plaintext[16] = {
0x10 };

int main(void)
{
    MarsContext ctx;
    error_t err;
    static const uint8_t s_pt[16] = {0};

    err = marsInit(&ctx, TV_MARS_KEY, sizeof(TV_MARS_KEY));
    if (err != NO_ERROR) { test_print_result("MARS_ECB", 0, NULL, 0); return 1; }

    TEST_MARK_START();
    marsEncryptBlock(&ctx, s_pt, g_output);
    TEST_MARK_END();

    err = marsInit(&ctx, TV_MARS_KEY, sizeof(TV_MARS_KEY));
    if (err != NO_ERROR) { test_print_result("MARS_ECB", 0, NULL, 0); return 1; }
    marsDecryptBlock(&ctx, g_output, g_decrypted);
    marsDeinit(&ctx);

    int ok = (ct_memcmp(g_decrypted, s_pt, 16) == 0);
    test_print_result("MARS_ECB", ok, g_output, 16);
    return ok ? 0 : 1;
}
