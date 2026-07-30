/**
 * @file test_cast128_ecb.c
 * @brief Benchmark test: CAST128_ECB
 * @note angr-timeout: 600
 */
#define CAST128_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../cipher/cast128.h"

static uint8_t g_output[8];
static uint8_t g_decrypted[8];
static const uint8_t s_plaintext[8] = {
0x08 };

int main(void)
{
    Cast128Context ctx;
    error_t err;
    static const uint8_t s_pt[8] = {0};

    err = cast128Init(&ctx, TV_CAST128_KEY, sizeof(TV_CAST128_KEY));
    if (err != NO_ERROR) { test_print_result("CAST128_ECB", 0, NULL, 0); return 1; }

    TEST_MARK_START();
    cast128EncryptBlock(&ctx, s_pt, g_output);
    TEST_MARK_END();

    err = cast128Init(&ctx, TV_CAST128_KEY, sizeof(TV_CAST128_KEY));
    if (err != NO_ERROR) { test_print_result("CAST128_ECB", 0, NULL, 0); return 1; }
    cast128DecryptBlock(&ctx, g_output, g_decrypted);
    cast128Deinit(&ctx);

    int ok = (ct_memcmp(g_decrypted, s_pt, 8) == 0);
    test_print_result("CAST128_ECB", ok, g_output, 8);
    return ok ? 0 : 1;
}
