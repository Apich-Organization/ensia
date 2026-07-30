/**
 * @file test_rc2_ecb.c
 * @brief Benchmark test: RC2_ECB
 * @note angr-timeout: 600
 */
#define RC2_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../cipher/rc2.h"

static uint8_t g_output[8];
static uint8_t g_decrypted[8];
static const uint8_t s_plaintext[8] = {
0x08 };

int main(void)
{
    Rc2Context ctx;
    error_t err;
    static const uint8_t s_pt[8] = {0};

    err = rc2Init(&ctx, TV_RC2_KEY, sizeof(TV_RC2_KEY));
    if (err != NO_ERROR) { test_print_result("RC2_ECB", 0, NULL, 0); return 1; }

    TEST_MARK_START();
    rc2EncryptBlock(&ctx, s_pt, g_output);
    TEST_MARK_END();

    err = rc2Init(&ctx, TV_RC2_KEY, sizeof(TV_RC2_KEY));
    if (err != NO_ERROR) { test_print_result("RC2_ECB", 0, NULL, 0); return 1; }
    rc2DecryptBlock(&ctx, g_output, g_decrypted);
    rc2Deinit(&ctx);

    int ok = (ct_memcmp(g_decrypted, s_pt, 8) == 0);
    test_print_result("RC2_ECB", ok, g_output, 8);
    return ok ? 0 : 1;
}
