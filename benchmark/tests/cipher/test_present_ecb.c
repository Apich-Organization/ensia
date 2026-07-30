/**
 * @file test_present_ecb.c
 * @brief Benchmark test: PRESENT-80 ECB (8-byte block)
 * @note angr-timeout: 600
 */
#define PRESENT_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../cipher/present.h"

static uint8_t g_output[8];
static uint8_t g_decrypted[8];
static const uint8_t s_pt[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

int main(void)
{
    PresentContext ctx;
    error_t err;

    /* PRESENT-80 key = 10 bytes */
    err = presentInit(&ctx, TV_PRESENT_KEY, sizeof(TV_PRESENT_KEY));
    if (err != NO_ERROR) { test_print_result("PRESENT_ECB", 0, NULL, 0); return 1; }

    TEST_MARK_START();
    presentEncryptBlock(&ctx, s_pt, g_output);
    TEST_MARK_END();

    err = presentInit(&ctx, TV_PRESENT_KEY, sizeof(TV_PRESENT_KEY));
    if (err != NO_ERROR) { test_print_result("PRESENT_ECB", 0, NULL, 0); return 1; }
    presentDecryptBlock(&ctx, g_output, g_decrypted);
    presentDeinit(&ctx);

    int ok = (ct_memcmp(g_decrypted, s_pt, 8) == 0);
    test_print_result("PRESENT_ECB", ok, g_output, 8);
    return ok ? 0 : 1;
}
