/**
 * @file test_serpent_ecb.c
 * @brief Benchmark test: SERPENT_ECB
 * @note angr-timeout: 600
 */
#define SERPENT_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../cipher/serpent.h"

static uint8_t g_output[16];
static uint8_t g_decrypted[16];
static const uint8_t s_plaintext[16] = {
0x10 };

int main(void)
{
    SerpentContext ctx;
    error_t err;
    static const uint8_t s_pt[16] = {0};

    err = serpentInit(&ctx, TV_SERPENT_KEY, sizeof(TV_SERPENT_KEY));
    if (err != NO_ERROR) { test_print_result("SERPENT_ECB", 0, NULL, 0); return 1; }

    TEST_MARK_START();
    serpentEncryptBlock(&ctx, s_pt, g_output);
    TEST_MARK_END();

    err = serpentInit(&ctx, TV_SERPENT_KEY, sizeof(TV_SERPENT_KEY));
    if (err != NO_ERROR) { test_print_result("SERPENT_ECB", 0, NULL, 0); return 1; }
    serpentDecryptBlock(&ctx, g_output, g_decrypted);
    serpentDeinit(&ctx);

    int ok = (ct_memcmp(g_decrypted, s_pt, 16) == 0);
    test_print_result("SERPENT_ECB", ok, g_output, 16);
    return ok ? 0 : 1;
}
