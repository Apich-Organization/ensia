/**
 * @file test_seed_ecb.c
 * @brief Benchmark test: SEED_ECB
 * @note angr-timeout: 600
 */
#define SEED_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../cipher/seed.h"

static uint8_t g_output[16];
static uint8_t g_decrypted[16];
static const uint8_t s_plaintext[16] = {
0x10 };

int main(void)
{
    SeedContext ctx;
    error_t err;
    static const uint8_t s_pt[16] = {0};

    err = seedInit(&ctx, TV_SEED_KEY, sizeof(TV_SEED_KEY));
    if (err != NO_ERROR) { test_print_result("SEED_ECB", 0, NULL, 0); return 1; }

    TEST_MARK_START();
    seedEncryptBlock(&ctx, s_pt, g_output);
    TEST_MARK_END();

    err = seedInit(&ctx, TV_SEED_KEY, sizeof(TV_SEED_KEY));
    if (err != NO_ERROR) { test_print_result("SEED_ECB", 0, NULL, 0); return 1; }
    seedDecryptBlock(&ctx, g_output, g_decrypted);
    seedDeinit(&ctx);

    int ok = (ct_memcmp(g_decrypted, s_pt, 16) == 0);
    test_print_result("SEED_ECB", ok, g_output, 16);
    return ok ? 0 : 1;
}
