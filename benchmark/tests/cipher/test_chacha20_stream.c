/**
 * @file test_chacha20_stream.c
 * @brief Benchmark test: ChaCha20 stream cipher (20 rounds)
 * @note angr-timeout: 600
 */
#define CHACHA_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../cipher/chacha.h"

static uint8_t g_output[32];
static uint8_t g_decrypted[32];

int main(void)
{
    ChachaContext ctx;
    error_t err;

    /* 20 rounds, 256-bit key, 64-bit nonce */
    err = chachaInit(&ctx, 20, TV_CHACHA_KEY, sizeof(TV_CHACHA_KEY),
                     TV_NONCE_8, sizeof(TV_NONCE_8));
    if (err != NO_ERROR) { test_print_result("CHACHA20_STREAM", 0, NULL, 0); return 1; }

    TEST_MARK_START();
    chachaCipher(&ctx, TV_MSG_32, g_output, sizeof(TV_MSG_32));
    TEST_MARK_END();

    err = chachaInit(&ctx, 20, TV_CHACHA_KEY, sizeof(TV_CHACHA_KEY),
                     TV_NONCE_8, sizeof(TV_NONCE_8));
    if (err != NO_ERROR) { test_print_result("CHACHA20_STREAM", 0, NULL, 0); return 1; }
    chachaCipher(&ctx, g_output, g_decrypted, 32);
    chachaDeinit(&ctx);

    int ok = (ct_memcmp(g_decrypted, TV_MSG_32, 32) == 0);
    test_print_result("CHACHA20_STREAM", ok, g_output, 16);
    return ok ? 0 : 1;
}
