/**
 * @file test_gmac_aes.c
 * @brief Benchmark test: GMAC-AES-128
 * @note angr-timeout: 600
 *
 * gmacInit(ctx, cipher, key, keyLen)     — 4 args, takes key directly.
 * gmacReset(ctx, iv, ivLen)              — sets IV.
 * gmacFinal(ctx, mac, macLen)            — 3 args.
 */
#define GCM_SUPPORT  ENABLED
#define GMAC_SUPPORT ENABLED
#define AES_SUPPORT  ENABLED

#include "../common/test_harness.h"
#include "../../cipher/aes.h"
#include "../../mac/gmac.h"

static uint8_t g_output[16];

int main(void)
{
    GmacContext ctx;
    error_t err;
    static const uint8_t s_zeros[16] = {0};

    err = gmacInit(&ctx, AES_CIPHER_ALGO, TV_AES128_KEY, sizeof(TV_AES128_KEY));
    if (err != NO_ERROR) { test_print_result("GMAC_AES", 0, NULL, 0); return 1; }

    TEST_MARK_START();
    err = gmacReset(&ctx, TV_NONCE_12, sizeof(TV_NONCE_12));
    if (err == NO_ERROR) gmacUpdate(&ctx, TV_MSG_32, sizeof(TV_MSG_32));
    if (err == NO_ERROR) err = gmacFinal(&ctx, g_output, sizeof(g_output));
    TEST_MARK_END();

    int ok = (err == NO_ERROR) && (ct_memcmp(g_output, s_zeros, 16) != 0);
    test_print_result("GMAC_AES", ok, g_output, 16);
    return ok ? 0 : 1;
}
