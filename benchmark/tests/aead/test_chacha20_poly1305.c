/**
 * @file test_chacha20_poly1305.c
 * @brief Benchmark test: ChaCha20-Poly1305 AEAD
 * @note angr-timeout: 600
 */
#define CHACHA_SUPPORT           ENABLED
#define CHACHA20_POLY1305_SUPPORT ENABLED
#define POLY1305_SUPPORT         ENABLED

#include "../common/test_harness.h"
#include "../../aead/chacha20_poly1305.h"

static uint8_t g_ct[32];
static uint8_t g_tag[16];
static uint8_t g_pt[32];
static uint8_t g_output[16];

int main(void)
{
    error_t err;

    TEST_MARK_START();
    err = chacha20Poly1305Encrypt(TV_CHACHA_KEY, sizeof(TV_CHACHA_KEY),
                                  TV_NONCE_12,   sizeof(TV_NONCE_12),
                                  TV_AAD,        sizeof(TV_AAD),
                                  TV_MSG_32, g_ct, sizeof(TV_MSG_32),
                                  g_tag, sizeof(g_tag));
    TEST_MARK_END();

    if (err != NO_ERROR) { test_print_result("CHACHA20_POLY1305", 0, NULL, 0); return 1; }

    err = chacha20Poly1305Decrypt(TV_CHACHA_KEY, sizeof(TV_CHACHA_KEY),
                                  TV_NONCE_12,   sizeof(TV_NONCE_12),
                                  TV_AAD,        sizeof(TV_AAD),
                                  g_ct, g_pt, sizeof(TV_MSG_32),
                                  g_tag, sizeof(g_tag));

    int ok = (err == NO_ERROR) && (ct_memcmp(g_pt, TV_MSG_32, 32) == 0);
    memcpy(g_output, g_tag, 16);
    test_print_result("CHACHA20_POLY1305", ok, g_output, 16);
    return ok ? 0 : 1;
}
