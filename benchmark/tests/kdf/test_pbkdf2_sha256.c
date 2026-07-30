/**
 * @file test_pbkdf2_sha256.c
 * @brief Benchmark test: PBKDF2-HMAC-SHA-256 (RFC 2898)
 * @note angr-timeout: 600
 */
#define PBKDF_SUPPORT  ENABLED
#define HMAC_SUPPORT   ENABLED
#define SHA256_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../kdf/pbkdf.h"
#include "../../hash/hash_algorithms.h"

static uint8_t g_output[32];

int main(void)
{
    error_t err;
    static const uint8_t s_zeros[32] = {0};

    TEST_MARK_START();
    err = pbkdf2(SHA256_HASH_ALGO,
                 TV_HMAC_KEY_32, sizeof(TV_HMAC_KEY_32),
                 TV_HKDF_SALT,   sizeof(TV_HKDF_SALT),
                 TV_PBKDF2_ITERATIONS,
                 g_output, sizeof(g_output));
    TEST_MARK_END();

    if (err != NO_ERROR) { test_print_result("PBKDF2_SHA256", 0, NULL, 0); return 1; }

    int ok = (ct_memcmp(g_output, s_zeros, 32) != 0);
    test_print_result("PBKDF2_SHA256", ok, g_output, 32);
    return ok ? 0 : 1;
}
