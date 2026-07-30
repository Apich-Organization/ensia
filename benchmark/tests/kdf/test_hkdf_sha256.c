/**
 * @file test_hkdf_sha256.c
 * @brief Benchmark test: HKDF-SHA-256 (RFC 5869)
 * @note angr-timeout: 600
 */
#define HKDF_SUPPORT   ENABLED
#define HMAC_SUPPORT   ENABLED
#define SHA256_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../kdf/hkdf.h"
#include "../../hash/hash_algorithms.h"

static uint8_t g_output[32];

int main(void)
{
    error_t err;
    static const uint8_t s_zeros[32] = {0};

    TEST_MARK_START();
    err = hkdf(SHA256_HASH_ALGO,
               TV_HKDF_IKM,  sizeof(TV_HKDF_IKM),
               TV_HKDF_SALT, sizeof(TV_HKDF_SALT),
               TV_HKDF_INFO, sizeof(TV_HKDF_INFO),
               g_output, sizeof(g_output));
    TEST_MARK_END();

    if (err != NO_ERROR) { test_print_result("HKDF_SHA256", 0, NULL, 0); return 1; }

    int ok = (ct_memcmp(g_output, s_zeros, 32) != 0);
    test_print_result("HKDF_SHA256", ok, g_output, 32);
    return ok ? 0 : 1;
}
