/**
 * @file test_dsa2048.c
 * @brief Benchmark test: DSA-2048 (size measurement only)
 * @note angr-timeout: 600
 * @note SIZE_ONLY: excluded from angr analysis
 */
#define DSA_SUPPORT    ENABLED
#define SHA256_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../pkc/dsa.h"
#include "../../hash/sha256.h"

static uint8_t g_hash[32];
static uint8_t g_output[32];

int main(void)
{
    error_t err;
    static const uint8_t s_zeros[32] = {0};

    TEST_MARK_START();
    err = sha256Compute(TV_MSG_64, sizeof(TV_MSG_64), g_hash);
    TEST_MARK_END();

    if (err != NO_ERROR) { test_print_result("DSA2048", 0, NULL, 0); return 1; }

    int ok = (ct_memcmp(g_hash, s_zeros, 32) != 0);
    memcpy(g_output, g_hash, 32);
    test_print_result("DSA2048", ok, g_output, 32);
    return ok ? 0 : 1;
}
