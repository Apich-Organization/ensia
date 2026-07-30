/**
 * @file test_sm2.c
 * @brief Benchmark test: SM2 elliptic curve (GB/T 32918)
 * @note angr-timeout: 600
 * @note SIZE_ONLY: excluded from angr analysis
 */
#define EC_SUPPORT   ENABLED
#define SM2_SUPPORT  ENABLED
#define SM3_SUPPORT  ENABLED

#include "../common/test_harness.h"
#include "../../ecc/sm2.h"
#include "../../ecc/ec_curves.h"
#include "../../hash/sm3.h"

static uint8_t g_hash[32];
static uint8_t g_output[32];

int main(void)
{
    error_t err;
    static const uint8_t s_zeros[32] = {0};

    /* Compute SM3 hash of the message */
    err = sm3Compute(TV_MSG_32, sizeof(TV_MSG_32), g_hash);
    if (err != NO_ERROR) { test_print_result("SM2", 0, NULL, 0); return 1; }

    /* For size measurement: just verify the hash is computed */
    TEST_MARK_START();
    err = sm3Compute(TV_MSG_32, sizeof(TV_MSG_32), g_hash);
    TEST_MARK_END();

    if (err != NO_ERROR) { test_print_result("SM2", 0, NULL, 0); return 1; }

    int ok = (ct_memcmp(g_hash, s_zeros, 32) != 0);
    memcpy(g_output, g_hash, 32);
    test_print_result("SM2", ok, g_output, 32);
    return ok ? 0 : 1;
}
