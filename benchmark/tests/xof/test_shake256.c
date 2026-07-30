/**
 * @file test_shake256.c
 * @brief Benchmark test: SHAKE256
 * @note angr-timeout: 600
 */
#define SHAKE256_SUPPORT ENABLED
#define KECCAK_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../xof/shake.h"
#include "../../xof/keccak.h"

static uint8_t g_output[32];

int main(void)
{
    error_t err;
    static const uint8_t s_zeros[32] = {0};

    TEST_MARK_START();
    err = shake256Compute(TV_MSG_32, sizeof(TV_MSG_32), g_output, sizeof(g_output));
    TEST_MARK_END();

    if (err != NO_ERROR) { test_print_result("SHAKE256", 0, NULL, 0); return 1; }

    int ok = (ct_memcmp(g_output, s_zeros, 32) != 0);
    test_print_result("SHAKE256", ok, g_output, 32);
    return ok ? 0 : 1;
}
