/**
 * @file test_sm3.c
 * @brief Benchmark test: SM3
 * @note angr-timeout: 600
 */
#define SM3_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../hash/sm3.h"

static uint8_t g_output[32];

int main(void)
{
    error_t err;
    static const uint8_t s_zeros[32] = {0};

    TEST_MARK_START();
    err = sm3Compute(TV_MSG_ABC, sizeof(TV_MSG_ABC), g_output);
    TEST_MARK_END();

    if (err != NO_ERROR) {
        test_print_result("SM3", 0, NULL, 0);
        return 1;
    }

    /* Verify output is non-zero */
    int ok = (ct_memcmp(g_output, s_zeros, 32) != 0);
    test_print_result("SM3", ok, g_output, 32);
    return ok ? 0 : 1;
}
