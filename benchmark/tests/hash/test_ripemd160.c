/**
 * @file test_ripemd160.c
 * @brief Benchmark test: RIPEMD160
 * @note angr-timeout: 600
 */
#define RIPEMD160_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../hash/ripemd160.h"

static uint8_t g_output[20];

int main(void)
{
    error_t err;
    static const uint8_t s_zeros[20] = {0};

    TEST_MARK_START();
    err = ripemd160Compute(TV_MSG_ABC, sizeof(TV_MSG_ABC), g_output);
    TEST_MARK_END();

    if (err != NO_ERROR) {
        test_print_result("RIPEMD160", 0, NULL, 0);
        return 1;
    }

    /* Verify output is non-zero */
    int ok = (ct_memcmp(g_output, s_zeros, 20) != 0);
    test_print_result("RIPEMD160", ok, g_output, 20);
    return ok ? 0 : 1;
}
