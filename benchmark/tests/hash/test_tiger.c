/**
 * @file test_tiger.c
 * @brief Benchmark test: TIGER
 * @note angr-timeout: 600
 */
#define TIGER_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../hash/tiger.h"

static uint8_t g_output[24];

int main(void)
{
    error_t err;
    static const uint8_t s_zeros[24] = {0};

    TEST_MARK_START();
    err = tigerCompute(TV_MSG_ABC, sizeof(TV_MSG_ABC), g_output);
    TEST_MARK_END();

    if (err != NO_ERROR) {
        test_print_result("TIGER", 0, NULL, 0);
        return 1;
    }

    /* Verify output is non-zero */
    int ok = (ct_memcmp(g_output, s_zeros, 24) != 0);
    test_print_result("TIGER", ok, g_output, 24);
    return ok ? 0 : 1;
}
