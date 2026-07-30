/**
 * @file test_sha384.c
 * @brief Benchmark test: SHA384
 * @note angr-timeout: 600
 */
#define SHA384_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../hash/sha384.h"

static uint8_t g_output[48];

int main(void)
{
    error_t err;
    static const uint8_t s_zeros[48] = {0};

    TEST_MARK_START();
    err = sha384Compute(TV_MSG_ABC, sizeof(TV_MSG_ABC), g_output);
    TEST_MARK_END();

    if (err != NO_ERROR) {
        test_print_result("SHA384", 0, NULL, 0);
        return 1;
    }

    /* Verify output is non-zero */
    int ok = (ct_memcmp(g_output, s_zeros, 48) != 0);
    test_print_result("SHA384", ok, g_output, 48);
    return ok ? 0 : 1;
}
