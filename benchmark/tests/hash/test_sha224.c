/**
 * @file test_sha224.c
 * @brief Benchmark test: SHA224
 * @note angr-timeout: 600
 */
#define SHA224_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../hash/sha224.h"

static uint8_t g_output[28];

int main(void)
{
    error_t err;
    static const uint8_t s_zeros[28] = {0};

    TEST_MARK_START();
    err = sha224Compute(TV_MSG_ABC, sizeof(TV_MSG_ABC), g_output);
    TEST_MARK_END();

    if (err != NO_ERROR) {
        test_print_result("SHA224", 0, NULL, 0);
        return 1;
    }

    /* Verify output is non-zero */
    int ok = (ct_memcmp(g_output, s_zeros, 28) != 0);
    test_print_result("SHA224", ok, g_output, 28);
    return ok ? 0 : 1;
}
