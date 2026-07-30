/**
 * @file test_blake2s128.c
 * @brief Benchmark test: BLAKE2S128
 * @note angr-timeout: 600
 */
#define BLAKE2S128_SUPPORT ENABLED
#define BLAKE2S_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../hash/blake2s128.h"

static uint8_t g_output[16];

int main(void)
{
    error_t err;
    static const uint8_t s_zeros[16] = {0};

    TEST_MARK_START();
    err = blake2s128Compute(TV_MSG_ABC, sizeof(TV_MSG_ABC), g_output);
    TEST_MARK_END();

    if (err != NO_ERROR) {
        test_print_result("BLAKE2S128", 0, NULL, 0);
        return 1;
    }

    /* Verify output is non-zero */
    int ok = (ct_memcmp(g_output, s_zeros, 16) != 0);
    test_print_result("BLAKE2S128", ok, g_output, 16);
    return ok ? 0 : 1;
}
