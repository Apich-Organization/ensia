/**
 * @file test_sha1.c
 * @brief Benchmark test: SHA1
 * @note angr-timeout: 600
 */
#define SHA1_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../hash/sha1.h"

static uint8_t g_output[20];

int main(void)
{
    error_t err;
    static const uint8_t s_zeros[20] = {0};

    TEST_MARK_START();
    err = sha1Compute(TV_MSG_ABC, sizeof(TV_MSG_ABC), g_output);
    TEST_MARK_END();

    if (err != NO_ERROR) {
        test_print_result("SHA1", 0, NULL, 0);
        return 1;
    }

    /* Known-answer test for SHA1("abc") */
    static const uint8_t s_expected[20] = {0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d};
    if (ct_memcmp(g_output, s_expected, 20) != 0) {
        test_print_result("SHA1", 0, g_output, 20);
        return 1;
    }

    /* Verify output is non-zero */
    int ok = (ct_memcmp(g_output, s_zeros, 20) != 0);
    test_print_result("SHA1", ok, g_output, 20);
    return ok ? 0 : 1;
}
