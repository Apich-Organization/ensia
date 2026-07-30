/**
 * @file test_sha256.c
 * @brief Benchmark test: SHA256
 * @note angr-timeout: 600
 */
#define SHA256_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../hash/sha256.h"

static uint8_t g_output[32];

int main(void)
{
    error_t err;
    static const uint8_t s_zeros[32] = {0};

    TEST_MARK_START();
    err = sha256Compute(TV_MSG_ABC, sizeof(TV_MSG_ABC), g_output);
    TEST_MARK_END();

    if (err != NO_ERROR) {
        test_print_result("SHA256", 0, NULL, 0);
        return 1;
    }

    /* Known-answer test for SHA256("abc") — verified against NIST FIPS 180-4 */
    static const uint8_t s_expected[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    if (ct_memcmp(g_output, s_expected, 32) != 0) {
        test_print_result("SHA256", 0, g_output, 32);
        return 1;
    }

    /* Verify output is non-zero */
    int ok = (ct_memcmp(g_output, s_zeros, 32) != 0);
    test_print_result("SHA256", ok, g_output, 32);
    return ok ? 0 : 1;
}
