/**
 * @file test_ascon_hash256.c
 * @brief Benchmark test: ASCON-HASH256
 * @note angr-timeout: 600
 */
#define ASCON_SUPPORT        ENABLED
#define ASCON_HASH256_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../lwc/ascon.h"
#include "../../lwc/ascon_hash256.h"

static uint8_t g_output[32];

int main(void)
{
    AsconHash256Context ctx;
    static const uint8_t s_zeros[32] = {0};

    TEST_MARK_START();
    asconHash256Init(&ctx);
    asconHash256Update(&ctx, TV_MSG_32, sizeof(TV_MSG_32));
    asconHash256Final(&ctx, g_output);
    TEST_MARK_END();

    int ok = (ct_memcmp(g_output, s_zeros, 32) != 0);
    test_print_result("ASCON_HASH256", ok, g_output, 32);
    return ok ? 0 : 1;
}
