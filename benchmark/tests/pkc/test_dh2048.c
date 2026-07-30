/**
 * @file test_dh2048.c
 * @brief Benchmark test: DH-2048 (size measurement only)
 * @note angr-timeout: 600
 * @note SIZE_ONLY: excluded from angr analysis
 */
#define DH_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../pkc/dh.h"

static uint8_t g_output[16];

int main(void)
{
    /* DH key agreement is too large for angr; measure code size only */
    DhContext ctx;
    error_t err;
    static const uint8_t s_zeros[16] = {0};

    dhInit(&ctx);

    TEST_MARK_START();
    err = dhGenerateKeyPair(&ctx, NULL, NULL);
    TEST_MARK_END();

    dhFree(&ctx);

    /* Accept error (no RNG), we only care about code size */
    static const uint8_t s_marker[16] = {0xDC, 0x20, 0x48, 0x00};
    memcpy(g_output, s_marker, 4);
    test_print_result("DH2048", 1, g_output, 4);
    return 0;
}
