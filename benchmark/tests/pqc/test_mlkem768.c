/**
 * @file test_mlkem768.c
 * @brief Benchmark test: MLKEM768 (NIST PQC, code-size measurement only)
 * @note angr-timeout: 600
 * @note SIZE_ONLY: excluded from angr analysis (lattice-based PQC too complex)
 */
/* Self-contained stub: no PQC library sources required (not yet in benchmark dir).
 * This file exists purely to measure code-size overhead of test infrastructure.
 */
#include "../common/test_harness.h"

static uint8_t g_output[4] = {0xCC, 0xCC, 0x00, 0x00};

int main(void)
{
    /* SIZE_ONLY: no computation — compiler sees the harness overhead.
     * The angr analysis script skips this target based on the SIZE_ONLY property. */
    TEST_MARK_START();
    (void)g_output[0]; /* prevent dead-store elimination */
    TEST_MARK_END();

    test_print_result("MLKEM768", 1, g_output, 4);
    return 0;
}
