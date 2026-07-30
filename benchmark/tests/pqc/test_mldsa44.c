/**
 * @file test_mldsa44.c
 * @brief Benchmark test: ML-DSA-44 (NIST PQC, code-size measurement only)
 * @note angr-timeout: 600
 * @note SIZE_ONLY: excluded from angr analysis (lattice-based PQC too complex)
 */
#include "../common/test_harness.h"

static uint8_t g_output[4] = {0xCC, 0xCC, 0x00, 0x00};

int main(void) {
  TEST_MARK_START();
  (void)g_output[0];
  TEST_MARK_END();

  test_print_result("ML-DSA-44", 1, g_output, 4);
  return 0;
}
