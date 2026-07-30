/**
 * @file test_salsa20_stream.c
 * @brief Benchmark test: Salsa20 stream cipher (raw block API)
 * @note angr-timeout: 600
 *
 * Salsa20 in CycloneCRYPTO only exposes salsa20ProcessBlock() — the low-level
 * 64-byte block transform. We benchmark that directly.
 */
#define SALSA20_SUPPORT ENABLED

#include "../../cipher/salsa20.h"
#include "../common/test_harness.h"

/* Salsa20 block is 64 bytes. Use a zero-initialised 64-byte block as input. */
static uint8_t g_input[64] = {0};
static uint8_t g_output[64] = {0};

int main(void) {
  /* Rounds parameter: 20 for Salsa20/20 */
  const uint_t NR = 20u;

  TEST_MARK_START();
  salsa20ProcessBlock(g_input, g_output, NR);
  TEST_MARK_END();

  /* Verify output is non-zero (any bit set means the block transform ran) */
  static const uint8_t s_zeros[16] = {0};
  int ok = (ct_memcmp(g_output, s_zeros, 16) != 0);
  test_print_result("SALSA20_BLOCK", ok, g_output, 16);
  return ok ? 0 : 1;
}
