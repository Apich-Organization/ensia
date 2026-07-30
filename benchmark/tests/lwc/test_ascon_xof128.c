/**
 * @file test_ascon_xof128.c
 * @brief Benchmark test: ASCON-XOF128
 * @note angr-timeout: 600
 */
#define ASCON_SUPPORT ENABLED
#define ASCON_XOF128_SUPPORT ENABLED

#include "../../lwc/ascon.h"
#include "../../lwc/ascon_xof128.h"
#include "../common/test_harness.h"

static uint8_t g_output[32];

int main(void) {
  AsconXof128Context ctx;
  static const uint8_t s_zeros[32] = {0};

  TEST_MARK_START();
  asconXof128Init(&ctx);
  asconXof128Absorb(&ctx, TV_MSG_32, sizeof(TV_MSG_32));
  asconXof128Squeeze(&ctx, g_output, sizeof(g_output));
  TEST_MARK_END();

  int ok = (ct_memcmp(g_output, s_zeros, 32) != 0);
  test_print_result("ASCON_XOF128", ok, g_output, 32);
  return ok ? 0 : 1;
}
