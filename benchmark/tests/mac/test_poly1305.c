/**
 * @file test_poly1305.c
 * @brief Benchmark test: Poly1305 MAC
 * @note angr-timeout: 600
 *
 * poly1305Init(ctx, key)  — 2 args, void return (no error_t).
 * poly1305Update(ctx, data, len)
 * poly1305Final(ctx, tag) — writes 16-byte tag.
 */
#define POLY1305_SUPPORT ENABLED

#include "../../mac/poly1305.h"
#include "../common/test_harness.h"

static uint8_t g_output[16];

int main(void) {
  Poly1305Context ctx;
  static const uint8_t s_zeros[16] = {0};

  /* Poly1305 uses a 32-byte one-time key (r||s), no error return */
  poly1305Init(&ctx, TV_HMAC_KEY_32);

  TEST_MARK_START();
  poly1305Update(&ctx, TV_MSG_32, sizeof(TV_MSG_32));
  poly1305Final(&ctx, g_output);
  TEST_MARK_END();

  int ok = (ct_memcmp(g_output, s_zeros, 16) != 0);
  test_print_result("POLY1305", ok, g_output, 16);
  return ok ? 0 : 1;
}
