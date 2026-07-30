/**
 * @file test_bcrypt.c
 * @brief Benchmark test: bcrypt password hashing
 * @note angr-timeout: 600
 *
 * bcryptHashPassword(prngAlgo, prngCtx, cost, password, hash_buf, hash_len_ptr)
 * requires a real PRNG context. Since we have no RNG in the stub environment,
 * we use bcryptVerifyPassword() for the benchmark path instead — it does the
 * same Blowfish key schedule work without needing a PRNG.
 * For code-expansion measurement the function bodies are what matter.
 */
#define BCRYPT_SUPPORT ENABLED
#define BLOWFISH_SUPPORT ENABLED

#include "../../cipher/blowfish.h"
#include "../../kdf/bcrypt.h"
#include "../common/test_harness.h"

/*
 * A real bcrypt hash string for "password" at cost=6 (pre-computed offline):
 * $2b$06$EFnXHBn7Vn7mM9vczSriLuYGq5BQxInPvimrfqaS4xhc0ZMpVYYhm
 */
static const char s_known_hash[] =
    "$2b$06$EFnXHBn7Vn7mM9vczSriLuYGq5BQxInPvimrfqaS4xhc0ZMpVYYhm";
static const char s_password[] = "password";
static uint8_t g_output[4] = {0xBC, 0x00, 0x00, 0x00};

int main(void) {
  error_t err;

  TEST_MARK_START();
  /* Verify exercises the full Blowfish key schedule — same cost as hash */
  err = bcryptVerifyPassword(s_password, s_known_hash);
  TEST_MARK_END();

  int ok = (err == NO_ERROR);
  g_output[0] = ok ? 0x01 : 0x00;
  test_print_result("BCRYPT", ok, g_output, 4);
  return ok ? 0 : 1;
}
