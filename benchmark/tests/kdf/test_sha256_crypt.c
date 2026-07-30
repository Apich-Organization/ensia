/**
 * @file test_sha256_crypt.c
 * @brief Benchmark test: SHA-256-crypt (Unix shadow password, glibc variant)
 * @note angr-timeout: 600
 *
 * shaCrypt(hashAlgo, password, salt, output, outputLen) — 5 args.
 * Uses SHA256_HASH_ALGO descriptor; password and salt are NUL-terminated
 * strings.
 */
#define SHA_CRYPT_SUPPORT ENABLED
#define SHA256_SUPPORT ENABLED

#include "../../hash/sha256.h"
#include "../../kdf/sha_crypt.h"
#include "../common/test_harness.h"

/* shaCrypt writes a printable hash string like $5$salt$... */
static char g_output[128];

int main(void) {
  error_t err;
  size_t outputLen = sizeof(g_output);

  static const char s_password[] = "benchmark_password";
  static const char s_salt[] = "benchsalt";

  TEST_MARK_START();
  err = shaCrypt(SHA256_HASH_ALGO, s_password, s_salt, g_output, &outputLen);
  TEST_MARK_END();

  if (err != NO_ERROR) {
    test_print_result("SHA256_CRYPT", 0, NULL, 0);
    return 1;
  }

  /* Output should be non-empty and start with "$5$" */
  int ok = (outputLen > 4) && (g_output[0] == '$');
  test_print_result("SHA256_CRYPT", ok, (const uint8_t *)g_output, 16);
  return ok ? 0 : 1;
}
