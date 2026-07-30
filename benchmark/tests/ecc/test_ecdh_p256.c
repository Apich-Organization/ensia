/**
 * @file test_ecdh_p256.c
 * @brief Benchmark test: ECDH P-256 key exchange
 * @note angr-timeout: 600
 * @note SIZE_ONLY: excluded from angr analysis (too complex)
 */
#define EC_SUPPORT ENABLED
#define ECDH_SUPPORT ENABLED
#define SHA256_SUPPORT ENABLED

#include "../../ecc/ec_curves.h"
#include "../../ecc/ecdh.h"
#include "../common/test_harness.h"

static uint8_t g_output[64]; /* shared secret */

error_t x25519(uint8_t *r, const uint8_t *k, const uint8_t *u) { return 0; }
error_t x448(uint8_t *r, const uint8_t *k, const uint8_t *u) { return 0; }

int main(void) {
  EcdhContext ecdhA, ecdhB;
  const EcCurve *curve = SECP256R1_CURVE;
  error_t err;
  size_t outLen = 0;
  static const uint8_t s_zeros[32] = {0};

  ecdhInit(&ecdhA);
  err = ecdhSetCurve(&ecdhA, curve);
  if (err != NO_ERROR) {
    test_print_result("ECDH_P256", 0, NULL, 0);
    return 1;
  }

  ecdhInit(&ecdhB);
  err = ecdhSetCurve(&ecdhB, curve);
  if (err != NO_ERROR) {
    test_print_result("ECDH_P256", 0, NULL, 0);
    return 1;
  }

  /* Generate keypairs (deterministic from fixed seed via drbg stub) */
  TEST_MARK_START();
  err = ecdhGenerateKeyPair(&ecdhA, NULL, NULL);
  if (err != NO_ERROR) {
    test_print_result("ECDH_P256", 0, NULL, 0);
    return 1;
  }

  err = ecdhGenerateKeyPair(&ecdhB, NULL, NULL);
  if (err != NO_ERROR) {
    test_print_result("ECDH_P256", 0, NULL, 0);
    return 1;
  }

  /* Set peer public keys */
  ecdhA.qb = ecdhB.da.q;

  err = ecdhComputeSharedSecret(&ecdhA, g_output, 32, &outLen);
  TEST_MARK_END();

  if (err != NO_ERROR) {
    test_print_result("ECDH_P256", 0, NULL, 0);
    return 1;
  }

  int ok = (ct_memcmp(g_output, s_zeros, 32) != 0);
  ecdhFree(&ecdhA);
  ecdhFree(&ecdhB);
  test_print_result("ECDH_P256", ok, g_output, 32);
  return ok ? 0 : 1;
}
