/**
 * @file test_ecdsa_p256.c
 * @brief Benchmark test: ECDSA P-256 signature generation and verification
 * @note angr-timeout: 600
 * @note SIZE_ONLY: excluded from angr analysis (too complex)
 */
#define EC_SUPPORT ENABLED
#define ECDSA_SUPPORT ENABLED
#define SHA256_SUPPORT ENABLED

#include "../../ecc/ec_curves.h"
#include "../../ecc/ecdsa.h"
#include "../../hash/sha256.h"
#include "../common/test_harness.h"

static uint8_t g_output[4];

int main(void) {
  EcPrivateKey privateKey;
  EcPublicKey publicKey;
  EcdsaSignature signature;
  const EcCurve *curve = SECP256R1_CURVE;
  error_t err;

  ecInitPrivateKey(&privateKey);
  ecInitPublicKey(&publicKey);
  ecdsaInitSignature(&signature);

  err = ecGeneratePrivateKey(NULL, NULL, curve, &privateKey);
  if (err != NO_ERROR) {
    test_print_result("ECDSA_P256", 0, NULL, 0);
    return 1;
  }

  err = ecGeneratePublicKey(&privateKey, &publicKey);
  if (err != NO_ERROR) {
    test_print_result("ECDSA_P256", 0, NULL, 0);
    return 1;
  }

  TEST_MARK_START();
  err = ecdsaGenerateDeterministicSignature(&privateKey, SHA256_HASH_ALGO,
                                            TV_MSG_32, &signature);
  if (err != NO_ERROR) {
    test_print_result("ECDSA_P256", 0, NULL, 0);
    return 1;
  }

  err = ecdsaVerifySignature(&publicKey, TV_MSG_32, sizeof(TV_MSG_32),
                             &signature);
  TEST_MARK_END();

  int ok = (err == NO_ERROR);
  g_output[0] = ok ? 1 : 0;

  ecFreePrivateKey(&privateKey);
  ecFreePublicKey(&publicKey);
  ecdsaFreeSignature(&signature);

  test_print_result("ECDSA_P256", ok, g_output, 4);
  return ok ? 0 : 1;
}
