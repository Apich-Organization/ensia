/**
 * @file test_scrypt.c
 * @brief Benchmark test: scrypt (RFC 7914, N=16, r=1, p=1)
 * @note angr-timeout: 600
 *
 * scrypt(password, salt, saltLen, N, r, p, dk, dkLen) — 8 args.
 * password is char_t* (NUL-terminated string), salt is uint8_t*.
 * N must be a power of 2; use small N=16 for fast benchmark run.
 */
#define SCRYPT_SUPPORT ENABLED
#define PBKDF2_SUPPORT ENABLED
#define HMAC_SUPPORT   ENABLED
#define SHA256_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../kdf/scrypt.h"
#include "../../hash/sha256.h"

static uint8_t g_output[32];

int main(void)
{
    error_t err;
    static const uint8_t s_zeros[32] = {0};

    /* scrypt takes a NUL-terminated password string */
    static const char s_password[] = "benchmark_password";

    TEST_MARK_START();
    err = scrypt(s_password,
                 TV_HKDF_SALT, sizeof(TV_HKDF_SALT),
                 16u, 1u, 1u,          /* N=16, r=1, p=1 */
                 g_output, sizeof(g_output));
    TEST_MARK_END();

    if (err != NO_ERROR) { test_print_result("SCRYPT", 0, NULL, 0); return 1; }

    int ok = (ct_memcmp(g_output, s_zeros, 32) != 0);
    test_print_result("SCRYPT", ok, g_output, 32);
    return ok ? 0 : 1;
}
