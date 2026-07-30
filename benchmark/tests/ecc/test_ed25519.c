/**
 * @file test_ed25519.c
 * @brief Benchmark test: Ed25519 sign + verify
 * @note angr-timeout: 600
 * @note SIZE_ONLY: excluded from angr analysis
 */
#define ED25519_SUPPORT ENABLED
#define SHA512_SUPPORT  ENABLED

#include "../common/test_harness.h"
#include "../../ecc/ed25519.h"

/* Fixed 32-byte private key seed (not a real key, just for size measurement) */
static const uint8_t s_privkey[ED25519_PRIVATE_KEY_LEN] = {
    0x9d,0x61,0xb1,0x9d,0xef,0xfd,0x5a,0x60,
    0xba,0x84,0x4a,0xf4,0x92,0xec,0x2c,0x44,
    0x34,0x86,0x15,0x97,0x18,0x8b,0xf8,0x6d,
    0xbf,0x3d,0x90,0xf0,0x21,0x76,0x96,0x3d
};
static uint8_t g_pubkey[ED25519_PUBLIC_KEY_LEN];
static uint8_t g_sig[ED25519_SIGNATURE_LEN];
static uint8_t g_output[32];

int main(void)
{
    error_t err;

    err = ed25519GeneratePublicKey(s_privkey, g_pubkey);
    if (err != NO_ERROR) { test_print_result("ED25519", 0, NULL, 0); return 1; }

    TEST_MARK_START();
    err = ed25519GenerateSignature(s_privkey, g_pubkey,
                                   TV_MSG_32, sizeof(TV_MSG_32),
                                   NULL, 0, 0, g_sig);
    if (err == NO_ERROR) {
        err = ed25519VerifySignature(g_pubkey,
                                     TV_MSG_32, sizeof(TV_MSG_32),
                                     NULL, 0, 0, g_sig);
    }
    TEST_MARK_END();

    int ok = (err == NO_ERROR);
    memcpy(g_output, g_sig, 32);
    test_print_result("ED25519", ok, g_output, 32);
    return ok ? 0 : 1;
}
