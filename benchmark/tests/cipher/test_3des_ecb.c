/**
 * @file test_3des_ecb.c
 * @brief Benchmark test: Triple-DES ECB
 * @note angr-timeout: 600
 */
#define DES_SUPPORT  ENABLED
#define DES3_SUPPORT ENABLED

#include "../common/test_harness.h"
#include "../../cipher/des3.h"
#include "../../cipher/des.h"

static uint8_t g_output[8];
static uint8_t g_decrypted[8];
static const uint8_t s_pt[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

int main(void)
{
    Des3Context ctx;
    error_t err;

    err = des3Init(&ctx, TV_3DES_KEY, sizeof(TV_3DES_KEY));
    if (err != NO_ERROR) { test_print_result("DES3_ECB", 0, NULL, 0); return 1; }

    TEST_MARK_START();
    des3EncryptBlock(&ctx, s_pt, g_output);
    TEST_MARK_END();

    err = des3Init(&ctx, TV_3DES_KEY, sizeof(TV_3DES_KEY));
    if (err != NO_ERROR) { test_print_result("DES3_ECB", 0, NULL, 0); return 1; }
    des3DecryptBlock(&ctx, g_output, g_decrypted);
    des3Deinit(&ctx);

    int ok = (ct_memcmp(g_decrypted, s_pt, 8) == 0);
    test_print_result("DES3_ECB", ok, g_output, 8);
    return ok ? 0 : 1;
}
