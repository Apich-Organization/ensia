/**
 * @file test_idea_ecb.c
 * @brief Benchmark test: IDEA_ECB
 * @note angr-timeout: 600
 */
#define IDEA_SUPPORT ENABLED

#include "../../cipher/idea.h"
#include "../common/test_harness.h"

static uint8_t g_output[8];
static uint8_t g_decrypted[8];
static const uint8_t s_plaintext[8] = {0x08};

int main(void) {
  IdeaContext ctx;
  error_t err;
  static const uint8_t s_pt[8] = {0};

  err = ideaInit(&ctx, TV_IDEA_KEY, sizeof(TV_IDEA_KEY));
  if (err != NO_ERROR) {
    test_print_result("IDEA_ECB", 0, NULL, 0);
    return 1;
  }

  TEST_MARK_START();
  ideaEncryptBlock(&ctx, s_pt, g_output);
  TEST_MARK_END();

  err = ideaInit(&ctx, TV_IDEA_KEY, sizeof(TV_IDEA_KEY));
  if (err != NO_ERROR) {
    test_print_result("IDEA_ECB", 0, NULL, 0);
    return 1;
  }
  ideaDecryptBlock(&ctx, g_output, g_decrypted);
  ideaDeinit(&ctx);

  int ok = (ct_memcmp(g_decrypted, s_pt, 8) == 0);
  test_print_result("IDEA_ECB", ok, g_output, 8);
  return ok ? 0 : 1;
}
