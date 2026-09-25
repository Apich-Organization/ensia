#include "crypto_core.hpp"
#include "obf_str.hpp"
#include "zeroize.hpp"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>

using namespace ctf;

int main(int argc, char *argv[]) {
  // 1. Initial anti-tamper & environment sanity check
  if (!security::check_canary()) {
    std::fputs(OBF_STR("[!] Fatal: Environment Integrity Fault.\n"), stderr);
    return 139;
  }

  std::puts(OBF_STR("====================================================="));
  std::puts(OBF_STR("    Ensia Secure Cryptographic Enclave [v2.4.9]      "));
  std::puts(OBF_STR("    Target Challenge: Multi-Stage Non-Linear Reversal"));
  std::puts(OBF_STR("====================================================="));
  std::putchar('\n');

  char input1[64] = {0};
  char input2_line[64] = {0};
  char input3[64] = {0};
  char input4[64] = {0};
  uint32_t diff_accum = 0;

  // ── STAGE 1 ─────────────────────────────────────────────────────────────
  std::printf(
      "%s",
      OBF_STR(
          "[Layer 1] Enter 16-char Activation Key (XXXX-XXXX-XXXX-XXXX): "));
  std::fflush(stdout);
  if (!std::fgets(input1, sizeof(input1), stdin) || input1[0] == '\0') {
    std::fputs(OBF_STR("[-] Invalid input.\n"), stderr);
    return 1;
  }

  std::array<uint32_t, 4> s1{};
  uint32_t diff1 = crypto::verify_stage1(input1, s1);
  diff_accum |= diff1;

  // ── STAGE 2 ─────────────────────────────────────────────────────────────
  std::printf("%s", OBF_STR("[Layer 2] Enter 4 Orbital Calibration Coordinates "
                            "(e.g. 1 2 3 4): "));
  std::fflush(stdout);
  if (!std::fgets(input2_line, sizeof(input2_line), stdin) ||
      input2_line[0] == '\0') {
    std::fputs(OBF_STR("[-] Invalid input.\n"), stderr);
    return 1;
  }

  uint32_t k[4] = {0, 0, 0, 0};
  if (std::sscanf(input2_line, "%u %u %u %u", &k[0], &k[1], &k[2], &k[3]) !=
      4) {
    diff_accum |= 0xFFFFFFFF;
  }

  std::array<uint32_t, 4> s2{};
  uint32_t diff2 = crypto::verify_stage2(k[0], k[1], k[2], k[3], s1, s2);
  diff_accum |= diff2;

  // ── STAGE 3 ─────────────────────────────────────────────────────────────
  std::printf(
      "%s",
      OBF_STR("[Layer 3] Enter 16-byte Polymorphic Feistel Passphrase: "));
  std::fflush(stdout);
  if (!std::fgets(input3, sizeof(input3), stdin) || input3[0] == '\0') {
    std::fputs(OBF_STR("[-] Invalid input.\n"), stderr);
    return 1;
  }
  // Strip trailing newline
  for (size_t i = 0; i < sizeof(input3); ++i) {
    if (input3[i] == '\r' || input3[i] == '\n')
      input3[i] = '\0';
  }

  std::array<uint32_t, 4> s3{};
  uint32_t diff3 = crypto::verify_stage3(input3, s2, s3);
  diff_accum |= diff3;

  // ── STAGE 4 ─────────────────────────────────────────────────────────────
  std::printf("%s", OBF_STR("[Layer 4] Enter 8-byte Final Sealing Token: "));
  std::fflush(stdout);
  if (!std::fgets(input4, sizeof(input4), stdin) || input4[0] == '\0') {
    std::fputs(OBF_STR("[-] Invalid input.\n"), stderr);
    return 1;
  }
  // Strip trailing newline
  for (size_t i = 0; i < sizeof(input4); ++i) {
    if (input4[i] == '\r' || input4[i] == '\n')
      input4[i] = '\0';
  }

  std::array<uint32_t, 8> s4{};
  uint32_t diff4 = crypto::verify_stage4(input4, s1, s2, s3, s4);
  diff_accum |= diff4;

  // Entangle opaque identity to prevent dead-code branch elimination
  diff_accum |= security::opaque_identity(diff1, diff3);

  // ── FINAL VERIFICATION & DECRYPTION ─────────────────────────────────────
  char decrypted_flag[64] = {0};
  crypto::decrypt_flag(s1, s2, s3, s4, decrypted_flag);

  if (diff_accum == 0) {
    std::putchar('\n');
    std::puts(OBF_STR("[+] Enclave Unlocked! Verification Complete."));
    std::printf("%s%s\n", OBF_STR("[+] Flag: "), decrypted_flag);
  } else {
    // Zeroize decrypted garbage immediately
    security::secure_zero(decrypted_flag, sizeof(decrypted_flag));
    std::putchar('\n');
    std::puts(OBF_STR("[-] Authentication Failed: State Vector Incoherent."));
  }

  // Wipe sensitive stack variables before returning
  security::secure_zero(s1.data(), s1.size() * sizeof(uint32_t));
  security::secure_zero(s2.data(), s2.size() * sizeof(uint32_t));
  security::secure_zero(s3.data(), s3.size() * sizeof(uint32_t));
  security::secure_zero(s4.data(), s4.size() * sizeof(uint32_t));
  security::secure_zero(k, sizeof(k));
  security::secure_zero(input1, sizeof(input1));
  security::secure_zero(input2_line, sizeof(input2_line));
  security::secure_zero(input3, sizeof(input3));
  security::secure_zero(input4, sizeof(input4));
  security::secure_zero(decrypted_flag, sizeof(decrypted_flag));

  return (diff_accum == 0) ? 0 : 1;
}
