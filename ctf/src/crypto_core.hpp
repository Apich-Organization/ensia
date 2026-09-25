#pragma once

#include "zeroize.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace ctf::crypto {

// ─────────────────────────────────────────────────────────────────────────────
// Stage 1: Non-Linear SPN over Galois Field GF(2^8)
// Irreducible Polynomial: P(x) = x^8 + x^4 + x^3 + x + 1 (0x11B)
// ─────────────────────────────────────────────────────────────────────────────

inline uint8_t gf_mul(uint8_t a, uint8_t b) {
  uint8_t p = 0;
  for (int i = 0; i < 8; ++i) {
    if (b & 1) {
      p ^= a;
    }
    uint8_t hi = a & 0x80;
    a = static_cast<uint8_t>((a << 1) & 0xFF);
    if (hi) {
      a ^= 0x1B;
    }
    b >>= 1;
  }
  return p;
}

inline uint8_t gf_inv(uint8_t a) {
  if (a == 0)
    return 0;
  uint8_t res = 1;
  uint8_t base = a;
  uint8_t exp = 254; // Fermat's Little Theorem: a^254 == a^-1 in GF(2^8)
  while (exp > 0) {
    if (exp & 1) {
      res = gf_mul(res, base);
    }
    base = gf_mul(base, base);
    exp >>= 1;
  }
  return res;
}

inline uint8_t sbox_transform(uint8_t x) { return gf_inv(x ^ 0x67) ^ 0x89; }

const uint8_t STAGE1_ROUND_KEYS[4][16] = {
    {0x1A, 0x9B, 0x4C, 0xF3, 0x5D, 0x8E, 0x27, 0x60, 0x31, 0xA5, 0x78, 0xC4,
     0x0F, 0xE2, 0xB6, 0xD9},
    {0xE7, 0x2A, 0x5F, 0x91, 0x83, 0xC6, 0x0D, 0x74, 0xB8, 0x1E, 0x42, 0xDB,
     0xF5, 0x6C, 0x39, 0xAA},
    {0x3C, 0xF0, 0x8A, 0x15, 0x96, 0x4D, 0x72, 0xEB, 0x29, 0x5E, 0xAC, 0x63,
     0xD4, 0x0B, 0xFE, 0x18},
    {0x71, 0x48, 0xCE, 0x23, 0xBF, 0x95, 0x6A, 0x0C, 0xD2, 0x3F, 0x87, 0x19,
     0x4E, 0xA1, 0x5B, 0x6D}};

const uint8_t STAGE1_TARGET[16] = {0x0E, 0x24, 0xCA, 0x2D, 0x12, 0x16,
                                   0xE6, 0x63, 0x56, 0xEB, 0x75, 0x86,
                                   0x8A, 0xD4, 0xDE, 0xBD};

inline uint32_t verify_stage1(const char *input,
                              std::array<uint32_t, 4> &out_s1) {
  if (!input)
    return 0xFFFFFFFF;
  char clean[16];
  size_t count = 0;
  for (size_t i = 0; input[i] != '\0'; ++i) {
    char c = input[i];
    if (c != '-' && c != ' ' && c != '\n' && c != '\r') {
      if (count < 16) {
        clean[count++] = c;
      } else {
        return 0xFFFFFFFF;
      }
    }
  }
  if (count != 16) {
    return 0xFFFFFFFF;
  }

  uint8_t state[16];
  std::memcpy(state, clean, 16);
  security::SecureBuffer<uint8_t> clean_guard(state, 16);

  for (int r = 0; r < 4; ++r) {
    // SubBytes + AddRoundKey
    for (int i = 0; i < 16; ++i) {
      state[i] = sbox_transform(state[i] ^ STAGE1_ROUND_KEYS[r][i]);
    }
    // ShiftRows
    uint8_t s[16];
    std::memcpy(s, state, 16);
    state[1] = s[5];
    state[5] = s[9];
    state[9] = s[13];
    state[13] = s[1];
    state[2] = s[10];
    state[6] = s[14];
    state[10] = s[2];
    state[14] = s[6];
    state[3] = s[15];
    state[7] = s[3];
    state[11] = s[7];
    state[15] = s[11];

    // MixColumns with MDS matrix
    for (int c = 0; c < 4; ++c) {
      uint8_t c0 = state[4 * c];
      uint8_t c1 = state[4 * c + 1];
      uint8_t c2 = state[4 * c + 2];
      uint8_t c3 = state[4 * c + 3];

      state[4 * c] = gf_mul(2, c0) ^ gf_mul(3, c1) ^ c2 ^ c3;
      state[4 * c + 1] = c0 ^ gf_mul(2, c1) ^ gf_mul(3, c2) ^ c3;
      state[4 * c + 2] = c0 ^ c1 ^ gf_mul(2, c2) ^ gf_mul(3, c3);
      state[4 * c + 3] = gf_mul(3, c0) ^ c1 ^ c2 ^ gf_mul(2, c3);
    }
  }

  // Branchless difference accumulation
  uint32_t diff = 0;
  for (int i = 0; i < 16; ++i) {
    diff |= (state[i] ^ STAGE1_TARGET[i]);
  }

  for (int i = 0; i < 4; ++i) {
    out_s1[i] = static_cast<uint32_t>(state[4 * i]) |
                (static_cast<uint32_t>(state[4 * i + 1]) << 8) |
                (static_cast<uint32_t>(state[4 * i + 2]) << 16) |
                (static_cast<uint32_t>(state[4 * i + 3]) << 24);
  }
  return diff;
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage 2: Coupled Chaotic Map over Mersenne Prime (2^31 - 1)
// ─────────────────────────────────────────────────────────────────────────────

constexpr uint64_t MOD_P = 2147483647ULL; // 2^31 - 1

inline uint64_t mod_pow(uint64_t base, uint64_t exp) {
  uint64_t res = 1;
  base %= MOD_P;
  while (exp > 0) {
    if (exp & 1)
      res = (res * base) % MOD_P;
    base = (base * base) % MOD_P;
    exp >>= 1;
  }
  return res;
}

const uint32_t STAGE2_TARGET_X = 0x5c675823;
const uint32_t STAGE2_TARGET_Y = 0x764f0e33;
const uint32_t STAGE2_INV1 = 0x2aa95a64;
const uint32_t STAGE2_INV2 = 0x1aed5470;

inline uint32_t verify_stage2(uint32_t k0, uint32_t k1, uint32_t k2,
                              uint32_t k3, const std::array<uint32_t, 4> &s1,
                              std::array<uint32_t, 4> &out_s2) {
  uint64_t x = (static_cast<uint64_t>(k0 ^ s1[0])) % MOD_P;
  uint64_t y = (static_cast<uint64_t>(k1 ^ s1[1])) % MOD_P;
  uint64_t p = (static_cast<uint64_t>(k2 ^ s1[2])) % MOD_P;
  uint64_t q = (static_cast<uint64_t>(k3 ^ s1[3])) % MOD_P;

  for (int r = 0; r < 16; ++r) {
    uint64_t x3 = mod_pow(x, 3);
    uint64_t y3 = mod_pow(y, 3);

    uint64_t nx = (2 * x + y + x3 + p + 0x314159ULL) % MOD_P;
    uint64_t ny = (x + y + y3 + q + 0x271828ULL) % MOD_P;
    x = nx;
    y = ny;
  }

  uint64_t inv1 = (static_cast<uint64_t>(k0) * 0x1337ULL +
                   static_cast<uint64_t>(k1) * 0xdeadULL) %
                  MOD_P;
  uint64_t inv2 = (static_cast<uint64_t>(k2) * 0xbeefULL +
                   static_cast<uint64_t>(k3) * 0xcafeULL) %
                  MOD_P;

  uint32_t diff = 0;
  diff |= static_cast<uint32_t>(x ^ STAGE2_TARGET_X);
  diff |= static_cast<uint32_t>(y ^ STAGE2_TARGET_Y);
  diff |= static_cast<uint32_t>(inv1 ^ STAGE2_INV1);
  diff |= static_cast<uint32_t>(inv2 ^ STAGE2_INV2);

  out_s2[0] = static_cast<uint32_t>(x);
  out_s2[1] = static_cast<uint32_t>(y);
  out_s2[2] = static_cast<uint32_t>(p);
  out_s2[3] = static_cast<uint32_t>(q);
  return diff;
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage 3: Dynamic Feistel Cipher with Runtime S-Box Derivation
// ─────────────────────────────────────────────────────────────────────────────

const uint8_t STAGE3_TARGET[16] = {0xea, 0x65, 0x6c, 0x32, 0x21, 0xb7,
                                   0x85, 0xc0, 0x99, 0xd4, 0x6c, 0x5e,
                                   0x3c, 0x43, 0x48, 0xcf};

const uint32_t STAGE3_ROUND_KEYS[8] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC,
                                       0xCA62C1D6, 0xC3D2E1F0, 0x10325476,
                                       0x98BADCFE, 0xEFCDAB89};

inline uint32_t verify_stage3(const char *input,
                              const std::array<uint32_t, 4> &s2,
                              std::array<uint32_t, 4> &out_s3) {
  if (!input || std::strlen(input) != 16) {
    return 0xFFFFFFFF;
  }

  // Dynamic S-box derivation from S2
  uint8_t dyn_sbox[256];
  for (int i = 0; i < 256; ++i)
    dyn_sbox[i] = static_cast<uint8_t>(i);

  uint8_t key_bytes[16];
  std::memcpy(key_bytes, s2.data(), 16);

  uint8_t j = 0;
  for (int i = 0; i < 256; ++i) {
    j = static_cast<uint8_t>(j + dyn_sbox[i] + key_bytes[i % 16]);
    uint8_t tmp = dyn_sbox[i];
    dyn_sbox[i] = dyn_sbox[j];
    dyn_sbox[j] = tmp;
  }
  security::SecureBuffer<uint8_t> key_guard(key_bytes, 16);

  uint64_t L = 0, R = 0;
  std::memcpy(&L, input, 8);
  std::memcpy(&R, input + 8, 8);

  for (int r = 0; r < 8; ++r) {
    // Feistel round function
    uint64_t sb = 0;
    for (int i = 0; i < 8; ++i) {
      uint8_t b = static_cast<uint8_t>((R >> (8 * i)) & 0xFF);
      sb |= (static_cast<uint64_t>(dyn_sbox[b]) << (8 * i));
    }
    uint64_t mixed = sb * static_cast<uint64_t>(STAGE3_ROUND_KEYS[r]);
    uint64_t f_val = (mixed << 13) | (mixed >> (64 - 13));

    uint64_t nL = R;
    uint64_t nR = L ^ f_val;
    L = nL;
    R = nR;
  }

  uint8_t cipher[16];
  std::memcpy(cipher, &L, 8);
  std::memcpy(cipher + 8, &R, 8);
  security::SecureBuffer<uint8_t> cipher_guard(cipher, 16);

  uint32_t diff = 0;
  for (int i = 0; i < 16; ++i) {
    diff |= (cipher[i] ^ STAGE3_TARGET[i]);
  }

  std::memcpy(out_s3.data(), cipher, 16);
  return diff;
}

// ─────────────────────────────────────────────────────────────────────────────
// Stage 4: Sponge Mixing Network & Sealing
// ─────────────────────────────────────────────────────────────────────────────

const uint32_t STAGE4_TARGET[8] = {0x962ff387, 0x2c2bd967, 0xa20f71f5,
                                   0xed83d7d8, 0x7ad3a7f2, 0xbab46fee,
                                   0xdfcb6312, 0x9ad894e1};

const uint32_t SPONGE_RC[6] = {0x428A2F98, 0x71374491, 0xB5C0FBCF,
                               0xE9B5DBA5, 0x3956C25B, 0x59F111F1};

const int SPONGE_ROT[8] = {3, 7, 11, 17, 19, 23, 29, 31};

inline uint32_t verify_stage4(const char *input,
                              const std::array<uint32_t, 4> &s1,
                              const std::array<uint32_t, 4> &s2,
                              const std::array<uint32_t, 4> &s3,
                              std::array<uint32_t, 8> &out_s4) {
  if (!input || std::strlen(input) != 8) {
    return 0xFFFFFFFF;
  }

  uint32_t inp_w[2];
  std::memcpy(inp_w, input, 8);

  uint32_t A[8] = {s1[0] ^ s2[0],         s1[1] ^ s2[1],        s1[2] ^ s3[0],
                   s1[3] ^ s3[1],         s2[2] ^ s3[2],        s2[3] ^ s3[3],
                   inp_w[0] ^ 0x6A09E667, inp_w[1] ^ 0xBB67AE85};
  security::SecureBuffer<uint32_t> state_guard(A, 8);

  for (int r = 0; r < 6; ++r) {
    // Theta: parity mixing
    uint32_t parity = 0;
    for (int i = 0; i < 8; ++i)
      parity ^= A[i];
    uint32_t rot_p = (parity << 1) | (parity >> 31);
    for (int i = 0; i < 8; ++i)
      A[i] ^= rot_p;

    // Rho & Pi: rotate and permute
    uint32_t nA[8];
    for (int i = 0; i < 8; ++i) {
      uint32_t w = A[i];
      int rot = SPONGE_ROT[i];
      uint32_t rot_w = (w << rot) | (w >> (32 - rot));
      nA[(i * 3 + 1) % 8] = rot_w;
    }
    std::memcpy(A, nA, sizeof(A));

    // Chi: non-linear row bitwise AND-inversion
    uint32_t A_chi[8];
    for (int i = 0; i < 8; ++i) {
      A_chi[i] = A[i] ^ ((~A[(i + 1) % 8]) & A[(i + 2) % 8]);
    }
    std::memcpy(A, A_chi, sizeof(A));

    // Iota: round constant
    A[0] ^= SPONGE_RC[r];
  }

  uint32_t diff = 0;
  for (int i = 0; i < 8; ++i) {
    diff |= (A[i] ^ STAGE4_TARGET[i]);
    out_s4[i] = A[i];
  }
  return diff;
}

// ─────────────────────────────────────────────────────────────────────────────
// Flag Unmasking Engine
// ─────────────────────────────────────────────────────────────────────────────

const uint8_t ENCRYPTED_FLAG[35] = {
    0xe4, 0xec, 0x6f, 0xdf, 0x62, 0x42, 0x2d, 0xff, 0x2f, 0x31, 0x23, 0x87,
    0xae, 0xd0, 0xcc, 0x76, 0x40, 0xa1, 0x90, 0xbc, 0x2f, 0xad, 0x06, 0x47,
    0xd8, 0x27, 0xfc, 0x67, 0xaf, 0x3c, 0x3a, 0x8a, 0x2c, 0xbe, 0x56};

inline void decrypt_flag(const std::array<uint32_t, 4> &s1,
                         const std::array<uint32_t, 4> &s2,
                         const std::array<uint32_t, 4> &s3,
                         const std::array<uint32_t, 8> &s4, char *out_flag) {
  uint8_t all_state[16 * 4 + 32];
  size_t pos = 0;

  auto append_words = [&](const auto &arr, size_t count) {
    for (size_t i = 0; i < count; ++i) {
      uint32_t w = arr[i];
      all_state[pos++] = static_cast<uint8_t>(w & 0xFF);
      all_state[pos++] = static_cast<uint8_t>((w >> 8) & 0xFF);
      all_state[pos++] = static_cast<uint8_t>((w >> 16) & 0xFF);
      all_state[pos++] = static_cast<uint8_t>((w >> 24) & 0xFF);
    }
  };

  append_words(s1, 4);
  append_words(s2, 4);
  append_words(s3, 4);
  append_words(s4, 8);

  uint32_t seed = 0x85EBCA6B;
  for (size_t i = 0; i < sizeof(ENCRYPTED_FLAG); ++i) {
    size_t idx = i % pos;
    seed = (seed * 1664525ULL + 1013904223ULL + all_state[idx]) & 0xFFFFFFFF;
    uint8_t k = static_cast<uint8_t>((seed >> 16) & 0xFF);
    out_flag[i] = static_cast<char>(ENCRYPTED_FLAG[i] ^ k);
  }
  out_flag[sizeof(ENCRYPTED_FLAG)] = '\0';

  security::secure_zero(all_state, sizeof(all_state));
}

} // namespace ctf::crypto
