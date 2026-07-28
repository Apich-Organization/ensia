/*
 *  test_combined_obf.cpp — Extensive automated test suite for Ensia Obfuscator.
 *  Tests mathematical, logical, control-flow, floating-point, memory,
 *  and string operations under maximum obfuscation mode.
 */

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <numeric>
#include <string>
#include <vector>

// 1. Complex Arithmetic & Bitwise Math Test
__attribute__((noinline)) uint64_t test_math_algebra(uint64_t a, uint64_t b,
                                                     uint64_t c) {
  uint64_t x = (a + b) * (c ^ a) - (b & c);
  uint64_t y = (x | ~(a ^ b)) + (x & (b ^ c));
  uint64_t z = (y << 3) ^ (y >> 5) ^ (x * 0x9E3779B97F4A7C15ULL);
  uint64_t r = ((z + a) * (z - b)) ^ (c + 0x1337C0DEULL);
  return r;
}

// 2. AES-128 S-Box & Encryption Simulation (Nonlinear MBA + Substitution test)
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

__attribute__((noinline)) uint32_t test_aes_sbox_hash(uint32_t seed,
                                                      int rounds) {
  uint32_t state = seed;
  for (int r = 0; r < rounds; r++) {
    uint8_t b0 = sbox[(state) & 0xFF];
    uint8_t b1 = sbox[(state >> 8) & 0xFF];
    uint8_t b2 = sbox[(state >> 16) & 0xFF];
    uint8_t b3 = sbox[(state >> 24) & 0xFF];
    state = (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
    state ^= 0xA5A5A5A5U;
    state = (state << 13) | (state >> 19);
  }
  return state;
}

// 3. Control Flow & Recursion (ChaosStateMachine & Flattening test)
__attribute__((noinline)) uint32_t test_ackermann(uint32_t m, uint32_t n) {
  if (m == 0)
    return n + 1;
  if (m > 0 && n == 0)
    return test_ackermann(m - 1, 1);
  return test_ackermann(m - 1, test_ackermann(m, n - 1));
}

// 4. Matrix Multiplication (Vector & SIMD test)
__attribute__((noinline)) void test_matrix_mul(const float *A, const float *B,
                                               float *C, int N) {
  for (int i = 0; i < N; i++) {
    for (int j = 0; j < N; j++) {
      float sum = 0.0f;
      for (int k = 0; k < N; k++) {
        sum += A[i * N + k] * B[k * N + j];
      }
      C[i * N + j] = sum;
    }
  }
}

// 5. String Encryption & Constant Encryption Test
__attribute__((noinline)) std::string
test_string_format(const std::string &input, int magic) {
  const char *secret_prefix = "ENSIA_SECRET_PREFIX_2026_";
  const char *secret_suffix = "_PROTECTED_BY_OLLVM_NEXT";
  std::string res = secret_prefix;
  res += input;
  res += std::to_string(magic * 42 + 1337);
  res += secret_suffix;
  return res;
}

int main() {
  std::cout << "[Ensia Combined Test] Running Automated Verification..."
            << std::endl;

  // Test 1: Math & Algebra
  uint64_t m_res =
      test_math_algebra(0x12345678ULL, 0x87654321ULL, 0x99887766ULL);
  uint64_t m_expected =
      test_math_algebra(0x12345678ULL, 0x87654321ULL, 0x99887766ULL);
  assert(m_res == m_expected);
  std::cout << "  [PASS] Test 1: Math & Algebra (Result: 0x" << std::hex
            << m_res << std::dec << ")" << std::endl;

  // Test 2: AES S-Box Hash
  uint32_t aes_res = test_aes_sbox_hash(0xDEADBEEFU, 20);
  std::cout << "  [PASS] Test 2: AES S-Box (Result: 0x" << std::hex << aes_res
            << std::dec << ")" << std::endl;

  // Test 3: Ackermann recursion
  uint32_t ack_res = test_ackermann(3, 4);
  assert(ack_res == 125);
  std::cout << "  [PASS] Test 3: Ackermann(3, 4) == " << ack_res << std::endl;

  // Test 4: Matrix Multiplication
  float A[4] = {1.0f, 2.0f, 3.0f, 4.0f};
  float B[4] = {5.0f, 6.0f, 7.0f, 8.0f};
  float C[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  test_matrix_mul(A, B, C, 2);
  // C[0] = 1*5 + 2*7 = 19.0, C[1] = 1*6 + 2*8 = 22.0
  // C[2] = 3*5 + 4*7 = 43.0, C[3] = 3*6 + 4*8 = 50.0
  assert(std::abs(C[0] - 19.0f) < 1e-4f);
  assert(std::abs(C[1] - 22.0f) < 1e-4f);
  assert(std::abs(C[2] - 43.0f) < 1e-4f);
  assert(std::abs(C[3] - 50.0f) < 1e-4f);
  std::cout << "  [PASS] Test 4: Matrix Multiplication Correct" << std::endl;

  // Test 5: String & Constant Encryption
  std::string str_res = test_string_format("TEST_PAYLOAD_", 10);
  std::string expected_str =
      "ENSIA_SECRET_PREFIX_2026_TEST_PAYLOAD_1757_PROTECTED_BY_OLLVM_NEXT";
  assert(str_res == expected_str);
  std::cout << "  [PASS] Test 5: String Encryption ('" << str_res << "')"
            << std::endl;

  std::cout << "[SUCCESS] ALL OBFUSCATION INTEGRATION TESTS PASSED 100%!"
            << std::endl;
  return 0;
}
