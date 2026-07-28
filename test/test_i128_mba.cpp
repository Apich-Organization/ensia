#include <cassert>
#include <cstdint>
#include <iostream>

typedef __int128_t int128_t;
typedef __uint128_t uint128_t;

__attribute__((noinline)) int128_t test_mul128(int128_t a, int128_t b) {
  return a * b;
}

__attribute__((noinline)) int128_t test_shl128(int128_t a, int b) {
  return a << b;
}

__attribute__((noinline)) int128_t test_lshr128(uint128_t a, int b) {
  return a >> b;
}

__attribute__((noinline)) int128_t test_ashr128(int128_t a, int b) {
  return a >> b;
}

int main() {
  int128_t a = ((int128_t)0x123456789ABCDEF0ULL << 64) | 0xFEDCBA9876543210ULL;
  int128_t b = ((int128_t)0x0000000000000005ULL << 64) | 0x0000000000000003ULL;

  int128_t expected_mul = a * b;
  int128_t actual_mul = test_mul128(a, b);
  assert(actual_mul == expected_mul);

  int128_t expected_shl = a << 64;
  int128_t actual_shl = test_shl128(a, 64);
  assert(actual_shl == expected_shl);

  uint128_t expected_lshr = (uint128_t)a >> 64;
  uint128_t actual_lshr = test_lshr128((uint128_t)a, 64);
  assert(actual_lshr == expected_lshr);

  int128_t expected_ashr = a >> 64;
  int128_t actual_ashr = test_ashr128(a, 64);
  assert(actual_ashr == expected_ashr);

  std::cout << "[PASS] 128-bit integer MBA & Substitution tests passed!"
            << std::endl;
  return 0;
}
