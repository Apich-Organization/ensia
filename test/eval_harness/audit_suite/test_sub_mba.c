#include <stdint.h>
#include <stdio.h>

__attribute__((noinline)) int32_t arith_add_sub(int32_t a, int32_t b) {
  int32_t s1 = a + b;
  int32_t d1 = a - b;
  int32_t s2 = s1 + 0x1234;
  int32_t d2 = d1 - 0x5678;
  return s2 ^ d2;
}

__attribute__((noinline)) int32_t arith_bitwise(int32_t a, int32_t b) {
  int32_t x1 = a ^ b;
  int32_t a1 = a & b;
  int32_t o1 = a | b;
  return (x1 + a1) ^ o1;
}

__attribute__((noinline)) int32_t arith_mul_shift(int32_t a, int32_t b) {
  int32_t m1 = a * 13;
  int32_t s1 = b << 3;
  int32_t s2 = (uint32_t)a >> 2;
  int32_t s3 = b >> 4;
  return m1 + s1 - s2 + s3;
}

__attribute__((noinline)) int32_t arith_complex_mba(int32_t x, int32_t y) {
  // Standard target for MBA expansion: (x ^ y) + 2*(x & y) == x + y
  int32_t t1 = (x ^ y) + 2 * (x & y);
  int32_t t2 = (x | y) - (x & ~y);
  return t1 * 3 + t2;
}

int main(int argc, char **argv) {
  int32_t a = argc > 1 ? argv[1][0] : 42;
  int32_t b = argc > 2 ? argv[2][0] : 17;
  int32_t r1 = arith_add_sub(a, b);
  int32_t r2 = arith_bitwise(a, b);
  int32_t r3 = arith_mul_shift(a, b);
  int32_t r4 = arith_complex_mba(a, b);
  printf("MBA/SUB Checksum: %d\n", r1 + r2 + r3 + r4);
  return 0;
}
