#include <stdint.h>
#include <stdio.h>

__attribute__((noinline)) int32_t vector_target_math(int32_t a, int32_t b) {
  int32_t x1 = a + b;
  int32_t x2 = a - b;
  int32_t x3 = x1 ^ x2;
  int32_t x4 = (x1 & 0x0F) * 3;
  int32_t x5 = (x2 | 0x30) + x3;
  return x4 + x5;
}

int main(int argc, char **argv) {
  int32_t a = argc > 1 ? argv[1][0] : 12;
  int32_t b = argc > 2 ? argv[2][0] : 34;
  int32_t r = vector_target_math(a, b);
  printf("Vector Result: %d\n", r);
  return 0;
}
