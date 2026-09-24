#include <stdint.h>
#include <stdio.h>

__attribute__((noinline)) int32_t split_target_block(int32_t a, int32_t b,
                                                     int32_t c) {
  int32_t v1 = a + 1;
  int32_t v2 = v1 ^ b;
  int32_t v3 = v2 * 3;
  int32_t v4 = v3 - c;
  int32_t v5 = v4 + 7;
  int32_t v6 = v5 ^ 0xAA;
  int32_t v7 = v6 * 5;
  int32_t v8 = v7 - a;
  int32_t v9 = v8 + b;
  int32_t v10 = v9 ^ c;
  return v10;
}

int main(int argc, char **argv) {
  int32_t a = argc > 1 ? argv[1][0] : 10;
  int32_t r = split_target_block(a, 20, 30);
  printf("Split Checksum: %d\n", r);
  return 0;
}
