#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) uint32_t crypto_const_calc(uint32_t val) {
  uint32_t c1 = 0x5A827999;
  uint32_t c2 = 0x6ED9EBA1;
  uint32_t c3 = 0x8F1BBCDC;
  uint32_t c4 = 0xCA62C1D6;

  // Mix with trivial and non-trivial constants
  uint32_t acc = val + 1;  // trivial constant 1
  acc = (acc ^ c1) * 3;    // trivial constant 3, non-trivial c1
  acc = (acc + c2) ^ 0xFF; // trivial mask 0xFF, non-trivial c2
  acc = (acc ^ c3) - c4;
  return acc;
}

int main(int argc, char **argv) {
  uint32_t in = (argc > 1) ? (uint32_t)atoi(argv[1]) : 0x12345678;
  uint32_t out = crypto_const_calc(in);
  printf("CONSTENC Result: %08X -> %08X\n", in, out);
  return 0;
}
