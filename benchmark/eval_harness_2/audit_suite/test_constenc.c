#include <stdint.h>
#include <stdio.h>

__attribute__((noinline)) uint32_t constenc_target_32(uint32_t x) {
  uint32_t c1 = 0x1337BEEF;
  uint32_t c2 = 0xDEADCAFE;
  uint32_t c3 = 0x41424344;
  uint32_t c4 = 0x7F800000;
  return (x ^ c1) + (x * 37) - (c2 ^ c3) + c4;
}

__attribute__((noinline)) uint64_t constenc_target_64(uint64_t x) {
  uint64_t k1 = 0x0123456789ABCDEFULL;
  uint64_t k2 = 0xFEDCBA9876543210ULL;
  return (x ^ k1) + k2;
}

int main(int argc, char **argv) {
  uint32_t a = argc > 1 ? (uint32_t)argv[1][0] : 0x55;
  uint32_t r32 = constenc_target_32(a);
  uint64_t r64 = constenc_target_64(a);
  printf("ConstEnc Checksum: 0x%08X 0x%016llX\n", r32, (unsigned long long)r64);
  return 0;
}
