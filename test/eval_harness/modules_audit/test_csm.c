#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) int csm_target_logic(int val, int n) {
  int acc = val;
  for (int i = 0; i < n; i++) {
    if ((acc & 1) == 0) {
      acc = (acc ^ 0x5A5A5A5A) + (i * 3);
    } else if ((acc & 3) == 1) {
      acc = (acc * 33) ^ 0x3C3C3C3C;
    } else {
      acc = (acc >> 1) + 0x12345678;
    }
    if (acc < 0) {
      acc = -acc;
    }
  }
  return acc;
}

int main(int argc, char **argv) {
  int seed = 42;
  if (argc > 1)
    seed = atoi(argv[1]);
  int r1 = csm_target_logic(seed, 10);
  int r2 = csm_target_logic(seed + 1337, 15);
  printf("CSM Result: %08X, %08X\n", r1, r2);
  return 0;
}
