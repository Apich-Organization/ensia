#include <stdint.h>
#include <stdio.h>

__attribute__((noinline)) int32_t protected_core_logic(int32_t x) {
  int32_t acc = x;
  for (int i = 0; i < 5; i++) {
    acc = (acc * 31) ^ (i + 0x1337);
  }
  return acc;
}

int main(int argc, char **argv) {
  int32_t input = argc > 1 ? argv[1][0] : 10;
  int32_t out = protected_core_logic(input);
  printf("Protected Core Logic Result: %d\n", out);
  return 0;
}
