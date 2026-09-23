#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) int32_t callee_target(int32_t a, int32_t b) {
  return a * 3 + b * 7;
}

__attribute__((noinline)) int32_t caller_func(int32_t x) {
  int32_t a = callee_target(x, 10);
  int32_t b = callee_target(x + 1, 20);
  printf("caller_func intermediate: %d, %d\n", a, b);
  return a + b;
}

int main(int argc, char **argv) {
  int32_t val = argc > 1 ? argv[1][0] : 5;
  int32_t res = caller_func(val);
  printf("Caller Result: %d\n", res);
  return 0;
}
