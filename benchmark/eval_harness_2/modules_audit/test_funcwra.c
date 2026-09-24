#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) int worker_add(int a, int b) { return a + b; }

__attribute__((noinline)) int worker_compute(int x, int y, int z) {
  return (x * y) ^ (z + 0x1337);
}

__attribute__((noinline)) void worker_accumulate(int *out, int val) {
  *out += val;
}

int main(int argc, char **argv) {
  int seed = (argc > 1) ? atoi(argv[1]) : 7;
  int acc = 0;
  int v1 = worker_add(seed, 42);
  int v2 = worker_compute(seed, v1, 100);
  worker_accumulate(&acc, v1);
  worker_accumulate(&acc, v2);
  printf("FUNCWRA Result: %d, %d, %d\n", v1, v2, acc);
  return 0;
}
