#include <stdio.h>
#include <stdlib.h>

__attribute__((noinline)) int indibran_decision_tree(int a, int b, int c) {
  int res = 0;
  if (a > 10) {
    if (b < 20) {
      res = a * b + c;
    } else {
      res = a - b + (c * 2);
    }
  } else {
    if (c > 5) {
      res = (a + b) ^ c;
    } else {
      res = (a ^ b) - c;
    }
  }

  for (int i = 0; i < (a & 7); i++) {
    if (i % 2 == 0) {
      res += i * 5;
    } else {
      res ^= (i << 2);
    }
  }
  return res;
}

int main(int argc, char **argv) {
  int v = (argc > 1) ? atoi(argv[1]) : 15;
  int r1 = indibran_decision_tree(v, 12, 7);
  int r2 = indibran_decision_tree(v - 10, 25, 3);
  printf("INDIBRAN Result: %d, %d\n", r1, r2);
  return 0;
}
