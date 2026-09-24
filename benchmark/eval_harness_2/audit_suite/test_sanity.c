#include <stdio.h>

int target(int a, int b) { return (a ^ b) + (a & b) * 2; }

int main() {
  printf("Result: %d\n", target(10, 20));
  return 0;
}
