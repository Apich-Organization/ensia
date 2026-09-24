#include <stdint.h>
#include <stdio.h>

__attribute__((noinline)) int32_t cff_loop_branch(int32_t val, int32_t iters) {
  int32_t acc = val;
  for (int i = 0; i < iters; i++) {
    if (acc % 2 == 0) {
      acc = acc / 2 + 3;
    } else if (acc % 3 == 0) {
      acc = acc * 3 + 1;
    } else {
      acc = acc + 7;
    }
  }
  return acc;
}

__attribute__((noinline)) int32_t cff_switch_nested(int32_t op, int32_t val) {
  int32_t res = val;
  switch (op % 6) {
  case 0:
    res = val * 7 + 1;
    break;
  case 1:
    res = (val ^ 0x3344) + 5;
    break;
  case 2:
    res = (val << 2) - 3;
    break;
  case 3:
    res = val / 3 + 19;
    break;
  case 4:
    res = val ^ 0x5A5A;
    break;
  default:
    res = val + op;
    break;
  }
  if (res > 100) {
    res -= 50;
  } else {
    res += 25;
  }
  return res;
}

__attribute__((noinline)) int32_t bcf_nested_conditionals(int32_t a,
                                                          int32_t b) {
  int32_t sum = 0;
  if (a > 10) {
    if (b < 20) {
      sum = a + b * 2;
    } else {
      sum = a - b;
    }
  } else {
    if (b > 5) {
      sum = a * b - 3;
    } else {
      sum = a ^ b;
    }
  }
  return sum;
}

int main(int argc, char **argv) {
  int32_t v = argc > 1 ? argv[1][0] : 15;
  int32_t r1 = cff_loop_branch(v, 10);
  int32_t r2 = cff_switch_nested(v, 40);
  int32_t r3 = bcf_nested_conditionals(v, 8);
  printf("CFG Checksum: %d\n", r1 + r2 + r3);
  return 0;
}
