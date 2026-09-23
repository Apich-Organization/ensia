#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((noinline)) int worker_math(int a, int b) {
  int v = (a * 17) ^ (b + 0x55AA55AA);
  if (v > 100)
    v -= 50;
  else
    v += 50;
  return v;
}

__attribute__((noinline)) int complex_workflow(int input, const char *token) {
  int state = input ^ 0x33445566;
  for (int i = 0; i < 6; i++) {
    if ((state & 1) == 0) {
      state = worker_math(state, i) + 0x1234;
    } else {
      state = (state >> 1) ^ 0x789A;
    }
  }
  size_t tlen = strlen(token);
  return state + (int)tlen;
}

int main(int argc, char **argv) {
  int seed = (argc > 1) ? atoi(argv[1]) : 99;
  const char *tok = "COMBINED_MODULES_AUDIT_TOKEN_2026";
  int res = complex_workflow(seed, tok);
  printf("COMBINED Workflow Result: %08X\n", res);
  return 0;
}
