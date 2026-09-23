#include <stdint.h>
#include <stdio.h>
#include <string.h>

__attribute__((noinline)) const char *strenc_get_secret(int id) {
  if (id == 1) {
    return "HARDCODED_API_KEY_9876543210_SECRET";
  } else if (id == 2) {
    return "CRITICAL_DATABASE_PASSWORD_XYZ123";
  }
  return "STANDARD_DEFAULT_FALLBACK_STRING";
}

int main(int argc, char **argv) {
  int id = argc > 1 ? argv[1][0] - '0' : 1;
  const char *s = strenc_get_secret(id);
  printf("StrEnc Output: %s (len=%zu)\n", s, strlen(s));
  return 0;
}
