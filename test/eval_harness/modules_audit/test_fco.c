#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  const char *msg = "FCO Test Message 2026";
  size_t len = strlen(msg);
  char *buf = (char *)malloc(len + 16);
  if (!buf)
    return 1;
  strcpy(buf, msg);
  int cmp = strcmp(buf, "FCO Test Message 2026");
  printf("FCO Buffer: %s (len=%zu, cmp=%d)\n", buf, len, cmp);
  free(buf);
  return 0;
}
