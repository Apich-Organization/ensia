#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Functions to be wrapped by FunctionWrapper
int helper_compute(int a, int b) {
    return (a * 7) ^ (b + 13);
}

int helper_transform(int x) {
    int r = helper_compute(x, x ^ 0x55);
    return r + (x << 2);
}

// Routine making multiple external calls (for FCO)
int process_message(const char *msg) {
    if (!msg) return -1;
    size_t len = strlen(msg);
    char *buf = (char *)malloc(len + 16);
    if (!buf) return -2;

    memcpy(buf, msg, len);
    buf[len] = '\0';

    int acc = 0;
    for (size_t i = 0; i < len; i++) {
        acc += helper_transform((int)buf[i]);
    }

    free(buf);
    return acc;
}

int main(int argc, char **argv) {
    const char *text = (argc > 1) ? argv[1] : "EnsiaSystemTestString2026";
    int val = process_message(text);
    printf("SYSTEM_TEST_VAL: %d\n", val);
    return 0;
}
