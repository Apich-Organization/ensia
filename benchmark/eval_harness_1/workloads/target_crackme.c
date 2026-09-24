#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Crackme verification function
// Known valid key: "K3y_P4ss"
int verify_key(const char *key) {
    if (!key) return 0;
    if (strlen(key) < 8) return 0;

    uint32_t w0 = ((uint32_t)(uint8_t)key[0]) |
                  (((uint32_t)(uint8_t)key[1]) << 8) |
                  (((uint32_t)(uint8_t)key[2]) << 16) |
                  (((uint32_t)(uint8_t)key[3]) << 24);

    uint32_t w1 = ((uint32_t)(uint8_t)key[4]) |
                  (((uint32_t)(uint8_t)key[5]) << 8) |
                  (((uint32_t)(uint8_t)key[6]) << 16) |
                  (((uint32_t)(uint8_t)key[7]) << 24);

    // Constraint 1: Affine MBA-like constraint on w0
    uint32_t t0 = ((w0 * 0x1337) ^ 0x5a17e9b3) + (w0 >> 3);
    if (t0 != 0xe7bea617) {
        return 0;
    }

    // Constraint 2: Non-linear coupling between w0 and w1
    uint32_t t1 = (w1 ^ w0) * 0x6543210f;
    uint32_t rot = (t1 << 13) | (t1 >> 19);
    if ((rot + (w1 & 0x00FF00FF)) != 0x3d25aca2) {
        return 0;
    }

    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <8-char-key>\n", argv[0]);
        return 2;
    }
    if (verify_key(argv[1])) {
        printf("KEY_VALID: SUCCESS!\n");
        return 0;
    } else {
        printf("KEY_INVALID: FAIL!\n");
        return 1;
    }
}
