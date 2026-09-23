#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ChaCha quarter-round style core
#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

void chacha_qr(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = ROTL32(*d, 16);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 12);
    *a += *b; *d ^= *a; *d = ROTL32(*d, 8);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 7);
}

// 64-bit non-linear integer mixing (Murmur-style)
uint64_t mix64(uint64_t k) {
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdULL;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53ULL;
    k ^= k >> 33;
    return k;
}

// GF(2^8) Galois Field multiplication using AES polynomial (0x11B)
uint8_t gf8_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

// S-box affine transform
uint8_t sbox_affine(uint8_t b) {
    uint8_t p = b;
    for (int i = 1; i < 5; i++) {
        p ^= ((b << i) | (b >> (8 - i)));
    }
    return p ^ 0x63;
}

// Composite hash function testing all components
uint64_t evaluate_crypto_pipeline(const uint8_t *input, size_t len) {
    uint32_t state[4] = {0x61707865, 0x33326e69, 0x79622d32, 0x6b206574};
    uint64_t accum = 0x9e3779b97f4a7c15ULL;

    for (size_t i = 0; i < len; i++) {
        uint8_t b = input[i];
        uint8_t s = sbox_affine(gf8_mul(b, (uint8_t)(i + 1)));
        state[i % 4] ^= ((uint32_t)s << ((i % 4) * 8));
        if ((i % 4) == 3 || i == len - 1) {
            chacha_qr(&state[0], &state[1], &state[2], &state[3]);
        }
        accum = mix64(accum ^ ((uint64_t)state[0] << 32 | state[1]));
    }
    accum ^= ((uint64_t)state[2] << 32 | state[3]);
    return mix64(accum);
}

int main(int argc, char **argv) {
    const char *test_data = "Ensia-Next-Gen-LLVM-Compiler-Obfuscation-Verification-Vector-2026!";
    uint64_t res = evaluate_crypto_pipeline((const uint8_t *)test_data, strlen(test_data));
    printf("CRYPTO_HASH: 0x%016llx\n", (unsigned long long)res);

    // Verify determinism across multiple rounds
    uint64_t check = evaluate_crypto_pipeline((const uint8_t *)test_data, strlen(test_data));
    if (res != check) {
        fprintf(stderr, "Non-deterministic execution detected!\n");
        return 1;
    }
    return 0;
}
