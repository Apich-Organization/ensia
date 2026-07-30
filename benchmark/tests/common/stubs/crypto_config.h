/**
 * @file crypto_config.h
 * @brief CycloneCRYPTO feature-flag configuration — ALL algorithms enabled
 *
 * This file enables every algorithm available in the benchmark directory.
 * Individual test targets may selectively override via compiler -D flags
 * if linking only a subset of sources.
 *
 * IMPORTANT: This file must appear before any CycloneCRYPTO source include.
 */

#ifndef _CRYPTO_CONFIG_H
#define _CRYPTO_CONFIG_H

/* ---- Static memory allocation (use standard heap for host tests) ---- */
#define CRYPTO_STATIC_MEM_SUPPORT    DISABLED

/* ---- MPI (big-integer) support ---- */
#define MPI_SUPPORT                  ENABLED
#define MPI_ASM_SUPPORT              DISABLED
#define MPI_MAX_BIT_LENGTH           4096

/* ---- Encoding ---- */
#define BASE64_SUPPORT               ENABLED
#define BASE64URL_SUPPORT            ENABLED
#define RADIX64_SUPPORT              ENABLED

/* ============================================================
 *  Hash algorithms
 * ============================================================ */
#define MD2_SUPPORT                  ENABLED
#define MD4_SUPPORT                  ENABLED
#define MD5_SUPPORT                  ENABLED
#define RIPEMD128_SUPPORT            ENABLED
#define RIPEMD160_SUPPORT            ENABLED
#define SHA1_SUPPORT                 ENABLED
#define SHA224_SUPPORT               ENABLED
#define SHA256_SUPPORT               ENABLED
#define SHA384_SUPPORT               ENABLED
#define SHA512_SUPPORT               ENABLED
#define SHA512_224_SUPPORT           ENABLED
#define SHA512_256_SUPPORT           ENABLED
#define SHA3_224_SUPPORT             ENABLED
#define SHA3_256_SUPPORT             ENABLED
#define SHA3_384_SUPPORT             ENABLED
#define SHA3_512_SUPPORT             ENABLED
#define ASCON_HASH256_SUPPORT        ENABLED
#define BLAKE2B_SUPPORT              ENABLED
#define BLAKE2B160_SUPPORT           ENABLED
#define BLAKE2B256_SUPPORT           ENABLED
#define BLAKE2B384_SUPPORT           ENABLED
#define BLAKE2B512_SUPPORT           ENABLED
#define BLAKE2S_SUPPORT              ENABLED
#define BLAKE2S128_SUPPORT           ENABLED
#define BLAKE2S160_SUPPORT           ENABLED
#define BLAKE2S224_SUPPORT           ENABLED
#define BLAKE2S256_SUPPORT           ENABLED
#define TIGER_SUPPORT                ENABLED
#define WHIRLPOOL_SUPPORT            ENABLED
#define SM3_SUPPORT                  ENABLED

/* ============================================================
 *  XOF algorithms
 * ============================================================ */
#define KECCAK_SUPPORT               ENABLED
#define SHAKE128_SUPPORT             ENABLED
#define SHAKE256_SUPPORT             ENABLED
#define CSHAKE128_SUPPORT            ENABLED
#define CSHAKE256_SUPPORT            ENABLED

/* ============================================================
 *  Cipher algorithms
 * ============================================================ */
#define AES_SUPPORT                  ENABLED
#define DES_SUPPORT                  ENABLED
#define DES3_SUPPORT                 ENABLED
#define BLOWFISH_SUPPORT             ENABLED
#define CAST128_SUPPORT              ENABLED
#define CAST256_SUPPORT              ENABLED
#define CAMELLIA_SUPPORT             ENABLED
#define IDEA_SUPPORT                 ENABLED
#define MARS_SUPPORT                 ENABLED
#define PRESENT_SUPPORT              ENABLED
#define RC2_SUPPORT                  ENABLED
#define RC4_SUPPORT                  ENABLED
#define RC6_SUPPORT                  ENABLED
#define SEED_SUPPORT                 ENABLED
#define SERPENT_SUPPORT              ENABLED
#define SM4_SUPPORT                  ENABLED
#define TEA_SUPPORT                  ENABLED
#define XTEA_SUPPORT                 ENABLED
#define TWOFISH_SUPPORT              ENABLED
#define ZUC_SUPPORT                  ENABLED
#define CHACHA_SUPPORT               ENABLED
#define SALSA20_SUPPORT              ENABLED
#define TRIVIUM_SUPPORT              ENABLED
#define ARIA_SUPPORT                 ENABLED

/* ============================================================
 *  Block cipher modes
 * ============================================================ */
#define ECB_SUPPORT                  ENABLED
#define CBC_SUPPORT                  ENABLED
#define CFB_SUPPORT                  ENABLED
#define OFB_SUPPORT                  ENABLED
#define CTR_SUPPORT                  ENABLED
#define XTS_SUPPORT                  ENABLED

/* ============================================================
 *  AEAD modes
 * ============================================================ */
#define GCM_SUPPORT                  ENABLED
#define CCM_SUPPORT                  ENABLED
#define SIV_SUPPORT                  ENABLED
#define CHACHA20_POLY1305_SUPPORT    ENABLED

/* ============================================================
 *  MAC algorithms
 * ============================================================ */
#define HMAC_SUPPORT                 ENABLED
#define CMAC_SUPPORT                 ENABLED
#define GMAC_SUPPORT                 ENABLED
#define POLY1305_SUPPORT             ENABLED
#define KMAC_SUPPORT                 ENABLED
#define XCBC_MAC_SUPPORT             ENABLED
#define BLAKE2B_MAC_SUPPORT          ENABLED
#define BLAKE2S_MAC_SUPPORT          ENABLED

/* ============================================================
 *  KDF algorithms
 * ============================================================ */
#define HKDF_SUPPORT                 ENABLED
#define PBKDF_SUPPORT                ENABLED
#define BCRYPT_SUPPORT               ENABLED
#define SCRYPT_SUPPORT               ENABLED
#define SHA_CRYPT_SUPPORT            ENABLED
#define MD5_CRYPT_SUPPORT            ENABLED
#define CONCAT_KDF_SUPPORT           ENABLED

/* ============================================================
 *  Lightweight cryptography (LWC)
 * ============================================================ */
#define ASCON_SUPPORT                ENABLED
#define ASCON_AEAD128_SUPPORT        ENABLED
#define ASCON_XOF128_SUPPORT         ENABLED
#define ASCON_CXOF128_SUPPORT        ENABLED

/* ============================================================
 *  Public-key cryptography
 * ============================================================ */
#define RSA_SUPPORT                  ENABLED
#define DSA_SUPPORT                  ENABLED
#define DH_SUPPORT                   ENABLED
#define EC_SUPPORT                   ENABLED
#define ECDH_SUPPORT                 ENABLED
#define ECDSA_SUPPORT                ENABLED
#define EDDSA_SUPPORT                ENABLED
#define ED25519_SUPPORT              ENABLED
#define ED448_SUPPORT                ENABLED
#define X25519_SUPPORT               ENABLED
#define X448_SUPPORT                 ENABLED
#define SM2_SUPPORT                  ENABLED
#define CURVE25519_SUPPORT           ENABLED
#define CURVE448_SUPPORT             ENABLED

/* ============================================================
 *  Post-quantum cryptography
 * ============================================================ */
#define KEM_SUPPORT                  ENABLED
#define ML_KEM_SUPPORT               ENABLED
#define ML_DSA_SUPPORT               ENABLED
#define SNTRUP761_SUPPORT            ENABLED

/* ============================================================
 *  Hash sizes (used by HMAC, etc.)
 * ============================================================ */
#define MAX_HASH_DIGEST_SIZE         64   /* SHA-512 */
#define MAX_HASH_BLOCK_SIZE          144  /* SHA3-224 */

/* ============================================================
 *  PRNG (not used in deterministic tests, stubbed)
 * ============================================================ */
#define YARROW_SUPPORT               DISABLED
#define FORTUNA_SUPPORT              DISABLED
#define TRUE_RANDOMNESS_SUPPORT      DISABLED

#endif /* _CRYPTO_CONFIG_H */
