/**
 * @file cpu_endian.h
 * @brief CPU endianness / byte-swap utilities — stub for benchmark tests
 *
 * Provides all load/store, rotation, and bit-reversal primitives that
 * CycloneCRYPTO algorithm implementations rely on.
 */

#ifndef _CPU_ENDIAN_H
#define _CPU_ENDIAN_H

#include <stdint.h>

/* ---- Byte-reversal (swap) ------------------------------------------------ */

static inline uint16_t reverseInt16(uint16_t value) {
  return (uint16_t)((value >> 8) | (value << 8));
}

static inline uint32_t reverseInt32(uint32_t value) {
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_bswap32(value);
#else
  return ((value & 0xFF000000u) >> 24) | ((value & 0x00FF0000u) >> 8) |
         ((value & 0x0000FF00u) << 8) | ((value & 0x000000FFu) << 24);
#endif
}

static inline uint64_t reverseInt64(uint64_t value) {
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_bswap64(value);
#else
  return ((value & UINT64_C(0xFF00000000000000)) >> 56) |
         ((value & UINT64_C(0x00FF000000000000)) >> 40) |
         ((value & UINT64_C(0x0000FF0000000000)) >> 24) |
         ((value & UINT64_C(0x000000FF00000000)) >> 8) |
         ((value & UINT64_C(0x00000000FF000000)) << 8) |
         ((value & UINT64_C(0x0000000000FF0000)) << 24) |
         ((value & UINT64_C(0x000000000000FF00)) << 40) |
         ((value & UINT64_C(0x00000000000000FF)) << 56);
#endif
}

/* Reverse nibble bits (for GCM table indexing) */
static inline uint8_t reverseInt4(uint8_t value) {
  value = (uint8_t)(((value & 0x0Au) >> 1) | ((value & 0x05u) << 1));
  value = (uint8_t)(((value & 0x0Cu) >> 2) | ((value & 0x03u) << 2));
  return value;
}

/* Reverse byte bits */
static inline uint8_t reverseInt8(uint8_t value) {
  value = (uint8_t)(((value & 0xAAu) >> 1) | ((value & 0x55u) << 1));
  value = (uint8_t)(((value & 0xCCu) >> 2) | ((value & 0x33u) << 2));
  value = (uint8_t)(((value & 0xF0u) >> 4) | ((value & 0x0Fu) << 4));
  return value;
}

/* ---- Unaligned load/store — big-endian ----------------------------------- */

static inline uint16_t LOAD16BE(const void *p) {
  const uint8_t *b = (const uint8_t *)p;
  return (uint16_t)((uint16_t)b[0] << 8 | b[1]);
}

static inline uint32_t LOAD24BE(const void *p) {
  const uint8_t *b = (const uint8_t *)p;
  return ((uint32_t)b[0] << 16) | ((uint32_t)b[1] << 8) | b[2];
}

static inline uint32_t LOAD32BE(const void *p) {
  const uint8_t *b = (const uint8_t *)p;
  return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
         ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

static inline uint64_t LOAD64BE(const void *p) {
  const uint8_t *b = (const uint8_t *)p;
  return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
         ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
         ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
         ((uint64_t)b[6] << 8) | (uint64_t)b[7];
}

/* ---- Unaligned load/store — little-endian -------------------------------- */

static inline uint16_t LOAD16LE(const void *p) {
  const uint8_t *b = (const uint8_t *)p;
  return (uint16_t)(b[0] | ((uint16_t)b[1] << 8));
}

static inline uint32_t LOAD32LE(const void *p) {
  const uint8_t *b = (const uint8_t *)p;
  return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
         ((uint32_t)b[3] << 24);
}

static inline uint64_t LOAD64LE(const void *p) {
  const uint8_t *b = (const uint8_t *)p;
  return (uint64_t)b[0] | ((uint64_t)b[1] << 8) | ((uint64_t)b[2] << 16) |
         ((uint64_t)b[3] << 24) | ((uint64_t)b[4] << 32) |
         ((uint64_t)b[5] << 40) | ((uint64_t)b[6] << 48) |
         ((uint64_t)b[7] << 56);
}

/* CycloneCRYPTO calling convention: STORE**(value, pointer) */

/* CycloneCRYPTO calling convention: STORE32BE(uint_value, byte_pointer) */
static inline void STORE16BE(uint16_t v, void *p) {
  uint8_t *b = (uint8_t *)p;
  b[0] = (uint8_t)(v >> 8);
  b[1] = (uint8_t)v;
}

static inline void STORE24BE(uint32_t v, void *p) {
  uint8_t *b = (uint8_t *)p;
  b[0] = (uint8_t)(v >> 16);
  b[1] = (uint8_t)(v >> 8);
  b[2] = (uint8_t)v;
}

static inline void STORE32BE(uint32_t v, void *p) {
  uint8_t *b = (uint8_t *)p;
  b[0] = (uint8_t)(v >> 24);
  b[1] = (uint8_t)(v >> 16);
  b[2] = (uint8_t)(v >> 8);
  b[3] = (uint8_t)v;
}

static inline void STORE64BE(uint64_t v, void *p) {
  uint8_t *b = (uint8_t *)p;
  b[0] = (uint8_t)(v >> 56);
  b[1] = (uint8_t)(v >> 48);
  b[2] = (uint8_t)(v >> 40);
  b[3] = (uint8_t)(v >> 32);
  b[4] = (uint8_t)(v >> 24);
  b[5] = (uint8_t)(v >> 16);
  b[6] = (uint8_t)(v >> 8);
  b[7] = (uint8_t)v;
}

/* ---- Stores — little-endian ---------------------------------------------- */

static inline void STORE16LE(uint16_t v, void *p) {
  uint8_t *b = (uint8_t *)p;
  b[0] = (uint8_t)v;
  b[1] = (uint8_t)(v >> 8);
}

static inline void STORE32LE(uint32_t v, void *p) {
  uint8_t *b = (uint8_t *)p;
  b[0] = (uint8_t)v;
  b[1] = (uint8_t)(v >> 8);
  b[2] = (uint8_t)(v >> 16);
  b[3] = (uint8_t)(v >> 24);
}

static inline void STORE64LE(uint64_t v, void *p) {
  uint8_t *b = (uint8_t *)p;
  b[0] = (uint8_t)v;
  b[1] = (uint8_t)(v >> 8);
  b[2] = (uint8_t)(v >> 16);
  b[3] = (uint8_t)(v >> 24);
  b[4] = (uint8_t)(v >> 32);
  b[5] = (uint8_t)(v >> 40);
  b[6] = (uint8_t)(v >> 48);
  b[7] = (uint8_t)(v >> 56);
}

/* ---- Bit rotation -------------------------------------------------------- */

static inline uint8_t ROL8(uint8_t a, unsigned int n) {
  n &= 7u;
  return (uint8_t)((a << n) | (a >> (8u - n)));
}

static inline uint8_t ROR8(uint8_t a, unsigned int n) {
  n &= 7u;
  return (uint8_t)((a >> n) | (a << (8u - n)));
}

static inline uint16_t ROL16(uint16_t a, unsigned int n) {
  n &= 15u;
  return (uint16_t)((a << n) | (a >> (16u - n)));
}

static inline uint16_t ROR16(uint16_t a, unsigned int n) {
  n &= 15u;
  return (uint16_t)((a >> n) | (a << (16u - n)));
}

static inline uint32_t ROL32(uint32_t a, unsigned int n) {
  n &= 31u;
  return (a << n) | (a >> (32u - n));
}

static inline uint32_t ROR32(uint32_t a, unsigned int n) {
  n &= 31u;
  return (a >> n) | (a << (32u - n));
}

static inline uint64_t ROL64(uint64_t a, unsigned int n) {
  n &= 63u;
  return (a << n) | (a >> (64u - n));
}

static inline uint64_t ROR64(uint64_t a, unsigned int n) {
  n &= 63u;
  return (a >> n) | (a << (64u - n));
}

/* ---- Host byte order helpers --------------------------------------------- */
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define betoh16(x) (x)
#define betoh32(x) (x)
#define betoh64(x) (x)
#define htobe16(x) (x)
#define htobe32(x) (x)
#define htobe64(x) (x)
#define letoh16(x) reverseInt16(x)
#define letoh32(x) reverseInt32(x)
#ifndef letoh64
#define letoh64(x) reverseInt64(x)
#endif
#ifndef htole16
#define htole16(x) reverseInt16(x)
#endif
#ifndef htole32
#define htole32(x) reverseInt32(x)
#endif
#ifndef htole64
#define htole64(x) reverseInt64(x)
#endif
#else /* little-endian (default) */
#ifndef betoh16
#define betoh16(x) reverseInt16(x)
#endif
#ifndef betoh32
#define betoh32(x) reverseInt32(x)
#endif
#ifndef betoh64
#define betoh64(x) reverseInt64(x)
#endif
#ifndef htobe16
#define htobe16(x) reverseInt16(x)
#endif
#ifndef htobe32
#define htobe32(x) reverseInt32(x)
#endif
#ifndef htobe64
#define htobe64(x) reverseInt64(x)
#endif
#ifndef letoh16
#define letoh16(x) (x)
#endif
#ifndef letoh32
#define letoh32(x) (x)
#endif
#ifndef letoh64
#define letoh64(x) (x)
#endif
#ifndef htole16
#define htole16(x) (x)
#endif
#ifndef htole32
#define htole32(x) (x)
#endif
#ifndef htole64
#define htole64(x) (x)
#endif
#endif

/* ---- 24-bit load/store (needed by ed448.c / curve448.c) ----------------- */
static inline uint32_t LOAD24LE(const void *p) {
  const uint8_t *b = (const uint8_t *)p;
  return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16);
}
static inline void STORE24LE(uint32_t v, void *p) {
  uint8_t *b = (uint8_t *)p;
  b[0] = (uint8_t)(v);
  b[1] = (uint8_t)(v >> 8);
  b[2] = (uint8_t)(v >> 16);
}

#endif /* _CPU_ENDIAN_H */
