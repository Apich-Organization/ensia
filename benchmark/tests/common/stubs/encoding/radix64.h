/**
 * @file encoding/radix64.h
 * @brief Radix-64 (base64) encoding stub for benchmark tests.
 *
 * bcrypt.c uses radix64Encode/radix64Decode for hash string formatting.
 * The real CycloneCRYPTO functions return error_t; stubs match that signature.
 */
#ifndef _RADIX64_H
#define _RADIX64_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "../os_port.h"  /* for error_t / NO_ERROR */

/* bcrypt-alphabet radix-64; stubs produce empty output but satisfy the linker */
static inline size_t radix64EncodeLen(size_t n)
{
    return (n * 4 + 2) / 3 + 1;
}

static inline error_t radix64Encode(const void *in, size_t inLen,
                                     char *out, size_t *outLen)
{
    (void)in;
    if (outLen) *outLen = radix64EncodeLen(inLen);
    if (out && inLen) out[0] = '\0';
    return NO_ERROR;
}

static inline size_t radix64DecodeLen(size_t n)
{
    return (n * 3) / 4 + 1;
}

static inline error_t radix64Decode(const char *in, size_t inLen,
                                     void *out, size_t *outLen)
{
    (void)in;
    size_t len = radix64DecodeLen(inLen);
    if (outLen) *outLen = len;
    if (out && len) memset(out, 0, len);
    return NO_ERROR;
}

#endif /* _RADIX64_H */
