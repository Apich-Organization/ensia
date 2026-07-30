/**
 * @file os_port.h
 * @brief RTOS abstraction layer — Linux host stub for benchmark tests
 *
 * Replaces the platform-specific os_port.h required by CycloneCRYPTO.
 * Provides all types, macros and OS wrappers needed to compile the
 * benchmark algorithm sources on a standard Linux x86-64 / aarch64 host.
 */

#ifndef _OS_PORT_H
#define _OS_PORT_H

/* ---- GPL acceptance (required by CycloneCRYPTO) ---- */
#define GPL_LICENSE_TERMS_ACCEPTED

/* ---- Standard C headers ---- */
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Feature switches ---- */
#ifndef ENABLED
#define ENABLED 1
#endif
#ifndef DISABLED
#define DISABLED 0
#endif

/* ---- Boolean ---- */
typedef int bool_t;
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

/* ---- char_t: CycloneCRYPTO character type alias ---- */
typedef char char_t;

/* ---- Unsigned int alias (used throughout CycloneCRYPTO) ---- */
typedef unsigned int uint_t;
typedef int int_t;

/* ---- Byte-order helpers (little-endian host assumed; adjust if needed) ----
 */
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define HTONL(x) (x)
#define NTOHL(x) (x)
#else
#define HTONL(x) __builtin_bswap32(x)
#define NTOHL(x) __builtin_bswap32(x)
#endif

/* ---- Min / Max ---- */
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

/* ---- Array size ---- */
#ifndef arraysize
#define arraysize(a) (sizeof(a) / sizeof((a)[0]))
#endif

/* ---- Pointer arithmetic ---- */
#define PTR_OFFSET(p, o) ((void *)((uint8_t *)(p) + (o)))

/* ---- Memory management ---- */
#define osAllocMem(size) malloc(size)
#define osFreeMem(p) free(p)
#define cryptoAllocMem(size) malloc(size)
#define cryptoFreeMem(p) free(p)

/* ---- Memory / string operations ---- */
#define osMemset(dest, c, len) memset((dest), (c), (len))
#define osMemcpy(dest, src, len) memcpy((dest), (src), (len))
#define osMemcmp(s1, s2, len) memcmp((s1), (s2), (len))
#define osMemmove(dest, src, len) memmove((dest), (src), (len))
#define osMemchr(s, c, len) memchr((s), (c), (len))
#define osStrlen(s) strlen(s)
#define osStrcmp(s1, s2) strcmp((s1), (s2))
#define osStrncmp(s1, s2, n) strncmp((s1), (s2), (n))
#define osStrcpy(dest, src) strcpy((dest), (src))
#define osStrncpy(dest, src, n) strncpy((dest), (src), (n))
#define osStrcat(dest, src) strcat((dest), (src))
#define osSprintf(buf, fmt, ...) sprintf((buf), (fmt), ##__VA_ARGS__)
#define osSnprintf(buf, size, fmt, ...)                                        \
  snprintf((buf), (size), (fmt), ##__VA_ARGS__)

/* ---- Mutex / task (stubbed — single-threaded tests) ---- */
typedef int OsMutex;
typedef int OsTask;
typedef int OsSemaphore;
typedef int OsEvent;

#define osCreateMutex(m) ((void)0)
#define osDeleteMutex(m) ((void)0)
#define osAcquireMutex(m) ((void)0)
#define osReleaseMutex(m) ((void)0)

/* ---- Time (stubbed) ---- */
typedef uint32_t systime_t;
#define osGetSystemTime() ((systime_t)0)

/* ---- Debug / trace (stubbed) ---- */
#ifndef TRACE_LEVEL
#define TRACE_LEVEL 0
#endif
#define TRACE_LEVEL_OFF 0
#define TRACE_LEVEL_ERROR 1
#define TRACE_LEVEL_WARNING 2
#define TRACE_LEVEL_INFO 3
#define TRACE_LEVEL_DEBUG 4
#define TRACE_LEVEL_VERBOSE 5

#ifndef CRYPTO_TRACE_LEVEL
#define CRYPTO_TRACE_LEVEL TRACE_LEVEL_OFF
#endif

#define TRACE_ERROR(fmt, ...) ((void)0)
#define TRACE_WARNING(fmt, ...) ((void)0)
#define TRACE_INFO(fmt, ...) ((void)0)
#define TRACE_DEBUG(fmt, ...) ((void)0)
#define TRACE_VERBOSE(fmt, ...) ((void)0)
#define TRACE_DEBUG_ARRAY(pre, data, len) ((void)0)

/* ---- Assertion (use standard assert in debug, no-op in release) ---- */
#ifdef NDEBUG
#define ASSERT(c) ((void)0)
#else
#define ASSERT(c) assert(c)
#endif

/* ---- Compiler hints ---- */
#if defined(__GNUC__) || defined(__clang__)
#define __weak __attribute__((weak))
#define __packed __attribute__((packed))
#define __aligned(n) __attribute__((aligned(n)))
#define __noinline __attribute__((noinline))
#ifndef __always_inline
#define __always_inline __attribute__((always_inline))
#endif
#define __unused __attribute__((unused))
/* __weak_func: marks functions as weakly-linked, overridable stubs */
#ifndef __weak_func
#define __weak_func __attribute__((weak))
#endif
#else
#define __weak
#define __packed
#define __aligned(n)
#define __noinline
#ifndef __always_inline
#define __always_inline
#endif
#define __unused
#ifndef __weak_func
#define __weak_func
#endif
#endif

/* ---- Interface identifier ---- */
typedef struct {
  char name[16];
  uint32_t index;
} NetInterface;

/* ---- String-to-number wrappers (used by sha_crypt, bcrypt, etc.) ---- */
#ifndef osStrtoul
#include <inttypes.h>
#include <stdlib.h>
static inline unsigned long osStrtoul(const char *s, char **end, int base) {
  return strtoul(s, end, base);
}
static inline long osStrtol(const char *s, char **end, int base) {
  return strtol(s, end, base);
}
#endif

#define TRACE_DEBUG_EC_SCALAR(p, a, b) (void)(a)
#define ERROR_OUT_OF_RANGE 999
#define ERROR_DECRYPTION_FAILED 998
#define ERROR_INCONSISTENT_VALUE 997

#endif /* _OS_PORT_H */
