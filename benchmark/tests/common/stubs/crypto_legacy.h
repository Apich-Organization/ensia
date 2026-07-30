/**
 * @file crypto_legacy.h
 * @brief Legacy compatibility macros — stub for benchmark tests
 *
 * Provides backward-compatibility shims that CycloneCRYPTO used to export.
 */

#ifndef _CRYPTO_LEGACY_H
#define _CRYPTO_LEGACY_H

/* bool is provided by <stdbool.h> included via os_port.h; no redefinition
 * needed */

/* Deprecated macro shims — kept for source compatibility */
#define TRUE_RANDOMNESS_SUPPORT DISABLED
#define YARROW_SUPPORT DISABLED
#define FORTUNA_SUPPORT DISABLED
#define RC4_SUPPORT DISABLED /* overridden per-test */
#define X509_SUPPORT DISABLED
#define TLS_SUPPORT DISABLED
#define SSH_SUPPORT DISABLED

#endif /* _CRYPTO_LEGACY_H */
