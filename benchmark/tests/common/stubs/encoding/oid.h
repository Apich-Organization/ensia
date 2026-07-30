#ifndef OID_H
#define OID_H
#include "core/crypto.h"
#include <stddef.h>
#include <stdint.h>

static inline int oidComp(const uint8_t *oid1, size_t oidLen1,
                          const uint8_t *oid2, size_t oidLen2) {
  return 0;
}
#define OID_COMP(oid1, len1, oid2) oidComp(oid1, len1, oid2, sizeof(oid2))

#endif
