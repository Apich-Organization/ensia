#ifndef ASN1_H
#define ASN1_H
#include "core/crypto.h"
#include <stddef.h>
#include <stdint.h>

#define ASN1_CLASS_UNIVERSAL 0
#define ASN1_TYPE_INTEGER 2
#define ASN1_TYPE_SEQUENCE 16
#define ASN1_TYPE_OBJECT_IDENTIFIER 6

typedef struct {
  size_t totalLength;
  const uint8_t *value;
  size_t length;
  uint8_t objClass;
  uint8_t objType;
  bool_t constructed;
} Asn1Tag;

static inline error_t asn1DumpObject(const uint8_t *data, size_t length,
                                     uint_t level) {
  return NO_ERROR;
}
static inline error_t asn1ReadSequence(const uint8_t *data, size_t length,
                                       Asn1Tag *tag) {
  tag->totalLength = length;
  tag->length = length;
  return NO_ERROR;
}
static inline error_t asn1ReadTag(const uint8_t *data, size_t length,
                                  Asn1Tag *tag) {
  tag->value = data;
  tag->length = 0;
  return NO_ERROR;
}
static inline error_t asn1CheckTag(const Asn1Tag *tag, bool_t constructed,
                                   uint8_t objClass, uint8_t objType) {
  return NO_ERROR;
}
static inline error_t asn1InsertHeader(const Asn1Tag *tag, uint8_t *data,
                                       size_t *written) {
  *written = 0;
  return NO_ERROR;
}
static inline error_t asn1WriteHeader(Asn1Tag *tag, bool_t dummy, uint8_t *data,
                                      size_t *written) {
  *written = 0;
  return NO_ERROR;
}
static inline error_t asn1WriteTag(Asn1Tag *tag, bool_t constructed,
                                   uint8_t objClass, uint8_t objType,
                                   const uint8_t *value, size_t length) {
  return NO_ERROR;
}
static inline error_t asn1ReadInt32(const uint8_t *data, size_t length,
                                    Asn1Tag *tag, int32_t *value) {
  return NO_ERROR;
}

#define ASN1_ENCODING_CONSTRUCTED 0x20
#define ASN1_TYPE_NULL 0x05
#define ASN1_TYPE_OCTET_STRING 0x04
#define ASN1_INC_POINTER(p, size)                                              \
  {                                                                            \
    p += size;                                                                 \
  }
#endif
