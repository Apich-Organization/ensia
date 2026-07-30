/**
 * @file mpi_stubs.c
 * @brief Stub implementations of the CycloneCRYPTO MPI (multi-precision
 *        integer) library functions. These are SIZE_ONLY targets that are
 *        excluded from angr analysis; the stubs are sufficient for linking.
 */
#include "core/crypto.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Re-define Mpi locally so the struct members are visible */
#ifndef MPI_LIMB_SIZE
#define MPI_LIMB_SIZE 4
#endif

typedef struct Mpi {
  int sign;
  uint_t size;
  uint32_t *data;
} Mpi;

/* Trace macro — must be a real function for link-time resolution */
void TRACE_DEBUG_MPI(const char *str, const Mpi *a) {
  (void)str;
  (void)a;
}
#define MPI_CHECK(call)                                                        \
  do {                                                                         \
    error_t _e = (call);                                                       \
    if (_e)                                                                    \
      return _e;                                                               \
  } while (0)

void mpiInit(Mpi *r) {
  if (r)
    memset(r, 0, sizeof(*r));
}
void mpiFree(Mpi *r) {
  if (r && r->data) {
    r->data = NULL;
    r->size = 0;
  }
}
error_t mpiCopy(Mpi *r, const Mpi *a) {
  (void)r;
  (void)a;
  return NO_ERROR;
}
error_t mpiSetValue(Mpi *r, int_t a) {
  (void)r;
  (void)a;
  return NO_ERROR;
}
uint_t mpiGetLength(const Mpi *a) {
  (void)a;
  return 0;
}
uint_t mpiGetBitLength(const Mpi *a) {
  (void)a;
  return 0;
}
uint_t mpiGetByteLength(const Mpi *a) {
  (void)a;
  return 0;
}
error_t mpiImport(Mpi *r, const uint8_t *data, uint_t length, uint_t format) {
  (void)r;
  (void)data;
  (void)length;
  (void)format;
  return NO_ERROR;
}
error_t mpiExport(const Mpi *a, uint8_t *data, uint_t length, uint_t format) {
  (void)a;
  (void)data;
  (void)length;
  (void)format;
  return NO_ERROR;
}
error_t mpiAdd(Mpi *r, const Mpi *a, const Mpi *b) {
  (void)r;
  (void)a;
  (void)b;
  return NO_ERROR;
}
error_t mpiSub(Mpi *r, const Mpi *a, const Mpi *b) {
  (void)r;
  (void)a;
  (void)b;
  return NO_ERROR;
}
error_t mpiMul(Mpi *r, const Mpi *a, const Mpi *b) {
  (void)r;
  (void)a;
  (void)b;
  return NO_ERROR;
}
error_t mpiMod(Mpi *r, const Mpi *a, const Mpi *p) {
  (void)r;
  (void)a;
  (void)p;
  return NO_ERROR;
}
error_t mpiMulMod(Mpi *r, const Mpi *a, const Mpi *b, const Mpi *p) {
  (void)r;
  (void)a;
  (void)b;
  (void)p;
  return NO_ERROR;
}
error_t mpiInvMod(Mpi *r, const Mpi *a, const Mpi *p) {
  (void)r;
  (void)a;
  (void)p;
  return NO_ERROR;
}
error_t mpiExpModFast(Mpi *r, const Mpi *a, const Mpi *e, const Mpi *p) {
  (void)r;
  (void)a;
  (void)e;
  (void)p;
  return NO_ERROR;
}
error_t mpiExpModRegular(Mpi *r, const Mpi *a, const Mpi *e, const Mpi *p) {
  (void)r;
  (void)a;
  (void)e;
  (void)p;
  return NO_ERROR;
}
int mpiComp(const Mpi *a, const Mpi *b) {
  (void)a;
  (void)b;
  return 0;
}
int mpiCompInt(const Mpi *a, int_t b) {
  (void)a;
  (void)b;
  return 0;
}
error_t mpiAddInt(Mpi *r, const Mpi *a, int_t b) {
  (void)r;
  (void)a;
  (void)b;
  return NO_ERROR;
}
error_t mpiSubInt(Mpi *r, const Mpi *a, int_t b) {
  (void)r;
  (void)a;
  (void)b;
  return NO_ERROR;
}
error_t mpiSetBitValue(Mpi *r, uint_t index, uint_t value) {
  (void)r;
  (void)index;
  (void)value;
  return NO_ERROR;
}
error_t mpiShiftRight(Mpi *r, uint_t n) {
  (void)r;
  (void)n;
  return NO_ERROR;
}
error_t mpiRand(Mpi *r, uint_t length, const void *prngAlgo, void *prngCtx) {
  (void)r;
  (void)length;
  (void)prngAlgo;
  (void)prngCtx;
  return NO_ERROR;
}
error_t mpiRandRange(Mpi *r, const Mpi *p, const void *prngAlgo,
                     void *prngCtx) {
  (void)r;
  (void)p;
  (void)prngAlgo;
  (void)prngCtx;
  return NO_ERROR;
}
error_t mpiCheckProbablePrime(const Mpi *p) {
  (void)p;
  return NO_ERROR;
}
