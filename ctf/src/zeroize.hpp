#pragma once

#include <cstddef>
#include <cstdint>
#include <sys/syscall.h>
#include <unistd.h>

namespace ctf::security {

// Securely wipe memory region using volatile pointers and compiler memory
// clobbers. Prevents dead-store elimination (DSE) optimizations in LLVM.
inline void secure_zero(void *ptr, size_t len) {
  if (!ptr || len == 0)
    return;
  volatile uint8_t *p = static_cast<volatile uint8_t *>(ptr);
  while (len--) {
    *p++ = 0;
  }
  // Memory clobber ensures the compiler cannot reorder or optimize away the
  // write
  asm volatile("" : : "r"(ptr) : "memory");
}

// RAII auto-zeroizer for sensitive buffers and keys upon scope exit
template <typename T> class SecureBuffer {
public:
  T *data;
  size_t size;

  SecureBuffer(T *buf, size_t sz) : data(buf), size(sz) {}
  ~SecureBuffer() {
    if (data && size > 0) {
      secure_zero(data, size * sizeof(T));
    }
  }

  // Disable copy
  SecureBuffer(const SecureBuffer &) = delete;
  SecureBuffer &operator=(const SecureBuffer &) = delete;
};

// Source-level opaque predicates based on mathematical identities
// In LLVM, these are preserved as complex control dependencies
inline uint32_t opaque_identity(uint32_t x, uint32_t y) {
  // Identity: (x | y) + (x & y) == x + y
  uint32_t lhs = (x | y) + (x & y);
  uint32_t rhs = x + y;
  return lhs ^ rhs; // Always evaluates to 0
}

inline bool verify_runtime_cohesion() {
  // Opaque algebraic predicate: (a * 2) - a == a
  volatile uint32_t v = 0x5A827999;
  uint32_t check = (v * 2) - v;
  if (check != 0x5A827999) {
    // Anti-tampering trap
    asm volatile("ud2");
    return false;
  }
  return true;
}

// Inline lightweight anti-tamper check (direct Linux syscall)
inline bool check_canary() {
  long pid = syscall(SYS_getpid);
  if (pid <= 0)
    return false;
  return verify_runtime_cohesion();
}

} // namespace ctf::security
