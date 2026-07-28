/*
 *  OLLVM-Next (Ensia): The next generation LLVM based Obfuscator
 *  Copyright (C) 2026  Xinyu Yang(<Xinyu.Yang@apich.org>)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _CRYPTO_UTILS_H_
#define _CRYPTO_UTILS_H_

#include "llvm/Support/ManagedStatic.h"
#include <mutex>
#include <stdint.h>
#include <unordered_map>

extern std::mutex g_crypto_mutex;

namespace llvm {

class CryptoUtils {
public:
  CryptoUtils();
  ~CryptoUtils() = default;
  void prng_seed(uint64_t seed);
  void prng_seed();
  template <typename T> T get() { return static_cast<T>(next()); }
  // Return a value in [0, max)
  uint32_t get_range(uint32_t max) { return get_range(0, max); }
  uint32_t get_range(uint32_t min, uint32_t max);
  uint32_t get_uint32_t() { return get<uint32_t>(); }
  uint64_t get_uint64_t() { return get<uint64_t>(); }
  uint32_t get_uint8_t() { return get<uint8_t>(); }
  uint32_t get_uint16_t() { return get<uint16_t>(); }

  uint32_t scramble32(uint32_t in,
                      std::unordered_map<uint32_t, uint32_t> &VMap);

private:
  uint64_t s[4]; // xoshiro256++ state (256 bits)
  bool seeded = false;

  static uint64_t rotl64(uint64_t x, int k) noexcept {
    return (x << k) | (x >> (64 - k));
  }
  // xoshiro256++ step — passes BigCrush, period 2^256-1
  uint64_t next() noexcept {
    std::lock_guard<std::mutex> lock(g_crypto_mutex);
    const uint64_t result = rotl64(s[0] + s[3], 23) + s[0];
    const uint64_t t = s[1] << 17;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = rotl64(s[3], 45);
    return result;
  }
  // splitmix64 — used to initialise xoshiro state from a single 64-bit seed
  static uint64_t splitmix64(uint64_t &x) noexcept {
    uint64_t z = (x += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
  }
  void seed_from(uint64_t s0, uint64_t s1, uint64_t s2, uint64_t s3) noexcept;
};

extern ManagedStatic<CryptoUtils> cryptoutils;

} // namespace llvm

#endif
