#pragma once

#include <cstddef>
#include <cstdint>

namespace ctf::obf {

// Compile-time XOR string masking with pure stack storage (zero heap, zero
// exceptions)
template <size_t N, uint8_t Key> class ObfuscatedString {
private:
  uint8_t encrypted_data[N]{};

public:
  constexpr ObfuscatedString(const char (&str)[N]) {
    for (size_t i = 0; i < N; ++i) {
      encrypted_data[i] =
          static_cast<uint8_t>(str[i]) ^ static_cast<uint8_t>(Key + i * 7);
    }
  }

  struct Decrypted {
    char str[N];
  };

  Decrypted decrypt() const {
    Decrypted res{};
    for (size_t i = 0; i < N - 1; ++i) {
      res.str[i] = static_cast<char>(encrypted_data[i] ^
                                     static_cast<uint8_t>(Key + i * 7));
    }
    res.str[N - 1] = '\0';
    return res;
  }
};

#define OBF_STR(s)                                                             \
  ([]() {                                                                      \
    constexpr ctf::obf::ObfuscatedString<sizeof(s), 0x5C> obf(s);              \
    return obf.decrypt();                                                      \
  }()                                                                          \
       .str)

} // namespace ctf::obf
