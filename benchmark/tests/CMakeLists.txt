################################################################################
# benchmark/tests/CMakeLists.txt
#
# Ensia Obfuscator Benchmark Test Suite
# ======================================
# Generates ~345 test executables: 69 algorithms × 5 obfuscation modes
#
# Usage:
#   cmake -S . -B build_baseline   -DOBFUSCATION_MODE=baseline
#   cmake -S . -B build_csm_only   -DOBFUSCATION_MODE=csm_only   -DENSIA_PLUGIN=<path>
#   cmake -S . -B build_vec_only   -DOBFUSCATION_MODE=vec_only    -DENSIA_PLUGIN=<path>
#   cmake -S . -B build_csm_vec    -DOBFUSCATION_MODE=csm_vec     -DENSIA_PLUGIN=<path>
#   cmake -S . -B build_max        -DOBFUSCATION_MODE=max         -DENSIA_PLUGIN=<path>
#
# All executables are named: <algo>_<mode>
# e.g.:  aes128_ecb_baseline,  sha256_csm_only,  ascon_aead128_max
################################################################################

cmake_minimum_required(VERSION 3.16)
project(ensia_benchmark C)

# --------------------------------------------------------------------------
# Compiler selection — prefer clang for obfuscation compatibility
# --------------------------------------------------------------------------
if(NOT DEFINED CMAKE_C_COMPILER)
    find_program(CLANG clang)
    if(CLANG)
        set(CMAKE_C_COMPILER ${CLANG})
    endif()
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# --------------------------------------------------------------------------
# Obfuscation mode parameter
# --------------------------------------------------------------------------
set(OBFUSCATION_MODE "baseline" CACHE STRING
    "Obfuscation mode: baseline | csm_only | vec_only | csm_vec | max")
set_property(CACHE OBFUSCATION_MODE PROPERTY STRINGS
    baseline csm_only vec_only csm_vec max)

set(ENSIA_PLUGIN "${CMAKE_SOURCE_DIR}/../../build/obfuscation/libEnsia.so"
    CACHE FILEPATH "Path to Ensia obfuscator plugin (.so)")

message(STATUS "=== Ensia Benchmark Test Suite ===")
message(STATUS "Obfuscation mode : ${OBFUSCATION_MODE}")
message(STATUS "Ensia plugin     : ${ENSIA_PLUGIN}")
message(STATUS "C Compiler       : ${CMAKE_C_COMPILER}")

# --------------------------------------------------------------------------
# Base compile flags
# --------------------------------------------------------------------------
set(BASE_CFLAGS
    -O1                         # Minimal optimization for fair comparison
    -g                          # Debug info (needed for angr symbol resolution)
    -fno-inline                 # Prevent inlining — keeps function boundaries for angr
    -fno-omit-frame-pointer     # Accurate stack frames
    -Wall
    -Wno-unused-variable
    -Wno-unused-function
    -Wno-implicit-function-declaration
    -Wno-int-conversion
    -Wno-macro-redefined                # Stubs may shadow system macros harmlessly
    # ---- Global feature flags ------------------------------------------------
    # CycloneCRYPTO uses #if (FOO_SUPPORT == ENABLED) guards everywhere.
    # We define ENABLED=1 globally and enable all algorithms so that library
    # .c files compiled as part of any target see the correct guards, regardless
    # of which test .c defines the macro first.
    -DENABLED=1
    -DAES_SUPPORT=ENABLED
    -DDES_SUPPORT=ENABLED -DDES3_SUPPORT=ENABLED
    -DBLOWFISH_SUPPORT=ENABLED -DCAST128_SUPPORT=ENABLED -DCAST256_SUPPORT=ENABLED
    -DCAMELLIA_SUPPORT=ENABLED -DIDEA_SUPPORT=ENABLED -DMARS_SUPPORT=ENABLED
    -DPRESENT_SUPPORT=ENABLED -DRC2_SUPPORT=ENABLED -DRC4_SUPPORT=ENABLED
    -DRC6_SUPPORT=ENABLED -DSEED_SUPPORT=ENABLED -DSERPENT_SUPPORT=ENABLED
    -DSM4_SUPPORT=ENABLED -DTEA_SUPPORT=ENABLED -DXTEA_SUPPORT=ENABLED
    -DTWOFISH_SUPPORT=ENABLED -DZUC_SUPPORT=ENABLED
    -DCHACHA_SUPPORT=ENABLED -DSALSA20_SUPPORT=ENABLED
    -DSHA1_SUPPORT=ENABLED -DSHA224_SUPPORT=ENABLED
    -DSHA256_SUPPORT=ENABLED -DSHA384_SUPPORT=ENABLED -DSHA512_SUPPORT=ENABLED
    -DSHA3_256_SUPPORT=ENABLED -DSHA3_512_SUPPORT=ENABLED
    -DMD5_SUPPORT=ENABLED -DSM3_SUPPORT=ENABLED
    -DRIPEMD128_SUPPORT=ENABLED -DRIPEMD160_SUPPORT=ENABLED
    -DBLAKE2B_SUPPORT=ENABLED -DBLAKE2B256_SUPPORT=ENABLED -DBLAKE2B512_SUPPORT=ENABLED
    -DBLAKE2S_SUPPORT=ENABLED -DBLAKE2S128_SUPPORT=ENABLED -DBLAKE2S256_SUPPORT=ENABLED
    -DTIGER_SUPPORT=ENABLED -DWHIRLPOOL_SUPPORT=ENABLED
    -DKECCAK_SUPPORT=ENABLED -DSHAKE_SUPPORT=ENABLED -DSHAKE128_SUPPORT=ENABLED -DSHAKE256_SUPPORT=ENABLED
    -DCSHAKE128_SUPPORT=ENABLED -DCSHAKE256_SUPPORT=ENABLED -DCSHAKE_SUPPORT=ENABLED
    -DGCM_SUPPORT=ENABLED -DCCM_SUPPORT=ENABLED -DCHACHAPOLY_SUPPORT=ENABLED
    -DGMAC_SUPPORT=ENABLED -DSIV_SUPPORT=ENABLED
    -DHMAC_SUPPORT=ENABLED -DCMAC_SUPPORT=ENABLED -DPOLY1305_SUPPORT=ENABLED
    -DKMAC_SUPPORT=ENABLED -DXCBC_MAC_SUPPORT=ENABLED
    -DHKDF_SUPPORT=ENABLED -DPBKDF2_SUPPORT=ENABLED -DPBKDF_SUPPORT=ENABLED
    -DBCRYPT_SUPPORT=ENABLED -DSCRYPT_SUPPORT=ENABLED -DSHA_CRYPT_SUPPORT=ENABLED
    -DASCON_AEAD_SUPPORT=ENABLED -DASCON_HASH_SUPPORT=ENABLED -DASCON_XOF_SUPPORT=ENABLED
    -DGIMLI_HASH_SUPPORT=ENABLED -DISAP_SUPPORT=ENABLED -DXOODYAK_SUPPORT=ENABLED
    -DHASH_ALGORITHMS_SUPPORT=ENABLED -DCIPHER_ALGORITHMS_SUPPORT=ENABLED
)

# --------------------------------------------------------------------------
# Include paths — stub headers take priority over everything
# --------------------------------------------------------------------------
set(STUB_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/common/stubs")
set(BENCH_ROOT_DIR   "${CMAKE_SOURCE_DIR}/..")  # = benchmark/  (tests/../ = benchmark/)

# The order matters: stubs first so they shadow any same-named system headers
set(COMMON_INCLUDES
    ${STUB_INCLUDE_DIR}          # os_port.h, error.h, cpu_endian.h, crypto_config.h
    ${CMAKE_SOURCE_DIR}/common   # test_harness.h
    ${BENCH_ROOT_DIR}            # core/crypto.h, cipher/aes.h, etc.
)

# --------------------------------------------------------------------------
# Mode-specific obfuscation flags
# --------------------------------------------------------------------------
if(OBFUSCATION_MODE STREQUAL "baseline")
    set(OBF_FLAGS "")
    set(OBF_LINK_FLAGS "")

elseif(OBFUSCATION_MODE STREQUAL "csm_only")
    if(NOT EXISTS "${ENSIA_PLUGIN}")
        message(FATAL_ERROR "Ensia plugin not found at: ${ENSIA_PLUGIN}")
    endif()
    set(OBF_FLAGS
        "SHELL:-Xclang -load" "SHELL:-Xclang ${ENSIA_PLUGIN}"
        "SHELL:-mllvm -ensia-preset=none"
        "SHELL:-mllvm -enable-csmobf"
        "SHELL:-mllvm -csm_warmup=64"
        "SHELL:-mllvm -csm_maxblocks=5000"
    )

elseif(OBFUSCATION_MODE STREQUAL "vec_only")
    if(NOT EXISTS "${ENSIA_PLUGIN}")
        message(FATAL_ERROR "Ensia plugin not found at: ${ENSIA_PLUGIN}")
    endif()
    set(OBF_FLAGS
        "SHELL:-Xclang -load" "SHELL:-Xclang ${ENSIA_PLUGIN}"
        "SHELL:-mllvm -ensia-preset=none"
        "SHELL:-mllvm -enable-vobf"
        "SHELL:-mllvm -vec_prob=80"
        "SHELL:-mllvm -vec_width=256"
        "SHELL:-mllvm -vec_shuffle=true"
        "SHELL:-mllvm -vec_icmp=true"
    )

elseif(OBFUSCATION_MODE STREQUAL "csm_vec")
    if(NOT EXISTS "${ENSIA_PLUGIN}")
        message(FATAL_ERROR "Ensia plugin not found at: ${ENSIA_PLUGIN}")
    endif()
    set(OBF_FLAGS
        "SHELL:-Xclang -load" "SHELL:-Xclang ${ENSIA_PLUGIN}"
        "SHELL:-mllvm -ensia-preset=none"
        "SHELL:-mllvm -enable-csmobf"
        "SHELL:-mllvm -csm_warmup=64"
        "SHELL:-mllvm -csm_maxblocks=5000"
        "SHELL:-mllvm -enable-vobf"
        "SHELL:-mllvm -vec_prob=80"
        "SHELL:-mllvm -vec_width=256"
        "SHELL:-mllvm -vec_shuffle=true"
        "SHELL:-mllvm -vec_icmp=true"
    )

elseif(OBFUSCATION_MODE STREQUAL "max")
    if(NOT EXISTS "${ENSIA_PLUGIN}")
        message(FATAL_ERROR "Ensia plugin not found at: ${ENSIA_PLUGIN}")
    endif()
    set(OBF_FLAGS
        "SHELL:-Xclang -load" "SHELL:-Xclang ${ENSIA_PLUGIN}"
        "SHELL:-mllvm -ensia-preset=max"
        "SHELL:-mllvm -enable-maxobf"
    )

else()
    message(FATAL_ERROR "Unknown OBFUSCATION_MODE: ${OBFUSCATION_MODE}")
endif()

# --------------------------------------------------------------------------
# Helper macro: add_crypto_test(
#     TARGET_NAME       -- e.g. aes128_ecb
#     SOURCES           -- list of .c files (test + library sources)
#     SIZE_ONLY         -- "ON" if excluded from angr (ECC/PKC/PQC)
# )
# --------------------------------------------------------------------------
macro(add_crypto_test TARGET_NAME SOURCES SIZE_ONLY)
    set(_full_target "${TARGET_NAME}_${OBFUSCATION_MODE}")
    # ${SOURCES} may contain semicolon-separated paths; CMake list-expands them automatically
    add_executable(${_full_target} ${SOURCES})

    # Stubs use SYSTEM so they get -isystem (highest priority, suppresses warnings)
    target_include_directories(${_full_target} SYSTEM PRIVATE ${STUB_INCLUDE_DIR})
    target_include_directories(${_full_target} PRIVATE
        ${CMAKE_SOURCE_DIR}/common
        ${BENCH_ROOT_DIR}
    )

    target_compile_options(${_full_target} PRIVATE
        ${BASE_CFLAGS}
        ${OBF_FLAGS}
    )

    # Annotate for test runner
    set_target_properties(${_full_target} PROPERTIES
        ENSIA_ALGO       "${TARGET_NAME}"
        ENSIA_MODE       "${OBFUSCATION_MODE}"
        ENSIA_SIZE_ONLY  "${SIZE_ONLY}"
    )

    # Write a companion .meta file alongside the binary for scripts
    add_custom_command(TARGET ${_full_target} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo
            "algo=${TARGET_NAME} mode=${OBFUSCATION_MODE} size_only=${SIZE_ONLY}"
            > $<TARGET_FILE:${_full_target}>.meta
        COMMENT "Writing metadata for ${_full_target}"
    )
endmacro()

################################################################################
# Source file helpers
# Each target = test .c + all library .c files it depends on
################################################################################

# Convenience variable for benchmark source roots
set(S_CIPHER       ${BENCH_ROOT_DIR}/cipher)
set(S_HASH         ${BENCH_ROOT_DIR}/hash)
set(S_AEAD         ${BENCH_ROOT_DIR}/aead)
set(S_MAC          ${BENCH_ROOT_DIR}/mac)
set(S_KDF          ${BENCH_ROOT_DIR}/kdf)
set(S_LWC          ${BENCH_ROOT_DIR}/lwc)
set(S_XOF          ${BENCH_ROOT_DIR}/xof)
set(S_MODES        ${BENCH_ROOT_DIR}/cipher_modes)
set(S_ECC          ${BENCH_ROOT_DIR}/ecc)
set(S_PKC          ${BENCH_ROOT_DIR}/pkc)
set(S_MPI          ${BENCH_ROOT_DIR}/mpi)
set(S_PQC          ${BENCH_ROOT_DIR}/pqc)

# Hash source library (all hash implementations compiled together)
set(HASH_SRCS
    ${S_HASH}/sha1.c
    ${S_HASH}/sha224.c
    ${S_HASH}/sha256.c
    ${S_HASH}/sha384.c
    ${S_HASH}/sha512.c
    ${S_HASH}/sha3_224.c
    ${S_HASH}/sha3_256.c
    ${S_HASH}/sha3_384.c
    ${S_HASH}/sha3_512.c
    ${S_HASH}/md5.c
    ${S_HASH}/sm3.c
    ${S_HASH}/ripemd128.c
    ${S_HASH}/ripemd160.c
    ${S_HASH}/tiger.c
    ${S_HASH}/whirlpool.c
    ${S_HASH}/blake2b160.c
    ${S_HASH}/blake2b256.c
    ${S_HASH}/blake2b384.c
    ${S_HASH}/blake2b512.c
    ${S_HASH}/blake2s128.c
    ${S_HASH}/blake2s160.c
    ${S_HASH}/blake2s224.c
    ${S_HASH}/blake2s256.c
    ${S_HASH}/md2.c
    ${S_HASH}/md4.c
    ${S_HASH}/sha512_224.c
    ${S_HASH}/sha512_256.c
    ${S_XOF}/keccak.c
    ${S_XOF}/shake.c
    ${S_XOF}/cshake.c
    ${S_MAC}/blake2b.c
    ${S_MAC}/blake2s.c
)

# MAC source library
set(MAC_BASE_SRCS
    ${S_MAC}/hmac.c
    ${S_MAC}/cmac.c
    ${S_MAC}/gmac.c
    ${S_MAC}/poly1305.c
    ${S_MAC}/kmac.c
    ${S_MAC}/xcbc_mac.c
)

################################################################################
# ── CIPHER tests ──────────────────────────────────────────────────────────────
################################################################################

add_crypto_test(aes128_ecb
    "cipher/test_aes128_ecb.c;${S_CIPHER}/aes.c"
    OFF)

add_crypto_test(aes192_ecb
    "cipher/test_aes192_ecb.c;${S_CIPHER}/aes.c"
    OFF)

add_crypto_test(aes256_ecb
    "cipher/test_aes256_ecb.c;${S_CIPHER}/aes.c"
    OFF)

add_crypto_test(des_ecb
    "cipher/test_des_ecb.c;${S_CIPHER}/des.c"
    OFF)

add_crypto_test(des3_ecb
    "cipher/test_3des_ecb.c;${S_CIPHER}/des.c;${S_CIPHER}/des3.c"
    OFF)

add_crypto_test(blowfish_ecb
    "cipher/test_blowfish_ecb.c;${S_CIPHER}/blowfish.c"
    OFF)

add_crypto_test(cast128_ecb
    "cipher/test_cast128_ecb.c;${S_CIPHER}/cast128.c"
    OFF)

add_crypto_test(cast256_ecb
    "cipher/test_cast256_ecb.c;${S_CIPHER}/cast256.c"
    OFF)

add_crypto_test(camellia_ecb
    "cipher/test_camellia_ecb.c;${S_CIPHER}/camellia.c"
    OFF)

add_crypto_test(idea_ecb
    "cipher/test_idea_ecb.c;${S_CIPHER}/idea.c"
    OFF)

add_crypto_test(mars_ecb
    "cipher/test_mars_ecb.c;${S_CIPHER}/mars.c"
    OFF)

add_crypto_test(present_ecb
    "cipher/test_present_ecb.c;${S_CIPHER}/present.c"
    OFF)

add_crypto_test(rc2_ecb
    "cipher/test_rc2_ecb.c;${S_CIPHER}/rc2.c"
    OFF)

add_crypto_test(rc4_stream
    "cipher/test_rc4_stream.c;${S_CIPHER}/rc4.c"
    OFF)

add_crypto_test(rc6_ecb
    "cipher/test_rc6_ecb.c;${S_CIPHER}/rc6.c"
    OFF)

add_crypto_test(seed_ecb
    "cipher/test_seed_ecb.c;${S_CIPHER}/seed.c"
    OFF)

add_crypto_test(serpent_ecb
    "cipher/test_serpent_ecb.c;${S_CIPHER}/serpent.c"
    OFF)

add_crypto_test(sm4_ecb
    "cipher/test_sm4_ecb.c;${S_CIPHER}/sm4.c"
    OFF)

add_crypto_test(tea_ecb
    "cipher/test_tea_ecb.c;${S_CIPHER}/tea.c"
    OFF)

add_crypto_test(xtea_ecb
    "cipher/test_xtea_ecb.c;${S_CIPHER}/xtea.c"
    OFF)

add_crypto_test(twofish_ecb
    "cipher/test_twofish_ecb.c;${S_CIPHER}/twofish.c"
    OFF)

add_crypto_test(zuc_stream
    "cipher/test_zuc_stream.c;${S_CIPHER}/zuc.c"
    OFF)

add_crypto_test(chacha20_stream
    "cipher/test_chacha20_stream.c;${S_CIPHER}/chacha.c"
    OFF)

add_crypto_test(salsa20_stream
    "cipher/test_salsa20_stream.c;${S_CIPHER}/salsa20.c"
    OFF)

################################################################################
# ── HASH tests ────────────────────────────────────────────────────────────────
################################################################################

add_crypto_test(sha1
    "hash/test_sha1.c;${S_HASH}/sha1.c"
    OFF)

add_crypto_test(sha224
    "hash/test_sha224.c;${S_HASH}/sha224.c;${S_HASH}/sha256.c"
    OFF)

add_crypto_test(sha256
    "hash/test_sha256.c;${S_HASH}/sha256.c"
    OFF)

add_crypto_test(sha384
    "hash/test_sha384.c;${S_HASH}/sha384.c;${S_HASH}/sha512.c"
    OFF)

add_crypto_test(sha512
    "hash/test_sha512.c;${S_HASH}/sha512.c"
    OFF)

add_crypto_test(sha3_256
    "hash/test_sha3_256.c;${S_HASH}/sha3_256.c;${S_XOF}/keccak.c"
    OFF)

add_crypto_test(sha3_512
    "hash/test_sha3_512.c;${S_HASH}/sha3_512.c;${S_XOF}/keccak.c"
    OFF)

add_crypto_test(md5
    "hash/test_md5.c;${S_HASH}/md5.c"
    OFF)

add_crypto_test(sm3
    "hash/test_sm3.c;${S_HASH}/sm3.c"
    OFF)

add_crypto_test(ripemd128
    "hash/test_ripemd128.c;${S_HASH}/ripemd128.c"
    OFF)

add_crypto_test(ripemd160
    "hash/test_ripemd160.c;${S_HASH}/ripemd160.c"
    OFF)

add_crypto_test(blake2b256
    "hash/test_blake2b256.c;${S_HASH}/blake2b256.c;${S_MAC}/blake2b.c"
    OFF)

add_crypto_test(blake2b512
    "hash/test_blake2b512.c;${S_HASH}/blake2b512.c;${S_MAC}/blake2b.c"
    OFF)

add_crypto_test(blake2s128
    "hash/test_blake2s128.c;${S_HASH}/blake2s128.c;${S_MAC}/blake2s.c"
    OFF)

add_crypto_test(blake2s256
    "hash/test_blake2s256.c;${S_HASH}/blake2s256.c;${S_MAC}/blake2s.c"
    OFF)

add_crypto_test(tiger
    "hash/test_tiger.c;${S_HASH}/tiger.c"
    OFF)

add_crypto_test(whirlpool
    "hash/test_whirlpool.c;${S_HASH}/whirlpool.c"
    OFF)

################################################################################
# ── AEAD tests ────────────────────────────────────────────────────────────────
################################################################################

add_crypto_test(aes_gcm
    "aead/test_aes_gcm.c;${S_AEAD}/gcm.c;${S_CIPHER}/aes.c"
    OFF)

add_crypto_test(aes_ccm
    "aead/test_aes_ccm.c;${S_AEAD}/ccm.c;${S_CIPHER}/aes.c"
    OFF)

add_crypto_test(chacha20_poly1305
    "aead/test_chacha20_poly1305.c;${S_AEAD}/chacha20_poly1305.c;${S_CIPHER}/chacha.c;${S_MAC}/poly1305.c"
    OFF)

add_crypto_test(aes_siv
    "aead/test_aes_siv.c;${S_AEAD}/siv.c;${S_CIPHER}/aes.c;${S_MAC}/cmac.c;${S_MODES}/ctr.c"
    OFF)


################################################################################
# ── MAC tests ─────────────────────────────────────────────────────────────────
################################################################################

add_crypto_test(hmac_sha256
    "mac/test_hmac_sha256.c;${S_MAC}/hmac.c;${S_HASH}/sha256.c"
    OFF)

add_crypto_test(cmac_aes
    "mac/test_cmac_aes.c;${S_MAC}/cmac.c;${S_CIPHER}/aes.c"
    OFF)

add_crypto_test(gmac_aes
    "mac/test_gmac_aes.c;${S_MAC}/gmac.c;${S_AEAD}/gcm.c;${S_CIPHER}/aes.c"
    OFF)

add_crypto_test(poly1305
    "mac/test_poly1305.c;${S_MAC}/poly1305.c"
    OFF)

add_crypto_test(kmac128
    "mac/test_kmac128.c;${S_MAC}/kmac.c;${S_XOF}/cshake.c;${S_XOF}/keccak.c;${S_XOF}/shake.c;${S_HASH}/sha3_256.c;${S_HASH}/sha3_512.c"
    OFF)



add_crypto_test(xcbc_mac
    "mac/test_xcbc_mac.c;${S_MAC}/xcbc_mac.c;${S_CIPHER}/aes.c"
    OFF)

################################################################################
# ── KDF tests ─────────────────────────────────────────────────────────────────
################################################################################

add_crypto_test(hkdf_sha256
    "kdf/test_hkdf_sha256.c;${S_KDF}/hkdf.c;${S_MAC}/hmac.c;${S_HASH}/sha256.c"
    OFF)

add_crypto_test(pbkdf2_sha256
    "kdf/test_pbkdf2_sha256.c;${S_KDF}/pbkdf.c;${S_MAC}/hmac.c;${S_HASH}/sha256.c"
    OFF)

add_crypto_test(bcrypt
    "kdf/test_bcrypt.c;${S_KDF}/bcrypt.c;${S_CIPHER}/blowfish.c"
    OFF)

add_crypto_test(scrypt
    "kdf/test_scrypt.c;${S_KDF}/scrypt.c;${S_KDF}/pbkdf.c;${S_MAC}/hmac.c;${S_HASH}/sha256.c;${S_CIPHER}/salsa20.c"
    OFF)


add_crypto_test(sha256_crypt
    "kdf/test_sha256_crypt.c;${S_KDF}/sha_crypt.c;${S_HASH}/sha256.c;${S_HASH}/sha512.c"
    OFF)

################################################################################
# ── LWC tests ─────────────────────────────────────────────────────────────────
################################################################################

add_crypto_test(ascon_aead128
    "lwc/test_ascon_aead128.c;${S_LWC}/ascon.c;${S_LWC}/ascon_aead128.c"
    OFF)

add_crypto_test(ascon_hash256
    "lwc/test_ascon_hash256.c;${S_LWC}/ascon.c;${S_LWC}/ascon_hash256.c"
    OFF)

add_crypto_test(ascon_xof128
    "lwc/test_ascon_xof128.c;${S_LWC}/ascon.c;${S_LWC}/ascon_xof128.c"
    OFF)

################################################################################
# ── XOF tests ─────────────────────────────────────────────────────────────────
################################################################################

add_crypto_test(shake128
    "xof/test_shake128.c;${S_XOF}/keccak.c;${S_XOF}/shake.c"
    OFF)

add_crypto_test(shake256
    "xof/test_shake256.c;${S_XOF}/keccak.c;${S_XOF}/shake.c"
    OFF)

add_crypto_test(cshake128
    "xof/test_cshake128.c;${S_XOF}/keccak.c;${S_XOF}/cshake.c;${S_XOF}/shake.c"
    OFF)

################################################################################
# ── Cipher mode tests ─────────────────────────────────────────────────────────
################################################################################

add_crypto_test(aes_cbc
    "cipher_modes/test_aes_cbc.c;${S_MODES}/cbc.c;${S_CIPHER}/aes.c"
    OFF)

add_crypto_test(aes_cfb
    "cipher_modes/test_aes_cfb.c;${S_MODES}/cfb.c;${S_CIPHER}/aes.c"
    OFF)

add_crypto_test(aes_ctr
    "cipher_modes/test_aes_ctr.c;${S_MODES}/ctr.c;${S_CIPHER}/aes.c"
    OFF)

add_crypto_test(aes_ecb_mode
    "cipher_modes/test_aes_ecb.c;${S_MODES}/ecb.c;${S_CIPHER}/aes.c"
    OFF)

add_crypto_test(aes_ofb
    "cipher_modes/test_aes_ofb.c;${S_MODES}/ofb.c;${S_CIPHER}/aes.c"
    OFF)

add_crypto_test(aes_xts
    "cipher_modes/test_aes_xts.c;${S_MODES}/xts.c;${S_CIPHER}/aes.c"
    OFF)

################################################################################
# ── ECC tests (SIZE_ONLY — excluded from angr) ────────────────────────────────
################################################################################

add_crypto_test(ecdh_p256
    "ecc/test_ecdh_p256.c;${S_ECC}/ec.c;${S_ECC}/ec_misc.c;${S_ECC}/ec_curves.c;${S_ECC}/ecdh.c"
    ON)

add_crypto_test(ecdsa_p256
    "ecc/test_ecdsa_p256.c;${S_ECC}/ec.c;${S_ECC}/ec_misc.c;${S_ECC}/ec_curves.c;${S_ECC}/ecdsa.c;${S_HASH}/sha256.c"
    ON)

add_crypto_test(ed25519
    "ecc/test_ed25519.c;${S_ECC}/ed25519.c;${S_ECC}/ed448.c;${S_ECC}/curve25519.c;${S_ECC}/curve448.c;${S_ECC}/eddsa.c;${S_ECC}/ec.c;${S_ECC}/ec_misc.c;${S_ECC}/ec_curves.c;${S_HASH}/sha512.c;${S_XOF}/shake.c;${S_XOF}/keccak.c"
    ON)

add_crypto_test(x25519
    "ecc/test_x25519.c;${S_ECC}/x25519.c;${S_ECC}/curve25519.c"
    ON)

add_crypto_test(sm2
    "ecc/test_sm2.c;${S_ECC}/sm2.c;${S_ECC}/ec.c;${S_ECC}/ec_misc.c;${S_ECC}/ec_curves.c;${S_HASH}/sm3.c"
    ON)

################################################################################
# ── PKC tests (SIZE_ONLY — excluded from angr) ────────────────────────────────
################################################################################

add_crypto_test(rsa2048
    "pkc/test_rsa2048.c;${S_PKC}/rsa.c;${S_PKC}/rsa_misc.c;${S_HASH}/sha256.c;${S_MPI}/mpi.c;${S_MPI}/mpi_misc.c"
    ON)

add_crypto_test(dsa2048
    "pkc/test_dsa2048.c;${S_PKC}/dsa.c;${S_HASH}/sha256.c;${S_MPI}/mpi.c;${S_MPI}/mpi_misc.c"
    ON)

add_crypto_test(dh2048
    "pkc/test_dh2048.c;${S_PKC}/dh.c;${S_MPI}/mpi.c;${S_MPI}/mpi_misc.c"
    ON)

################################################################################
# ── PQC tests (SIZE_ONLY — excluded from angr) ────────────────────────────────
################################################################################

add_crypto_test(mlkem512
    "pqc/test_mlkem512.c"
    ON)

add_crypto_test(mlkem768
    "pqc/test_mlkem768.c"
    ON)

add_crypto_test(mldsa44
    "pqc/test_mldsa44.c"
    ON)

################################################################################
# ── Summary target ────────────────────────────────────────────────────────────
################################################################################

# Count total targets
get_property(_all_targets DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY BUILDSYSTEM_TARGETS)
list(LENGTH _all_targets _n_targets)
message(STATUS "Total test targets in mode '${OBFUSCATION_MODE}': ${_n_targets}")

# Custom target to print all binary paths (useful for scripts)
add_custom_target(list_binaries
    COMMAND ${CMAKE_COMMAND} -E echo "=== Ensia Benchmark Binaries ==="
    COMMAND find ${CMAKE_BINARY_DIR} -maxdepth 1 -type f -name "*_${OBFUSCATION_MODE}" | sort
    COMMENT "Listing all benchmark binaries"
)

# Custom target to run all tests
add_custom_target(run_all_tests
    DEPENDS ${_all_targets}
    COMMAND ${CMAKE_SOURCE_DIR}/../scripts/run_all_baseline.sh ${CMAKE_BINARY_DIR} ${OBFUSCATION_MODE}
    COMMENT "Running all benchmark tests for mode: ${OBFUSCATION_MODE}"
)
