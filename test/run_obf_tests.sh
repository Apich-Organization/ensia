#!/bin/bash
set -e

# Increase stack size limit for deep recursion stress tests (e.g. Ackermann) under heavy obfuscation
ulimit -s 65536 2>/dev/null || true

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${PROJECT_DIR}/build"
PLUGIN_LIB="${BUILD_DIR}/obfuscation/libEnsia.so"

echo "=== Ensia Obfuscator Automated Verification Suite ==="

if [ ! -f "${PLUGIN_LIB}" ]; then
  echo "[!] Building Ensia plugin..."
  cmake -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Release
  cmake --build "${BUILD_DIR}" -j$(nproc)
fi

echo "[+] 1. Verifying Individual Obfuscation Passes on min_obf_example.c..."
declare -a PASSES=(
  "SUBOBF=1"
  "MBAOBF=1"
  "STRCRY=1"
  "SPLITOBF=1"
  "BCFOBF=1"
  "CFFOBF=1"
  "CSMOBF=1"
  "CONSTENC=1"
  "INDIBRAN=1"
  "FUNCWRA=1"
  "FCO=1"
  "VOBF=1"
  "ADB=1"
  "ANTIHOOK=1"
)

for p in "${PASSES[@]}"; do
  echo "    [+] Testing pass: $p"
  env ENSIA=1 $p clang -fpass-plugin="${PLUGIN_LIB}" \
    -O1 "${PROJECT_DIR}/test/min_obf_example.c" -ldl -o "${BUILD_DIR}/test_indiv_${p%%=*}"
  "${BUILD_DIR}/test_indiv_${p%%=*}" >/dev/null
  echo "    [PASS] $p functional"
done

echo "[+] 2. Verifying Combined Obfuscation on min_obf_example.c..."
ENSIA=1 SUBOBF=1 MBAOBF=1 STRCRY=1 SPLITOBF=1 BCFOBF=1 CFFOBF=1 CSMOBF=1 CONSTENC=1 INDIBRAN=1 FUNCWRA=1 FCO=1 ANTIHOOK=1 \
clang -fpass-plugin="${PLUGIN_LIB}" \
  -O1 "${PROJECT_DIR}/test/min_obf_example.c" \
  -ldl \
  -o "${BUILD_DIR}/min_test_combined_obf"

echo "[+] Executing Minimal Obfuscated Binary..."
"${BUILD_DIR}/min_test_combined_obf"

echo "[+] 3. Compiling test_combined_obf.cpp with Production Obfuscation Preset (mid)..."
ENSIA=1 MEDOBF=1 \
clang++ -fpass-plugin="${PLUGIN_LIB}" \
  -O2 "${PROJECT_DIR}/test/test_combined_obf.cpp" \
  -ldl \
  -o "${BUILD_DIR}/test_combined_obf_mid"

echo "[+] Executing test_combined_obf_mid Binary..."
"${BUILD_DIR}/test_combined_obf_mid"

echo "[+] 4. Verifying Anti-Hooking and Code Integrity Tamper Defenses..."
ENSIA=1 ANTIHOOK=1 \
clang -fpass-plugin="${PLUGIN_LIB}" \
  -O1 "${PROJECT_DIR}/test/test_antihook_tamper.c" \
  -o "${BUILD_DIR}/test_antihook_tamper"

"${BUILD_DIR}/test_antihook_tamper"

echo "=== ALL OBFUSCATION VERIFICATION TESTS PASSED SUCCESSFULLY ==="
