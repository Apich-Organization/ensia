#!/bin/bash
set -e

PROJECT_DIR="$(pwd)"
BUILD_DIR="${PROJECT_DIR}/build"
PLUGIN_LIB="${BUILD_DIR}/obfuscation/libEnsia.so"

echo "=== Ensia Obfuscator Automated Verification Suite ==="

if [ ! -f "${PLUGIN_LIB}" ]; then
  echo "[!] Building Ensia plugin..."
  cmake -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Release
  cmake --build "${BUILD_DIR}" -j$(nproc)
fi

echo "[+] Compiling test_combined_obf.cpp with FULL HIGH OBFUSCATION (-enable-maxobf)..."
clang++ -fplugin="${PLUGIN_LIB}" \
  -mllvm -ensia \
  -mllvm -enable-maxobf \
  -O2 "${PROJECT_DIR}/test/test_combined_obf.cpp" \
  -o "${BUILD_DIR}/test_combined_obf_high"

echo "[+] Executing High-Obfuscation Binary..."
"${BUILD_DIR}/test_combined_obf_high"

echo "=== ALL OBFUSCATION VERIFICATION TESTS PASSED SUCCESSFULLY ==="
