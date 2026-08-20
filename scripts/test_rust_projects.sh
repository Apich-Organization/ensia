#!/usr/bin/env bash
# ==============================================================================
# Ensia Rust Project Obfuscation Test Runner
# Tests compilation and unit test pass rates of Rust projects using libEnsia_rust.so
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENSIA_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PLUGIN_PATH="${ENSIA_PLUGIN:-$ENSIA_ROOT/build/obfuscation/libEnsia_rust.so}"
PRESET="${1:-csm_vec}"

if [ ! -f "$PLUGIN_PATH" ]; then
    echo "[!] Ensia Rust plugin not found at: $PLUGIN_PATH"
    echo "    Building plugin first..."
    cmake --build "$ENSIA_ROOT/build" --target EnsiaRust --parallel "$(nproc)"
fi

echo "================================================================="
echo " Ensia Rust Obfuscation Test Suite"
echo " Plugin: $PLUGIN_PATH"
echo " Preset: $PRESET"
echo "================================================================="

PROJECTS=(
    "$ENSIA_ROOT/../bincode"
    "$ENSIA_ROOT/../dtact"
)

TOTAL=0
PASSED=0
FAILED=0

for proj in "${PROJECTS[@]}"; do
    if [ ! -d "$proj" ]; then
        echo "[-] Project directory not found: $proj (Skipping)"
        continue
    fi

    PROJ_NAME="$(basename "$proj")"
    echo ""
    echo "[*] Testing project: $PROJ_NAME ($proj)"
    echo "-----------------------------------------------------------------"
    
    TOTAL=$((TOTAL + 1))
    
    pushd "$proj" > /dev/null
    
    # Run cargo test with Ensia pass plugin enabled
    if ENSIA_PRESET="$PRESET" \
       RUSTC_BOOTSTRAP=1 \
       RUSTFLAGS="-Z llvm-plugins=$PLUGIN_PATH -C passes=ensia" \
       cargo test --lib --tests; then
        echo "[+] $PROJ_NAME: ALL TESTS PASSED"
        PASSED=$((PASSED + 1))
    else
        echo "[-] $PROJ_NAME: TESTS FAILED"
        FAILED=$((FAILED + 1))
    fi
    
    popd > /dev/null
done

echo ""
echo "================================================================="
echo " Summary: $TOTAL tested, $PASSED passed, $FAILED failed"
echo "================================================================="

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi
