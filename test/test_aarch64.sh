#!/usr/bin/env bash
# ==============================================================================
# Ensia AArch64 Cross-Compilation and Emulation Test Suite
# Tests whether all obfuscation passes work properly targeting AArch64 (ARM64)
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PLUGIN="${ROOT_DIR}/build/obfuscation/libEnsia.so"
CLANG="clang"
SYSROOT="/tmp/aarch64-sysroot"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}       Ensia AArch64 Multi-Platform Verification      ${NC}"
echo -e "${BLUE}======================================================${NC}"

WORK_DIR="${ROOT_DIR}/build/aarch64_test"
mkdir -p "${WORK_DIR}"

compile_and_test() {
    local test_name="$1"
    local env_vars="$2"
    local source_file="$3"
    local expected_exit="${4:-0}"
    
    echo -e "${YELLOW}[TEST] AArch64: ${test_name}...${NC}"
    local obj_file="${WORK_DIR}/${test_name}.o"
    
    # 1. Compile on host with clang + Ensia pass plugin targeting AArch64
    env ${env_vars} ${CLANG} --target=aarch64-linux-gnu -O1 \
        --sysroot="${SYSROOT}" \
        -I"${SYSROOT}/usr/include/aarch64-linux-gnu" \
        -fPIE \
        -fpass-plugin="${PLUGIN}" \
        -c "${source_file}" -o "${obj_file}"
        
    # 2. Link & Execute inside arm64 Debian container using qemu-aarch64-static
    set +e
    local output
    output=$(podman run --arch arm64 --rm \
        -v "${ROOT_DIR}:${ROOT_DIR}:ro,z" \
        localhost/ensia-aarch64-tester:latest \
        sh -c "gcc -no-pie '${obj_file}' -o /tmp/${test_name}.elf -lpthread -lm && /tmp/${test_name}.elf" 2>&1)
    local ret=$?
    set -e
    
    if [ "${expected_exit}" -eq 0 ]; then
        if [ $ret -eq 0 ]; then
            echo -e "${GREEN}[PASS] ${test_name} succeeded!${NC}"
        else
            echo -e "${RED}[FAIL] ${test_name} failed with code ${ret}! Output:${NC}"
            echo "${output}"
            return 1
        fi
    else
        if [ $ret -ne 0 ]; then
            echo -e "${GREEN}[PASS] ${test_name} expectedly failed with code ${ret}! Output: ${output}${NC}"
        else
            echo -e "${RED}[FAIL] ${test_name} expected failure but exited with 0!${NC}"
            return 1
        fi
    fi
}

echo -e "\n${BLUE}--- 1. Testing Individual Passes on AArch64 ---${NC}"

# Baseline
compile_and_test "arm64_baseline" "" "${ROOT_DIR}/test/min_obf_example.c"

# SUB (Instruction Substitution)
compile_and_test "arm64_sub" "ENSIA=1 SUBOBF=1" "${ROOT_DIR}/test/min_obf_example.c"

# MBA (Mixed Boolean Arithmetic)
compile_and_test "arm64_mba" "ENSIA=1 MBAOBF=1" "${ROOT_DIR}/test/min_obf_example.c"

# FLAT / CFF (Control Flow Flattening)
compile_and_test "arm64_cff" "ENSIA=1 CFFOBF=1" "${ROOT_DIR}/test/min_obf_example.c"

# BCF (Bogus Control Flow)
compile_and_test "arm64_bcf" "ENSIA=1 BCFOBF=1" "${ROOT_DIR}/test/min_obf_example.c"

# SPLIT (Split Basic Blocks)
compile_and_test "arm64_split" "ENSIA=1 SPLITOBF=1" "${ROOT_DIR}/test/min_obf_example.c"

# STRCRY (String Encryption)
compile_and_test "arm64_strcry" "ENSIA=1 STRCRY=1" "${ROOT_DIR}/test/min_obf_example.c"

# CSM (Chaos State Machine)
compile_and_test "arm64_csm" "ENSIA=1 CSMOBF=1" "${ROOT_DIR}/test/min_obf_example.c"

# CONSTENC (Constant Encryption)
compile_and_test "arm64_constenc" "ENSIA=1 CONSTENC=1" "${ROOT_DIR}/test/min_obf_example.c"

# INDIBRAN (Indirect Branch)
compile_and_test "arm64_indibran" "ENSIA=1 INDIBRAN=1" "${ROOT_DIR}/test/min_obf_example.c"

# FUNCWRA (Function Wrapper)
compile_and_test "arm64_funcwra" "ENSIA=1 FUNCWRA=1" "${ROOT_DIR}/test/min_obf_example.c"

# ANTIHOOK (AntiHooking with AArch64 inline hook check & direct syscall exit)
compile_and_test "arm64_antihook" "ENSIA=1 ANTIHOOK=1" "${ROOT_DIR}/test/min_obf_example.c"

echo -e "\n${BLUE}--- 2. Testing Combined Obfuscation on AArch64 ---${NC}"
compile_and_test "arm64_combined" \
    "ENSIA=1 SUBOBF=1 MBAOBF=1 STRCRY=1 SPLITOBF=1 BCFOBF=1 CFFOBF=1 CSMOBF=1 INDIBRAN=1 FUNCWRA=1 ANTIHOOK=1" \
    "${ROOT_DIR}/test/min_obf_example.c"

echo -e "\n${BLUE}--- 3. Testing Anti-Hook Tamper Detection on AArch64 ---${NC}"
compile_and_test "arm64_antihook_clean" "ENSIA=1 ANTIHOOK=1" "${ROOT_DIR}/test/test_antihook_tamper.c" 0

echo -e "\n${GREEN}======================================================${NC}"
echo -e "${GREEN}      All Ensia AArch64 Tests Passed Successfully!    ${NC}"
echo -e "${GREEN}======================================================${NC}"
