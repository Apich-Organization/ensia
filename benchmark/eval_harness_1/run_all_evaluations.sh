#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Independent Evaluation Suite for Ensia LLVM Obfuscator
# Autonomous Benchmark & Resilience Test Runner
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENSIA_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "======================================================================"
echo "[+] Starting Comprehensive Independent Evaluation for Ensia Obfuscator"
echo "[+] Target Root: ${ENSIA_ROOT}"
echo "[+] Output Directory: ${SCRIPT_DIR}/results"
echo "======================================================================"

mkdir -p "${SCRIPT_DIR}/results"

# 1. Functional Correctness & Physical Pass Verification
echo ""
echo "[*] Step 1/4: Running Pass Verification Matrix (IR/ASM Physical Checks)..."
python3 "${SCRIPT_DIR}/pass_verifier/run_pass_verification.py"

# 2. Symbolic Execution & SMT Solver Resilience (angr / claripy / Z3)
echo ""
echo "[*] Step 2/4: Running Symbolic Execution Resilience Evaluation (angr)..."
python3 "${SCRIPT_DIR}/resilience/test_symbolic_angr.py"

# 3. Memory Barrier Stripping & LLVM IR Lifting Simplification
echo ""
echo "[*] Step 3/4: Running Memory Barrier Stripping & Lifting Evaluation..."
python3 "${SCRIPT_DIR}/resilience/test_barrier_stripping.py"

# 4. Anti-Tamper, Hook Detection & Patch Resilience
echo ""
echo "[*] Step 4/4: Running Dynamic Tamper & Anti-Hook Evaluation..."
python3 "${SCRIPT_DIR}/resilience/test_patching_tamper.py"

echo ""
echo "======================================================================"
echo "[+] Evaluation Suite Completed Successfully!"
echo "[+] Results stored in: ${SCRIPT_DIR}/results/"
echo "[+] Full Academic Report: ${SCRIPT_DIR}/reports/COMPREHENSIVE_INDEPENDENT_EVALUATION_REPORT.md"
echo "======================================================================"
