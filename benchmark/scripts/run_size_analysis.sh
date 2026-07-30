#!/usr/bin/env bash
# run_size_analysis.sh — Ensia Benchmark: Code Bloat Analysis
# ============================================================
#
# Measures binary size and LLVM IR instruction count for all modes.
# Outputs a CSV: algo, mode, elf_text_bytes, ir_instr_count, bloat_ratio
#
# Prerequisites:
#   - All 5 build directories built (baseline, csm_only, vec_only, csm_vec, max)
#   - llvm-objdump or size(1) available
#   - opt --print-stats or llvm-dis available for IR counting (optional)
#
# Usage:
#   ./run_size_analysis.sh <build_root_dir> [output_csv]
#   e.g.: ./run_size_analysis.sh /home/user/ensia/benchmark/builds size_report.csv

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_ROOT="${1:-${SCRIPT_DIR}/../builds}"
OUTPUT_CSV="${2:-${SCRIPT_DIR}/../results/size_analysis.csv}"
MODES=("baseline" "csm_only" "vec_only" "csm_vec" "max")

mkdir -p "$(dirname "$OUTPUT_CSV")"

# ── Helper: get .text section size in bytes ──────────────────────────────────
get_text_size() {
    local binary="$1"
    if command -v llvm-size &>/dev/null; then
        llvm-size "$binary" 2>/dev/null | awk 'NR==2 {print $1}'
    elif command -v size &>/dev/null; then
        size "$binary" 2>/dev/null | awk 'NR==2 {print $1}'
    else
        # Fallback: total file size
        stat -c %s "$binary" 2>/dev/null || echo 0
    fi
}

# ── Helper: get total ELF file size ─────────────────────────────────────────
get_file_size() {
    local binary="$1"
    stat -c %s "$binary" 2>/dev/null || echo 0
}

# ── Helper: count total IR instructions from .ll file ───────────────────────
count_ir_instructions() {
    local ll_file="$1"
    if [[ -f "$ll_file" ]]; then
        grep -c "^\s\+[a-z]" "$ll_file" 2>/dev/null || echo 0
    else
        echo 0
    fi
}

# ── Write CSV header ─────────────────────────────────────────────────────────
echo "algo,mode,elf_text_bytes,elf_file_bytes,ir_instr_count,baseline_text,baseline_file,text_bloat_ratio,file_bloat_ratio,size_only" \
    > "$OUTPUT_CSV"

echo "=== Ensia Code Bloat Analysis ==="
echo "Build root : $BUILD_ROOT"
echo "Output CSV : $OUTPUT_CSV"
echo ""

# ── Collect baseline sizes first ─────────────────────────────────────────────
declare -A BASELINE_TEXT
declare -A BASELINE_FILE

BASELINE_DIR="${BUILD_ROOT}/build_baseline"
if [[ -d "$BASELINE_DIR" ]]; then
    echo "[1/2] Scanning baseline binaries..."
    for binary in "${BASELINE_DIR}"/*_baseline; do
        [[ -x "$binary" ]] || continue
        algo="$(basename "$binary" _baseline)"
        BASELINE_TEXT[$algo]="$(get_text_size "$binary")"
        BASELINE_FILE[$algo]="$(get_file_size "$binary")"
    done
    echo "      Found ${#BASELINE_TEXT[@]} baseline binaries"
else
    echo "[WARN] Baseline build dir not found: $BASELINE_DIR"
fi

# ── Scan all modes ────────────────────────────────────────────────────────────
echo "[2/2] Scanning all modes..."
echo ""
printf "%-30s %-12s %12s %12s %10s %10s\n" \
    "ALGO" "MODE" "TEXT_BYTES" "FILE_BYTES" "TEXT_BLOAT" "FILE_BLOAT"
printf "%s\n" "$(printf '%.0s-' {1..90})"

for mode in "${MODES[@]}"; do
    build_dir="${BUILD_ROOT}/build_${mode}"
    [[ -d "$build_dir" ]] || { echo "[WARN] Missing: $build_dir"; continue; }

    for binary in "${build_dir}"/*_${mode}; do
        [[ -x "$binary" ]] || continue

        algo="$(basename "$binary" "_${mode}")"
        meta_file="${binary}.meta"
        size_only="OFF"
        [[ -f "$meta_file" ]] && size_only="$(grep -o 'size_only=[A-Za-z]*' "$meta_file" | cut -d= -f2 || echo OFF)"

        text_bytes="$(get_text_size "$binary")"
        file_bytes="$(get_file_size "$binary")"

        # IR instruction count (optional, from .ll if built with -save-temps)
        ll_file="${build_dir}/${algo}_${mode}.ll"
        ir_count="$(count_ir_instructions "$ll_file")"

        # Bloat ratios
        base_text="${BASELINE_TEXT[$algo]:-0}"
        base_file="${BASELINE_FILE[$algo]:-0}"

        if [[ "$base_text" -gt 0 ]]; then
            text_ratio=$(awk "BEGIN {printf \"%.3f\", $text_bytes / $base_text}")
        else
            text_ratio="N/A"
        fi
        if [[ "$base_file" -gt 0 ]]; then
            file_ratio=$(awk "BEGIN {printf \"%.3f\", $file_bytes / $base_file}")
        else
            file_ratio="N/A"
        fi

        # Append to CSV
        echo "${algo},${mode},${text_bytes},${file_bytes},${ir_count},${base_text},${base_file},${text_ratio},${file_ratio},${size_only}" \
            >> "$OUTPUT_CSV"

        printf "%-30s %-12s %12s %12s %10s %10s\n" \
            "$algo" "$mode" "$text_bytes" "$file_bytes" "$text_ratio" "$file_ratio"
    done
done

echo ""
echo "=== Size analysis complete ==="
echo "Results: $OUTPUT_CSV"
