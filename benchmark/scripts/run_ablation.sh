#!/usr/bin/env bash
# run_ablation.sh — Ensia Benchmark: Full Ablation Experiment Driver
# ==================================================================
#
# Orchestrates the full ablation pipeline:
#   1. Build all 5 mode variants
#   2. Run size analysis
#   3. Run angr analysis for angr-eligible targets
#   4. Collect results
#
# Usage:
#   ./run_ablation.sh [options]
#
# Options:
#   --tests-dir DIR    Path to benchmark/tests/  (default: script/../tests)
#   --builds-dir DIR   Where to create build dirs (default: script/../builds)
#   --results-dir DIR  Where to write CSV results (default: script/../results)
#   --ensia-plugin SO  Path to libEnsia.so        (default: ../../build/obfuscation/libEnsia.so)
#   --jobs N           Parallel make jobs          (default: $(nproc))
#   --skip-build       Skip cmake/make step
#   --skip-angr        Skip angr analysis
#   --skip-size        Skip size analysis
#   --mode MODE        Run only one specific mode (for incremental runs)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="${SCRIPT_DIR}/../tests"
BUILDS_DIR="${SCRIPT_DIR}/../builds"
RESULTS_DIR="${SCRIPT_DIR}/../results"
ENSIA_PLUGIN="${SCRIPT_DIR}/../../../build/obfuscation/libEnsia.so"
JOBS="$(nproc 2>/dev/null || echo 4)"
SKIP_BUILD=0
SKIP_ANGR=0
SKIP_SIZE=0
ONLY_MODE=""
ANGR_TIMEOUT=600

# ── Parse arguments ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tests-dir)    TESTS_DIR="$2";    shift 2 ;;
        --builds-dir)   BUILDS_DIR="$2";   shift 2 ;;
        --results-dir)  RESULTS_DIR="$2";  shift 2 ;;
        --ensia-plugin) ENSIA_PLUGIN="$2"; shift 2 ;;
        --jobs)         JOBS="$2";         shift 2 ;;
        --skip-build)   SKIP_BUILD=1;      shift   ;;
        --skip-angr)    SKIP_ANGR=1;       shift   ;;
        --skip-size)    SKIP_SIZE=1;       shift   ;;
        --mode)         ONLY_MODE="$2";    shift 2 ;;
        --timeout)      ANGR_TIMEOUT="$2"; shift 2 ;;
        --help|-h)
            grep '^#' "$0" | sed 's/^# \?//' | head -20
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

MODES=("baseline" "csm_only" "vec_only" "csm_vec" "max")
[[ -n "$ONLY_MODE" ]] && MODES=("$ONLY_MODE")

mkdir -p "$BUILDS_DIR" "$RESULTS_DIR"

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; RESET='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${RESET}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
log_error() { echo -e "${RED}[ERROR]${RESET} $*"; }

# ── Step 1: Build ─────────────────────────────────────────────────────────────
if [[ $SKIP_BUILD -eq 0 ]]; then
    log_info "=== Step 1: Building all modes ==="
    for mode in "${MODES[@]}"; do
        build_dir="${BUILDS_DIR}/build_${mode}"
        log_info "  Building mode: ${mode} → ${build_dir}"

        cmake_args=(
            -S "${TESTS_DIR}"
            -B "${build_dir}"
            "-DOBFUSCATION_MODE=${mode}"
            "-DCMAKE_BUILD_TYPE=RelWithDebInfo"
        )

        # Add plugin path for non-baseline modes
        if [[ "$mode" != "baseline" ]]; then
            if [[ ! -f "$ENSIA_PLUGIN" ]]; then
                log_error "Ensia plugin not found: $ENSIA_PLUGIN"
                log_error "Build the plugin first with: cmake --build build/ --target Ensia"
                exit 1
            fi
            cmake_args+=("-DENSIA_PLUGIN=${ENSIA_PLUGIN}")
        fi

        cmake "${cmake_args[@]}" 2>&1 | tail -5

        if cmake --build "${build_dir}" --parallel "${JOBS}" 2>&1 | tail -3; then
            log_ok "  Mode '${mode}' built successfully"
        else
            log_error "  Build FAILED for mode '${mode}'"
            log_warn "  Continuing with other modes..."
        fi
    done
else
    log_warn "Step 1 (build) skipped via --skip-build"
fi

# ── Step 2: Size analysis ─────────────────────────────────────────────────────
if [[ $SKIP_SIZE -eq 0 ]]; then
    log_info "=== Step 2: Code bloat analysis ==="
    size_output="${RESULTS_DIR}/size_analysis.csv"
    bash "${SCRIPT_DIR}/run_size_analysis.sh" "${BUILDS_DIR}" "${size_output}"
    log_ok "  Size analysis: ${size_output}"
else
    log_warn "Step 2 (size analysis) skipped via --skip-size"
fi

# ── Step 3: angr analysis ─────────────────────────────────────────────────────
if [[ $SKIP_ANGR -eq 0 ]]; then
    log_info "=== Step 3: angr symbolic execution analysis ==="

    # Check angr is available
    if ! python3 -c "import angr" 2>/dev/null; then
        log_error "angr not installed. Run: pip install angr psutil"
        log_warn "Skipping angr analysis."
        SKIP_ANGR=1
    fi
fi

if [[ $SKIP_ANGR -eq 0 ]]; then
    for mode in "${MODES[@]}"; do
        build_dir="${BUILDS_DIR}/build_${mode}"
        [[ -d "$build_dir" ]] || { log_warn "Build dir not found: $build_dir, skipping"; continue; }

        angr_output="${RESULTS_DIR}/angr_${mode}.csv"
        log_info "  Running angr for mode '${mode}'..."

        python3 "${SCRIPT_DIR}/run_angr_analysis.py" \
            --build-dir "${build_dir}" \
            --mode "${mode}" \
            --timeout "${ANGR_TIMEOUT}" \
            --output "${angr_output}" \
            --skip-size-only \
            && log_ok "  angr results: ${angr_output}" \
            || log_warn "  angr analysis encountered errors for mode '${mode}'"
    done
fi

# ── Step 4: Collect and summarise results ─────────────────────────────────────
log_info "=== Step 4: Collecting results ==="
python3 "${SCRIPT_DIR}/collect_results.py" \
    --results-dir "${RESULTS_DIR}" \
    --output "${RESULTS_DIR}/summary.csv" \
    2>/dev/null && log_ok "  Summary: ${RESULTS_DIR}/summary.csv" || true

# ── Final summary ─────────────────────────────────────────────────────────────
echo ""
log_ok "=== Ablation experiment complete ==="
echo ""
echo "  Results directory: ${RESULTS_DIR}/"
ls -lh "${RESULTS_DIR}"/*.csv 2>/dev/null || true
