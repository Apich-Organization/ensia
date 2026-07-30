#!/usr/bin/env python3
"""
collect_results.py — Ensia Benchmark: Result Aggregation
=========================================================

Merges angr CSV files (one per mode) + size CSV into a unified summary table.

Output columns:
  algo, size_only,
  [per mode]: text_bytes, file_bytes, text_bloat, file_bloat,
              wall_time_s, peak_mem_mib, max_active_states,
              deadended_states, unresolved_branches,
              z3_timeout_count, z3_solver_calls, angr_status

Usage:
    python3 collect_results.py --results-dir ./results --output ./results/summary.csv
"""

import argparse
import csv
import os
import sys
from collections import defaultdict

MODES = ["baseline", "csm_only", "vec_only", "csm_vec", "max"]
ANGR_FIELDS = [
    "wall_time_s", "peak_mem_mib", "max_active_states",
    "deadended_states", "found_states", "unresolved_branches",
    "z3_timeout_count", "z3_solver_calls", "status"
]
SIZE_FIELDS = [
    "elf_text_bytes", "elf_file_bytes", "ir_instr_count",
    "baseline_text", "baseline_file", "text_bloat_ratio", "file_bloat_ratio"
]


def load_csv(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def safe_float(v: str) -> float:
    try:
        return float(v)
    except (ValueError, TypeError):
        return 0.0


def main():
    ap = argparse.ArgumentParser(description="Ensia benchmark result collector")
    ap.add_argument("--results-dir", required=True, help="Directory containing CSV files")
    ap.add_argument("--output",      default="summary.csv", help="Output summary CSV")
    ap.add_argument("--latex",       action="store_true", help="Also generate LaTeX table snippet")
    args = ap.parse_args()

    # ── Load size data ────────────────────────────────────────────────────────
    size_data: dict[tuple, dict] = {}  # (algo, mode) → row
    size_csv = os.path.join(args.results_dir, "size_analysis.csv")
    for row in load_csv(size_csv):
        key = (row.get("algo", ""), row.get("mode", ""))
        size_data[key] = row

    # ── Load angr data ────────────────────────────────────────────────────────
    angr_data: dict[tuple, dict] = {}  # (algo, mode) → row
    for mode in MODES:
        angr_csv = os.path.join(args.results_dir, f"angr_{mode}.csv")
        for row in load_csv(angr_csv):
            key = (row.get("algo", ""), mode)
            angr_data[key] = row

    # ── Gather all algos ──────────────────────────────────────────────────────
    all_algos = set()
    for (algo, _) in size_data:
        all_algos.add(algo)
    for (algo, _) in angr_data:
        all_algos.add(algo)
    all_algos = sorted(all_algos)

    # ── Build output rows ─────────────────────────────────────────────────────
    output_rows = []
    for algo in all_algos:
        # Determine size_only from any available meta
        size_only = "OFF"
        for mode in MODES:
            row = size_data.get((algo, mode), {})
            if row.get("size_only", "OFF") in ("ON", "1", "true"):
                size_only = "ON"
                break

        base_row: dict = {"algo": algo, "size_only": size_only}

        for mode in MODES:
            prefix = f"{mode}_"

            s = size_data.get((algo, mode), {})
            base_row[f"{prefix}text_bytes"]     = s.get("elf_text_bytes", "")
            base_row[f"{prefix}file_bytes"]     = s.get("elf_file_bytes", "")
            base_row[f"{prefix}ir_instr"]       = s.get("ir_instr_count", "")
            base_row[f"{prefix}text_bloat"]     = s.get("text_bloat_ratio", "")
            base_row[f"{prefix}file_bloat"]     = s.get("file_bloat_ratio", "")

            a = angr_data.get((algo, mode), {})
            base_row[f"{prefix}wall_time_s"]    = a.get("wall_time_s", "")
            base_row[f"{prefix}peak_mem_mib"]   = a.get("peak_mem_mib", "")
            base_row[f"{prefix}max_states"]     = a.get("max_active_states", "")
            base_row[f"{prefix}deadended"]      = a.get("deadended_states", "")
            base_row[f"{prefix}unresolved"]     = a.get("unresolved_branches", "")
            base_row[f"{prefix}z3_timeout"]     = a.get("z3_timeout_count", "")
            base_row[f"{prefix}z3_calls"]       = a.get("z3_solver_calls", "")
            base_row[f"{prefix}angr_status"]    = a.get("status", "")

        output_rows.append(base_row)

    # ── Write summary CSV ─────────────────────────────────────────────────────
    if not output_rows:
        print("[WARNING] No data to summarise.")
        sys.exit(0)

    fieldnames = list(output_rows[0].keys())
    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output_rows)

    print(f"[OK] Summary written: {args.output} ({len(output_rows)} algorithms)")

    # ── Print quick stats ─────────────────────────────────────────────────────
    print("\n--- Quick Stats (angr-eligible algorithms) ---")
    for mode in MODES[1:]:  # skip baseline
        times = [safe_float(r.get(f"{mode}_wall_time_s", 0)) for r in output_rows
                 if r.get("size_only") == "OFF" and r.get(f"{mode}_wall_time_s")]
        states = [safe_float(r.get(f"{mode}_max_states", 0)) for r in output_rows
                  if r.get("size_only") == "OFF" and r.get(f"{mode}_max_states")]
        timeouts = sum(1 for r in output_rows
                       if r.get("size_only") == "OFF"
                       and "timeout" in r.get(f"{mode}_angr_status", ""))
        if times:
            avg_t = sum(times) / len(times)
            avg_s = sum(states) / len(states) if states else 0
            print(f"  {mode:12s}: avg_time={avg_t:7.2f}s  avg_states={avg_s:7.1f}  "
                  f"timeouts={timeouts}/{len(times)}")

    # ── Optional LaTeX table ──────────────────────────────────────────────────
    if args.latex:
        latex_path = args.output.replace(".csv", "_latex.tex")
        _write_latex(output_rows, latex_path)
        print(f"\n[OK] LaTeX snippet: {latex_path}")


def _write_latex(rows: list[dict], path: str):
    """Generate a compact LaTeX table for the paper (ablation section)."""
    with open(path, "w") as f:
        f.write("% Auto-generated by collect_results.py\n")
        f.write("\\begin{table}[ht]\n")
        f.write("\\centering\n")
        f.write("\\caption{Ablation study: angr analysis metrics across obfuscation modes}\n")
        f.write("\\label{tab:ablation}\n")
        f.write("\\resizebox{\\textwidth}{!}{%\n")
        f.write("\\begin{tabular}{l|rr|rr|rr|rr|rr}\n")
        f.write("\\toprule\n")
        f.write("\\textbf{Algorithm} & "
                "\\multicolumn{2}{c|}{\\textbf{Baseline}} & "
                "\\multicolumn{2}{c|}{\\textbf{CSM-only}} & "
                "\\multicolumn{2}{c|}{\\textbf{Vec-only}} & "
                "\\multicolumn{2}{c|}{\\textbf{CSM+Vec}} & "
                "\\multicolumn{2}{c}{\\textbf{MAX}} \\\\\n")
        f.write("& T(s) & Sts & T(s) & Sts & T(s) & Sts & T(s) & Sts & T(s) & Sts \\\\\n")
        f.write("\\midrule\n")

        for row in rows:
            if row.get("size_only") == "ON":
                continue
            algo = row["algo"].replace("_", "\\_")
            cells = []
            for mode in MODES:
                t  = row.get(f"{mode}_wall_time_s", "--") or "--"
                st = row.get(f"{mode}_max_states",  "--") or "--"
                try:
                    t = f"{float(t):.1f}"
                except ValueError:
                    pass
                cells.append(f"{t} & {st}")
            f.write(f"\\texttt{{{algo}}} & {' & '.join(cells)} \\\\\n")

        f.write("\\bottomrule\n")
        f.write("\\end{tabular}%\n}\n")
        f.write("\\end{table}\n")


if __name__ == "__main__":
    main()
