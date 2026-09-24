#!/usr/bin/env python3
import json
import re
import sys
import os

sys.path.append(os.path.dirname(__file__))
from run_full_reverse_engineering_benchmark import categorize_algorithm

def generate_rust_code(json_file, target_rs):
    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Sort data by algo name
    data.sort(key=lambda x: x["algo"])

    rows = []
    for item in data:
        algo = item["algo"]
        cat = categorize_algorithm(algo)
        base = item["baseline"]
        mx = item["max"]
        ratios = item["ratios"]

        base_sz = base.get("size_bytes", 0)
        max_sz = mx.get("size_bytes", 0)
        sz_ratio = ratios.get("size_expansion", 1.0)

        base_bbs = base.get("main_bb_count", 0)
        max_bbs = mx.get("main_bb_count", 0)
        bb_ratio = ratios.get("bb_expansion", 1.0)

        base_edges = base.get("total_cfg_edges", 0)
        max_edges = mx.get("total_cfg_edges", 0)
        edges_ratio = ratios.get("edges_expansion", 1.0)

        base_cyc = base.get("cyclomatic_complexity", 0)
        max_cyc = mx.get("cyclomatic_complexity", 0)
        cyc_ratio = ratios.get("cyclomatic_expansion", 1.0)

        base_z3 = base.get("z3_branch_time_s", 0.0)
        max_z3 = mx.get("z3_branch_time_s", 0.0)
        z3_ratio = ratios.get("z3_cost_ratio", 1.0)

        base_to = "true" if base.get("symbolic_timed_out", False) else "false"
        max_to = "true" if mx.get("symbolic_timed_out", False) else "false"
        base_status = base.get("symbolic_status", "TIMEOUT" if base.get("symbolic_timed_out") else "OK")
        max_status = mx.get("symbolic_status", "TIMEOUT" if mx.get("symbolic_timed_out") else "OK")

        row = f"""    BenchmarkRow {{
        algo: "{algo}",
        category: "{cat}",
        base_size: {base_sz},
        max_size: {max_sz},
        size_ratio: {sz_ratio},
        base_bbs: {base_bbs},
        max_bbs: {max_bbs},
        bb_ratio: {bb_ratio},
        base_edges: {base_edges},
        max_edges: {max_edges},
        edges_ratio: {edges_ratio},
        base_cyc: {base_cyc},
        max_cyc: {max_cyc},
        cyc_ratio: {cyc_ratio},
        base_z3_s: {base_z3},
        max_z3_s: {max_z3},
        z3_ratio: {z3_ratio},
        base_timeout: {base_to},
        max_timeout: {max_to},
        base_status: "{base_status}",
        max_status: "{max_status}",
    }},"""
        rows.append(row)

    benchmark_data_str = "const BENCHMARK_DATA: &[BenchmarkRow] = &[\n" + "\n".join(rows) + "\n];"

    with open(target_rs, "r", encoding="utf-8") as f:
        content = f.read()

    # Replace from 'const BENCHMARK_DATA: &[BenchmarkRow] = &[' to the closing '];' before PassVerificationRow
    pattern = r"const BENCHMARK_DATA: &\[BenchmarkRow\] = &\[[\s\S]*?\n\];\n"
    replacement = benchmark_data_str + "\n"

    new_content, count = re.subn(pattern, replacement, content, count=1)
    if count == 0:
        print("[!] Error: Could not find BENCHMARK_DATA block in target file.")
        sys.exit(1)

    with open(target_rs, "w", encoding="utf-8") as f:
        f.write(new_content)

    print(f"[+] Successfully updated {len(data)} rows in {target_rs}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 sync_to_web.py <full_deobf_benchmark.json> <path_to_benchmark.rs>")
        sys.exit(1)
    generate_rust_code(sys.argv[1], sys.argv[2])
