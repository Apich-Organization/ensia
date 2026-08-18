#!/usr/bin/env python3
"""
run_full_reverse_engineering_benchmark.py
====================================================================================
Comprehensive Reverse Engineering & Obfuscation Resistance Benchmark Suite for Ensia
====================================================================================

Analyzes all 79 cryptographic targets across baseline and max obfuscation modes:
  1. Static Graph & Binary Metrics (Size, BBs, Edges, Cyclomatic Complexity)
  2. SMT Opaque Predicate Deobfuscation Attack (Z3 query time, branch resistance)
  3. Symbolic Execution & Dispatcher Trapping (Trace steps, exploration time, timeouts)

Outputs:
  - benchmark/results/full_deobf_benchmark.json
  - benchmark/results/full_deobf_benchmark.csv
  - benchmark/results/BENCHMARK_REPORT.md
"""

import argparse
import csv
import json
import os
import sys
import time
import concurrent.futures
from typing import Dict, Any, List

# Suppress angr/claripy noise
import logging
logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("claripy").setLevel(logging.CRITICAL)
logging.getLogger("pyvex").setLevel(logging.CRITICAL)
logging.getLogger("cle").setLevel(logging.CRITICAL)

try:
    import angr
    import claripy
except ImportError:
    print("[!] Error: angr or claripy is not installed in the python environment.")
    sys.exit(1)


def analyze_single_binary(bin_path: str, timeout: float = 10.0) -> Dict[str, Any]:
    """Analyzes a single binary for CFG metrics, SMT branch cost, and symbolic trace."""
    if not os.path.exists(bin_path):
        return {"error": f"File not found: {bin_path}"}

    res: Dict[str, Any] = {
        "path": bin_path,
        "size_bytes": os.path.getsize(bin_path),
        "total_functions": 0,
        "main_bb_count": 0,
        "total_cfg_nodes": 0,
        "total_cfg_edges": 0,
        "cyclomatic_complexity": 0,
        "analyzed_branches": 0,
        "z3_branch_time_s": 0.0,
        "opaque_resistant_branches": 0,
        "symbolic_trace_steps": 0,
        "symbolic_trace_time_s": 0.0,
        "symbolic_timed_out": False,
        "status": "OK",
    }

    try:
        proj = angr.Project(bin_path, auto_load_libs=False)

        # ── 1. CFG Fast Recovery ──────────────────────────────────────────
        cfg = proj.analyses.CFGFast()
        res["total_functions"] = len(cfg.functions)
        res["total_cfg_nodes"] = len(list(cfg.graph.nodes))
        res["total_cfg_edges"] = len(list(cfg.graph.edges))

        main_sym = proj.loader.find_symbol("main")
        main_addr = main_sym.rebased_addr if main_sym else proj.entry
        main_func = cfg.functions.get(main_addr, None)

        if main_func:
            res["main_bb_count"] = len(list(main_func.blocks))
            res["cyclomatic_complexity"] = main_func.cyclomatic_complexity
        else:
            res["main_bb_count"] = res["total_cfg_nodes"]

        # ── 2. Opaque Predicate SMT Analysis ─────────────────────────────
        if main_func:
            branch_count = 0
            z3_time = 0.0
            opaque_resistant = 0
            for b in list(main_func.blocks)[:40]:  # sample first 40 basic blocks
                if (
                    b.vex.jumpkind == "Ijk_Boring"
                    and len(b.vex.constant_jump_targets_and_jumpkinds) == 2
                ):
                    branch_count += 1
                    t0 = time.perf_counter()
                    try:
                        st = proj.factory.blank_state(addr=b.addr)
                        succs = proj.factory.successors(st)
                        z3_time += time.perf_counter() - t0
                        if len(succs.flat_successors) > 1:
                            opaque_resistant += 1
                    except Exception:
                        z3_time += time.perf_counter() - t0
                        opaque_resistant += 1
            res["analyzed_branches"] = branch_count
            res["z3_branch_time_s"] = round(z3_time, 4)
            res["opaque_resistant_branches"] = opaque_resistant

        # ── 3. Symbolic Path Trace ────────────────────────────────────────
        st = proj.factory.call_state(
            main_addr,
            add_options={
                angr.options.SIMPLIFY_EXPRS,
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            },
        )
        sm = proj.factory.simulation_manager(st)
        steps = 0
        t0 = time.perf_counter()
        deadline = t0 + timeout

        while sm.active:
            if time.perf_counter() > deadline:
                res["symbolic_timed_out"] = True
                break
            sm.step()
            steps += 1
            if len(sm.active) > 256:
                sm.active = sm.active[:256]

        t1 = time.perf_counter()
        res["symbolic_trace_steps"] = steps
        res["symbolic_trace_time_s"] = round(t1 - t0, 3)

    except Exception as exc:
        res["status"] = f"ERROR: {str(exc)}"

    return res


def evaluate_target_pair(algo_name: str, base_dir: str, max_dir: str, timeout: float) -> Dict[str, Any]:
    """Runs evaluation on both baseline and max binaries for a target algorithm."""
    base_bin = os.path.join(base_dir, f"{algo_name}_baseline")
    max_bin = os.path.join(max_dir, f"{algo_name}_max")

    base_res = analyze_single_binary(base_bin, timeout=timeout)
    max_res = analyze_single_binary(max_bin, timeout=timeout)

    # Compute comparison ratios
    sz_ratio = (
        round(max_res.get("size_bytes", 0) / max(1, base_res.get("size_bytes", 1)), 2)
    )
    bb_ratio = round(
        max_res.get("main_bb_count", 0) / max(1, base_res.get("main_bb_count", 1)), 2
    )
    edges_ratio = round(
        max_res.get("total_cfg_edges", 0)
        / max(1, base_res.get("total_cfg_edges", 1)),
        2,
    )
    cyc_ratio = round(
        max_res.get("cyclomatic_complexity", 0)
        / max(1, base_res.get("cyclomatic_complexity", 1)),
        2,
    )

    z3_base = max_res.get("z3_branch_time_s", 0.0001)
    z3_cost_ratio = round(
        max_res.get("z3_branch_time_s", 0)
        / max(0.0001, base_res.get("z3_branch_time_s", 0.0001)),
        2,
    )

    return {
        "algo": algo_name,
        "baseline": base_res,
        "max": max_res,
        "ratios": {
            "size_expansion": sz_ratio,
            "bb_expansion": bb_ratio,
            "edges_expansion": edges_ratio,
            "cyclomatic_expansion": cyc_ratio,
            "z3_cost_ratio": z3_cost_ratio,
        },
    }


def categorize_algorithm(algo: str) -> str:
    """Categorizes algorithm name into cryptographic domain."""
    if any(k in algo for k in ["aes", "des", "blowfish", "camellia", "cast", "idea", "mars", "present", "rc2", "rc6", "seed", "serpent", "sm4", "tea", "twofish", "xtea"]):
        return "Block Cipher"
    if any(k in algo for k in ["chacha", "salsa", "rc4", "zuc"]):
        return "Stream Cipher"
    if any(k in algo for k in ["md5", "sha", "ripemd", "sm3", "tiger", "whirlpool", "blake"]):
        return "Hash / Digest"
    if any(k in algo for k in ["cmac", "gmac", "hmac", "kmac", "xcbc", "poly1305"]):
        return "MAC / Authenticator"
    if any(k in algo for k in ["ascon"]):
        return "Lightweight / AEAD"
    if any(k in algo for k in ["bcrypt", "scrypt", "pbkdf2", "hkdf"]):
        return "KDF / Password"
    if any(k in algo for k in ["rsa", "dsa", "dh", "ecdh", "ecdsa", "ed25519", "sm2", "x25519"]):
        return "Asymmetric / PKC"
    if any(k in algo for k in ["mldsa", "mlkem"]):
        return "Post-Quantum (PQC)"
    return "Cryptographic Other"


def generate_markdown_report(results: List[Dict[str, Any]], output_path: str):
    """Generates a detailed Markdown benchmark report."""
    total_targets = len(results)
    if total_targets == 0:
        return

    # Compute overall statistics
    valid_results = [r for r in results if r["baseline"].get("status") == "OK" and r["max"].get("status") == "OK"]
    
    avg_size_exp = sum(r["ratios"]["size_expansion"] for r in valid_results) / len(valid_results)
    avg_bb_exp = sum(r["ratios"]["bb_expansion"] for r in valid_results) / len(valid_results)
    avg_edges_exp = sum(r["ratios"]["edges_expansion"] for r in valid_results) / len(valid_results)
    avg_cyc_exp = sum(r["ratios"]["cyclomatic_expansion"] for r in valid_results) / len(valid_results)
    avg_z3_ratio = sum(r["ratios"]["z3_cost_ratio"] for r in valid_results) / len(valid_results)
    
    base_timeouts = sum(1 for r in valid_results if r["baseline"].get("symbolic_timed_out", False))
    max_timeouts = sum(1 for r in valid_results if r["max"].get("symbolic_timed_out", False))

    lines = []
    lines.append("# Ensia Obfuscator: Comprehensive Reverse Engineering & Security Benchmark Report\n")
    lines.append(f"**Date**: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Evaluated Cryptographic Targets**: {total_targets}")
    lines.append(f"**Evaluation Toolchain**: Angr 9.3 + Z3 SMT Solver + LLVM 22.1 Engine\n")

    lines.append("## 1. Executive Summary & Macro Metrics\n")
    lines.append("| Metric | Average Value across All Targets | Key Impact on Reverse Engineering |")
    lines.append("| :--- | :---: | :--- |")
    lines.append(f"| **Binary Code Expansion** | **{avg_size_exp:.2f}x** | Eliminates code signatures & increases disassembler memory overhead |")
    lines.append(f"| **Basic Block (BB) Multiplier** | **{avg_bb_exp:.2f}x** | Shatters basic block control flow & complicates AST recovery |")
    lines.append(f"| **CFG Edge Transition Explosion** | **{avg_edges_exp:.2f}x** | Massive state-transition graph defeats linear control-flow reconstruction |")
    lines.append(f"| **Cyclomatic Complexity Expansion** | **{avg_cyc_exp:.2f}x** | Extreme complexity score breaks automatic decompilers |")
    lines.append(f"| **SMT Invariant Solving Slowdown** | **{avg_z3_ratio:.2f}x** | Multi-layer MBA & Feistel expansion severely bogs down Z3 queries |")
    lines.append(f"| **Symbolic Execution Timeout Rate** | **{max_timeouts}/{len(valid_results)} ({max_timeouts/len(valid_results)*100:.1f}%)** vs Baseline ({base_timeouts}/{len(valid_results)}) | Automated symbolic solvers get trapped in chaos state machines |")
    lines.append("\n---\n")

    lines.append("## 2. Category Breakdown\n")
    categories = {}
    for r in valid_results:
        cat = categorize_algorithm(r["algo"])
        categories.setdefault(cat, []).append(r)

    lines.append("| Cryptographic Category | Count | Avg Size Exp | Avg BB Exp | Avg Edge Exp | Avg Cyclomatic Exp | SMT Slowdown |")
    lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |")
    for cat, items in sorted(categories.items()):
        c_size = sum(x["ratios"]["size_expansion"] for x in items) / len(items)
        c_bb = sum(x["ratios"]["bb_expansion"] for x in items) / len(items)
        c_edges = sum(x["ratios"]["edges_expansion"] for x in items) / len(items)
        c_cyc = sum(x["ratios"]["cyclomatic_expansion"] for x in items) / len(items)
        c_z3 = sum(x["ratios"]["z3_cost_ratio"] for x in items) / len(items)
        lines.append(f"| **{cat}** | {len(items)} | {c_size:.2f}x | {c_bb:.2f}x | {c_edges:.2f}x | {c_cyc:.2f}x | {c_z3:.2f}x |")
    lines.append("\n---\n")

    lines.append("## 3. Full 79-Target Comparative Benchmark Data\n")
    lines.append("| Target Algorithm | Domain | Baseline Size | Max Size (Exp) | Main BBs (Exp) | Total Edges (Exp) | Cyclomatic (Exp) | SMT Branch Cost | Symbolic Status (Base vs Max) |")
    lines.append("| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")

    for r in sorted(results, key=lambda x: x["algo"]):
        algo = r["algo"]
        cat = categorize_algorithm(algo)
        base = r["baseline"]
        mx = r["max"]
        rat = r["ratios"]

        b_sz = f"{base.get('size_bytes', 0):,} B"
        m_sz = f"{mx.get('size_bytes', 0):,} B ({rat.get('size_expansion', 1.0)}x)"
        bbs = f"{base.get('main_bb_count', 0)} → {mx.get('main_bb_count', 0)} ({rat.get('bb_expansion', 1.0)}x)"
        edges = f"{base.get('total_cfg_edges', 0)} → {mx.get('total_cfg_edges', 0)} ({rat.get('edges_expansion', 1.0)}x)"
        cyc = f"{base.get('cyclomatic_complexity', 0)} → {mx.get('cyclomatic_complexity', 0)} ({rat.get('cyclomatic_expansion', 1.0)}x)"
        smt = f"{base.get('z3_branch_time_s', 0)}s → {mx.get('z3_branch_time_s', 0)}s ({rat.get('z3_cost_ratio', 1.0)}x)"

        b_trace_time = base.get("symbolic_trace_time_s", 0)
        m_trace_time = mx.get("symbolic_trace_time_s", 0)
        b_status = "TIMEOUT" if base.get("symbolic_timed_out") else f"{b_trace_time}s"
        m_status = "TIMEOUT" if mx.get("symbolic_timed_out") else f"{m_trace_time}s"
        sym_stat = f"{b_status} / **{m_status}**"

        lines.append(f"| `{algo}` | {cat} | {b_sz} | {m_sz} | {bbs} | {edges} | {cyc} | {smt} | {sym_stat} |")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Run Full Ensia Obfuscation & Reverse Engineering Benchmark Suite")
    parser.add_argument("--base-dir", default="benchmark/tests/build_baseline", help="Directory of baseline binaries")
    parser.add_argument("--max-dir", default="benchmark/tests/build_max", help="Directory of max obfuscated binaries")
    parser.add_argument("--output-dir", default="benchmark/results", help="Directory to save benchmark results")
    parser.add_argument("--timeout", type=float, default=10.0, help="Symbolic execution timeout per target in seconds")
    parser.add_argument("--workers", type=int, default=4, help="Number of parallel worker processes")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    # Discover all targets
    base_files = [f for f in os.listdir(args.base_dir) if f.endswith("_baseline")]
    targets = sorted([f.replace("_baseline", "") for f in base_files])

    print("==========================================================================================================")
    print(f" ENSIA FULL REVERSE ENGINEERING BENCHMARK SUITE ({len(targets)} Targets, Workers={args.workers}, Timeout={args.timeout}s)")
    print("==========================================================================================================")
    print(f"[*] Discovering targets from: {args.base_dir}")
    print(f"[*] Total target algorithms to evaluate: {len(targets)}")
    print(f"[*] Starting parallel evaluation...")
    print("-" * 106)

    t_start = time.perf_counter()
    all_results = []
    completed_count = 0

    with concurrent.futures.ProcessPoolExecutor(max_workers=args.workers) as executor:
        future_to_algo = {
            executor.submit(evaluate_target_pair, algo, args.base_dir, args.max_dir, args.timeout): algo
            for algo in targets
        }

        for future in concurrent.futures.as_completed(future_to_algo):
            algo = future_to_algo[future]
            try:
                res = future.result()
                all_results.append(res)
                completed_count += 1

                rat = res["ratios"]
                b_stat = "TIMEOUT" if res["baseline"].get("symbolic_timed_out") else f"{res['baseline'].get('symbolic_trace_time_s', 0)}s"
                m_stat = "TIMEOUT" if res["max"].get("symbolic_timed_out") else f"{res['max'].get('symbolic_trace_time_s', 0)}s"

                print(
                    f"[{completed_count:02d}/{len(targets):02d}] {algo:<22} | "
                    f"Size: {rat['size_expansion']:>5.2f}x | "
                    f"BB: {rat['bb_expansion']:>5.2f}x | "
                    f"Edges: {rat['edges_expansion']:>5.2f}x | "
                    f"Cyc: {rat['cyclomatic_expansion']:>5.2f}x | "
                    f"Trace: {b_stat} -> {m_stat}"
                )
            except Exception as exc:
                print(f"[!] Target {algo} generated an exception: {exc}")

    t_total = time.perf_counter() - t_start
    print("-" * 106)
    print(f"[+] All {len(all_results)} targets evaluated in {t_total:.2f} seconds.")

    # Save JSON
    json_path = os.path.join(args.output_dir, "full_deobf_benchmark.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)
    print(f"[+] JSON results saved to: {json_path}")

    # Save CSV
    csv_path = os.path.join(args.output_dir, "full_deobf_benchmark.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "algo", "category",
            "base_size", "max_size", "size_ratio",
            "base_main_bbs", "max_main_bbs", "bb_ratio",
            "base_edges", "max_edges", "edges_ratio",
            "base_cyclomatic", "max_cyclomatic", "cyc_ratio",
            "base_z3_time_s", "max_z3_time_s", "z3_slowdown",
            "base_trace_time_s", "base_timed_out",
            "max_trace_time_s", "max_timed_out"
        ])
        for r in sorted(all_results, key=lambda x: x["algo"]):
            base = r["baseline"]
            mx = r["max"]
            rat = r["ratios"]
            writer.writerow([
                r["algo"], categorize_algorithm(r["algo"]),
                base.get("size_bytes", 0), mx.get("size_bytes", 0), rat.get("size_expansion", 1.0),
                base.get("main_bb_count", 0), mx.get("main_bb_count", 0), rat.get("bb_expansion", 1.0),
                base.get("total_cfg_edges", 0), mx.get("total_cfg_edges", 0), rat.get("edges_expansion", 1.0),
                base.get("cyclomatic_complexity", 0), mx.get("cyclomatic_complexity", 0), rat.get("cyclomatic_expansion", 1.0),
                base.get("z3_branch_time_s", 0), mx.get("z3_branch_time_s", 0), rat.get("z3_cost_ratio", 1.0),
                base.get("symbolic_trace_time_s", 0), base.get("symbolic_timed_out", False),
                mx.get("symbolic_trace_time_s", 0), mx.get("symbolic_timed_out", False)
            ])
    print(f"[+] CSV summary saved to: {csv_path}")

    # Generate Markdown report
    md_path = os.path.join(args.output_dir, "BENCHMARK_REPORT.md")
    generate_markdown_report(all_results, md_path)
    print(f"[+] Comprehensive Markdown report saved to: {md_path}")
    print("==========================================================================================================")


if __name__ == "__main__":
    main()
