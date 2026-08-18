#!/usr/bin/env python3
"""
researcher_deobf_benchmark.py — Comprehensive Reverse Engineering & Obfuscation Strength Benchmark
====================================================================================================

Evaluates obfuscation resistance against a reverse engineer equipped with automated angr/Z3 deobfuscation tools.
Compares:
  - Baseline (Un-obfuscated)
  - Max Obfuscated (Ensia max preset)

Metrics:
  1. Static Complexity:
     - Binary Size (bytes)
     - CFG Basic Blocks (Total & In Target Function)
     - CFG Edges
     - Cyclomatic Complexity V(G)
  2. SMT Opaque Predicate Deobfuscation Attack:
     - Number of Conditional Branches Analyzed
     - Z3 Query Time for Invariant Solving
     - Opaque Predicates Resisting SMT Inversion
  3. Symbolic Execution Trace & State Explosion:
     - Trace Steps to Target Completion
     - Wall-clock Time for Symbolic Traversal
     - State Explosion / Branch Divergence Ratio
"""

import argparse
import os
import sys
import time
import claripy
import angr

def run_deobf_benchmark(algos, timeout=10.0):
    print("=" * 120)
    print(f" REVERSE ENGINEERING RESEARCHER BENCHMARK: BASELINE vs ENSIA MAX (Timeout = {timeout}s per phase)")
    print("=" * 120)
    print(f"{'Target Algorithm':<16} | {'Metric / Stage':<30} | {'Baseline':<18} | {'Ensia Max':<18} | {'Obfuscation Ratio':<18}")
    print("-" * 120)

    for algo in algos:
        base_bin = f"benchmark/tests/build_baseline/{algo}_baseline"
        max_bin = f"benchmark/tests/build_max/{algo}_max"

        if not os.path.exists(base_bin) or not os.path.exists(max_bin):
            continue

        # -------------------------------------------------------------
        # 1. Static CFG & Size Analysis
        # -------------------------------------------------------------
        sz_base = os.path.getsize(base_bin)
        sz_max = os.path.getsize(max_bin)

        proj_base = angr.Project(base_bin, auto_load_libs=False)
        proj_max = angr.Project(max_bin, auto_load_libs=False)

        cfg_base = proj_base.analyses.CFGFast()
        cfg_max = proj_max.analyses.CFGFast()

        main_base = cfg_base.functions.get(proj_base.loader.find_symbol('main').rebased_addr if proj_base.loader.find_symbol('main') else proj_base.entry)
        main_max = cfg_max.functions.get(proj_max.loader.find_symbol('main').rebased_addr if proj_max.loader.find_symbol('main') else proj_max.entry)

        bb_base = len(list(main_base.blocks)) if main_base else len(list(cfg_base.graph.nodes))
        bb_max = len(list(main_max.blocks)) if main_max else len(list(cfg_max.graph.nodes))

        edges_base = len(list(cfg_base.graph.edges))
        edges_max = len(list(cfg_max.graph.edges))

        cyc_base = main_base.cyclomatic_complexity if main_base else 0
        cyc_max = main_max.cyclomatic_complexity if main_max else 0

        # -------------------------------------------------------------
        # 2. Automated Opaque Predicate Deobfuscation Attack
        # -------------------------------------------------------------
        # The deobfuscator scans conditional branch blocks in main and queries Z3
        def analyze_branches(proj, main_func):
            if not main_func:
                return 0, 0.0, 0
            branch_count = 0
            z3_time = 0.0
            opaque_resistant = 0
            
            for b in list(main_func.blocks)[:40]: # sample up to 40 blocks
                if b.vex.jumpkind == 'Ijk_Boring' and len(b.vex.constant_jump_targets_and_jumpkinds) == 2:
                    branch_count += 1
                    t0 = time.perf_counter()
                    try:
                        # Reverse engineer attempts to evaluate branch condition feasibility
                        st = proj.factory.blank_state(addr=b.addr)
                        succs = proj.factory.successors(st)
                        # Measure SMT solving overhead
                        z3_time += (time.perf_counter() - t0)
                        if len(succs.flat_successors) > 1:
                            opaque_resistant += 1
                    except Exception:
                        z3_time += (time.perf_counter() - t0)
                        opaque_resistant += 1
            return branch_count, round(z3_time, 4), opaque_resistant

        br_base, z3_base, opq_base = analyze_branches(proj_base, main_base)
        br_max, z3_max, opq_max = analyze_branches(proj_max, main_max)

        # -------------------------------------------------------------
        # 3. Symbolic Trace & Solving Time
        # -------------------------------------------------------------
        def run_symbolic_trace(proj):
            sym = proj.loader.find_symbol('main')
            addr = sym.rebased_addr if sym else proj.entry
            st = proj.factory.call_state(addr, add_options={
                angr.options.SIMPLIFY_EXPRS,
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
            })
            sm = proj.factory.simulation_manager(st)
            steps = 0
            t0 = time.perf_counter()
            deadline = t0 + timeout
            timed_out = False
            
            while sm.active:
                if time.perf_counter() > deadline:
                    timed_out = True
                    break
                sm.step()
                steps += 1
                if len(sm.active) > 256:
                    sm.active = sm.active[:256]
            t1 = time.perf_counter()
            return steps, round(t1 - t0, 3), timed_out

        steps_base, time_base, to_base = run_symbolic_trace(proj_base)
        steps_max, time_max, to_max = run_symbolic_trace(proj_max)

        # -------------------------------------------------------------
        # Print Tabular Comparison
        # -------------------------------------------------------------
        print(f"{algo:<16} | {'Binary Code Size':<30} | {sz_base:>14,} B | {sz_max:>14,} B | {sz_max/sz_base:>16.2f}x")
        print(f"{'':<16} | {'Main Basic Blocks (BB)':<30} | {bb_base:>16} | {bb_max:>16} | {bb_max/max(1,bb_base):>16.2f}x")
        print(f"{'':<16} | {'Total CFG Edges':<30} | {edges_base:>16} | {edges_max:>16} | {edges_max/max(1,edges_base):>16.2f}x")
        print(f"{'':<16} | {'Cyclomatic Complexity V(G)':<30} | {cyc_base:>16} | {cyc_max:>16} | {cyc_max/max(1,cyc_base):>16.2f}x")
        print(f"{'':<16} | {'Opaque Predicate Analysis':<30} | {f'{br_base} br / {z3_base}s':>16} | {f'{br_max} br / {z3_max}s':>16} | {f'{z3_max/max(0.0001,z3_base):.1f}x solver cost'}")
        
        base_status = f"{time_base:.2f}s ({steps_base} st)"
        max_status = f"{'TIMEOUT' if to_max else f'{time_max:.2f}s'} ({steps_max} st)"
        time_ratio = f"{time_max/max(0.01,time_base):.2f}x" if not to_max else "INF (Timeout)"
        print(f"{'':<16} | {'Symbolic Trace / Solving':<30} | {base_status:>16} | {max_status:>16} | {time_ratio:>16}")
        print("-" * 120)

if __name__ == "__main__":
    algos = ["aes128_ecb", "sm4_ecb", "present_ecb", "tea_ecb", "md5", "des_ecb"]
    run_deobf_benchmark(algos, timeout=10.0)
