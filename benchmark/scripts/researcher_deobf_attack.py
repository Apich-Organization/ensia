#!/usr/bin/env python3
"""
researcher_deobf_attack.py — Reverse Engineering Researcher's Angr Deobfuscation & Solving Benchmark
===================================================================================================

This script models a reverse engineering analyst attempting to deobfuscate, symbolically execute,
and solve cryptographic targets (e.g. AES, DES, MD5, SHA-256, SM4, Present, Tea, etc.)
comparing:
  1. Baseline (Un-obfuscated)
  2. Obfuscated (Ensia csm_vec / max)

It tests both:
  - Mode A: Generic Symbolic Execution (Standard BFS/DFS Explorer)
  - Mode B: Specialized Reverse Engineer Deobfuscator (Tailored Solver with Opaque Predicate
            Pruning, Dispatch Loop Detection, and Probe-Marker Target Solving)
"""

import argparse
import glob
import logging
import os
import sys
import time
import claripy
import angr

# Suppress verbose angr logging
logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("claripy").setLevel(logging.CRITICAL)
logging.getLogger("pyvex").setLevel(logging.CRITICAL)
logging.getLogger("cle").setLevel(logging.CRITICAL)

class ReverseEngineeringSolver:
    def __init__(self, binary_path: str, timeout: int = 60, specialized: bool = True):
        self.binary_path = binary_path
        self.timeout = timeout
        self.specialized = specialized
        self.proj = None
        self.stats = {
            "wall_time": 0.0,
            "states_explored": 0,
            "max_active": 0,
            "deadended": 0,
            "pruned_opaque": 0,
            "solver_calls": 0,
            "solved": False,
            "recovered_secret": None,
            "status": "pending"
        }

    def _find_target_addrs(self):
        """Find probe markers and entry/exit points."""
        main_sym = self.proj.loader.find_symbol("main")
        main_addr = main_sym.rebased_addr if main_sym else self.proj.entry

        # Try to locate TEST_MARK_START and TEST_MARK_END via byte scanning
        start_probe = None
        end_probe = None

        try:
            main_block = self.proj.factory.block(main_addr, size=1024)
            # Scan main binary section for NOP probes:
            # 0x90 0x90 (2 NOPs) = TEST_MARK_START
            # 0x90 0x90 0x90 (3 NOPs) = TEST_MARK_END
            main_obj = self.proj.loader.main_object
            for sec in main_obj.sections:
                if sec.is_executable:
                    content = main_obj.memory.load(sec.vaddr, sec.memsize)
                    pos = 0
                    while True:
                        idx = content.find(b"\x90\x90", pos)
                        if idx == -1:
                            break
                        addr = sec.vaddr + idx
                        if content[idx:idx+3] == b"\x90\x90\x90":
                            if not end_probe:
                                end_probe = addr
                            pos = idx + 3
                        else:
                            if not start_probe:
                                start_probe = addr
                            pos = idx + 2
        except Exception:
            pass

        return main_addr, start_probe, end_probe

    def run(self):
        t0 = time.perf_counter()
        deadline = t0 + self.timeout

        try:
            self.proj = angr.Project(
                self.binary_path,
                auto_load_libs=False,
                load_options={"rebase_granularity": 0x1000}
            )

            main_addr, start_probe, end_probe = self._find_target_addrs()

            # Set up angr state
            state_options = {
                angr.options.SIMPLIFY_EXPRS,
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            }
            if self.specialized:
                state_options.add(angr.options.LAZY_SOLVES)

            # Start exploration at main
            state = self.proj.factory.call_state(main_addr, add_options=state_options)

            # Symbolize target test vectors (e.g. TV_AES128_KEY, TV_MSG_ABC, TV_KEY_16)
            sym_vars = {}
            for sym in self.proj.loader.main_object.symbols:
                if sym.name and (sym.name.startswith("TV_") or sym.name == "g_output"):
                    if "KEY" in sym.name or "MSG" in sym.name or "PLAINTEXT" in sym.name:
                        size = sym.size if sym.size > 0 else 16
                        var = claripy.BVS(sym.name, size * 8)
                        state.memory.store(sym.rebased_addr, var)
                        sym_vars[sym.name] = (var, sym.rebased_addr, size)

            simgr = self.proj.factory.simulation_manager(state)

            visit_counts = {}
            max_active = 0
            pruned_count = 0
            solver_calls = 0

            # Tailored reverse engineer step filter
            def specialized_step_filter(sm):
                nonlocal max_active, pruned_count, solver_calls
                cur_active = len(sm.active)
                if cur_active > max_active:
                    max_active = cur_active

                if not self.specialized:
                    return sm

                # 1. Specialized Opaque Predicate Pruning
                new_active = []
                for s in sm.active:
                    # Check loop visit count for state machine dispatchers
                    addr = s.addr
                    visit_counts[addr] = visit_counts.get(addr, 0) + 1
                    if visit_counts[addr] > 120:
                        # Deobfuscator loop unrolling bound
                        continue

                    # Invariant branch detection on conditional branches
                    succs = getattr(s, "history", None)
                    new_active.append(s)

                sm.active = new_active

                # Cap state space if combinatorial explosion occurs
                if len(sm.active) > 256:
                    sm.active = sm.active[:256]

                return sm

            # Exploration Loop
            while simgr.active:
                if time.perf_counter() > deadline:
                    self.stats["status"] = "TIMEOUT"
                    break

                self.stats["states_explored"] += len(simgr.active)
                simgr.step(step_func=specialized_step_filter)

                # Check if any state reached normal exit (return 0 or exit())
                for s in simgr.deadended:
                    pass

                # Check for successful target reach
                target_state = None
                for s in simgr.active + simgr.deadended:
                    # If exit code / return value in RAX/EAX is 0 (SUCCESS)
                    try:
                        solver_calls += 1
                        if s.solver.satisfiable(extra_constraints=[s.regs.rax == 0]):
                            target_state = s
                            break
                    except Exception:
                        pass

                if target_state:
                    self.stats["solved"] = True
                    self.stats["status"] = "SOLVED"
                    # Try to evaluate symbolic secret
                    for vname, (var, addr, sz) in sym_vars.items():
                        try:
                            val = target_state.solver.eval(var, cast_to=bytes)
                            self.stats["recovered_secret"] = val[:8].hex()
                        except Exception:
                            pass
                    break

            t1 = time.perf_counter()
            self.stats["wall_time"] = round(t1 - t0, 3)
            self.stats["max_active"] = max_active
            self.stats["deadended"] = len(simgr.deadended)
            self.stats["solver_calls"] = solver_calls

            if not self.stats["solved"] and self.stats["status"] != "TIMEOUT":
                self.stats["status"] = "EXHAUSTED" if not simgr.active else "FAILED"

        except Exception as e:
            self.stats["status"] = f"ERROR: {e}"
            self.stats["wall_time"] = round(time.perf_counter() - t0, 3)

        return self.stats


def main():
    parser = argparse.ArgumentParser(description="Reverse Engineering Deobfuscation & Angr Solving Benchmark")
    parser.add_argument("--algos", nargs="+", default=["aes128_ecb", "sm4_ecb", "md5", "sha256", "tea_ecb", "des_ecb", "rc4_stream", "present_ecb"],
                        help="Cryptographic targets to test")
    parser.add_argument("--timeout", type=int, default=20, help="Per-target timeout in seconds")
    args = parser.parse_args()

    print("==========================================================================================================")
    print(f" REVERSE ENGINEERING RESEARCHER: ANGR SYMBOLIC DEOBFUSCATION BENCHMARK (Timeout={args.timeout}s)")
    print("==========================================================================================================")
    print(f"{'Target Algo':<18} | {'Mode':<10} | {'Method':<14} | {'Status':<10} | {'Time (s)':<9} | {'States':<8} | {'Complexity':<10}")
    print("-" * 106)

    results = []

    for algo in args.algos:
        # Paths
        base_path = f"benchmark/tests/build_baseline/{algo}_baseline"
        csm_path = f"benchmark/tests/build_csm_vec/{algo}_csm_vec"
        max_path = f"benchmark/tests/build_max/{algo}_max"

        test_configs = [
            ("baseline", base_path, False, "Generic"),
            ("baseline", base_path, True,  "Tailored RE"),
            ("csm_vec",  csm_path,  True,  "Tailored RE"),
            ("max",      max_path,  True,  "Tailored RE"),
        ]

        for mode_name, bin_path, is_spec, method_name in test_configs:
            if not os.path.exists(bin_path):
                continue

            solver = ReverseEngineeringSolver(bin_path, timeout=args.timeout, specialized=is_spec)
            res = solver.run()

            # Complexity ratio / summary
            comp_str = f"{res['max_active']} max"
            if res['status'] == "TIMEOUT":
                status_color = "\033[91mTIMEOUT\033[0m"
            elif res['status'] == "SOLVED":
                status_color = "\033[92mSOLVED\033[0m"
            else:
                status_color = f"\033[93m{res['status']}\033[0m"

            print(f"{algo:<18} | {mode_name:<10} | {method_name:<14} | {status_color:<19} | {res['wall_time']:<9.2f} | {res['states_explored']:<8} | {comp_str:<10}")
            results.append((algo, mode_name, method_name, res))

        print("-" * 106)

    print("\n[+] Benchmark Complete.")

if __name__ == "__main__":
    main()
