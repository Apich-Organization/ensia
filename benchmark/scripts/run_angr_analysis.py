#!/usr/bin/env python3
"""
run_angr_analysis.py — Ensia Obfuscator Benchmark: angr Symbolic Execution Analysis
====================================================================================

Metrics collected per (algorithm, mode) pair:
  - wall_clock_time   : seconds from SimMgr init to termination
  - peak_memory_rss   : peak RSS in MiB (sampled via /proc/self/status)
  - max_active_states : maximum number of active states observed during exploration
  - deadended_states  : states that reached exit normally
  - found_states      : states matching the target (exit addr)
  - unresolved_branches: states in simgr.unsat + simgr.avoid + simgr.errored
  - z3_timeout_count  : number of Z3 solver timeouts (hooked via claripy)

Output: CSV with one row per binary.

Usage:
    python3 run_angr_analysis.py \\
        --build-dir /path/to/build_baseline \\
        --mode baseline \\
        --timeout 600 \\
        --output results/angr_baseline.csv \\
        [--skip-size-only]

    # Analyse all modes at once:
    for mode in baseline csm_only vec_only csm_vec max; do
        python3 run_angr_analysis.py \\
            --build-dir /path/to/build_${mode} \\
            --mode ${mode} \\
            --output results/angr_${mode}.csv
    done
"""

import argparse
import csv
import gc
import os
import resource
import signal
import subprocess
import sys
import time
import threading
import glob
import logging

logging.getLogger('angr.calling_conventions').setLevel(logging.ERROR)

# ---------------------------------------------------------------------------
# Dependency guard
# ---------------------------------------------------------------------------
try:
    import angr
    import claripy
    import psutil
except ImportError as e:
    print(f"[ERROR] Missing dependency: {e}")
    print("Install with:  pip install angr psutil")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_TIMEOUT  = 600   # seconds
CSV_FIELDNAMES   = [
    "algo", "mode", "binary",
    "wall_time_s", "peak_mem_mib",
    "max_active_states", "deadended_states",
    "found_states", "unresolved_branches",
    "z3_timeout_count", "z3_solver_calls",
    "status"            # "ok" | "timeout" | "error:<msg>"
]

# ---------------------------------------------------------------------------
# Z3 timeout counter hook
# ---------------------------------------------------------------------------
class Z3Counter:
    """Monkey-patches claripy.backends.z3 to count timeouts and calls."""
    def __init__(self):
        self.calls    = 0
        self.timeouts = 0
        self._orig_solve = None
        self._patched    = False

    def attach(self):
        """Patch claripy solver backend."""
        try:
            import claripy.backends.backend_z3 as bz3
            orig = bz3.BackendZ3._solve_expr
            counter = self

            def patched_solve(self_b, *args, **kwargs):
                counter.calls += 1
                try:
                    return orig(self_b, *args, **kwargs)
                except Exception as exc:
                    if "timeout" in str(exc).lower() or "z3exception" in type(exc).__name__.lower():
                        counter.timeouts += 1
                    raise
            bz3.BackendZ3._solve_expr = patched_solve
            self._patched = True
        except Exception:
            pass  # graceful degradation

    def reset(self):
        self.calls    = 0
        self.timeouts = 0


# ---------------------------------------------------------------------------
# Memory sampler
# ---------------------------------------------------------------------------
class MemorySampler(threading.Thread):
    """Background thread that samples RSS every 0.5 s."""
    def __init__(self, pid=None):
        super().__init__(daemon=True)
        self.pid      = pid or os.getpid()
        self.peak_mib = 0.0
        self._stop    = threading.Event()

    def run(self):
        try:
            proc = psutil.Process(self.pid)
            while not self._stop.is_set():
                try:
                    rss = proc.memory_info().rss / (1024 * 1024)
                    if rss > self.peak_mib:
                        self.peak_mib = rss
                except psutil.NoSuchProcess:
                    break
                self._stop.wait(0.5)
        except Exception:
            pass

    def stop(self):
        self._stop.set()


# ---------------------------------------------------------------------------
# Core analysis function
# ---------------------------------------------------------------------------
def analyse_binary(binary_path: str, timeout: int, z3_counter: Z3Counter) -> dict:
    """
    Run angr symbolic execution on a single benchmark binary.

    Returns a dict with all metric fields.
    """
    z3_counter.reset()
    gc.collect()

    mem_sampler = MemorySampler()
    mem_sampler.start()

    result = {
        "wall_time_s"       : 0.0,
        "peak_mem_mib"      : 0.0,
        "max_active_states" : 0,
        "deadended_states"  : 0,
        "found_states"      : 0,
        "unresolved_branches": 0,
        "z3_timeout_count"  : 0,
        "z3_solver_calls"   : 0,
        "status"            : "ok",
    }

    t0 = time.perf_counter()

    try:
        # ── Load project ──────────────────────────────────────────────────
        proj = angr.Project(
            binary_path,
            auto_load_libs=False,          # no dynamic libs needed
            load_options={"rebase_granularity": 0x1000},
        )

        # Find main() entry address
        main_addr = None
        for sym_name in ("main", "_main", "__main"):
            sym = proj.loader.find_symbol(sym_name)
            if sym is not None:
                main_addr = sym.rebased_addr
                break
        if main_addr is None:
            # Fall back to entry point
            main_addr = proj.entry

        # Find exit addresses (libc exit / _exit)
        exit_addrs = []
        for sym_name in ("exit", "_exit", "__exit", "abort"):
            sym = proj.loader.find_symbol(sym_name)
            if sym:
                exit_addrs.append(sym.rebased_addr)

        # ── Set up SimulationManager ──────────────────────────────────────
        state = proj.factory.call_state(
            main_addr,
            add_options={
                angr.options.SIMPLIFY_EXPRS,
            }
        )

        # Make test vectors symbolic so angr actually explores states
        for sym in proj.loader.main_object.symbols:
            if sym.name and sym.name.startswith("TV_"):
                sym_size = sym.size if sym.size > 0 else 16
                sym_var = claripy.BVS(sym.name, sym_size * 8)
                state.memory.store(sym.rebased_addr, sym_var)

        simgr = proj.factory.simulation_manager(state)

        # ── Exploration loop with timeout ─────────────────────────────────
        timed_out    = False
        max_active   = 0

        def exploration_step(simgr_inner):
            nonlocal max_active
            active_count = len(simgr_inner.active)
            if active_count > max_active:
                max_active = active_count
            # Hard cap: prevent combinatorial explosion beyond 4096 states
            if active_count > 4096:
                # Prune to most recently created states
                simgr_inner.active = simgr_inner.active[:4096]
            return simgr_inner

        deadline = t0 + timeout

        while simgr.active:
            if time.perf_counter() > deadline:
                timed_out = True
                result["status"] = "timeout"
                break
            simgr.step(step_func=exploration_step)
            # Also move to deadended any state that called exit()
            if exit_addrs:
                simgr.move(
                    from_stash="active",
                    to_stash="deadended",
                    filter_func=lambda s: s.addr in exit_addrs
                )

        t1 = time.perf_counter()

        # ── Collect metrics ───────────────────────────────────────────────
        result["wall_time_s"]        = round(t1 - t0, 3)
        result["max_active_states"]  = max_active
        result["deadended_states"]   = len(simgr.deadended)
        result["found_states"]       = len(getattr(simgr, "found", []))
        result["unresolved_branches"] = (
            len(getattr(simgr, "unsat",    [])) +
            len(getattr(simgr, "avoid",    [])) +
            len(getattr(simgr, "errored",  []))
        )

        if not timed_out:
            result["status"] = "ok"

    except Exception as exc:
        t1 = time.perf_counter()
        result["wall_time_s"] = round(t1 - t0, 3)
        result["status"]      = f"error:{type(exc).__name__}:{str(exc)[:120]}"

    finally:
        mem_sampler.stop()
        mem_sampler.join(timeout=2.0)
        result["peak_mem_mib"]     = round(mem_sampler.peak_mib, 2)
        result["z3_timeout_count"] = z3_counter.timeouts
        result["z3_solver_calls"]  = z3_counter.calls

    return result


# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------
def discover_binaries(build_dir: str, mode: str, skip_size_only: bool) -> list[dict]:
    """
    Find all benchmark binaries in build_dir matching *_<mode>.
    Reads the companion .meta file to determine if SIZE_ONLY.
    """
    pattern = os.path.join(build_dir, f"*_{mode}")
    entries = []

    for binary in sorted(glob.glob(pattern)):
        if not os.access(binary, os.X_OK):
            continue
        meta_path = binary + ".meta"
        algo      = os.path.basename(binary)[: -len(f"_{mode}")]
        size_only = False

        if os.path.exists(meta_path):
            with open(meta_path) as f:
                for token in f.read().split():
                    if token.startswith("size_only="):
                        size_only = token.split("=")[1].strip().lower() in ("on", "1", "true")

        if skip_size_only and size_only:
            print(f"  [SKIP size_only] {algo}")
            continue

        entries.append({"algo": algo, "binary": binary, "size_only": size_only})

    return entries


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Ensia benchmark angr analysis")
    ap.add_argument("--build-dir",     required=True, help="CMake build directory")
    ap.add_argument("--mode",          default="baseline",
                    choices=["baseline", "csm_only", "vec_only", "csm_vec", "bench_max"])
    ap.add_argument("--timeout",       type=int, default=DEFAULT_TIMEOUT,
                    help=f"Per-binary timeout in seconds (default: {DEFAULT_TIMEOUT})")
    ap.add_argument("--output",        default="angr_results.csv",
                    help="Output CSV file path")
    ap.add_argument("--skip-size-only", action="store_true",
                    help="Skip ECC/PKC/PQC binaries marked size_only")
    ap.add_argument("--binary",        default=None,
                    help="Analyse a single binary instead of discovering all")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)

    # Attach Z3 counter
    z3_counter = Z3Counter()
    z3_counter.attach()

    # Discover binaries
    if args.binary:
        algo = os.path.basename(args.binary).replace(f"_{args.mode}", "")
        entries = [{"algo": algo, "binary": args.binary, "size_only": False}]
    else:
        entries = discover_binaries(args.build_dir, args.mode, args.skip_size_only)

    if not entries:
        print(f"[WARNING] No binaries found in {args.build_dir} for mode '{args.mode}'")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  Ensia angr Analysis — mode: {args.mode}")
    print(f"  Timeout per binary : {args.timeout}s")
    print(f"  Binaries to analyse: {len(entries)}")
    print(f"  Output             : {args.output}")
    print(f"{'='*60}\n")

    # Write CSV
    with open(args.output, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()

        for i, entry in enumerate(entries, 1):
            algo   = entry["algo"]
            binary = entry["binary"]
            print(f"[{i:3d}/{len(entries)}] {algo:30s} ... ", end="", flush=True)

            metrics = analyse_binary(binary, args.timeout, z3_counter)
            row = {
                "algo"   : algo,
                "mode"   : args.mode,
                "binary" : binary,
                **metrics,
            }
            writer.writerow(row)
            csvfile.flush()

            status = metrics["status"]
            t      = metrics["wall_time_s"]
            states = metrics["max_active_states"]
            z3t    = metrics["z3_timeout_count"]
            print(f"  {status:12s}  t={t:7.2f}s  states={states:5d}  z3_to={z3t:4d}")

    print(f"\n[DONE] Results written to: {args.output}")


if __name__ == "__main__":
    main()
