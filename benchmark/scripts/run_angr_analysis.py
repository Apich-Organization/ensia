#!/usr/bin/env python3
"""
run_angr_analysis.py — Ensia Obfuscator Benchmark: Enhanced angr Symbolic Execution Analysis
====================================================================================

Key enhancements:
  - Multiprocessing pool (--jobs / -j): parallel analysis across multiple CPU cores
  - Per-process isolation: eliminates angr/claripy AST memory leaks and prevents worker crashes from affecting parent
  - Granular timeout management: exploration deadline and optional per-query solver timeout
  - Resume support (--resume): skips already completed target binaries
  - Target filtering (--algo, --filter): run single algorithm or subset pattern
  - Visited basic blocks and state complexity tracking
  - Clean error logging and suppression of benign engine notices

Metrics collected per (algorithm, mode) pair:
  - wall_clock_time   : seconds from SimMgr init to termination
  - peak_memory_rss   : peak RSS in MiB (sampled via /proc/self/status)
  - max_active_states : maximum number of active states observed during exploration
  - deadended_states  : states that reached exit normally
  - found_states      : states matching the target (exit addr)
  - unresolved_branches: states in simgr.unsat + simgr.avoid + simgr.errored
  - z3_timeout_count  : number of Z3 solver timeouts (hooked via claripy)
  - z3_solver_calls   : total Z3 solver queries executed
  - visited_blocks    : unique basic block entry addresses reached during exploration
  - status            : "ok" | "timeout" | "error:<msg>"

Usage:
    python3 run_angr_analysis.py \\
        --build-dir /path/to/build_baseline \\
        --mode baseline \\
        --timeout 60 \\
        --jobs 4 \\
        --output results/angr_baseline.csv
"""

import argparse
import concurrent.futures
import csv
import fnmatch
import gc
import glob
import logging
import multiprocessing
import os
import signal
import sys
import threading
import time
import warnings

# Suppress benign engine warnings
warnings.filterwarnings("ignore")
logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("claripy").setLevel(logging.ERROR)
logging.getLogger("pyvex").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)
logging.getLogger("angr.calling_conventions").setLevel(logging.ERROR)
logging.getLogger("angr.state_plugins.unicorn_engine").setLevel(logging.CRITICAL)

# ---------------------------------------------------------------------------
# Dependency guard
# ---------------------------------------------------------------------------
try:
    import angr
    try:
        import claripy
    except ImportError:
        from angr import claripy
    import psutil
except ImportError as e:
    print(f"[ERROR] Missing dependency: {e}")
    print("Install with:  pip install angr psutil")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_TIMEOUT = 60    # seconds
DEFAULT_MAX_STATES = 64
CSV_FIELDNAMES = [
    "algo", "mode", "binary",
    "wall_time_s", "peak_mem_mib",
    "max_active_states", "deadended_states",
    "found_states", "unresolved_branches",
    "z3_timeout_count", "z3_solver_calls",
    "visited_blocks",
    "status"            # "ok" | "timeout" | "error:<msg>"
]

# ---------------------------------------------------------------------------
# Z3 timeout counter hook
# ---------------------------------------------------------------------------
class Z3Counter:
    """Monkey-patches claripy.backends.z3 to count timeouts and calls."""
    def __init__(self):
        self.calls = 0
        self.timeouts = 0
        self._orig_solve = None
        self._patched = False

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
                    exc_str = str(exc).lower()
                    exc_cls = type(exc).__name__.lower()
                    if "timeout" in exc_str or "z3exception" in exc_cls:
                        counter.timeouts += 1
                    raise
            bz3.BackendZ3._solve_expr = patched_solve
            self._patched = True
        except Exception:
            pass  # graceful degradation

    def reset(self):
        self.calls = 0
        self.timeouts = 0


# ---------------------------------------------------------------------------
# Memory sampler
# ---------------------------------------------------------------------------
class MemorySampler(threading.Thread):
    """Background thread that samples RSS every 0.25 s."""
    def __init__(self, pid=None):
        super().__init__(daemon=True)
        self.pid = pid or os.getpid()
        self.peak_mib = 0.0
        self._stop = threading.Event()

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
                self._stop.wait(0.25)
        except Exception:
            pass

    def stop(self):
        self._stop.set()


# ---------------------------------------------------------------------------
# Core analysis worker function (isolated execution)
# ---------------------------------------------------------------------------
def _worker_analyse_binary(binary_path: str, timeout: int, max_states: int) -> dict:
    """
    Run angr symbolic execution on a single benchmark binary in a worker process.
    Returns a dict with metric fields.
    """
    try:
        import z3
        z3.set_param("timeout", min(5000, max(1000, timeout * 250)))
    except Exception:
        pass

    z3_counter = Z3Counter()
    z3_counter.attach()
    z3_counter.reset()
    gc.collect()

    mem_sampler = MemorySampler()
    mem_sampler.start()

    result = {
        "wall_time_s": 0.0,
        "peak_mem_mib": 0.0,
        "max_active_states": 0,
        "deadended_states": 0,
        "found_states": 0,
        "unresolved_branches": 0,
        "z3_timeout_count": 0,
        "z3_solver_calls": 0,
        "visited_blocks": 0,
        "status": "ok",
    }

    visited_addrs = set()
    t0 = time.perf_counter()

    def sig_handler(signum, frame):
        raise TimeoutError("Per-binary timeout reached")

    signal.signal(signal.SIGALRM, sig_handler)
    signal.alarm(max(1, timeout))

    try:
        # Load project
        proj = angr.Project(
            binary_path,
            auto_load_libs=False,
            load_options={"rebase_granularity": 0x1000},
        )

        # Find entry point
        main_addr = None
        for sym_name in ("main", "_main", "__main"):
            sym = proj.loader.find_symbol(sym_name)
            if sym is not None:
                main_addr = sym.rebased_addr
                break
        if main_addr is None:
            main_addr = proj.entry

        # Find exit addresses
        exit_addrs = []
        for sym_name in ("exit", "_exit", "__exit", "abort"):
            sym = proj.loader.find_symbol(sym_name)
            if sym:
                exit_addrs.append(sym.rebased_addr)

        # Initialize simulation state
        state = proj.factory.call_state(
            main_addr,
            add_options={
                angr.options.SIMPLIFY_EXPRS,
                angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
            }
        )

        # Symbolize test vectors if present (limit to 16 bytes for bounded exploration)
        for sym in proj.loader.main_object.symbols:
            if sym.name and sym.name.startswith("TV_"):
                sym_size = min(sym.size if sym.size > 0 else 16, 16)
                sym_var = claripy.BVS(sym.name, sym_size * 8)
                state.memory.store(sym.rebased_addr, sym_var)

        simgr = proj.factory.simulation_manager(state)

        timed_out = False
        max_active = 0
        deadline = t0 + timeout

        def exploration_step(simgr_inner):
            nonlocal max_active, timed_out
            active_count = len(simgr_inner.active)
            if active_count > max_active:
                max_active = active_count

            for s in simgr_inner.active:
                visited_addrs.add(s.addr)

            # Check timeout or memory threshold (1 GB RSS limit)
            if time.perf_counter() > deadline or mem_sampler.peak_mib > 1024.0:
                timed_out = True
                simgr_inner.active.clear()
                return simgr_inner

            if active_count > max_states:
                # Cap combinatorial explosion to limit runaway state proliferation
                simgr_inner.active = simgr_inner.active[:max_states]
            return simgr_inner

        while simgr.active:
            if time.perf_counter() > deadline:
                timed_out = True
                result["status"] = "timeout"
                break

            simgr.step(step_func=exploration_step)

            # Move exit states to deadended
            if exit_addrs:
                simgr.move(
                    from_stash="active",
                    to_stash="deadended",
                    filter_func=lambda s: s.addr in exit_addrs
                )

        t1 = time.perf_counter()
        result["wall_time_s"] = round(t1 - t0, 3)
        result["max_active_states"] = max_active
        result["deadended_states"] = len(simgr.deadended)
        result["found_states"] = len(getattr(simgr, "found", []))
        result["unresolved_branches"] = (
            len(getattr(simgr, "unsat", [])) +
            len(getattr(simgr, "avoid", [])) +
            len(getattr(simgr, "errored", []))
        )
        result["visited_blocks"] = len(visited_addrs)

        if not timed_out:
            result["status"] = "ok"

    except TimeoutError:
        t1 = time.perf_counter()
        result["wall_time_s"] = round(t1 - t0, 3)
        result["status"] = "timeout"
        result["visited_blocks"] = len(visited_addrs)
    except Exception as exc:
        t1 = time.perf_counter()
        result["wall_time_s"] = round(t1 - t0, 3)
        result["status"] = f"error:{type(exc).__name__}:{str(exc)[:80]}"
        result["visited_blocks"] = len(visited_addrs)

    finally:
        signal.alarm(0)
        mem_sampler.stop()
        mem_sampler.join(timeout=1.0)
        result["peak_mem_mib"] = round(mem_sampler.peak_mib, 2)
        result["z3_timeout_count"] = z3_counter.timeouts
        result["z3_solver_calls"] = z3_counter.calls

    return result


def _proc_target(entry: dict, mode: str, timeout: int, max_states: int, conn) -> None:
    """Worker target executed in a separate process."""
    try:
        res = _worker_analyse_binary(entry["binary"], timeout, max_states)
        conn.send(res)
    except Exception as exc:
        conn.send({"status": f"worker_error:{type(exc).__name__}:{str(exc)[:60]}", "wall_time_s": 0.0})
    finally:
        conn.close()


def run_target_isolated(entry: dict, mode: str, timeout: int, max_states: int) -> dict:
    """Runs binary analysis in a dedicated subprocess with hard kernel kill timeout."""
    parent_conn, child_conn = multiprocessing.Pipe(duplex=False)
    p = multiprocessing.Process(target=_proc_target, args=(entry, mode, timeout, max_states, child_conn))
    t0 = time.perf_counter()
    p.start()
    child_conn.close()

    # Wait up to timeout + 1 seconds
    p.join(timeout=timeout + 1)
    wall_time = round(time.perf_counter() - t0, 3)

    if p.is_alive():
        # Forceful kernel kill
        p.kill()
        p.join(timeout=1.0)
        parent_conn.close()
        return {
            "algo": entry["algo"],
            "mode": mode,
            "binary": entry["binary"],
            "wall_time_s": wall_time,
            "peak_mem_mib": 0.0,
            "max_active_states": 0,
            "deadended_states": 0,
            "found_states": 0,
            "unresolved_branches": 0,
            "z3_timeout_count": 0,
            "z3_solver_calls": 0,
            "visited_blocks": 0,
            "status": "timeout",
        }

    metrics = None
    try:
        if parent_conn.poll(0.5):
            metrics = parent_conn.recv()
    except Exception:
        pass
    finally:
        parent_conn.close()

    if metrics is None:
        metrics = {
            "wall_time_s": wall_time,
            "peak_mem_mib": 0.0,
            "max_active_states": 0,
            "deadended_states": 0,
            "found_states": 0,
            "unresolved_branches": 0,
            "z3_timeout_count": 0,
            "z3_solver_calls": 0,
            "visited_blocks": 0,
            "status": "error:process_exited",
        }

    return {
        "algo": entry["algo"],
        "mode": mode,
        "binary": entry["binary"],
        **metrics,
    }


# ---------------------------------------------------------------------------
# Binary discovery
# ---------------------------------------------------------------------------
def discover_binaries(
    build_dir: str,
    mode: str,
    skip_size_only: bool,
    filter_pattern: str = None,
    algo_list: list[str] = None
) -> list[dict]:
    """Find all benchmark binaries in build_dir matching *_<mode>."""
    pattern = os.path.join(build_dir, f"*_{mode}")
    entries = []

    for binary in sorted(glob.glob(pattern)):
        if not os.access(binary, os.X_OK):
            continue
        meta_path = binary + ".meta"
        algo = os.path.basename(binary)[: -len(f"_{mode}")]
        size_only = False

        if os.path.exists(meta_path):
            with open(meta_path) as f:
                for token in f.read().split():
                    if token.startswith("size_only="):
                        size_only = token.split("=")[1].strip().lower() in ("on", "1", "true")

        if skip_size_only and size_only:
            continue

        if filter_pattern and not fnmatch.fnmatch(algo, filter_pattern):
            continue

        if algo_list and algo not in algo_list:
            continue

        entries.append({"algo": algo, "binary": binary, "size_only": size_only})

    return entries


def load_completed_algos(csv_path: str, mode: str) -> set[str]:
    """Load algorithms that have already completed in the CSV."""
    if not os.path.exists(csv_path):
        return set()
    completed = set()
    try:
        with open(csv_path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("mode") == mode and row.get("algo"):
                    completed.add(row["algo"])
    except Exception:
        pass
    return completed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Ensia benchmark angr analysis (Enhanced)")
    ap.add_argument("--build-dir", required=True, help="CMake build directory")
    ap.add_argument("--mode", default="baseline",
                    choices=["baseline", "csm_only", "vec_only", "csm_vec", "bench_max", "max"])
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                    help=f"Per-binary timeout in seconds (default: {DEFAULT_TIMEOUT})")
    ap.add_argument("--jobs", "-j", type=int, default=1,
                    help="Parallel workers (default: 1; use 0 or nproc for CPU count)")
    ap.add_argument("--max-states", type=int, default=DEFAULT_MAX_STATES,
                    help=f"Max state cap to prevent explosion (default: {DEFAULT_MAX_STATES})")
    ap.add_argument("--output", default="angr_results.csv",
                    help="Output CSV file path")
    ap.add_argument("--skip-size-only", action="store_true",
                    help="Skip ECC/PKC/PQC binaries marked size_only")
    ap.add_argument("--binary", default=None,
                    help="Analyse a single binary instead of discovering all")
    ap.add_argument("--algo", default=None,
                    help="Comma-separated list of target algorithms")
    ap.add_argument("--filter", default=None,
                    help="Wildcard filter for algorithm names (e.g. 'aes*', '*sha*')")
    ap.add_argument("--resume", action="store_true",
                    help="Resume run and skip already processed algorithms in output CSV")
    args = ap.parse_args()

    # Normalise mode alias
    canonical_mode = "bench_max" if args.mode == "max" else args.mode

    jobs = args.jobs
    if jobs <= 0:
        jobs = os.cpu_count() or 4

    os.makedirs(os.path.dirname(os.path.abspath(args.output)) or ".", exist_ok=True)

    algo_list = [a.strip() for a in args.algo.split(",")] if args.algo else None

    # Discover binaries
    if args.binary:
        algo = os.path.basename(args.binary).replace(f"_{args.mode}", "").replace(f"_{canonical_mode}", "")
        entries = [{"algo": algo, "binary": args.binary, "size_only": False}]
    else:
        entries = discover_binaries(
            args.build_dir,
            canonical_mode,
            args.skip_size_only,
            filter_pattern=args.filter,
            algo_list=algo_list,
        )
        if not entries and canonical_mode == "bench_max":
            # Fallback to check _max suffix
            entries = discover_binaries(
                args.build_dir,
                "max",
                args.skip_size_only,
                filter_pattern=args.filter,
                algo_list=algo_list,
            )

    if not entries:
        print(f"[WARNING] No binaries found in {args.build_dir} for mode '{args.mode}'")
        sys.exit(1)

    completed_algos = set()
    write_header = True
    if args.resume and os.path.exists(args.output):
        completed_algos = load_completed_algos(args.output, canonical_mode)
        write_header = False
        remaining = [e for e in entries if e["algo"] not in completed_algos]
        print(f"[*] Resuming: {len(completed_algos)} algorithms already completed, {len(remaining)} remaining.")
        entries = remaining

    print(f"\n{'='*72}")
    print(f"  Ensia angr Analysis (Enhanced)")
    print(f"  Obfuscation Mode    : {canonical_mode}")
    print(f"  Timeout per binary  : {args.timeout}s")
    print(f"  Parallel workers    : {jobs}")
    print(f"  Binaries to analyse : {len(entries)}")
    print(f"  Output CSV          : {args.output}")
    print(f"{'='*72}\n")

    if not entries:
        print("[*] All targets are already analyzed.")
        return

    # Open CSV for streaming writes
    file_mode = "a" if (args.resume and not write_header) else "w"
    csvfile = open(args.output, file_mode, newline="")
    writer = csv.DictWriter(csvfile, fieldnames=CSV_FIELDNAMES)
    if write_header:
        writer.writeheader()
        csvfile.flush()

    total = len(entries)
    completed_count = 0

    try:
        if jobs == 1:
            for i, entry in enumerate(entries, 1):
                algo = entry["algo"]
                print(f"[{i:3d}/{total}] {algo:30s} ... ", end="", flush=True)
                row = run_target_isolated(entry, canonical_mode, args.timeout, args.max_states)
                writer.writerow(row)
                csvfile.flush()
                completed_count += 1

                status = row["status"]
                t = row["wall_time_s"]
                states = row["max_active_states"]
                blocks = row["visited_blocks"]
                z3t = row["z3_timeout_count"]
                print(f"  {status:10s}  t={t:6.2f}s  states={states:4d}  blocks={blocks:4d}  z3_to={z3t:2d}")
        else:
            print(f"[*] Spawning {jobs} parallel worker processes...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as executor:
                future_to_entry = {
                    executor.submit(
                        run_target_isolated, entry, canonical_mode, args.timeout, args.max_states
                    ): entry for entry in entries
                }

                for future in concurrent.futures.as_completed(future_to_entry):
                    entry = future_to_entry[future]
                    algo = entry["algo"]
                    completed_count += 1
                    try:
                        row = future.result()
                    except Exception as e:
                        row = {
                            "algo": algo,
                            "mode": canonical_mode,
                            "binary": entry["binary"],
                            "wall_time_s": 0.0,
                            "peak_mem_mib": 0.0,
                            "max_active_states": 0,
                            "deadended_states": 0,
                            "found_states": 0,
                            "unresolved_branches": 0,
                            "z3_timeout_count": 0,
                            "z3_solver_calls": 0,
                            "visited_blocks": 0,
                            "status": f"worker_error:{type(e).__name__}",
                        }

                    writer.writerow(row)
                    csvfile.flush()

                    status = row["status"]
                    t = row["wall_time_s"]
                    states = row["max_active_states"]
                    blocks = row["visited_blocks"]
                    z3t = row["z3_timeout_count"]
                    print(f"[{completed_count:3d}/{total}] {algo:30s}  {status:10s}  t={t:6.2f}s  states={states:4d}  blocks={blocks:4d}  z3_to={z3t:2d}")

    finally:
        csvfile.close()

    print(f"\n[DONE] Completed {completed_count}/{total} targets. Results written to: {args.output}")


if __name__ == "__main__":
    main()
