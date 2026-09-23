#!/usr/bin/env python3
"""
Symbolic Execution Resilience Evaluation Harness (angr / claripy / Z3).
Tests how symbolic solvers perform against individual passes and combinations.
"""

import os
import sys
import subprocess
import json
import time
from pathlib import Path
import warnings
warnings.filterwarnings("ignore")

import angr
from angr import claripy

WORKSPACE = Path("/home/user/dev/ensia")
EVAL_DIR = WORKSPACE / "independent_eval"
WORKLOADS_DIR = EVAL_DIR / "workloads"
RESULTS_DIR = EVAL_DIR / "results"
PLUGIN_SO = WORKSPACE / "build" / "obfuscation" / "libEnsia.so"

CRACKME_SRC = WORKLOADS_DIR / "target_crackme.c"

TEST_PASSES = [
    {"id": "BASELINE", "env": {}, "desc": "Unobfuscated Baseline"},
    {"id": "SUBOBF", "env": {"SUB": "1"}, "desc": "Instruction Substitution"},
    {"id": "MBAOBF", "env": {"MBA": "1"}, "desc": "Mixed Boolean-Arithmetic"},
    {"id": "BCFOBF", "env": {"BCF": "1"}, "desc": "Bogus Control Flow"},
    {"id": "CFFOBF", "env": {"CFF": "1"}, "desc": "Control Flow Flattening"},
    {"id": "CSMOBF", "env": {"CSM": "1"}, "desc": "Chaos State Machine"},
    {"id": "VOBF", "env": {"VOBF": "1"}, "desc": "Vector Obfuscation"},
    {"id": "CONSTENC", "env": {"CONSTENC": "1"}, "desc": "Constant Encryption"},
    {"id": "PRESET_LOW", "env": {"ENSIA_PRESET": "low"}, "desc": "Low Preset"},
    {"id": "PRESET_MID", "env": {"ENSIA_PRESET": "mid"}, "desc": "Mid Preset"},
    {"id": "PRESET_HIGH", "env": {"ENSIA_PRESET": "high"}, "desc": "High Preset"},
]

TIMEOUT_SECONDS = 60

def compile_crackme(pass_id, env_vars):
    """Compile target_crackme with the given pass configuration."""
    bin_path = RESULTS_DIR / f"symbolic_crackme_{pass_id}.bin"
    run_env = os.environ.copy()
    if not pass_id.startswith("PRESET_"):
        run_env["ENSIA_CONFIG"] = str(EVAL_DIR / "empty.toml")
    run_env.update(env_vars)

    cmd = [
        "clang",
        f"-fpass-plugin={PLUGIN_SO}",
        "-O1",
        str(CRACKME_SRC),
        "-o", str(bin_path)
    ]
    res = subprocess.run(cmd, env=run_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        print(f"  [-] Compilation failed for {pass_id}: {res.stderr[:200]}")
        return None
    return bin_path

def evaluate_symbolic_execution(bin_path, pass_id):
    """Run angr symbolic execution on bin_path to solve for 8-byte key."""
    print(f"\n[+] Running angr Symbolic Execution on {pass_id} (timeout={TIMEOUT_SECONDS}s)...")
    t0 = time.time()

    try:
        # Load binary in angr without debug symbols
        proj = angr.Project(str(bin_path), auto_load_libs=False)

        # Create 8-byte symbolic argument
        sym_key = claripy.BVS("sym_key", 8 * 8)
        # Constrain to printable ASCII
        constraints = []
        for i in range(8):
            byte = sym_key.get_byte(i)
            constraints.append(byte >= 0x20)
            constraints.append(byte <= 0x7E)

        # Initialize entry state with argv[1] = sym_key
        state = proj.factory.entry_state(args=[str(bin_path), sym_key])
        for c in constraints:
            state.solver.add(c)

        sm = proj.factory.simulation_manager(state)

        # Look for "KEY_VALID: SUCCESS!"
        # Avoid "KEY_INVALID: FAIL!"
        target_str = b"KEY_VALID"
        avoid_str = b"KEY_INVALID"

        def is_successful(s):
            return target_str in s.posix.dumps(1)

        def should_avoid(s):
            return avoid_str in s.posix.dumps(1)

        states_explored = 0
        peak_active = 0
        timed_out = False

        while len(sm.active) > 0:
            if time.time() - t0 > TIMEOUT_SECONDS:
                timed_out = True
                break

            peak_active = max(peak_active, len(sm.active))
            states_explored += len(sm.active)

            # Step forward
            sm.step()

            # Check if any state reached success
            found = [s for s in sm.active if is_successful(s)]
            if found:
                sm.stashes['found'] = found
                break

            # Filter avoids
            sm.move(from_stash='active', to_stash='avoid', filter_func=should_avoid)

        elapsed = time.time() - t0

        if timed_out:
            print(f"  [-] TIMEOUT after {elapsed:.2f}s! States explored: {states_explored}, Peak active: {peak_active}")
            return {
                "id": pass_id,
                "status": "TIMEOUT",
                "time_sec": round(elapsed, 2),
                "states_explored": states_explored,
                "peak_active_states": peak_active,
                "solution": None,
                "solved_correctly": False
            }

        if 'found' in sm.stashes and len(sm.stashes['found']) > 0:
            sol_state = sm.stashes['found'][0]
            concrete_key = sol_state.solver.eval(sym_key, cast_to=bytes)
            key_str = concrete_key.decode("latin1", errors="replace")
            is_correct = (key_str == "K3y_P4ss")
            print(f"  [+] SOLVED in {elapsed:.2f}s! Found key: {key_str} (Correct: {is_correct}) | States explored: {states_explored}")
            return {
                "id": pass_id,
                "status": "SOLVED",
                "time_sec": round(elapsed, 2),
                "states_explored": states_explored,
                "peak_active_states": peak_active,
                "solution": key_str,
                "solved_correctly": is_correct
            }
        else:
            print(f"  [-] UNSOLVABLE / PATH EXHAUSTED after {elapsed:.2f}s! States explored: {states_explored}")
            return {
                "id": pass_id,
                "status": "EXHAUSTED",
                "time_sec": round(elapsed, 2),
                "states_explored": states_explored,
                "peak_active_states": peak_active,
                "solution": None,
                "solved_correctly": False
            }

    except Exception as e:
        elapsed = time.time() - t0
        print(f"  [-] ERROR during symbolic execution: {str(e)}")
        return {
            "id": pass_id,
            "status": f"ERROR_{str(e)[:50]}",
            "time_sec": round(elapsed, 2),
            "states_explored": 0,
            "peak_active_states": 0,
            "solution": None,
            "solved_correctly": False
        }

def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    all_results = []
    print("=" * 80)
    print("STARTING ANGR / Z3 SYMBOLIC EXECUTION RESILIENCE EVALUATION")
    print("=" * 80)

    for cfg in TEST_PASSES:
        pass_id = cfg["id"]
        bin_file = compile_crackme(pass_id, cfg["env"])
        if bin_file and bin_file.exists():
            res = evaluate_symbolic_execution(bin_file, pass_id)
            res["description"] = cfg["desc"]
            all_results.append(res)

    out_file = RESULTS_DIR / "symbolic_resilience_results.json"
    with open(out_file, "w") as f:
        json.dump(all_results, f, indent=2)

    print("\n" + "=" * 80)
    print(f"Symbolic execution evaluation complete: {out_file}")
    print("=" * 80)

if __name__ == "__main__":
    main()
