#!/usr/bin/env python3
"""
Robust Memory Barrier Stripping & LLVM IR Deobfuscation Resilience Benchmark.
Compares IR simplification under LLVM opt -O3 when memory barriers are:
Case A: Respected (Volatile memory semantics + polymorphic asm clobbers preserved)
Case B: Disrespected/Stripped (All volatile keywords, inline asm barriers, and opaque sinks stripped)
"""

import os
import sys
import subprocess
import json
import re
import time
from pathlib import Path

WORKSPACE = Path("/home/user/dev/ensia")
EVAL_DIR = WORKSPACE / "independent_eval"
WORKLOADS_DIR = EVAL_DIR / "workloads"
RESULTS_DIR = EVAL_DIR / "results"
PLUGIN_SO = WORKSPACE / "build" / "obfuscation" / "libEnsia.so"

TARGET_CONFIGS = [
    {"id": "SUBOBF", "env": {"SUB": "1"}, "workload": "target_crypto.c", "desc": "Instruction Substitution"},
    {"id": "MBAOBF", "env": {"MBA": "1"}, "workload": "target_crypto.c", "desc": "Mixed Boolean-Arithmetic"},
    {"id": "SPLITOBF", "env": {"SPLIT": "1"}, "workload": "target_control_flow.c", "desc": "Basic Block Splitting"},
    {"id": "BCFOBF", "env": {"BCF": "1"}, "workload": "target_control_flow.c", "desc": "Bogus Control Flow"},
    {"id": "CFFOBF", "env": {"CFF": "1"}, "workload": "target_control_flow.c", "desc": "Control Flow Flattening"},
    {"id": "CSMOBF", "env": {"CSM": "1"}, "workload": "target_control_flow.c", "desc": "Chaos State Machine"},
    {"id": "VOBF", "env": {"VOBF": "1"}, "workload": "target_crypto.c", "desc": "Vector Obfuscation"},
    {"id": "CONSTENC", "env": {"CONSTENC": "1"}, "workload": "target_crypto.c", "desc": "Constant Encryption"},
    {"id": "ACDOBF", "env": {"ACD": "1"}, "workload": "target_objc.m", "desc": "Anti-Class-Dump (ObjC metadata)", "target": "arm64-apple-darwin"},
    {"id": "PRESET_LOW", "env": {"ENSIA_PRESET": "low"}, "workload": "target_crackme.c", "desc": "Preset Low"},
    {"id": "PRESET_MID", "env": {"ENSIA_PRESET": "mid"}, "workload": "target_crackme.c", "desc": "Preset Mid"},
    {"id": "PRESET_HIGH", "env": {"ENSIA_PRESET": "high"}, "workload": "target_crackme.c", "desc": "Preset High"},
]

def analyze_ir_metrics(ir_text):
    """Accurately count instructions, basic blocks, branches, volatile accesses, and barriers."""
    inst_count = 0
    bb_count = 0
    branch_count = 0
    volatile_loads = 0
    volatile_stores = 0
    barriers = 0
    alloca_count = 0

    for raw_line in ir_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";"):
            continue
        if re.match(r'^([a-zA-Z0-9_.]+:\s*$|\d+:\s*$)', line):
            bb_count += 1
        elif "=" in line or line.startswith("store ") or line.startswith("br ") or line.startswith("ret ") or line.startswith("call ") or line.startswith("switch "):
            inst_count += 1
        
        if line.startswith("br "):
            branch_count += 1
        if "load volatile" in line:
            volatile_loads += 1
        if "store volatile" in line:
            volatile_stores += 1
        if "alloca " in line:
            alloca_count += 1
        if "asm sideeffect" in line and ("%fs:0x" in line or "%rsp" in line or "prfm" in line or "tpidr_el0" in line or "barrier.slot" in line):
            barriers += 1

    return {
        "instructions": inst_count,
        "basic_blocks": bb_count,
        "branches": branch_count,
        "volatile_loads": volatile_loads,
        "volatile_stores": volatile_stores,
        "alloca_count": alloca_count,
        "barriers": barriers
    }

def clean_ir_attributes(ir_text):
    """Strip optnone, noinline, and remove resulting empty attribute sets."""
    cleaned = re.sub(r'\boptnone\b', '', ir_text)
    cleaned = re.sub(r'\bnoinline\b', '', cleaned)
    # Remove empty attribute groups that cause opt syntax errors: attributes #N = {   }
    cleaned = re.sub(r'attributes\s+#\d+\s*=\s*\{\s*\}', '', cleaned)
    return cleaned

def strip_barriers_from_ir(ir_text):
    """Simulate lifting/deobfuscation that discards memory barriers and volatile semantics."""
    cleaned = clean_ir_attributes(ir_text)
    out_lines = []
    for line in cleaned.splitlines():
        # Remove inline asm barriers
        if "asm sideeffect" in line and ("%fs:0x" in line or "%rsp" in line or "prfm" in line or "tpidr_el0" in line or "movzbl" in line or "barrier" in line):
            continue
        # Remove stores to opaque sinks
        if "store volatile" in line and ("__ensia_opaque_sink" in line or "@_v" in line):
            continue
        # Demote volatile loads and stores to regular loads and stores
        line = re.sub(r'\bload volatile\b', 'load', line)
        line = re.sub(r'\bstore volatile\b', 'store', line)
        out_lines.append(line)
    return "\n".join(out_lines)

def run_opt(in_path, out_path):
    """Run opt with default<O3>."""
    cmd = ["opt", "-passes=default<O3>", str(in_path), "-S", "-o", str(out_path)]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        print(f"    [-] opt failed on {in_path.name}: {res.stderr[:160]}")
        return False
    return True

def compile_orig_ir(cfg):
    target_id = cfg["id"]
    workload = cfg["workload"]
    src_file = WORKLOADS_DIR / workload
    out_ll = RESULTS_DIR / f"barrier_eval_{target_id}_orig.ll"

    # Use empty.toml for isolated passes
    run_env = os.environ.copy()
    if not target_id.startswith("PRESET_"):
        run_env["ENSIA_CONFIG"] = str(EVAL_DIR / "empty.toml")
    run_env.update(cfg["env"])

    cmd = [
        "clang", f"-fpass-plugin={PLUGIN_SO}",
        "-O1", "-S", "-emit-llvm",
        str(src_file), "-o", str(out_ll)
    ]
    if cfg.get("target"):
        cmd.extend(["-target", cfg["target"]])
    res = subprocess.run(cmd, env=run_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if res.returncode != 0:
        print(f"  [-] Clang compilation failed for {target_id}: {res.stderr[:200]}")
        return None
    return out_ll

def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    results = []

    print("=" * 80)
    print("STARTING MEMORY BARRIER STRIPPING & LLVM IR RESILIENCE BENCHMARK")
    print("=" * 80)

    for cfg in TARGET_CONFIGS:
        target_id = cfg["id"]
        workload = cfg["workload"]
        print(f"\n[+] Evaluating Barrier Resilience for {target_id} ({cfg['desc']}) on {workload}")

        orig_ll = compile_orig_ir(cfg)
        if not orig_ll or not orig_ll.exists():
            continue

        orig_text = orig_ll.read_text(errors="ignore")
        orig_metrics = analyze_ir_metrics(orig_text)

        # 1. Respecting Barriers (optnone stripped to enable O3, but volatile & asm barriers preserved)
        respect_in = RESULTS_DIR / f"barrier_eval_{target_id}_respect_in.ll"
        respect_out = RESULTS_DIR / f"barrier_eval_{target_id}_respect_O3.ll"
        respect_in.write_text(clean_ir_attributes(orig_text))
        success_respect = run_opt(respect_in, respect_out)
        respect_metrics = analyze_ir_metrics(respect_out.read_text(errors="ignore")) if success_respect else orig_metrics

        # 2. Stripping Barriers (volatile removed, asm barriers stripped, opaque sinks eliminated)
        stripped_in = RESULTS_DIR / f"barrier_eval_{target_id}_stripped_in.ll"
        stripped_out = RESULTS_DIR / f"barrier_eval_{target_id}_stripped_O3.ll"
        stripped_in.write_text(strip_barriers_from_ir(orig_text))
        success_stripped = run_opt(stripped_in, stripped_out)
        stripped_metrics = analyze_ir_metrics(stripped_out.read_text(errors="ignore")) if success_stripped else orig_metrics

        # Retention metrics
        inst_ret_respect = round((respect_metrics["instructions"] / max(1, orig_metrics["instructions"])) * 100.0, 1)
        inst_ret_stripped = round((stripped_metrics["instructions"] / max(1, orig_metrics["instructions"])) * 100.0, 1)
        bb_ret_respect = round((respect_metrics["basic_blocks"] / max(1, orig_metrics["basic_blocks"])) * 100.0, 1)
        bb_ret_stripped = round((stripped_metrics["basic_blocks"] / max(1, orig_metrics["basic_blocks"])) * 100.0, 1)

        diff_instructions = respect_metrics["instructions"] - stripped_metrics["instructions"]
        diff_bbs = respect_metrics["basic_blocks"] - stripped_metrics["basic_blocks"]

        print(f"  [Original]   Insts: {orig_metrics['instructions']:>6} | BBs: {orig_metrics['basic_blocks']:>4} | Barriers: {orig_metrics['barriers']:>3} | Volatile Loads/Stores: {orig_metrics['volatile_loads']}/{orig_metrics['volatile_stores']}")
        print(f"  [Respect O3] Insts: {respect_metrics['instructions']:>6} ({inst_ret_respect:>5}%) | BBs: {respect_metrics['basic_blocks']:>4} ({bb_ret_respect:>5}%)")
        print(f"  [Strip O3]   Insts: {stripped_metrics['instructions']:>6} ({inst_ret_stripped:>5}%) | BBs: {stripped_metrics['basic_blocks']:>4} ({bb_ret_stripped:>5}%)")
        print(f"  [Barrier Impact] Dead instructions collapsed when stripped: {diff_instructions:>5} ({inst_ret_respect - inst_ret_stripped:>5.1f}% gap)")

        results.append({
            "id": target_id,
            "description": cfg["desc"],
            "workload": workload,
            "original": orig_metrics,
            "respecting_barriers_O3": respect_metrics,
            "stripped_barriers_O3": stripped_metrics,
            "instruction_retention_respect_pct": inst_ret_respect,
            "instruction_retention_stripped_pct": inst_ret_stripped,
            "bb_retention_respect_pct": bb_ret_respect,
            "bb_retention_stripped_pct": bb_ret_stripped,
            "barrier_protection_gap_pct": round(inst_ret_respect - inst_ret_stripped, 1)
        })

    out_json = RESULTS_DIR / "barrier_resilience_results.json"
    with open(out_json, "w") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 80)
    print(f"Barrier resilience benchmark completed: {out_json}")
    print("=" * 80)

if __name__ == "__main__":
    main()
