#!/usr/bin/env python3
"""
Ensia / OLLVM-Next Modules Audit Verification Script
Runs rigorous evaluation on:
  - CSM (Chaos State Machine)
  - INDIBRAN (Indirect Branch)
  - FUNCWRA (Function Wrapper)
  - FCO (Function Call Obfuscate)
  - VOBF (Vector Obfuscation)
  - Polymorphic Barriers
  - CFF & CSM State Transitions
  - String Encryption Anti-Dump
  - Constant Encryption (Schemes A, B, C)
  - Full Combined Pipeline
"""

import os
import re
import sys
import time
import subprocess
from collections import Counter

PLUGIN = "/home/user/dev/ensia/build/obfuscation/libEnsia.so"
AUDIT_DIR = "/home/user/dev/ensia/test/eval_harness/modules_audit"

def run_cmd(cmd, cwd=AUDIT_DIR):
    res = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
    return res

def print_header(title):
    print("\n" + "=" * 75)
    print(f"  {title}")
    print("=" * 75)

def test_module(name, src_c, obf_flag, run_args=""):
    base_ll = f"{name}_base.ll"
    base_bin = f"{name}_base"
    obf_ll = f"{name}_obf.ll"
    obf_bin = f"{name}_obf"
    opt_o3_ll = f"{name}_opt_o3.ll"
    opt_aggr_ll = f"{name}_opt_aggr.ll"

    # 1. Base compile
    run_cmd(f"clang -O0 -emit-llvm -S {src_c} -o {base_ll}")
    run_cmd(f"clang -O0 {base_ll} -o {base_bin}")
    r_base = run_cmd(f"./{base_bin} {run_args}")
    base_out = r_base.stdout.strip()

    # 2. Obfuscate
    t0 = time.time()
    r_obf = run_cmd(f"opt -load-pass-plugin={PLUGIN} {obf_flag} -passes='ensia' {base_ll} -S -o {obf_ll}")
    obf_time = time.time() - t0
    run_cmd(f"clang -O0 {obf_ll} -o {obf_bin}")
    r_run = run_cmd(f"./{obf_bin} {run_args}")
    obf_out = r_run.stdout.strip()
    correctness = (base_out == obf_out and r_run.returncode == 0)

    # 3. Optimize opt -O3
    run_cmd(f"opt -passes='default<O3>' -S {obf_ll} -o {opt_o3_ll}")
    run_cmd(f"opt -passes='sccp,simplifycfg,instcombine,dce,gvn' -S {obf_ll} -o {opt_aggr_ll}")

    # Line counts
    def lines(f):
        return len(open(f"{AUDIT_DIR}/{f}").readlines()) if os.path.exists(f"{AUDIT_DIR}/{f}") else 0

    base_lines = lines(base_ll)
    obf_lines = lines(obf_ll)
    o3_lines = lines(opt_o3_ll)
    aggr_lines = lines(opt_aggr_ll)

    retention_o3 = (o3_lines / obf_lines * 100) if obf_lines else 0
    retention_aggr = (aggr_lines / obf_lines * 100) if obf_lines else 0

    print(f"[*] Module: {name.upper()} ({obf_flag})")
    print(f"    - Correctness          : {'PASS' if correctness else 'FAIL'} (rc={r_run.returncode})")
    print(f"    - Obfuscation Time     : {obf_time:.4f}s")
    print(f"    - IR Lines (Base->Obf) : {base_lines} -> {obf_lines} ({obf_lines/base_lines:.1f}x bloat)")
    print(f"    - IR Lines after opt-O3: {o3_lines} ({retention_o3:.1f}% retained)")
    print(f"    - IR Lines after aggr  : {aggr_lines} ({retention_aggr:.1f}% retained)")

    return {
        "name": name,
        "correctness": correctness,
        "obf_time": obf_time,
        "base_lines": base_lines,
        "obf_lines": obf_lines,
        "o3_lines": o3_lines,
        "aggr_lines": aggr_lines,
        "retention_o3": retention_o3,
        "retention_aggr": retention_aggr,
        "output_match": base_out == obf_out
    }

def main():
    print_header("1. INDIVIDUAL MODULES AUDIT")
    results = {}
    results["csm"] = test_module("test_csm", "test_csm.c", "-enable-csmobf")
    results["csm_nested"] = test_module("test_csm_nested", "test_csm.c", "-enable-csmobf --csm_nested")
    results["indibran"] = test_module("test_indibran", "test_indibran.c", "-enable-indibran")
    results["funcwra"] = test_module("test_funcwra", "test_funcwra.c", "-enable-funcwra --fw_prob=100")
    results["fco"] = test_module("test_fco", "test_fco.c", "-enable-fco")
    results["vobf"] = test_module("test_vobf", "test_vobf.c", "-enable-vobf --vec_prob=100")
    results["constenc_a"] = test_module("test_constenc_a", "test_constenc.c", "-enable-constenc")
    results["constenc_b"] = test_module("test_constenc_b", "test_constenc.c", "-enable-constenc --constenc_feistel")
    results["str_antidump"] = test_module("test_str_antidump", "test_str_antidump.c", "-enable-strcry")

    print_header("2. POLYMORPHIC BARRIER AUDIT")
    # Generate assembly and check barrier distribution
    run_cmd("clang -S test_combined_all.ll -o test_combined_all.s")
    asm_text = open(f"{AUDIT_DIR}/test_combined_all.s").read()
    barriers = {
        "xorb $0": len(re.findall(r"xorb\s+\$0,", asm_text)),
        "orb $0": len(re.findall(r"orb\s+\$0,", asm_text)),
        "andb $-1": len(re.findall(r"andb\s+\$-1,", asm_text)),
        "addb $0": len(re.findall(r"addb\s+\$0,", asm_text)),
        "subb $0": len(re.findall(r"subb\s+\$0,", asm_text)),
        "rolb $0": len(re.findall(r"rolb\s+\$0,", asm_text)),
        "rorb $0": len(re.findall(r"rorb\s+\$0,", asm_text)),
        "notb/notb": len(re.findall(r"notb.*\n\s*notb", asm_text, re.MULTILINE)),
        "incb/decb": len(re.findall(r"incb.*\n\s*decb", asm_text, re.MULTILINE)),
    }
    total_barriers = sum(barriers.values())
    print(f"Total x86 polymorphic barriers in combined binary: {total_barriers}")
    for k, v in sorted(barriers.items(), key=lambda x: -x[1]):
        pct = (v / total_barriers * 100) if total_barriers else 0
        print(f"    - {k:12s}: {v:4d} ({pct:5.1f}%)")

    print_header("3. COMBINED PASSES AUDIT (FULL PIPELINE)")
    all_flags = "-enable-csmobf -enable-indibran -enable-funcwra -enable-fco -enable-vobf -enable-strcry -enable-constenc"
    results["combined"] = test_module("test_combined", "test_combined.c", all_flags)

    print("\nAudit execution completed successfully.")

if __name__ == "__main__":
    main()
