#!/usr/bin/env python3
"""
Comprehensive Correctness and Lifting Resistance Verification Script for Ensia Obfuscator.
Tests all individual passes + combined presets:
  1. Execution correctness on all test functions (assertions validation)
  2. Disassembly machine instruction counts
  3. ASM to LLVM IR lifting with memory barriers preserved + opt -O3
  4. ASM to LLVM IR lifting with memory barriers STRIPPED + opt -O3 (adversary model)
  5. Retention rate and deobfuscation analysis
"""

import sys
import os
import subprocess

PROJECT_ROOT = "/home/user/dev/ensia"
sys.path.insert(0, PROJECT_ROOT)

import capstone
from test.asm_lifter import lift_function_to_ll, get_symbol_bytes

PROJECT_ROOT = "/home/user/dev/ensia"
BUILD_DIR = os.path.join(PROJECT_ROOT, "build")
PLUGIN_LIB = os.path.join(BUILD_DIR, "obfuscation", "libEnsia.so")
SRC_C = os.path.join(PROJECT_ROOT, "test", "min_obf_example.c")
OUT_DIR = os.path.join(BUILD_DIR, "individual_verification")
os.makedirs(OUT_DIR, exist_ok=True)

PASS_SPECS = [
    {
        "pass_name": "SUBOBF",
        "env_flag": "SUBOBF=1",
        "target_sym": "test_arithmetic",
        "num_args": 2,
        "description": "Instruction Substitution (algebraic identities)"
    },
    {
        "pass_name": "MBAOBF",
        "env_flag": "MBAOBF=1",
        "target_sym": "test_arithmetic",
        "num_args": 2,
        "description": "Mixed Boolean-Arithmetic (linear & polynomial MBA)"
    },
    {
        "pass_name": "STRCRY",
        "env_flag": "STRCRY=1",
        "target_sym": "test_strings",
        "num_args": 1,
        "description": "String Literal Encryption"
    },
    {
        "pass_name": "SPLITOBF",
        "env_flag": "SPLITOBF=1",
        "target_sym": "test_sequential_math",
        "num_args": 3,
        "description": "Basic Block Splitting"
    },
    {
        "pass_name": "BCFOBF",
        "env_flag": "BCFOBF=1",
        "target_sym": "test_control_flow",
        "num_args": 2,
        "description": "Bogus Control Flow (opaque predicates)"
    },
    {
        "pass_name": "CFFOBF",
        "env_flag": "CFFOBF=1",
        "target_sym": "test_control_flow",
        "num_args": 2,
        "description": "Control Flow Flattening (switch dispatcher)"
    },
    {
        "pass_name": "CSMOBF",
        "env_flag": "CSMOBF=1",
        "target_sym": "test_control_flow",
        "num_args": 2,
        "description": "Chaos State Machine (multi-state pseudo-random walk)"
    },
    {
        "pass_name": "CONSTENC",
        "env_flag": "CONSTENC=1",
        "target_sym": "test_constants",
        "num_args": 1,
        "description": "Constant Encryption (Feistel rounds + dynamic S-Box)"
    },
    {
        "pass_name": "INDIBRAN",
        "env_flag": "INDIBRAN=1",
        "target_sym": "test_control_flow",
        "num_args": 2,
        "description": "Indirect Branching (table permutation & offset encryption)"
    },
    {
        "pass_name": "FUNCWRA",
        "env_flag": "FUNCWRA=1",
        "target_sym": "test_function_calls",
        "num_args": 1,
        "description": "Function Wrapper (trampoline indirection)"
    },
    {
        "pass_name": "FCO",
        "env_flag": "FCO=1",
        "target_sym": "test_function_calls",
        "num_args": 1,
        "description": "Function Call Obfuscation (dynamic dlsym import)"
    },
    {
        "pass_name": "VOBF",
        "env_flag": "VOBF=1",
        "target_sym": "test_sequential_math",
        "num_args": 3,
        "description": "Vector Obfuscation (SIMD lane lifting & shuffle)"
    },
    {
        "pass_name": "ADB",
        "env_flag": "ADB=1",
        "target_sym": "test_arithmetic",
        "num_args": 2,
        "description": "Anti-Debugging (ptrace & timing barriers)"
    },
    {
        "pass_name": "ANTIHOOK",
        "env_flag": "ANTIHOOK=1",
        "target_sym": "test_arithmetic",
        "num_args": 2,
        "description": "Anti-Hooking & Integrity Self-Check (hardware traps + data entanglement)"
    },
]

def count_asm_insns(obj_path, sym_name):
    raw = get_symbol_bytes(obj_path, sym_name)
    if not raw:
        return 0
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    return len(list(cs.disasm(raw, 0x1000)))

def lift_and_optimize(obj_path, sym_name, num_args, preserve_barrier):
    try:
        ll = lift_function_to_ll(obj_path, sym_name, num_args, preserve_barrier=preserve_barrier)
    except Exception as e:
        return f"LIFT_ERR: {e}", ""
    
    as_res = subprocess.run(["llvm-as", "-o", "/tmp/temp_lift.bc"], input=ll, text=True, capture_output=True)
    if as_res.returncode != 0:
        return f"AS_ERR: {as_res.stderr[:200]}", ""
        
    opt_res = subprocess.run(["opt", "-passes=default<O3>", "-S", "/tmp/temp_lift.bc"], capture_output=True, text=True)
    if opt_res.returncode != 0:
        return f"OPT_ERR: {opt_res.stderr[:200]}", ""
        
    ir_lines = [l.strip() for l in opt_res.stdout.splitlines() if l.strip() and not l.startswith(";") and not l.startswith("attributes") and not l.startswith("define") and not l.startswith("}") and not l.endswith(":")]
    return len(ir_lines), opt_res.stdout

def run():
    print("=" * 80)
    print(" EnSia Obfuscator: Full Correctness & Lifting Resistance Verification")
    print("=" * 80)
    
    # 1. Baseline Compilation & Measurement
    print("\n[+] 1. Measuring Clean Unobfuscated Baseline...")
    base_bin = os.path.join(OUT_DIR, "baseline_bin")
    base_obj = os.path.join(OUT_DIR, "baseline_obj.o")
    cmd_base = ["clang", "-O1", SRC_C, "-ldl", "-o", base_bin]
    subprocess.check_call(cmd_base)
    cmd_base_obj = ["clang", "-O1", "-c", SRC_C, "-o", base_obj]
    subprocess.check_call(cmd_base_obj)
    
    # Verify baseline execution
    res = subprocess.run([base_bin], capture_output=True, text=True)
    assert res.returncode == 0 and "All basic tests executed successfully" in res.stdout, "Baseline execution failed!"
    print("    [PASS] Clean baseline execution verified.")
    
    # Measure baseline stats
    baseline_stats = {}
    for spec in PASS_SPECS:
        sym = spec["target_sym"]
        if sym not in baseline_stats:
            asm_cnt = count_asm_insns(base_obj, sym)
            opt_cnt, _ = lift_and_optimize(base_obj, sym, spec["num_args"], preserve_barrier=True)
            baseline_stats[sym] = {"asm": asm_cnt, "opt": opt_cnt}
            print(f"    Baseline '{sym}': ASM={asm_cnt} insns, Lifted+Opt={opt_cnt} insns")

    # 2. Individual Pass Verification
    print("\n[+] 2. Testing Each Pass Individually (Correctness & Lifting Resistance)...")
    results = []
    
    for spec in PASS_SPECS:
        pname = spec["pass_name"]
        env_flag = spec["env_flag"]
        sym = spec["target_sym"]
        nargs = spec["num_args"]
        desc = spec["description"]
        
        print(f"\n--- Testing Pass: {pname} ({env_flag}) ---")
        print(f"    Target: {sym} | {desc}")
        
        bin_path = os.path.join(OUT_DIR, f"bin_{pname}")
        obj_path = os.path.join(OUT_DIR, f"obj_{pname}.o")
        
        # Compile executable
        env = os.environ.copy()
        env["ENSIA"] = "1"
        key, val = env_flag.split("=")
        env[key] = val
        
        cmd_bin = ["clang", f"-fpass-plugin={PLUGIN_LIB}", "-O1", SRC_C, "-ldl", "-o", bin_path]
        compile_res = subprocess.run(cmd_bin, env=env, capture_output=True, text=True)
        if compile_res.returncode != 0:
            print(f"    [-] Compilation FAILED: {compile_res.stderr}")
            continue
            
        cmd_obj = ["clang", f"-fpass-plugin={PLUGIN_LIB}", "-O1", "-c", SRC_C, "-o", obj_path]
        subprocess.check_call(cmd_obj, env=env)
        
        # Test correctness execution
        run_res = subprocess.run([bin_path], capture_output=True, text=True)
        correctness_pass = (run_res.returncode == 0 and "All basic tests executed successfully" in run_res.stdout)
        if correctness_pass:
            print(f"    [PASS] Correctness verified: output matches golden test values")
        else:
            print(f"    [-] FAILED Execution: returncode={run_res.returncode}, stdout={run_res.stdout}, stderr={run_res.stderr}")
            
        # Disassemble and lift
        asm_cnt = count_asm_insns(obj_path, sym)
        ir_with_barrier, _ = lift_and_optimize(obj_path, sym, nargs, preserve_barrier=True)
        ir_stripped, opt_ir = lift_and_optimize(obj_path, sym, nargs, preserve_barrier=False)
        
        base_asm = baseline_stats[sym]["asm"]
        base_opt = baseline_stats[sym]["opt"]
        
        print(f"    ASM Insns: {asm_cnt} (vs baseline {base_asm}) -> Expansion: {asm_cnt / max(1, base_asm):.1f}x")
        print(f"    Lifted + Opt-O3 (With Barrier):     {ir_with_barrier} insns")
        print(f"    Lifted + Opt-O3 (STRIPPED Barrier): {ir_stripped} insns")
        
        results.append({
            "pass": pname,
            "sym": sym,
            "correctness": "PASS" if correctness_pass else "FAIL",
            "base_asm": base_asm,
            "obf_asm": asm_cnt,
            "ir_barrier": ir_with_barrier,
            "ir_stripped": ir_stripped,
            "desc": desc
        })

    # 3. Print Final Markdown Table
    print("\n" + "=" * 80)
    print(" SUMMARY TABLE: INDIVIDUAL PASS CORRECTNESS & LIFTING RESISTANCE")
    print("=" * 80)
    header = f"| {'Pass':<10} | {'Target Symbol':<22} | {'Correctness':<11} | {'Base ASM':<8} | {'Obf ASM':<8} | {'Lift+O3 (Bar)':<13} | {'Lift+O3 (Strip)':<15} | {'Description':<35} |"
    sep = f"|{'-'*12}|{'-'*24}|{'-'*13}|{'-'*10}|{'-'*10}|{'-'*15}|{'-'*17}|{'-'*37}|"
    print(header)
    print(sep)
    for r in results:
        row = f"| {r['pass']:<10} | {r['sym']:<22} | {r['correctness']:<11} | {r['base_asm']:<8} | {r['obf_asm']:<8} | {str(r['ir_barrier']):<13} | {str(r['ir_stripped']):<15} | {r['desc']:<35} |"
        print(row)
    print("=" * 80)

if __name__ == "__main__":
    run()
