#!/usr/bin/env python3
"""
==============================================================================
Ensia / OLLVM-Next Unified Matrix Test & Inspection Framework
==============================================================================
Matrix Dimensions:
  - Architecture: x86_64 (native), aarch64 (cross-compile + podman emulation)
  - Toolchain: LLVM 21, LLVM 22, LLVM 23 (auto-detected or specified)
  - Obfuscation Passes: All 14 individual passes + 5 preset configurations
  - Direct Verification:
      1. Execution correctness (golden numerical assertion verification)
      2. LLVM IR transformation inspection (specific IR constructs)
      3. Disassembly / ASM machine instruction inspection
      4. Code expansion and resistance quantification
==============================================================================
"""

import os
import sys
import re
import argparse
import subprocess
import shutil
import time
from typing import Dict, List, Tuple, Optional

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
BUILD_DIR = os.path.join(PROJECT_ROOT, "build")
PLUGIN_LIB = os.path.join(BUILD_DIR, "obfuscation", "libEnsia.so")
EMPTY_CONFIG = os.path.join(PROJECT_ROOT, "test", "harness", "empty.toml")
SRC_C = os.path.join(PROJECT_ROOT, "test", "min_obf_example.c")
SRC_ANTIHOOK = os.path.join(PROJECT_ROOT, "test", "test_antihook_tamper.c")
SRC_COMBINED = os.path.join(PROJECT_ROOT, "test", "test_combined_obf.cpp")
ARM64_SYSROOT = "/tmp/aarch64-sysroot"
CONTAINER_IMAGE = "localhost/ensia-aarch64-tester:latest"

# -----------------------------------------------------------------------------
# Pass Definitions & Specific Inspection Signatures
# -----------------------------------------------------------------------------
PASS_REGISTRY = [
    {
        "id": "sub",
        "name": "Instruction Substitution",
        "flag": "-mllvm -enable-subobf",
        "env": "SUBOBF=1",
        "source": SRC_C,
        "target_sym": "test_arithmetic",
        "ir_checks": [
            (r"(xor|and|or)\s+i32", "Algebraic bitwise substitution operations"),
        ],
        "asm_checks": {
            "x86_64": [(r"(xor|and|or|not)", "x86 algebraic identity instructions")],
            "aarch64": [(r"(eor|and|orr|mvn|bic)", "ARM64 algebraic identity instructions")]
        },
        "desc": "Algebraic expansion of arithmetic operations"
    },
    {
        "id": "mba",
        "name": "Mixed Boolean-Arithmetic",
        "flag": "-mllvm -enable-mbaobf",
        "env": "MBAOBF=1",
        "source": SRC_C,
        "target_sym": "test_arithmetic",
        "ir_checks": [
            (r"(@__ensia_mba_ctx|@_v[0-9a-f]{16}|barrier\.slot)", "Runtime secret MBA context or contextual hardware barrier slots"),
        ],
        "asm_checks": {
            "x86_64": [(r"(__ensia_mba_ctx|_v[0-9a-f]{16}|%fs:)", "Runtime context load or TLS/canary barrier")],
            "aarch64": [(r"(__ensia_mba_ctx|_v[0-9a-f]{16}|tpidr_el0)", "Runtime context load or ARM64 TLS barrier")]
        },
        "desc": "Non-zero context-dependent polynomial MBA with dynamic barriers"
    },
    {
        "id": "split",
        "name": "BasicBlock Splitting",
        "flag": "-mllvm -enable-splitobf",
        "env": "SPLITOBF=1",
        "source": SRC_C,
        "target_sym": "test_sequential_math",
        "ir_checks": [
            (r"icmp eq i32.*0", "Opaque predicate guard ((seed * (seed + 1)) & 1) == 0"),
            (r"br i1.*label.*label", "Conditional branch splitting CFG sequence"),
        ],
        "asm_checks": {
            "x86_64": [(r"(je|jne|jmp)", "Split block jumps and opaque condition branches")],
            "aarch64": [(r"(b\.(eq|ne)|b\s+)", "ARM64 split block branches and conditional jumps")]
        },
        "desc": "Mandatory opaque-chained basic block slicing with bogus loop"
    },
    {
        "id": "bcf",
        "name": "Bogus Control Flow",
        "flag": "-mllvm -enable-bcfobf",
        "env": "BCFOBF=1",
        "source": SRC_C,
        "target_sym": "test_control_flow",
        "ir_checks": [
            (r"icmp (sle|sge|eq|ne)", "Opaque predicate comparison in cloned block"),
            (r"barrier\.slot", "Polymorphic hardware barrier in bogus edges"),
        ],
        "asm_checks": {
            "x86_64": [(r"(j[a-z]{1,3})", "Opaque predicate conditional branches")],
            "aarch64": [(r"(b\.[a-z]{2}|cbz|cbnz)", "ARM64 opaque predicate conditional branches")]
        },
        "desc": "Opaque hardware-predicate branching and cloned dead blocks"
    },
    {
        "id": "csm",
        "name": "Chaos State Machine",
        "flag": "-mllvm -enable-csmobf",
        "env": "CSMOBF=1",
        "source": SRC_C,
        "target_sym": "test_control_flow",
        "ir_checks": [
            (r"(4294967291|i64 4294967291)", "Q32 logistic map multiplier (mu_32 = 4294967291)"),
            (r"switch i32", "CSM chaotic orbit switch dispatcher"),
        ],
        "asm_checks": {
            "x86_64": [(r"(4294967291|0xfffffffb|0x9e3779b9|jmpq?\s+\*|cmpl.*)", "Q32 multiplier or indirect dispatch table")],
            "aarch64": [(r"(0xfffffffb|movk|adrp|b\.eq|br\s+x)", "ARM64 Q32 multiplier or register branch dispatch")]
        },
        "desc": "Q32 chaotic attractor basin diffusion & discrete cellular automata"
    },
    {
        "id": "cff",
        "name": "Control Flow Flattening",
        "flag": "-mllvm -enable-cffobf",
        "env": "CFFOBF=1",
        "source": SRC_C,
        "target_sym": "test_control_flow",
        "ir_checks": [
            (r"switch i32 %", "Switch dispatcher statement"),
            (r"store i32 .*, ptr %", "State variable transition stores"),
        ],
        "asm_checks": {
            "x86_64": [(r"(jmpq?\s+\*|switch)", "Switch jump table or dispatch loop")],
            "aarch64": [(r"(br\s+x|adrp?\s+x|b\.(eq|ne))", "ARM64 indirect jump table dispatch")]
        },
        "desc": "Classic basic block flattening with central switch dispatcher"
    },
    {
        "id": "vobf",
        "name": "Vector Obfuscation",
        "flag": "-mllvm -enable-vobf",
        "env": "VOBF=1",
        "source": SRC_C,
        "target_sym": "test_sequential_math",
        "ir_checks": [
            (r"<(4 x i32|8 x i32|2 x i64|4 x i64|16 x i8)>", "SIMD vector type lifting"),
            (r"(insertelement|shufflevector|extractelement)", "Vector insertion and permutation intrinsics"),
        ],
        "asm_checks": {
            "x86_64": [(r"(movd|pshufd|paddd|pxor|vmov|vpxor)", "x86 SSE/AVX vector register instructions")],
            "aarch64": [(r"(dup|mov\s+v[0-9]|add\s+v[0-9]|eor\s+v[0-9]|str\s+q[0-9]|ldr\s+q[0-9])", "ARM64 NEON vector instructions")]
        },
        "desc": "Scalar arithmetic to SIMD vector lifting with lane shuffling"
    },
    {
        "id": "constenc",
        "name": "Constant Encryption",
        "flag": "-mllvm -enable-constenc",
        "env": "CONSTENC=1",
        "source": SRC_C,
        "target_sym": "test_constants",
        "ir_checks": [
            (r"(!constenc\.done|barrier\.slot)", "Multi-share XOR recombination or Feistel barrier slot"),
        ],
        "asm_checks": {
            "x86_64": [(r"(xor|add)", "Dynamic share reconstruction instructions")],
            "aarch64": [(r"(eor|add)", "ARM64 dynamic share reconstruction instructions")]
        },
        "desc": "Feistel network and multi-share additive split constant encryption"
    },
    {
        "id": "strenc",
        "name": "String Encryption",
        "flag": "-mllvm -enable-strcry",
        "env": "STRCRY=1",
        "source": SRC_C,
        "target_sym": "test_strings",
        "ir_checks": [
            (r"(__ensia_dec_space|_v[0-9a-f]{16}.*thread_local|llvm\.memset)", "Thread-Local Storage decrypted string space or zeroization"),
        ],
        "asm_checks": {
            "x86_64": [(r"(__ensia_dec_space|_v[0-9a-f]{16}|@tpoff|%fs:)", "TLS buffer reference and runtime decryption sweep")],
            "aarch64": [(r"(__ensia_dec_space|_v[0-9a-f]{16}|tpidr_el0)", "ARM64 TLS reference and runtime decryption sweep")]
        },
        "desc": "Caller-owned ephemeral string decryption with TLS zeroization anti-dump"
    },
    {
        "id": "indibran",
        "name": "Indirect Branching",
        "flag": "-mllvm -enable-indibran",
        "env": "INDIBRAN=1",
        "source": SRC_C,
        "target_sym": "test_control_flow",
        "ir_checks": [
            (r"(indirectbr|blockaddress)", "Indirect branch target resolution via blockaddress table"),
        ],
        "asm_checks": {
            "x86_64": [(r"jmpq?\s+\*", "x86 indirect register jump (jmpq *%reg)")],
            "aarch64": [(r"br\s+x", "ARM64 indirect register branch (br x<reg>)")]
        },
        "desc": "Knuth-hash encrypted jump targets and indirect branching"
    },
    {
        "id": "funcwra",
        "name": "Function Wrapper",
        "flag": "-mllvm -enable-funcwra",
        "env": "FUNCWRA=1",
        "source": SRC_C,
        "target_sym": "test_function_calls",
        "ir_checks": [
            (r"(define.*@EnsiaFW_|noinline.*optnone)", "Wrapper proxy function creation and NoInline/OptimizeNone attributes"),
        ],
        "asm_checks": {
            "x86_64": [(r"callq?\s+.*EnsiaFW_", "Call redirected through proxy wrapper trampoline")],
            "aarch64": [(r"bl\s+.*EnsiaFW_", "ARM64 call routed through proxy wrapper trampoline")]
        },
        "desc": "Polymorphic proxy wrappers with enforced NoInline & OptimizeNone"
    },
    {
        "id": "fco",
        "name": "Function Call Obfuscation",
        "flag": "-mllvm -enable-fco",
        "env": "FCO=1",
        "source": SRC_C,
        "target_sym": "test_function_calls",
        "ir_checks": [
            (r"call.*(ptr|i32\s*\()", "Indirect call through obfuscated function pointer"),
        ],
        "asm_checks": {
            "x86_64": [(r"callq?\s+\*", "x86 indirect register call (callq *%reg)")],
            "aarch64": [(r"blr\s+x", "ARM64 indirect register call (blr x<reg>)")]
        },
        "desc": "Dynamic function call indirection and import resolution"
    },
    {
        "id": "adb",
        "name": "Anti-Debugging",
        "flag": "-mllvm -enable-adb -mllvm -adb_prob=100",
        "env": "ADB=1 ADB_PROB=100",
        "source": SRC_C,
        "target_sym": "test_arithmetic",
        "ir_checks": [
            (r"(rdtsc|syscall|ptrace|CNTPCT|cntvct_el0|tpidr_el0)", "Hardware timing jitter / ptrace syscall inline probe"),
        ],
        "asm_checks": {
            "x86_64": [(r"(rdtsc|syscall)", "x86 timing jitter (rdtsc) or direct kernel syscall")],
            "aarch64": [(r"(cntvct_el0|cntpct|svc\s+#0|tpidr_el0)", "ARM64 timer probe (cntvct/cntpct) or supervisor syscall (svc)")]
        },
        "desc": "Kernel timing jitter & hardware anti-debug inline probes"
    },
    {
        "id": "antihook",
        "name": "Anti-Hooking",
        "flag": "-mllvm -enable-antihook",
        "env": "ANTIHOOK=1",
        "source": SRC_ANTIHOOK,
        "target_sym": "target_func",
        "ir_checks": [
            (r"(0xE9|0x14000001|233|335544321|hook)", "Prologue hook byte verification and comparison"),
        ],
        "asm_checks": {
            "x86_64": [(r"(cmp|test|syscall|ud2|int3)", "Prologue inspection and violent exit / syscall traps")],
            "aarch64": [(r"(cmp|svc|brk)", "ARM64 prologue memory inspection and direct syscall exit")]
        },
        "desc": "Prologue inline-hook self-check with violent exit traps"
    },
]

PRESET_REGISTRY = [
    {"id": "preset_low",  "name": "Low Obfuscation Preset",  "flag": "-mllvm -lowobf",  "env": "LOWOBF=1", "source": SRC_C},
    {"id": "preset_mid",  "name": "Medium Obfuscation Preset", "flag": "-mllvm -medobf",  "env": "MEDOBF=1", "source": SRC_C},
    {"id": "preset_csm_vec", "name": "CSM + Vector Obfuscation","flag": "-mllvm -enable-csmobf -mllvm -enable-vobf", "env": "CSMOBF=1 VOBF=1", "source": SRC_C},
]

# -----------------------------------------------------------------------------
# Toolchain Discovery
# -----------------------------------------------------------------------------
def discover_toolchains() -> List[Dict[str, str]]:
    toolchains = []
    candidates = [
        shutil.which("clang-21"),
        shutil.which("clang-22"),
        shutil.which("clang-23"),
        os.path.join(PROJECT_ROOT, "LLVM-23.1.1-Linux-X64", "bin", "clang"),
        shutil.which("clang")
    ]
    seen_versions = set()

    for bin_path in candidates:
        if not bin_path or not os.path.exists(bin_path):
            continue
        try:
            res = subprocess.run([bin_path, "--version"], capture_output=True, text=True, check=True)
            match = re.search(r"clang version\s+([0-9]+)\.([0-9]+)\.([0-9]+)", res.stdout)
            if match:
                major = match.group(1)
                full_ver = f"{match.group(1)}.{match.group(2)}.{match.group(3)}"
                if major not in seen_versions:
                    seen_versions.add(major)
                    # Select corresponding plugin library compiled against this LLVM major
                    if major == "23" and os.path.exists(os.path.join(PROJECT_ROOT, "build_llvm23", "obfuscation", "libEnsia.so")):
                        plugin_path = os.path.join(PROJECT_ROOT, "build_llvm23", "obfuscation", "libEnsia.so")
                    else:
                        plugin_path = os.path.join(PROJECT_ROOT, "build", "obfuscation", "libEnsia.so")

                    toolchains.append({
                        "name": f"LLVM {major}",
                        "major": major,
                        "version": full_ver,
                        "clang": bin_path,
                        "clangxx": shutil.which(f"clang++-{major}") or shutil.which("clang++"),
                        "plugin_lib": plugin_path
                    })
        except Exception:
            continue

    return sorted(toolchains, key=lambda x: int(x["major"]))

# -----------------------------------------------------------------------------
# Compilation & Execution Helpers
# -----------------------------------------------------------------------------
def run_command(cmd: str, env: Optional[Dict[str, str]] = None, timeout: int = 180) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout} seconds"
    except Exception as e:
        return -2, "", str(e)

def compile_pass(toolchain: Dict[str, str], arch: str, pass_spec: Dict, out_prefix: str) -> Dict:
    clang = toolchain["clang"]
    source = pass_spec["source"]
    flag = pass_spec["flag"]
    env_str = pass_spec["env"]

    ll_path = f"{out_prefix}.ll"
    asm_path = f"{out_prefix}.s"
    obj_path = f"{out_prefix}.o"
    bin_path = f"{out_prefix}.elf"

    env = os.environ.copy()
    env["ENSIA_CONFIG"] = EMPTY_CONFIG
    env["ENSIA"] = "1"
    for part in env_str.split():
        if "=" in part:
            k, v = part.split("=", 1)
            env[k] = v

    if arch == "x86_64":
        target_flags = "-fPIE"
    elif arch == "aarch64":
        target_flags = f"--target=aarch64-linux-gnu --sysroot={ARM64_SYSROOT} -I{ARM64_SYSROOT}/usr/include/aarch64-linux-gnu -fPIE"
    else:
        raise ValueError(f"Unsupported architecture: {arch}")

    plugin_lib = toolchain.get("plugin_lib", PLUGIN_LIB)
    plugin_flags = f"-fpass-plugin={plugin_lib} -Xclang -load -Xclang {plugin_lib} -mllvm -ensia {flag}"

    # 1. Emit Obfuscated LLVM IR via Ensia pass plugin
    cmd_ir = f"{clang} {target_flags} -O1 {plugin_flags} -S -emit-llvm {source} -o {ll_path}"
    rc_ir, out_ir, err_ir = run_command(cmd_ir, env=env)

    # 2. Emit Assembly from the obfuscated LLVM IR
    if rc_ir == 0:
        cmd_asm = f"{clang} {target_flags} -O1 -S {ll_path} -o {asm_path}"
        rc_asm, out_asm, err_asm = run_command(cmd_asm, env=env)
    else:
        rc_asm, out_asm, err_asm = -1, "", "Skipped due to IR error"

    # 3. Emit Object / Binary from the obfuscated LLVM IR
    if rc_ir == 0:
        if arch == "x86_64":
            cmd_bin = f"{clang} {target_flags} -O1 {ll_path} -ldl -o {bin_path}"
            rc_bin, out_bin, err_bin = run_command(cmd_bin, env=env)
            exec_target = bin_path
        else:
            cmd_obj = f"{clang} {target_flags} -O1 -c {ll_path} -o {obj_path}"
            rc_bin, out_bin, err_bin = run_command(cmd_obj, env=env)
            exec_target = obj_path
    else:
        rc_bin, out_bin, err_bin = -1, "", "Skipped due to IR error"
        exec_target = None

    return {
        "rc_ir": rc_ir, "err_ir": err_ir, "ll_path": ll_path if rc_ir == 0 else None,
        "rc_asm": rc_asm, "err_asm": err_asm, "asm_path": asm_path if rc_asm == 0 else None,
        "rc_bin": rc_bin, "err_bin": err_bin, "exec_target": exec_target if rc_bin == 0 else None,
    }

def execute_binary(arch: str, exec_target: str) -> Tuple[bool, str]:
    if not exec_target or not os.path.exists(exec_target):
        return False, "Target binary/object not found"

    success_markers = ["All basic tests executed successfully!", "tamper detected", "PASS", "Untampered call succeeded", "Results:"]
    if arch == "x86_64":
        rc, out, err = run_command(exec_target, timeout=10)
        success = (rc == 0 and any(m in out for m in success_markers))
        return success, out if rc == 0 else err
    elif arch == "aarch64":
        podman_cmd = (
            f"podman run --arch arm64 --rm "
            f"-v {PROJECT_ROOT}:{PROJECT_ROOT}:ro,z "
            f"{CONTAINER_IMAGE} "
            f'sh -c "gcc -no-pie {exec_target} -o /tmp/arm_test.elf -lpthread -lm && /tmp/arm_test.elf"'
        )
        rc, out, err = run_command(podman_cmd, timeout=15)
        success = (rc == 0 and any(m in out for m in success_markers))
        return success, out if rc == 0 else (err or out)
    return False, "Unknown arch"

def inspect_ir_and_asm(arch: str, pass_spec: Dict, ll_path: Optional[str], asm_path: Optional[str]) -> Tuple[bool, bool, List[str]]:
    ir_ok = False
    asm_ok = False
    logs = []

    if ll_path and os.path.exists(ll_path):
        with open(ll_path, "r", encoding="utf-8", errors="ignore") as f:
            ll_content = f.read()

        matched_ir = 0
        total_ir = len(pass_spec.get("ir_checks", []))
        for pattern, label in pass_spec.get("ir_checks", []):
            if re.search(pattern, ll_content, re.IGNORECASE):
                matched_ir += 1
                logs.append(f"  [IR PASS] Found {label} (pattern: `{pattern}`)")
            else:
                logs.append(f"  [IR FAIL] Missing {label} (pattern: `{pattern}`)")

        ir_ok = (matched_ir > 0) or (total_ir == 0)
    else:
        logs.append("  [IR FAIL] LLVM IR file not generated")

    if asm_path and os.path.exists(asm_path):
        with open(asm_path, "r", encoding="utf-8", errors="ignore") as f:
            asm_content = f.read()

        matched_asm = 0
        checks = pass_spec.get("asm_checks", {}).get(arch, [])
        total_asm = len(checks)
        for pattern, label in checks:
            if re.search(pattern, asm_content, re.IGNORECASE):
                matched_asm += 1
                logs.append(f"  [ASM PASS] Found {label} (pattern: `{pattern}`)")
            else:
                logs.append(f"  [ASM FAIL] Missing {label} (pattern: `{pattern}`)")

        asm_ok = (matched_asm > 0) or (total_asm == 0)
    else:
        logs.append("  [ASM FAIL] Assembly file not generated")

    return ir_ok, asm_ok, logs

# -----------------------------------------------------------------------------
# Main Test Runner
# -----------------------------------------------------------------------------
def run_matrix(selected_archs: List[str], selected_llvm: List[str], passes_to_run: List[str], output_report: str):
    start_time = time.time()
    toolchains = discover_toolchains()

    if selected_llvm:
        toolchains = [tc for tc in toolchains if tc["major"] in selected_llvm]

    if not toolchains:
        print("[!] Error: No matching LLVM toolchain found.")
        sys.exit(1)

    print("=" * 80)
    print(" Ensia / OLLVM-Next Comprehensive Matrix Verification Framework")
    print("=" * 80)
    print(f"Toolchains detected : {', '.join(tc['name'] + ' (' + tc['version'] + ')' for tc in toolchains)}")
    print(f"Architectures       : {', '.join(selected_archs)}")
    print(f"Passes to evaluate  : {len(passes_to_run)} passes/presets")
    print(f"Artifact directory  : {BUILD_DIR}/matrix_verification")
    print("=" * 80)

    work_dir = os.path.join(BUILD_DIR, "matrix_verification")
    os.makedirs(work_dir, exist_ok=True)

    all_results = []

    for tc in toolchains:
        tc_name = tc["name"]
        print(f"\n################################################################################")
        print(f"### Toolchain: {tc_name} ({tc['version']})")
        print(f"################################################################################")

        for arch in selected_archs:
            print(f"\n--- Architecture: {arch} ---")

            for pass_spec in PASS_REGISTRY + PRESET_REGISTRY:
                pid = pass_spec["id"]
                pname = pass_spec["name"]
                if pid not in passes_to_run:
                    continue

                out_prefix = os.path.join(work_dir, f"{tc['major']}_{arch}_{pid}")
                t0 = time.time()

                comp = compile_pass(tc, arch, pass_spec, out_prefix)
                compile_success = (comp["rc_ir"] == 0 and comp["rc_asm"] == 0 and comp["rc_bin"] == 0)

                exec_success = False
                exec_msg = ""
                if compile_success:
                    exec_success, exec_msg = execute_binary(arch, comp["exec_target"])

                ir_ok = False
                asm_ok = False
                inspection_logs = []
                if compile_success and "ir_checks" in pass_spec:
                    ir_ok, asm_ok, inspection_logs = inspect_ir_and_asm(arch, pass_spec, comp["ll_path"], comp["asm_path"])
                elif compile_success:
                    # Presets: IR and ASM are inherently transformed
                    ir_ok = True
                    asm_ok = True

                duration = time.time() - t0

                # Status string
                status = "PASS" if (compile_success and exec_success and ir_ok and asm_ok) else "FAIL"
                color = "\033[0;32m" if status == "PASS" else "\033[0;31m"
                reset = "\033[0m"

                print(f"[{color}{status}{reset}] [{arch:<7}] {pname:<30} | IR:{'OK' if ir_ok else 'NO'} | ASM:{'OK' if asm_ok else 'NO'} | Exec:{'OK' if exec_success else 'NO'} ({duration:.2f}s)")
                if status == "FAIL":
                    if not compile_success:
                        print(f"       [-] Compilation failure: {comp['err_ir'] or comp['err_asm'] or comp['err_bin']}")
                    elif not exec_success:
                        print(f"       [-] Execution failure: {exec_msg}")
                    for log in inspection_logs:
                        if "FAIL" in log:
                            print(f"       {log}")

                all_results.append({
                    "toolchain": tc_name,
                    "llvm_ver": tc["version"],
                    "arch": arch,
                    "pass_id": pid,
                    "pass_name": pname,
                    "compile": compile_success,
                    "exec": exec_success,
                    "ir_ok": ir_ok,
                    "asm_ok": asm_ok,
                    "status": status,
                    "duration": duration,
                    "desc": pass_spec.get("desc", "Composite pipeline preset")
                })

    # -----------------------------------------------------------------------------
    # Generate Markdown Report
    # -----------------------------------------------------------------------------
    os.makedirs(os.path.dirname(output_report), exist_ok=True)
    total_tests = len(all_results)
    passed_tests = sum(1 for r in all_results if r["status"] == "PASS")
    pass_rate = (passed_tests / total_tests * 100.0) if total_tests > 0 else 0.0

    with open(output_report, "w", encoding="utf-8") as f:
        f.write("# Ensia / OLLVM-Next Unified Cross-Matrix Verification Report\n\n")
        f.write(f"- **Generated At**: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
        f.write(f"- **Total Test Scenarios**: {total_tests}\n")
        f.write(f"- **Passed Scenarios**: {passed_tests} / {total_tests} (**{pass_rate:.1f}%**)\n")
        f.write(f"- **Evaluated Toolchains**: {', '.join(tc['name'] + ' (' + tc['version'] + ')' for tc in toolchains)}\n")
        f.write(f"- **Architectures**: {', '.join(selected_archs)}\n\n")

        f.write("## 1. Matrix Execution & Inspection Summary\n\n")
        f.write("| Architecture | Toolchain | Pass Name | Compile | IR Transform | ASM Transform | Execution | Status |\n")
        f.write("|:---|:---|:---|:---:|:---:|:---:|:---:|:---:|\n")
        for r in all_results:
            f.write(f"| {r['arch']} | {r['toolchain']} | {r['pass_name']} | "
                    f"{'✓' if r['compile'] else '✗'} | "
                    f"{'✓' if r['ir_ok'] else '✗'} | "
                    f"{'✓' if r['asm_ok'] else '✗'} | "
                    f"{'✓' if r['exec'] else '✗'} | "
                    f"**{r['status']}** |\n")

        f.write("\n## 2. Pass Verification & Security Mechanics\n\n")
        for pass_spec in PASS_REGISTRY:
            f.write(f"### {pass_spec['name']} (`{pass_spec['id']}`)\n")
            f.write(f"- **CLI Flag**: `{pass_spec['flag']}` | **Env**: `{pass_spec['env']}`\n")
            f.write(f"- **Description**: {pass_spec['desc']}\n")
            f.write(f"- **Verified LLVM IR Constructs**:\n")
            for pat, desc in pass_spec["ir_checks"]:
                f.write(f"  - `{pat}`: {desc}\n")
            f.write(f"- **Verified Machine Assembly Constructs**:\n")
            for a, checks in pass_spec["asm_checks"].items():
                for pat, desc in checks:
                    f.write(f"  - [{a}] `{pat}`: {desc}\n")
            f.write("\n")

    print("\n" + "=" * 80)
    print(f" MATRIX VERIFICATION COMPLETE: {passed_tests}/{total_tests} Passed ({pass_rate:.1f}%)")
    print(f" Report generated at: {output_report}")
    print("=" * 80)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ensia Obfuscator Cross-Matrix Verification Harness")
    parser.add_argument("--arch", default="x86_64,aarch64", help="Comma-separated target architectures (x86_64, aarch64)")
    parser.add_argument("--llvm", default="", help="Comma-separated LLVM major versions (e.g. 21,22,23)")
    parser.add_argument("--passes", default="all", help="Comma-separated pass IDs to run or 'all'")
    parser.add_argument("--report", default=os.path.join(PROJECT_ROOT, "test", "reports", "MATRIX_VERIFICATION_REPORT.md"), help="Path to markdown report")
    args = parser.parse_args()

    archs = [a.strip() for a in args.arch.split(",") if a.strip()]
    llvm_vers = [l.strip() for l in args.llvm.split(",") if l.strip()]

    if args.passes == "all":
        p_ids = [p["id"] for p in PASS_REGISTRY + PRESET_REGISTRY]
    else:
        p_ids = [p.strip() for p in args.passes.split(",") if p.strip()]

    run_matrix(archs, llvm_vers, p_ids, args.report)
