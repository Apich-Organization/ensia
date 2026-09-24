#!/usr/bin/env python3
"""
Ensia Binary ASM to LLVM IR Lifter & Deobfuscation Analyzer
Lifts x86-64 machine code from compiled ELF objects into LLVM IR,
then executes LLVM optimization passes to evaluate obfuscation resilience.
"""

import sys
import os
import re
import subprocess
import capstone
from capstone import x86

REG_MAP_64 = {
    x86.X86_REG_RAX: "rax", x86.X86_REG_EAX: "rax",
    x86.X86_REG_RCX: "rcx", x86.X86_REG_ECX: "rcx",
    x86.X86_REG_RDX: "rdx", x86.X86_REG_EDX: "rdx",
    x86.X86_REG_RBX: "rbx", x86.X86_REG_EBX: "rbx",
    x86.X86_REG_RSI: "rsi", x86.X86_REG_ESI: "rsi",
    x86.X86_REG_RDI: "rdi", x86.X86_REG_EDI: "rdi",
    x86.X86_REG_RBP: "rbp", x86.X86_REG_EBP: "rbp",
    x86.X86_REG_RSP: "rsp", x86.X86_REG_ESP: "rsp",
    x86.X86_REG_R8:  "r8",  x86.X86_REG_R8D: "r8",
    x86.X86_REG_R9:  "r9",  x86.X86_REG_R9D: "r9",
    x86.X86_REG_R10: "r10", x86.X86_REG_R10D: "r10",
    x86.X86_REG_R11: "r11", x86.X86_REG_R11D: "r11",
    x86.X86_REG_R12: "r12", x86.X86_REG_R12D: "r12",
    x86.X86_REG_R13: "r13", x86.X86_REG_R13D: "r13",
    x86.X86_REG_R14: "r14", x86.X86_REG_R14D: "r14",
    x86.X86_REG_R15: "r15", x86.X86_REG_R15D: "r15",
}

ALL_REGS = ["rax", "rcx", "rdx", "rbx", "rsi", "rdi", "rbp", "rsp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

def get_symbol_bytes(obj_path, symbol_name):
    """Extract raw machine bytes of a symbol using llvm-objdump."""
    cmd = ["llvm-objdump", "-d", f"--disassemble-symbols={symbol_name}", obj_path]
    out = subprocess.check_output(cmd, text=True)
    
    insns = []
    in_symbol = False
    for line in out.splitlines():
        if f"<{symbol_name}>:" in line:
            in_symbol = True
            continue
        if in_symbol:
            if not line.strip() or (line.endswith(">:") and "<" in line):
                if insns: break
                continue
            if ":" in line:
                addr, rest = line.split(":", 1)
                parts = rest.split("\t")
                hex_part = parts[0].strip()
                try:
                    b_list = bytes([int(b, 16) for b in hex_part.split()])
                    insns.append(b_list)
                except ValueError:
                    pass
    return b"".join(insns)

def lift_function_to_ll(obj_path, symbol_name, num_args=2, preserve_barrier=True):
    raw_bytes = get_symbol_bytes(obj_path, symbol_name)
    if not raw_bytes:
        raise ValueError(f"Symbol {symbol_name} not found or empty in {obj_path}")
        
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cs.detail = True
    
    ir_lines = []
    ir_lines.append("; Lifted LLVM IR for function: " + symbol_name)
    ir_lines.append("; Source: " + obj_path)
    
    # Declare external RIP-relative memory accessors
    ir_lines.append("declare i32 @__read_rip_data_i32(i64)")
    ir_lines.append("declare i64 @__read_rip_data_i64(i64)")
    ir_lines.append("declare void @__write_rip_data_i32(i64, i32)")
    ir_lines.append("declare void @__write_rip_data_i64(i64, i64)")
    ir_lines.append("declare i64 @__external_call()")
    ir_lines.append("declare i32 @__get_flag()")
    ir_lines.append("declare void @__branch_barrier()")
    ir_lines.append("declare void @__simd_barrier()")
    
    # Declare function signature
    args_sig = ", ".join([f"i32 %arg{i}" for i in range(num_args)])
    ir_lines.append(f"define dso_local i32 @{symbol_name}({args_sig}) {{")
    ir_lines.append("entry:")
    
    # Allocate virtual registers (64-bit)
    for reg in ALL_REGS:
        ir_lines.append(f"  %{reg}_ptr = alloca i64, align 8")
        ir_lines.append(f"  store i64 0, ptr %{reg}_ptr, align 8")
        
    # Allocate stack memory frame (4KB)
    ir_lines.append("  %stack_frame = alloca [4096 x i8], align 16")
    ir_lines.append("  %rsp_base = getelementptr inbounds [4096 x i8], ptr %stack_frame, i32 0, i32 2048")
    ir_lines.append("  %rsp_base_i64 = ptrtoint ptr %rsp_base to i64")
    ir_lines.append("  store i64 %rsp_base_i64, ptr %rsp_ptr, align 8")
    
    # Initialize incoming arguments (%rdi, %rsi, %rdx, ...)
    arg_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
    for i in range(min(num_args, len(arg_regs))):
        reg = arg_regs[i]
        ir_lines.append(f"  %init_arg{i} = zext i32 %arg{i} to i64")
        ir_lines.append(f"  store i64 %init_arg{i}, ptr %{reg}_ptr, align 8")
        
    v_cnt = 0
    def next_var():
        nonlocal v_cnt
        v_cnt += 1
        return f"%v{v_cnt}"
        
    # Lift instructions
    for insn in cs.disasm(raw_bytes, 0x1000):
        mnemonic = insn.mnemonic
        op_str = insn.op_str
        operands = insn.operands
        
        # Helper to resolve an operand to an i32/i64 Value
        def read_op(op, is_32bit=True):
            nonlocal v_cnt
            if op.type == x86.X86_OP_IMM:
                val = op.imm
                # clamp to 32/64 bit signed
                return f"{val & 0xFFFFFFFF}" if is_32bit else f"{val}"
            elif op.type == x86.X86_OP_REG:
                reg_name = REG_MAP_64.get(op.reg, None)
                if not reg_name: return "0"
                v_load = next_var()
                ir_lines.append(f"  {v_load} = load i64, ptr %{reg_name}_ptr, align 8")
                if is_32bit:
                    v_trunc = next_var()
                    ir_lines.append(f"  {v_trunc} = trunc i64 {v_load} to i32")
                    return v_trunc
                return v_load
            elif op.type == x86.X86_OP_MEM:
                base_reg = REG_MAP_64.get(op.mem.base, None)
                disp = op.mem.disp
                val_type = "i32" if is_32bit else "i64"
                if base_reg in ("rsp", "rbp"):
                    v_ptr = next_var()
                    ir_lines.append(f"  {v_ptr} = getelementptr inbounds i8, ptr %rsp_base, i32 {disp}")
                    v_val = next_var()
                    ir_lines.append(f"  {v_val} = load {val_type}, ptr {v_ptr}, align 4")
                    return v_val
                else:
                    # RIP-relative or external global memory access
                    v_val = next_var()
                    fn_suffix = "i32" if is_32bit else "i64"
                    ir_lines.append(f"  {v_val} = call {val_type} @__read_rip_data_{fn_suffix}(i64 {disp})")
                    return v_val
            return "0"
            
        def write_dst(op, val_str, is_32bit=True):
            nonlocal v_cnt
            if op.type == x86.X86_OP_REG:
                reg_name = REG_MAP_64.get(op.reg, None)
                if not reg_name: return
                if is_32bit:
                    v_zext = next_var()
                    ir_lines.append(f"  {v_zext} = zext i32 {val_str} to i64")
                    ir_lines.append(f"  store i64 {v_zext}, ptr %{reg_name}_ptr, align 8")
                else:
                    ir_lines.append(f"  store i64 {val_str}, ptr %{reg_name}_ptr, align 8")
            elif op.type == x86.X86_OP_MEM:
                base_reg = REG_MAP_64.get(op.mem.base, None)
                disp = op.mem.disp
                val_type = "i32" if is_32bit else "i64"
                if base_reg in ("rsp", "rbp"):
                    v_ptr = next_var()
                    ir_lines.append(f"  {v_ptr} = getelementptr inbounds i8, ptr %rsp_base, i32 {disp}")
                    ir_lines.append(f"  store {val_type} {val_str}, ptr {v_ptr}, align 4")
                else:
                    fn_suffix = "i32" if is_32bit else "i64"
                    ir_lines.append(f"  call void @__write_rip_data_{fn_suffix}(i64 {disp}, {val_type} {val_str})")
                
        # Dispatch mnemonics
        if mnemonic in ("nop", "nopl", "nopw"):
            continue
        elif mnemonic == "ret":
            # Return %rax truncated to i32
            v_rax = next_var()
            ir_lines.append(f"  {v_rax} = load i64, ptr %rax_ptr, align 8")
            v_ret = next_var()
            ir_lines.append(f"  {v_ret} = trunc i64 {v_rax} to i32")
            ir_lines.append(f"  ret i32 {v_ret}")
            break
        elif mnemonic == "mov":
            is_32 = operands[0].size <= 4
            src = read_op(operands[1], is_32bit=is_32)
            write_dst(operands[0], src, is_32bit=is_32)
        elif mnemonic in ("add", "sub", "imul", "and", "or", "xor"):
            llvm_op = {"add": "add", "sub": "sub", "imul": "mul", "and": "and", "or": "or", "xor": "xor"}[mnemonic]
            # Special check: xorb $0, [mem] -> barrier
            if mnemonic == "xor" and operands[0].type == x86.X86_OP_MEM and operands[1].type == x86.X86_OP_IMM and operands[1].imm == 0:
                if preserve_barrier:
                    # Model as memory barrier asm sideeffect
                    base_reg = REG_MAP_64.get(operands[0].mem.base, "rsp")
                    disp = operands[0].mem.disp
                    v_p = next_var()
                    ir_lines.append(f"  {v_p} = getelementptr inbounds i8, ptr %rsp_base, i32 {disp}")
                    ir_lines.append(f'  call void asm sideeffect "xorb $$0, $0", "=*m,~{{memory}}"(ptr elementtype(i8) {v_p})')
                continue
            is_32 = operands[0].size <= 4
            dst_val = read_op(operands[0], is_32bit=is_32)
            src_val = read_op(operands[1], is_32bit=is_32)
            v_res = next_var()
            t_str = "i32" if is_32 else "i64"
            ir_lines.append(f"  {v_res} = {llvm_op} {t_str} {dst_val}, {src_val}")
            write_dst(operands[0], v_res, is_32bit=is_32)
        elif mnemonic in ("shl", "shr", "sar"):
            is_32 = operands[0].size <= 4
            dst_val = read_op(operands[0], is_32bit=is_32)
            shift_op = {"shl": "shl", "shr": "lshr", "sar": "ashr"}[mnemonic]
            t_str = "i32" if is_32 else "i64"
            if operands[1].type == x86.X86_OP_IMM:
                sh_amt = operands[1].imm
                v_res = next_var()
                ir_lines.append(f"  {v_res} = {shift_op} {t_str} {dst_val}, {sh_amt}")
                write_dst(operands[0], v_res, is_32bit=is_32)
        elif mnemonic == "lea":
            is_32 = operands[0].size <= 4
            t_str = "i32" if is_32 else "i64"
            base_reg = REG_MAP_64.get(operands[1].mem.base, None)
            idx_reg = REG_MAP_64.get(operands[1].mem.index, None)
            scale = operands[1].mem.scale
            disp = operands[1].mem.disp
            
            # compute disp + base + index * scale
            v_curr = next_var()
            ir_lines.append(f"  {v_curr} = add {t_str} 0, {disp}")
            if base_reg:
                v_b_load = next_var()
                ir_lines.append(f"  {v_b_load} = load i64, ptr %{base_reg}_ptr, align 8")
                if is_32:
                    v_b = next_var()
                    ir_lines.append(f"  {v_b} = trunc i64 {v_b_load} to i32")
                else:
                    v_b = v_b_load
                v_curr2 = next_var()
                ir_lines.append(f"  {v_curr2} = add {t_str} {v_curr}, {v_b}")
                v_curr = v_curr2
            if idx_reg:
                v_i_load = next_var()
                ir_lines.append(f"  {v_i_load} = load i64, ptr %{idx_reg}_ptr, align 8")
                if is_32:
                    v_i = next_var()
                    ir_lines.append(f"  {v_i} = trunc i64 {v_i_load} to i32")
                else:
                    v_i = v_i_load
                v_mul = next_var()
                ir_lines.append(f"  {v_mul} = mul {t_str} {v_i}, {scale}")
                v_curr3 = next_var()
                ir_lines.append(f"  {v_curr3} = add {t_str} {v_curr}, {v_mul}")
                v_curr = v_curr3
            write_dst(operands[0], v_curr, is_32bit=is_32)
        elif mnemonic == "call":
            v_call = next_var()
            ir_lines.append(f"  {v_call} = call i64 @__external_call()")
            ir_lines.append(f"  store i64 {v_call}, ptr %rax_ptr, align 8")
        elif mnemonic in ("cmp", "test"):
            is_32 = operands[0].size <= 4
            t_str = "i32" if is_32 else "i64"
            v0 = read_op(operands[0], is_32bit=is_32)
            v1 = read_op(operands[1], is_32bit=is_32)
            v_cmp = next_var()
            ir_lines.append(f"  {v_cmp} = sub {t_str} {v0}, {v1}")
        elif mnemonic.startswith("set"):
            v_set = next_var()
            ir_lines.append(f"  {v_set} = call i32 @__get_flag()")
            write_dst(operands[0], v_set, is_32bit=True)
        elif mnemonic.startswith("j"):
            ir_lines.append(f"  call void @__branch_barrier()")
        elif mnemonic.startswith("p") or mnemonic in ("movaps", "movups", "movd", "shufps", "movsd"):
            ir_lines.append(f"  call void @__simd_barrier()")
            
    if not ir_lines[-1].strip().startswith("ret"):
        v_rax = next_var()
        ir_lines.append(f"  {v_rax} = load i64, ptr %rax_ptr, align 8")
        v_ret = next_var()
        ir_lines.append(f"  {v_ret} = trunc i64 {v_rax} to i32")
        ir_lines.append(f"  ret i32 {v_ret}")
    ir_lines.append("}\n")
    return "\n".join(ir_lines)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: asm_lifter.py <obj_path> <symbol_name> [num_args]")
        sys.exit(1)
    obj = sys.argv[1]
    sym = sys.argv[2]
    nargs = int(sys.argv[3]) if len(sys.argv) > 3 else 2
    ll = lift_function_to_ll(obj, sym, nargs)
    print(ll)
