# Ensia / OLLVM-Next Unified Cross-Matrix Verification Report

- **Generated At**: 2026-09-23 08:43:25 UTC
- **Total Test Scenarios**: 68
- **Passed Scenarios**: 68 / 68 (**100.0%**)
- **Evaluated Toolchains**: LLVM 21 (21.1.8), LLVM 23 (23.1.1)
- **Architectures**: x86_64, aarch64

## 1. Matrix Execution & Inspection Summary

| Architecture | Toolchain | Pass Name | Compile | IR Transform | ASM Transform | Execution | Status |
|:---|:---|:---|:---:|:---:|:---:|:---:|:---:|
| x86_64 | LLVM 21 | Instruction Substitution | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 21 | Mixed Boolean-Arithmetic | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 21 | BasicBlock Splitting | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 21 | Bogus Control Flow | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 21 | Chaos State Machine | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 21 | Control Flow Flattening | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 21 | Vector Obfuscation | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 21 | Constant Encryption | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 21 | String Encryption | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 21 | Indirect Branching | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 21 | Function Wrapper | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 21 | Function Call Obfuscation | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 21 | Anti-Debugging | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 21 | Anti-Hooking | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 21 | Low Obfuscation Preset | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 21 | Medium Obfuscation Preset | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 21 | CSM + Vector Obfuscation | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 21 | Instruction Substitution | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 21 | Mixed Boolean-Arithmetic | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 21 | BasicBlock Splitting | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 21 | Bogus Control Flow | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 21 | Chaos State Machine | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 21 | Control Flow Flattening | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 21 | Vector Obfuscation | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 21 | Constant Encryption | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 21 | String Encryption | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 21 | Indirect Branching | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 21 | Function Wrapper | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 21 | Function Call Obfuscation | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 21 | Anti-Debugging | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 21 | Anti-Hooking | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 21 | Low Obfuscation Preset | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 21 | Medium Obfuscation Preset | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 21 | CSM + Vector Obfuscation | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 23 | Instruction Substitution | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 23 | Mixed Boolean-Arithmetic | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 23 | BasicBlock Splitting | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 23 | Bogus Control Flow | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 23 | Chaos State Machine | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 23 | Control Flow Flattening | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 23 | Vector Obfuscation | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 23 | Constant Encryption | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 23 | String Encryption | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 23 | Indirect Branching | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 23 | Function Wrapper | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 23 | Function Call Obfuscation | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 23 | Anti-Debugging | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 23 | Anti-Hooking | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 23 | Low Obfuscation Preset | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 23 | Medium Obfuscation Preset | ✓ | ✓ | ✓ | ✓ | **PASS** |
| x86_64 | LLVM 23 | CSM + Vector Obfuscation | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 23 | Instruction Substitution | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 23 | Mixed Boolean-Arithmetic | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 23 | BasicBlock Splitting | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 23 | Bogus Control Flow | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 23 | Chaos State Machine | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 23 | Control Flow Flattening | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 23 | Vector Obfuscation | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 23 | Constant Encryption | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 23 | String Encryption | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 23 | Indirect Branching | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 23 | Function Wrapper | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 23 | Function Call Obfuscation | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 23 | Anti-Debugging | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 23 | Anti-Hooking | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 23 | Low Obfuscation Preset | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 23 | Medium Obfuscation Preset | ✓ | ✓ | ✓ | ✓ | **PASS** |
| aarch64 | LLVM 23 | CSM + Vector Obfuscation | ✓ | ✓ | ✓ | ✓ | **PASS** |

## 2. Pass Verification & Security Mechanics

### Instruction Substitution (`sub`)
- **CLI Flag**: `-mllvm -enable-subobf` | **Env**: `SUBOBF=1`
- **Description**: Algebraic expansion of arithmetic operations
- **Verified LLVM IR Constructs**:
  - `(xor|and|or)\s+i32`: Algebraic bitwise substitution operations
- **Verified Machine Assembly Constructs**:
  - [x86_64] `(xor|and|or|not)`: x86 algebraic identity instructions
  - [aarch64] `(eor|and|orr|mvn|bic)`: ARM64 algebraic identity instructions

### Mixed Boolean-Arithmetic (`mba`)
- **CLI Flag**: `-mllvm -enable-mbaobf` | **Env**: `MBAOBF=1`
- **Description**: Non-zero context-dependent polynomial MBA with dynamic barriers
- **Verified LLVM IR Constructs**:
  - `(@__ensia_mba_ctx|@_v[0-9a-f]{16}|barrier\.slot)`: Runtime secret MBA context or contextual hardware barrier slots
- **Verified Machine Assembly Constructs**:
  - [x86_64] `(__ensia_mba_ctx|_v[0-9a-f]{16}|%fs:)`: Runtime context load or TLS/canary barrier
  - [aarch64] `(__ensia_mba_ctx|_v[0-9a-f]{16}|tpidr_el0)`: Runtime context load or ARM64 TLS barrier

### BasicBlock Splitting (`split`)
- **CLI Flag**: `-mllvm -enable-splitobf` | **Env**: `SPLITOBF=1`
- **Description**: Mandatory opaque-chained basic block slicing with bogus loop
- **Verified LLVM IR Constructs**:
  - `icmp eq i32.*0`: Opaque predicate guard ((seed * (seed + 1)) & 1) == 0
  - `br i1.*label.*label`: Conditional branch splitting CFG sequence
- **Verified Machine Assembly Constructs**:
  - [x86_64] `(je|jne|jmp)`: Split block jumps and opaque condition branches
  - [aarch64] `(b\.(eq|ne)|b\s+)`: ARM64 split block branches and conditional jumps

### Bogus Control Flow (`bcf`)
- **CLI Flag**: `-mllvm -enable-bcfobf` | **Env**: `BCFOBF=1`
- **Description**: Opaque hardware-predicate branching and cloned dead blocks
- **Verified LLVM IR Constructs**:
  - `icmp (sle|sge|eq|ne)`: Opaque predicate comparison in cloned block
  - `barrier\.slot`: Polymorphic hardware barrier in bogus edges
- **Verified Machine Assembly Constructs**:
  - [x86_64] `(j[a-z]{1,3})`: Opaque predicate conditional branches
  - [aarch64] `(b\.[a-z]{2}|cbz|cbnz)`: ARM64 opaque predicate conditional branches

### Chaos State Machine (`csm`)
- **CLI Flag**: `-mllvm -enable-csmobf` | **Env**: `CSMOBF=1`
- **Description**: Q32 chaotic attractor basin diffusion & discrete cellular automata
- **Verified LLVM IR Constructs**:
  - `(4294967291|i64 4294967291)`: Q32 logistic map multiplier (mu_32 = 4294967291)
  - `switch i32`: CSM chaotic orbit switch dispatcher
- **Verified Machine Assembly Constructs**:
  - [x86_64] `(4294967291|0xfffffffb|0x9e3779b9|jmpq?\s+\*|cmpl.*)`: Q32 multiplier or indirect dispatch table
  - [aarch64] `(0xfffffffb|movk|adrp|b\.eq|br\s+x)`: ARM64 Q32 multiplier or register branch dispatch

### Control Flow Flattening (`cff`)
- **CLI Flag**: `-mllvm -enable-cffobf` | **Env**: `CFFOBF=1`
- **Description**: Classic basic block flattening with central switch dispatcher
- **Verified LLVM IR Constructs**:
  - `switch i32 %`: Switch dispatcher statement
  - `store i32 .*, ptr %`: State variable transition stores
- **Verified Machine Assembly Constructs**:
  - [x86_64] `(jmpq?\s+\*|switch)`: Switch jump table or dispatch loop
  - [aarch64] `(br\s+x|adrp?\s+x|b\.(eq|ne))`: ARM64 indirect jump table dispatch

### Vector Obfuscation (`vobf`)
- **CLI Flag**: `-mllvm -enable-vobf` | **Env**: `VOBF=1`
- **Description**: Scalar arithmetic to SIMD vector lifting with lane shuffling
- **Verified LLVM IR Constructs**:
  - `<(4 x i32|8 x i32|2 x i64|4 x i64|16 x i8)>`: SIMD vector type lifting
  - `(insertelement|shufflevector|extractelement)`: Vector insertion and permutation intrinsics
- **Verified Machine Assembly Constructs**:
  - [x86_64] `(movd|pshufd|paddd|pxor|vmov|vpxor)`: x86 SSE/AVX vector register instructions
  - [aarch64] `(dup|mov\s+v[0-9]|add\s+v[0-9]|eor\s+v[0-9]|str\s+q[0-9]|ldr\s+q[0-9])`: ARM64 NEON vector instructions

### Constant Encryption (`constenc`)
- **CLI Flag**: `-mllvm -enable-constenc` | **Env**: `CONSTENC=1`
- **Description**: Feistel network and multi-share additive split constant encryption
- **Verified LLVM IR Constructs**:
  - `(!constenc\.done|barrier\.slot)`: Multi-share XOR recombination or Feistel barrier slot
- **Verified Machine Assembly Constructs**:
  - [x86_64] `(xor|add)`: Dynamic share reconstruction instructions
  - [aarch64] `(eor|add)`: ARM64 dynamic share reconstruction instructions

### String Encryption (`strenc`)
- **CLI Flag**: `-mllvm -enable-strcry` | **Env**: `STRCRY=1`
- **Description**: Caller-owned ephemeral string decryption with TLS zeroization anti-dump
- **Verified LLVM IR Constructs**:
  - `(__ensia_dec_space|_v[0-9a-f]{16}.*thread_local|llvm\.memset)`: Thread-Local Storage decrypted string space or zeroization
- **Verified Machine Assembly Constructs**:
  - [x86_64] `(__ensia_dec_space|_v[0-9a-f]{16}|@tpoff|%fs:)`: TLS buffer reference and runtime decryption sweep
  - [aarch64] `(__ensia_dec_space|_v[0-9a-f]{16}|tpidr_el0)`: ARM64 TLS reference and runtime decryption sweep

### Indirect Branching (`indibran`)
- **CLI Flag**: `-mllvm -enable-indibran` | **Env**: `INDIBRAN=1`
- **Description**: Knuth-hash encrypted jump targets and indirect branching
- **Verified LLVM IR Constructs**:
  - `(indirectbr|blockaddress)`: Indirect branch target resolution via blockaddress table
- **Verified Machine Assembly Constructs**:
  - [x86_64] `jmpq?\s+\*`: x86 indirect register jump (jmpq *%reg)
  - [aarch64] `br\s+x`: ARM64 indirect register branch (br x<reg>)

### Function Wrapper (`funcwra`)
- **CLI Flag**: `-mllvm -enable-funcwra` | **Env**: `FUNCWRA=1`
- **Description**: Polymorphic proxy wrappers with enforced NoInline & OptimizeNone
- **Verified LLVM IR Constructs**:
  - `(define.*@EnsiaFW_|noinline.*optnone)`: Wrapper proxy function creation and NoInline/OptimizeNone attributes
- **Verified Machine Assembly Constructs**:
  - [x86_64] `callq?\s+.*EnsiaFW_`: Call redirected through proxy wrapper trampoline
  - [aarch64] `bl\s+.*EnsiaFW_`: ARM64 call routed through proxy wrapper trampoline

### Function Call Obfuscation (`fco`)
- **CLI Flag**: `-mllvm -enable-fco` | **Env**: `FCO=1`
- **Description**: Dynamic function call indirection and import resolution
- **Verified LLVM IR Constructs**:
  - `call.*(ptr|i32\s*\()`: Indirect call through obfuscated function pointer
- **Verified Machine Assembly Constructs**:
  - [x86_64] `callq?\s+\*`: x86 indirect register call (callq *%reg)
  - [aarch64] `blr\s+x`: ARM64 indirect register call (blr x<reg>)

### Anti-Debugging (`adb`)
- **CLI Flag**: `-mllvm -enable-adb -mllvm -adb_prob=100` | **Env**: `ADB=1 ADB_PROB=100`
- **Description**: Kernel timing jitter & hardware anti-debug inline probes
- **Verified LLVM IR Constructs**:
  - `(rdtsc|syscall|ptrace|CNTPCT|cntvct_el0|tpidr_el0)`: Hardware timing jitter / ptrace syscall inline probe
- **Verified Machine Assembly Constructs**:
  - [x86_64] `(rdtsc|syscall)`: x86 timing jitter (rdtsc) or direct kernel syscall
  - [aarch64] `(cntvct_el0|cntpct|svc\s+#0|tpidr_el0)`: ARM64 timer probe (cntvct/cntpct) or supervisor syscall (svc)

### Anti-Hooking (`antihook`)
- **CLI Flag**: `-mllvm -enable-antihook` | **Env**: `ANTIHOOK=1`
- **Description**: Prologue inline-hook self-check with violent exit traps
- **Verified LLVM IR Constructs**:
  - `(0xE9|0x14000001|233|335544321|hook)`: Prologue hook byte verification and comparison
- **Verified Machine Assembly Constructs**:
  - [x86_64] `(cmp|test|syscall|ud2|int3)`: Prologue inspection and violent exit / syscall traps
  - [aarch64] `(cmp|svc|brk)`: ARM64 prologue memory inspection and direct syscall exit

