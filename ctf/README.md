# CTF Reverse Engineering Challenge: Ensia Secure Cryptographic Enclave

## Challenge Overview
- **Name:** Ensia Secure Cryptographic Enclave
- **Category:** Reverse Engineering / Cryptography
- **Difficulty:** Hard / Insane
- **Profile:** Built with Ensia `max` profile (Extreme-mode LLVM Obfuscation)

---

## 1. Description
The binary `./challenge_obf` acts as a multi-stage hardware-like cryptographic security enclave. It verifies a sequence of 4 distinct user inputs through interconnected non-linear mathematical and cryptographic layers. The verification state does not rely on a single magic number comparison, but rather accumulates entropy across all 4 stages into a coherent key vector $(S_1, S_2, S_3, S_4)$ to decrypt the flag in memory.

If any stage is incorrect, the difference accumulator silently drifts, corrupting the decryption keystream and resulting in complete state zeroization (`memset_s` / volatile scrubber with compiler memory barriers).

---

## 2. Multi-Stage Non-Linear Cryptographic Architecture

### Layer 1: Galois Field $GF(2^8)$ SPN Permutation
- **Input:** 16-character activation key `XXXX-XXXX-XXXX-XXXX` (Input: `K9mX-7vQ2-Lp8A-W3zR`).
- **Algorithm:**
  - Irreducible polynomial: $P(x) = x^8 + x^4 + x^3 + x + 1$ (`0x11B`, AES field).
  - Dynamic non-linear S-box computed via Fermat's Little Theorem modular inversion:
    $$S(x) = (x \oplus 0x67)^{254} \oplus 0x89 \pmod{P(x)}$$
  - 4-round Substitution-Permutation Network (SPN) with round-key addition, non-linear ByteSub, ShiftRows, and MixColumns over an MDS matrix.
- **State Export:** Emits 128-bit state vector $S_1 = (s_{1,0}, s_{1,1}, s_{1,2}, s_{1,3})$.

### Layer 2: 2D Coupled Chaotic Orbit over Mersenne Prime
- **Input:** 4 unsigned 32-bit calibration coordinates (Input: `31337 424242 10007 88888888`).
- **Algorithm:**
  - Prime field: $\mathbb{F}_p$ where $p = 2^{31} - 1$ (Mersenne prime $M_{31}$).
  - Coupled non-linear Arnold's Cat Map with cubic feedback:
    $$x_{t+1} = (2x_t + y_t + x_t^3 + p_0 + 0x314159) \pmod p$$
    $$y_{t+1} = (x_t + y_t + y_t^3 + q_0 + 0x271828) \pmod p$$
  - Initial seeds $(x_0, y_0, p_0, q_0)$ are cross-coupled with Layer 1 state vector $S_1$:
    $$x_0 = k_0 \oplus s_{1,0}, \quad y_0 = k_1 \oplus s_{1,1}, \quad p_0 = k_2 \oplus s_{1,2}, \quad q_0 = k_3 \oplus s_{1,3}$$
  - Dual modular algebraic invariant checks:
    $$\text{inv}_1 = (k_0 \cdot 0x1337 + k_1 \cdot 0xDEAD) \pmod p$$
    $$\text{inv}_2 = (k_2 \cdot 0xBEEF + k_3 \cdot 0xCAFE) \pmod p$$
- **State Export:** Emits 128-bit state vector $S_2$.

### Layer 3: Polymorphic Feistel Cipher with Dynamic S-Box
- **Input:** 16-byte passphrase (Input: `n0n_l1n34r_ch40s`).
- **Algorithm:**
  - 8-round balanced Feistel network ($64\text{-bit} \times 2 = 128\text{-bit}$).
  - The round function $F(R, K_r)$ uses a dynamic S-box generated at runtime by permuting a 256-byte substitution table seeded by Layer 2's chaotic coordinate $S_2$.
- **State Export:** Emits 128-bit state vector $S_3$.

### Layer 4: Sponge Permutation Network (Keccak-style)
- **Input:** 8-byte hexadecimal sealing token (Input: `8F3a9C2e`).
- **Algorithm:**
  - State array of eight 32-bit words: $A[0..7]$ initialized with $(S_1, S_2, S_3)$.
  - Absorbs token bytes and executes 12 rounds of non-linear step mappings:
    - $\theta$: Column parity diffusion
    - $\rho$ & $\pi$: Cyclic intra-word bit rotation and position permutation
    - $\chi$: Non-linear bitwise row interaction $a_i \leftarrow a_i \oplus (\neg a_{i+1} \ \& \ a_{i+2})$
    - $\iota$: Round constant asymmetric injection
- **State Export:** Emits 256-bit state vector $S_4$.

### Flag Decryption
- The flag ciphertext is decrypted in-memory using an XOR keystream derived from the SHA-like non-linear compression of $(S_1, S_2, S_3, S_4)$.
- Decrypted flag: `ensia{k9Mx_7vQ2_cHa0s_9x8F_lAtT1cE}`.

---

## 3. Ensia Max Obfuscation Profile Protection
The challenge binary `./challenge_obf` is obfuscated using Ensia in `max` mode:
1. **AntiHooking:** Dual-defense AntiHooking architecture: Entry Prologue Guard + Scattered In-Flight CFG Auditing against inline hooks (0xE9 JMP rel32, 0xEB JMP rel8, 0xCC INT3, 0x68 PUSH imm32, 0xFF 0x25 indirect jump, 0x48 0xB8 MOVABS), embedded cryptographic code segment self-checks with data-flow entanglement (`T_env` / `T_exp`), and direct kernel syscall bypass.
2. **FunctionWrapper:** Wraps core functions in polymorphic proxy trampolines with argument XOR shuffling and return masking.
3. **FunctionCallObfuscate (FCO):** External API imports are resolved dynamically via dlsym at runtime, eliminating static import references.
4. **AntiDebugging:** Multi-vector hardware and kernel probes: ptrace, hardware debug registers (DR0-DR7), EFLAGS.TF single-step traps, and unrecoverable violent exit.
5. **StringEncryption:** All string literals encrypted using Vernam-GF(2^8) ciphers and decrypted just-in-time on the stack with automatic volatile zeroization at function exits (Anti-Dump).
6. **ConstantEncryption:** Phase 1 & 2 encrypt programmer constants and CFG skeleton constants using 4-round Feistel networks and 6-share XOR chains.
7. **Instruction Substitution & MBA:** Arithmetic expressions expanded into multi-term Mixed Boolean-Arithmetic expressions with polymorphic hardware barriers.
8. **BasicBlockSplit & BogusControlFlow:** Splits basic blocks and injects hardware opaque predicate bogus control-flow loops.
9. **ChaosStateMachine (CSM):** Logistic-map quadratic control flow flattening in full Q32 fixed-point arithmetic with 2-level nested dispatchers.
10. **VectorObfuscation:** Scalar comparisons and transitions lifted into wide 512-bit SIMD vector operations.
11. **IndirectBranch:** All conditional and unconditional branches converted into Knuth-hash encrypted indirect branches with randomized 4-slot jump tables and decoy basic blocks.
12. **Cleanup Markers, FeatureElimination & LTO Evasion:** Erases temporary compiler sentinel declarations (`ensia_*`), strips DWARF metadata, anonymizes TU paths to "a", drops `llvm.ident`, clears COMDATs, internalizes ODR linkages, scrambles private/internal symbols (`_f<hex>`, `_v<hex>`, `_a<hex>`), and stamps functions with `Attribute::OptimizeNone` and `Attribute::NoInline`.

---

## 4. Building & Running

### Requirements
- Clang 21.x with C++20 support
- Ensia LLVM obfuscation plugin (`libEnsia.so`)
- Linux x86_64

### Build Commands
```bash
# Build clean binary (unobfuscated reference)
make challenge_clean

# Build obfuscated binary (Ensia max profile)
make challenge_obf

# Run automated tests
make test
```

### Solving
```bash
python3 solution/solve.py ./challenge_obf
```
