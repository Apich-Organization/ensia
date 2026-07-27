# OLLVM-Next (Ensia)

<img align="right" src="./logo.svg" height="200" />

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20149843.svg)](https://doi.org/10.5281/zenodo.20149843)
[![Discord Server](https://img.shields.io/discord/1459399539403522074.svg?label=Discord&logo=discord&color=blue)](https://discord.gg/D5e2czMTT9)
[![Scc Count Badge Code](https://sloc.xyz/github/Apich-Organization/dtact/?category=code)](https://github.com/Apich-Organization/dtact/)

**⚠️ ETHICAL USE WARNING:** This is a high-strength obfuscation tool. Please read our [Ethics & Disclaimer Notice](./ETHICS.md) before use.

OLLVM-Next (Ensia) is an LLVM-based obfuscator. It is a derivative work, continuing the lineage of the [Hikari](https://github.com/HikariObfuscator/Hikari/), [Hikari-LLVM15](https://github.com/NeHyci/Hikari-LLVM15/), and [Hikari-LLVM19](https://github.com/PPKunOfficial/Hikari-LLVM19/) projects.  
This project aims to provide a functional tool for protecting code on modern LLVM toolchains (versions 21 and 22). It is not meant to be "perfect," but it tries to make the reverse-engineering process more time-consuming.

## **Core Philosophy**

Traditional **VM-based obfuscators (Virtualizers)** wrap bytecode inside a custom interpreter runtime. While hard to reverse manually, they introduce a **high Single Point of Failure (SPOF) risk**: once an analyst or automated tool devirtualizes the core handler table or dispatches the central VM loop, the entire protection collapses at once.

**Ensia abandons the single-point interpreter architecture.** Instead, it enforces **SMT Symbolic Solver State-Space Explosion** through a composition of distributed passes:
* **Vector-Space Lifting (SIMD):** Lifts scalar logic into multi-lane SIMD vector operations, defeating scalar symbolic execution engines.
* **Interleaved Data & Control Flow:** Interlocks data flow passes (MBA, String/Constant Encryption) with control flow transforms (Chaos State Machine, Control Flow Flattening).
* **Multi-Layer MBA & Hardware Predicates:** Injects multi-term Mixed Boolean-Arithmetic expressions and hardware-bound non-patchable opaque predicates (CPUID, RDTSC/CNTVCT), forcing SMT solvers (like Z3/Angr/KLEE) into exponential path and expression explosion.

## **Current Status**

* **Core:** Updated to work with the latest LLVM internal APIs.  
* **Logic:** Uses a specific pass order to ensure different layers of obfuscation build on top of each other without breaking the code.  
* **Intensity:** Offers presets to balance between protection strength and the resulting binary size/speed.

## **Obfuscation Pipeline**

The tool runs passes in a deliberate order to ensure stability. Here is a simplified look at what happens:

1. **Environment Checks:** Includes basic checks for debuggers, hooks, and metadata dumping.  
2. **Data Hiding:** Encrypts strings and constants using different methods (XOR, GF8, Feistel).  
3. **Control Flow:**  
   * **Chaos State Machine (CSM):** Uses a logistic-map to flatten code. This is the strongest mode.  
   * **Flattening:** A fallback for functions that the CSM cannot handle.  
4. **Instruction Complexity:** Uses Substitution and Mixed Boolean-Arithmetic (MBA) to make simple math look complicated.  
5. **Vectorization:** Lifts scalar code into SIMD vectors to confuse analysis tools.  
6. **Cleanup:** Strips debug information and renames internal symbols to hide their purpose.

## **How to Use**

You can use the obfuscator by passing flags to the LLVM compiler:

* \-mllvm \-ensia: Enable the tool.  
* \-mllvm \-enable-medobf: A "medium" setting for production. It uses math complexity and flattening but avoids the slowest passes.  
* \-mllvm \-enable-maxobf: Enables everything at maximum settings. This is very slow and will make your program much larger.
* ... Please see the source code for more details.

### **Environmental Variables**

You can also enable specific features by setting variables in your shell:

* STRCRY=1 (String Encryption)  
* CSMOBF=1 (Chaos State Machine)  
* MBAOBF=1 (MBA Math)
* ... Please see the source code for more details.

## **Important Warnings**

* **Dual-Use:** Please read the [ETHICS.md](./ETHICS.md) file and the the [ETHICS.pdf](./ETHICS.pdf) file. This tool is for protecting your own work or for research.  
* **Stability:** Obfuscation can sometimes introduce bugs or performance issues. Always test your software thoroughly after building it with these flags.  
* **Bloat:** Using "Max Mode" can increase binary size significantly.

## **Licensing & Attribution**

This project is licensed under the **AGPL-3.0**. It includes code and logic from the Hikari and LLVM projects. See [LEGAL.md](./LEGAL.md) for full details on project history and original authors.

## Sponsorship & Funding Policy

We welcome sponsorships from individuals and organizations supporting open-source compiler security research. Please review our [Sponsorship Policy](./sponsor.md) for details on fund allocation, contribution options via Open Collective, corporate tiers, and our strict anti-money laundering policies.

* **Open Collective Link:** [https://opencollective.com/apich-organization](https://opencollective.com/apich-organization)

## Code of Conduct & Security

Please read the [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) and [SECURITY.md](./SECURITY.md) files for more details.