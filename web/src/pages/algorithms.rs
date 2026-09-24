use leptos::{html, prelude::*};
use wasm_bindgen::prelude::*;

#[derive(Clone, Copy, PartialEq, Debug, Default)]
enum Algo {
    #[default]
    Bcf,
    Cff,
    Csm,
    StrEnc,
    ConstEnc,
    Sub,
    Mba,
    Vec,
    IndirBranch,
    FuncWrap,
    AntiDebug,
    AntiHook,
    AntiClassDump,
    FuncCallObf,
    SplitBlocks,
}

struct AlgoMeta {
    key: Algo,
    icon: &'static str,
    label: &'static str,
}

const ALGOS: &[AlgoMeta] = &[
    AlgoMeta {
        key: Algo::Bcf,
        icon: "\u{1F500}",
        label: "Bogus Control Flow",
    },
    AlgoMeta {
        key: Algo::Cff,
        icon: "\u{2B1B}",
        label: "Control Flow Flattening",
    },
    AlgoMeta {
        key: Algo::Csm,
        icon: "\u{1F300}",
        label: "Chaos State Machine",
    },
    AlgoMeta {
        key: Algo::StrEnc,
        icon: "\u{1F512}",
        label: "String Encryption",
    },
    AlgoMeta {
        key: Algo::ConstEnc,
        icon: "\u{1F9EE}",
        label: "Constant Encryption",
    },
    AlgoMeta {
        key: Algo::Sub,
        icon: "+",
        label: "Instruction Substitution",
    },
    AlgoMeta {
        key: Algo::Mba,
        icon: "\u{03A3}",
        label: "Mixed Boolean-Arithmetic",
    },
    AlgoMeta {
        key: Algo::Vec,
        icon: "\u{2B21}",
        label: "Vector Obfuscation",
    },
    AlgoMeta {
        key: Algo::IndirBranch,
        icon: "\u{21A9}",
        label: "Indirect Branching",
    },
    AlgoMeta {
        key: Algo::FuncWrap,
        icon: "\u{1F4E6}",
        label: "Function Wrapper",
    },
    AlgoMeta {
        key: Algo::AntiDebug,
        icon: "\u{1F41B}",
        label: "Anti-Debugging",
    },
    AlgoMeta {
        key: Algo::AntiHook,
        icon: "\u{1F3A3}",
        label: "Anti-Hooking",
    },
    AlgoMeta {
        key: Algo::AntiClassDump,
        icon: "\u{1F50D}",
        label: "Anti-Class Dump",
    },
    AlgoMeta {
        key: Algo::FuncCallObf,
        icon: "\u{1F4DE}",
        label: "Call Obfuscation",
    },
    AlgoMeta {
        key: Algo::SplitBlocks,
        icon: "\u{2702}",
        label: "Block Splitting",
    },
];

#[component]
pub fn AlgorithmsPage() -> impl IntoView {
    let current = RwSignal::new(Algo::Bcf);

    view! {
        <div class="page-wrap algo-layout">
            <aside class="algo-sidebar glass-alt card-pad">
                {ALGOS.iter().map(|m| {
                    let key = m.key;
                    view! {
                        <button
                            class="algo-nav-btn"
                            class:active=move || current.get() == key
                            on:click=move |_| current.set(key)
                        >
                            <span class="algo-nav-icon">{m.icon}</span>
                            {m.label}
                        </button>
                    }
                }).collect_view()}
            </aside>

            <div class="algo-content">
                {move || match current.get() {
                    Algo::Bcf        => view! { <BcfSection        /> }.into_any(),
                    Algo::Cff        => view! { <CffSection        /> }.into_any(),
                    Algo::Csm        => view! { <CsmSection        /> }.into_any(),
                    Algo::StrEnc     => view! { <StrEncSection     /> }.into_any(),
                    Algo::ConstEnc   => view! { <ConstEncSection   /> }.into_any(),
                    Algo::Sub        => view! { <SubSection        /> }.into_any(),
                    Algo::Mba        => view! { <MbaSection        /> }.into_any(),
                    Algo::Vec        => view! { <VecSection        /> }.into_any(),
                    Algo::IndirBranch=> view! { <IndirBranchSection/> }.into_any(),
                    Algo::FuncWrap      => view! { <FuncWrapSection      /> }.into_any(),
                    Algo::AntiDebug     => view! { <AntiDebugSection     /> }.into_any(),
                    Algo::AntiHook      => view! { <AntiHookSection      /> }.into_any(),
                    Algo::AntiClassDump => view! { <AntiClassDumpSection /> }.into_any(),
                    Algo::FuncCallObf   => view! { <FuncCallObfSection   /> }.into_any(),
                    Algo::SplitBlocks   => view! { <SplitBlocksSection   /> }.into_any(),
                }}
            </div>
        </div>
    }
}

// ── Bogus Control Flow ────────────────────────────────────────────────────

#[component]
fn BcfSection() -> impl IntoView {
    view! {
        <div class="algo-header">
            <h2>"\u{1F500} Bogus Control Flow"</h2>
            <p>
                "BCF inserts opaque predicates — conditionals whose outcome is
                 always known at compile time but not statically to an analyser —
                 to create fake branches that lead to cloned or junk code, reinforced
                 with polymorphic hardware execution barriers."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"How it works"</p>
            <p>
                "BCF uses hardware-predicate tiers backed by non-patchable hardware invariants:
                 Tier 1: CPUID feature bits (always set on modern x86 processors).
                 Tier 2: RDTSC parity checks (a high-resolution timing register sampled at compile time).
                 Tier 3: AArch64 "
                <code class="font-mono">"MRS x0, CNTPCT_EL0"</code>
                " counter register.
                 Tier 4: Polymorphic hardware memory/pipeline barriers (a 9-variant x86 instruction family
                 including orb, andb, addb, subb, rolb, rorb, incb/decb, notb/notb, and ARM64 prfm/isb/dmb),
                 eliminating static signature detection.
                 Selected blocks are cloned into original and bogus copies; the opaque predicate
                 guarantees dynamic routing to the real path while bogus blocks introduce dead-code loops."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Control-flow graph transformation"</p>
            <div class="vis-frame">
                <BcfSvg />
            </div>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Polymorphic Hardware Barrier & Predicate Invariants"</p>
            <MathBlock formula=r"$$\texttt{CPUID}(1).\text{ECX}[25] = 1 \;\;\land\;\; \text{Barrier}(\Delta) \equiv \Delta \pmod{2^n}$$" />
            <p class="text-sm mt-sm">
                "Hardware invariants are combined with an entropy chain threaded through
                 preceding calculations. Static deobfuscators and SMT solvers cannot resolve
                 these invariants without whole-system emulation. The polymorphic barrier family
                 ensures uniform YARA rules searching for static instructions (such as xorb $0, $0)
                 detect under 10% of barrier sites."
            </p>
        </div>

        <AlgoConfigTable pass="bcf" rows=vec![
            ("enabled",           "bool",  "true",  "Master switch for this pass."),
            ("probability",       "0-100", "50",    "Probability that any given basic block is selected."),
            ("iterations",        "1-5",   "1",     "Number of BCF rounds applied per function."),
            ("complexity",        "1-10",  "3",     "Number of bogus clones injected per selected block."),
            ("entropy_chain",     "bool",  "false", "Thread predicate values through prior computations."),
            ("junk_asm",          "bool",  "false", "Insert inline assembly noise in bogus blocks."),
            ("junk_asm_min/max",  "int",   "1/4",   "Range of junk ASM instructions per bogus block."),
            ("nested",            "bool",  "false", "Enable nested conditional predicate generation."),
            ("create_func",       "bool",  "false", "Extract bogus cloned blocks into external dead functions."),
        ]/>
    }
}

// ── Control Flow Flattening ───────────────────────────────────────────────

#[component]
fn CffSection() -> impl IntoView {
    view! {
        <div class="algo-header">
            <h2>"\u{2B1B} Control Flow Flattening"</h2>
            <p>
                "CFF restructures the control-flow graph of a function into a
                 single switch-dispatch loop, hiding the original control flow edges.
                 Ensia replaces fragile volatile dependencies with branchless algebraic
                 masking to achieve Zero-SPOF flattening."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Transformation overview"</p>
            <div class="vis-frame">
                <CffSvg />
            </div>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Zero-SPOF Branchless Algebraic State Transitions"</p>
            <MathBlock formula=r"$$\text{mask} = 0 - \text{zext}(\text{cond}), \quad \text{state}_{n+1} = \text{Barrier}\bigl(\text{caseFalse} \oplus (\text{mask} \;\wedge\; (\text{caseTrue} \oplus \text{caseFalse}))\bigr)$$" />
            <p class="text-sm mt-sm">
                "Traditional CFF implementations store the state variable with a "
                <code class="font-mono">"volatile"</code>
                " qualifier. When an adversary removes volatile attributes, standard compiler
                 optimisers (opt -O3 / SCCP) instantly fold the switch. Ensia computes state transitions
                 through branchless bitmask algebra without any conditional branches or naked select
                 instructions, anchored by polymorphic hardware barriers. Red-team audits prove that
                 even if all volatile markers are stripped, 100% of dispatch switches and blocks remain intact."
            </p>
        </div>

        <AlgoConfigTable pass="flattening" rows=vec![
            ("enabled", "bool", "false", "Enable classic CFF. Functions already processed by CSM are skipped automatically."),
        ]/>
    }
}

// ── Chaos State Machine ───────────────────────────────────────────────────

#[component]
fn CsmSection() -> impl IntoView {
    view! {
        <div class="algo-header">
            <h2>"\u{1F300} Chaos State Machine"</h2>
            <p>
                "CSM is an industrial-strength non-linear control flow flattening engine that
                 drives the dispatch variable through the quadratic logistic map — a chaotic
                 dynamical recurrence relation coupled with live data-flow feedback (DFB)."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Q32 fixed-point IR recurrence, Multi-Step Attractor Basins & DFB"</p>
            <MathBlock formula=r"$$x_{n+1} = \lfloor \mu \cdot x_n \cdot (1 - x_n) \rfloor \oplus \text{DFB}(\text{args}, \text{BBs}), \quad \mu \approx 3.999999999,\; x_n \in Q_{32}$$" />
            <p class="text-sm mt-sm">
                "The logistic map is evaluated entirely in full Q32 fixed-point integer arithmetic ($2^{32}$ state space)
                 inside LLVM IR without using floating-point types, extending cycle lengths beyond 50,000 steps and
                 rendering precomputed lookup tables (requiring ≥16 GB) completely infeasible. Furthermore, state transitions
                 replace 1-step linear cancellations with multi-step cellular automata attractor diffusion and modular inverse
                 decoding, coupled directly with function input arguments and intermediate basic block computations: "
                <code class="font-mono">"DFB_new = (DFB_old * 33) ^ val"</code>
                ". Without concrete runtime execution arguments, static symbolic solvers
                 (like Z3, angr, or KLEE) cannot compute the next state algebraically."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Nested 2-Level Dispatch & Optimization Stripping Resistance"</p>
            <p class="text-sm">
                "In traditional CFF, switch dispatchers collapse under compiler optimization if volatile markers
                 are removed. CSM combines branchless algebraic transitions with polymorphic hardware barriers:
                 in our red-team benchmarks, opt -O3 retained 97.9% of the IR with 100% of dispatch switches
                 intact. When "
                <code class="font-mono">"nested_dispatch"</code>
                " is enabled, CSM injects an intermediate 16-target relay switch per destination block,
                 doubling the CFG cyclomatic complexity and defeating graph-reduction heuristics."
            </p>
        </div>

        <AlgoConfigTable pass="chaos_state_machine" rows=vec![
            ("enabled",         "bool",    "false", "Enable CSM. Subsumes classic flattening on processed functions."),
            ("warmup",          "16-512",  "64",    "Number of logistic-map iterations discarded before use."),
            ("nested_dispatch", "bool",    "false", "Add a second 16-target relay dispatch level for maximum CFG complexity."),
            ("max_blocks",      "int",     "5000",  "Safety threshold for function basic block count before fallback."),
        ]/>
    }
}

// ── String Encryption ─────────────────────────────────────────────────────

#[component]
fn StrEncSection() -> impl IntoView {
    view! {
        <div class="algo-header">
            <h2>"\u{1F512} String Encryption"</h2>
            <p>
                "Each selected string literal is encrypted with a per-string
                 pseudo-random key using a dual-layer cipher over GF(2^8),
                 reinforced with automatic Memory-Dump Protection (Anti-Dump)."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Dual-layer cipher: Vernam + Rijndael GF(2^8)"</p>
            <MathBlock formula=r"$$c_i = \bigl(p_i \oplus k^{(1)}_i\bigr) \;\cdot_{GF(2^8)}\; k^{(2)}_i, \quad \text{poly} = x^8+x^4+x^3+x+1 \;(0x11b)$$" />
            <p class="text-sm mt-sm">
                "Layer 1 is a classical Vernam OTP XOR with a per-string random key.
                 Layer 2 multiplies the XOR result by a second random key byte in "
                <strong>"GF(2^8)"</strong>
                 " using the AES irreducible polynomial 0x11b. Recovering plaintext requires
                 inverting finite-field polynomial multiplication rather than simple XOR unmasking.
                 Keys are separated across split-key global arrays to defeat alias analysis."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Dynamic Memory-Dump Protection (Anti-Dump Zeroization)"</p>
            <p class="text-sm">
                "Traditional string encryption leaves decrypted strings permanently resident
                 in global memory, allowing simple process core dumps to harvest all secrets.
                 Ensia automatically injects inlined "
                <code class="font-mono">"isVolatile memset"</code>
                " zeroization stubs at all function returns (ReturnInst) and exception unwinds (ResumeInst).
                 The plaintext buffer is wiped to 0x00 bytes upon function exit, and the atomic status
                 flag is reset with release ordering so subsequent calls re-decrypt transparently.
                 Returning pointer safety analysis ensures escaping string pointers are preserved."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Byte-level transform (animated)"</p>
            <div class="vis-frame">
                <StrEncSvg />
            </div>
        </div>

        <AlgoConfigTable pass="string_encryption" rows=vec![
            ("enabled",       "bool",    "true",  "Master switch."),
            ("probability",   "0-100",   "80",    "Percentage of string globals that are encrypted."),
            ("anti_dump",     "bool",    "true",  "Zeroize plaintext buffers at return/resume exits to defeat memory dumping."),
            ("force_content", "regex[]", "[]",    "Substrings/patterns that guarantee encryption."),
            ("skip_content",  "regex[]", "[]",    "Substrings/patterns that skip encryption."),
        ]/>
    }
}

// ── Constant Encryption ───────────────────────────────────────────────────

#[component]
fn ConstEncSection() -> impl IntoView {
    view! {
        <div class="algo-header">
            <h2>"\u{1F9EE} Constant Encryption"</h2>
            <p>
                "Protects immediate integer constants via a Triple-Scheme redundant architecture
                 (Bivariate MBA, Feistel Networks, and Dynamic Anti-Debugging Token Entanglement)
                 executed in a bounded Two-Phase pipeline."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Triple-Scheme Redundancy (Zero-SPOF)"</p>
            <p class="text-sm">
                <strong>"Scheme A — Bivariate MBA k-Share Decomposition: "</strong>
                "Splits constants into k secret shares (C = s_1 ^ s_2 ^ ... ^ s_k) with polymorphic barriers, completely eliminating raw constants from disassembly."
            </p>
            <p class="text-sm mt-sm">
                <strong>"Scheme B — 4-Round Polymorphic Feistel Mixing: "</strong>
                "Applies a 4-round Feistel non-linear permutation (L_{n+1} = R_n, R_{n+1} = L_n ^ F(R_n)) with multiply-add-XOR mixing before share splitting, defeating affine algebraic solving."
            </p>
            <p class="text-sm mt-sm">
                <strong>"Scheme C — Dynamic AntiDebug Token (%adb.tok) Entanglement: "</strong>
                "Entangles constant shares with the runtime execution token from AntiDebugging (realShare0 = share0 ^ K_dyn ^ adb.tok) using Dominator Tree validation. If an analyst patches or bypasses anti-debugging, the constant decrypts to garbage, causing downstream algorithmic corruption."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Two-Phase Pipeline & Combinatorial Explosion Elimination"</p>
            <MathBlock formula=r"$$\text{Phase 1: Encrypt Literals} \;\longrightarrow\; \text{CFG Mutations} \;\longrightarrow\; \text{Phase 2: Encrypt Skeleton Keys}$$" />
            <p class="text-sm mt-sm">
                "Earlier constant obfuscators suffered from combinatorial code bloat (300k+ instructions).
                 Ensia splits encryption into two phases: Phase 1 encrypts programmer literals before CFG passes;
                 Phase 2 encrypts state machine keys generated by BCF and CSM. A small-constant whitelist
                 filters trivial values in [-1, 8] and bitmasks, keeping compile times bounded (<0.2s)."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"k-share visualisation"</p>
            <div class="vis-frame">
                <ConstEncSvg />
            </div>
        </div>

        <AlgoConfigTable pass="constant_encryption" rows=vec![
            ("enabled",             "bool",    "true",  "Master switch."),
            ("share_count",         "2-6",     "3",     "Number of XOR shares per constant."),
            ("feistel",             "bool",    "false", "Add Feistel non-linear layer (+26 IR instrs/constant)."),
            ("substitute_xor",      "bool",    "false", "Replace some XOR ops with equivalent MBA expressions."),
            ("substitute_xor_prob", "0-100",   "40",    "Probability of XOR substitution when enabled."),
            ("force_value",         "hex[]",   "[]",    "Constants guaranteed to be encrypted (hex literals)."),
            ("skip_value",          "regex[]", "[]",    "Constants skipped (e.g. 0x0, 0x1 regex patterns)."),
        ]/>
    }
}

// ── Instruction Substitution ──────────────────────────────────────────────

#[component]
fn SubSection() -> impl IntoView {
    view! {
        <div class="algo-header">
            <h2>"+ Instruction Substitution"</h2>
            <p>
                "Arithmetic and logical instructions are replaced with semantically
                 equivalent but more complex sequences. This raises the effort
                 required to understand individual expressions."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Four substitution strategies"</p>
            <div class="mba-expr">
                <span class="mba-highlight">"mulSubstitution3/4"</span>
                {" — replaces MUL with 3- or 4-instruction sequences using shifts and adds"}
            </div>
            <div class="mba-expr">
                <span class="mba-highlight">"addChainedMBA"</span>
                {" — rewrites ADD as a 3-term boolean-arithmetic identity: (a | b) + (a & b)"}
            </div>
            <div class="mba-expr">
                <span class="mba-highlight">"xorSplitRotate"</span>
                {" — splits XOR into rotate-left / rotate-right pairs with a noise mask"}
            </div>
            <div class="mba-expr">
                <span class="mba-highlight">"dereference noise"</span>
                {" — injects a dead stack-slot load/store that aliases nothing but confuses Binja/IDA type recovery"}
            </div>
        </div>

        <AlgoConfigTable pass="substitution" rows=vec![
            ("enabled",     "bool",  "true", "Master switch."),
            ("probability", "0-100", "60",   "Probability each eligible instruction is substituted."),
        ]/>
    }
}

// ── MBA ───────────────────────────────────────────────────────────────────

#[component]
fn MbaSection() -> impl IntoView {
    view! {
        <div class="algo-header">
            <h2>"\u{03A3} Mixed Boolean-Arithmetic"</h2>
            <p>
                "MBA obfuscation expresses arithmetic operations as multi-term
                 identities mixing boolean operators (AND, OR, XOR) with
                 addition and multiplication over Z/2^nZ, reinforced with
                 randomized polymorphic hardware barriers."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"MBA identity for addition & Point-to-Point (BPP) Tracking"</p>
            <MathBlock formula=r"$$a + b \equiv (a \oplus b) + 2(a \wedge b) \pmod{2^n}$$" />
            <p class="text-sm mt-sm">
                "This generalises: the XOR captures bits where carries do not
                 propagate, and the AND detects carry positions. Point-to-Point
                 (BPP) tracking tracks non-linear polynomial data-flow across basic
                 blocks, frustrating linear algebraic simplification."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"42 built-in identity variants & Polymorphic Barriers"</p>
            <p class="text-sm">
                "The identity table covers five operator families: "
                <strong>"ADD \u{00D7}8"</strong>
                ", "
                <strong>"SUB \u{00D7}7"</strong>
                ", "
                <strong>"XOR \u{00D7}7"</strong>
                ", "
                <strong>"AND \u{00D7}8"</strong>
                ", "
                <strong>"OR \u{00D7}7"</strong>
                ", "
                <strong>"MUL \u{00D7}5"</strong>
                " — 42 variants total. To eliminate signature detection and defeat blackbox I/O synthesis (Syntia model), Ensia embeds
                 stateful contextual barriers derived from dynamic runtime state (stack canary %fs:0x28, stack alignment %rsp & 15,
                 TLS self-pointers, and ARM64 tpidr_el0), coupled with context-dependent affine polynomial noise
                 P(a, b) * (ctx ^ K) resolving through an opaque global context variable."
            </p>
        </div>

        <AlgoConfigTable pass="mba" rows=vec![
            ("enabled",   "bool", "true",  "Master switch."),
            ("layers",    "1-4",  "1",     "Number of MBA identity substitution rounds."),
            ("heuristic", "bool", "false", "Allow noise-injection for weaker but faster transforms."),
        ]/>
    }
}

// ── Vector Obfuscation ────────────────────────────────────────────────────

#[component]
fn VecSection() -> impl IntoView {
    view! {
        <div class="algo-header">
            <h2>"\u{2B21} Vector Obfuscation"</h2>
            <p>
                "Scalar integer and float operations are lifted into SIMD vector
                 space, shuffled across lanes, operated on, and extracted.
                 Includes Vector Taint Diffusion to defeat Dynamic Taint Analysis (DTA)."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Lane-insert strategy & Vector Taint Diffusion"</p>
            <MathBlock formula=r"$$\text{scalar } x \;\xrightarrow{\texttt{insertelement}}\; \langle r_0, \ldots, x_L, \ldots, r_{W-1} \rangle \;\xrightarrow{\text{shufflevector}}\; \text{VecBarrier} \;\xrightarrow{\text{extractelement}}\; x'$$" />
            <p class="text-sm mt-sm">
                "The scalar is inserted into a random lane L of a vector of width W
                 (64, 128, 256, or 512 bits) using insertelement. Filler lanes are populated
                 with pseudo-random polynomial noise derived from the live operand.
                 Lane contents are scrambled using bijective shufflevector permutations
                 anchored by inline vector hardware barriers.
                 In our deobfuscation audit, 100% of generated SIMD vector instructions (374/374)
                 survived aggressive opt -O3 and DCE/GVN unflattening passes."
            </p>
        </div>

        <AlgoConfigTable pass="vector_obfuscation" rows=vec![
            ("enabled",          "bool",       "false", "Master switch."),
            ("probability",      "0-100",      "50",    "Per-instruction selection probability."),
            ("width",            "64/128/256/512", "128", "SIMD vector width in bits."),
            ("shuffle",          "bool",       "false", "Permute lanes between operations."),
            ("lift_comparisons", "bool",       "false", "Also lift integer comparisons into vector ICMPs."),
        ]/>
    }
}

// ── Indirect Branching ────────────────────────────────────────────────────

#[component]
fn IndirBranchSection() -> impl IntoView {
    view! {
        <div class="algo-header">
            <h2>"\u{21A9} Indirect Branching"</h2>
            <p>
                "Direct branch targets (function addresses, basic block labels)
                 are replaced with encrypted pointers resolved at runtime via
                 a Knuth multiplicative hash. This prevents static construction
                 of a call graph."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"3-instruction decryption chain"</p>
            <MathBlock formula=r"$$\text{target} = \bigl((\text{raw\_addr} + \delta_1) \times K_{\text{mult}}\bigr) \oplus K_{\text{xor}}$$" />
            <p class="text-sm mt-sm">
                "Each branch target is encrypted at compile time and stored as a
                 global. At the call site, three IR instructions reverse this:
                 add "
                <code class="font-mono">"delta1"</code>
                " (per-function random offset), multiply by "
                <code class="font-mono">"KNUTH_MULT"</code>
                " (the Knuth golden-ratio constant "
                <code class="font-mono">"0x9e3779b97f4a7c15"</code>
                " for 64-bit), then XOR with "
                <code class="font-mono">"KNUTH_XOR"</code>
                " (a second per-function random key). Both "
                <code class="font-mono">"delta1"</code>
                " and the XOR key are unique per function, derived from the
                 config PRNG. After encryption, the global array is shuffled
                 so sequential slot indices do not correspond to lexical function order."
            </p>
        </div>

        <AlgoConfigTable pass="indirect_branch" rows=vec![
            ("enabled", "bool", "false", "Master switch. Applies to all branch targets in selected functions."),
        ]/>
    }
}

// ── Function Wrapper ──────────────────────────────────────────────────────

#[component]
fn FuncWrapSection() -> impl IntoView {
    view! {
        <div class="algo-header">
            <h2>"\u{1F4E6} Function Wrapper"</h2>
            <p>
                "Each selected function is wrapped in a polymorphic proxy that
                 forwards all arguments and return values. The wrapper can be
                 applied multiple times to build chains, and each wrapper is
                 given a unique mangled name."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Three wrapper strategies"</p>
            <p>
                <strong>"Strategy A — dead stack slots: "</strong>
                "The proxy allocates several dummy stack variables whose addresses
                 are taken but never read, confusing alias analysis and stack-frame
                 recovery tools."
            </p>
            <p class="mt-sm">
                <strong>"Strategy B — argument XOR shuffle: "</strong>
                "Each argument is XOR-ed with a per-wrapper random constant before
                 being forwarded, then the callee XOR-reverses the value. From the
                 caller's perspective the arguments look scrambled."
            </p>
            <p class="mt-sm">
                <strong>"Strategy C — return value XOR masking: "</strong>
                "The return value is XOR-ed with a constant in the callee and
                 unmasked in the wrapper, hiding the real return path. The three
                 strategies are composable and the chain depth is configurable."
            </p>
        </div>

        <AlgoConfigTable pass="function_wrapper" rows=vec![
            ("enabled",     "bool",  "false", "Master switch."),
            ("probability", "0-100", "50",    "Fraction of functions that receive a wrapper."),
            ("times",       "1-5",   "1",     "Wrapper chain depth per function."),
        ]/>
    }
}

// ── Anti-Debugging ────────────────────────────────────────────────────────

#[component]
fn AntiDebugSection() -> impl IntoView {
    view! {
        <div class="algo-header">
            <h2>"\u{1F41B} Anti-Debugging"</h2>
            <p>
                "Detects interactive debuggers and static analysis environments at runtime
                 using zero-dependency direct system probes across Windows, macOS, and Linux.
                 Injects hardware fast-fail abort mechanisms (int 0x29 / brk #0xF003) to prevent
                 exception handler interception."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Multi-layered detection mechanisms"</p>
            <div class="vis-frame">
                <AntiDebugSvg />
            </div>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Platform-specific probes & violent exit handlers"</p>
            <p class="text-sm">
                <strong>"Linux / Android: "</strong>
                "Direct kernel syscalls for ptrace(PTRACE_TRACEME), /proc/self/status TracerPid polling, and prctl(PR_SET_DUMPABLE, 0). Probes hardware debug registers (DR0-DR7). Inspects the single-step Trap Flag (EFLAGS.TF) with System V AMD64 Red Zone preservation (subq $128, %rsp ... addq $128, %rsp) and Attribute::NoRedZone to prevent stack pointer clobbering. On detection, triggers immediate violent exit (SYS_exit_group(137) or hardware traps ud2 / brk #0xDEAD) to prevent debugger or hook interception."
            </p>
            <p class="text-sm mt-sm">
                <strong>"Windows (x86_64 / AArch64): "</strong>
                "Direct memory mapping checks on KUSER_SHARED_DATA at 0x7FFE02D4 (KdDebuggerEnabled) and 0x7FFE02D0 (BeingDebugged). Probes PEB+0xBC for NtGlobalFlag heap validation flags (0x70 mask). Checks TEB hardware debug registers (DR0-DR3 / DR7). Triggers int 0x29 / non-canonical address `#GP` or brk #0xF003 to bypass VEH/SEH handlers."
            </p>
            <p class="text-sm mt-sm">
                <strong>"macOS / iOS: "</strong>
                "Direct ptrace(PT_DENY_ATTACH, 0, 0, 0) via inline assembly (svc #0x80 / syscall). Checks sysctl(CTL_KERN, KERN_PROC_PID) for kp_proc.p_flag & P_TRACED and P_NOATTACH, along with task_for_pid permission probing."
            </p>
        </div>

        <AlgoConfigTable pass="anti_debugging" rows=vec![
            ("enabled",             "bool",   "false", "Insert debugger-detection checks and violent fast-fail probes at function entry points."),
            ("probability",         "0-100",  "50",    "Percentage of functions receiving inline anti-debug validation stubs."),
            ("precompiled_ir_path", "string", "\"\"",  "Path to external precompiled LLVM IR module containing verified defense stubs."),
        ]/>
    }
}

// ── Anti-Hooking ──────────────────────────────────────────────────────────

#[component]
fn AntiHookSection() -> impl IntoView {
    view! {
        <div class="algo-header">
            <h2>"\u{1F3A3} Anti-Hooking"</h2>
            <p>
                "Validates function prologue integrity against inline hooks (E9 / 48 B8),
                 incorporates direct syscall bypass paths, and deploys a 3-Tier Anti-Taint Engine
                 with Bidirectional Function I/O Entanglement."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Hook detection flow"</p>
            <div class="vis-frame">
                <AntiHookSvg />
            </div>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"3-Tier Anti-Taint Engine & I/O Entanglement"</p>
            <p class="text-sm">
                <strong>"Tier 1 (Global Identity LUT): "</strong>
                "Routes tainted registers through volatile memory lookups in a 256-byte private array (__ensia_launder_lut), severing direct ALU dataflow dependencies."
            </p>
            <p class="text-sm mt-sm">
                <strong>"Tier 2 (Implicit Control-Flow Bit Laundering): "</strong>
                "Synthesizes each byte bit-by-bit using select(bit_test, 1 << bit, 0) over pure compile-time constants. Because Dynamic Taint Analysis engines deliberately do not propagate taint across constant control dependencies to avoid taint explosion, taint tags are sanitized to clean."
            </p>
            <p class="text-sm mt-sm">
                <strong>"Tier 3 (SIMD Vector Taint Diffusion): "</strong>
                "Packs values into 128/256-bit SIMD vector registers, diffuses across lanes with shufflevector and polymorphic barriers, defeating scalar taint trackers (Triton / angr)."
            </p>
            <p class="text-sm mt-sm">
                <strong>"Bidirectional I/O Entanglement: "</strong>
                "Function arguments and return values are dynamically masked with runtime execution tokens (T_env / T_exp). If an adversary hooks a function or modifies memory, downstream computations silently corrupt without leaving an explicit taint trace."
            </p>
        </div>

        <AlgoConfigTable pass="anti_hooking" rows=vec![
            ("enabled",             "bool",   "false", "Verify function prologue integrity and activate anti-taint I/O entanglement."),
            ("inline_aarch64",      "bool",   "true",  "Scan AArch64 prologues for 0x14000001 (B .+4) and hook branch stubs."),
            ("inline_x86",          "bool",   "true",  "Scan x86_64 prologues for E9 (JMP) and 48 B8 (MOV RAX) inline patches."),
            ("inline_win",          "bool",   "true",  "Windows API inline hook detection."),
            ("objc_runtime",        "bool",   "false", "Inspect Objective-C method dispatch tables."),
            ("antirebind",          "bool",   "false", "Detect and counter dynamic linker rebinding (fishhook / dyld)."),
            ("direct_syscall",      "bool",   "false", "Bypass libc hooks with direct kernel syscalls (svc #0 / syscall)."),
            ("check_integrity",     "bool",   "true",  "Verify code segment cryptographic checksums to detect memory tampering."),
            ("precompiled_ir_path", "string", "\"\"",  "Path to external precompiled LLVM IR module containing verified defense stubs."),
        ]/>
    }
}

// ── Anti-Class Dump ───────────────────────────────────────────────────────

#[component]
fn AntiClassDumpSection() -> impl IntoView {
    view! {
        <div class="algo-header">
            <h2>"\u{1F50D} Anti-Class Dump"</h2>
            <p>
                "Objective-C specific pass. Prevents class-dump, otool, and
                 Frida from recovering class structures, method names, and
                 property lists from the Mach-O binary. Only active on targets
                 that support the Objective-C runtime (iOS, macOS)."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"What it protects"</p>
            <div class="vis-frame">
                <AntiClassDumpSvg />
            </div>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Five Defense-in-Depth ObjC Hardening Techniques (ADB & AntiHook Standard)"</p>
            <p>
                <strong>"1. Dynamic Stack String Decryption (Zero Plaintext in .rodata): "</strong>
                "All Objective-C class names, selector names, and method type encodings are compiled into XOR ciphertext.
                 At runtime, unrolled decryption loops restore strings directly on local stack buffers and pass them through
                 opaque hardware memory barriers. Zero plaintext metadata symbols survive in .rodata for class-dump or strings."
            </p>
            <p class="mt-sm">
                <strong>"2. Runtime Anti-Hooking & Anti-Tracing Guard: "</strong>
                "Prior to executing dynamic method registration, the initializer checks the prologue bytes of "
                <code class="font-mono">"class_replaceMethod"</code> " and " <code class="font-mono">"sel_registerName"</code> ".
                 On AArch64, it flags direct branches (B), breakpoints (BRK), and Frida trampolines (LDR X16/X17, [PC, #8]);
                 on x86_64, it flags 0xE9, 0xCC, 0xEB, and 0xFF 0x25. If hooked, it executes a direct kernel syscall abort (svc #0x80)."
            </p>
            <p class="mt-sm">
                <strong>"3. Hardware Memory Barriers & Volatile Sinks: "</strong>
                "All resolved class, selector, and IMP pointers pass through "
                <code class="font-mono">"insertOpaqueBarrier"</code>
                " (prfm pldl1keep; dmb ishld; isb) and volatile sink entanglement, preserving 46.9% of code under aggressive opt -O3
                 and preventing SMT/symbolic solvers from folding runtime bindings."
            </p>
            <p class="mt-sm">
                <strong>"4. Deceptive Honeypot Selectors: "</strong>
                "Injects realistic security-critical decoy selectors (e.g. "
                <code class="font-mono">"_validateAppReceiptStatus:error:"</code> ", "
                <code class="font-mono">"_decryptSecurePayloadWithKey:iv:"</code> ", "
                <code class="font-mono">"_checkJailbreakEnvironmentSandboxed:"</code>
                ") into the selector table to confuse automated Frida/Cycript introspection."
            </p>
            <p class="mt-sm">
                <strong>"5. ScrambleMethodOrder & Method IMP Renaming: "</strong>
                "The method list in each "
                <code class="font-mono">"objc_class"</code>
                " structure is shuffled in-place using Fisher-Yates, and internal IMP symbols are renamed to random hex tokens."
            </p>
        </div>

        <AlgoConfigTable pass="anti_class_dump" rows=vec![
            ("enabled", "bool", "false", "Obfuscate Objective-C class pointers and method lists (iOS/macOS only)."),
            ("use_initialize", "bool", "true", "Inject dynamic method registration code into +initialize instead of +load."),
            ("rename_methodimp", "bool", "false", "Scramble method implementation function symbol names with random 64-bit identifiers."),
            ("scramble_methods", "bool", "true", "Shuffle method list order using Fisher-Yates to break sequential dump heuristics."),
            ("dummy_selectors", "bool", "true", "Inject realistic security honeypot selectors to mislead dynamic tracers."),
            ("dummy_count", "u32", "8", "Number of honeypot decoy selectors to register at startup."),
            ("encrypt_strings", "bool", "true", "Zero plaintext metadata: encrypt all selector and class names via dynamic stack XOR buffers."),
            ("anti_hook", "bool", "true", "Inline prologue integrity verification on class_replaceMethod and sel_registerName."),
            ("opaque_barriers", "bool", "true", "Hardware memory barriers and opaque sink entanglement on registered IMPs."),
        ]/>
    }
}

// ── Function Call Obfuscation ─────────────────────────────────────────────

#[component]
fn FuncCallObfSection() -> impl IntoView {
    view! {
        <div class="algo-header">
            <h2>"\u{1F4DE} Function Call Obfuscation"</h2>
            <p>
                "Replaces direct "
                <code class="font-mono">"call"</code>
                " instructions with "
                <code class="font-mono">"dlopen"</code>
                " / "
                <code class="font-mono">"dlsym"</code>
                " indirection resolved at runtime. The symbol name string fed to
                 "
                <code class="font-mono">"dlsym"</code>
                " is itself encrypted by StringEncryption (when enabled), so
                 neither the call target nor the symbol name is statically visible.
                 Runs per-function in pipeline step 3, before CFG transforms."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Direct vs indirect call"</p>
            <div class="vis-frame">
                <FuncCallObfSvg />
            </div>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"dlopen / dlsym indirection"</p>
            <MathBlock formula=r"$$\texttt{call } f \;\Longrightarrow\; \texttt{call *dlsym(dlopen(lib, RTLD\_NOW), \textquotedbl{}}\mathit{sym}\texttt{\textquotedbl{}})$$" />
            <p class="text-sm mt-sm">
                "Each direct call instruction is replaced with a "
                <code class="font-mono">"dlopen"</code>
                " / "
                <code class="font-mono">"dlsym"</code>
                " pair that resolves the symbol by name at runtime.
                 The symbol name string is itself run through StringEncryption
                 (if enabled), so the target function name is never visible in
                 the binary as a plain string. Static disassemblers see only an
                 indirect call through the result of "
                <code class="font-mono">"dlsym"</code>
                " — the call graph edge disappears completely."
            </p>
        </div>

        <AlgoConfigTable pass="func_call_obf" rows=vec![
            ("enabled", "bool", "false", "Replace direct call instructions with indirect pointer-table calls."),
        ]/>
    }
}

// ── Basic Block Splitting ─────────────────────────────────────────────────

#[component]
fn SplitBlocksSection() -> impl IntoView {
    view! {
        <div class="algo-header">
            <h2>"\u{2702} Basic Block Splitting"</h2>
            <p>
                "Splits basic blocks at randomly chosen insertion points, enforced by
                 mandatory opaque predicate chaining and bogus target loops. This prevents
                 standard compiler optimizers (LLVM simplifycfg) from collapsing split blocks
                 while slicing multivariate MBA expression chains across block boundaries."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"CFG before and after splitting"</p>
            <div class="vis-frame">
                <SplitBlocksSvg />
            </div>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Splitting model + mandatory opaque chaining + stack confusion"</p>
            <MathBlock formula=r"$$B \xrightarrow{\text{split at }k} B_1 \xrightarrow{\text{opaque cond}} B_2 \quad\text{with}\quad B_{\text{bogus}} \to B_2, \quad k \sim \mathcal{U}[1, |B|-1]$$" />
            <p class="text-sm mt-sm">
                "A block "
                <em>"B"</em>
                " is split at a uniform-random position "
                <em>"k"</em>
                " into two blocks. Instead of an unconditional jump, Ensia binds every split boundary to a
                 provably opaque predicate "
                <code class="font-mono">"((seed * (seed + 1)) & 1) == 0"</code>
                " shielded by stateful barriers. A cold bogus target block loops back to the destination, ensuring
                 CFG restructuring survives LLVM -O3 passes. On "
                <strong>"x86_64 and AArch64"</strong>
                " targets, the splitting point also injects a stack-confusion
                 inline ASM sequence: a paired "
                <code class="font-mono">"push / pop"</code>
                " of a dead register value (x86_64) or a "
                <code class="font-mono">"str / ldr"</code>
                " to a scratch slot (AArch64). IDA Pro's and Binary Ninja's
                 stack-frame reconstruction heuristics mis-track the stack pointer
                 delta across the split, causing incorrect stack layout analysis
                 for the remainder of the function."
            </p>
        </div>

        <AlgoConfigTable pass="split_basic_blocks" rows=vec![
            ("enabled",     "bool",  "false", "Enable basic block splitting."),
            ("probability", "0-100", "50",    "Probability each basic block is selected for splitting."),
        ]/>
    }
}

// ── Anti-Debug SVG ────────────────────────────────────────────────────────

#[component]
fn AntiDebugSvg() -> impl IntoView {
    view! {
        <svg viewBox="0 0 480 180" xmlns="http://www.w3.org/2000/svg" style="max-width:480px">
            <defs>
                <marker id="arr-ad" markerWidth="7" markerHeight="5" refX="6" refY="2.5" orient="auto">
                    <polygon points="0 0, 7 2.5, 0 5" class="cfg-arrow"/>
                </marker>
                <marker id="arr-ad-ok" markerWidth="7" markerHeight="5" refX="6" refY="2.5" orient="auto">
                    <polygon points="0 0, 7 2.5, 0 5" class="cfg-arrow-true"/>
                </marker>
                <marker id="arr-ad-bad" markerWidth="7" markerHeight="5" refX="6" refY="2.5" orient="auto">
                    <polygon points="0 0, 7 2.5, 0 5" class="cfg-arrow-fake"/>
                </marker>
            </defs>
            <rect x="10" y="70" width="90" height="36" rx="6" class="cfg-node cfg-node-entry"/>
            <text x="55" y="88" text-anchor="middle" class="cfg-text">"fn_entry()"</text>
            <text x="55" y="99" text-anchor="middle" class="cfg-text-sm">"+anti-debug"</text>
            <path d="M100 88 H135" class="cfg-edge" marker-end="url(#arr-ad)"/>
            <rect x="135" y="54" width="100" height="28" rx="5" class="cfg-node"/>
            <text x="185" y="67" text-anchor="middle" class="cfg-text">"ptrace probe"</text>
            <text x="185" y="76" text-anchor="middle" class="cfg-text-sm">"PT_TRACE_ME"</text>
            <rect x="135" y="98" width="100" height="28" rx="5" class="cfg-node"/>
            <text x="185" y="111" text-anchor="middle" class="cfg-text">"timing check"</text>
            <text x="185" y="120" text-anchor="middle" class="cfg-text-sm">"\u{0394}t > \u{03C4}?"</text>
            <path d="M100 82 Q118 68 135 68" class="cfg-edge" marker-end="url(#arr-ad)"/>
            <path d="M100 95 Q118 112 135 112" class="cfg-edge" marker-end="url(#arr-ad)"/>
            <path d="M235 68 H270" class="cfg-edge" marker-end="url(#arr-ad)"/>
            <path d="M235 112 H270" class="cfg-edge" marker-end="url(#arr-ad)"/>
            <rect x="270" y="56" width="74" height="24" rx="5" class="cfg-node"/>
            <text x="307" y="73" text-anchor="middle" class="cfg-text">"OK"</text>
            <rect x="270" y="100" width="74" height="24" rx="5" class="cfg-node-fake"/>
            <text x="307" y="117" text-anchor="middle" class="cfg-text">"DETECTED"</text>
            <path d="M344 68 H380" class="cfg-edge cfg-edge-true" marker-end="url(#arr-ad-ok)"/>
            <rect x="380" y="56" width="90" height="24" rx="5" class="cfg-node"/>
            <text x="425" y="73" text-anchor="middle" class="cfg-text">"fn body"</text>
            <path d="M344 112 H380" class="cfg-edge cfg-edge-fake" marker-end="url(#arr-ad-bad)"/>
            <rect x="380" y="100" width="90" height="24" rx="5" class="cfg-node-fake"/>
            <text x="425" y="117" text-anchor="middle" class="cfg-text">"abort / trap"</text>
        </svg>
    }
}

#[component]
fn AntiHookSvg() -> impl IntoView {
    view! {
        <svg viewBox="0 0 500 190" xmlns="http://www.w3.org/2000/svg" style="max-width:500px">
            <defs>
                <marker id="arr-ah" markerWidth="7" markerHeight="5" refX="6" refY="2.5" orient="auto">
                    <polygon points="0 0, 7 2.5, 0 5" class="cfg-arrow"/>
                </marker>
            </defs>
            <text x="10" y="18" class="cfg-text" style="fill:var(--c-text-3);font-size:9px;letter-spacing:.1em">"CLEAN"</text>
            <rect x="10" y="24" width="90" height="52" rx="6" class="cfg-node cfg-node-entry"/>
            <text x="55" y="44" text-anchor="middle" class="cfg-text">"target_fn"</text>
            <text x="55" y="56" text-anchor="middle" class="cfg-text" style="fill:var(--c-success);font-size:9px">"PUSH rbp"</text>
            <text x="55" y="66" text-anchor="middle" class="cfg-text" style="fill:var(--c-success);font-size:9px">"MOV rbp,rsp"</text>

            <text x="140" y="18" class="cfg-text" style="fill:var(--c-text-3);font-size:9px;letter-spacing:.1em">"HOOKED"</text>
            <rect x="140" y="24" width="90" height="52" rx="6" class="cfg-node-fake"/>
            <text x="185" y="44" text-anchor="middle" class="cfg-text">"target_fn"</text>
            <text x="185" y="56" text-anchor="middle" class="cfg-text" style="fill:var(--c-accent);font-size:9px">"JMP hook_fn"</text>
            <text x="185" y="66" text-anchor="middle" class="cfg-text" style="fill:var(--c-text-3);font-size:9px">"(overwritten)"</text>

            <text x="240" y="100" class="cfg-text" style="fill:var(--c-primary);font-size:20px;font-weight:700">"\u{2192}"</text>

            <text x="270" y="18" class="cfg-text" style="fill:var(--c-text-3);font-size:9px;letter-spacing:.1em">"CHECK AT STARTUP"</text>
            <rect x="270" y="24" width="110" height="36" rx="6" class="cfg-node"/>
            <text x="325" y="38" text-anchor="middle" class="cfg-text">"load expected"</text>
            <text x="325" y="50" text-anchor="middle" class="cfg-text-sm">"fn[0..N] bytes"</text>
            <path d="M325 60 V85" class="cfg-edge" marker-end="url(#arr-ah)"/>
            <rect x="270" y="85" width="110" height="36" rx="6" class="cfg-node"/>
            <text x="325" y="99" text-anchor="middle" class="cfg-text">"compare live"</text>
            <text x="325" y="111" text-anchor="middle" class="cfg-text-sm">"prologue bytes"</text>
            <path d="M325 121 L310 145" class="cfg-edge cfg-edge-true" marker-end="url(#arr-ah)"/>
            <path d="M325 121 L355 145" class="cfg-edge cfg-edge-fake" marker-end="url(#arr-ah)"/>
            <rect x="270" y="145" width="60" height="28" rx="5" class="cfg-node"/>
            <text x="300" y="164" text-anchor="middle" class="cfg-text">"clean"</text>
            <rect x="345" y="145" width="70" height="28" rx="5" class="cfg-node-fake"/>
            <text x="380" y="164" text-anchor="middle" class="cfg-text">"hook detected"</text>
        </svg>
    }
}

#[component]
fn AntiClassDumpSvg() -> impl IntoView {
    view! {
        <svg viewBox="0 0 500 170" xmlns="http://www.w3.org/2000/svg" style="max-width:500px">
            <defs>
                <marker id="arr-acd" markerWidth="7" markerHeight="5" refX="6" refY="2.5" orient="auto">
                    <polygon points="0 0, 7 2.5, 0 5" class="cfg-arrow"/>
                </marker>
            </defs>
            <text x="10" y="18" class="cfg-text" style="fill:var(--c-text-3);font-size:9px;letter-spacing:.1em">"MACH-O __DATA,__objc_classlist"</text>

            <rect x="10" y="26" width="140" height="36" rx="6" class="cfg-node cfg-node-entry"/>
            <text x="80" y="40" text-anchor="middle" class="cfg-text">"MyClass *"</text>
            <text x="80" y="52" text-anchor="middle" class="cfg-text-sm">"raw pointer (visible)"</text>

            <path d="M155 44 H185" class="cfg-edge" marker-end="url(#arr-acd)"/>
            <text x="162" y="40" class="cfg-text-sm">"obfuscate"</text>

            <rect x="185" y="26" width="140" height="36" rx="6" class="cfg-node-fake"/>
            <text x="255" y="40" text-anchor="middle" class="cfg-text">"0x???? ^ key"</text>
            <text x="255" y="52" text-anchor="middle" class="cfg-text-sm">"encrypted pointer"</text>

            <text x="10" y="100" class="cfg-text" style="fill:var(--c-text-3);font-size:9px;letter-spacing:.1em">"RUNTIME (+load / dyld)"</text>
            <rect x="10" y="108" width="140" height="36" rx="6" class="cfg-node"/>
            <text x="80" y="122" text-anchor="middle" class="cfg-text">"decrypt_stub()"</text>
            <text x="80" y="134" text-anchor="middle" class="cfg-text-sm">"called before +load"</text>
            <path d="M150 126 H185" class="cfg-edge cfg-edge-true" marker-end="url(#arr-acd)"/>
            <rect x="185" y="108" width="140" height="36" rx="6" class="cfg-node"/>
            <text x="255" y="122" text-anchor="middle" class="cfg-text">"real MyClass *"</text>
            <text x="255" y="134" text-anchor="middle" class="cfg-text-sm">"restored in memory"</text>

            <text x="370" y="44" class="cfg-text" style="fill:var(--c-danger);font-size:10px">"class-dump"</text>
            <text x="370" y="58" class="cfg-text-sm" style="fill:var(--c-text-3)">"reads disk:"</text>
            <text x="370" y="70" class="cfg-text-sm" style="fill:var(--c-text-3)">"sees 0x???? (fail)"</text>
            <text x="370" y="122" class="cfg-text" style="fill:var(--c-success);font-size:10px">"ObjC runtime"</text>
            <text x="370" y="136" class="cfg-text-sm" style="fill:var(--c-text-3)">"reads memory:"</text>
            <text x="370" y="148" class="cfg-text-sm" style="fill:var(--c-text-3)">"decrypted OK"</text>
        </svg>
    }
}

#[component]
fn FuncCallObfSvg() -> impl IntoView {
    view! {
        <svg viewBox="0 0 500 180" xmlns="http://www.w3.org/2000/svg" style="max-width:500px">
            <defs>
                <marker id="arr-fco" markerWidth="7" markerHeight="5" refX="6" refY="2.5" orient="auto">
                    <polygon points="0 0, 7 2.5, 0 5" class="cfg-arrow"/>
                </marker>
            </defs>
            <text x="10" y="18" class="cfg-text" style="fill:var(--c-text-3);font-size:9px;letter-spacing:.1em">"BEFORE"</text>
            <rect x="10" y="26" width="120" height="30" rx="5" class="cfg-node cfg-node-entry"/>
            <text x="70" y="46" text-anchor="middle" class="cfg-text">"CALL crypto_fn"</text>
            <path d="M130 41 H170" class="cfg-edge" marker-end="url(#arr-fco)"/>
            <rect x="170" y="26" width="100" height="30" rx="5" class="cfg-node"/>
            <text x="220" y="46" text-anchor="middle" class="cfg-text">"crypto_fn"</text>

            <text x="10" y="100" class="cfg-text" style="fill:var(--c-text-3);font-size:9px;letter-spacing:.1em">"AFTER"</text>
            <rect x="10" y="108" width="120" height="30" rx="5" class="cfg-node cfg-node-entry"/>
            <text x="70" y="128" text-anchor="middle" class="cfg-text">"CALL *table[h(f)]"</text>
            <path d="M130 123 H155" class="cfg-edge cfg-edge-fake" marker-end="url(#arr-fco)"/>
            <rect x="155" y="90" width="90" height="26" rx="5" class="cfg-node-fake"/>
            <text x="200" y="107" text-anchor="middle" class="cfg-text">"fn_ptr_table"</text>
            <text x="200" y="118" text-anchor="middle" class="cfg-text-sm">"[h(crypto_fn)]"</text>
            <path d="M245 103 H280" class="cfg-edge cfg-edge-fake" marker-end="url(#arr-fco)"/>
            <rect x="280" y="90" width="90" height="26" rx="5" class="cfg-node"/>
            <text x="325" y="107" text-anchor="middle" class="cfg-text">"crypto_fn"</text>

            <text x="160" y="165" class="cfg-text" style="fill:var(--c-text-3);font-size:9px">
                "static analysis: call target = ?? (runtime only)"
            </text>
        </svg>
    }
}

#[component]
fn SplitBlocksSvg() -> impl IntoView {
    view! {
        <svg viewBox="0 0 500 200" xmlns="http://www.w3.org/2000/svg" style="max-width:500px">
            <defs>
                <marker id="arr-sb" markerWidth="7" markerHeight="5" refX="6" refY="2.5" orient="auto">
                    <polygon points="0 0, 7 2.5, 0 5" class="cfg-arrow"/>
                </marker>
            </defs>
            <text x="10" y="18" class="cfg-text" style="fill:var(--c-text-3);font-size:9px;letter-spacing:.1em">"BEFORE"</text>
            <rect x="10" y="26" width="100" height="80" rx="6" class="cfg-node cfg-node-entry"/>
            <text x="60" y="48" text-anchor="middle" class="cfg-text">"Block B"</text>
            <text x="60" y="62" text-anchor="middle" class="cfg-text-sm">"inst 1"</text>
            <text x="60" y="74" text-anchor="middle" class="cfg-text-sm">"inst 2"</text>
            <text x="60" y="86" text-anchor="middle" class="cfg-text-sm">"inst 3"</text>
            <text x="60" y="98" text-anchor="middle" class="cfg-text-sm">"inst 4"</text>

            <text x="170" y="60" class="cfg-text" style="fill:var(--c-primary);font-size:22px;font-weight:700">"\u{2192}"</text>

            <text x="210" y="18" class="cfg-text" style="fill:var(--c-text-3);font-size:9px;letter-spacing:.1em">"AFTER SPLIT"</text>
            <rect x="210" y="26" width="100" height="46" rx="6" class="cfg-node cfg-node-entry"/>
            <text x="260" y="44" text-anchor="middle" class="cfg-text">"B1"</text>
            <text x="260" y="58" text-anchor="middle" class="cfg-text-sm">"inst 1"</text>
            <text x="260" y="68" text-anchor="middle" class="cfg-text-sm">"inst 2"</text>

            <path d="M260 72 V100" class="cfg-edge" marker-end="url(#arr-sb)"/>
            <text x="265" y="90" class="cfg-text-sm" style="fill:var(--c-primary)">"JMP"</text>

            <rect x="210" y="100" width="100" height="46" rx="6" class="cfg-node"/>
            <text x="260" y="118" text-anchor="middle" class="cfg-text">"B2"</text>
            <text x="260" y="132" text-anchor="middle" class="cfg-text-sm">"inst 3"</text>
            <text x="260" y="142" text-anchor="middle" class="cfg-text-sm">"inst 4"</text>

            <text x="360" y="60" class="cfg-text" style="fill:var(--c-text-3);font-size:9px">
                "CFG nodes: 1 \u{2192} 2"
            </text>
            <text x="360" y="78" class="cfg-text" style="fill:var(--c-text-3);font-size:9px">
                "edges: 0 \u{2192} 1"
            </text>
            <text x="360" y="96" class="cfg-text" style="fill:var(--c-text-3);font-size:9px">
                "analysis cost"
            </text>
            <text x="360" y="110" class="cfg-text" style="fill:var(--c-text-3);font-size:9px">
                "scales with |nodes|"
            </text>
        </svg>
    }
}

// ── KaTeX math block ──────────────────────────────────────────────────────

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = triggerKatex, catch)]
    fn trigger_katex() -> Result<(), wasm_bindgen::JsValue>;
}

#[component]
fn MathBlock(formula: &'static str) -> impl IntoView {
    let el = NodeRef::<html::Div>::new();
    Effect::new(move |_| {
        if let Some(el) = el.get() {
            el.set_inner_html(formula);
            let _ = trigger_katex();
        }
    });
    view! {
        <div class="math-block" node_ref=el></div>
    }
}

// ── Config table ──────────────────────────────────────────────────────────

#[component]
fn AlgoConfigTable(
    pass: &'static str,
    rows: Vec<(&'static str, &'static str, &'static str, &'static str)>,
) -> impl IntoView {
    view! {
        <div class="glass card-pad">
            <p class="algo-section-title">"TOML configuration \u{2014} [passes." {pass} "]"</p>
            <table class="cfg-table">
                <thead>
                    <tr>
                        <th>"Key"</th>
                        <th>"Type / Range"</th>
                        <th>"Default"</th>
                        <th>"Description"</th>
                    </tr>
                </thead>
                <tbody>
                    {rows.into_iter().map(|(k, t, d, desc)| view! {
                        <tr>
                            <td>{k}</td>
                            <td>{t}</td>
                            <td>{d}</td>
                            <td>{desc}</td>
                        </tr>
                    }).collect_view()}
                </tbody>
            </table>
        </div>
    }
}

// ── SVG Visualisations ─────────────────────────────────────────────────────

#[component]
fn BcfSvg() -> impl IntoView {
    view! {
        <svg viewBox="0 0 520 210" xmlns="http://www.w3.org/2000/svg" style="max-width:520px">
            <defs>
                <marker id="arr-bcf" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
                    <polygon points="0 0, 8 3, 0 6" class="cfg-arrow" />
                </marker>
                <marker id="arr-bcf-fake" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
                    <polygon points="0 0, 8 3, 0 6" class="cfg-arrow-fake" />
                </marker>
                <marker id="arr-bcf-true" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
                    <polygon points="0 0, 8 3, 0 6" class="cfg-arrow-true" />
                </marker>
            </defs>

            <text x="80" y="18" class="cfg-text" font-weight="600" fill="currentColor" style="fill:var(--c-text-3);font-size:10px;letter-spacing:.1em">
                "BEFORE"
            </text>
            <rect x="55" y="28" width="80" height="32" rx="6" class="cfg-node cfg-node-entry"/>
            <text x="95" y="49" text-anchor="middle" class="cfg-text">"Block A"</text>

            <path d="M95 60 V82" class="cfg-edge" marker-end="url(#arr-bcf)" />

            <rect x="55" y="82" width="80" height="32" rx="6" class="cfg-node"/>
            <text x="95" y="103" text-anchor="middle" class="cfg-text">"Block B"</text>

            <path d="M95 114 V136" class="cfg-edge" marker-end="url(#arr-bcf)" />

            <rect x="55" y="136" width="80" height="32" rx="6" class="cfg-node"/>
            <text x="95" y="157" text-anchor="middle" class="cfg-text">"Block C"</text>

            <text x="190" y="108" class="cfg-text" style="fill:var(--c-primary);font-size:22px;font-weight:700">
                "\u{2192}"
            </text>

            <text x="255" y="18" class="cfg-text" font-weight="600" style="fill:var(--c-text-3);font-size:10px;letter-spacing:.1em">
                "AFTER BCF"
            </text>
            <rect x="230" y="28" width="100" height="32" rx="6" class="cfg-node cfg-node-entry"/>
            <text x="280" y="44" text-anchor="middle" class="cfg-text">"Block A"</text>
            <text x="280" y="55" text-anchor="middle" class="cfg-text-sm">"+ opaque pred"</text>

            <path d="M280 60 V84" class="cfg-edge cfg-edge-true" marker-end="url(#arr-bcf-true)" />
            <text x="285" y="76" class="cfg-label-edge" style="fill:var(--c-success)">"always true"</text>

            <rect x="240" y="84" width="80" height="32" rx="6" class="cfg-node"/>
            <text x="280" y="105" text-anchor="middle" class="cfg-text">"Block B"</text>

            <path d="M280 116 V140" class="cfg-edge" marker-end="url(#arr-bcf)" />

            <rect x="240" y="140" width="80" height="32" rx="6" class="cfg-node"/>
            <text x="280" y="161" text-anchor="middle" class="cfg-text">"Block C"</text>

            <path d="M330 44 Q420 44 420 96" class="cfg-edge cfg-edge-fake" marker-end="url(#arr-bcf-fake)" />
            <text x="355" y="38" class="cfg-label-edge" style="fill:var(--c-accent)">"dead branch"</text>

            <rect x="380" y="84" width="80" height="32" rx="6" class="cfg-node-fake"/>
            <text x="420" y="100" text-anchor="middle" class="cfg-text">"B' (bogus)"</text>
            <text x="420" y="111" text-anchor="middle" class="cfg-text-sm">"junk / mutated"</text>

            <path d="M460 100 Q510 100 510 50 Q510 12 330 12" class="cfg-edge cfg-edge-fake" style="stroke-opacity:0.4"/>
        </svg>
    }
}

#[component]
fn CffSvg() -> impl IntoView {
    view! {
        <svg viewBox="0 0 520 220" xmlns="http://www.w3.org/2000/svg" style="max-width:520px">
            <defs>
                <marker id="arr-cff" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
                    <polygon points="0 0, 8 3, 0 6" class="cfg-arrow"/>
                </marker>
            </defs>
            <text x="50" y="16" class="cfg-text" style="fill:var(--c-text-3);font-size:10px;letter-spacing:.1em">"BEFORE"</text>
            <rect x="50" y="24" width="70" height="28" rx="5" class="cfg-node cfg-node-entry"/>
            <text x="85" y="43" text-anchor="middle" class="cfg-text">"A"</text>
            <path d="M85 52 V74" class="cfg-edge" marker-end="url(#arr-cff)"/>
            <rect x="50" y="74" width="70" height="28" rx="5" class="cfg-node"/>
            <text x="85" y="93" text-anchor="middle" class="cfg-text">"B"</text>
            <path d="M85 102 L60 124" class="cfg-edge" marker-end="url(#arr-cff)"/>
            <path d="M85 102 L110 124" class="cfg-edge" marker-end="url(#arr-cff)"/>
            <rect x="28" y="124" width="65" height="28" rx="5" class="cfg-node"/>
            <text x="60" y="143" text-anchor="middle" class="cfg-text">"C"</text>
            <rect x="102" y="124" width="65" height="28" rx="5" class="cfg-node"/>
            <text x="135" y="143" text-anchor="middle" class="cfg-text">"D"</text>

            <text x="190" y="108" class="cfg-text" style="fill:var(--c-primary);font-size:22px;font-weight:700">"\u{2192}"</text>

            <text x="230" y="16" class="cfg-text" style="fill:var(--c-text-3);font-size:10px;letter-spacing:.1em">"AFTER CFF"</text>
            <rect x="250" y="24" width="100" height="28" rx="5" class="cfg-node cfg-node-entry"/>
            <text x="300" y="38" text-anchor="middle" class="cfg-text">"dispatch(state)"</text>
            <text x="300" y="48" text-anchor="middle" class="cfg-text-sm">"switch"</text>

            <path d="M260 52 L230 84" class="cfg-edge cfg-edge-fake" marker-end="url(#arr-cff)"/>
            <path d="M285 52 L285 84" class="cfg-edge cfg-edge-fake" marker-end="url(#arr-cff)"/>
            <path d="M315 52 L340 84" class="cfg-edge cfg-edge-fake" marker-end="url(#arr-cff)"/>
            <path d="M345 52 L395 84" class="cfg-edge cfg-edge-fake" marker-end="url(#arr-cff)"/>

            <rect x="205" y="84" width="46" height="28" rx="5" class="cfg-node"/>
            <text x="228" y="103" text-anchor="middle" class="cfg-text">"A"</text>
            <rect x="262" y="84" width="46" height="28" rx="5" class="cfg-node"/>
            <text x="285" y="103" text-anchor="middle" class="cfg-text">"B"</text>
            <rect x="319" y="84" width="46" height="28" rx="5" class="cfg-node"/>
            <text x="342" y="103" text-anchor="middle" class="cfg-text">"C"</text>
            <rect x="375" y="84" width="46" height="28" rx="5" class="cfg-node"/>
            <text x="398" y="103" text-anchor="middle" class="cfg-text">"D"</text>

            <path d="M228 112 Q200 155 248 168 Q298 178 300 52" class="cfg-edge" style="stroke-opacity:0.35" marker-end="url(#arr-cff)"/>
            <text x="210" y="162" class="cfg-text-sm">"state = next"</text>
        </svg>
    }
}

#[component]
fn StrEncSvg() -> impl IntoView {
    view! {
        <svg viewBox="0 0 440 140" xmlns="http://www.w3.org/2000/svg" style="max-width:440px">
            <text x="10" y="24" class="cfg-text" style="fill:var(--c-text-3);font-size:9px;letter-spacing:.1em">"PLAINTEXT"</text>
            {[("K", 75u8), ("E", 69u8), ("Y", 89u8)].iter().enumerate().map(|(i, (c, ascii))| {
                let x = 10 + i as i32 * 58;
                view! {
                    <rect x={x} y="30" width="46" height="36" rx="6" class="cfg-node cfg-node-entry"/>
                    <text x={x + 23} y="53" text-anchor="middle" class="cfg-text" font-weight="700">{*c}</text>
                    <text x={x + 23} y="63" text-anchor="middle" class="cfg-text-sm">{format!("{}", ascii)}</text>
                }
            }).collect_view()}
            {(0..3).map(|i| {
                let x = 10 + i * 58 + 20;
                view! {
                    <text x={x} y="82" text-anchor="middle" class="cfg-text" style="fill:var(--c-primary)">
                        "\u{2295}"
                    </text>
                }
            }).collect_view()}
            <text x="10" y="98" class="cfg-text" style="fill:var(--c-text-3);font-size:9px;letter-spacing:.1em">"KEY"</text>
            {["r1","r2","r3"].iter().enumerate().map(|(i, k)| {
                let x = 10 + i as i32 * 58;
                view! {
                    <rect x={x} y="100" width="46" height="28" rx="5" class="cfg-node-fake"/>
                    <text x={x + 23} y="119" text-anchor="middle" class="cfg-text" style="fill:var(--c-accent)">{*k}</text>
                }
            }).collect_view()}
            <text x="215" y="24" class="cfg-text" style="fill:var(--c-text-3);font-size:9px;letter-spacing:.1em">"CIPHERTEXT"</text>
            {["c1","c2","c3"].iter().enumerate().map(|(i, c)| {
                let x = 215 + i as i32 * 58;
                view! {
                    <rect x={x} y="30" width="46" height="36" rx="6" class="cfg-node"/>
                    <text x={x + 23} y="53" text-anchor="middle" class="cfg-text" style="fill:var(--c-primary);font-weight:700">{*c}</text>
                    <text x={x + 23} y="63" text-anchor="middle" class="cfg-text-sm">"0x??"</text>
                }
            }).collect_view()}
            <text x="188" y="53" class="cfg-text" style="fill:var(--c-primary);font-size:18px;font-weight:700">"\u{2192}"</text>
        </svg>
    }
}

#[component]
fn ConstEncSvg() -> impl IntoView {
    view! {
        <svg viewBox="0 0 420 170" xmlns="http://www.w3.org/2000/svg" style="max-width:420px">
            <defs>
                <marker id="arr-ce" markerWidth="7" markerHeight="5" refX="6" refY="2.5" orient="auto">
                    <polygon points="0 0, 7 2.5, 0 5" class="cfg-arrow"/>
                </marker>
            </defs>
            <text x="10" y="18" class="cfg-text" style="fill:var(--c-text-3);font-size:9px;letter-spacing:.1em">"CONSTANT"</text>
            <rect x="10" y="24" width="80" height="36" rx="6" class="cfg-node cfg-node-entry"/>
            <text x="50" y="42" text-anchor="middle" class="cfg-text" font-weight="700">"C = 42"</text>
            <text x="50" y="54" text-anchor="middle" class="cfg-text-sm">"0x0000002A"</text>

            <path d="M90 42 H120" class="cfg-edge" marker-end="url(#arr-ce)"/>
            <text x="95" y="38" class="cfg-text-sm">"split into k=3 shares"</text>

            <text x="125" y="18" class="cfg-text" style="fill:var(--c-text-3);font-size:9px;letter-spacing:.1em">"SHARES  (stored in global vars)"</text>
            {[("s1","r1"),("s2","r2"),("s3","r1^r2^42")].iter().enumerate().map(|(i, (name, val))| {
                let x = 125 + i as i32 * 90;
                view! {
                    <rect x={x} y="24" width="78" height="36" rx="6" class="cfg-node-fake"/>
                    <text x={x+39} y="40" text-anchor="middle" class="cfg-text" style="fill:var(--c-accent);font-weight:600">{*name}</text>
                    <text x={x+39} y="52" text-anchor="middle" class="cfg-text-sm">{*val}</text>
                }
            }).collect_view()}

            <text x="125" y="82" class="cfg-text" style="fill:var(--c-text-3);font-size:9px;letter-spacing:.1em">"RUNTIME RECONSTRUCTION"</text>
            <rect x="125" y="90" width="278" height="36" rx="6" class="cfg-node"/>
            <text x="264" y="108" text-anchor="middle" class="cfg-text">"s1 XOR s2 XOR s3  =  42"</text>
            <text x="264" y="120" text-anchor="middle" class="cfg-text-sm">"load + xor sequence in IR"</text>

            {(0..3).map(|i| {
                let x = 164 + i * 90;
                view! {
                    <path d={format!("M {} 60 V 90", x)} class="cfg-edge" style="stroke-opacity:0.5" marker-end="url(#arr-ce)"/>
                }
            }).collect_view()}
        </svg>
    }
}
