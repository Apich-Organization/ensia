use leptos::{html, prelude::*};

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
    AlgoMeta { key: Algo::Bcf,         icon: "\u{1F500}", label: "Bogus Control Flow" },
    AlgoMeta { key: Algo::Cff,         icon: "\u{2B1B}",  label: "Control Flow Flattening" },
    AlgoMeta { key: Algo::Csm,         icon: "\u{1F300}", label: "Chaos State Machine" },
    AlgoMeta { key: Algo::StrEnc,      icon: "\u{1F512}", label: "String Encryption" },
    AlgoMeta { key: Algo::ConstEnc,    icon: "\u{1F9EE}", label: "Constant Encryption" },
    AlgoMeta { key: Algo::Sub,         icon: "+",         label: "Instruction Substitution" },
    AlgoMeta { key: Algo::Mba,         icon: "\u{03A3}",  label: "Mixed Boolean-Arithmetic" },
    AlgoMeta { key: Algo::Vec,         icon: "\u{2B21}",  label: "Vector Obfuscation" },
    AlgoMeta { key: Algo::IndirBranch, icon: "\u{21A9}",  label: "Indirect Branching" },
    AlgoMeta { key: Algo::FuncWrap,    icon: "\u{1F4E6}", label: "Function Wrapper" },
    AlgoMeta { key: Algo::AntiDebug,   icon: "\u{1F41B}", label: "Anti-Debugging" },
    AlgoMeta { key: Algo::AntiHook,    icon: "\u{1F3A3}", label: "Anti-Hooking" },
    AlgoMeta { key: Algo::AntiClassDump, icon: "\u{1F50D}", label: "Anti-Class Dump" },
    AlgoMeta { key: Algo::FuncCallObf, icon: "\u{1F4DE}", label: "Call Obfuscation" },
    AlgoMeta { key: Algo::SplitBlocks, icon: "\u{2702}",  label: "Block Splitting" },
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
                 to create fake branches that lead to cloned or junk code."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"How it works"</p>
            <p>
                "BCF uses four hardware-predicate tiers in descending order of strength.
                 Tier 1: CPUID SSE-feature bit (always set on any modern x86; reads a CPU
                 register, cannot be patched without changing CPUID output).
                 Tier 2: RDTSC parity check (a timing register sampled at compile time,
                 unpredictable to a static solver).
                 Tier 3: AArch64 "
                <code class="font-mono">"MRS x0, CNTPCT_EL0"</code>
                " counter (same idea on ARM64).
                 Tier 4: software fallback — the classic "
                <code class="font-mono">"(x*x - x) % 2 == 0"</code>
                " identity for any integer "
                <code class="font-mono">"x"</code>
                ". Each selected block is cloned into an original and a bogus copy;
                 the opaque predicate routes control to the original while the bogus copy
                 contains corrupted or junk instructions that never execute."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Control-flow graph transformation"</p>
            <div class="vis-frame">
                <BcfSvg />
            </div>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Tier-1 predicate: CPUID SSE bit (strongest)"</p>
            <MathBlock formula=r"$$\texttt{CPUID}(1).\text{ECX}[25] = 1 \;\;\forall\text{ modern x86}$$" />
            <p class="text-sm mt-sm">
                "The SSE4.2 feature flag in ECX bit 25 is always set on any processor
                 released after 2008. Reading it via the "
                <code class="font-mono">"CPUID"</code>
                " instruction is non-patchable without hardware-level intervention.
                 Fallback software predicate: "
                <em>"x(x-1)"</em>
                " is always even for any integer (product of two consecutive integers)."
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
                 single dispatch loop: a switch statement selects which original
                 basic block executes each iteration, completely hiding the
                 original control flow from a static analyser."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Transformation overview"</p>
            <div class="vis-frame">
                <CffSvg />
            </div>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Dispatch variable"</p>
            <MathBlock formula=r"$$\texttt{state}_{n+1} = f(\texttt{state}_n, \text{branch outcome})$$" />
            <p class="text-sm mt-sm">
                "Each original basic block writes its successor's scrambled ID into "
                <code class="font-mono">"state"</code>
                " before jumping back to the dispatcher. The ID mapping is seeded by a
                 chaos key so IDs are unique and non-sequential.
                 A double-pointer indirection ("
                <code class="font-mono">"**state_ptr"</code>
                ") and a volatile XOR/ADD chain protect the state variable from
                 constant-propagation optimisation that would collapse the switch."
            </p>
        </div>

        <AlgoConfigTable pass="flattening" rows=vec![
            ("enabled", "bool", "false", "Enable classic CFF. Functions already handled by CSM are skipped automatically."),
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
                "CSM is an advanced CFF variant that drives the dispatch variable
                 through the logistic map — a chaotic, non-linear recurrence
                 relation. The resulting jump table is impossible to unroll
                 symbolically."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Q16 fixed-point IR recurrence"</p>
            <MathBlock formula=r"$$x_{n+1} = r \cdot x_n \cdot (1 - x_n), \quad r \approx 3.9999,\; x_n \in Q_{16}$$" />
            <p class="text-sm mt-sm">
                "The logistic map is evaluated entirely in Q16 fixed-point arithmetic
                 inside the IR — no floating-point types are used. The IR chain per
                 iteration is: "
                <code class="font-mono">"zext"</code>
                " -> "
                <code class="font-mono">"and"</code>
                " -> "
                <code class="font-mono">"sub"</code>
                " -> "
                <code class="font-mono">"mul"</code>
                " -> "
                <code class="font-mono">"lshr"</code>
                " -> "
                <code class="font-mono">"trunc"</code>
                ". Block-exit correctness is preserved: the state value written at each
                 block exit is proven to map uniquely to its successor under the
                 Feistel constant seeded from the function's chaos key."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Why it defeats symbolic execution"</p>
            <p>
                "A classic switch dispatch collapses in a few SMT solver iterations.
                 CSM's state transitions require tracking Q16 fixed-point multiply
                 semantics across up to 512 warmup iterations plus the live block chain.
                 Each iteration's intermediate values are interdependent, so memoisation
                 does not help. CSM-processed functions are automatically skipped by
                 the classic Flattening pass to avoid conflicting transforms."
            </p>
        </div>

        <AlgoConfigTable pass="chaos_state_machine" rows=vec![
            ("enabled",         "bool",    "false", "Enable CSM. Subsumes classic flattening on processed functions."),
            ("warmup",          "16-512",  "64",    "Number of logistic-map iterations discarded before use."),
            ("nested_dispatch", "bool",    "false", "Add a second dispatch level for maximum CFG complexity."),
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
                 pseudo-random key using a Vernam cipher over GF(2^8).
                 A stub function decrypts the bytes at runtime on first access."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Dual-layer cipher: Vernam + GF(2^8)"</p>
            <MathBlock formula=r"$$c_i = \bigl(p_i \oplus k^{(1)}_i\bigr) \;\cdot_{GF(2^8)}\; k^{(2)}_i, \quad \text{poly} = x^8+x^4+x^3+x+1 \;(0x11b)$$" />
            <p class="text-sm mt-sm">
                "Layer 1 is a classical Vernam OTP XOR: each plaintext byte is XOR-ed
                 with a random per-string key byte. Layer 2 multiplies the XOR result
                 by a second random key byte in "
                <strong>"GF(2^8)"</strong>
                " using the AES irreducible polynomial 0x11b. This means recovering
                 a plaintext byte requires inverting a GF multiply — a non-linear
                 operation over a finite field, not a simple XOR. Both key halves
                 are stored in separate split-key globals so alias analysis cannot
                 reassemble them. The decryption stub runs in unordered (random)
                 byte sequence to defeat pattern-matching disassemblers."
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
                "Integer constants are split into "
                <em>"k"</em>
                " shares whose XOR equals the original value.
                 An optional Feistel-network layer adds 26 non-linear
                 IR instructions per constant for resistance to
                 arithmetic-only analyses."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"k-share XOR ensemble (all-shares-required threshold)"</p>
            <MathBlock formula=r"$$C = s_1 \oplus s_2 \oplus \cdots \oplus s_k, \quad s_i \in_R \{0,\ldots,2^{64}-1\},\; s_k = C \oplus \bigoplus_{i=1}^{k-1} s_i$$" />
            <p class="text-sm mt-sm">
                "The scheme is a (k, k) secret-sharing threshold: all "
                <em>"k"</em>
                " shares must be XOR-ed to reconstruct "
                <em>"C"</em>
                ". Each share is stored in its own separate global variable
                 so LLVM alias analysis cannot collapse them into a single load.
                 This is analogous to thermodynamic entropy: observing any strict
                 subset of shares leaks zero information about "
                <em>"C"</em>
                "."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Feistel nonlinear layer"</p>
            <MathBlock formula=r"$$L_{n+1} = R_n, \quad R_{n+1} = L_n \oplus F(R_n)$$" />
            <p class="text-sm mt-sm">
                "The 32-bit Feistel round function "
                <em>"F"</em>
                " uses multiply-add-XOR mixing, requiring a solver to
                 invert a non-linear bijection to recover the original value."
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
                 addition and multiplication. These identities hold over "
                <strong>"Z/2^nZ"</strong>
                " but are intractable for algebraic simplifiers."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"MBA identity for addition"</p>
            <MathBlock formula=r"$$a + b \equiv (a \oplus b) + 2(a \wedge b) \pmod{2^n}$$" />
            <p class="text-sm mt-sm">
                "This generalises: the XOR captures bits where carries do not
                 propagate, and the AND detects carry positions. Chaining
                 multiple such identities (controlled by "
                <em>"layers"</em>
                ") compounds the complexity."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"42 built-in identity variants"</p>
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
                " — 42 variants total. Each replaces a single instruction with a
                 multi-term boolean-arithmetic expression. The zero-term injection
                 engine appends additional zero-valued MBA expressions
                 (e.g. "
                <code class="font-mono">"(x & ~x)"</code>
                ", "
                <code class="font-mono">"(x ^ x)"</code>
                ") to further obscure the identity without changing the value.
                 Chaining multiple layers compounds the complexity multiplicatively."
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
                 space, shuffled across lanes, operated on, then extracted.
                 The resulting code requires a vectorisation-aware decompiler
                 to reconstruct the original scalar semantics."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Lane-insert strategy"</p>
            <MathBlock formula=r"$$\text{scalar } x \;\xrightarrow{\texttt{insertelement}}\; \langle r_0, \ldots, x_L, \ldots, r_{W-1} \rangle \;\xrightarrow{\text{op}}\; \texttt{extractelement}_{L}$$" />
            <p class="text-sm mt-sm">
                "The scalar is inserted into a random lane "
                <em>"L"</em>
                " of a vector of width "
                <em>"W"</em>
                " (64 / 128 / 256 bits) using "
                <code class="font-mono">"insertelement"</code>
                ". Filler lanes are populated with random values so the vector
                 looks non-trivial to a vectoriser. The shift amount in shift
                 instructions is first broadcast to all lanes via "
                <code class="font-mono">"shufflevector"</code>
                " before the vector shift, matching the LLVM vector-shift semantics
                 requirement. Integer comparisons ("
                <code class="font-mono">"ICmp"</code>
                ") are optionally lifted into vector "
                <code class="font-mono">"ICmp"</code>
                " + "
                <code class="font-mono">"extractelement"</code>
                ". After the operation, "
                <code class="font-mono">"extractelement"</code>
                " on lane "
                <em>"L"</em>
                " recovers the scalar result. Shuffle noise between operations
                 prevents lane-tracking optimisations."
            </p>
        </div>

        <AlgoConfigTable pass="vector_obfuscation" rows=vec![
            ("enabled",          "bool",       "false", "Master switch."),
            ("probability",      "0-100",      "50",    "Per-instruction selection probability."),
            ("width",            "64/128/256", "128",   "SIMD vector width in bits."),
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
                "Injects a multi-layered debugger and VM-detection harness at module scope.
                 Covers: CPUID hypervisor-present bit, RDTSC variance test (512K-cycle
                 threshold), ptrace self-probe on Linux/macOS, PR_GET_DUMPABLE sysctl,
                 Windows PEB NtGlobalFlag / BeingDebugged fields, and macOS
                 KERN_PROC_PID p_flag check. When a debugger or sandbox is detected,
                 the process terminates or triggers undefined behaviour to corrupt analysis."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Detection techniques"</p>
            <div class="vis-frame">
                <AntiDebugSvg />
            </div>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"VM fingerprinting (CPUID hypervisor bit)"</p>
            <MathBlock formula=r"$$\texttt{CPUID}(1).\text{ECX}[31] = 1 \;\Rightarrow\; \text{running inside hypervisor}$$" />
            <p class="text-sm mt-sm">
                "CPUID leaf 1 bit 31 of ECX is the hypervisor-present flag.
                 Combined with the RDTSC variance test (if the delta between two
                 consecutive RDTSC reads exceeds 512,000 cycles, a VM context-switch
                 is suspected), this identifies sandbox environments with high
                 confidence."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Platform-specific probes"</p>
            <p class="text-sm">
                <strong>"Linux: "</strong>
                <code class="font-mono">"ptrace(PT_TRACE_ME)"</code>
                " self-probe (fails with EPERM if already traced) and "
                <code class="font-mono">"PR_GET_DUMPABLE"</code>
                " sysctl check."
            </p>
            <p class="text-sm mt-sm">
                <strong>"Windows: "</strong>
                "PEB "
                <code class="font-mono">"NtGlobalFlag"</code>
                " field read via inline ASM ("
                <code class="font-mono">"fs:[0x30]"</code>
                " / "
                <code class="font-mono">"gs:[0x60]"</code>
                "); debugger sets this to "
                <code class="font-mono">"0x70"</code>
                ". Also checks "
                <code class="font-mono">"BeingDebugged"</code>
                " byte at PEB+2."
            </p>
            <p class="text-sm mt-sm">
                <strong>"macOS/iOS: "</strong>
                <code class="font-mono">"sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PID)"</code>
                " checks "
                <code class="font-mono">"kp_proc.p_flag & P_TRACED"</code>
                "."
            </p>
        </div>

        <AlgoConfigTable pass="anti_debugging" rows=vec![
            ("enabled", "bool", "false", "Insert debugger-detection checks at function entry points."),
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
                "Scans function prologues at startup for E9 (JMP rel32) and 48 B8
                 (MOV RAX, imm64) byte sequences — the two most common inline-hook
                 signatures used by Frida, Detours, and minhook. Includes a
                 BSD kernel-level syscall bypass path to avoid libc hooking, and
                 wraps the integrity check in RDTSC-gated timing noise to make
                 the detection window non-deterministic."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Hook detection flow"</p>
            <div class="vis-frame">
                <AntiHookSvg />
            </div>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Byte-pattern scan: E9 / 48 B8 signatures"</p>
            <MathBlock formula=r"$$\text{fn}[0] \in \{0xE9,\; 0x48\} \;\Rightarrow\; \text{JMP/MOV-hook detected}$$" />
            <p class="text-sm mt-sm">
                "An x86-64 inline hook typically overwrites the function prologue
                 with either a relative "
                <code class="font-mono">"JMP rel32"</code>
                " (opcode "
                <code class="font-mono">"0xE9"</code>
                ") or an absolute "
                <code class="font-mono">"MOV RAX, imm64; JMP RAX"</code>
                " sequence (starting with "
                <code class="font-mono">"0x48 0xB8"</code>
                "). The pass scans for both signatures. On BSD targets, a kernel-level
                 syscall bypass path is also injected: syscalls are made directly via
                 "
                <code class="font-mono">"int 0x80"</code>
                " / "
                <code class="font-mono">"syscall"</code>
                " to avoid userspace libc hooks. RDTSC-gated timing noise is inserted
                 around the check to make the detection window non-deterministic."
            </p>
        </div>

        <AlgoConfigTable pass="anti_hooking" rows=vec![
            ("enabled", "bool", "false", "Verify function prologue integrity and IAT/GOT pointers at startup."),
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
            <p class="algo-section-title">"Three ObjC hardening techniques"</p>
            <p>
                <strong>"ScrambleMethodOrder: "</strong>
                "The method list in each "
                <code class="font-mono">"objc_class"</code>
                " structure is shuffled in-place using a Fisher-Yates algorithm
                 seeded from the config PRNG. Tools like class-dump assume a stable
                 method ordering; scrambling it makes layout-based heuristics unreliable."
            </p>
            <p class="mt-sm">
                <strong>"RandomisedRename: "</strong>
                "Selector strings are replaced with 64-bit hexadecimal random identifiers
                 (e.g. "
                <code class="font-mono">"a3f2c1d8e5b09471"</code>
                "). The mapping is stored separately so the runtime still resolves
                 messages correctly, but string-based class-dump output is unreadable."
            </p>
            <p class="mt-sm">
                <strong>"DummySelectorInjection: "</strong>
                "Phantom IMP entries pointing to stub functions are injected into the
                 method list. Frida-based runtime method enumeration returns inflated
                 and misleading method counts."
            </p>
        </div>

        <AlgoConfigTable pass="anti_class_dump" rows=vec![
            ("enabled", "bool", "false", "Obfuscate Objective-C class pointers and method lists (iOS/macOS only)."),
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
                "Splits basic blocks at randomly chosen insertion points by
                 inserting unconditional jump instructions. This multiplies the
                 basic block count, inflating the CFG and increasing the cost
                 of automated analysis tools that scale with block count."
            </p>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"CFG before and after splitting"</p>
            <div class="vis-frame">
                <SplitBlocksSvg />
            </div>
        </div>

        <div class="glass card-pad">
            <p class="algo-section-title">"Splitting model + inline-ASM stack confusion"</p>
            <MathBlock formula=r"$$B \xrightarrow{\text{split at }k} B_1 \xrightarrow{\texttt{jmp}} B_2, \quad k \sim \mathcal{U}[1, |B|-1]$$" />
            <p class="text-sm mt-sm">
                "A block "
                <em>"B"</em>
                " is split at a uniform-random position "
                <em>"k"</em>
                " into two blocks connected by an unconditional branch.
                 On "
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

#[component]
fn MathBlock(formula: &'static str) -> impl IntoView {
    let el = NodeRef::<html::Div>::new();
    Effect::new(move |_| {
        if let Some(el) = el.get() {
            el.set_inner_html(formula);
            let _ = js_sys::eval("window.triggerKatex && window.triggerKatex()");
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
