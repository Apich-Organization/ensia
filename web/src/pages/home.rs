use crate::app::Page;
use leptos::prelude::*;

#[component]
pub fn HomePage() -> impl IntoView {
    let page = expect_context::<RwSignal<Page>>();

    view! {
        // ── Hero ────────────────────────────────────────────────────────────
        <section class="hero">
            <div class="hero-logo-wrap">
                <img src="logo.svg" alt="Ensia logo" class="hero-logo" />
            </div>
            <p class="hero-eyebrow">"Next-Generation LLVM Obfuscation"</p>
            <h1 class="hero-title">"Ensia"</h1>
            <p class="hero-sub">
                "Principled, precise, and open-source IR-level code protection
                 built on LLVM \u{2014} continuing the Hikari lineage, modernised for LLVM 21, 22, and 23.
                 Engineered for x86_64, AArch64 (ARM64), and i386 across Linux, Windows (MSVC/clang-cl/MinGW),
                 macOS, iOS, and Android for transparent, high-resilience binary hardening."
            </p>

            // ── Citation & release badges ──────────────────────────────────
            <div class="hero-badges">
                <a
                    href="https://doi.org/10.5281/zenodo.20149843"
                    target="_blank" rel="noopener"
                    class="badge-link"
                    title="Cite Ensia via Zenodo DOI"
                >
                    <span class="badge badge-doi">"DOI"</span>
                    <span class="badge badge-doi-val">"10.5281/zenodo.20149843"</span>
                </a>
                <a
                    href="https://github.com/Apich-Organization/ensia/releases"
                    target="_blank" rel="noopener"
                    class="badge-link"
                    title="Latest releases"
                >
                    <span class="badge badge-success">"Releases"</span>
                    <span class="badge badge-primary">"\u{1F4E6} GitHub"</span>
                </a>
                <a href="mailto:info@apich.org" class="badge-link" title="Contact us">
                    <span class="badge badge-primary">"Contact"</span>
                    <span class="badge badge-neutral">"info@apich.org"</span>
                </a>
            </div>

            <div class="hero-actions">
                <a
                    href="https://github.com/Apich-Organization/ensia"
                    target="_blank" rel="noopener"
                    class="btn btn-primary"
                >
                    <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                        <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38
                                 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13
                                 -.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66
                                 .07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15
                                 -.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27
                                 .68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12
                                 .51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48
                                 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
                    </svg>
                    "View on GitHub"
                </a>
                <a
                    href="https://github.com/Apich-Organization/ensia/releases"
                    target="_blank" rel="noopener"
                    class="btn btn-ghost"
                >
                    "\u{1F4E6} Releases"
                </a>
                <a href="https://discord.gg/D5e2czMTT9" target="_blank" rel="noopener" class="btn btn-ghost">
                    "Discord"
                </a>
                <button
                    class="btn btn-ghost"
                    on:click=move |_| page.set(Page::Algorithms)
                >"Explore Passes"</button>
                <button
                    class="btn btn-ghost"
                    on:click=move |_| page.set(Page::Config)
                >"Config Builder"</button>
            </div>
            <div class="hero-scroll-hint">
                <svg class="scroll-arrow" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8">
                    <path d="M10 4v12M4 11l6 6 6-6"/>
                </svg>
                "scroll to learn more"
            </div>
        </section>

        // ── Feature overview ────────────────────────────────────────────────
        <section class="section page-wrap">
            <div class="mb-lg">
                <h2>"What Ensia Does"</h2>
                <p class="mt-sm">
                    "Ensia is an LLVM-based obfuscation framework that transforms
                     Intermediate Representation (IR) to make reverse engineering
                     significantly harder. It is not meant to be perfect, but it makes
                     the reverse-engineering process considerably more time-consuming."
                </p>
            </div>
            <div class="grid-2">
                <FeatureCard
                    icon="\u{26D3}"
                    title="IR-Level Transforms"
                    body="Operates on LLVM IR, so it works with any language that
                          compiles through LLVM: C, C++, Rust, Swift, Kotlin/Native,
                          and more. Source code is never touched."
                />
                <FeatureCard
                    icon="\u{2699}"
                    title="TOML-Driven Policy"
                    body="Fine-grained per-module and per-function control via a
                          structured TOML config. Apply high-intensity passes to
                          crypto functions while keeping hot paths clean."
                />
                <FeatureCard
                    icon="\u{1F52C}"
                    title="15 Orthogonal Passes"
                    body="BCF, CFF, CSM, String Encryption, Constant Encryption,
                          MBA, Instruction Substitution, Indirect Branching,
                          Vector Obfuscation, Function Wrapping, Anti-Debugging,
                          Anti-Hooking, Anti-Class-Dump, Call Obfuscation,
                          and Basic Block Splitting."
                />
                <FeatureCard
                    icon="\u{1F4D0}"
                    title="Mathematically Grounded"
                    body="Opaque predicates, GF(2^8) cipher, k-share XOR ensembles,
                          Feistel networks, logistic-map CFF, and multi-term MBA
                          identities \u{2014} every technique has a formal basis."
                />
                <FeatureCard
                    icon="\u{1F9E9}"
                    title="Modern Pass Plugin"
                    body="Integrates via modern LLVM Pass Plugin (-fpass-plugin=libEnsia.so for Clang, -Z llvm-plugins=libEnsia_rust.so for Rust/Cargo). Native support for Linux & Windows (MSVC/clang-cl/MinGW) with LLVM 21/22."
                />
                <FeatureCard
                    icon="\u{1F310}"
                    title="Multi-Language Aware"
                    body="Rust v0 and legacy Itanium name demangling built-in.
                          Write policy regexes against human-readable crate::module::fn
                          paths, not mangled symbols."
                />
            </div>
        </section>

        // ── Core Design Philosophy ──────────────────────────────────────────
        <section class="section page-wrap">
            <div class="glass card-pad-lg policy-section">
                <span class="section-chip">"Architecture & Design Philosophy"</span>
                <h2>"SMT State-Space Explosion vs. VM Single Point of Failure"</h2>
                <p class="mt-sm">
                    "Traditional " <strong>"VM-based Obfuscators (Virtualizers)"</strong>
                    " translate native code into custom bytecode executed by an interpreter runtime loop. While effective at hiding control flow, virtualizers carry an inherent "
                    <strong style="color: var(--c-danger);">"Single Point of Failure (SPOF)"</strong>
                    ": once an analyst devirtualizes the core handler table or dispatches the central loop, the entire protection layer collapses at once."
                </p>
                <div class="grid-4 mt-md">
                    <div class="glass-alt card-pad">
                        <h4>"\u{2694} Zero-SPOF Algebraic Masking"</h4>
                        <p class="text-sm mt-xs">
                            "Replaces fragile volatile switch variables with branchless algebraic masking: condExt = zext(cond), mask = 0 - condExt, nextState = caseFalse ^ (mask & diff). Retains 100% dispatch switches under opt -O3 even if volatile is stripped."
                        </p>
                    </div>
                    <div class="glass-alt card-pad">
                        <h4>"\u{1F6E1} 3-Tier Anti-Taint Engine"</h4>
                        <p class="text-sm mt-xs">
                            "Combines Global Identity LUT memory dereferences, implicit control-flow bit laundering with select over pure constants, and SIMD vector diffusion to sever register-level ALU taint propagation in Triton and angr."
                        </p>
                    </div>
                    <div class="glass-alt card-pad">
                        <h4>"\u{1F3B2} Polymorphic Hardware Barriers"</h4>
                        <p class="text-sm mt-xs">
                            "Randomized 9-variant x86 instruction families (orb, andb, addb, subb, rolb, rorb, incb/decb, notb/notb) and 4 ARM64 pipeline barriers eliminate uniform signature patterns and defeat YARA scanning."
                        </p>
                    </div>
                    <div class="glass-alt card-pad">
                        <h4>"\u{2B21} SIMD Vector Lifting & Anti-Dump"</h4>
                        <p class="text-sm mt-xs">
                            "Lifts scalar logic into multi-lane SIMD vector operations (<4 x i32>, <8 x float>) up to 512-bit width, paired with volatile exit zeroization that cleans decrypted buffers to defeat memory dumping."
                        </p>
                    </div>
                </div>
            </div>
        </section>

        // ── Security Benchmark Section ───────────────────────────────────────
        <section class="section page-wrap">
            <div class="mb-lg">
                <span class="section-chip">"Empirical Security Evaluation"</span>
                <h2>"Reverse Engineering Resistance Benchmark"</h2>
                <p class="mt-sm">
                    "Evaluated across 79 cryptographic targets (AES, SM4, SHA-3, ChaCha20, Ed25519, ML-KEM) using automated Angr 9.3 symbolic execution and Z3 SMT solver attacks."
                </p>
            </div>
            <div class="grid-4 mb-lg">
                <div class="glass card-pad text-center">
                    <h3 class="hero-title text-primary" style="font-size: 2.2rem; margin-bottom: 0.25rem;">"13.5x"</h3>
                    <p class="text-sm text-muted">"Code Size Expansion"</p>
                </div>
                <div class="glass card-pad text-center">
                    <h3 class="hero-title text-primary" style="font-size: 2.2rem; margin-bottom: 0.25rem;">"10.1x"</h3>
                    <p class="text-sm text-muted">"Basic Block Multiplier"</p>
                </div>
                <div class="glass card-pad text-center">
                    <h3 class="hero-title text-primary" style="font-size: 2.2rem; margin-bottom: 0.25rem;">"9.3x"</h3>
                    <p class="text-sm text-muted">"CFG State Edges"</p>
                </div>
                <div class="glass card-pad text-center">
                    <h3 class="hero-title text-danger" style="font-size: 2.2rem; margin-bottom: 0.25rem;">"96.2%"</h3>
                    <p class="text-sm text-muted">"Symbolic Solver Timeout"</p>
                </div>
            </div>
            <div class="text-center mt-md">
                <button
                    class="btn btn-primary"
                    on:click=move |_| page.set(Page::Benchmark)
                >
                    "View Full 79-Target Empirical Benchmark Report \u{2192}"
                </button>
            </div>
        </section>

        // ── Obfuscation pipeline ─────────────────────────────────────────────
        <section class="section page-wrap">
            <div class="mb-lg">
                <h2>"Obfuscation Pipeline"</h2>
                <p class="mt-sm">
                    "Passes run in a deliberate order so each layer builds on the previous
                     without breaking the IR. The scheduler auto-skips conflicting passes."
                </p>
            </div>
            <div class="pipeline-steps">
                <PipelineStep n="1" label="AntiHooking & AntiClassDump (module)"
                    detail="Validates function prologue integrity; BSD direct syscall bypass path; 3-tier anti-taint engine (LUT, bit laundering, vector diffusion); ObjC metadata scrambling." />
                <PipelineStep n="2" label="FunctionCallObfuscate (module)"
                    detail="Replaces direct call instructions with runtime dlopen/dlsym indirection, eliminating static import references and stripping cross-module call graphs." />
                <PipelineStep n="3" label="AntiDebugging (module)"
                    detail="Multi-vector hardware & kernel probes: ptrace, hardware debug registers (DR0-DR7), EFLAGS.TF single-step traps with AMD64 Red Zone preservation, and unrecoverable violent exit." />
                <PipelineStep n="4" label="StringEncryption (module)"
                    detail="Dual-layer cipher: Vernam OTP + GF(2^8) Rijndael polynomial multiplication; on-demand decrypt stubs with automatic volatile zeroization at function exit (Anti-Dump)." />
                <PipelineStep n="5" label="ConstantEncryption Phase 1 (module)"
                    detail="Pre-CFG constant blinding: bivariate MBA, 4-round Feistel network, and AntiDebug token entanglement applied to original user literals before control-flow expansion." />
                <PipelineStep n="6" label="Per-Function Transformations (a-g)"
                    detail="In order: Substitution -> MBAObfuscation (42 identities + stateful contextual barriers) -> SplitBasicBlocks (mandatory opaque chaining) -> BogusControlFlow (hardware opaque predicates) -> ChaosStateMachine (Q32 logistic map & attractor basins) / Classic CFF (Zero-SPOF algebraic masking) -> VectorObfuscation (512-bit SIMD lift)." />
                <PipelineStep n="7" label="ConstantEncryption Phase 2 (module)"
                    detail="Post-CFG constant blinding: targets new state constants, dispatcher cases, and opaque keys generated by BCF, CSM, and CFF, neutralizing reverse-engineering pattern matching." />
                <PipelineStep n="8" label="IndirectBranch (module)"
                    detail="Knuth multiplicative target hashing with per-function keys; replaces direct basic block jumps with encrypted indirect branch tables." />
                <PipelineStep n="9" label="FunctionWrapper (module)"
                    detail="Polymorphic proxy wrappers with frame-depth mutation, argument XOR shuffling, return value masking, and enforced NoInline/OptimizeNone to destroy static call-graph topologies." />
                <PipelineStep n="10" label="FeatureElimination (module)"
                    detail="Strips DWARF debug metadata, anonymizes TU paths to single-character identifiers, erases llvm.ident, and scrambles private symbol names." />
                <PipelineStep n="11" label="Sentinel Cleanup & Sanitization (module)"
                    detail="Erases internal compilation markers (__dlsym_proxy_*, ensia_*), validates module structural invariants, and ensures pristine binary output." />
                <PipelineStep n="12" label="LTO Evasion & Linkage Sealing (module)"
                    detail="Enforces Attribute::OptimizeNone and Attribute::NoInline on protected functions, preventing cross-module LTO inlining and post-link deobfuscation." />
            </div>
        </section>

        // ── Ethics & Responsible Use ────────────────────────────────────────
        <section class="section page-wrap">
            <div class="glass card-pad-lg policy-section">
                <span class="section-chip">"Ethics & Misuse Disclaimer"</span>
                <h2>"A Note on Purpose"</h2>
                <p class="mt-sm">
                    "This is a dual-use technology. Due to the extreme potency of the
                     obfuscation techniques implemented (derived from the Hikari lineage),
                     the resulting binaries are designed to be resilient against modern
                     reverse-engineering tools and manual analysis."
                </p>

                <hr class="divider" />

                <h3>"\u{2714} Permitted Uses"</h3>
                <p>
                    "Protection of intellectual property and proprietary algorithms;
                     hardening applications against unauthorised tampering, patching, and cracking;
                     advancing research into compiler-based security and code transformation;
                     CTF challenge creation; testing static analysis tools."
                </p>

                <h3 class="mt-md">"\u{274C} Strictly Prohibited"</h3>
                <p>
                    "Development or distribution of malware, ransomware, or any malicious code;
                     surveillance software designed to violate user privacy; any software that
                     facilitates illegal activities. Violation reflects solely on the user."
                </p>

                <blockquote>
                    "By using Ensia you agree that you are solely responsible for the legal
                     and ethical implications of the software you obfuscate. The authors are
                     not responsible if your software triggers AV or EDR false positives."
                </blockquote>

                <p>
                    "Use must comply with the AGPL-3.0 license. See "
                    <a href="https://github.com/Apich-Organization/ensia/blob/main/ETHICS.md"
                       target="_blank" rel="noopener">"ETHICS.md"</a>
                    " and "
                    <a href="https://github.com/Apich-Organization/ensia/blob/main/LEGAL.md"
                       target="_blank" rel="noopener">"LEGAL.md"</a>
                    " for full details."
                </p>
            </div>
        </section>

        // ── Code of Conduct & Security ───────────────────────────────────────
        <section class="section page-wrap">
            <div class="grid-2">
                <div class="glass card-pad policy-section">
                    <span class="section-chip">"Code of Conduct"</span>
                    <h3>"Community Standards"</h3>
                    <p>
                        "All participants are required to adhere to all applicable laws.
                         This CoC ensures a safe, respectful, inclusive, and legally
                         compliant environment across GitHub and all related channels."
                    </p>
                    <h4 class="mt-md">"Expected Behaviour"</h4>
                    <p>
                        "Be welcoming and inclusive. Respect differing viewpoints and experiences.
                         Communicate clearly and professionally. Give and accept constructive
                         feedback focused on code and ideas, not people."
                    </p>
                    <h4 class="mt-md">"Unacceptable Behaviour"</h4>
                    <p>
                        "Harassment, doxxing, hate speech, IP violations, spamming, trolling,
                         or retaliation against reporters. Severe violations may be referred
                         to legal authorities."
                    </p>
                    <p class="text-muted text-sm mt-md">
                        "Report violations to "
                        <a href="mailto:Xinyu.Yang@apich.org">"Xinyu.Yang@apich.org"</a>
                        " or privately to a maintainer. Full CoC at "
                        <a href="https://github.com/Apich-Organization/ensia/blob/main/CODE_OF_CONDUCT.md"
                           target="_blank" rel="noopener">"CODE_OF_CONDUCT.md"</a>
                        "."
                    </p>
                </div>

                <div class="glass card-pad policy-section">
                    <span class="section-chip">"Security Policy"</span>
                    <h3>"Responsible Disclosure"</h3>
                    <p>
                        "Do not report security vulnerabilities via public GitHub issues.
                         All security reports must be sent privately to protect users
                         during the disclosure window."
                    </p>
                    <h4 class="mt-md">"How to Report"</h4>
                    <p>
                        "Email "
                        <a href="mailto:security@apich.org">"security@apich.org"</a>
                        " or visit "
                        <a href="https://security.apich.org" target="_blank" rel="noopener">
                            "security.apich.org"
                        </a>
                        " for PGP key and instructions. Include a minimal reproduction
                         case and describe the potential impact."
                    </p>
                    <h4 class="mt-md">"Supported Versions"</h4>
                    <p>
                        "Branch 0.1.x is under active support.
                         Earlier versions are end-of-life and receive no security patches."
                    </p>
                </div>
            </div>
        </section>

        // ── Citation & Contact ───────────────────────────────────────────────
        <section class="section page-wrap">
            <div class="grid-2">
                <div class="glass card-pad">
                    <span class="section-chip">"Citation"</span>
                    <h3>"Cite Ensia"</h3>
                    <p class="mt-sm">
                        "If you use Ensia in academic work, please cite via the Zenodo DOI:"
                    </p>
                    <pre class="code-block text-xs mt-sm">
"@software{yang_2026_21648942,
  author       = {Yang, Xinyu},
  title        = {Ensia (OLLVM-Next): A Chaos-Based High-Entropy
                   Obfuscation Framework for LLVM IR with Dual-Use
                   Security Protocols
                  },
  month        = jul,
  year         = 2026,
  publisher    = {Zenodo},
  version      = {v0.1.2},
  doi          = {10.5281/zenodo.21648942},
  url          = {https://doi.org/10.5281/zenodo.21648942},
}"
                    </pre>
                    <div class="flex gap-sm mt-md flex-wrap">
                        <a
                            href="https://doi.org/10.5281/zenodo.20149843"
                            target="_blank" rel="noopener"
                            class="btn btn-ghost btn-sm"
                        >"DOI: 10.5281/zenodo.20149843 \u{2197}"</a>
                    </div>
                </div>

                <div class="glass card-pad">
                    <span class="section-chip">"Contact & Releases"</span>
                    <h3>"Get in Touch"</h3>
                    <p class="mt-sm">
                        "General enquiries, collaboration proposals, and partnership requests:"
                    </p>
                    <p class="mt-sm">
                        <a href="mailto:info@apich.org" class="mono">"info@apich.org"</a>
                    </p>
                    <p class="mt-md">
                        "Security vulnerabilities: "
                        <a href="mailto:security@apich.org" class="mono">"security@apich.org"</a>
                    </p>
                    <p class="mt-sm">
                        "Community (Discord): "
                        <a href="https://discord.gg/D5e2czMTT9" target="_blank" rel="noopener">
                            "discord.gg/D5e2czMTT9"
                        </a>
                    </p>
                    <hr class="divider" />
                    <h4>"Latest Releases"</h4>
                    <p class="mt-sm text-sm">
                        "Binary distributions, release notes, and changelogs are published on GitHub Releases:"
                    </p>
                    <a
                        href="https://github.com/Apich-Organization/ensia/releases"
                        target="_blank" rel="noopener"
                        class="btn btn-ghost btn-sm mt-sm"
                    >"\u{1F4E6} github.com/Apich-Organization/ensia/releases \u{2197}"</a>
                </div>
            </div>
        </section>

        // ── License ─────────────────────────────────────────────────────────
        <section class="section page-wrap">
            <div class="glass-alt card-pad">
                <span class="section-chip">"License & Lineage"</span>
                <h3>"GNU Affero General Public License v3.0"</h3>
                <p class="mt-sm">
                    "Ensia is free software. If you distribute a modified version or run it
                     as a network service, you must make your source changes available under
                     the same license (AGPL-3.0 Section 13)."
                </p>
                <p class="mt-sm">
                    "Ensia continues the lineage of "
                    <a href="https://github.com/HikariObfuscator/Hikari/" target="_blank" rel="noopener">
                        "Hikari"
                    </a>
                    " \u{2192} "
                    <a href="https://github.com/NeHyci/Hikari-LLVM15/" target="_blank" rel="noopener">
                        "Hikari-LLVM15"
                    </a>
                    " \u{2192} "
                    <a href="https://github.com/PPKunOfficial/Hikari-LLVM19/" target="_blank" rel="noopener">
                        "Hikari-LLVM19"
                    </a>
                    " \u{2192} Ensia. Full attribution in "
                    <a href="https://github.com/Apich-Organization/ensia/blob/main/LEGAL.md"
                       target="_blank" rel="noopener">"LEGAL.md"</a>
                    "."
                </p>
                <p class="mt-sm text-sm text-muted">
                    "Copyright \u{00A9} 2026 Xinyu Yang (Xinyu.Yang@apich.org). "
                    "Upstream copyrights: PPKunOfficial, NeHyci, HikariObfuscator Team, "
                    "University of Illinois at Urbana-Champaign, nlohmann/json, marzer/tomlplusplus."
                </p>
                <div class="flex gap-sm mt-md flex-wrap">
                    <span class="badge badge-success">"AGPL-3.0"</span>
                    <span class="badge badge-primary">"Open Source"</span>
                    <span class="badge badge-primary">"Hikari Lineage"</span>
                    <span class="badge badge-primary">"LLVM 21/22"</span>
                </div>
            </div>
        </section>
    }
}

#[component]
fn FeatureCard(icon: &'static str, title: &'static str, body: &'static str) -> impl IntoView {
    view! {
        <div class="glass card-pad">
            <div class="feature-icon">{icon}</div>
            <h3 class="mb-sm">{title}</h3>
            <p class="text-sm">{body}</p>
        </div>
    }
}

#[component]
fn PipelineStep(n: &'static str, label: &'static str, detail: &'static str) -> impl IntoView {
    view! {
        <div class="pipeline-step">
            <div class="pipeline-n">{n}</div>
            <div>
                <p class="pipeline-label">{label}</p>
                <p class="pipeline-detail">{detail}</p>
            </div>
        </div>
    }
}
