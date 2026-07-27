use leptos::prelude::*;

#[component]
pub fn SponsorPage() -> impl IntoView {
    view! {
        <div class="page-wrap section">
            <div class="mb-lg text-center">
                <span class="section-chip">"Sponsorship & Funding"</span>
                <h1 class="hero-title" style="font-size: 2.2rem; margin-top: 0.5rem;">
                    "Ensia Sponsorship & Funding Policy"
                </h1>
                <p class="hero-sub" style="max-width: 760px; margin: 0.75rem auto 0;">
                    "Supporting continuous development, multi-architecture compiler testing, and high-performance open-source security research."
                </p>
            </div>

            // ── Section 1: Overview & Allocation ──────────────────────────────────
            <div class="glass card-pad-lg mb-lg policy-section">
                <h2>"1. Allocation of Funds"</h2>
                <p class="mt-sm">
                    "As a next-generation LLVM-based compiler obfuscation framework, "
                    <strong>"Ensia (OLLVM-Next)"</strong>
                    " requires substantial computational resources for continuous development, cross-platform architecture optimization (Windows, macOS, Linux, Android/iOS), and rigorous stress testing under complex compilation workloads. All sponsored funds are strictly allocated to technical and operational requirements:"
                </p>
                <ul class="mt-md" style="display: flex; flex-direction: column; gap: 0.75rem; padding-left: 1.25rem;">
                    <li>
                        <strong>"Multi-Architecture Compiler Testing: "</strong>
                        "Provisioning and licensing of diverse hardware architectures (including x86_64, AArch64, ARM32, and RISC-V systems) to verify pass stability, code transformation semantics, and execution correctness across heterogeneous environments."
                    </li>
                    <li>
                        <strong>"High-Performance Build & Matrix Infrastructure: "</strong>
                        "Acquisition, hosting, and maintenance of high-core-count build nodes and continuous integration cluster nodes dedicated to heavy LLVM compilation pipeline stress testing, SMT solver explosion profiling, and pass-interaction benchmarking."
                    </li>
                    <li>
                        <strong>"Virtualized & Cross-Platform Sandbox Environments: "</strong>
                        "Maintenance of distributed testing environments simulating Windows (PEB/TEB/KUSER_SHARED_DATA), macOS/iOS (Mach-O, ObjC runtime, dyld), and Android/Linux runtime scenarios for anti-analysis pass validation."
                    </li>
                    <li>
                        <strong>"Operations & Documentation: "</strong>
                        "Hosting and operational maintenance of the official project website, online interactive configuration tools, documentation, public releases, and secure distribution channels."
                    </li>
                </ul>
            </div>

            // ── Section 2: Individual & Corporate Sponsorship ────────────────────
            <div class="grid-2 mb-lg">
                <div class="glass card-pad-lg policy-section">
                    <span class="section-chip">"Community & Individuals"</span>
                    <h2 class="mt-xs">"2. Individual Sponsorship"</h2>
                    <p class="mt-sm">
                        "For individual supporters, we accept voluntary contributions via "
                        <strong>"Open Collective"</strong>
                        " only."
                    </p>
                    <div class="my-md">
                        <a
                            href="https://opencollective.com/apich-organization"
                            target="_blank"
                            rel="noopener noreferrer"
                            class="btn btn-primary"
                        >
                            "\u{2764} Open Collective Page \u{2197}"
                        </a>
                    </div>
                    <div class="glass-alt card-pad text-sm" style="border-left: 3px solid var(--c-primary);">
                        <strong>"Mandatory Requirement:"</strong>
                        <p class="mt-xs">
                            "You " <strong>"MUST"</strong> " include a note in the transaction with the following declarations:"
                        </p>
                        <ol class="mt-xs" style="padding-left: 1rem; display: flex; flex-direction: column; gap: 0.35rem;">
                            <li><em>"1. \"This is a voluntary donation/gift with no expectation of commercial return.\""</em></li>
                            <li><em>"2. \"I certify that these funds are derived from legal sources.\""</em></li>
                            <li><em>"3. (Optional) Any name, handle, or organization you wish to be credited with on our official \"Sponsors\" page."</em></li>
                        </ol>
                    </div>
                </div>

                <div class="glass card-pad-lg policy-section">
                    <span class="section-chip">"Enterprise & Organizations"</span>
                    <h2 class="mt-xs">"3. Corporate Sponsorship"</h2>
                    <p class="mt-sm">
                        "We offer structured tiers for organizations requiring advanced consulting or high-level strategic alignment with the Ensia compiler security ecosystem. Corporate sponsors "
                        <strong>"must provide proof of legal entity/incorporation"</strong>
                        " before any funds are accepted."
                    </p>

                    <div class="mt-md glass-alt card-pad">
                        <h4>"Tier 1: Strategic Support ($1,000+ USD/month)"</h4>
                        <p class="text-sm mt-xs">
                            "Officially recognized as a Lead Corporate Sponsor of Ensia. Includes priority technical communication channels and direct consulting for compiler pipeline integration and custom pass tuning. Must sign a formal declaration certifying legal origin of funds and compliance with dual-use technology regulations."
                        </p>
                    </div>

                    <div class="mt-sm glass-alt card-pad">
                        <h4>"Tier 2: Core Engineering Support ($10,000+ USD/month)"</h4>
                        <p class="text-sm mt-xs">
                            "Ability to request specialized LLVM transformation passes, custom hardware opaque predicates, or tailored pass scheduling targeting proprietary toolchains. Includes up to 12 months of \"Gray-box\" staging and testing for experimental obfuscation passes before evaluation for main branch inclusion."
                        </p>
                    </div>
                </div>
            </div>

            // ── Section 4: Ethical Statement & AML ──────────────────────────────
            <div class="glass card-pad-lg policy-section">
                <span class="section-chip" style="color: var(--c-danger);">"Zero Tolerance Policy"</span>
                <h2 class="mt-xs">"4. Ethical Statement and Anti-Money Laundering (AML)"</h2>
                <p class="mt-sm">
                    "The maintainers of Ensia maintain a strict zero-tolerance policy toward illicit financial activities and malicious usage."
                </p>

                <div class="grid-3 mt-md">
                    <div class="glass-alt card-pad">
                        <h4>"\u{1F6AB} Strict Prohibition of Cryptocurrency"</h4>
                        <p class="text-sm mt-xs">
                            "We " <strong>"REFUSE"</strong> " all forms of cryptocurrency payments (including Bitcoin, Monero, etc.) to ensure complete financial transparency, comply with international accounting standards, and prevent money laundering."
                        </p>
                    </div>
                    <div class="glass-alt card-pad">
                        <h4>"\u{1F6E1} Anti-Malware & Safe Use Policy"</h4>
                        <p class="text-sm mt-xs">
                            "As outlined in our ETHICS.md, Ensia is a dual-use technology intended strictly for intellectual property protection and research. We resolutely oppose the use of Ensia for malware, ransomware, or unauthorized intrusion tools."
                        </p>
                    </div>
                    <div class="glass-alt card-pad">
                        <h4>"\u{2696} Law Enforcement Cooperation"</h4>
                        <p class="text-sm mt-xs">
                            "If any contribution is identified as originating from illegal proceeds or linked to illicit software activities, we reserve the right to immediately terminate the sponsor association and fully cooperate with authorities."
                        </p>
                    </div>
                </div>

                <div class="mt-md text-sm text-muted text-center">
                    "Compliance Notice: By sponsoring Ensia, you acknowledge that this is a research-oriented and utility-focused contribution, adhering strictly to all local and international laws regarding dual-use technology funding."
                </div>
            </div>
        </div>
    }
}
