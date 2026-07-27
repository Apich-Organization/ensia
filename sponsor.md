# Ensia Sponsorship and Funding Policy

As a next-generation LLVM-based compiler obfuscation framework, **Ensia (OLLVM-Next)** requires substantial computational resources for continuous development, cross-platform architecture optimization (Windows, macOS, Linux, Android/iOS), and rigorous stress testing under complex compilation workloads. We welcome sponsorships from individuals and organizations who wish to support the advancement of robust, high-performance open-source compiler security tools.

---

### 1. Allocation of Funds

All sponsored funds are strictly allocated to the following technical and operational requirements:

* **Multi-Architecture Compiler Testing:** Provisioning and licensing of diverse hardware architectures (including x86_64, AArch64, ARM32, and RISC-V systems) to verify pass stability, code transformation semantics, and execution correctness across heterogeneous environments.
* **High-Performance Build & Matrix Infrastructure:** Acquisition, hosting, and maintenance of high-core-count build nodes and continuous integration cluster nodes dedicated to heavy LLVM compilation pipeline stress testing, SMT solver explosion profiling, and pass-interaction benchmarking.
* **Virtualized & Cross-Platform Sandbox Environments:** Maintenance of distributed testing environments simulating Windows (PEB/TEB/KUSER_SHARED_DATA), macOS/iOS (Mach-O, ObjC runtime, dyld), and Android/Linux runtime scenarios for anti-analysis pass validation.
* **Operations & Documentation:** Hosting and operational maintenance of the official project website, online interactive configuration tools, documentation, public releases, and secure distribution channels.

---

### 2. Individual Sponsorship

For individual supporters, we accept voluntary contributions via **Open Collective** only.

* **Open Collective Link:** [https://opencollective.com/apich-organization](https://opencollective.com/apich-organization)
* **Mandatory Requirement:** You **MUST** include a note in the transaction with the following declarations:
  1. *"This is a voluntary donation/gift with no expectation of commercial return."*
  2. *"I certify that these funds are derived from legal sources."*
  3. *(Optional)* Any name, handle, or organization you wish to be credited with on our official "Sponsors" page.

---

### 3. Corporate Sponsorship

We offer structured tiers for organizations requiring advanced consulting or high-level strategic alignment with the Ensia compiler security ecosystem. Corporate sponsors **must provide proof of legal entity/incorporation** before any funds are accepted.

#### **Tier 1: Strategic Support ($1,000+ USD/month)**

* **Status:** Officially recognized as a Lead Corporate Sponsor of Ensia.
* **Support:** Priority technical communication channels and direct consulting for compiler pipeline integration and custom pass tuning.
* **Certification:** Must sign a formal declaration certifying the legal origin of funds and full compliance with regional and international dual-use technology and export regulations.

#### **Tier 2: Core Engineering Support ($10,000+ USD/month)**

* **Custom Development:** Ability to request specialized LLVM transformation passes, custom hardware opaque predicates, or tailored pass scheduling targeting proprietary toolchains or specialized execution environments.
* **Early Access:** Up to 12 months of "Gray-box" staging and testing for experimental obfuscation passes before they are evaluated for potential inclusion in the open-source main branch.

---

### 4. Ethical Statement and Anti-Money Laundering (AML)

The maintainers of Ensia maintain a zero-tolerance policy toward illicit financial activities and malicious usage.

* **Strict Prohibition of Cryptocurrency:** We **REFUSE** all forms of cryptocurrency payments (including Bitcoin, Monero, etc.) to ensure complete financial transparency, comply with international accounting standards, and prevent money laundering.
* **Anti-Malware and Safe Use Policy:** As outlined in our `ETHICS.md`, Ensia is a dual-use technology intended strictly for intellectual property protection and research. We resolutely oppose the use of Ensia for illegal operations, including but not limited to the creation of malware, ransomware, unauthorized intrusion tools, or system monitoring evasion.
* **Law Enforcement Cooperation:** In the event that any law enforcement or regulatory agency identifies a contribution as originating from illegal proceeds or linked to illicit software activities, we reserve the right to immediately terminate the sponsor association and will fully cooperate by turning over relevant transaction details and funds to the appropriate authorities.

---

**Compliance Notice:** By sponsoring Ensia, you acknowledge that this is a research-oriented and utility-focused contribution, and that you adhere strictly to all local and international laws regarding the funding of dual-use technology frameworks and open-source infrastructure.
