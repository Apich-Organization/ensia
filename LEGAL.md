# Legal Information & Attribution

## License
This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. 
A full copy of the license text is included in the `LICENSE` file in this repository.

---

## Project Lineage and Provenance
This software is a derivative work. It has evolved through several iterations of the LLVM-based obfuscation framework. To maintain transparency and honor the work of previous contributors, the lineage is documented below:

### 1. Current Work
* **Project:** OLLVM-Next (Ensia)
* **Maintainer:** Xinyu Yang (Apich Organization Development Team & Apich Organization Security Team) <Xinyu.Yang@apich.org>
* **Repository:** Current Repository [https://github.com/Apich-Organization/ensia/](https://github.com/Apich-Organization/ensia/)
* **Modifications:** Modernized the core Hikari logic to support the LLVM 22 toolchain and updated build systems; strengthens all obfuscation passes, adds new obfuscation passes, and others.
* **License:** AGPL-3.0

### 2. Immediate Parent (Father)
* **Project:** Hikari-LLVM19
* **Maintainer/Origin:** PPKunOfficial
* **Upstream Link:** [https://github.com/PPKunOfficial/Hikari-LLVM19/](https://github.com/PPKunOfficial/Hikari-LLVM19/)
* **License:** AGPL-3.0
* **Contribution:** Modernized the core Hikari logic to support the LLVM 19 toolchain and updated build systems.

### 3. Immediate Grandparent (Grandfather)
* **Project:** Hikari-LLVM15
* **Maintainer/Origin:** NeHyci
* **Upstream Link:** [https://github.com/NeHyci/Hikari-LLVM15/](https://github.com/NeHyci/Hikari-LLVM15/)
* **License:** AGPL-3.0
* **Contribution:** Modernized the core Hikari logic to support the LLVM 15 toolchain and updated build systems.

### 4. Root Origin (Root)
* **Project:** Hikari
* **Original Author:** HikariObfuscator Team
* **Upstream Link:** [https://github.com/HikariObfuscator/Hikari/](https://github.com/HikariObfuscator/Hikari/)
* **License:** AGPL-3.0
* **Contribution:** Established the foundational LLVM obfuscation passes, including String Obfuscation, Control Flow Flattening, and Bogus Control Flow.

---

## Copyright Notices
This project retains all original copyright notices from upstream contributors. Modifications made in this fork are:

Copyright © 2026 Xinyu Yang (<Xinyu.Yang@apich.org>)

**Upstream Copyrights:**
* Copyright © 2025 PPKunOfficial (Hikari-LLVM19)
* Copyright © 2023-2025 NeHyci (Hikari-LLVM15)
* Copyright © 2019-2023 HikariObfuscator Team (Original Hikari)
* Copyright © 2003-2026 University of Illinois at Urbana-Champaign. (LLVM)

**Third Party Copyrights:**
* Copyright © 2013-2026 Niels Lohmann (nlohmann/json)
* Copyright © 2020-2026 Mark Gillard <mark.gillard@outlook.com.au> (marzer/tomlplusplus)

---

## Compliance Note
Under the terms of the **AGPL-3.0 (Section 13)**, if you modify this program and offer its functionality to users over a network (e.g., as a SaaS obfuscation service), you **must** make your modified source code available to those users.
