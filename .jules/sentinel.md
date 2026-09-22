## 2026-09-22 - Fix reverse tabnabbing and referrer leakage
**Vulnerability:** Found `target="_blank"` links using only `rel="noopener"`, instead of `rel="noopener noreferrer"`.
**Learning:** In the Leptos frontend, external links need proper `rel` attributes. `noopener` alone prevents tabnabbing but doesn't prevent sending referrer information (referrer leakage).
**Prevention:** Always use `rel="noopener noreferrer"` when adding external links with `target="_blank"` in the Leptos frontend.
