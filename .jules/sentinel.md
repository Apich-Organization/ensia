## 2024-05-18 - Fix Reverse Tabnabbing Vulnerability
**Vulnerability:** Found `target="_blank"` missing `rel="noopener noreferrer"` across multiple frontend pages.
**Learning:** `target="_blank"` inherently grants the new page partial access to the referring page via the `window.opener` API, allowing the newly opened page to hijack the original tab, a vulnerability known as reverse tabnabbing.
**Prevention:** Always pair `target="_blank"` with `rel="noopener noreferrer"` in HTML templates to prevent referrer leakage and tabnabbing.
