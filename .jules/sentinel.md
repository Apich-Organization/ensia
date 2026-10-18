## 2024-10-18 - Missing Subresource Integrity (SRI) on CDN Assets
**Vulnerability:** CDN assets (KaTeX CSS/JS) lacked `integrity` hashes in `web/index.html`, which could lead to XSS if the CDN is compromised.
**Learning:** External scripts and stylesheets were included via CDN links without cryptographically verifying their contents, trusting the CDN completely.
**Prevention:** Always generate and include SHA-384 (or stronger) `integrity` attributes alongside `crossorigin="anonymous"` when fetching static assets from third-party domains.
