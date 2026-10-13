## 2024-05-24 - Missing Subresource Integrity (SRI) Hashes
**Vulnerability:** External CSS and JS resources from CDNs (like KaTeX on `cdn.jsdelivr.net`) were included without Subresource Integrity (`integrity`) attributes.
**Learning:** This exposes the application to XSS and remote code execution if the CDN is compromised, allowing attackers to serve malicious scripts or styles to users.
**Prevention:** Always include `integrity` attributes with cryptographically strong hashes (e.g., SHA-384) and `crossorigin="anonymous"` when fetching assets from external CDNs.
