## 2026-10-14 - Add Subresource Integrity (SRI) hashes to CDN resources
**Vulnerability:** External KaTeX CSS and JavaScript assets loaded via CDN lacked `integrity` attributes.
**Learning:** External assets loaded without SRI can be manipulated by an attacker who compromises the CDN, leading to Cross-Site Scripting (XSS) and complete loss of integrity over the web frontend execution environment.
**Prevention:** Always generate and verify cryptographic hashes (e.g., SHA-384) for external resources, and enforce them using the `integrity` attribute alongside `crossorigin="anonymous"` for all `<link>` and `<script>` elements relying on CDNs.
