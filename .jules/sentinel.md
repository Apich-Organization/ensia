## 2026-10-25 - Add Content-Security-Policy (CSP) to Frontend
**Vulnerability:** Missing Content Security Policy (CSP) in `index.html`
**Learning:** Modern SPAs built with WebAssembly (like Leptos) and Trunk lack a default CSP. Without explicit CSP headers or meta tags, they are vulnerable to XSS if an attacker finds a way to execute malicious scripts or load external resources.
**Prevention:** Always inject a `Content-Security-Policy` HTTP header or `<meta>` tag in the entry HTML file, locking down `script-src` and other sources to known CDNs and `'self'`, and properly isolating `'wasm-unsafe-eval'` permissions for the Wasm binary context.

## 2026-10-25 - Add Subresource Integrity (SRI) hashes to CDN resources
**Vulnerability:** External KaTeX CSS and JavaScript assets loaded via CDN lacked `integrity` attributes.
**Learning:** External assets loaded without SRI can be manipulated by an attacker who compromises the CDN, leading to Cross-Site Scripting (XSS) and complete loss of integrity over the web frontend execution environment.
**Prevention:** Always generate and verify cryptographic hashes (e.g., SHA-384) for external resources, and enforce them using the `integrity` attribute alongside `crossorigin="anonymous"` for all `<link>` and `<script>` elements relying on CDNs.
