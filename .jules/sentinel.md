
## 2025-02-14 - Add Content-Security-Policy (CSP) to Frontend
**Vulnerability:** Missing Content Security Policy (CSP) in `index.html`
**Learning:** Modern SPAs built with WebAssembly (like Leptos) and Trunk lack a default CSP. Without explicit CSP headers or meta tags, they are vulnerable to XSS if an attacker finds a way to execute malicious scripts or load external resources.
**Prevention:** Always inject a `Content-Security-Policy` HTTP header or `<meta>` tag in the entry HTML file, locking down `script-src` and other sources to known CDNs and `'self'`, and properly isolating `'wasm-unsafe-eval'` permissions for the Wasm binary context.
