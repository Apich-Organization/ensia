## 2024-10-24 - Missing Subresource Integrity (SRI) for CDN assets
**Vulnerability:** External JS and CSS assets (KaTeX) were loaded from a CDN without `integrity` attributes.
**Learning:** This is a severe security gap. If the CDN is compromised, malicious code can be injected into the web application, leading to a third-party XSS vulnerability.
**Prevention:** Always use `integrity` attributes with cryptographically strong hashes (like SHA-384) and set `crossorigin="anonymous"` when loading scripts or stylesheets from external sources or CDNs.
