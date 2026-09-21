## 2024-05-18 - [Fix reverse tabnabbing / Referrer leakage]
**Vulnerability:** External links with target="_blank" only used rel="noopener".
**Learning:** Adding noreferrer prevents the referring page URL from being leaked to external sites via the Referer header and serves as a fallback for older browsers for noopener.
**Prevention:** Always use `rel="noopener noreferrer"` with `target="_blank"`.
