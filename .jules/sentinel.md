## 2024-05-24 - [Referrer Leakage on External Links]
**Vulnerability:** External links with `target="_blank"` were missing `rel="noreferrer"` alongside `rel="noopener"`.
**Learning:** `noopener` alone doesn't prevent leaking sensitive information in the URL to external websites.
**Prevention:** Always use `rel="noopener noreferrer"` for external `target="_blank"` links in web frontend code to prevent both reverse tabnabbing and referrer leakage.
