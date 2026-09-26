## 2025-02-18 - Fix Reverse Tabnabbing Vulnerability
**Vulnerability:** External links with target="_blank" missing rel="noopener noreferrer"
**Learning:** Found in multiple locations across Leptos frontend. Allows target site to manipulate window.opener and launch phishing attacks.
**Prevention:** Always append rel="noopener noreferrer" when using target="_blank"
