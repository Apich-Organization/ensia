## 2024-05-18 - XSS in Config Builder Download
**Vulnerability:** XSS through `js_sys::eval` when generating the config string. If a malicious input contains `")`, it could break out of the string formatting and execute arbitrary JavaScript.
**Learning:** `js_sys::eval` with formatted string inputs that contain dynamic strings is prone to XSS in Leptos/WASM environments, just like `eval()` in standard JavaScript.
**Prevention:** Always declare the external JavaScript functions via `#[wasm_bindgen]` and call them directly, passing arguments safely across the WASM boundary instead of string-formatting them into `eval`. Use native JS promises or `TimeoutFuture` for timeouts instead of `setTimeout` strings.
