## 2024-08-14 - Fix Cross-Site Scripting (XSS) due to incomplete HTML escaping
**Vulnerability:** A Cross-Site Scripting (XSS) vulnerability was found in the configuration page's TOML syntax highlighter. The `escape_html` function in `web/src/pages/config.rs` did not escape double quotes (`"`) and single quotes (`'`). These strings were subsequently rendered via `set_inner_html`.
**Learning:** Even if `<` and `>` are escaped, when rendering content that will end up dynamically inside HTML (like `<span class='...'>{val}</span>`), missing single/double quotes can sometimes lead to escaping string interpolation or context attributes, eventually leading to XSS depending on exact interpolation structure. In our context, since users can inject raw payloads through the input text config and the output includes HTML spans built via string formatting, proper escaping of single and double quotes is crucial.
**Prevention:** Always escape all context-sensitive characters (`<`, `>`, `&`, `"`, `'`) when writing custom HTML escaping routines before dangerously setting inner HTML (like `set_inner_html`), or preferably avoid `inner_html` rendering user inputs entirely and stick to safe DOM text node assignments where possible.
## 2024-05-18 - XSS in Config Builder Download
**Vulnerability:** XSS through `js_sys::eval` when generating the config string. If a malicious input contains `")`, it could break out of the string formatting and execute arbitrary JavaScript.
**Learning:** `js_sys::eval` with formatted string inputs that contain dynamic strings is prone to XSS in Leptos/WASM environments, just like `eval()` in standard JavaScript.
**Prevention:** Always declare the external JavaScript functions via `#[wasm_bindgen]` and call them directly, passing arguments safely across the WASM boundary instead of string-formatting them into `eval`. Use native JS promises or `TimeoutFuture` for timeouts instead of `setTimeout` strings.
## 2024-08-27 - [CRITICAL] Fix arbitrary code execution vulnerability (XSS)

**Vulnerability:** Found `js_sys::eval` being used in the Leptos frontend application to trigger KaTeX mathematical rendering. This is dangerous as it allows string execution, can bypass Content Security Policy (CSP) `unsafe-eval`, and may lead to DOM-based Cross-Site Scripting (XSS).

**Learning:** The previous implementation relied on a direct JavaScript evaluation wrapper `js_sys::eval("window.triggerKatex && window.triggerKatex()")` to run dynamic JavaScript upon Leptos Effect hooks triggering.

**Prevention:** Replace direct string execution mechanisms (like `eval` in JS or `js_sys::eval` in WASM) with proper external declarations via `wasm_bindgen` (e.g., `#[wasm_bindgen(catch)] extern "C" { fn triggerKatex() -> Result<(), JsValue>; }`).
