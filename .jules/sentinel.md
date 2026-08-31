## 2024-05-18 - Unhandled JS Panic in WASM Frontend
**Vulnerability:** JS function bindings (like `copyText`) missing `catch` could panic the whole WebAssembly application if the function was missing or threw an error, acting as a DoS vector.
**Learning:** `wasm-bindgen` defaults to panicking on JS exceptions unless explicitly caught, and missing JS globals will also throw immediately on access.
**Prevention:** Always use `#[wasm_bindgen(catch)]` and return a `Result<T, JsValue>` for external JS functions where reliability or error-handling is crucial.
