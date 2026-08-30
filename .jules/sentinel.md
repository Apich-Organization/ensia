## 2026-08-30 - Fix Thread Safety Vulnerability in Global State
**Vulnerability:** Global configuration variables across obfuscation passes were defined as mutable `static` without `thread_local`, leading to a thread-safety vulnerability (race conditions) when the modern LLVM Pass Manager executes passes concurrently across different threads.
**Learning:** Legacy LLVM passes ported to the New Pass Manager often overlook concurrency issues. Mutable static configuration state shared across the module/function processing must be isolated per thread.
**Prevention:** Always declare mutable `static` configuration variables within pass logic as `static thread_local` to prevent state corruption when passes execute concurrently across threads.
