/*
 *  OLLVM-Next (Ensia): The next generation LLVM based Obfuscator
 *  Copyright (C) 2026  Xinyu Yang(<Xinyu.Yang@apich.org>)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// ObfConfig.h — Structured configuration for OLLVM-Next presets and TOML files.
//
// Priority chain (highest wins):
//   source annotation  >  TOML policy override  >  TOML global  >  preset  >  cl::opt default
//
// Usage in passes:
//   auto ec = GObfConfig.resolve(F.getParent()->getSourceFileName(), F.getName());
//   uint32_t prob = ec.bcf.probability.value_or((uint32_t)ObfProbRate);
//
// TOML schema (ensia.toml):
//   [global]
//   preset          = "mid"   # "low" | "mid" | "high" | "max" | "none"
//   seed            = 0x1337
//   verbose         = false
//   trace           = false
//   demangle_names  = true    # match policy function regexes against demangled names (Rust/C++)
//
//   [passes.bcf]
//   enabled       = true
//   probability   = 60
//   iterations    = 1
//   complexity    = 4
//   entropy_chain = false
//   junk_asm      = false
//   junk_asm_min  = 2
//   junk_asm_max  = 4
//
//   [passes.substitution]
//   enabled     = true
//   probability = 60
//   iterations  = 1
//
//   [passes.mba]
//   enabled     = true
//   probability = 50
//   layers      = 2       # 1-3
//   heuristic   = true
//
//   [passes.split_blocks]
//   enabled         = true
//   splits          = 3
//   stack_confusion = true
//
//   [passes.string_encryption]
//   enabled       = true
//   probability   = 100
//   skip_content  = ["debug", "Usage:"]   # skip strings whose content matches
//   force_content = ["secret", "key"]     # force-encrypt matching strings
//
//   [passes.constant_encryption]
//   enabled                  = true
//   iterations               = 1
//   share_count              = 3      # XOR shares [2-8]
//   feistel                  = false
//   substitute_xor           = true
//   substitute_xor_prob      = 40
//   globalize                = false
//   globalize_prob           = 50
//   skip_value               = ["0x0", "0x1"]     # skip these constant values (hex regex, icase)
//   force_value              = ["0xDEADBEEF"]      # force-encrypt matching values
//
//   [passes.vector_obfuscation]
//   enabled          = true
//   probability      = 40
//   width            = 128    # 128 | 256 | 512
//   shuffle          = false
//   lift_comparisons = true
//
//   [passes.chaos_state_machine]
//   enabled         = false
//   nested_dispatch = false
//   warmup          = 64
//
//   [passes.flattening]
//   enabled = true
//
//   [passes.indirect_branch]
//   enabled = true
//
//   [passes.function_wrapper]
//   enabled     = false
//   probability = 50
//   times       = 1
//
//   [passes.function_call_obfuscate]
//   enabled = false
//
//   [passes.anti_hooking]
//   enabled = false
//
//   [passes.anti_debugging]
//   enabled = false
//
//   [passes.anti_class_dump]
//   enabled = false
//
//   # Per-module/function policy rules — matched in order, all matches merged,
//   # later rules override earlier ones for each field.
//   # 'module' is a regex on the LLVM module source file path.
//   # 'function' (optional) is a regex on the function name; omit for module-wide.
//
//   [[policy]]
//   module   = ".*crypto.*"
//   function = ".*encrypt.*"
//   preset   = "high"           # use "high" as base for these functions
//   passes.bcf.probability = 90
//
//   [[policy]]
//   module   = ".*"
//   function = "^main$"
//   passes.bcf.enabled = false

#pragma once

#include "llvm/ADT/StringRef.h"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace llvm {

// ── Per-pass configuration structs ───────────────────────────────────────────
// Every field is optional: absent means "use the pass's own cl::opt default".

struct ObfBcfConfig {
  std::optional<bool>     enabled;
  std::optional<uint32_t> probability;    // 0–100
  std::optional<uint32_t> iterations;
  std::optional<uint32_t> complexity;     // predicate depth 1–10
  std::optional<bool>     entropy_chain;  // 3-way CPUID & RDTSC & global
  std::optional<bool>     junk_asm;
  std::optional<uint32_t> junk_asm_min;
  std::optional<uint32_t> junk_asm_max;
};

struct ObfSubConfig {
  std::optional<bool>     enabled;
  std::optional<uint32_t> probability;
  std::optional<uint32_t> iterations;
};

struct ObfMbaConfig {
  std::optional<bool>     enabled;
  std::optional<uint32_t> probability;
  std::optional<uint32_t> layers;         // 1–3
  std::optional<bool>     heuristic;      // zero-noise injection
};

struct ObfSplitConfig {
  std::optional<bool>     enabled;
  std::optional<uint32_t> splits;         // splits per BB
  std::optional<bool>     stack_confusion;
};

struct ObfStrEncConfig {
  std::optional<bool>      enabled;
  std::optional<uint32_t>  probability;
  // Regex patterns matched against raw string content (i8 arrays only).
  // skip_content: if any pattern matches, do not encrypt this string literal.
  // force_content: if any pattern matches, encrypt regardless of probability.
  std::vector<std::string> skip_content;
  std::vector<std::string> force_content;
};

struct ObfConstEncConfig {
  std::optional<bool>      enabled;
  std::optional<uint32_t>  iterations;
  std::optional<uint32_t>  share_count;         // 2–8
  std::optional<bool>      feistel;
  std::optional<bool>      substitute_xor;
  std::optional<uint32_t>  substitute_xor_prob; // 0–100
  std::optional<bool>      globalize;
  std::optional<uint32_t>  globalize_prob;      // 0–100
  // Regex patterns matched case-insensitively against the hex value of each
  // ConstantInt (format: "0xDEADBEEF").
  // skip_value: skip encrypting constants whose value matches.
  // force_value: always encrypt constants whose value matches.
  std::vector<std::string> skip_value;
  std::vector<std::string> force_value;
};

struct ObfVecConfig {
  std::optional<bool>     enabled;
  std::optional<uint32_t> probability;
  std::optional<uint32_t> width;          // 128 | 256 | 512
  std::optional<bool>     shuffle;
  std::optional<bool>     lift_comparisons;
};

struct ObfCsmConfig {
  std::optional<bool>     enabled;
  std::optional<bool>     nested_dispatch;
  std::optional<uint32_t> warmup;
};

struct ObfFlatConfig {
  std::optional<bool> enabled;
};

struct ObfIndirConfig {
  std::optional<bool> enabled;
};

struct ObfFwConfig {
  std::optional<bool>     enabled;
  std::optional<uint32_t> probability;
  std::optional<uint32_t> times;
};

struct ObfFcoConfig {
  std::optional<bool> enabled;
};

struct ObfAntiHookConfig {
  std::optional<bool> enabled;
};

struct ObfAntiDbgConfig {
  std::optional<bool> enabled;
};

struct ObfAntiAcdConfig {
  std::optional<bool> enabled;
};

// All passes collected
struct ObfPassConfig {
  ObfBcfConfig      bcf;
  ObfSubConfig      sub;
  ObfMbaConfig      mba;
  ObfSplitConfig    split;
  ObfStrEncConfig   str_enc;
  ObfConstEncConfig const_enc;
  ObfVecConfig      vec;
  ObfCsmConfig      csm;
  ObfFlatConfig     flatten;
  ObfIndirConfig    indir_branch;
  ObfFwConfig       func_wrap;
  ObfFcoConfig      fco;
  ObfAntiHookConfig anti_hook;
  ObfAntiDbgConfig  anti_dbg;
  ObfAntiAcdConfig  anti_class_dump;
};

// ── Policy rule ───────────────────────────────────────────────────────────────

struct ObfPolicy {
  std::string       module_regex;   // regex on module source file path
  std::string       func_regex;     // regex on function name (empty = module-wide)
  std::string       preset;         // optional: "low"|"mid"|"high" base for this rule
  ObfPassConfig     overrides;      // specific per-pass overrides
};

// ── Top-level config ──────────────────────────────────────────────────────────

struct ObfGlobalConfig {
  std::string             preset;   // "none"|"low"|"mid"|"high" (max handled separately)
  uint64_t                seed            = 0;
  bool                    verbose         = false;
  bool                    trace           = false;
  // When true, policy function regexes are matched against both the raw
  // (mangled) LLVM function name AND the demangled form.  This lets users
  // write patterns like "my_crate::crypto::.*" for Rust functions that appear
  // as "_ZN8my_crate6crypto..." in the IR.  Enabled by default.
  bool                    demangle_names  = true;
  ObfPassConfig           passes;           // global (preset + file [passes.*])
  std::vector<ObfPolicy>  policies;         // ordered policy rules

  // Build a config from a preset name ("low", "mid", "high").
  static ObfPassConfig presetConfig(const std::string &name);

  // Merge src's non-empty optionals into dst (dst is modified in place).
  static void merge(ObfPassConfig &dst, const ObfPassConfig &src);

  // Resolve effective config for a given module/function pair.
  // Starts from passes (global), then applies all matching policies in order.
  ObfPassConfig resolve(StringRef module_name, StringRef func_name) const;

  // Load config from a TOML file.  Returns defaults on parse error.
  static ObfGlobalConfig loadFromFile(StringRef path);

  // Returns a config with no fields set (passes everything through to cl::opt defaults).
  static ObfGlobalConfig defaults() { return {}; }
};

// Global instance — populated by createObfuscationLegacyPass() before any pass runs.
extern ObfGlobalConfig GObfConfig;

} // namespace llvm
