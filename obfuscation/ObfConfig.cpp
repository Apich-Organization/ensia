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

// ObfConfig.cpp — Preset definitions, TOML parsing, and policy resolution.
//
// Preset summary (parameter-level differences, not just pass selection):
//
//  Preset  BCF prob  BCF loop  BCF compl  Sub prob  Sub loop  MBA prob  MBA
//  layers low     30        1         2          40        1         30 1 mid
//  60        1         4          60        1         50        2 high    75 2
//  6          80        2         70        3
//
//  Preset  ConstEnc shares  ConstEnc feistel  Vec prob  Vec width  CSM nested
//  low     2                no                —         —          —
//  mid     3                no                40        128        —
//  high    4                yes               65        256        no

#include "include/ObfConfig.h"
#include "include/toml.hpp"
#include "llvm/Demangle/Demangle.h"
#include "llvm/Support/raw_ostream.h"
#include <cstdlib>
#include <regex>

namespace llvm {

ObfGlobalConfig GObfConfig;

// ── Preset definitions
// ────────────────────────────────────────────────────────

static ObfPassConfig makeLowPreset() {
  ObfPassConfig c;
  // BCF: lightweight — low probability, minimal complexity, no hardware tricks
  c.bcf.enabled = true;
  c.bcf.probability = 30;
  c.bcf.iterations = 1;
  c.bcf.complexity = 2;
  c.bcf.entropy_chain = false;
  c.bcf.junk_asm = false;
  c.bcf.junk_asm_min = 0;
  c.bcf.junk_asm_max = 0;
  c.bcf.nested = false;
  c.bcf.create_func = false;
  c.bcf.only_junk_asm = false;

  // Substitution: sparse, single pass
  c.sub.enabled = true;
  c.sub.probability = 40;
  c.sub.iterations = 1;

  // MBA: shallow, no noise injection — reduces IR growth
  c.mba.enabled = true;
  c.mba.probability = 30;
  c.mba.layers = 1;
  c.mba.heuristic = false;

  // String encryption: partial — reduces decryptor overhead at callsites
  c.str_enc.enabled = true;
  c.str_enc.probability = 70;

  // Constant encryption: minimal — classic 2-share XOR, no Feistel
  c.const_enc.enabled = true;
  c.const_enc.iterations = 1;
  c.const_enc.share_count = 2;
  c.const_enc.feistel = false;
  c.const_enc.substitute_xor = false;
  c.const_enc.substitute_xor_prob = 0;
  c.const_enc.globalize = false;
  c.const_enc.globalize_prob = 0;

  // Split blocks: minimal splits, no stack confusion
  c.split.enabled = true;
  c.split.splits = 2;
  c.split.stack_confusion = false;

  // Heavier passes disabled — would bloat binary significantly
  c.vec.enabled = false;
  c.csm.enabled = false;
  c.flatten.enabled = false;
  c.indir_branch.enabled = false;
  c.func_wrap.enabled = false;
  c.fco.enabled = false;
  c.anti_hook.enabled = false;
  c.anti_dbg.enabled = false;
  c.anti_class_dump.enabled = false;

  return c;
}

static ObfPassConfig makeMidPreset() {
  ObfPassConfig c;
  // BCF: moderate probability, no hardware entropy (portability)
  c.bcf.enabled = true;
  c.bcf.probability = 60;
  c.bcf.iterations = 1;
  c.bcf.complexity = 4;
  c.bcf.entropy_chain = false;
  c.bcf.junk_asm = false;
  c.bcf.junk_asm_min = 2;
  c.bcf.junk_asm_max = 4;
  c.bcf.nested = false;
  c.bcf.create_func = false;
  c.bcf.only_junk_asm = false;

  // Substitution: balanced coverage, single pass
  c.sub.enabled = true;
  c.sub.probability = 60;
  c.sub.iterations = 1;

  // MBA: 2-layer with noise — provides good decompiler resistance
  c.mba.enabled = true;
  c.mba.probability = 50;
  c.mba.layers = 2;
  c.mba.heuristic = true;

  // String encryption: all strings
  c.str_enc.enabled = true;
  c.str_enc.probability = 100;

  // Constant encryption: 3-share XOR + XOR substitution, no Feistel
  c.const_enc.enabled = true;
  c.const_enc.iterations = 1;
  c.const_enc.share_count = 3;
  c.const_enc.feistel = false;
  c.const_enc.substitute_xor = true;
  c.const_enc.substitute_xor_prob = 40;
  c.const_enc.globalize = false;
  c.const_enc.globalize_prob = 50;

  // Split: 3 splits per BB with stack confusion
  c.split.enabled = true;
  c.split.splits = 3;
  c.split.stack_confusion = true;

  // Vector obfuscation: moderate, 128-bit, no shuffle (keeps code size bounded)
  c.vec.enabled = true;
  c.vec.probability = 40;
  c.vec.width = 128;
  c.vec.shuffle = false;
  c.vec.lift_comparisons = true;

  // Classic CFF instead of CSM — more predictable size growth
  c.csm.enabled = false;
  c.flatten.enabled = true;
  c.indir_branch.enabled = true;
  c.indir_branch.use_stack = true;
  c.indir_branch.enc_jump_target = false;

  // Wrappers and anti-analysis: opt-in only
  c.func_wrap.enabled = false;
  c.fco.enabled = false;
  c.anti_hook.enabled = false;
  c.anti_dbg.enabled = false;
  c.anti_class_dump.enabled = false;

  return c;
}

static ObfPassConfig makeHighPreset() {
  ObfPassConfig c;
  // BCF: high probability, 2 loops, deep complexity, entropy-chain, junk asm
  c.bcf.enabled = true;
  c.bcf.probability = 75;
  c.bcf.iterations = 2;
  c.bcf.complexity = 6;
  c.bcf.entropy_chain = true;
  c.bcf.junk_asm = true;
  c.bcf.junk_asm_min = 2;
  c.bcf.junk_asm_max = 4;
  c.bcf.nested = false;
  c.bcf.create_func = true;
  c.bcf.only_junk_asm = false;

  // Substitution: high coverage, 2 passes (stacks on top of MBA output)
  c.sub.enabled = true;
  c.sub.probability = 80;
  c.sub.iterations = 2;

  // MBA: maximum layers with noise — decompiler-hostile
  c.mba.enabled = true;
  c.mba.probability = 70;
  c.mba.layers = 3;
  c.mba.heuristic = true;

  // String encryption: all strings
  c.str_enc.enabled = true;
  c.str_enc.probability = 100;

  // Constant encryption: 4-share Feistel + XOR substitution
  c.const_enc.enabled = true;
  c.const_enc.iterations = 2;
  c.const_enc.share_count = 4;
  c.const_enc.feistel = true;
  c.const_enc.substitute_xor = true;
  c.const_enc.substitute_xor_prob = 60;
  c.const_enc.globalize = true;
  c.const_enc.globalize_prob = 50;

  // Split: 5 splits per BB with stack confusion
  c.split.enabled = true;
  c.split.splits = 5;
  c.split.stack_confusion = true;

  // Vector obfuscation: 256-bit with shuffle — heavier, more opaque
  c.vec.enabled = true;
  c.vec.probability = 65;
  c.vec.width = 256;
  c.vec.shuffle = true;
  c.vec.lift_comparisons = true;

  // CSM (not nested) preferred over classic flatten
  c.csm.enabled = true;
  c.csm.nested_dispatch =
      false; // nested would cause exponential growth at high BCF
  c.csm.warmup = 128;
  c.csm.max_blocks = 5000;
  c.flatten.enabled =
      false; // CSM stamps done functions; flatten is fallback only

  c.indir_branch.enabled = true;
  c.indir_branch.use_stack = true;
  c.indir_branch.enc_jump_target = true;

  // Function wrapper: moderate wrapping
  c.func_wrap.enabled = true;
  c.func_wrap.probability = 50;
  c.func_wrap.times = 1;

  // Function call obfuscate: enabled at high
  c.fco.enabled = true;

  // Anti-analysis: enabled at high
  c.anti_hook.enabled = true;
  c.anti_hook.inline_aarch64 = true;
  c.anti_hook.inline_x86 = true;
  c.anti_hook.inline_win = true;
  c.anti_hook.objc_runtime = true;
  c.anti_hook.antirebind = false;
  c.anti_hook.direct_syscall = true;

  c.anti_dbg.enabled = true;
  c.anti_dbg.probability = 50;

  c.anti_class_dump.enabled = true;
  c.anti_class_dump.use_initialize = true;
  c.anti_class_dump.rename_methodimp = false;
  c.anti_class_dump.scramble_methods = true;
  c.anti_class_dump.dummy_selectors = true;
  c.anti_class_dump.dummy_count = 8;

  return c;
}

static ObfPassConfig makeMaxPreset() {
  ObfPassConfig c;
  // BCF: 100% prob, 3 iterations, 8 complexity, entropy chain, junk asm
  c.bcf.enabled = true;
  c.bcf.probability = 100;
  c.bcf.iterations = 3;
  c.bcf.complexity = 8;
  c.bcf.entropy_chain = true;
  c.bcf.junk_asm = true;
  c.bcf.junk_asm_min = 4;
  c.bcf.junk_asm_max = 8;
  c.bcf.nested = false;
  c.bcf.create_func = true;
  c.bcf.only_junk_asm = false;

  // Sub: 100% prob, 3 iterations
  c.sub.enabled = true;
  c.sub.probability = 100;
  c.sub.iterations = 3;

  // MBA: 100% prob, 3 layers, heuristic
  c.mba.enabled = true;
  c.mba.probability = 100;
  c.mba.layers = 3;
  c.mba.heuristic = true;

  // Split: 8 splits, stack confusion
  c.split.enabled = true;
  c.split.splits = 8;
  c.split.stack_confusion = true;

  // StrEnc: 100%
  c.str_enc.enabled = true;
  c.str_enc.probability = 100;

  // ConstEnc: 3 iterations, 6 shares, feistel=true, subxor=true (100%),
  // globalize=true (80%)
  c.const_enc.enabled = true;
  c.const_enc.iterations = 3;
  c.const_enc.share_count = 6;
  c.const_enc.feistel = true;
  c.const_enc.substitute_xor = true;
  c.const_enc.substitute_xor_prob = 100;
  c.const_enc.globalize = true;
  c.const_enc.globalize_prob = 80;

  // Vec: 90% prob, 512-bit width, shuffle=true, lift_comparisons=true
  c.vec.enabled = true;
  c.vec.probability = 90;
  c.vec.width = 512;
  c.vec.shuffle = true;
  c.vec.lift_comparisons = true;

  // CSM: enabled, nested_dispatch=true, warmup=256, max_blocks=10000
  c.csm.enabled = true;
  c.csm.nested_dispatch = true;
  c.csm.warmup = 256;
  c.csm.max_blocks = 10000;
  c.flatten.enabled = true;

  // IndirBranch: enabled, use_stack=true, enc_jump_target=true
  c.indir_branch.enabled = true;
  c.indir_branch.use_stack = true;
  c.indir_branch.enc_jump_target = true;

  // FuncWrap: 100% prob, 2 times
  c.func_wrap.enabled = true;
  c.func_wrap.probability = 100;
  c.func_wrap.times = 2;

  // FCO: enabled
  c.fco.enabled = true;

  // AntiHook: enabled, all features on
  c.anti_hook.enabled = true;
  c.anti_hook.inline_aarch64 = true;
  c.anti_hook.inline_x86 = true;
  c.anti_hook.inline_win = true;
  c.anti_hook.objc_runtime = true;
  c.anti_hook.antirebind = true;
  c.anti_hook.direct_syscall = true;

  // AntiDbg: 100% prob
  c.anti_dbg.enabled = true;
  c.anti_dbg.probability = 100;

  // AntiAcd: enabled, all features on
  c.anti_class_dump.enabled = true;
  c.anti_class_dump.use_initialize = true;
  c.anti_class_dump.rename_methodimp = true;
  c.anti_class_dump.scramble_methods = true;
  c.anti_class_dump.dummy_selectors = true;
  c.anti_class_dump.dummy_count = 16;

  return c;
}

static ObfPassConfig makeCsmOnlyPreset() {
  ObfPassConfig c;
  c.csm.enabled = true;
  c.csm.warmup = 64;
  c.csm.max_blocks = 5000;
  return c;
}

static ObfPassConfig makeVecOnlyPreset() {
  ObfPassConfig c;
  c.vec.enabled = true;
  c.vec.probability = 80;
  c.vec.width = 256;
  c.vec.shuffle = true;
  c.vec.lift_comparisons = true;
  return c;
}

static ObfPassConfig makeCsmVecPreset() {
  ObfPassConfig c;
  c.csm.enabled = true;
  c.csm.warmup = 64;
  c.csm.max_blocks = 5000;
  c.vec.enabled = true;
  c.vec.probability = 80;
  c.vec.width = 256;
  c.vec.shuffle = true;
  c.vec.lift_comparisons = true;
  return c;
}

// ── Merge helper
// ────────────────────────────────────────────────────────────── Copy every
// non-empty optional from src into dst (src overrides dst).

#define MERGE_OPT(field)                                                       \
  if (src.field.has_value())                                                   \
    dst.field = src.field;
// Vector merge: replace dst with src when src is non-empty.
#define MERGE_VEC(field)                                                       \
  if (!src.field.empty())                                                      \
    dst.field = src.field;

void ObfGlobalConfig::merge(ObfPassConfig &dst, const ObfPassConfig &src){
    // BCF
    MERGE_OPT(bcf.enabled) MERGE_OPT(bcf.probability) MERGE_OPT(bcf.iterations)
        MERGE_OPT(bcf.complexity) MERGE_OPT(bcf.entropy_chain)
            MERGE_OPT(bcf.junk_asm) MERGE_OPT(bcf.junk_asm_min)
                MERGE_OPT(bcf.junk_asm_max) MERGE_OPT(bcf.nested)
                    MERGE_OPT(bcf.create_func) MERGE_OPT(bcf.only_junk_asm)
    // Sub
    MERGE_OPT(sub.enabled) MERGE_OPT(sub.probability) MERGE_OPT(sub.iterations)
    // MBA
    MERGE_OPT(mba.enabled) MERGE_OPT(mba.probability) MERGE_OPT(mba.layers)
        MERGE_OPT(mba.heuristic)
    // Split
    MERGE_OPT(split.enabled) MERGE_OPT(split.splits)
        MERGE_OPT(split.stack_confusion)
    // StrEnc
    MERGE_OPT(str_enc.enabled) MERGE_OPT(str_enc.probability)
        MERGE_VEC(str_enc.skip_content) MERGE_VEC(str_enc.force_content)
    // ConstEnc
    MERGE_OPT(const_enc.enabled) MERGE_OPT(const_enc.iterations)
        MERGE_OPT(const_enc.share_count) MERGE_OPT(const_enc.feistel)
            MERGE_OPT(const_enc.substitute_xor)
                MERGE_OPT(const_enc.substitute_xor_prob)
                    MERGE_OPT(const_enc.globalize)
                        MERGE_OPT(const_enc.globalize_prob)
                            MERGE_VEC(const_enc.skip_value)
                                MERGE_VEC(const_enc.force_value)
    // Vec
    MERGE_OPT(vec.enabled) MERGE_OPT(vec.probability) MERGE_OPT(vec.width)
        MERGE_OPT(vec.shuffle) MERGE_OPT(vec.lift_comparisons)
    // CSM
    MERGE_OPT(csm.enabled) MERGE_OPT(csm.nested_dispatch) MERGE_OPT(csm.warmup)
        MERGE_OPT(csm.max_blocks)
    // Flatten
    MERGE_OPT(flatten.enabled)
    // IndirBranch
    MERGE_OPT(indir_branch.enabled) MERGE_OPT(indir_branch.use_stack)
        MERGE_OPT(indir_branch.enc_jump_target)
    // FuncWrap
    MERGE_OPT(func_wrap.enabled) MERGE_OPT(func_wrap.probability)
        MERGE_OPT(func_wrap.times)
    // FCO
    MERGE_OPT(fco.enabled) MERGE_OPT(fco.flag) MERGE_OPT(fco.symbol_config_path)
    // Anti-*
    MERGE_OPT(anti_hook.enabled) MERGE_OPT(anti_hook.inline_aarch64)
        MERGE_OPT(anti_hook.inline_x86) MERGE_OPT(anti_hook.inline_win)
            MERGE_OPT(anti_hook.objc_runtime) MERGE_OPT(anti_hook.antirebind)
                MERGE_OPT(anti_hook.direct_syscall)

                    MERGE_OPT(anti_dbg.enabled) MERGE_OPT(anti_dbg.probability)

                        MERGE_OPT(anti_class_dump.enabled)
                            MERGE_OPT(anti_class_dump.use_initialize) MERGE_OPT(
                                anti_class_dump.rename_methodimp)
                                MERGE_OPT(anti_class_dump.scramble_methods)
                                    MERGE_OPT(anti_class_dump.dummy_selectors)
                                        MERGE_OPT(anti_class_dump.dummy_count)}

#undef MERGE_OPT
#undef MERGE_VEC

// ── Preset factory
// ────────────────────────────────────────────────────────────

ObfPassConfig ObfGlobalConfig::presetConfig(const std::string &name) {
  std::string s = name;
  for (char &c : s)
    c = (char)std::tolower((unsigned char)c);
  if (s == "low" || s == "light" || s == "1")
    return makeLowPreset();
  if (s == "mid" || s == "med" || s == "medium" || s == "2")
    return makeMidPreset();
  if (s == "high" || s == "3")
    return makeHighPreset();
  if (s == "max" || s == "maximum" || s == "extreme" || s == "4")
    return makeMaxPreset();
  if (s == "csm_only" || s == "csm")
    return makeCsmOnlyPreset();
  if (s == "vec_only" || s == "vec")
    return makeVecOnlyPreset();
  if (s == "csm_vec" || s == "csm+vec")
    return makeCsmVecPreset();
  return {}; // "none" or unknown → all empty optionals
}

// ── Policy resolution
// ─────────────────────────────────────────────────────────

ObfPassConfig ObfGlobalConfig::resolve(StringRef module_name,
                                       StringRef func_name) const {
  ObfPassConfig eff = passes; // start from global config

  // Pre-demangle the function name once for all policy iterations.
  // We use the most specific available API for each mangling scheme:
  //   _R...  → rustDemangle()      (Rust v0, RFC 2603; no hash suffix)
  //   _Z...  → itaniumDemangle()   (C++ Itanium ABI + Rust legacy _ZN…17h…)
  //   ?...   → microsoftDemangle() (MSVC)
  //   other  → nonMicrosoftDemangle() / demangle() heuristic fallback
  // If the result equals the input (i.e. nothing was demangled), we leave
  // demangled_str empty to avoid a redundant second regex pass.
  std::string func_str = func_name.str();
  std::string demangled_str;
  if (demangle_names && !func_str.empty()) {
    StringRef target_sym = func_str;
    if (target_sym.starts_with("\01"))
      target_sym = target_sym.drop_front(1);
    if (target_sym.starts_with("_") &&
        target_sym.drop_front(1).starts_with("_R"))
      target_sym = target_sym.drop_front(
          1); // strip extra C-symbol leading underscore on macOS

    char *buf = nullptr;
    if (target_sym.starts_with("_R")) {
      // Rust v0 mangling (RFC 2603 / Rust 1.97+ default): rustDemangle gives a
      // clean "crate::mod::fn" form without the hash suffix that
      // itaniumDemangle would leave on legacy Rust.
      buf = llvm::rustDemangle(target_sym);
    } else if (target_sym.starts_with("_Z")) {
      // Itanium C++ ABI (also covers Rust legacy _ZN…17h…E mangling).
      // ParseParams=false keeps the result as "ns::fn" rather than
      // "ns::fn(type, type)" — cleaner for regex matching.
      buf = llvm::itaniumDemangle(target_sym, /*ParseParams=*/false);
    } else if (target_sym.starts_with("?")) {
      // MSVC mangling
      buf = llvm::microsoftDemangle(target_sym, nullptr, nullptr);
    } else {
      // Heuristic fallback (D, dlang, already-demangled, etc.)
      std::string r = llvm::demangle(target_sym);
      if (r != target_sym.str() && r != func_str)
        demangled_str = std::move(r);
    }
    if (buf) {
      demangled_str = buf;
      std::free(buf);
    }
  }

  for (const auto &pol : policies) {
    // Match module
    if (pol.compiled_module_regex.has_value()) {
      std::string mod_str = module_name.str();
      if (!std::regex_search(mod_str, pol.compiled_module_regex.value()))
        continue;
    } else if (!pol.module_regex.empty()) {
      try {
        std::regex mod_re(pol.module_regex,
                          std::regex::ECMAScript | std::regex::optimize);
        std::string mod_str = module_name.str();
        if (!std::regex_search(mod_str, mod_re))
          continue;
      } catch (const std::regex_error &) {
        errs() << "[Ensia] invalid module regex in policy: " << pol.module_regex
               << "\n";
        continue;
      }
    }

    // Match function (if specified).
    // Try both the raw mangled name and the demangled form so users can write
    // human-readable patterns for Rust / C++ without knowing the mangling.
    if (pol.compiled_func_regex.has_value()) {
      bool matched = std::regex_search(func_str, pol.compiled_func_regex.value());
      if (!matched && !demangled_str.empty())
        matched = std::regex_search(demangled_str, pol.compiled_func_regex.value());
      if (!matched)
        continue;
    } else if (!pol.func_regex.empty()) {
      try {
        std::regex func_re(pol.func_regex,
                           std::regex::ECMAScript | std::regex::optimize);
        bool matched = std::regex_search(func_str, func_re);
        if (!matched && !demangled_str.empty())
          matched = std::regex_search(demangled_str, func_re);
        if (!matched)
          continue;
      } catch (const std::regex_error &) {
        errs() << "[Ensia] invalid function regex in policy: " << pol.func_regex
               << "\n";
        continue;
      }
    }

    // Apply preset base first (lower priority than specific overrides)
    if (!pol.preset.empty()) {
      ObfPassConfig preset_cfg = presetConfig(pol.preset);
      merge(eff, preset_cfg);
    }

    // Apply specific pass overrides (highest priority within this policy)
    merge(eff, pol.overrides);
  }

  return eff;
}

// ── TOML helpers
// ──────────────────────────────────────────────────────────────

// Helper: append strings from a TOML array node into a vector.
static void tomlStrArr(const toml::node_view<const toml::node> &v,
                       std::vector<std::string> &out) {
  if (const auto *arr = v.as_array())
    arr->for_each(
        [&](const toml::value<std::string> &s) { out.push_back(s.get()); });
}

// Helper: read a uint32 from a TOML node (accepts both int64 and double).
static std::optional<uint32_t>
tomlU32(const toml::node_view<const toml::node> &v) {
  if (auto i = v.value<int64_t>())
    return (uint32_t)*i;
  return std::nullopt;
}

// Parse a [passes.bcf]-style table into ObfBcfConfig.
static void parseBcf(const toml::table &t, ObfBcfConfig &c) {
  if (auto v = t["enabled"].value<bool>())
    c.enabled = *v;
  if (auto v = tomlU32(t["probability"]))
    c.probability = *v;
  if (auto v = tomlU32(t["iterations"]))
    c.iterations = *v;
  if (auto v = tomlU32(t["complexity"]))
    c.complexity = *v;
  if (auto v = t["entropy_chain"].value<bool>())
    c.entropy_chain = *v;
  if (auto v = t["junk_asm"].value<bool>())
    c.junk_asm = *v;
  if (auto v = tomlU32(t["junk_asm_min"]))
    c.junk_asm_min = *v;
  if (auto v = tomlU32(t["junk_asm_max"]))
    c.junk_asm_max = *v;
  if (auto v = t["nested"].value<bool>())
    c.nested = *v;
  if (auto v = t["create_func"].value<bool>())
    c.create_func = *v;
  if (auto v = t["only_junk_asm"].value<bool>())
    c.only_junk_asm = *v;
}

static void parseSub(const toml::table &t, ObfSubConfig &c) {
  if (auto v = t["enabled"].value<bool>())
    c.enabled = *v;
  if (auto v = tomlU32(t["probability"]))
    c.probability = *v;
  if (auto v = tomlU32(t["iterations"]))
    c.iterations = *v;
}

static void parseMba(const toml::table &t, ObfMbaConfig &c) {
  if (auto v = t["enabled"].value<bool>())
    c.enabled = *v;
  if (auto v = tomlU32(t["probability"]))
    c.probability = *v;
  if (auto v = tomlU32(t["layers"]))
    c.layers = *v;
  if (auto v = t["heuristic"].value<bool>())
    c.heuristic = *v;
}

static void parseSplit(const toml::table &t, ObfSplitConfig &c) {
  if (auto v = t["enabled"].value<bool>())
    c.enabled = *v;
  if (auto v = tomlU32(t["splits"]))
    c.splits = *v;
  if (auto v = t["stack_confusion"].value<bool>())
    c.stack_confusion = *v;
}

static void parseStrEnc(const toml::table &t, ObfStrEncConfig &c) {
  if (auto v = t["enabled"].value<bool>())
    c.enabled = *v;
  if (auto v = tomlU32(t["probability"]))
    c.probability = *v;
  tomlStrArr(t["skip_content"], c.skip_content);
  tomlStrArr(t["force_content"], c.force_content);
}

static void parseConstEnc(const toml::table &t, ObfConstEncConfig &c) {
  if (auto v = t["enabled"].value<bool>())
    c.enabled = *v;
  if (auto v = tomlU32(t["iterations"]))
    c.iterations = *v;
  if (auto v = tomlU32(t["share_count"]))
    c.share_count = *v;
  if (auto v = t["feistel"].value<bool>())
    c.feistel = *v;
  if (auto v = t["substitute_xor"].value<bool>())
    c.substitute_xor = *v;
  if (auto v = tomlU32(t["substitute_xor_prob"]))
    c.substitute_xor_prob = *v;
  if (auto v = t["globalize"].value<bool>())
    c.globalize = *v;
  if (auto v = tomlU32(t["globalize_prob"]))
    c.globalize_prob = *v;
  tomlStrArr(t["skip_value"], c.skip_value);
  tomlStrArr(t["force_value"], c.force_value);
}

static void parseVec(const toml::table &t, ObfVecConfig &c) {
  if (auto v = t["enabled"].value<bool>())
    c.enabled = *v;
  if (auto v = tomlU32(t["probability"]))
    c.probability = *v;
  if (auto v = tomlU32(t["width"]))
    c.width = *v;
  if (auto v = t["shuffle"].value<bool>())
    c.shuffle = *v;
  if (auto v = t["lift_comparisons"].value<bool>())
    c.lift_comparisons = *v;
}

static void parseCsm(const toml::table &t, ObfCsmConfig &c) {
  if (auto v = t["enabled"].value<bool>())
    c.enabled = *v;
  if (auto v = t["nested_dispatch"].value<bool>())
    c.nested_dispatch = *v;
  if (auto v = tomlU32(t["warmup"]))
    c.warmup = *v;
  if (auto v = tomlU32(t["max_blocks"]))
    c.max_blocks = *v;
}

static void parseIndir(const toml::table &t, ObfIndirConfig &c) {
  if (auto v = t["enabled"].value<bool>())
    c.enabled = *v;
  if (auto v = t["use_stack"].value<bool>())
    c.use_stack = *v;
  if (auto v = t["enc_jump_target"].value<bool>())
    c.enc_jump_target = *v;
}

static void parseFw(const toml::table &t, ObfFwConfig &c) {
  if (auto v = t["enabled"].value<bool>())
    c.enabled = *v;
  if (auto v = tomlU32(t["probability"]))
    c.probability = *v;
  if (auto v = tomlU32(t["times"]))
    c.times = *v;
}

static void parseFco(const toml::table &t, ObfFcoConfig &c) {
  if (auto v = t["enabled"].value<bool>())
    c.enabled = *v;
  if (auto v = t["flag"].value<int64_t>())
    c.flag = (uint64_t)*v;
  if (auto v = t["symbol_config_path"].value<std::string>())
    c.symbol_config_path = *v;
}

static void parseAntiHook(const toml::table &t, ObfAntiHookConfig &c) {
  if (auto v = t["enabled"].value<bool>())
    c.enabled = *v;
  if (auto v = t["inline_aarch64"].value<bool>())
    c.inline_aarch64 = *v;
  if (auto v = t["inline_x86"].value<bool>())
    c.inline_x86 = *v;
  if (auto v = t["inline_win"].value<bool>())
    c.inline_win = *v;
  if (auto v = t["objc_runtime"].value<bool>())
    c.objc_runtime = *v;
  if (auto v = t["antirebind"].value<bool>())
    c.antirebind = *v;
  if (auto v = t["direct_syscall"].value<bool>())
    c.direct_syscall = *v;
}

static void parseAntiDbg(const toml::table &t, ObfAntiDbgConfig &c) {
  if (auto v = t["enabled"].value<bool>())
    c.enabled = *v;
  if (auto v = tomlU32(t["probability"]))
    c.probability = *v;
}

static void parseAntiAcd(const toml::table &t, ObfAntiAcdConfig &c) {
  if (auto v = t["enabled"].value<bool>())
    c.enabled = *v;
  if (auto v = t["use_initialize"].value<bool>())
    c.use_initialize = *v;
  if (auto v = t["rename_methodimp"].value<bool>())
    c.rename_methodimp = *v;
  if (auto v = t["scramble_methods"].value<bool>())
    c.scramble_methods = *v;
  if (auto v = t["dummy_selectors"].value<bool>())
    c.dummy_selectors = *v;
  if (auto v = tomlU32(t["dummy_count"]))
    c.dummy_count = *v;
}

// Parse the [passes] table.
static void parsePasses(const toml::table &passes, ObfPassConfig &pc) {
  if (auto *t = passes["bcf"].as_table())
    parseBcf(*t, pc.bcf);
  if (auto *t = passes["substitution"].as_table())
    parseSub(*t, pc.sub);
  if (auto *t = passes["mba"].as_table())
    parseMba(*t, pc.mba);
  if (auto *t = passes["split_blocks"].as_table())
    parseSplit(*t, pc.split);
  if (auto *t = passes["string_encryption"].as_table())
    parseStrEnc(*t, pc.str_enc);
  if (auto *t = passes["constant_encryption"].as_table())
    parseConstEnc(*t, pc.const_enc);
  if (auto *t = passes["vector_obfuscation"].as_table())
    parseVec(*t, pc.vec);
  if (auto *t = passes["chaos_state_machine"].as_table())
    parseCsm(*t, pc.csm);
  if (auto *t = passes["flattening"].as_table())
    if (auto v = (*t)["enabled"].value<bool>())
      pc.flatten.enabled = *v;
  if (auto *t = passes["indirect_branch"].as_table())
    parseIndir(*t, pc.indir_branch);
  if (auto *t = passes["function_wrapper"].as_table())
    parseFw(*t, pc.func_wrap);
  if (auto *t = passes["function_call_obfuscate"].as_table())
    parseFco(*t, pc.fco);
  if (auto *t = passes["anti_hooking"].as_table())
    parseAntiHook(*t, pc.anti_hook);
  if (auto *t = passes["anti_debugging"].as_table())
    parseAntiDbg(*t, pc.anti_dbg);
  if (auto *t = passes["anti_class_dump"].as_table())
    parseAntiAcd(*t, pc.anti_class_dump);
}

// Parse one [[policy]] entry.
static ObfPolicy parsePolicy(const toml::table &pt) {
  ObfPolicy pol;
  if (auto v = pt["module"].value<std::string>()) {
    pol.module_regex = *v;
    try {
      pol.compiled_module_regex.emplace(*v, std::regex::ECMAScript | std::regex::optimize);
    } catch (const std::regex_error &) {
      errs() << "[Ensia] invalid module regex in policy: " << *v << "\n";
    }
  }
  if (auto v = pt["function"].value<std::string>()) {
    pol.func_regex = *v;
    try {
      pol.compiled_func_regex.emplace(*v, std::regex::ECMAScript | std::regex::optimize);
    } catch (const std::regex_error &) {
      errs() << "[Ensia] invalid function regex in policy: " << *v << "\n";
    }
  }
  if (auto v = pt["preset"].value<std::string>())
    pol.preset = *v;

  // Optional inline pass overrides: passes.bcf.probability = 90
  if (auto *passes_tbl = pt["passes"].as_table())
    parsePasses(*passes_tbl, pol.overrides);

  return pol;
}

// ── Main loader
// ───────────────────────────────────────────────────────────────

ObfGlobalConfig ObfGlobalConfig::loadFromFile(StringRef path) {
  ObfGlobalConfig cfg;

  try {
    auto tbl = toml::parse_file(path.str());

    // [global]
    if (const auto *global = tbl["global"].as_table()) {
      if (auto v = (*global)["preset"].value<std::string>())
        cfg.preset = *v;
      if (auto v = (*global)["seed"].value<int64_t>())
        cfg.seed = (uint64_t)*v;
      if (auto v = (*global)["verbose"].value<bool>())
        cfg.verbose = *v;
      if (auto v = (*global)["trace"].value<bool>())
        cfg.trace = *v;
      if (auto v = (*global)["demangle_names"].value<bool>())
        cfg.demangle_names = *v;
    }

    // Apply preset first (lowest priority for pass params)
    if (!cfg.preset.empty())
      cfg.passes = presetConfig(cfg.preset);

    // [passes.*] overrides — higher priority than preset
    if (const auto *passes = tbl["passes"].as_table())
      parsePasses(*passes, cfg.passes);

    // [[policy]] rules
    if (const auto *policy_arr = tbl["policy"].as_array()) {
      for (const auto &entry : *policy_arr)
        if (const auto *pt = entry.as_table())
          cfg.policies.push_back(parsePolicy(*pt));
    }

    errs() << "[Ensia] Loaded config from '" << path << "'";
    if (!cfg.preset.empty())
      errs() << " (preset=" << cfg.preset << ")";
    errs() << "\n";

  } catch (const toml::parse_error &e) {
    errs() << "[Ensia] TOML parse error in '" << path << "': " << e.what()
           << "\n";
    errs() << "[Ensia] Using defaults.\n";
    return defaults();
  }

  return cfg;
}

} // namespace llvm
