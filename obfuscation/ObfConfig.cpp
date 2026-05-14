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
//  Preset  BCF prob  BCF loop  BCF compl  Sub prob  Sub loop  MBA prob  MBA layers
//  low     30        1         2          40        1         30        1
//  mid     60        1         4          60        1         50        2
//  high    75        2         6          80        2         70        3
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

// ── Preset definitions ────────────────────────────────────────────────────────

static ObfPassConfig makeLowPreset() {
  ObfPassConfig c;
  // BCF: lightweight — low probability, minimal complexity, no hardware tricks
  c.bcf.enabled       = true;
  c.bcf.probability   = 30;
  c.bcf.iterations    = 1;
  c.bcf.complexity    = 2;
  c.bcf.entropy_chain = false;
  c.bcf.junk_asm      = false;
  c.bcf.junk_asm_min  = 0;
  c.bcf.junk_asm_max  = 0;

  // Substitution: sparse, single pass
  c.sub.enabled     = true;
  c.sub.probability = 40;
  c.sub.iterations  = 1;

  // MBA: shallow, no noise injection — reduces IR growth
  c.mba.enabled     = true;
  c.mba.probability = 30;
  c.mba.layers      = 1;
  c.mba.heuristic   = false;

  // String encryption: partial — reduces decryptor overhead at callsites
  c.str_enc.enabled     = true;
  c.str_enc.probability = 70;

  // Constant encryption: minimal — classic 2-share XOR, no Feistel
  c.const_enc.enabled              = true;
  c.const_enc.iterations           = 1;
  c.const_enc.share_count          = 2;
  c.const_enc.feistel              = false;
  c.const_enc.substitute_xor       = false;
  c.const_enc.substitute_xor_prob  = 0;
  c.const_enc.globalize            = false;
  c.const_enc.globalize_prob       = 0;

  // Split blocks: minimal splits, no stack confusion
  c.split.enabled         = true;
  c.split.splits          = 2;
  c.split.stack_confusion = false;

  // Heavier passes disabled — would bloat binary significantly
  c.vec.enabled          = false;
  c.csm.enabled          = false;
  c.flatten.enabled      = false;
  c.indir_branch.enabled = false;
  c.func_wrap.enabled    = false;
  c.fco.enabled          = false;
  c.anti_hook.enabled    = false;
  c.anti_dbg.enabled     = false;
  c.anti_class_dump.enabled = false;

  return c;
}

static ObfPassConfig makeMidPreset() {
  ObfPassConfig c;
  // BCF: moderate probability, no hardware entropy (portability)
  c.bcf.enabled       = true;
  c.bcf.probability   = 60;
  c.bcf.iterations    = 1;
  c.bcf.complexity    = 4;
  c.bcf.entropy_chain = false;
  c.bcf.junk_asm      = false;
  c.bcf.junk_asm_min  = 2;
  c.bcf.junk_asm_max  = 4;

  // Substitution: balanced coverage, single pass
  c.sub.enabled     = true;
  c.sub.probability = 60;
  c.sub.iterations  = 1;

  // MBA: 2-layer with noise — provides good decompiler resistance
  c.mba.enabled     = true;
  c.mba.probability = 50;
  c.mba.layers      = 2;
  c.mba.heuristic   = true;

  // String encryption: all strings
  c.str_enc.enabled     = true;
  c.str_enc.probability = 100;

  // Constant encryption: 3-share XOR + XOR substitution, no Feistel
  c.const_enc.enabled              = true;
  c.const_enc.iterations           = 1;
  c.const_enc.share_count          = 3;
  c.const_enc.feistel              = false;
  c.const_enc.substitute_xor       = true;
  c.const_enc.substitute_xor_prob  = 40;
  c.const_enc.globalize            = false;
  c.const_enc.globalize_prob       = 50;

  // Split: 3 splits per BB with stack confusion
  c.split.enabled         = true;
  c.split.splits          = 3;
  c.split.stack_confusion = true;

  // Vector obfuscation: moderate, 128-bit, no shuffle (keeps code size bounded)
  c.vec.enabled          = true;
  c.vec.probability      = 40;
  c.vec.width            = 128;
  c.vec.shuffle          = false;
  c.vec.lift_comparisons = true;

  // Classic CFF instead of CSM — more predictable size growth
  c.csm.enabled          = false;
  c.flatten.enabled      = true;
  c.indir_branch.enabled = true;

  // Wrappers and anti-analysis: opt-in only
  c.func_wrap.enabled    = false;
  c.fco.enabled          = false;
  c.anti_hook.enabled    = false;
  c.anti_dbg.enabled     = false;
  c.anti_class_dump.enabled = false;

  return c;
}

static ObfPassConfig makeHighPreset() {
  ObfPassConfig c;
  // BCF: high probability, 2 loops, deep complexity, entropy-chain, junk asm
  c.bcf.enabled       = true;
  c.bcf.probability   = 75;
  c.bcf.iterations    = 2;
  c.bcf.complexity    = 6;
  c.bcf.entropy_chain = true;
  c.bcf.junk_asm      = true;
  c.bcf.junk_asm_min  = 2;
  c.bcf.junk_asm_max  = 4;

  // Substitution: high coverage, 2 passes (stacks on top of MBA output)
  c.sub.enabled     = true;
  c.sub.probability = 80;
  c.sub.iterations  = 2;

  // MBA: maximum layers with noise — decompiler-hostile
  c.mba.enabled     = true;
  c.mba.probability = 70;
  c.mba.layers      = 3;
  c.mba.heuristic   = true;

  // String encryption: all strings
  c.str_enc.enabled     = true;
  c.str_enc.probability = 100;

  // Constant encryption: 4-share Feistel + XOR substitution
  c.const_enc.enabled              = true;
  c.const_enc.iterations           = 2;
  c.const_enc.share_count          = 4;
  c.const_enc.feistel              = true;
  c.const_enc.substitute_xor       = true;
  c.const_enc.substitute_xor_prob  = 60;
  c.const_enc.globalize            = false;
  c.const_enc.globalize_prob       = 50;

  // Split: 5 splits per BB with stack confusion
  c.split.enabled         = true;
  c.split.splits          = 5;
  c.split.stack_confusion = true;

  // Vector obfuscation: 256-bit with shuffle — heavier, more opaque
  c.vec.enabled          = true;
  c.vec.probability      = 65;
  c.vec.width            = 256;
  c.vec.shuffle          = true;
  c.vec.lift_comparisons = true;

  // CSM (not nested) preferred over classic flatten
  c.csm.enabled          = true;
  c.csm.nested_dispatch  = false;   // nested would cause exponential growth at high BCF
  c.csm.warmup           = 128;
  c.flatten.enabled      = false;   // CSM stamps done functions; flatten is fallback only

  c.indir_branch.enabled = true;

  // Function wrapper: moderate wrapping
  c.func_wrap.enabled    = true;
  c.func_wrap.probability = 50;
  c.func_wrap.times      = 1;

  // Function call obfuscate: enabled at high
  c.fco.enabled = true;

  // Anti-analysis: user opt-in (environment/platform specific)
  c.anti_hook.enabled       = false;
  c.anti_dbg.enabled        = false;
  c.anti_class_dump.enabled = false;

  return c;
}

// ── Merge helper ──────────────────────────────────────────────────────────────
// Copy every non-empty optional from src into dst (src overrides dst).

#define MERGE_OPT(field) if (src.field.has_value()) dst.field = src.field;
// Vector merge: replace dst with src when src is non-empty.
#define MERGE_VEC(field) if (!src.field.empty()) dst.field = src.field;

void ObfGlobalConfig::merge(ObfPassConfig &dst, const ObfPassConfig &src) {
  // BCF
  MERGE_OPT(bcf.enabled)
  MERGE_OPT(bcf.probability)
  MERGE_OPT(bcf.iterations)
  MERGE_OPT(bcf.complexity)
  MERGE_OPT(bcf.entropy_chain)
  MERGE_OPT(bcf.junk_asm)
  MERGE_OPT(bcf.junk_asm_min)
  MERGE_OPT(bcf.junk_asm_max)
  // Sub
  MERGE_OPT(sub.enabled)
  MERGE_OPT(sub.probability)
  MERGE_OPT(sub.iterations)
  // MBA
  MERGE_OPT(mba.enabled)
  MERGE_OPT(mba.probability)
  MERGE_OPT(mba.layers)
  MERGE_OPT(mba.heuristic)
  // Split
  MERGE_OPT(split.enabled)
  MERGE_OPT(split.splits)
  MERGE_OPT(split.stack_confusion)
  // StrEnc
  MERGE_OPT(str_enc.enabled)
  MERGE_OPT(str_enc.probability)
  MERGE_VEC(str_enc.skip_content)
  MERGE_VEC(str_enc.force_content)
  // ConstEnc
  MERGE_OPT(const_enc.enabled)
  MERGE_OPT(const_enc.iterations)
  MERGE_OPT(const_enc.share_count)
  MERGE_OPT(const_enc.feistel)
  MERGE_OPT(const_enc.substitute_xor)
  MERGE_OPT(const_enc.substitute_xor_prob)
  MERGE_OPT(const_enc.globalize)
  MERGE_OPT(const_enc.globalize_prob)
  MERGE_VEC(const_enc.skip_value)
  MERGE_VEC(const_enc.force_value)
  // Vec
  MERGE_OPT(vec.enabled)
  MERGE_OPT(vec.probability)
  MERGE_OPT(vec.width)
  MERGE_OPT(vec.shuffle)
  MERGE_OPT(vec.lift_comparisons)
  // CSM
  MERGE_OPT(csm.enabled)
  MERGE_OPT(csm.nested_dispatch)
  MERGE_OPT(csm.warmup)
  // Flatten
  MERGE_OPT(flatten.enabled)
  // IndirBranch
  MERGE_OPT(indir_branch.enabled)
  // FuncWrap
  MERGE_OPT(func_wrap.enabled)
  MERGE_OPT(func_wrap.probability)
  MERGE_OPT(func_wrap.times)
  // FCO
  MERGE_OPT(fco.enabled)
  // Anti-*
  MERGE_OPT(anti_hook.enabled)
  MERGE_OPT(anti_dbg.enabled)
  MERGE_OPT(anti_class_dump.enabled)
}

#undef MERGE_OPT
#undef MERGE_VEC

// ── Preset factory ────────────────────────────────────────────────────────────

ObfPassConfig ObfGlobalConfig::presetConfig(const std::string &name) {
  if (name == "low")  return makeLowPreset();
  if (name == "mid")  return makeMidPreset();
  if (name == "high") return makeHighPreset();
  return {};  // "none" or unknown → all empty optionals
}

// ── Policy resolution ─────────────────────────────────────────────────────────

ObfPassConfig ObfGlobalConfig::resolve(StringRef module_name,
                                       StringRef func_name) const {
  ObfPassConfig eff = passes;  // start from global config

  // Pre-demangle the function name once for all policy iterations.
  // We use the most specific available API for each mangling scheme:
  //   _R...  → rustDemangle()      (Rust v0, RFC 2603; no hash suffix)
  //   _Z...  → itaniumDemangle()   (C++ Itanium ABI + Rust legacy _ZN…17h…)
  //   ?...   → microsoftDemangle() (MSVC)
  //   other  → nonMicrosoftDemangle() / demangle() heuristic fallback
  // If the result equals the input (i.e. nothing was demangled), we leave
  // demangled_str empty to avoid a redundant second regex pass.
  std::string func_str      = func_name.str();
  std::string demangled_str;
  if (demangle_names && !func_str.empty()) {
    const char *raw = func_str.c_str();
    char *buf = nullptr;
    if (func_str.size() >= 2 && raw[0] == '_' && raw[1] == 'R') {
      // Rust v0 mangling: rustDemangle gives a clean "crate::mod::fn" form
      // without the hash suffix that itaniumDemangle would leave on legacy Rust.
      buf = llvm::rustDemangle(func_str);
    } else if (func_str.size() >= 2 && raw[0] == '_' && raw[1] == 'Z') {
      // Itanium C++ ABI (also covers Rust legacy _ZN…17h…E mangling).
      // ParseParams=false keeps the result as "ns::fn" rather than
      // "ns::fn(type, type)" — cleaner for regex matching.
      buf = llvm::itaniumDemangle(func_str, /*ParseParams=*/false);
    } else if (!func_str.empty() && raw[0] == '?') {
      // MSVC mangling
      buf = llvm::microsoftDemangle(func_str, nullptr, nullptr);
    } else {
      // Heuristic fallback (D, dlang, already-demangled, etc.)
      std::string r = llvm::demangle(func_str);
      if (r != func_str)
        demangled_str = std::move(r);
    }
    if (buf) {
      demangled_str = buf;
      std::free(buf);
    }
  }

  for (const auto &pol : policies) {
    // Match module
    try {
      std::regex mod_re(pol.module_regex,
                        std::regex::ECMAScript | std::regex::optimize);
      std::string mod_str = module_name.str();
      if (!std::regex_search(mod_str, mod_re))
        continue;
    } catch (const std::regex_error &) {
      errs() << "[Ensia] invalid module regex in policy: " << pol.module_regex << "\n";
      continue;
    }

    // Match function (if specified).
    // Try both the raw mangled name and the demangled form so users can write
    // human-readable patterns for Rust / C++ without knowing the mangling.
    if (!pol.func_regex.empty()) {
      try {
        std::regex func_re(pol.func_regex,
                           std::regex::ECMAScript | std::regex::optimize);
        bool matched = std::regex_search(func_str, func_re);
        if (!matched && !demangled_str.empty())
          matched = std::regex_search(demangled_str, func_re);
        if (!matched)
          continue;
      } catch (const std::regex_error &) {
        errs() << "[Ensia] invalid function regex in policy: " << pol.func_regex << "\n";
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

// ── TOML helpers ──────────────────────────────────────────────────────────────

// Helper: append strings from a TOML array node into a vector.
static void tomlStrArr(const toml::node_view<const toml::node> &v,
                       std::vector<std::string> &out) {
  if (const auto *arr = v.as_array())
    arr->for_each([&](const toml::value<std::string> &s) {
      out.push_back(s.get());
    });
}

// Helper: read a uint32 from a TOML node (accepts both int64 and double).
static std::optional<uint32_t> tomlU32(const toml::node_view<const toml::node> &v) {
  if (auto i = v.value<int64_t>())
    return (uint32_t)*i;
  return std::nullopt;
}

// Parse a [passes.bcf]-style table into ObfBcfConfig.
static void parseBcf(const toml::table &t, ObfBcfConfig &c) {
  if (auto v = t["enabled"].value<bool>())          c.enabled       = *v;
  if (auto v = tomlU32(t["probability"]))            c.probability   = *v;
  if (auto v = tomlU32(t["iterations"]))             c.iterations    = *v;
  if (auto v = tomlU32(t["complexity"]))             c.complexity    = *v;
  if (auto v = t["entropy_chain"].value<bool>())     c.entropy_chain = *v;
  if (auto v = t["junk_asm"].value<bool>())          c.junk_asm      = *v;
  if (auto v = tomlU32(t["junk_asm_min"]))           c.junk_asm_min  = *v;
  if (auto v = tomlU32(t["junk_asm_max"]))           c.junk_asm_max  = *v;
}

static void parseSub(const toml::table &t, ObfSubConfig &c) {
  if (auto v = t["enabled"].value<bool>())  c.enabled     = *v;
  if (auto v = tomlU32(t["probability"]))   c.probability = *v;
  if (auto v = tomlU32(t["iterations"]))    c.iterations  = *v;
}

static void parseMba(const toml::table &t, ObfMbaConfig &c) {
  if (auto v = t["enabled"].value<bool>())  c.enabled     = *v;
  if (auto v = tomlU32(t["probability"]))   c.probability = *v;
  if (auto v = tomlU32(t["layers"]))        c.layers      = *v;
  if (auto v = t["heuristic"].value<bool>()) c.heuristic  = *v;
}

static void parseSplit(const toml::table &t, ObfSplitConfig &c) {
  if (auto v = t["enabled"].value<bool>())          c.enabled         = *v;
  if (auto v = tomlU32(t["splits"]))                c.splits          = *v;
  if (auto v = t["stack_confusion"].value<bool>())  c.stack_confusion = *v;
}

static void parseStrEnc(const toml::table &t, ObfStrEncConfig &c) {
  if (auto v = t["enabled"].value<bool>())  c.enabled     = *v;
  if (auto v = tomlU32(t["probability"]))   c.probability = *v;
  tomlStrArr(t["skip_content"],  c.skip_content);
  tomlStrArr(t["force_content"], c.force_content);
}

static void parseConstEnc(const toml::table &t, ObfConstEncConfig &c) {
  if (auto v = t["enabled"].value<bool>())           c.enabled              = *v;
  if (auto v = tomlU32(t["iterations"]))             c.iterations           = *v;
  if (auto v = tomlU32(t["share_count"]))            c.share_count          = *v;
  if (auto v = t["feistel"].value<bool>())           c.feistel              = *v;
  if (auto v = t["substitute_xor"].value<bool>())    c.substitute_xor       = *v;
  if (auto v = tomlU32(t["substitute_xor_prob"]))    c.substitute_xor_prob  = *v;
  if (auto v = t["globalize"].value<bool>())         c.globalize            = *v;
  if (auto v = tomlU32(t["globalize_prob"]))         c.globalize_prob       = *v;
  tomlStrArr(t["skip_value"],  c.skip_value);
  tomlStrArr(t["force_value"], c.force_value);
}

static void parseVec(const toml::table &t, ObfVecConfig &c) {
  if (auto v = t["enabled"].value<bool>())          c.enabled          = *v;
  if (auto v = tomlU32(t["probability"]))           c.probability      = *v;
  if (auto v = tomlU32(t["width"]))                 c.width            = *v;
  if (auto v = t["shuffle"].value<bool>())          c.shuffle          = *v;
  if (auto v = t["lift_comparisons"].value<bool>()) c.lift_comparisons = *v;
}

static void parseCsm(const toml::table &t, ObfCsmConfig &c) {
  if (auto v = t["enabled"].value<bool>())          c.enabled         = *v;
  if (auto v = t["nested_dispatch"].value<bool>())  c.nested_dispatch = *v;
  if (auto v = tomlU32(t["warmup"]))                c.warmup          = *v;
}

static void parseFw(const toml::table &t, ObfFwConfig &c) {
  if (auto v = t["enabled"].value<bool>())  c.enabled     = *v;
  if (auto v = tomlU32(t["probability"]))   c.probability = *v;
  if (auto v = tomlU32(t["times"]))         c.times       = *v;
}

// Parse the [passes] table.
static void parsePasses(const toml::table &passes, ObfPassConfig &pc) {
  if (auto *t = passes["bcf"].as_table())                  parseBcf(*t, pc.bcf);
  if (auto *t = passes["substitution"].as_table())         parseSub(*t, pc.sub);
  if (auto *t = passes["mba"].as_table())                  parseMba(*t, pc.mba);
  if (auto *t = passes["split_blocks"].as_table())         parseSplit(*t, pc.split);
  if (auto *t = passes["string_encryption"].as_table())    parseStrEnc(*t, pc.str_enc);
  if (auto *t = passes["constant_encryption"].as_table())  parseConstEnc(*t, pc.const_enc);
  if (auto *t = passes["vector_obfuscation"].as_table())   parseVec(*t, pc.vec);
  if (auto *t = passes["chaos_state_machine"].as_table())  parseCsm(*t, pc.csm);
  if (auto *t = passes["flattening"].as_table())
    if (auto v = (*t)["enabled"].value<bool>()) pc.flatten.enabled = *v;
  if (auto *t = passes["indirect_branch"].as_table())
    if (auto v = (*t)["enabled"].value<bool>()) pc.indir_branch.enabled = *v;
  if (auto *t = passes["function_wrapper"].as_table())     parseFw(*t, pc.func_wrap);
  if (auto *t = passes["function_call_obfuscate"].as_table())
    if (auto v = (*t)["enabled"].value<bool>()) pc.fco.enabled = *v;
  if (auto *t = passes["anti_hooking"].as_table())
    if (auto v = (*t)["enabled"].value<bool>()) pc.anti_hook.enabled = *v;
  if (auto *t = passes["anti_debugging"].as_table())
    if (auto v = (*t)["enabled"].value<bool>()) pc.anti_dbg.enabled = *v;
  if (auto *t = passes["anti_class_dump"].as_table())
    if (auto v = (*t)["enabled"].value<bool>()) pc.anti_class_dump.enabled = *v;
}

// Parse one [[policy]] entry.
static ObfPolicy parsePolicy(const toml::table &pt) {
  ObfPolicy pol;
  if (auto v = pt["module"].value<std::string>())   pol.module_regex = *v;
  if (auto v = pt["function"].value<std::string>()) pol.func_regex   = *v;
  if (auto v = pt["preset"].value<std::string>())   pol.preset       = *v;

  // Optional inline pass overrides: passes.bcf.probability = 90
  if (auto *passes_tbl = pt["passes"].as_table())
    parsePasses(*passes_tbl, pol.overrides);

  return pol;
}

// ── Main loader ───────────────────────────────────────────────────────────────

ObfGlobalConfig ObfGlobalConfig::loadFromFile(StringRef path) {
  ObfGlobalConfig cfg;

  try {
    auto tbl = toml::parse_file(path.str());

    // [global]
    if (const auto *global = tbl["global"].as_table()) {
      if (auto v = (*global)["preset"].value<std::string>())          cfg.preset         = *v;
      if (auto v = (*global)["seed"].value<int64_t>())                cfg.seed           = (uint64_t)*v;
      if (auto v = (*global)["verbose"].value<bool>())                cfg.verbose        = *v;
      if (auto v = (*global)["trace"].value<bool>())                  cfg.trace          = *v;
      if (auto v = (*global)["demangle_names"].value<bool>())         cfg.demangle_names = *v;
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
    errs() << "[Ensia] TOML parse error in '" << path << "': " << e.what() << "\n";
    errs() << "[Ensia] Using defaults.\n";
    return defaults();
  }

  return cfg;
}

} // namespace llvm
