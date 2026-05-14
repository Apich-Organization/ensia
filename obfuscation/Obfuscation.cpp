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

// Obfuscation.cpp — OLLVM-Next master scheduler.
//
// ── Pass execution order ──────────────────────────────────────────────────────
//
//  1. AntiHooking          (module)   — Windows/Darwin/Linux inline-hook detection
//                                       + kernel fast-fail termination
//  2. AntiClassDump        (module)   — ObjC metadata scrambling
//  3. FunctionCallObfuscate(function) — dlopen/dlsym indirection
//  4. AntiDebugging        (module)   — ptrace/sysctl/timing anti-debug checks
//  5. StringEncryption     (module)   — Vernam-GF(2^8) per-byte cipher
//                                       (OTP XOR + GF8 multiply, info-theoretically
//                                        secure; different from ConstantEncryption)
//  6. Per-function (order is deliberate — see rationale below):
//     a. SplitBasicBlocks             — split + stack-confusion injection
//                                       (more granular dispatch targets for CFF)
//     b. BogusControlFlow             — hardware-predicate opaque edges
//                                       (runs on unsplit blocks for wider scope)
//     c. Substitution                 — integer/shift instruction substitution
//                                       (Sub+AShr+Shl/LShr with verified identities)
//     d. MBAObfuscation               — multi-term Mixed Boolean-Arithmetic
//                                       (sees Substitution output → stacked layers)
//     e. ChaosStateMachine            — logistic-map quadratic CFF (strongest)
//                                       (runs first so it sees the clean original
//                                        function; stamps done functions so
//                                        Flattening skips them)
//     f. Flattening                   — chaos-seeded classic CFF (fallback)
//                                       (only processes functions CSM skipped:
//                                        EH pads, coroutines, ≤1 block, etc.)
//     g. VectorObfuscation            — SIMD scalar→vector lifting
//                                       (runs last so even CFF dispatch gets lifted)
//  7. ConstantEncryption   (module)   — k-share XOR ensemble + Feistel nonlinear layer
//                                       (runs after Sub/MBA so it also encrypts their
//                                        injected constants; Feistel adds 26 IR instrs
//                                        per constant on top of the XOR share chain)
//  8. IndirectBranch       (function) — Knuth-hash encrypted branch targets
//                                       (sees the Flatten/CSM switch tables)
//  9. FunctionWrapper      (module)   — polymorphic proxy generation
//                                       (wraps fully-obfuscated functions)
// 10. FeatureElimination   (module)   — strip debug/ident/names, scramble privates
//                                       MUST run last so TOML policy name-matching
//                                       works correctly in all preceding passes.
// 11. Cleanup: remove ensia_* marker declarations
//
// ── Ordering rationale ────────────────────────────────────────────────────────
//  • Sub → MBA: MBA sees both original and Substitution-generated ops.
//  • MBA → CSM: the chaos switch dispatch contains MBA-obfuscated values.
//  • CSM → Flatten: CSM stamps processed functions; Flattening skips them.
//    Running Flatten AFTER CSM on the same function would feed Flatten's
//    LowerSwitchPass a switch with O(N) cases → O(N²) binary-compare tree.
//    Inversion ensures every function gets exactly ONE CFF layer, the
//    strongest available: CSM when eligible, classic Flatten as fallback.
//  • Vec last (per-fn): SIMD-lifts even the CFF/CSM dispatch arithmetic.
//  • ConstEnc after Vec: encrypts constants introduced by all previous passes.
//  • IndirBranch after ConstEnc: Knuth-hash targets include ConstEnc-injected GVs.

#include "include/Obfuscation.h"
#include "include/ChaosStateMachine.h"
#include "include/MBAObfuscation.h"
#include "include/ObfConfig.h"
#include "include/VectorObfuscation.h"
#include "include/Utils.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/Passes/PassBuilder.h"
#if LLVM_VERSION_MAJOR >= 18
#include "llvm/Plugins/PassPlugin.h"
#endif
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"
#include <cstdlib>

using namespace llvm;

// ── Master enable / disable ───────────────────────────────────────────────────

static cl::opt<bool>
    EnableIRObfusaction("ensia", cl::init(false), cl::NotHidden,
                        cl::desc("Enable IR Code Obfuscation."),
                        cl::ZeroOrMore);
static cl::opt<uint64_t> AesSeed("aesSeed", cl::init(0x1337),
                                 cl::desc("PRNG seed for the obfuscator"));

// ── Original pass flags ───────────────────────────────────────────────────────

static cl::opt<bool> EnableAntiClassDump("enable-acdobf", cl::init(false),
                                         cl::NotHidden, cl::desc("Enable AntiClassDump."));
static cl::opt<bool> EnableAntiHooking("enable-antihook", cl::init(false),
                                       cl::NotHidden, cl::desc("Enable AntiHooking."));
static cl::opt<bool> EnableAntiDebugging("enable-adb", cl::init(false),
                                         cl::NotHidden, cl::desc("Enable AntiDebugging."));
static cl::opt<bool> EnableBogusControlFlow("enable-bcfobf", cl::init(false),
                                            cl::NotHidden, cl::desc("Enable BogusControlFlow."));
static cl::opt<bool> EnableFlattening("enable-cffobf", cl::init(false),
                                      cl::NotHidden, cl::desc("Enable CFF Flattening."));
static cl::opt<bool> EnableBasicBlockSplit("enable-splitobf", cl::init(false),
                                           cl::NotHidden, cl::desc("Enable BasicBlockSplitting."));
static cl::opt<bool> EnableSubstitution("enable-subobf", cl::init(false),
                                        cl::NotHidden, cl::desc("Enable Instruction Substitution."));
static cl::opt<bool> EnableAllObfuscation("enable-allobf", cl::init(false),
                                          cl::NotHidden, cl::desc("Enable All Obfuscation."));
static cl::opt<bool> EnableFunctionCallObfuscate("enable-fco", cl::init(false),
                                                  cl::NotHidden, cl::desc("Enable FCO."));
static cl::opt<bool> EnableStringEncryption("enable-strcry", cl::init(false),
                                             cl::NotHidden, cl::desc("Enable String Encryption."));
static cl::opt<bool> EnableConstantEncryption("enable-constenc", cl::init(false),
                                               cl::NotHidden, cl::desc("Enable Constant Encryption."));
static cl::opt<bool> EnableIndirectBranching("enable-indibran", cl::init(false),
                                              cl::NotHidden, cl::desc("Enable Indirect Branching."));
static cl::opt<bool> EnableFunctionWrapper("enable-funcwra", cl::init(false),
                                            cl::NotHidden, cl::desc("Enable Function Wrapper."));

// ── OLLVM-Next new pass flags ─────────────────────────────────────────────────

static cl::opt<bool> EnableChaosStateMachine(
    "enable-csmobf", cl::init(false), cl::NotHidden,
    cl::desc("Enable ChaosStateMachine (logistic-map CFF)."));
static cl::opt<bool> EnableMBAObfuscation(
    "enable-mbaobf", cl::init(false), cl::NotHidden,
    cl::desc("Enable Mixed Boolean-Arithmetic Obfuscation."));
static cl::opt<bool> EnableVectorObfuscation(
    "enable-vobf", cl::init(false), cl::NotHidden,
    cl::desc("Enable SIMD Vector-Space Obfuscation."));

// ── Extreme-mode flag ─────────────────────────────────────────────────────────
//
// -enable-maxobf: "maximum obfuscation" — enables every pass simultaneously
// and sets global ObfuscationMaxMode=true.  Each pass checks this flag and
// self-tunes to maximum intensity:
//
//   Pass              Max-mode effect
//   ────────────────  ─────────────────────────────────────────────────────────
//   BCF               prob=100, loop=3, entropy_chain=100%, junk-asm=true
//   Split             num=8 splits per BB, stack-confusion always on
//   Sub               3 loops, sub_prob=100 (all eligible ops substituted)
//   MBA               mba_heuristic=true (noise injection enabled)
//   Vec               vec_prob=80, vec_width=256, vec_shuffle=true, vec_icmp=true
//   CSM               nested dispatch, warmup=256
//   ConstEnc          constenc_times=3, constenc_kshare=4, constenc_feistel=true
//   FW                funcwra_prob=100, funcwra_times=3
//   StringEnc         strcry_prob=100 (all bytes encrypted)
//   Anti-*            All three anti-analysis passes active
//
// Intended for: stress-testing toolchains, red-team deliverables, benchmarking.
// NOT for production: compile time and binary size will be substantially higher.
//
// ── Medium-intensity preset (-enable-medobf) ─────────────────────────────────
//
// -enable-medobf: enables a practical subset for production builds where
// compile-time overhead and binary-size growth must be bounded:
//   Sub (sub_loop=1, sub_prob=70) + MBA + ConstEnc (k-share=3, no Feistel)
//   + StringEnc (strcry_prob=100) + Flatten
//   Anti-analysis passes are NOT enabled (they require controlled environments).
//   Vec and CSM are disabled to keep binary size reasonable.
static cl::opt<bool> EnableMaxObfuscation(
    "enable-maxobf", cl::init(false), cl::NotHidden,
    cl::desc("[OLLVM-Next] Maximum-intensity obfuscation: all passes at extreme "
             "settings. For stress-testing and red-team use."));
static cl::opt<bool> EnableObfVerbose(
    "obf-verbose", cl::init(false), cl::NotHidden,
    cl::desc("[OLLVM-Next] Print a 'Running X On Y' line for every pass/function. "
             "Disabled by default: on large modules the output can exceed the "
             "64 KB stderr pipe buffer, causing WriteFile to block (0% CPU)."));
static cl::opt<bool> EnableObfTrace(
    "obf-trace", cl::init(false), cl::NotHidden,
    cl::desc("[OLLVM-Next] Emit one step-marker before/after each major pass in the "
             "scheduler (StringEncryption, per-function loop, ConstEnc, etc.). "
             "Also prints function name + sub-pass tag for each per-function step. "
             "Max output: ~15 lines + ~7 per function. Use to diagnose 0% CPU hangs."));
static cl::opt<bool> EnableMedObfuscation(
    "enable-medobf", cl::init(false), cl::NotHidden,
    cl::desc("[OLLVM-Next] Medium-intensity obfuscation: Sub+MBA+ConstEnc+StrEnc+"
             "Flatten. Good for production builds."));

// ── Structured preset and TOML config ─────────────────────────────────────────

static cl::opt<std::string> ObfPreset(
    "ensia-preset", cl::init(""), cl::NotHidden,
    cl::desc("[OLLVM-Next] Obfuscation preset: low | mid | high  "
             "(max remains -enable-maxobf for backward compat). "
             "Can be combined with -ensia-config for parameter fine-tuning."));

static cl::opt<std::string> ObfConfigFile(
    "ensia-config", cl::init(""), cl::NotHidden,
    cl::desc("[OLLVM-Next] Path to TOML configuration file. "
             "Searched in order: this flag > ENSIA_CONFIG env var > ./ensia.toml"));

// ── Environment variable loader ───────────────────────────────────────────────

static void LoadEnv() {
  if (getenv("SPLITOBF"))   EnableBasicBlockSplit   = true;
  if (getenv("SUBOBF"))     EnableSubstitution       = true;
  if (getenv("ALLOBF"))     EnableAllObfuscation     = true;
  if (getenv("FCO"))        EnableFunctionCallObfuscate = true;
  if (getenv("STRCRY"))     EnableStringEncryption   = true;
  if (getenv("INDIBRAN"))   EnableIndirectBranching  = true;
  if (getenv("FUNCWRA"))    EnableFunctionWrapper    = true;
  if (getenv("BCFOBF"))     EnableBogusControlFlow   = true;
  if (getenv("ACDOBF"))     EnableAntiClassDump      = true;
  if (getenv("CFFOBF"))     EnableFlattening         = true;
  if (getenv("CONSTENC"))   EnableConstantEncryption = true;
  if (getenv("ANTIHOOK"))   EnableAntiHooking        = true;
  if (getenv("ADB"))        EnableAntiDebugging      = true;
  // OLLVM-Next new passes
  if (getenv("CSMOBF"))     EnableChaosStateMachine  = true;
  if (getenv("MBAOBF"))     EnableMBAObfuscation     = true;
  if (getenv("VOBF"))       EnableVectorObfuscation  = true;
  if (getenv("MAXOBF"))     EnableMaxObfuscation     = true;
  if (getenv("MEDOBF"))     EnableMedObfuscation     = true;
  if (getenv("VERBOSE"))    EnableObfVerbose         = true;
  if (getenv("TRACE"))      EnableObfTrace           = true;
}

// ── Config loading ────────────────────────────────────────────────────────────
//
// Final priority (highest → lowest) for per-pass parameters:
//   source annotation  >  TOML [passes.*]  >  -ensia-preset  >  [global] preset  >  cl::opt default
//
// Config file is searched:  -ensia-config flag  >  ENSIA_CONFIG env  >  ./ensia.toml
static void loadObfConfig() {
  std::string path = ObfConfigFile;
  bool explicitConfig = !path.empty(); // -ensia-config was given explicitly
  if (path.empty()) {
    if (const char *env = getenv("ENSIA_CONFIG")) {
      path = env;
      explicitConfig = true; // env var also counts as explicit intent
    }
  }
  if (path.empty()) {
    if (llvm::sys::fs::exists("ensia.toml"))
      path = "ensia.toml";
    // auto-discovered ensia.toml does NOT auto-enable — it's just a parameter
    // file, not an obfuscation request.
  }

  // Step 1: load file (this applies the file's [global] preset internally,
  // then overlays [passes.*] sections on top of it).
  if (!path.empty()) {
    GObfConfig = ObfGlobalConfig::loadFromFile(path);
    // An explicit config file signals intent to obfuscate — auto-enable the
    // master gate so the user doesn't also need to pass -mllvm -ensia.
    if (explicitConfig)
      EnableIRObfusaction = true;
  } else {
    GObfConfig = ObfGlobalConfig::defaults();
  }

  // Step 2: if -ensia-preset is given on the command line, it overrides
  // the file's [global] preset while preserving explicit [passes.*] settings.
  // We rebuild as: preset_base merged with the file's explicit [passes.*] overrides.
  if (!ObfPreset.empty()) {
    std::string cliPreset = (std::string)ObfPreset;
    GObfConfig.preset = cliPreset;
    // Extract the file's explicit [passes.*] overrides by comparing to the
    // file-preset's base (approximation: just keep GObfConfig.passes as
    // user-supplied delta and re-merge onto the CLI preset base).
    ObfPassConfig cli_preset_base = ObfGlobalConfig::presetConfig(cliPreset);
    ObfGlobalConfig::merge(cli_preset_base, GObfConfig.passes); // file settings win
    GObfConfig.passes = cli_preset_base;
  }
}

// ── Apply TOML policy metadata injection ──────────────────────────────────────
// For each function, resolve its effective config (global + matching policies)
// and inject enable/disable annotations as function metadata so the existing
// toObfuscate() mechanism can honour TOML-defined per-function enables.
// Parameter overrides are handled at runtime inside each pass via GObfConfig.resolve().
static void applyTomlPolicies(Module &M) {
  if (GObfConfig.policies.empty())
    return;

  StringRef modName = M.getSourceFileName();

  for (Function &F : M) {
    if (F.isDeclaration())
      continue;

    StringRef fnName = F.getName();
    ObfPassConfig eff = GObfConfig.resolve(modName, fnName);

    // Helper: write enable/disable annotation only when the policy differs from
    // the cl::opt global flag (to avoid redundant metadata).
    auto injectEnable = [&](std::optional<bool> enabled,
                            const char *attr, const char *noattr) {
      if (!enabled.has_value())
        return;
      if (*enabled)
        writeAnnotationMetadata(&F, attr);
      else
        writeAnnotationMetadata(&F, noattr);
    };

    injectEnable(eff.bcf.enabled,         "bcf",      "nobcf");
    injectEnable(eff.sub.enabled,         "sub",      "nosub");
    injectEnable(eff.mba.enabled,         "mba",      "nomb");
    injectEnable(eff.split.enabled,       "split",    "nosplit");
    injectEnable(eff.str_enc.enabled,     "strcry",   "nostrcry");
    injectEnable(eff.const_enc.enabled,   "constenc", "noconstenc");
    injectEnable(eff.vec.enabled,         "vobf",     "novobf");
    injectEnable(eff.csm.enabled,         "csm",      "nocsm");
    injectEnable(eff.flatten.enabled,     "fla",      "nofla");
    injectEnable(eff.indir_branch.enabled,"indibran", "noindibran");
    injectEnable(eff.func_wrap.enabled,   "fw",       "nofw");
    injectEnable(eff.fco.enabled,         "fco",      "nofco");
    injectEnable(eff.anti_hook.enabled,   "antihook", "noantihook");
    injectEnable(eff.anti_dbg.enabled,    "adb",      "noadb");
  }
}

// ── Feature Elimination ───────────────────────────────────────────────────────
// Strips diagnostic artifacts that survive linking and help reverse engineers
// orient themselves in the binary.  Runs after all obfuscation passes so that
// renamed/injected symbols are also cleaned up.
static void runFeatureElimination(Module &M) {
  // Remove all DWARF/debug metadata (source locations, variable names, etc.)
  StripDebugInfo(M);

  // Anonymise the translation-unit path stored in the IR
  M.setSourceFileName("a");

  // Drop llvm.ident — reveals the compiler version and command line
  if (NamedMDNode *Ident = M.getNamedMetadata("llvm.ident"))
    Ident->eraseFromParent();

  // Prune informational module flags (SDK version, min-OS, branch-protection
  // notes, PGO summary).  Keep correctness-affecting flags (PIC level, etc.).
  if (NamedMDNode *Flags = M.getNamedMetadata("llvm.module.flags")) {
    SmallVector<MDNode *, 8> toKeep;
    for (MDNode *Op : Flags->operands()) {
      if (Op->getNumOperands() < 2) { toKeep.push_back(Op); continue; }
      if (auto *S = dyn_cast<MDString>(Op->getOperand(1))) {
        StringRef n = S->getString();
        if (n.contains("SDK Version") || n.contains("min_os") ||
            n.contains("PGO") || n.contains("branch_protection_spec") ||
            n.contains("Objective-C Class Properties") ||
            n.contains("Swift ABI") || n.contains("Swift Version"))
          continue; // discard
      }
      toKeep.push_back(Op);
    }
    Flags->clearOperands();
    for (MDNode *N : toKeep)
      Flags->addOperand(N);
  }

  // Rename all private/internal-linkage functions to unparseable hex strings.
  // Even after symbol-table stripping, decompilers reconstruct names from
  // DWARF or heuristics — replacing them before strip removes the fallback.
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    if (!F.hasPrivateLinkage() && !F.hasInternalLinkage())
      continue;
    // Don't rename our own sentinel/marker functions
    StringRef nm = F.getName();
#if LLVM_VERSION_MAJOR >= 18
    if (nm.starts_with("ensia_") || nm.starts_with("EnsiaBCF") ||
        nm.starts_with("ADB") || nm.starts_with("InitADB"))
#else
    if (nm.startswith("ensia_") || nm.startswith("EnsiaBCF") ||
        nm.startswith("ADB") || nm.startswith("InitADB"))
#endif
      continue;
    std::string newName;
    raw_string_ostream OS(newName);
    OS << format("_f%08x%08x", cryptoutils->get_uint32_t(),
                 cryptoutils->get_uint32_t());
    F.setName(OS.str());
  }

  // Scramble private GlobalVariable names that survived previous passes
  for (GlobalVariable &GV : M.globals()) {
    if (!GV.hasPrivateLinkage() && !GV.hasInternalLinkage())
      continue;
    StringRef nm = GV.getName();
    // Preserve BCF sentinel and our injected GVs — they're already hex-named
#if LLVM_VERSION_MAJOR >= 18
    if (nm.starts_with("bcf.") || nm.starts_with("LHSGV") ||
        nm.starts_with("RHSGV") || nm.starts_with("g"))
#else
    if (nm.startswith("bcf.") || nm.startswith("LHSGV") ||
        nm.startswith("RHSGV") || nm.startswith("g"))
#endif
      continue;
    std::string newName;
    raw_string_ostream OS(newName);
    OS << format("_v%08x%08x", cryptoutils->get_uint32_t(),
                 cryptoutils->get_uint32_t());
    GV.setName(OS.str());
  }
}

namespace llvm {
struct Obfuscation : public ModulePass {
  static char ID;
  Obfuscation() : ModulePass(ID) {
    initializeObfuscationPass(*PassRegistry::getPassRegistry());
  }
  StringRef getPassName() const override {
    return "EnsiaObfuscationScheduler";
  }

  bool runOnModule(Module &M) override {
    if (!EnableIRObfusaction)
      return false;

    // Propagate verbose/trace flags — must happen before any pass runs.
    ObfVerbose = EnableObfVerbose;
    ObfTrace   = EnableObfTrace;

    // ── Maximum-intensity mode: all passes + extreme tuning ──────────────
    if (EnableMaxObfuscation) {
      ObfuscationMaxMode = true;
      EnableAntiClassDump         = true;
      EnableAntiHooking           = true;
      EnableAntiDebugging         = true;
      EnableBogusControlFlow      = true;
      EnableFlattening            = true;
      EnableBasicBlockSplit       = true;
      EnableSubstitution          = true;
      EnableFunctionCallObfuscate = true;
      EnableStringEncryption      = true;
      EnableConstantEncryption    = true;
      EnableIndirectBranching     = true;
      EnableFunctionWrapper       = true;
      EnableChaosStateMachine     = true;
      EnableMBAObfuscation        = true;
      EnableVectorObfuscation     = true;
      errs() << "[OLLVM-Next] *** MAXIMUM OBFUSCATION MODE ACTIVE ***\n"
             << "    BCF:     prob=100, loop=3, entropy_chain=100%\n"
             << "    CSM:     nested_dispatch=true (2-level CFG explosion)\n"
             << "    MBA:     mba_heuristic=true\n"
             << "    Vec:     vec_prob=80, vec_width=256, shuffle+icmp\n"
             << "    ConstEnc:constenc_times=3, kshare=4, feistel=true\n";
    }

    // ── Medium-intensity mode: production-safe subset ─────────────────────
    if (EnableMedObfuscation && !EnableMaxObfuscation) {
      EnableSubstitution          = true;
      EnableMBAObfuscation        = true;
      EnableConstantEncryption    = true;
      EnableStringEncryption      = true;
      EnableFlattening            = true;
      // Medium: kshare=3 (no Feistel), sub_prob=70, constenc_times=2
      // These are set via the per-pass option mechanism after the pass runs
      // (or via -constenc_kshare=3 etc. on the command line).
      errs() << "[OLLVM-Next] Medium obfuscation mode: Sub+MBA+ConstEnc+"
                "StrEnc+Flatten\n";
    }

    // ── Structured preset / TOML config ───────────────────────────────────
    // Apply verbose/trace from config (cl::opt already took effect above, but
    // config file can also set them).
    if (GObfConfig.verbose) ObfVerbose = true;
    if (GObfConfig.trace)   ObfTrace   = true;

    // Apply preset/config enables (only if not already forced by max/med mode).
    if (!EnableMaxObfuscation && !EnableMedObfuscation) {
      auto &pc = GObfConfig.passes;
      if (pc.bcf.enabled.value_or(false))           EnableBogusControlFlow      = true;
      if (pc.sub.enabled.value_or(false))           EnableSubstitution          = true;
      if (pc.mba.enabled.value_or(false))           EnableMBAObfuscation        = true;
      if (pc.split.enabled.value_or(false))         EnableBasicBlockSplit       = true;
      if (pc.str_enc.enabled.value_or(false))       EnableStringEncryption      = true;
      if (pc.const_enc.enabled.value_or(false))     EnableConstantEncryption    = true;
      if (pc.vec.enabled.value_or(false))           EnableVectorObfuscation     = true;
      if (pc.csm.enabled.value_or(false))           EnableChaosStateMachine     = true;
      if (pc.flatten.enabled.value_or(false))       EnableFlattening            = true;
      if (pc.indir_branch.enabled.value_or(false))  EnableIndirectBranching     = true;
      if (pc.func_wrap.enabled.value_or(false))     EnableFunctionWrapper       = true;
      if (pc.fco.enabled.value_or(false))           EnableFunctionCallObfuscate = true;
      if (pc.anti_hook.enabled.value_or(false))     EnableAntiHooking           = true;
      if (pc.anti_dbg.enabled.value_or(false))      EnableAntiDebugging         = true;
      if (pc.anti_class_dump.enabled.value_or(false)) EnableAntiClassDump       = true;

      if (!GObfConfig.preset.empty())
        errs() << "[OLLVM-Next] Preset '" << GObfConfig.preset << "' active\n";
    }

    TimerGroup *tg = new TimerGroup("Obfuscation", "Obfuscation");
    Timer *timer = new Timer("Total", "Total", *tg);
    timer->startTimer();

    errs() << "Running OLLVM-Next on " << M.getSourceFileName()
           << "  [LLVM " << LLVM_VERSION_MAJOR << "." << LLVM_VERSION_MINOR
           << ", commit " << GIT_COMMIT_HASH << "]\n";

    annotation2Metadata(M);
    applyTomlPolicies(M);   // inject per-function enables from TOML policies

    // ── 1. AntiHooking ─────────────────────────────────────────────────────
    {
      ModulePass *MP = createAntiHookPass(EnableAntiHooking);
      MP->doInitialization(M);
      MP->runOnModule(M);
      delete MP;
    }

    // ── 2. AntiClassDump ───────────────────────────────────────────────────
    if (EnableAllObfuscation || EnableAntiClassDump) {
      ModulePass *P = createAntiClassDumpPass();
      P->doInitialization(M);
      P->runOnModule(M);
      delete P;
    }

    // ── 3. FunctionCallObfuscate ───────────────────────────────────────────
    {
      FunctionPass *FP = createFunctionCallObfuscatePass(
          EnableAllObfuscation || EnableFunctionCallObfuscate);
      for (Function &F : M)
        if (!F.isDeclaration())
          FP->runOnFunction(F);
      delete FP;
    }

    // ── 4. AntiDebugging ───────────────────────────────────────────────────
    {
      ModulePass *MP = createAntiDebuggingPass(EnableAntiDebugging);
      MP->runOnModule(M);
      delete MP;
    }

    // ── 5. StringEncryption ────────────────────────────────────────────────
    if (ObfTrace) errs() << "[OLLVM-Next][5] StringEncryption: start\n";
    {
      ModulePass *MP = createStringEncryptionPass(
          EnableAllObfuscation || EnableStringEncryption);
      MP->runOnModule(M);
      delete MP;
    }
    if (ObfTrace) errs() << "[OLLVM-Next][5] StringEncryption: done\n";

    // ── 6. Per-function passes ─────────────────────────────────────────────
    if (ObfTrace) errs() << "[OLLVM-Next][6] per-function loop: start\n";
    for (Function &F : M) {
      if (F.isDeclaration())
        continue;

      if (ObfTrace) errs() << "[OLLVM-Next][6] F=" << F.getName() << "\n";

      // 6a. SplitBasicBlocks — creates finer-grained dispatch targets for CFF
      if (ObfTrace) errs() << "[OLLVM-Next][6a] split\n";
      {
        FunctionPass *P = createSplitBasicBlockPass(
            EnableAllObfuscation || EnableBasicBlockSplit);
        P->runOnFunction(F);
        delete P;
      }
      // 6b. BogusControlFlow — inserts opaque hardware-predicate edges
      if (ObfTrace) errs() << "[OLLVM-Next][6b] bcf\n";
      {
        FunctionPass *P = createBogusControlFlowPass(
            EnableAllObfuscation || EnableBogusControlFlow);
        P->runOnFunction(F);
        delete P;
      }
      // 6c. Instruction Substitution — runs before Flatten so MBA expressions
      //     are embedded in blocks that Flatten must then dispatch through
      if (ObfTrace) errs() << "[OLLVM-Next][6c] sub\n";
      {
        FunctionPass *P = createSubstitutionPass(
            EnableAllObfuscation || EnableSubstitution);
        P->runOnFunction(F);
        delete P;
      }
      // 6d. MBAObfuscation — multi-term MBA after Substitution so both layers
      //     compound; before Flatten so the dispatch table contains MBA exprs
      if (ObfTrace) errs() << "[OLLVM-Next][6d] mba\n";
      {
        FunctionPass *P = createMBAObfuscationPass(
            EnableAllObfuscation || EnableMBAObfuscation);
        P->runOnFunction(F);
        delete P;
      }
      // 6e. ChaosStateMachine — logistic-map CFF on the clean original function.
      //     This is the strongest CFF variant; it stamps processed functions
      //     with "ensia.csm.done" so Flattening (below) skips them.
      //     Running CSM first avoids the cascade: if Flattening ran first, CSM's
      //     own LowerSwitchPass would explode the Flattening switch into a
      //     binary-compare tree (O(N²) BB growth) before re-flattening.
      if (ObfTrace) errs() << "[OLLVM-Next][6e] csm\n";
      {
        FunctionPass *P = createChaosStateMachinePass(
            EnableAllObfuscation || EnableChaosStateMachine);
        P->runOnFunction(F);
        delete P;
      }
      // 6f. Classic Flattening — fallback CFF for functions CSM couldn't handle
      //     (EH pads, coroutines, ≤1 block, or exceeding csm_maxblocks).
      //     Checks "ensia.csm.done" attribute and skips if CSM already ran.
      if (ObfTrace) errs() << "[OLLVM-Next][6f] flatten\n";
      {
        FunctionPass *P = createFlatteningPass(
            EnableAllObfuscation || EnableFlattening);
        P->runOnFunction(F);
        delete P;
      }
      // 6g. VectorObfuscation — SIMD scalar→vector lifting as final per-fn step
      if (ObfTrace) errs() << "[OLLVM-Next][6g] vec\n";
      {
        FunctionPass *P = createVectorObfuscationPass(
            EnableAllObfuscation || EnableVectorObfuscation);
        P->runOnFunction(F);
        delete P;
      }
      if (ObfTrace) errs() << "[OLLVM-Next][6] F=" << F.getName() << " done\n";
    }
    if (ObfTrace) errs() << "[OLLVM-Next][6] per-function loop: done\n";

    // ── 7. ConstantEncryption ─────────────────────────────────────────────
    // Runs after all per-function passes so it also encrypts constants that
    // were injected by Sub, MBA, BCF, and Vec.  Feistel tier adds a nonlinear
    // layer (26 IR instructions per constant) on top of the k-share XOR chain.
    // Must run BEFORE FeatureElimination (step 9) so TOML policy module/function
    // name regexes can still match the original source file and function names.
    if (ObfTrace) errs() << "[OLLVM-Next][7] ConstantEncryption\n";
    {
      ModulePass *MP = createConstantEncryptionPass(
          EnableAllObfuscation || EnableConstantEncryption);
      MP->runOnModule(M);
      delete MP;
    }
    if (ObfTrace) errs() << "[OLLVM-Next][7] ConstantEncryption: done\n";

    // ── 8. IndirectBranch (Knuth-hash encrypted targets) ─────────────────
    // Also before FeatureElimination for the same naming reason.
    if (ObfTrace) errs() << "[OLLVM-Next][8] IndirectBranch\n";
    {
      FunctionPass *P = createIndirectBranchPass(
          EnableAllObfuscation || EnableIndirectBranching);
      for (Function &F : M)
        if (!F.isDeclaration())
          P->runOnFunction(F);
      delete P;
    }
    if (ObfTrace) errs() << "[OLLVM-Next][8] IndirectBranch: done\n";

    // ── 9. FunctionWrapper (polymorphic proxies) ──────────────────────────
    // Also before FeatureElimination for the same naming reason.
    if (ObfTrace) errs() << "[OLLVM-Next][9] FunctionWrapper\n";
    {
      ModulePass *MP = createFunctionWrapperPass(
          EnableAllObfuscation || EnableFunctionWrapper);
      MP->runOnModule(M);
      delete MP;
    }
    if (ObfTrace) errs() << "[OLLVM-Next][9] FunctionWrapper: done\n";

    // ── 10. Feature Elimination ────────────────────────────────────────────
    // Runs LAST — after all obfuscation passes have finished — so that:
    //   • TOML policy module/function regexes can match original names in all
    //     passes above (ConstantEncryption, IndirectBranch, FunctionWrapper).
    //   • Renamed private functions (_f<hex>) and the "a" source filename don't
    //     interfere with policy resolution in any pass.
    if (ObfTrace) errs() << "[OLLVM-Next][10] FeatureElimination\n";
    runFeatureElimination(M);
    if (ObfTrace) errs() << "[OLLVM-Next][10] FeatureElimination: done\n";

    // ── 11. Cleanup marker declarations ───────────────────────────────────
    SmallVector<Function *, 8> toDelete;
    for (Function &F : M) {
      if (!F.isDeclaration() || !F.hasName())
        continue;
#if LLVM_VERSION_MAJOR >= 18
      if (!F.getName().starts_with("ensia_"))
#else
      if (!F.getName().startswith("ensia_"))
#endif
        continue;
      for (User *U : F.users())
        if (Instruction *Inst = dyn_cast<Instruction>(U))
          Inst->eraseFromParent();
      toDelete.push_back(&F);
    }
    for (Function *F : toDelete)
      F->eraseFromParent();

    timer->stopTimer();
    errs() << "OLLVM-Next done.  Wall time: "
           << format("%.5f", timer->getTotalTime().getWallTime()) << "s\n";
    tg->clearAll();
    return true;
  }
}; // struct Obfuscation

ModulePass *createObfuscationLegacyPass() {
  LoadEnv();
  loadObfConfig();
  if (!EnableIRObfusaction)
    return new Obfuscation(); // gate off — runOnModule will return false immediately

  // Config file may specify a seed; cl::opt -aesSeed overrides it.
  uint64_t seed = (AesSeed != 0x1337) ? (uint64_t)AesSeed
                : (GObfConfig.seed != 0 ? GObfConfig.seed : 0x1337);
  if (seed != 0x1337)
    cryptoutils->prng_seed(seed);
  else
    cryptoutils->prng_seed();
  errs() << "Initializing OLLVM-Next with commit:" << GIT_COMMIT_HASH << "\n";
  return new Obfuscation();
}

PreservedAnalyses ObfuscationPass::run(Module &M, ModuleAnalysisManager &) {
  if (createObfuscationLegacyPass()->runOnModule(M))
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();
}

} // namespace llvm

char llvm::Obfuscation::ID = 0;
INITIALIZE_PASS_BEGIN(Obfuscation, "obfus", "Enable OLLVM-Next Obfuscation",
                      false, false)
INITIALIZE_PASS_DEPENDENCY(AntiClassDump)
INITIALIZE_PASS_DEPENDENCY(BogusControlFlow)
INITIALIZE_PASS_DEPENDENCY(ConstantEncryption)
INITIALIZE_PASS_DEPENDENCY(Flattening)
INITIALIZE_PASS_DEPENDENCY(FunctionCallObfuscate)
INITIALIZE_PASS_DEPENDENCY(IndirectBranch)
INITIALIZE_PASS_DEPENDENCY(MBAObfuscation)
INITIALIZE_PASS_DEPENDENCY(SplitBasicBlock)
INITIALIZE_PASS_DEPENDENCY(StringEncryption)
INITIALIZE_PASS_DEPENDENCY(Substitution)
INITIALIZE_PASS_DEPENDENCY(VectorObfuscation)
INITIALIZE_PASS_END(Obfuscation, "obfus", "Enable OLLVM-Next Obfuscation",
                    false, false)

#if LLVM_VERSION_MAJOR >= 18

namespace llvm {

PassPluginLibraryInfo getEnsiaPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION, "OLLVM-Next", LLVM_VERSION_STRING,
      [](PassBuilder &PB) {
        // ── Auto-inject via optimizer-last EP ─────────────────────────────────
        // Fires during pipeline construction (including O0) so -Xclang -load is
        // enough — the user doesn't need to also spell out -passes=ensia.
        // LoadEnv()/loadObfConfig() are called here so the TOML file and env
        // vars are honoured before the pass checks EnableIRObfusaction.
        PB.registerOptimizerLastEPCallback(
            [](ModulePassManager &MPM, OptimizationLevel, ThinOrFullLTOPhase) {
              static bool s_ep_added = false;
              if (s_ep_added) return;
              LoadEnv();
              loadObfConfig();
              if (!EnableIRObfusaction) return;
              s_ep_added = true;
              MPM.addPass(ObfuscationPass());
            });

        // ── Explicit -passes=ensia[<inner-opts>] ─────────────────────────────
        // Also supports the classic explicit form so both invocation styles work.
        PB.registerPipelineParsingCallback(
            [](StringRef Name, ModulePassManager &MPM,
               ArrayRef<PassBuilder::PipelineElement> InnerPipeline) {
              if (Name != EnableIRObfusaction.ArgStr)
                return false;
              static bool s_pp_added = false;
              EnableIRObfusaction = true;
              for (const auto &E : InnerPipeline) {
                auto n = E.Name;
                if (n == EnableAntiClassDump.ArgStr)          EnableAntiClassDump = true;
                else if (n == EnableAntiHooking.ArgStr)       EnableAntiHooking = true;
                else if (n == EnableAntiDebugging.ArgStr)     EnableAntiDebugging = true;
                else if (n == EnableBogusControlFlow.ArgStr)  EnableBogusControlFlow = true;
                else if (n == EnableFlattening.ArgStr)        EnableFlattening = true;
                else if (n == EnableBasicBlockSplit.ArgStr)   EnableBasicBlockSplit = true;
                else if (n == EnableSubstitution.ArgStr)      EnableSubstitution = true;
                else if (n == EnableAllObfuscation.ArgStr)    EnableAllObfuscation = true;
                else if (n == EnableFunctionCallObfuscate.ArgStr) EnableFunctionCallObfuscate = true;
                else if (n == EnableStringEncryption.ArgStr)  EnableStringEncryption = true;
                else if (n == EnableConstantEncryption.ArgStr)EnableConstantEncryption = true;
                else if (n == EnableIndirectBranching.ArgStr) EnableIndirectBranching = true;
                else if (n == EnableFunctionWrapper.ArgStr)   EnableFunctionWrapper = true;
                // OLLVM-Next new passes and intensity presets
                else if (n == EnableChaosStateMachine.ArgStr) EnableChaosStateMachine = true;
                else if (n == EnableMBAObfuscation.ArgStr)    EnableMBAObfuscation = true;
                else if (n == EnableVectorObfuscation.ArgStr) EnableVectorObfuscation = true;
                else if (n == EnableMaxObfuscation.ArgStr)    EnableMaxObfuscation = true;
                else if (n == EnableMedObfuscation.ArgStr)    EnableMedObfuscation = true;
              }
              if (!s_pp_added) {
                s_pp_added = true;
                MPM.addPass(ObfuscationPass());
              }
              return true;
            });
      }};
}

} // namespace llvm

// llvmGetPassPluginInfo must be a top-level C symbol (not in any namespace).
// On Windows, __declspec(dllexport) is required so the linker puts it in the
// DLL export table — LLVM_ATTRIBUTE_WEAK is a no-op on MSVC/clang-cl.
#ifdef _WIN32
extern "C" __declspec(dllexport)
#else
extern "C" LLVM_ATTRIBUTE_WEAK
#endif
::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return llvm::getEnsiaPluginInfo();
}

#endif // LLVM_VERSION_MAJOR >= 18
