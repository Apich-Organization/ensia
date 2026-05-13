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

#include "include/AntiDebugging.h"
#if LLVM_VERSION_MAJOR >= 17
#include "llvm/ADT/SmallString.h"
#include "llvm/TargetParser/Triple.h"
#else
#include "llvm/ADT/Triple.h"
#endif
#include "llvm/ADT/SmallPtrSet.h"
#include "include/CryptoUtils.h"
#include "include/Utils.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"
#include <fstream>

using namespace llvm;

static cl::opt<std::string> PreCompiledIRPath(
    "adbextirpath",
    cl::desc("External Path Pointing To Pre-compiled AntiDebugging IR"),
    cl::value_desc("filename"), cl::init(""));
static cl::opt<uint32_t>
    ProbRate("adb_prob",
             cl::desc("Choose the probability [%] For Each Function To Be "
                      "Obfuscated By AntiDebugging"),
             cl::value_desc("Probability Rate"), cl::init(40), cl::Optional);

namespace llvm {
struct AntiDebugging : public ModulePass {
  static char ID;
  bool flag;
  bool initialized;
  Triple triple;
  AntiDebugging() : ModulePass(ID) {
    this->flag = true;
    this->initialized = false;
  }
  AntiDebugging(bool flag) : ModulePass(ID) {
    this->flag = flag;
    this->initialized = false;
  }
  StringRef getPassName() const override { return "AntiDebugging"; }
  bool initialize(Module &M) {
    if (PreCompiledIRPath == "") {
      SmallString<32> Path;
      if (sys::path::home_directory(Path)) { // Stolen from LineEditor.cpp
        sys::path::append(Path, "Ensia");
        Triple tri(M.getTargetTriple());
        sys::path::append(Path, "PrecompiledAntiDebugging-" +
                                    Triple::getArchTypeName(tri.getArch()) +
                                    "-" + Triple::getOSTypeName(tri.getOS()) +
                                    ".bc");
        PreCompiledIRPath = Path.c_str();
      }
    }
    std::ifstream f(PreCompiledIRPath);
    if (f.good()) {
      errs() << "Linking PreCompiled AntiDebugging IR From:"
             << PreCompiledIRPath << "\n";
      SMDiagnostic SMD;
      std::unique_ptr<Module> ADBM(
          parseIRFile(StringRef(PreCompiledIRPath), SMD, M.getContext()));
      Linker::linkModules(M, std::move(ADBM), Linker::Flags::LinkOnlyNeeded);
      Function *ADBCallBack = M.getFunction("ADBCallBack");
      if (ADBCallBack) {
        assert(!ADBCallBack->isDeclaration() &&
               "AntiDebuggingCallback is not concrete!");

        // Scramble names of every private/internal GlobalVariable referenced
        // from ADBCallBack so IR symbol names give no hint about the detection
        // logic.  Then inject decoy GVs with matching types to confuse pattern
        // matchers that try to locate the real variables by count or position.
        SmallPtrSet<GlobalVariable *, 8> seen;
        SmallVector<GlobalVariable *, 8> refGVs;
        for (BasicBlock &BB : *ADBCallBack) {
          for (Instruction &I : BB) {
            for (Use &U : I.operands()) {
              if (GlobalVariable *GV = dyn_cast<GlobalVariable>(U.get())) {
                if ((GV->hasPrivateLinkage() || GV->hasInternalLinkage()) &&
                    seen.insert(GV).second)
                  refGVs.push_back(GV);
              }
            }
          }
        }
        for (GlobalVariable *GV : refGVs) {
          // Replace name with random 16-char hex so no semantic hint survives
          std::string newName;
          raw_string_ostream OS(newName);
          OS << format("g%08x%08x", cryptoutils->get_uint32_t(),
                       cryptoutils->get_uint32_t());
          GV->setName(OS.str());
        }
        // Decoy GVs: one extra per real GV, same type, random initialiser
        for (GlobalVariable *GV : refGVs) {
          Constant *init = GV->hasInitializer()
                               ? GV->getInitializer()
                               : Constant::getNullValue(GV->getValueType());
          std::string decoyName;
          raw_string_ostream OS(decoyName);
          OS << format("g%08x%08x", cryptoutils->get_uint32_t(),
                       cryptoutils->get_uint32_t());
          (void)new GlobalVariable(M, GV->getValueType(), GV->isConstant(),
                                   GlobalValue::PrivateLinkage, init,
                                   OS.str());
        }

        ADBCallBack->setVisibility(
            GlobalValue::VisibilityTypes::HiddenVisibility);
        ADBCallBack->setLinkage(GlobalValue::LinkageTypes::PrivateLinkage);
        ADBCallBack->removeFnAttr(Attribute::AttrKind::NoInline);
        ADBCallBack->removeFnAttr(Attribute::AttrKind::OptimizeNone);
        ADBCallBack->addFnAttr(Attribute::AttrKind::AlwaysInline);
      }
      Function *ADBInit = M.getFunction("InitADB");
      if (ADBInit) {
        assert(!ADBInit->isDeclaration() &&
               "AntiDebuggingInitializer is not concrete!");
        ADBInit->setVisibility(GlobalValue::VisibilityTypes::HiddenVisibility);
        ADBInit->setLinkage(GlobalValue::LinkageTypes::PrivateLinkage);
        ADBInit->removeFnAttr(Attribute::AttrKind::NoInline);
        ADBInit->removeFnAttr(Attribute::AttrKind::OptimizeNone);
        ADBInit->addFnAttr(Attribute::AttrKind::AlwaysInline);
      }
    } else {
      errs() << "Failed To Link PreCompiled AntiDebugging IR From:"
             << PreCompiledIRPath << "\n";
    }
    this->initialized = true;
    this->triple = Triple(M.getTargetTriple());
    return true;
  }
  bool runOnModule(Module &M) override {
    if (ProbRate > 100) {
      errs() << "AntiDebugging application function percentage "
                "-adb_prob=x must be 0 < x <= 100";
      return false;
    }
    for (Function &F : M) {
      if (toObfuscate(flag, &F, "adb") && F.getName() != "ADBCallBack" &&
          F.getName() != "InitADB") {
        if (ObfVerbose) errs() << "Running AntiDebugging On " << F.getName() << "\n";
        if (!this->initialized)
          initialize(M);
        if (cryptoutils->get_range(100) <= ProbRate)
          runOnFunction(F);
      }
    }
    return true;
  }
  bool runOnFunction(Function &F) {
    auto shuffleBlocks = [](SmallVectorImpl<std::string> &v) {
      unsigned n = v.size();
      for (unsigned i = n - 1; i > 0; --i) {
        unsigned j = (unsigned)(rand() % (i + 1));
        std::swap(v[i], v[j]);
      }
    };

    BasicBlock *EntryBlock = &(F.getEntryBlock());
    Function *ADBCallBack = F.getParent()->getFunction("ADBCallBack");
    Function *ADBInit     = F.getParent()->getFunction("InitADB");
    if (ADBCallBack && ADBInit) {
      CallInst::Create(ADBInit, "",
                       cast<Instruction>(EntryBlock->getFirstInsertionPt()));
      return true;
    }

    errs() << "The ADBCallBack/ADBInit functions were not found; "
              "injecting inline-asm anti-debug for "
#if LLVM_VERSION_MAJOR >= 20
           << F.getParent()->getTargetTriple().getTriple() << "\n";
#else
           << F.getParent()->getTargetTriple() << "\n";
#endif

    if (!F.getReturnType()->isVoidTy())
      return false;

    Instruction *lastTerm = nullptr;
    for (BasicBlock &BB : F)
      lastTerm = BB.getTerminator();
    if (!lastTerm)
      return false;

    FunctionType *VoidFTy =
        FunctionType::get(Type::getVoidTy(EntryBlock->getContext()), false);

    // ── Darwin AArch64 ────────────────────────────────────────────────────
    if (triple.isOSDarwin() && triple.isAArch64()) {

      // VM fingerprint: CNTVCT_EL0 frozen-counter check.
      // Paused-timer VMs (Corellium, QEMU with clock=vm) return the same
      // value across successive reads separated by a NOP sled.  A frozen
      // counter (delta == 0) or absurdly large delta (slow full-system emulator)
      // triggers an immediate SYS_exit before any ptrace logic runs.
      {
        std::string vm;
        vm += "mrs x12, cntvct_el0\n\t";
        // 128 NOPs so even a 1GHz counter produces ≥1 tick delta
        for (int i = 0; i < 16; i++)
          vm += "nop\n\tnop\n\tnop\n\tnop\n\tnop\n\tnop\n\tnop\n\tnop\n\t";
        vm += "mrs x13, cntvct_el0\n\t";
        vm += "sub x14, x13, x12\n\t";   // delta
        // delta == 0 → frozen timer → hypervisor
        vm += "cbnz x14, 1f\n\t";
        vm += "mov x16, #1\n\t";          // SYS_exit (Darwin)
        vm += "svc #0x80\n\t";
        vm += "1:\n\t";
        // delta > 0xA000 (40960 units, ~1.7ms at 24MHz) → emulation too slow
        vm += "mov x15, #0xA000\n\t";
        vm += "cmp x14, x15\n\t";
        vm += "b.lo 2f\n\t";
        vm += "mov x16, #1\n\t";
        vm += "svc #0x80\n\t";
        vm += "2:\n\t";
        InlineAsm *vmIA = InlineAsm::get(VoidFTy, vm,
            "~{x12},~{x13},~{x14},~{x15},~{x16},~{dirflag},~{fpsr},~{flags}",
            true, false);
        CallInst::Create(vmIA->getFunctionType(), vmIA, ArrayRef<Value*>{}, "", lastTerm);
      }

      // ptrace(PT_DENY_ATTACH) with randomised instruction order
      std::string adbasm;
      uint32_t variant = cryptoutils->get_range(2);
      SmallVector<std::string, 6> parts;
      if (variant == 0) {
        parts.push_back("mov x0, #31\n\t");
        parts.push_back("mov x1, #0\n\t");
        parts.push_back("mov x2, #0\n\t");
        parts.push_back("mov x3, #0\n\t");
        parts.push_back("mov x16, #26\n\t");
      } else {
        parts.push_back("mov x0, #26\n\t");
        parts.push_back("mov x1, #31\n\t");
        parts.push_back("mov x2, #0\n\t");
        parts.push_back("mov x3, #0\n\t");
        parts.push_back("mov x16, #0\n\t");
      }
      shuffleBlocks(parts);
      for (auto &p : parts) adbasm += p;
      adbasm += "svc #" + std::to_string(cryptoutils->get_range(0x80, 0x200)) + "\n\t";
      adbasm += "mrs x9, cntvct_el0\n\t";
      uint32_t ji = cryptoutils->get_range(1, 0x100);
      adbasm += "add x9, x9, #" + std::to_string(ji) + "\n\t";
      adbasm += "sub x9, x9, #" + std::to_string(ji) + "\n\t";
      InlineAsm *IA = InlineAsm::get(VoidFTy, adbasm,
          "~{x0},~{x1},~{x2},~{x3},~{x9},~{x16},~{dirflag},~{fpsr},~{flags}",
          true, false);
      CallInst::Create(IA->getFunctionType(), IA, ArrayRef<Value*>{}, "", lastTerm);

    // ── Darwin x86_64 ─────────────────────────────────────────────────────
    } else if (triple.isOSDarwin() &&
               (triple.getArch() == Triple::x86_64 ||
                triple.getArch() == Triple::x86_64)) {

      // VM fingerprint: CPUID hypervisor bit + vendor string.
      // CPUID leaf 1 ECX[31] = hypervisor-present flag (always 0 on bare metal).
      // CPUID leaf 0x40000000 EBX = first 4 bytes of hypervisor vendor string;
      // we check against VMware, KVM, Hyper-V, VirtualBox, Xen, QEMU TCG.
      {
        std::string vm;
        // Abort for Darwin x86_64 = BSD exit(1) syscall
        std::string darwinAbort =
            "movq $$0x2000001, %rax\n\t"  // SYS_exit (BSD class 2)
            "movq $$1, %rdi\n\t"
            "syscall\n\t";
        // --- CPUID leaf 1: hypervisor present bit ---
        vm += "push %rbx\n\t";
        vm += "movl $$1, %eax\n\t";
        vm += "cpuid\n\t";
        vm += "pop %rbx\n\t";
        vm += "testl $$0x80000000, %ecx\n\t"; // ECX bit 31
        vm += "jz 1f\n\t";
        vm += darwinAbort;
        vm += "1:\n\t";
        // --- CPUID leaf 0x40000000: hypervisor vendor EBX ---
        // Little-endian register value for each 4-char prefix:
        // "VMwa"(VMware)=0x61774D56, "KVMK"(KVM)=0x4B4D564B,
        // "Micr"(Hyper-V)=0x7263694D, "VBox"(VirtualBox)=0x786F4256,
        // "XenV"(Xen)=0x566E6558, "TCGT"(QEMU TCG)=0x54474354
        vm += "push %rbx\n\t";
        vm += "movl $$0x40000000, %eax\n\t";
        vm += "cpuid\n\t";
        vm += "cmpl $$0x61774D56, %ebx\n\t"; vm += "je 2f\n\t";
        vm += "cmpl $$0x4B4D564B, %ebx\n\t"; vm += "je 2f\n\t";
        vm += "cmpl $$0x7263694D, %ebx\n\t"; vm += "je 2f\n\t";
        vm += "cmpl $$0x786F4256, %ebx\n\t"; vm += "je 2f\n\t";
        vm += "cmpl $$0x566E6558, %ebx\n\t"; vm += "je 2f\n\t";
        vm += "cmpl $$0x54474354, %ebx\n\t"; vm += "je 2f\n\t";
        vm += "pop %rbx\n\t";
        vm += "jmp 3f\n\t";
        vm += "2:\n\t";
        vm += "pop %rbx\n\t";
        vm += darwinAbort;
        vm += "3:\n\t";
        InlineAsm *vmIA = InlineAsm::get(VoidFTy, vm,
            "~{rax},~{rcx},~{rdx},~{rdi},~{dirflag},~{fpsr},~{flags}",
            true, false, InlineAsm::AD_ATT);
        CallInst::Create(vmIA->getFunctionType(), vmIA, ArrayRef<Value*>{}, "", lastTerm);
      }

      // ptrace(PT_DENY_ATTACH) via BSD syscall with RDTSC noise
      uint64_t noiseK = cryptoutils->get_uint32_t() & 0xFFFF;
      SmallVector<std::string, 6> parts;
      parts.push_back("movq $$31, %rdi\n\t");
      parts.push_back("xorq %rsi, %rsi\n\t");
      parts.push_back("xorq %rdx, %rdx\n\t");
      parts.push_back("xorq %rcx, %rcx\n\t");
      parts.push_back("movq $$0x200001A, %rax\n\t");
      shuffleBlocks(parts);
      std::string adbasm;
      adbasm += "rdtsc\n\t";
      adbasm += "andl $$0xFFFF, %eax\n\t";
      adbasm += "addl $$" + std::to_string(noiseK) + ", %eax\n\t";
      adbasm += "subl $$" + std::to_string(noiseK) + ", %eax\n\t";
      for (auto &p : parts) adbasm += p;
      adbasm += "syscall\n\t";
      InlineAsm *IA = InlineAsm::get(VoidFTy, adbasm,
          "~{rax},~{rdi},~{rsi},~{rdx},~{rcx},~{dirflag},~{fpsr},~{flags}",
          true, false, InlineAsm::AD_ATT);
      CallInst::Create(IA->getFunctionType(), IA, ArrayRef<Value*>{}, "", lastTerm);

    // ── Linux / Android x86_64 ────────────────────────────────────────────
    } else if ((triple.isOSLinux() || triple.isAndroid()) &&
               (triple.getArch() == Triple::x86_64 ||
                triple.getArch() == Triple::x86_64)) {

      // VM fingerprint block (separate InlineAsm, inserted before ptrace block).
      // GAS numeric local labels reuse safely: the jz/jmp within this block find
      // the nearest forward occurrence of the label, which is always in THIS block.
      {
        std::string vm;
        // Abort = prctl(PR_SET_DUMPABLE,0) + ud2 (hardware #UD, not libc)
        std::string linAbort =
            "movq $$157, %rax\n\t"   // SYS_prctl
            "movq $$4, %rdi\n\t"     // PR_SET_DUMPABLE
            "xorq %rsi, %rsi\n\t"
            "xorq %rdx, %rdx\n\t"
            "xorq %r10, %r10\n\t"
            "syscall\n\t"
            "ud2\n\t";
        // --- CPUID leaf 1: ECX bit 31 (hypervisor present) ---
        vm += "push %rbx\n\t";
        vm += "movl $$1, %eax\n\t";
        vm += "cpuid\n\t";
        vm += "pop %rbx\n\t";
        vm += "testl $$0x80000000, %ecx\n\t";
        vm += "jz 1f\n\t";
        vm += linAbort;
        vm += "1:\n\t";
        // --- CPUID leaf 0x40000000: vendor EBX check ---
        vm += "push %rbx\n\t";
        vm += "movl $$0x40000000, %eax\n\t";
        vm += "cpuid\n\t";
        vm += "cmpl $$0x61774D56, %ebx\n\t"; vm += "je 2f\n\t";
        vm += "cmpl $$0x4B4D564B, %ebx\n\t"; vm += "je 2f\n\t";
        vm += "cmpl $$0x7263694D, %ebx\n\t"; vm += "je 2f\n\t";
        vm += "cmpl $$0x786F4256, %ebx\n\t"; vm += "je 2f\n\t";
        vm += "cmpl $$0x566E6558, %ebx\n\t"; vm += "je 2f\n\t";
        vm += "cmpl $$0x54474354, %ebx\n\t"; vm += "je 2f\n\t";
        vm += "pop %rbx\n\t";
        vm += "jmp 3f\n\t";
        vm += "2:\n\t";
        vm += "pop %rbx\n\t";
        vm += linAbort;
        vm += "3:\n\t";
        // --- RDTSC variance: CPUID-serialized dual read ---
        // On bare metal: delta between two CPUID-fenced RDTSC reads is
        // typically 200-5000 cycles.  Full-system emulation (QEMU TCG,
        // Bochs) inflates this to >512K.  Threshold: 512K cycles.
        vm += "rdtsc\n\t";
        vm += "shlq $$32, %rdx\n\t";
        vm += "orq %rax, %rdx\n\t";
        vm += "movq %rdx, %r12\n\t";     // t0
        vm += "push %rbx\n\t";
        vm += "xorl %eax, %eax\n\t";
        vm += "cpuid\n\t";               // serialisation fence
        vm += "pop %rbx\n\t";
        vm += "rdtsc\n\t";
        vm += "shlq $$32, %rdx\n\t";
        vm += "orq %rax, %rdx\n\t";
        vm += "subq %r12, %rdx\n\t";     // delta = t1 - t0
        vm += "cmpq $$0x80000, %rdx\n\t"; // 512K cycle threshold
        vm += "jbe 4f\n\t";
        vm += linAbort;
        vm += "4:\n\t";
        // --- PR_GET_DUMPABLE check ---
        // Returns 0 (no dump), 1 (normal), or 2 (suid_dumpable).
        // Value 2 requires a patched kernel or root-modified sysctl — suspect.
        vm += "movq $$157, %rax\n\t";
        vm += "movq $$3, %rdi\n\t";      // PR_GET_DUMPABLE = 3
        vm += "xorq %rsi, %rsi\n\t";
        vm += "xorq %rdx, %rdx\n\t";
        vm += "xorq %r10, %r10\n\t";
        vm += "syscall\n\t";
        vm += "cmpq $$2, %rax\n\t";      // 2 = forced suid-dumpable (suspicious)
        vm += "jne 5f\n\t";
        vm += linAbort;
        vm += "5:\n\t";
        InlineAsm *vmIA = InlineAsm::get(VoidFTy, vm,
            "~{rax},~{rcx},~{rdx},~{rdi},~{rsi},~{r10},~{r12},~{dirflag},~{fpsr},~{flags}",
            true, false, InlineAsm::AD_ATT);
        CallInst::Create(vmIA->getFunctionType(), vmIA, ArrayRef<Value*>{}, "", lastTerm);
      }

      // ptrace(PTRACE_TRACEME) + dual-RDTSC single-step detection
      uint64_t noiseK   = cryptoutils->get_uint32_t() & 0xFFFF;
      uint64_t tsThresh = 0x100000ULL;
      std::string adbasm;
      adbasm += "rdtsc\n\t";
      adbasm += "shlq $$32, %rdx\n\t";
      adbasm += "orq %rax, %rdx\n\t";
      adbasm += "movq %rdx, %r11\n\t";
      adbasm += "xorq %rax, %rax\n\t";
      adbasm += "addq $$" + std::to_string(noiseK) + ", %rax\n\t";
      adbasm += "subq $$" + std::to_string(noiseK) + ", %rax\n\t";
      adbasm += "movq $$101, %rax\n\t";
      adbasm += "xorq %rdi, %rdi\n\t";
      adbasm += "xorq %rsi, %rsi\n\t";
      adbasm += "xorq %rdx, %rdx\n\t";
      adbasm += "xorq %r10, %r10\n\t";
      adbasm += "syscall\n\t";
      adbasm += "rdtsc\n\t";
      adbasm += "shlq $$32, %rdx\n\t";
      adbasm += "orq %rax, %rdx\n\t";
      adbasm += "subq %r11, %rdx\n\t";
      adbasm += "cmpq $$" + std::to_string(tsThresh) + ", %rdx\n\t";
      adbasm += "ja 1f\n\t";
      adbasm += "testq %rax, %rax\n\t";
      adbasm += "je 2f\n\t";
      adbasm += "1:\n\t";
      adbasm += "movq $$157, %rax\n\t";
      adbasm += "movq $$4, %rdi\n\t";
      adbasm += "xorq %rsi, %rsi\n\t";
      adbasm += "xorq %rdx, %rdx\n\t";
      adbasm += "xorq %r10, %r10\n\t";
      adbasm += "syscall\n\t";
      adbasm += "ud2\n\t";
      adbasm += "2:\n\t";
      InlineAsm *IA = InlineAsm::get(VoidFTy, adbasm,
          "~{rax},~{rdi},~{rsi},~{rdx},~{r10},~{r11},~{rcx},~{dirflag},~{fpsr},~{flags}",
          true, false, InlineAsm::AD_ATT);
      CallInst::Create(IA->getFunctionType(), IA, ArrayRef<Value*>{}, "", lastTerm);

    // ── Linux / Android AArch64 ───────────────────────────────────────────
    } else if ((triple.isOSLinux() || triple.isAndroid()) &&
               triple.isAArch64()) {

      // VM fingerprint: frozen or implausibly fast CNTVCT_EL0
      {
        std::string vm;
        std::string linAA64Abort =
            "mov x8, #167\n\t"  // SYS_prctl (arm64 Linux)
            "mov x0, #4\n\t"    // PR_SET_DUMPABLE
            "mov x1, #0\n\t"
            "mov x2, #0\n\t"
            "mov x3, #0\n\t"
            "mov x4, #0\n\t"
            "svc #0\n\t"
            "brk #0xBEEF\n\t";
        vm += "mrs x12, cntvct_el0\n\t";
        for (int i = 0; i < 16; i++)
          vm += "nop\n\tnop\n\tnop\n\tnop\n\tnop\n\tnop\n\tnop\n\tnop\n\t";
        vm += "mrs x13, cntvct_el0\n\t";
        vm += "sub x14, x13, x12\n\t";
        // delta == 0 → paused timer → VM
        vm += "cbnz x14, 1f\n\t";
        vm += linAA64Abort;
        vm += "1:\n\t";
        // delta > 0xA000 → emulation too slow
        vm += "mov x15, #0xA000\n\t";
        vm += "cmp x14, x15\n\t";
        vm += "b.lo 2f\n\t";
        vm += linAA64Abort;
        vm += "2:\n\t";
        InlineAsm *vmIA = InlineAsm::get(VoidFTy, vm,
            "~{x0},~{x1},~{x2},~{x3},~{x4},~{x8},~{x12},~{x13},~{x14},~{x15},~{dirflag},~{fpsr},~{flags}",
            true, false);
        CallInst::Create(vmIA->getFunctionType(), vmIA, ArrayRef<Value*>{}, "", lastTerm);
      }

      // ptrace(PTRACE_TRACEME) + CNTVCT_EL0 timing check
      uint32_t noiseImm = cryptoutils->get_range(1, 0x100);
      uint64_t tsThresh = 0x40000ULL;
      std::string adbasm;
      adbasm += "mrs x11, cntvct_el0\n\t";
      adbasm += "add x9, x11, #" + std::to_string(noiseImm) + "\n\t";
      adbasm += "sub x9, x9, #" + std::to_string(noiseImm) + "\n\t";
      adbasm += "mov x8, #117\n\t";
      adbasm += "mov x0, #0\n\t";
      adbasm += "mov x1, #0\n\t";
      adbasm += "mov x2, #0\n\t";
      adbasm += "mov x3, #0\n\t";
      adbasm += "svc #0\n\t";
      adbasm += "mrs x10, cntvct_el0\n\t";
      adbasm += "sub x10, x10, x11\n\t";
      adbasm += "mov x12, #" + std::to_string(tsThresh & 0xFFFF) + "\n\t";
      adbasm += "cmp x10, x12\n\t";
      adbasm += "b.hi 1f\n\t";
      adbasm += "cbz x0, 2f\n\t";
      adbasm += "1:\n\t";
      adbasm += "mov x8, #167\n\t";
      adbasm += "mov x0, #4\n\t";
      adbasm += "mov x1, #0\n\t";
      adbasm += "mov x2, #0\n\t";
      adbasm += "mov x3, #0\n\t";
      adbasm += "mov x4, #0\n\t";
      adbasm += "svc #0\n\t";
      adbasm += "brk #0xDEAD\n\t";
      adbasm += "2:\n\t";
      InlineAsm *IA = InlineAsm::get(VoidFTy, adbasm,
          "~{x0},~{x1},~{x2},~{x3},~{x4},~{x8},~{x9},~{x10},~{x11},~{x12},~{dirflag},~{fpsr},~{flags}",
          true, false);
      CallInst::Create(IA->getFunctionType(), IA, ArrayRef<Value*>{}, "", lastTerm);

    // ── Windows x86_64 ────────────────────────────────────────────────────
    } else if (triple.isOSWindows() &&
               (triple.getArch() == Triple::x86_64 ||
                triple.getArch() == Triple::x86_64)) {
      // Multi-layer debugger detection via PEB fields — all raw, no API calls.
      //
      // PEB is at GS:[0x60] on x86_64 Windows.
      // Key offsets (stable across Win 7-11 x64):
      //   PEB+0x002 = BeingDebugged (BYTE)
      //   PEB+0x0BC = NtGlobalFlag (ULONG); bits 0x70 set by debugger heaps
      //   PEB+0x030 = ProcessHeap (PVOID)
      //   _HEAP+0x44 = ForceFlags (ULONG); 0 in normal process, non-0 under debugger
      //
      // Abort: __fastfail(FAST_FAIL_FATAL_APP_EXIT=7) via `int 0x29`.
      // KiRaiseSecurityCheckFailure handles int 0x29 in kernel mode — no
      // usermode VEH/SEH handler (including hooks) can intercept this path.
      uint64_t noiseK = cryptoutils->get_uint32_t() & 0xFFFF;
      std::string adbasm;
      // Abort snippet for Windows
      auto winAbort = [&]() -> std::string {
        return "movl $$7, %ecx\n\t"   // FAST_FAIL_FATAL_APP_EXIT
               "int $$0x29\n\t";       // → KiRaiseSecurityCheckFailure
      };
      // --- PEB.BeingDebugged ---
      adbasm += "movq %gs:96, %rax\n\t";       // GS:[0x60] = PEB
      adbasm += "movzbl 2(%rax), %ecx\n\t";    // PEB+0x02 = BeingDebugged
      adbasm += "testl %ecx, %ecx\n\t";
      adbasm += "jz 1f\n\t";
      adbasm += winAbort();
      adbasm += "1:\n\t";
      // --- PEB.NtGlobalFlag (bits 0x70 = debug-heap flags) ---
      adbasm += "movq %gs:96, %rax\n\t";
      adbasm += "movl 188(%rax), %ecx\n\t";    // PEB+0xBC = NtGlobalFlag
      adbasm += "andl $$0x70, %ecx\n\t";
      adbasm += "jz 2f\n\t";
      adbasm += winAbort();
      adbasm += "2:\n\t";
      // --- PEB.ProcessHeap → _HEAP.ForceFlags ---
      adbasm += "movq %gs:96, %rax\n\t";
      adbasm += "movq 48(%rax), %rax\n\t";     // PEB+0x30 = ProcessHeap
      adbasm += "movl 68(%rax), %ecx\n\t";     // _HEAP+0x44 = ForceFlags
      adbasm += "testl %ecx, %ecx\n\t";        // non-zero → debugger
      adbasm += "jz 3f\n\t";
      adbasm += winAbort();
      adbasm += "3:\n\t";
      // RDTSC timing noise
      adbasm += "rdtsc\n\t";
      adbasm += "andl $$0xFFFF, %eax\n\t";
      adbasm += "addl $$" + std::to_string(noiseK) + ", %eax\n\t";
      adbasm += "subl $$" + std::to_string(noiseK) + ", %eax\n\t";
      InlineAsm *IA = InlineAsm::get(VoidFTy, adbasm,
          "~{rax},~{rcx},~{rdx},~{dirflag},~{fpsr},~{flags}",
          true, false, InlineAsm::AD_ATT);
      CallInst::Create(IA->getFunctionType(), IA, ArrayRef<Value*>{}, "", lastTerm);

    } else {
      errs() << "Unsupported Inline Assembly AntiDebugging Target: "
#if LLVM_VERSION_MAJOR >= 20
             << F.getParent()->getTargetTriple().getTriple() << "\n";
#else
             << F.getParent()->getTargetTriple() << "\n";
#endif
    }
    return true;
  }
};

ModulePass *createAntiDebuggingPass(bool flag) {
  return new AntiDebugging(flag);
}
} // namespace llvm

char AntiDebugging::ID = 0;
INITIALIZE_PASS(AntiDebugging, "adb", "Enable AntiDebugging.", false, false)
