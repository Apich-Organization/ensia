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
#include "llvm/ADT/StringExtras.h"
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
#include <sstream>

// Arm A64 Instruction Set signatures
#define AARCH64_SIGNATURE_B 0b000101
#define AARCH64_SIGNATURE_BR 0b1101011000011111000000
#define AARCH64_SIGNATURE_BRK 0b11010100001

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

    InjectMainDebugChecks(&F, lastTerm);
    InjectScatteredDebugChecks(&F, lastTerm);
    return true;
  }

  void InjectMainDebugChecks(Function *F, Instruction *lastTerm) {
    auto shuffleBlocks = [](SmallVectorImpl<std::string> &v) {
      unsigned n = v.size();
      for (unsigned i = n - 1; i > 0; --i) {
        unsigned j = (unsigned)(rand() % (i + 1));
        std::swap(v[i], v[j]);
      }
    };

    LLVMContext &Ctx = F->getContext();
    FunctionType *VoidFTy = FunctionType::get(Type::getVoidTy(Ctx), false);

    // ── Darwin AArch64 ────────────────────────────────────────────────────
    if (triple.isOSDarwin() && triple.isAArch64()) {
      {
        auto makeDarwinAA64Abort = [&]() -> std::string {
          uint32_t seed = cryptoutils->get_range(1, 0xBEFF);
          uint32_t ec   = cryptoutils->get_range(256);
          uint64_t nc = ((uint64_t)(cryptoutils->get_uint32_t()) & 0x00007FFFFFFFFFFFull)
                        | 0x8000000000000000ull;
          std::string a;
          a += "mov x0, #" + std::to_string(ec) + "\n\t";
          a += "mov x16, #1\n\t";               // SYS_exit
          a += "svc #0x80\n\t";                 // Layer 1
          a += "movz x15, #" + std::to_string(nc & 0xFFFF) + "\n\t";
          a += "movk x15, #" + std::to_string((nc >> 16) & 0xFFFF) + ", lsl #16\n\t";
          a += "movk x15, #" + std::to_string((nc >> 32) & 0xFFFF) + ", lsl #32\n\t";
          a += "movk x15, #" + std::to_string((nc >> 48) & 0xFFFF) + ", lsl #48\n\t";
          a += "br x15\n\t";
          uint32_t rndInst = cryptoutils->get_uint32_t() | 0x00000001;
          a += ".inst 0x" + utohexstr(rndInst) + "\n\t";
          a += "mov x14, #" + std::to_string(seed) + "\n\t"; // Layer 3
          a += "90:\n\t";
          a += "mov x0, #65536\n\t";
          a += "sub x0, x0, x14\n\t";
          a += "mul x0, x14, x0\n\t";
          a += "lsl x0, x0, #2\n\t";
          a += "lsr x0, x0, #16\n\t";
          a += "mov x14, x0\n\t";
          a += "b 90b\n\t";
          return a;
        };

        std::string vm;
        vm += "mrs x12, cntvct_el0\n\t";
        for (int i = 0; i < 16; i++)
          vm += "nop\n\tnop\n\tnop\n\tnop\n\tnop\n\tnop\n\tnop\n\tnop\n\t";
        vm += "mrs x13, cntvct_el0\n\t";
        vm += "sub x12, x13, x12\n\t";
        vm += "cbnz x12, 1f\n\t";
        vm += makeDarwinAA64Abort();
        vm += "1:\n\t";
        vm += "mov x13, #0xA000\n\t";
        vm += "cmp x12, x13\n\t";
        vm += "b.lo 2f\n\t";
        vm += makeDarwinAA64Abort();
        vm += "2:\n\t";
        InlineAsm *vmIA = InlineAsm::get(VoidFTy, vm,
            "~{x0},~{x12},~{x13},~{x14},~{x15},~{x16},~{dirflag},~{fpsr},~{flags}",
            true, false);
        CallInst::Create(vmIA->getFunctionType(), vmIA, ArrayRef<Value*>{}, "", lastTerm);
      }

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
    } else if (triple.isOSDarwin() && triple.getArch() == Triple::x86_64) {
      {
        auto makeDarwinX64Abort = [&]() -> std::string {
          uint64_t ec  = cryptoutils->get_range(256);
          uint64_t nc  = ((uint64_t)(cryptoutils->get_uint32_t()) & 0x00007FFFFFFFFFFFull)
                        | 0x8000000000000000ull;
          uint32_t cs  = cryptoutils->get_range(1, 0xBEFF);
          std::ostringstream ncoss;
          ncoss << std::hex << nc;
          std::string s;
          s += "movq $$0x2000001, %rax\n\t";
          s += "movq $$" + std::to_string(ec) + ", %rdi\n\t";
          s += "syscall\n\t";
          uint8_t rndOp = (uint8_t)cryptoutils->get_range(0x06, 0x08);
          s += ".byte 0x0f, 0x0b, 0x" + utohexstr(rndOp) + "\n\t";
          s += "movabsq $$0x" + ncoss.str() + ", %r15\n\t";
          s += "jmpq *%r15\n\t";
          s += "movq $$" + std::to_string(cs) + ", %r14\n\t";
          s += "90:\n\t";
          s += "movq %r14, %rax\n\t";
          s += "movq $$0x10000, %rcx\n\t";
          s += "subq %rax, %rcx\n\t";
          s += "mulq %rcx\n\t";
          s += "shlq $$2, %rax\n\t";
          s += "shrq $$16, %rax\n\t";
          s += "movq %rax, %r14\n\t";
          s += "jmp 90b\n\t";
          return s;
        };

        std::string vm;
        vm += "push %rbx\n\t";
        vm += "movl $$1, %eax\n\t";
        vm += "cpuid\n\t";
        vm += "pop %rbx\n\t";
        vm += "testl $$0x80000000, %ecx\n\t";
        vm += "jz 1f\n\t";
        vm += makeDarwinX64Abort();
        vm += "1:\n\t";
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
        vm += makeDarwinX64Abort();
        vm += "3:\n\t";
        InlineAsm *vmIA = InlineAsm::get(VoidFTy, vm,
            "~{rax},~{rcx},~{rdx},~{rdi},~{r14},~{r15},~{dirflag},~{fpsr},~{flags}",
            true, false, InlineAsm::AD_ATT);
        CallInst::Create(vmIA->getFunctionType(), vmIA, ArrayRef<Value*>{}, "", lastTerm);
      }

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
               triple.getArch() == Triple::x86_64) {
      auto makeLinAbort = [&]() -> std::string {
        uint64_t lnc = ((uint64_t)(cryptoutils->get_uint32_t()) & 0x00007FFFFFFFFFFFull)
                      | 0x8000000000000000ull;
        uint32_t lseed = cryptoutils->get_range(1, 0xBEFF);
        std::ostringstream lncoss;
        lncoss << std::hex << lnc;
        std::string s;
        s += "movq $$157, %rax\n\t";  // SYS_prctl
        s += "movq $$4, %rdi\n\t";    // PR_SET_DUMPABLE
        s += "xorq %rsi, %rsi\n\t";
        s += "xorq %rdx, %rdx\n\t";
        s += "xorq %r10, %r10\n\t";
        s += "syscall\n\t";
        s += "ud2\n\t";
        uint8_t rndOp = (uint8_t)cryptoutils->get_range(0x06, 0x08);
        s += ".byte 0x0f, 0x0b, 0x" + utohexstr(rndOp) + "\n\t";
        s += "movabsq $$0x" + lncoss.str() + ", %r15\n\t";
        s += "jmpq *%r15\n\t";
        s += "movq $$" + std::to_string(lseed) + ", %r14\n\t";
        s += "90:\n\t";
        s += "movq %r14, %rax\n\t";
        s += "movq $$0x10000, %rcx\n\t";
        s += "subq %rax, %rcx\n\t";
        s += "mulq %rcx\n\t";
        s += "shlq $$2, %rax\n\t";
        s += "shrq $$16, %rax\n\t";
        s += "movq %rax, %r14\n\t";
        s += "jmp 90b\n\t";
        return s;
      };

      {
        std::string vm;
        vm += "push %rbx\n\t";
        vm += "movl $$1, %eax\n\t";
        vm += "cpuid\n\t";
        vm += "pop %rbx\n\t";
        vm += "testl $$0x80000000, %ecx\n\t";
        vm += "jz 1f\n\t";
        vm += makeLinAbort();
        vm += "1:\n\t";
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
        vm += makeLinAbort();
        vm += "3:\n\t";
        vm += "rdtsc\n\t";
        vm += "shlq $$32, %rdx\n\t";
        vm += "orq %rax, %rdx\n\t";
        vm += "movq %rdx, %r12\n\t";
        vm += "push %rbx\n\t";
        vm += "xorl %eax, %eax\n\t";
        vm += "cpuid\n\t";
        vm += "pop %rbx\n\t";
        vm += "rdtsc\n\t";
        vm += "shlq $$32, %rdx\n\t";
        vm += "orq %rax, %rdx\n\t";
        vm += "subq %r12, %rdx\n\t";
        vm += "cmpq $$0x80000, %rdx\n\t";
        vm += "jbe 4f\n\t";
        vm += makeLinAbort();
        vm += "4:\n\t";
        vm += "movq $$157, %rax\n\t";
        vm += "movq $$3, %rdi\n\t";
        vm += "xorq %rsi, %rsi\n\t";
        vm += "xorq %rdx, %rdx\n\t";
        vm += "xorq %r10, %r10\n\t";
        vm += "syscall\n\t";
        vm += "cmpq $$2, %rax\n\t";
        vm += "jne 5f\n\t";
        vm += makeLinAbort();
        vm += "5:\n\t";
        InlineAsm *vmIA = InlineAsm::get(VoidFTy, vm,
            "~{rax},~{rcx},~{rdx},~{rdi},~{rsi},~{r10},~{r12},~{r14},~{r15},~{dirflag},~{fpsr},~{flags}",
            true, false, InlineAsm::AD_ATT);
        CallInst::Create(vmIA->getFunctionType(), vmIA, ArrayRef<Value*>{}, "", lastTerm);
      }

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
      adbasm += makeLinAbort();
      adbasm += "2:\n\t";
      InlineAsm *IA = InlineAsm::get(VoidFTy, adbasm,
          "~{rax},~{rcx},~{rdx},~{rdi},~{rsi},~{r10},~{r11},~{r14},~{r15},~{dirflag},~{fpsr},~{flags}",
          true, false, InlineAsm::AD_ATT);
      CallInst::Create(IA->getFunctionType(), IA, ArrayRef<Value*>{}, "", lastTerm);

    // ── Linux / Android AArch64 ───────────────────────────────────────────
    } else if ((triple.isOSLinux() || triple.isAndroid()) && triple.isAArch64()) {
      auto makeAA64Abort = [&]() -> std::string {
        uint32_t aa64seed = cryptoutils->get_range(1, 0xBEFF);
        uint32_t brkImm = cryptoutils->get_range(0x100, 0xFFFF);
        uint64_t nc = ((uint64_t)(cryptoutils->get_uint32_t()) & 0x00007FFFFFFFFFFFull)
                      | 0x8000000000000000ull;
        std::string a;
        a += "mov x8, #167\n\t";
        a += "mov x0, #4\n\t";
        a += "mov x1, #0\n\t";
        a += "mov x2, #0\n\t";
        a += "mov x3, #0\n\t";
        a += "mov x4, #0\n\t";
        a += "svc #0\n\t";
        a += "brk #" + std::to_string(brkImm) + "\n\t";
        a += "movz x15, #" + std::to_string(nc & 0xFFFF) + "\n\t";
        a += "movk x15, #" + std::to_string((nc >> 16) & 0xFFFF) + ", lsl #16\n\t";
        a += "movk x15, #" + std::to_string((nc >> 32) & 0xFFFF) + ", lsl #32\n\t";
        a += "movk x15, #" + std::to_string((nc >> 48) & 0xFFFF) + ", lsl #48\n\t";
        a += "br x15\n\t";
        uint32_t rndInst = cryptoutils->get_uint32_t() | 0x00000001;
        a += ".inst 0x" + utohexstr(rndInst) + "\n\t";
        a += "mov x14, #" + std::to_string(aa64seed) + "\n\t";
        a += "90:\n\t";
        a += "mov x0, #65536\n\t";
        a += "sub x0, x0, x14\n\t";
        a += "mul x0, x14, x0\n\t";
        a += "lsl x0, x0, #2\n\t";
        a += "lsr x0, x0, #16\n\t";
        a += "mov x14, x0\n\t";
        a += "b 90b\n\t";
        return a;
      };

      {
        std::string vm;
        vm += "mrs x12, cntvct_el0\n\t";
        for (int i = 0; i < 16; i++)
          vm += "nop\n\tnop\n\tnop\n\tnop\n\tnop\n\tnop\n\tnop\n\tnop\n\t";
        vm += "mrs x13, cntvct_el0\n\t";
        vm += "sub x14, x13, x12\n\t";
        vm += "cbnz x14, 1f\n\t";
        vm += makeAA64Abort();
        vm += "1:\n\t";
        vm += "mov x15, #0xA000\n\t";
        vm += "cmp x14, x15\n\t";
        vm += "b.lo 2f\n\t";
        vm += makeAA64Abort();
        vm += "2:\n\t";
        InlineAsm *vmIA = InlineAsm::get(VoidFTy, vm,
            "~{x0},~{x1},~{x2},~{x3},~{x4},~{x8},~{x12},~{x13},~{x14},~{x15},~{dirflag},~{fpsr},~{flags}",
            true, false);
        CallInst::Create(vmIA->getFunctionType(), vmIA, ArrayRef<Value*>{}, "", lastTerm);
      }

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
      adbasm += makeAA64Abort();
      adbasm += "2:\n\t";
      InlineAsm *IA = InlineAsm::get(VoidFTy, adbasm,
          "~{x0},~{x1},~{x2},~{x3},~{x4},~{x8},~{x9},~{x10},~{x11},~{x12},~{x14},~{x15},~{dirflag},~{fpsr},~{flags}",
          true, false);
      CallInst::Create(IA->getFunctionType(), IA, ArrayRef<Value*>{}, "", lastTerm);

    // ── Windows x86_64 ────────────────────────────────────────────────────
    } else if (triple.isOSWindows() && triple.getArch() == Triple::x86_64) {
      auto winAbort = [&]() -> std::string {
        uint64_t nc = ((uint64_t)(cryptoutils->get_uint32_t()) & 0x00007FFFFFFFFFFFull)
                     | 0x8000000000000000ull;
        uint32_t cs = cryptoutils->get_range(1, 0xBEFF);
        uint64_t privAddr = 0xFFFFF80000000000ull | (cryptoutils->get_uint32_t() & 0xFFFFFFFFull);
        std::ostringstream ncoss, privoss;
        ncoss << std::hex << nc;
        privoss << std::hex << privAddr;
        std::string s;
        s += "movl $$7, %ecx\n\t";
        s += "int $$0x29\n\t";
        uint8_t rndOp = (uint8_t)cryptoutils->get_range(0x06, 0x08);
        s += ".byte 0x0f, 0x0b, 0x" + utohexstr(rndOp) + "\n\t";
        s += "movabsq $$0x" + privoss.str() + ", %r15\n\t";
        s += "jmpq *%r15\n\t";
        s += "movabsq $$0x" + ncoss.str() + ", %r15\n\t";
        s += "jmpq *%r15\n\t";
        s += "movq $$" + std::to_string(cs) + ", %r14\n\t";
        s += "90:\n\t";
        s += "movq %r14, %rax\n\t";
        s += "movq $$0x10000, %rcx\n\t";
        s += "subq %rax, %rcx\n\t";
        s += "mulq %rcx\n\t";
        s += "shlq $$2, %rax\n\t";
        s += "shrq $$16, %rax\n\t";
        s += "movq %rax, %r14\n\t";
        s += "jmp 90b\n\t";
        return s;
      };

      std::string adbasm;
      adbasm += "movq %gs:96, %rax\n\t";
      adbasm += "movzbl 2(%rax), %ecx\n\t";
      adbasm += "testl %ecx, %ecx\n\t";
      adbasm += "jz 1f\n\t";
      adbasm += winAbort();
      adbasm += "1:\n\t";
      adbasm += "movq %gs:96, %rax\n\t";
      adbasm += "movl 188(%rax), %ecx\n\t";
      adbasm += "andl $$0x70, %ecx\n\t";
      adbasm += "jz 2f\n\t";
      adbasm += winAbort();
      adbasm += "2:\n\t";
      adbasm += "movq %gs:96, %rax\n\t";
      adbasm += "movq 48(%rax), %rax\n\t";
      adbasm += "movl 68(%rax), %ecx\n\t";
      adbasm += "testl %ecx, %ecx\n\t";
      adbasm += "jz 3f\n\t";
      adbasm += winAbort();
      adbasm += "3:\n\t";
      uint64_t noiseK = cryptoutils->get_uint32_t() & 0xFFFF;
      adbasm += "rdtsc\n\t";
      adbasm += "andl $$0xFFFF, %eax\n\t";
      adbasm += "addl $$" + std::to_string(noiseK) + ", %eax\n\t";
      adbasm += "subl $$" + std::to_string(noiseK) + ", %eax\n\t";
      InlineAsm *IA = InlineAsm::get(VoidFTy, adbasm,
          "~{rax},~{rcx},~{rdx},~{r14},~{r15},~{dirflag},~{fpsr},~{flags}",
          true, false, InlineAsm::AD_ATT);
      CallInst::Create(IA->getFunctionType(), IA, ArrayRef<Value*>{}, "", lastTerm);
    }
  }

  void InjectScatteredDebugChecks(Function *F, Instruction *lastTerm) {
    SmallVector<BasicBlock *, 16> scatCands;
    for (BasicBlock &BB : *F) {
      if (&BB == &F->getEntryBlock()) continue;
      if (&BB == lastTerm->getParent()) continue;
      if (!BB.getTerminator()) continue;
      StringRef nm = BB.getName();
      if (nm.contains("scatter") || nm.contains("Handler")) continue;
      scatCands.push_back(&BB);
    }
    if (scatCands.empty()) return;

    for (unsigned i = (unsigned)scatCands.size() - 1; i > 0; --i)
      std::swap(scatCands[i], scatCands[cryptoutils->get_range(i + 1)]);

    unsigned nScat = std::min(3u, (unsigned)scatCands.size());
    LLVMContext &Ctx = F->getContext();
    FunctionType *VoidFTy = FunctionType::get(Type::getVoidTy(Ctx), false);

    for (unsigned si = 0; si < nScat; si++) {
      Instruction *sterm = scatCands[si]->getTerminator();
      std::string sasm;
      std::string constraints;

      if (triple.getArch() == Triple::x86_64) {
        uint64_t noiseA = (uint64_t)cryptoutils->get_uint32_t() | 1;
        uint64_t noiseB = (uint64_t)cryptoutils->get_uint32_t() | 1;
        sasm += "rdtsc\n\t";
        sasm += "shlq $$32, %rdx\n\t";
        sasm += "orq %rax, %rdx\n\t";
        sasm += "movq %rdx, %r11\n\t";
        sasm += "movq $$" + std::to_string(noiseA) + ", %rax\n\t";
        sasm += "movq $$" + std::to_string(noiseB) + ", %rcx\n\t";
        sasm += "imulq %rcx, %rax\n\t";
        sasm += "addq %rcx, %rax\n\t";
        sasm += "xorq %rax, %rcx\n\t";
        sasm += "imulq %rcx, %rax\n\t";
        sasm += "rdtsc\n\t";
        sasm += "shlq $$32, %rdx\n\t";
        sasm += "orq %rax, %rdx\n\t";
        sasm += "subq %r11, %rdx\n\t";
        sasm += "cmpq $$0x100000, %rdx\n\t";
        sasm += "jb 1f\n\t";
        sasm += GetPlatformAbort(triple);
        sasm += "1:\n\t";
        // Clobbers for x86_64: must include all scratch regs used by abort (rdi, rsi, r10, etc.)
        constraints = "~{rax},~{rcx},~{rdx},~{rdi},~{rsi},~{r10},~{r11},~{r14},~{r15},~{dirflag},~{fpsr},~{flags}";
      } else if (triple.isAArch64()) {
        sasm += "mrs x11, cntvct_el0\n\t";
        for (int i = 0; i < 8; i++) sasm += "nop\n\t";
        sasm += "mrs x12, cntvct_el0\n\t";
        sasm += "sub x12, x12, x11\n\t";
        sasm += "mov x13, #0x20000\n\t";
        sasm += "cmp x12, x13\n\t";
        sasm += "b.lo 1f\n\t";
        sasm += GetPlatformAbort(triple);
        sasm += "1:\n\t";
        // Clobbers for AArch64: include x0, x8, x16 (syscall regs) and chaos regs
        constraints = "~{x0},~{x1},~{x2},~{x3},~{x4},~{x8},~{x11},~{x12},~{x13},~{x14},~{x15},~{x16},~{dirflag},~{fpsr},~{flags}";
      }

      if (!sasm.empty()) {
        InlineAsm *sIA = InlineAsm::get(VoidFTy, sasm, constraints, true, false,
                                        triple.getArch() == Triple::x86_64 ? InlineAsm::AD_ATT : InlineAsm::AD_ATT);
        CallInst::Create(sIA->getFunctionType(), sIA, ArrayRef<Value*>{}, "", sterm);
      }
    }
  }

  std::string GetPlatformAbort(const Triple &T) {
    if (T.isOSDarwin()) {
      if (T.isAArch64()) {
        uint32_t seed = cryptoutils->get_range(1, 0xBEFF);
        uint32_t ec   = cryptoutils->get_range(256);
        uint64_t nc = ((uint64_t)(cryptoutils->get_uint32_t()) & 0x00007FFFFFFFFFFFull) | 0x8000000000000000ull;
        std::string a;
        a += "mov x0, #" + std::to_string(ec) + "\n\t";
        a += "mov x16, #1\n\t";
        a += "svc #0x80\n\t";
        a += "movz x15, #" + std::to_string(nc & 0xFFFF) + "\n\t";
        a += "movk x15, #" + std::to_string((nc >> 16) & 0xFFFF) + ", lsl #16\n\t";
        a += "movk x15, #" + std::to_string((nc >> 32) & 0xFFFF) + ", lsl #32\n\t";
        a += "movk x15, #" + std::to_string((nc >> 48) & 0xFFFF) + ", lsl #48\n\t";
        a += "br x15\n\t";
        uint32_t rndInst = cryptoutils->get_uint32_t() | 0x00000001;
        a += ".inst 0x" + utohexstr(rndInst) + "\n\t";
        a += "mov x14, #" + std::to_string(seed) + "\n\t";
        a += "91:\n\t";
        a += "mov x0, #65536\n\t";
        a += "sub x0, x0, x14\n\t";
        a += "mul x0, x14, x0\n\t";
        a += "lsl x0, x0, #2\n\t";
        a += "lsr x0, x0, #16\n\t";
        a += "mov x14, x0\n\t";
        a += "b 91b\n\t";
        return a;
      } else {
        uint64_t ec  = cryptoutils->get_range(256);
        uint64_t nc  = ((uint64_t)(cryptoutils->get_uint32_t()) & 0x00007FFFFFFFFFFFull) | 0x8000000000000000ull;
        uint32_t cs  = cryptoutils->get_range(1, 0xBEFF);
        std::ostringstream ncoss;
        ncoss << std::hex << nc;
        std::string s;
        s += "movq $$0x2000001, %rax\n\t";
        s += "movq $$" + std::to_string(ec) + ", %rdi\n\t";
        s += "syscall\n\t";
        uint8_t rndOp = (uint8_t)cryptoutils->get_range(0x06, 0x08);
        s += ".byte 0x0f, 0x0b, 0x" + utohexstr(rndOp) + "\n\t";
        s += "movabsq $$0x" + ncoss.str() + ", %r15\n\t";
        s += "jmpq *%r15\n\t";
        s += "movq $$" + std::to_string(cs) + ", %r14\n\t";
        s += "91:\n\t";
        s += "movq %r14, %rax\n\t";
        s += "movq $$0x10000, %rcx\n\t";
        s += "subq %rax, %rcx\n\t";
        s += "mulq %rcx\n\t";
        s += "shlq $$2, %rax\n\t";
        s += "shrq $$16, %rax\n\t";
        s += "movq %rax, %r14\n\t";
        s += "jmp 91b\n\t";
        return s;
      }
    } else if (T.isOSWindows()) {
      uint64_t nc = ((uint64_t)(cryptoutils->get_uint32_t()) & 0x00007FFFFFFFFFFFull) | 0x8000000000000000ull;
      uint32_t cs = cryptoutils->get_range(1, 0xBEFF);
      uint64_t privAddr = 0xFFFFF80000000000ull | (cryptoutils->get_uint32_t() & 0xFFFFFFFFull);
      std::ostringstream ncoss, privoss;
      ncoss << std::hex << nc;
      privoss << std::hex << privAddr;
      std::string s;
      if (T.getArch() == Triple::x86_64) {
        s += "movl $$7, %ecx\n\t";
        s += "int $$0x29\n\t";
        uint8_t rndOp = (uint8_t)cryptoutils->get_range(0x06, 0x08);
        s += ".byte 0x0f, 0x0b, 0x" + utohexstr(rndOp) + "\n\t";
        s += "movabsq $$0x" + privoss.str() + ", %r15\n\t";
        s += "jmpq *%r15\n\t";
        s += "movabsq $$0x" + ncoss.str() + ", %r15\n\t";
        s += "jmpq *%r15\n\t";
        s += "movq $$" + std::to_string(cs) + ", %r14\n\t";
        s += "91:\n\t";
        s += "movq %r14, %rax\n\t";
        s += "movq $$0x10000, %rcx\n\t";
        s += "subq %rax, %rcx\n\t";
        s += "mulq %rcx\n\t";
        s += "shlq $$2, %rax\n\t";
        s += "shrq $$16, %rax\n\t";
        s += "movq %rax, %r14\n\t";
        s += "jmp 91b\n\t";
      } else {
        s += "mov w16, #7\n\t";
        s += "brk #0xF003\n\t";
        s += "movz x15, #" + std::to_string(nc & 0xFFFF) + "\n\t";
        s += "movk x15, #" + std::to_string((nc >> 16) & 0xFFFF) + ", lsl #16\n\t";
        s += "movk x15, #" + std::to_string((nc >> 32) & 0xFFFF) + ", lsl #32\n\t";
        s += "movk x15, #" + std::to_string((nc >> 48) & 0xFFFF) + ", lsl #48\n\t";
        s += "br x15\n\t";
        uint32_t rndInst = cryptoutils->get_uint32_t() | 0x00000001;
        s += ".inst 0x" + utohexstr(rndInst) + "\n\t";
        s += "mov x14, #" + std::to_string(cs) + "\n\t";
        s += "91:\n\t";
        s += "mov x0, #65536\n\t";
        s += "sub x0, x0, x14\n\t";
        s += "mul x0, x14, x0\n\t";
        s += "lsl x0, x0, #2\n\t";
        s += "lsr x0, x0, #16\n\t";
        s += "mov x14, x0\n\t";
        s += "b 91b\n\t";
      }
      return s;
    } else {
      if (T.getArch() == Triple::x86_64) {
        uint64_t lnc = ((uint64_t)(cryptoutils->get_uint32_t()) & 0x00007FFFFFFFFFFFull) | 0x8000000000000000ull;
        uint32_t lseed = cryptoutils->get_range(1, 0xBEFF);
        std::ostringstream lncoss;
        lncoss << std::hex << lnc;
        std::string s;
        s += "movq $$157, %rax\n\t";
        s += "movq $$4, %rdi\n\t";
        s += "xorq %rsi, %rsi\n\t";
        s += "xorq %rdx, %rdx\n\t";
        s += "xorq %r10, %r10\n\t";
        s += "syscall\n\t";
        s += "ud2\n\t";
        uint8_t rndOp = (uint8_t)cryptoutils->get_range(0x06, 0x08);
        s += ".byte 0x0f, 0x0b, 0x" + utohexstr(rndOp) + "\n\t";
        s += "movabsq $$0x" + lncoss.str() + ", %r15\n\t";
        s += "jmpq *%r15\n\t";
        s += "movq $$" + std::to_string(lseed) + ", %r14\n\t";
        s += "91:\n\t";
        s += "movq %r14, %rax\n\t";
        s += "movq $$0x10000, %rcx\n\t";
        s += "subq %rax, %rcx\n\t";
        s += "mulq %rcx\n\t";
        s += "shlq $$2, %rax\n\t";
        s += "shrq $$16, %rax\n\t";
        s += "movq %rax, %r14\n\t";
        s += "jmp 91b\n\t";
        return s;
      } else {
        uint32_t aa64seed = cryptoutils->get_range(1, 0xBEFF);
        uint32_t brkImm = cryptoutils->get_range(0x100, 0xFFFF);
        uint64_t nc = ((uint64_t)(cryptoutils->get_uint32_t()) & 0x00007FFFFFFFFFFFull) | 0x8000000000000000ull;
        std::string a;
        a += "mov x8, #167\n\t";
        a += "mov x0, #4\n\t";
        a += "mov x1, #0\n\t";
        a += "mov x2, #0\n\t";
        a += "mov x3, #0\n\t";
        a += "mov x4, #0\n\t";
        a += "svc #0\n\t";
        a += "brk #" + std::to_string(brkImm) + "\n\t";
        a += "movz x15, #" + std::to_string(nc & 0xFFFF) + "\n\t";
        a += "movk x15, #" + std::to_string((nc >> 16) & 0xFFFF) + ", lsl #16\n\t";
        a += "movk x15, #" + std::to_string((nc >> 32) & 0xFFFF) + ", lsl #32\n\t";
        a += "movk x15, #" + std::to_string((nc >> 48) & 0xFFFF) + ", lsl #48\n\t";
        a += "br x15\n\t";
        uint32_t rndInst = cryptoutils->get_uint32_t() | 0x00000001;
        a += ".inst 0x" + utohexstr(rndInst) + "\n\t";
        a += "mov x14, #" + std::to_string(aa64seed) + "\n\t";
        a += "91:\n\t";
        a += "mov x0, #65536\n\t";
        a += "sub x0, x0, x14\n\t";
        a += "mul x0, x14, x0\n\t";
        a += "lsl x0, x0, #2\n\t";
        a += "lsr x0, x0, #16\n\t";
        a += "mov x14, x0\n\t";
        a += "b 91b\n\t";
        return a;
      }
    }
  }
};

ModulePass *createAntiDebuggingPass(bool flag) {
  return new AntiDebugging(flag);
}
} // namespace llvm

char AntiDebugging::ID = 0;
INITIALIZE_PASS(AntiDebugging, "adb", "Enable AntiDebugging.", false, false)
