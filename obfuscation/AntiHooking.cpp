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

#include "include/AntiHook.h"
#include "include/CryptoUtils.h"
#include "include/ObfConfig.h"
#include "include/Utils.h"
#include "include/compat/CallSite.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Linker/Linker.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <fstream>
#include <sstream>

// Arm A64 Instruction Set for A-profile architecture 2022-12, Page 56
#define AARCH64_SIGNATURE_B 0b000101
// Arm A64 Instruction Set for A-profile architecture 2022-12, Page 75
#define AARCH64_SIGNATURE_BR 0b1101011000011111000000
// Arm A64 Instruction Set for A-profile architecture 2022-12, Page 79
#define AARCH64_SIGNATURE_BRK 0b11010100001

// x86_64 common hooking opcode prefixes
#define X86_64_JMP_REL32 0xE9u  // jmp rel32 (Substrate / MS Detours classic)
#define X86_64_MOVABS_RAX 0x48u // REX.W prefix → movabs rax, imm64 + jmp rax
#define X86_64_INT3 0xCCu       // INT3 — Detours hot-patch / debugger trap
#define X86_64_JMP_SHORT 0xEBu  // jmp rel8 — Detours compact trampoline
#define X86_64_MOV_EDI_EDI_B0 0x8Bu // MOV EDI, EDI = 8B FF (Detours 2.x marker)
#define X86_64_MOV_EDI_EDI_B1 0xFFu
// FF 25 xx xx xx xx — JMP [RIP+disp32], the canonical Frida/ELF-PLT stub on
// Linux. This is the most prevalent hook pattern on Linux x86_64 because the
// dynamic linker resolves PLT entries using exactly this encoding in the
// .plt.sec section.
#define X86_64_JMP_INDIR 0xFFu
#define X86_64_JMP_INDIR_B1 0x25u

// AArch64 Windows Detours-style hook opcodes (16-byte trampoline)
// byte[0:3] can be B rel26 (same as Darwin/Linux) or LDR x17, [pc,#8]
#define AARCH64_WIN_LDR_X17_PC8 0x58000051u // LDR x17, [PC, #8]

using namespace llvm;

// Opaque-pointer-safe helper
static inline Type *getOpaquePtrTy(LLVMContext &Ctx) {
  return PointerType::getUnqual(Ctx);
}

static cl::opt<std::string>
    PreCompiledIRPath("adhexrirpath",
                      cl::desc("External Path Pointing To Pre-compiled Anti "
                               "Hooking Handler IR"),
                      cl::value_desc("filename"), cl::init(""));
static cl::alias PreCompiledIRPathAlias1("ah_ir_path",
                                         cl::desc("Alias for -adhexrirpath"),
                                         cl::aliasopt(PreCompiledIRPath));
static cl::alias PreCompiledIRPathAlias2("ah-ir-path",
                                         cl::desc("Alias for -adhexrirpath"),
                                         cl::aliasopt(PreCompiledIRPath));

static cl::opt<bool> CheckInlineHook("ah_inline", cl::init(true), cl::NotHidden,
                                     cl::desc("Check Inline Hook for AArch64"));
static thread_local bool CheckInlineHookTemp = true;
static cl::alias CheckInlineHookAlias1("ah-inline",
                                       cl::desc("Alias for -ah_inline"),
                                       cl::aliasopt(CheckInlineHook));
static cl::alias CheckInlineHookAlias2("ah_inline_aarch64",
                                       cl::desc("Alias for -ah_inline"),
                                       cl::aliasopt(CheckInlineHook));

static cl::opt<bool>
    CheckObjectiveCRuntimeHook("ah_objcruntime", cl::init(true), cl::NotHidden,
                               cl::desc("Check Objective-C Runtime Hook"));
static thread_local bool CheckObjectiveCRuntimeHookTemp = true;
static cl::alias
    CheckObjectiveCRuntimeHookAlias1("ah-objcruntime",
                                     cl::desc("Alias for -ah_objcruntime"),
                                     cl::aliasopt(CheckObjectiveCRuntimeHook));
static cl::alias
    CheckObjectiveCRuntimeHookAlias2("ah_objc",
                                     cl::desc("Alias for -ah_objcruntime"),
                                     cl::aliasopt(CheckObjectiveCRuntimeHook));

static cl::opt<bool> AntiRebindSymbol("ah_antirebind", cl::init(false),
                                      cl::NotHidden,
                                      cl::desc("Make fishhook unavailable"));
static thread_local bool AntiRebindSymbolTemp = false;
static cl::alias AntiRebindSymbolAlias("ah-antirebind",
                                       cl::desc("Alias for -ah_antirebind"),
                                       cl::aliasopt(AntiRebindSymbol));

static cl::opt<bool>
    CheckInlineHookX86("ah_inline_x86", cl::init(true), cl::NotHidden,
                       cl::desc("[AntiHook]Check Inline Hook for x86_64"));
static thread_local bool CheckInlineHookX86Temp = true;
static cl::alias CheckInlineHookX86Alias("ah-inline-x86",
                                         cl::desc("Alias for -ah_inline_x86"),
                                         cl::aliasopt(CheckInlineHookX86));

static cl::opt<bool> DirectSyscallExit(
    "ah_direct_syscall", cl::init(true), cl::NotHidden,
    cl::desc("[AntiHook]Use direct syscall (not libc abort) "
             "as hook-detected handler — bypasses libc hooks"));
static thread_local bool DirectSyscallExitTemp = true;
static cl::alias
    DirectSyscallExitAlias("ah-direct-syscall",
                           cl::desc("Alias for -ah_direct_syscall"),
                           cl::aliasopt(DirectSyscallExit));

// ── Windows-specific options
// ──────────────────────────────────────────────────
static cl::opt<bool> CheckInlineHookWin(
    "ah_inline_win", cl::init(true), cl::NotHidden,
    cl::desc("[AntiHook]Check Windows-specific prologue hook "
             "patterns (Detours INT3, MOV EDI EDI, etc.)"));
static thread_local bool CheckInlineHookWinTemp = true;
static cl::alias CheckInlineHookWinAlias("ah-inline-win",
                                         cl::desc("Alias for -ah_inline_win"),
                                         cl::aliasopt(CheckInlineHookWin));

// ── Embedded Integrity Self-Check with Anti-Patching Data-Flow Entanglement
static cl::opt<bool>
    CheckIntegrity("ah_integrity", cl::init(true), cl::NotHidden,
                   cl::desc("[AntiHook] Embedded Code Integrity Self-Check "
                            "with Data-Flow Entanglement"));
static thread_local bool CheckIntegrityTemp = true;
static cl::alias CheckIntegrityAlias("ah-integrity",
                                     cl::desc("Alias for -ah_integrity"),
                                     cl::aliasopt(CheckIntegrity));

namespace llvm {
struct AntiHook : public ModulePass {
  static char ID;
  bool flag;
  bool initialized;
  bool opaquepointers;
  Triple triple;
  AntiHook() : ModulePass(ID) {
    this->flag = true;
    this->initialized = false;
  }
  AntiHook(bool flag) : ModulePass(ID) {
    this->flag = flag;
    this->initialized = false;
  }
  StringRef getPassName() const override { return "AntiHook"; }

  bool initialize(Module &M) {
    this->triple = Triple(M.getTargetTriple());
    if (PreCompiledIRPath == "") {
      if (GObfConfig.passes.anti_hook.precompiled_ir_path.has_value() &&
          !GObfConfig.passes.anti_hook.precompiled_ir_path->empty()) {
        PreCompiledIRPath = *GObfConfig.passes.anti_hook.precompiled_ir_path;
      } else if (const char *env = getenv("ENSIA_PRECOMPILED_AH")) {
        PreCompiledIRPath = env;
      } else if (const char *env2 = getenv("AH_IR_PATH")) {
        PreCompiledIRPath = env2;
      } else {
        SmallString<32> Path;
        if (sys::path::home_directory(Path)) {
          sys::path::append(Path, "Ensia");
          sys::path::append(
              Path, "PrecompiledAntiHooking-" +
                        Triple::getArchTypeName(triple.getArch()) + "-" +
                        Triple::getOSTypeName(triple.getOS()) + ".bc");
          PreCompiledIRPath = Path.c_str();
        }
      }
    }
    std::ifstream f(PreCompiledIRPath);
    if (f.good()) {
      errs() << "Linking PreCompiled AntiHooking IR From:" << PreCompiledIRPath
             << "\n";
      SMDiagnostic SMD;
      std::unique_ptr<Module> ADBM(
          parseIRFile(StringRef(PreCompiledIRPath), SMD, M.getContext()));
      Linker::linkModules(M, std::move(ADBM), Linker::Flags::OverrideFromSrc);
    } else {
      if (ObfVerbose)
        errs() << "Notice: PreCompiled AntiHooking IR not found at:"
               << PreCompiledIRPath
               << " (using embedded self-check & direct syscalls)\n";
    }
    opaquepointers = true;
    this->initialized = true;

    if (triple.getVendor() == Triple::VendorType::Apple &&
        StructType::getTypeByName(M.getContext(), "struct._objc_method")) {
      // Use opaque pointer type for all ObjC API declarations
      Type *OpaquePtrTy = getOpaquePtrTy(M.getContext());
      M.getOrInsertFunction(
          "objc_getClass",
          FunctionType::get(OpaquePtrTy, {OpaquePtrTy}, false));
      M.getOrInsertFunction(
          "sel_registerName",
          FunctionType::get(OpaquePtrTy, {OpaquePtrTy}, false));
      FunctionType *IMPType =
          FunctionType::get(OpaquePtrTy, {OpaquePtrTy, OpaquePtrTy}, true);
      PointerType *IMPPointerType = PointerType::getUnqual(IMPType);
      M.getOrInsertFunction(
          "method_getImplementation",
          FunctionType::get(IMPPointerType,
                            {PointerType::getUnqual(StructType::getTypeByName(
                                M.getContext(), "struct._objc_method"))},
                            false));
      M.getOrInsertFunction(
          "class_getInstanceMethod",
          FunctionType::get(PointerType::getUnqual(StructType::getTypeByName(
                                M.getContext(), "struct._objc_method")),
                            {OpaquePtrTy, OpaquePtrTy}, false));
      M.getOrInsertFunction(
          "class_getClassMethod",
          FunctionType::get(PointerType::getUnqual(StructType::getTypeByName(
                                M.getContext(), "struct._objc_method")),
                            {OpaquePtrTy, OpaquePtrTy}, false));
    }
    return true;
  }

  bool runOnModule(Module &M) override {
    SmallVector<Function *, 16> protectedFuncs;
    for (Function &F : M) {
      auto ec = GObfConfig.resolve(M.getSourceFileName(), F.getName());
      bool shouldObf = ec.anti_hook.enabled.value_or(flag);
      if (toObfuscate(shouldObf, &F, "antihook")) {
        if (triple.getArch() == Triple::x86_64)
          F.addFnAttr(Attribute::NoRedZone);
        if (ObfVerbose)
          errs() << "Running AntiHooking On " << F.getName() << "\n";
        if (!this->initialized)
          initialize(M);
        if (!toObfuscateBoolOption(&F, "ah_inline", &CheckInlineHookTemp))
          CheckInlineHookTemp =
              ec.anti_hook.inline_aarch64.value_or((bool)CheckInlineHook);
        if (!toObfuscateBoolOption(&F, "ah_direct_syscall",
                                   &DirectSyscallExitTemp))
          DirectSyscallExitTemp =
              ec.anti_hook.direct_syscall.value_or((bool)DirectSyscallExit);
        if (!toObfuscateBoolOption(&F, "ah_inline_x86",
                                   &CheckInlineHookX86Temp))
          CheckInlineHookX86Temp =
              ec.anti_hook.inline_x86.value_or((bool)CheckInlineHookX86);

        bool didInlineHook = false;
        // AArch64 inline hook detection (covers Darwin + Linux)
        if (triple.isAArch64() && !triple.isOSWindows() &&
            CheckInlineHookTemp) {
          HandleInlineHookAArch64(&F);
          didInlineHook = true;
        }
        // x86_64 inline hook detection (Darwin / Linux)
        if (triple.getArch() == Triple::x86_64 && !triple.isOSWindows() &&
            CheckInlineHookX86Temp) {
          HandleInlineHookX86_64(&F);
          didInlineHook = true;
        }
        // Windows inline hook detection (x86_64 and AArch64)
        if (!toObfuscateBoolOption(&F, "ah_inline_win",
                                   &CheckInlineHookWinTemp))
          CheckInlineHookWinTemp =
              ec.anti_hook.inline_win.value_or((bool)CheckInlineHookWin);
        if (triple.isOSWindows() && CheckInlineHookWinTemp) {
          if (triple.getArch() == Triple::x86_64) {
            HandleInlineHookWindows(&F);
            didInlineHook = true;
          } else if (triple.isAArch64()) {
            HandleInlineHookWindowsAArch64(&F);
            didInlineHook = true;
          }
        }
        if (didInlineHook) {
          // Scatter additional hook checks throughout the function body so a
          // patcher cannot defeat detection by patching just the prologue
          // check or jumping directly over entry guards.
          InjectScatteredHookChecks(&F);
        }

        // Embedded Code Integrity Self-Check with Data-Flow Entanglement
        if (!toObfuscateBoolOption(&F, "ah_integrity", &CheckIntegrityTemp))
          CheckIntegrityTemp =
              ec.anti_hook.check_integrity.value_or((bool)CheckIntegrity);
        if (CheckIntegrityTemp && !F.isDeclaration() && !F.empty()) {
          HandleIntegritySelfCheck(&F);
          protectedFuncs.push_back(&F);
        }

        if (!toObfuscateBoolOption(&F, "ah_antirebind", &AntiRebindSymbolTemp))
          AntiRebindSymbolTemp =
              ec.anti_hook.antirebind.value_or((bool)AntiRebindSymbol);
        if (AntiRebindSymbolTemp)
          for (Instruction &I : instructions(F))
            if (isa<CallInst>(&I) || isa<InvokeInst>(&I)) {
              CallSite CS(&I);
              Function *Called = CS.getCalledFunction();
              if (!Called)
                Called = dyn_cast<Function>(
                    CS.getCalledValue()->stripPointerCasts()); // LLVM16+
              if (Called && Called->isDeclaration() &&
                  Called->isExternalLinkage(Called->getLinkage()) &&
                  !Called->isIntrinsic() &&
                  !Called->getName().starts_with("clang.")) {
                GlobalVariable *GV = cast<GlobalVariable>(M.getOrInsertGlobal(
                    ("AntiRebindSymbol_" + Called->getName()).str(),
                    Called->getType()));
                if (!GV->hasInitializer()) {
                  GV->setConstant(true);
                  GV->setInitializer(Called);
                  GV->setLinkage(GlobalValue::LinkageTypes::PrivateLinkage);
                }
                appendToCompilerUsed(M, {GV});
                Value *Load =
                    new LoadInst(GV->getValueType(), GV, Called->getName(), &I);
                Value *BitCasted = BitCastInst::CreateBitOrPointerCast(
                    Load, CS.getCalledValue()->getType(), "", &I); // LLVM16+
                CS.setCalledFunction(BitCasted);
              }
            }
        if (!toObfuscateBoolOption(&F, "ah_objcruntime",
                                   &CheckObjectiveCRuntimeHookTemp))
          CheckObjectiveCRuntimeHookTemp = ec.anti_hook.objc_runtime.value_or(
              (bool)CheckObjectiveCRuntimeHook);
        if (!CheckObjectiveCRuntimeHookTemp)
          continue;
        GlobalVariable *methodListGV = nullptr;
        ConstantStruct *methodStruct = nullptr;
        for (User *U : F.users()) {
          if (opaquepointers)
            if (ConstantStruct *CS = dyn_cast<ConstantStruct>(U))
              if (CS->getType()->getName() == "struct._objc_method")
                methodStruct = CS;
          for (User *U2 : U->users()) {
            if (!opaquepointers)
              if (ConstantStruct *CS = dyn_cast<ConstantStruct>(U2))
                if (CS->getType()->getName() == "struct._objc_method")
                  methodStruct = CS;
            for (User *U3 : U2->users())
              for (User *U4 : U3->users()) {
                if (opaquepointers) {
                  if (U4->getName().starts_with("_OBJC_$_INSTANCE_METHODS") ||
                      U4->getName().starts_with("_OBJC_$_CLASS_METHODS"))
                    methodListGV = dyn_cast<GlobalVariable>(U4);
                } else
                  for (User *U5 : U4->users()) {
                    if (U5->getName().starts_with("_OBJC_$_INSTANCE_METHODS") ||
                        U5->getName().starts_with("_OBJC_$_CLASS_METHODS"))
                      methodListGV = dyn_cast<GlobalVariable>(U5);
                  }
              }
          }
        }
        if (methodListGV && methodStruct) {
          GlobalVariable *SELNameGV = cast<GlobalVariable>(
              methodStruct->getOperand(0)->stripPointerCasts());
          ConstantDataSequential *SELNameCDS =
              cast<ConstantDataSequential>(SELNameGV->getInitializer());
          bool classmethod =
              methodListGV->getName().starts_with("_OBJC_$_CLASS_METHODS");
          std::string classname =
              methodListGV->getName()
                  .substr(strlen(classmethod ? "_OBJC_$_CLASS_METHODS_"
                                             : "_OBJC_$_INSTANCE_METHODS_"))
                  .str();
          std::string selname = SELNameCDS->getAsCString().str();
          HandleObjcRuntimeHook(&F, classname, selname, classmethod);
        }
      }
    }
    if (!protectedFuncs.empty()) {
      BuildIntegrityConstructor(M, protectedFuncs);
    }
    return true;
  }

  // ── AArch64 inline hook detection
  // ───────────────────────────────────────────
  void HandleInlineHookAArch64(Function *F) {
    BasicBlock *A = &(F->getEntryBlock());
    BasicBlock *C = A->splitBasicBlock(A->getFirstNonPHIOrDbgOrLifetime());
    BasicBlock *B =
        BasicBlock::Create(F->getContext(), "HookDetectedHandler", F);
    BasicBlock *Detect2 = BasicBlock::Create(F->getContext(), "", F);
    A->getTerminator()->eraseFromParent();

    IRBuilder<> IRBDetect(A);
    IRBuilder<> IRBDetect2(Detect2);
    IRBuilder<> IRBB(B);

    LLVMContext &Ctx = F->getContext();
    Type *Int64Ty = Type::getInt64Ty(Ctx);
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    Type *PtrTy = getOpaquePtrTy(Ctx);

    // Load first 4-byte instruction from function entry
    Value *FPtrCast = IRBDetect.CreateBitCast(F, PtrTy);
    Value *Load = IRBDetect.CreateLoad(Int32Ty, FPtrCast);
    Value *LS2 = IRBDetect.CreateLShr(Load, ConstantInt::get(Int32Ty, 26));
    Value *ICmpEQ2 = IRBDetect.CreateICmpEQ(
        LS2, ConstantInt::get(Int32Ty, AARCH64_SIGNATURE_B));
    Value *LS3 = IRBDetect.CreateLShr(Load, ConstantInt::get(Int32Ty, 21));
    Value *ICmpEQ3 = IRBDetect.CreateICmpEQ(
        LS3, ConstantInt::get(Int32Ty, AARCH64_SIGNATURE_BRK));
    Value *Or = IRBDetect.CreateOr(ICmpEQ2, ICmpEQ3);
    // Also check for LDR x16/x17, [PC, #8] (Frida/Detours 16-byte trampoline)
    Value *IsLDR16 =
        IRBDetect.CreateICmpEQ(Load, ConstantInt::get(Int32Ty, 0x58000050u));
    Value *IsLDR17 =
        IRBDetect.CreateICmpEQ(Load, ConstantInt::get(Int32Ty, 0x58000051u));
    Value *OrLDR = IRBDetect.CreateOr(IsLDR16, IsLDR17);
    Value *Stage1A64 = IRBDetect.CreateOr(Or, OrLDR);
    IRBDetect.CreateCondBr(Stage1A64, B, Detect2);

    // Check instruction at +4 and +8 for BR pattern
    Value *PTI = IRBDetect2.CreatePtrToInt(F, Int64Ty);
    Value *AddFour = IRBDetect2.CreateAdd(PTI, ConstantInt::get(Int64Ty, 4));
    Value *ITP = IRBDetect2.CreateIntToPtr(AddFour, PtrTy);
    Value *Load2 = IRBDetect2.CreateLoad(Int32Ty, ITP);
    Value *LS4 = IRBDetect2.CreateLShr(Load2, ConstantInt::get(Int32Ty, 10));
    Value *ICmpEQ4 = IRBDetect2.CreateICmpEQ(
        LS4, ConstantInt::get(Int32Ty, AARCH64_SIGNATURE_BR));
    Value *AddEight = IRBDetect2.CreateAdd(PTI, ConstantInt::get(Int64Ty, 8));
    Value *ITP2 = IRBDetect2.CreateIntToPtr(AddEight, PtrTy);
    Value *Load3 = IRBDetect2.CreateLoad(Int32Ty, ITP2);
    Value *LS5 = IRBDetect2.CreateLShr(Load3, ConstantInt::get(Int32Ty, 10));
    Value *ICmpEQ5 = IRBDetect2.CreateICmpEQ(
        LS5, ConstantInt::get(Int32Ty, AARCH64_SIGNATURE_BR));
    Value *Or2 = IRBDetect2.CreateOr(ICmpEQ4, ICmpEQ5);
    IRBDetect2.CreateCondBr(Or2, B, C);
    CreateCallbackAndJumpBack(&IRBB, C);
  }

  void HandleInlineHookX86_64(Function *F) {
    BasicBlock *A = &(F->getEntryBlock());
    BasicBlock *C = A->splitBasicBlock(A->getFirstNonPHIOrDbgOrLifetime());
    BasicBlock *B =
        BasicBlock::Create(F->getContext(), "HookDetectedHandler.x86", F);
    BasicBlock *Detect2 =
        BasicBlock::Create(F->getContext(), "HookDetect2.x86", F);
    BasicBlock *Detect3 =
        BasicBlock::Create(F->getContext(), "HookDetect3.x86", F);
    A->getTerminator()->eraseFromParent();

    LLVMContext &Ctx = F->getContext();
    Type *Int8Ty = Type::getInt8Ty(Ctx);
    Type *Int64Ty = Type::getInt64Ty(Ctx);
    Type *PtrTy = getOpaquePtrTy(Ctx);

    // ── Stage 1: byte[0] in {0xE9 (jmp rel32), 0xEB (jmp rel8), 0xCC (INT3),
    // 0x68 (PUSH imm32), 0xF1 (ICEBP)}
    IRBuilder<> IRBDet1(A);
    Value *FPtr1 = IRBDet1.CreateBitCast(F, PtrTy);
    Value *Byte0 = IRBDet1.CreateLoad(Int8Ty, FPtr1, "ah.b0");
    Value *IsE9 = IRBDet1.CreateICmpEQ(
        Byte0, ConstantInt::get(Int8Ty, X86_64_JMP_REL32), "ah.e9");
    Value *IsEB = IRBDet1.CreateICmpEQ(
        Byte0, ConstantInt::get(Int8Ty, X86_64_JMP_SHORT), "ah.eb");
    Value *IsCC = IRBDet1.CreateICmpEQ(
        Byte0, ConstantInt::get(Int8Ty, X86_64_INT3), "ah.cc");
    Value *Is68 =
        IRBDet1.CreateICmpEQ(Byte0, ConstantInt::get(Int8Ty, 0x68u), "ah.push");
    Value *IsF1 = IRBDet1.CreateICmpEQ(Byte0, ConstantInt::get(Int8Ty, 0xF1u),
                                       "ah.icebp");
    Value *Or1 = IRBDet1.CreateOr(IsE9, IsEB);
    Value *Or2 = IRBDet1.CreateOr(IsCC, Is68);
    Value *Or3 = IRBDet1.CreateOr(Or1, Or2);
    Value *Stage1Match = IRBDet1.CreateOr(Or3, IsF1, "ah.stage1");
    IRBDet1.CreateCondBr(Stage1Match, B, Detect2);

    // ── Stage 2: 2-byte opcode sequences ───────────────────────────────────
    IRBuilder<> IRBDet2(Detect2);
    Value *FPtrI2 = IRBDet2.CreatePtrToInt(F, Int64Ty);
    Value *B0D2 = IRBDet2.CreateLoad(
        Int8Ty, IRBDet2.CreateIntToPtr(FPtrI2, PtrTy), "ah.b0d2");
    Value *B1D2 = IRBDet2.CreateLoad(
        Int8Ty,
        IRBDet2.CreateIntToPtr(
            IRBDet2.CreateAdd(FPtrI2, ConstantInt::get(Int64Ty, 1)), PtrTy),
        "ah.b1d2");
    // 0x48 0xB8 (movabs rax, imm64)
    Value *IsREXW = IRBDet2.CreateICmpEQ(
        B0D2, ConstantInt::get(Int8Ty, X86_64_MOVABS_RAX), "ah.rex");
    Value *IsB8 =
        IRBDet2.CreateICmpEQ(B1D2, ConstantInt::get(Int8Ty, 0xB8u), "ah.b8");
    Value *IsMovAbs = IRBDet2.CreateAnd(IsREXW, IsB8, "ah.movabs");
    // 0x8B 0xFF (mov edi, edi)
    Value *Is8B = IRBDet2.CreateICmpEQ(B0D2, ConstantInt::get(Int8Ty, 0x8Bu));
    Value *IsFF2 = IRBDet2.CreateICmpEQ(B1D2, ConstantInt::get(Int8Ty, 0xFFu));
    Value *IsMovEdi = IRBDet2.CreateAnd(Is8B, IsFF2, "ah.movidi");
    // 0x90 0x90 (NOP sled patch)
    Value *Is90_0 = IRBDet2.CreateICmpEQ(B0D2, ConstantInt::get(Int8Ty, 0x90u));
    Value *Is90_1 = IRBDet2.CreateICmpEQ(B1D2, ConstantInt::get(Int8Ty, 0x90u));
    Value *IsNopSled = IRBDet2.CreateAnd(Is90_0, Is90_1, "ah.nopsled");
    // 0x0F 0x0B (UD2)
    Value *Is0F = IRBDet2.CreateICmpEQ(B0D2, ConstantInt::get(Int8Ty, 0x0Fu));
    Value *Is0B = IRBDet2.CreateICmpEQ(B1D2, ConstantInt::get(Int8Ty, 0x0Bu));
    Value *IsUD2 = IRBDet2.CreateAnd(Is0F, Is0B, "ah.ud2");
    // 0xCD 0x03 (INT 3)
    Value *IsCD = IRBDet2.CreateICmpEQ(B0D2, ConstantInt::get(Int8Ty, 0xCDu));
    Value *Is03 = IRBDet2.CreateICmpEQ(B1D2, ConstantInt::get(Int8Ty, 0x03u));
    Value *IsINT3 = IRBDet2.CreateAnd(IsCD, Is03, "ah.int3");

    Value *M2A = IRBDet2.CreateOr(IsMovAbs, IsMovEdi);
    Value *M2B = IRBDet2.CreateOr(IsNopSled, IsUD2);
    Value *M2C = IRBDet2.CreateOr(M2A, M2B);
    Value *Stage2Match = IRBDet2.CreateOr(M2C, IsINT3, "ah.stage2");
    IRBDet2.CreateCondBr(Stage2Match, B, Detect3);

    // ── Stage 3: byte[0]==0xFF AND byte[1]==0x25 (jmp [RIP+disp32]) ────────
    IRBuilder<> IRBDet3(Detect3);
    Value *FPtrI3 = IRBDet3.CreatePtrToInt(F, Int64Ty);
    Value *B0D3 = IRBDet3.CreateLoad(
        Int8Ty, IRBDet3.CreateIntToPtr(FPtrI3, PtrTy), "ah.b0d3");
    Value *B1D3 = IRBDet3.CreateLoad(
        Int8Ty,
        IRBDet3.CreateIntToPtr(
            IRBDet3.CreateAdd(FPtrI3, ConstantInt::get(Int64Ty, 1)), PtrTy),
        "ah.b1d3");
    Value *IsFF = IRBDet3.CreateICmpEQ(
        B0D3, ConstantInt::get(Int8Ty, X86_64_JMP_INDIR), "ah.ff");
    Value *Is25 = IRBDet3.CreateICmpEQ(
        B1D3, ConstantInt::get(Int8Ty, X86_64_JMP_INDIR_B1), "ah.25");
    Value *IsIndir = IRBDet3.CreateAnd(IsFF, Is25, "ah.indir");
    IRBDet3.CreateCondBr(IsIndir, B, C);

    // Handler
    IRBuilder<> IRBB(B);
    CreateCallbackAndJumpBack(&IRBB, C);
  }

  // ── Windows x86_64 inline hook detection
  // ────────────────────────────────────
  //
  // Detects Microsoft Detours and similar Windows user-space hooks:
  //
  //  Pattern A — INT3 hot-patch (0xCC):
  //    Detours v1.x and many debugging frameworks replace the first byte
  //    with an INT3 breakpoint.  Also used by WinAPI function detours that
  //    work by placing a hardware breakpoint at the entry point.
  //
  //  Pattern B — JMP short (0xEB xx):
  //    Detours v2.x "two-byte NOP" style: MOV EDI,EDI (0x8B 0xFF) replaced
  //    by a JMP short two bytes back into a five-byte hot-patch landing pad.
  //    We detect both (a) the JMP short byte 0xEB and (b) the original
  //    MOV EDI,EDI two-byte sequence that Detours inserts as a pre-hook
  //    placeholder (before patching, used to mark hot-patchable functions).
  //
  //  Pattern C — JMP rel32 (0xE9):
  //    Detours classic five-byte trampoline: first byte patched to 0xE9.
  //
  //  Pattern D — MOV RAX, imm64 + JMP RAX (0x48 0xB8 ... 0xFF 0xE0):
  //    Frida / manual long-jmp stubs on 64-bit.  Detected by checking
  //    byte[0]==0x48, byte[1]==0xB8.
  //
  // The detection generates four basic blocks:
  //   Detect  → checks patterns A and C (INT3 / JMP rel32)
  //   Detect2 → checks pattern B (JMP short or MOV EDI,EDI)
  //   Detect3 → checks pattern D (REX.W MOV RAX imm64)
  //   Handler → termination block (Windows __fastfail)
  //   C       → original entry block (no hook detected)
  void HandleInlineHookWindows(Function *F) {
    BasicBlock *A = &(F->getEntryBlock());
    BasicBlock *C = A->splitBasicBlock(A->getFirstNonPHIOrDbgOrLifetime());
    BasicBlock *B =
        BasicBlock::Create(F->getContext(), "WinHookHandler.x64", F);
    BasicBlock *Det2 =
        BasicBlock::Create(F->getContext(), "WinHookDetect2.x64", F);
    BasicBlock *Det3 =
        BasicBlock::Create(F->getContext(), "WinHookDetect3.x64", F);
    A->getTerminator()->eraseFromParent();

    IRBuilder<> IRBDet1(A);
    IRBuilder<> IRBDet2(Det2);
    IRBuilder<> IRBDet3(Det3);
    IRBuilder<> IRBB(B);

    LLVMContext &Ctx = F->getContext();
    Type *I8Ty = Type::getInt8Ty(Ctx);
    Type *I64Ty = Type::getInt64Ty(Ctx);
    Type *PtrTy = getOpaquePtrTy(Ctx);

    // ── Detect1: byte[0] == 0xCC (INT3) OR 0xE9 (JMP rel32) OR 0xEB (JMP
    // short)
    Value *FPtr = IRBDet1.CreateBitCast(F, PtrTy);
    Value *B0 = IRBDet1.CreateLoad(I8Ty, FPtr, "wh.b0");
    Value *IsCC = IRBDet1.CreateICmpEQ(B0, ConstantInt::get(I8Ty, X86_64_INT3));
    Value *IsE9 =
        IRBDet1.CreateICmpEQ(B0, ConstantInt::get(I8Ty, X86_64_JMP_REL32));
    Value *IsEB =
        IRBDet1.CreateICmpEQ(B0, ConstantInt::get(I8Ty, X86_64_JMP_SHORT));
    Value *IsSusp1 = IRBDet1.CreateOr(IRBDet1.CreateOr(IsCC, IsE9), IsEB);
    IRBDet1.CreateCondBr(IsSusp1, B, Det2);

    // ── Detect2: byte[0:1] == 0x8B 0xFF (MOV EDI, EDI — Detours hot-patch
    // marker)
    Value *FPtrInt = IRBDet2.CreatePtrToInt(F, I64Ty);
    Value *PB0 = IRBDet2.CreateIntToPtr(FPtrInt, PtrTy);
    Value *PB1 = IRBDet2.CreateIntToPtr(
        IRBDet2.CreateAdd(FPtrInt, ConstantInt::get(I64Ty, 1)), PtrTy);
    Value *D2B0 = IRBDet2.CreateLoad(I8Ty, PB0, "wh.d2b0");
    Value *D2B1 = IRBDet2.CreateLoad(I8Ty, PB1, "wh.d2b1");
    Value *Is8B = IRBDet2.CreateICmpEQ(
        D2B0, ConstantInt::get(I8Ty, X86_64_MOV_EDI_EDI_B0));
    Value *IsFF = IRBDet2.CreateICmpEQ(
        D2B1, ConstantInt::get(I8Ty, X86_64_MOV_EDI_EDI_B1));
    Value *IsMEDI = IRBDet2.CreateAnd(Is8B, IsFF);
    IRBDet2.CreateCondBr(IsMEDI, B, Det3);

    // ── Detect3: byte[0]==0x48 && byte[1]==0xB8 (MOV RAX, imm64 — Frida stub)
    Value *D3B0 = IRBDet3.CreateLoad(
        I8Ty, IRBDet3.CreateIntToPtr(FPtrInt, PtrTy), "wh.d3b0");
    Value *D3B1 = IRBDet3.CreateLoad(
        I8Ty,
        IRBDet3.CreateIntToPtr(
            IRBDet3.CreateAdd(FPtrInt, ConstantInt::get(I64Ty, 1)), PtrTy),
        "wh.d3b1");
    Value *IsREXW =
        IRBDet3.CreateICmpEQ(D3B0, ConstantInt::get(I8Ty, X86_64_MOVABS_RAX));
    Value *IsMovAbs = IRBDet3.CreateICmpEQ(D3B1, ConstantInt::get(I8Ty, 0xB8u));
    Value *IsLongStub = IRBDet3.CreateAnd(IsREXW, IsMovAbs);
    IRBDet3.CreateCondBr(IsLongStub, B, C);

    CreateCallbackAndJumpBack(&IRBB, C);
  }

  // ── Windows AArch64 inline hook detection
  // ───────────────────────────────────
  //
  // Detects Detours-style and manual trampolines on ARM64 Windows:
  //
  //  Pattern A — B rel26 (first 6 bits = 0b000101):
  //    Direct branch, same encoding as on Darwin/Linux.
  //
  //  Pattern B — LDR X17, [PC, #8] (encoding = 0x58000051):
  //    Detours on ARM64 Windows uses a 16-byte "long jump" trampoline:
  //      LDR  x17, [pc, #8]   ; load 64-bit target address from +8
  //      BR   x17             ; jump to it
  //      <8 bytes of target address>
  //    The LDR encoding is fixed: 0x58000051 (offset=2, register=x17).
  //
  //  Pattern C — BRK #0 or BRK #1 (software breakpoint):
  //    Some debuggers / anti-tamper tools patch the entry with BRK.
  void HandleInlineHookWindowsAArch64(Function *F) {
    BasicBlock *A = &(F->getEntryBlock());
    BasicBlock *C = A->splitBasicBlock(A->getFirstNonPHIOrDbgOrLifetime());
    BasicBlock *B =
        BasicBlock::Create(F->getContext(), "WinHookHandler.arm64", F);
    BasicBlock *Det2 =
        BasicBlock::Create(F->getContext(), "WinHookDetect2.arm64", F);
    A->getTerminator()->eraseFromParent();

    IRBuilder<> IRBDet1(A);
    IRBuilder<> IRBDet2(Det2);
    IRBuilder<> IRBB(B);

    LLVMContext &Ctx = F->getContext();
    Type *I32Ty = Type::getInt32Ty(Ctx);
    Type *I64Ty = Type::getInt64Ty(Ctx);
    Type *PtrTy = getOpaquePtrTy(Ctx);

    // ── Detect1: load first 4 bytes and check B / BRK patterns
    Value *FPtr = IRBDet1.CreateBitCast(F, PtrTy);
    Value *Instr0 = IRBDet1.CreateLoad(I32Ty, FPtr, "wha.i0");
    // B rel26: top 6 bits == 0b000101
    Value *LS_B = IRBDet1.CreateLShr(Instr0, ConstantInt::get(I32Ty, 26));
    Value *IsB = IRBDet1.CreateICmpEQ(
        LS_B, ConstantInt::get(I32Ty, AARCH64_SIGNATURE_B));
    // BRK: top 11 bits == 0b11010100001 (= AARCH64_SIGNATURE_BRK)
    Value *LS_BRK = IRBDet1.CreateLShr(Instr0, ConstantInt::get(I32Ty, 21));
    Value *IsBRK = IRBDet1.CreateICmpEQ(
        LS_BRK, ConstantInt::get(I32Ty, AARCH64_SIGNATURE_BRK));
    IRBDet1.CreateCondBr(IRBDet1.CreateOr(IsB, IsBRK), B, Det2);

    // ── Detect2: check for LDR X17, [PC, #8] (Detours long-jump first word)
    Value *FPtrInt = IRBDet2.CreatePtrToInt(F, I64Ty);
    Value *Instr0v2 = IRBDet2.CreateLoad(
        I32Ty, IRBDet2.CreateIntToPtr(FPtrInt, PtrTy), "wha.i0v2");
    Value *IsLdrX17 = IRBDet2.CreateICmpEQ(
        Instr0v2, ConstantInt::get(I32Ty, AARCH64_WIN_LDR_X17_PC8));
    IRBDet2.CreateCondBr(IsLdrX17, B, C);

    CreateCallbackAndJumpBack(&IRBB, C);
  }

  // ── ObjC runtime hook detection
  // ─────────────────────────────────────────────
  void HandleObjcRuntimeHook(Function *ObjcMethodImp, std::string classname,
                             std::string selname, bool classmethod) {
    Module *M = ObjcMethodImp->getParent();
    BasicBlock *A = &(ObjcMethodImp->getEntryBlock());
    BasicBlock *C = A->splitBasicBlock(A->getFirstNonPHIOrDbgOrLifetime());
    BasicBlock *B = BasicBlock::Create(A->getContext(), "HookDetectedHandler",
                                       ObjcMethodImp, C);
    A->getTerminator()->eraseFromParent();

    IRBuilder<> IRBA(A);
    IRBuilder<> IRBB(B);

    Type *PtrTy = getOpaquePtrTy(M->getContext());

    Value *GetClass = IRBA.CreateCall(M->getFunction("objc_getClass"),
                                      {IRBA.CreateGlobalString(classname)});
    Value *GetSelector = IRBA.CreateCall(M->getFunction("sel_registerName"),
                                         {IRBA.CreateGlobalString(selname)});
    Value *GetMethod =
        IRBA.CreateCall(M->getFunction(classmethod ? "class_getClassMethod"
                                                   : "class_getInstanceMethod"),
                        {GetClass, GetSelector});
    Value *GetMethodImp = IRBA.CreateCall(
        M->getFunction("method_getImplementation"), {GetMethod});
    // Compare IMP via opaque pointer cast
    Value *IcmpEq =
        IRBA.CreateICmpEQ(IRBA.CreateBitCast(GetMethodImp, PtrTy),
                          ConstantExpr::getBitCast(ObjcMethodImp, PtrTy));
    IRBA.CreateCondBr(IcmpEq, C, B);
    CreateCallbackAndJumpBack(&IRBB, C);
  }

  void CreateCallbackAndJumpBack(IRBuilder<> *IRBB, BasicBlock *C = nullptr) {
    Module *M = C ? C->getModule() : IRBB->GetInsertBlock()->getModule();
    Function *AHCallBack = M->getFunction("AHCallBack");
    if (AHCallBack) {
      IRBB->CreateCall(AHCallBack);
    }
    insertViolentExit(*IRBB, triple);
  }

  // ── Embedded Code Integrity Self-Check with Anti-Patching Data-Flow
  // Entanglement ──
  //
  // Computes a non-linear checksum over the function's own in-memory machine
  // code bytes. The computed checksum is compared with a baseline recorded at
  // startup in a module constructor.
  //
  // ANTI-PATCHING ENTANGLEMENT:
  // Instead of merely branching to an exit on mismatch (which could be patched
  // by inverting a jump or replacing with NOPs), the delta Delta = H_calc ^
  // H_base is mathematically multiplied by a large prime and entangled into the
  // function's downstream computation. If an attacker modifies or hooks the
  // function, Delta != 0, so all downstream arithmetic and return values become
  // completely corrupted garbage even if the crash branch is patched out!
  void HandleIntegritySelfCheck(Function *F) {
    if (F->isDeclaration() || F->empty())
      return;

    BasicBlock *Entry = &(F->getEntryBlock());
    BasicBlock *C = Entry->splitBasicBlock(
        Entry->getFirstNonPHIOrDbgOrLifetime(), "ah.integ.cont");
    BasicBlock *IntegFail = BasicBlock::Create(F->getContext(), "IntegFail", F);
    Entry->getTerminator()->eraseFromParent();

    LLVMContext &Ctx = F->getContext();
    Type *I64Ty = Type::getInt64Ty(Ctx);
    Type *PtrTy = getOpaquePtrTy(Ctx);
    IRBuilder<> IRB(Entry);

    // Load first 16 bytes from F's runtime entry address (2 x 64-bit words) as
    // volatile loads
    Value *FPtrI = IRB.CreatePtrToInt(F, I64Ty, "ah.fptr.i");
    Value *W0 = IRB.CreateLoad(I64Ty, IRB.CreateIntToPtr(FPtrI, PtrTy),
                               /*isVolatile=*/true, "ah.w0");
    Value *W1 = IRB.CreateLoad(
        I64Ty,
        IRB.CreateIntToPtr(IRB.CreateAdd(FPtrI, ConstantInt::get(I64Ty, 8)),
                           PtrTy),
        /*isVolatile=*/true, "ah.w1");

    // Fast non-linear 64-bit mixing (FNV-1a style)
    Value *K1 = ConstantInt::get(I64Ty, 0x517cc1b727220a95ULL);
    Value *K2 = ConstantInt::get(I64Ty, 0x9e3779b97f4a7c15ULL);
    Value *H0 = IRB.CreateXor(W0, K1);
    Value *H1 = IRB.CreateMul(IRB.CreateXor(H0, W1), K2);
    Value *HCalc = IRB.CreateXor(
        H1, IRB.CreateLShr(H1, ConstantInt::get(I64Ty, 27)), "ah.hcalc");

    // Global variable for pristine baseline
    std::string gvName = "__ah_integ_" + F->getName().str();
    GlobalVariable *BaseGV = F->getParent()->getGlobalVariable(gvName);
    if (!BaseGV) {
      BaseGV = new GlobalVariable(*F->getParent(), I64Ty, /*isConstant=*/false,
                                  GlobalValue::InternalLinkage,
                                  ConstantInt::get(I64Ty, 0), gvName);
    }

    Value *HBase =
        IRB.CreateLoad(I64Ty, BaseGV, /*isVolatile=*/true, "ah.hbase");
    // Lazy fallback: if HBase == 0 (e.g. called before constructors run),
    // adopt HCalc so execution continues safely
    Value *IsZero =
        IRB.CreateICmpEQ(HBase, ConstantInt::get(I64Ty, 0), "ah.is_zero");
    Value *EffBase = IRB.CreateSelect(IsZero, HCalc, HBase, "ah.effbase");

    // Calculate delta: Delta == 0 when unpatched
    Value *Delta = IRB.CreateXor(HCalc, EffBase, "ah.delta");

    // ── Anti-Patching Data-Flow Entanglement ──
    Value *Prime = ConstantInt::get(I64Ty, 0xbf58476d1ce4e5b9ULL);
    Value *DeltaScaled = IRB.CreateMul(Delta, Prime, "ah.deltascaled");

    insertOpaqueBarrier(IRB, DeltaScaled);
    GlobalVariable *sinkGV = getOrCreateOpaqueSink(F->getParent());
    if (sinkGV) {
      IRB.CreateStore(DeltaScaled, sinkGV, /*isVolatile=*/true);
    }

    AllocaInst *DeltaScaledSlot =
        IRBuilder<>(&F->getEntryBlock(), F->getEntryBlock().begin())
            .CreateAlloca(I64Ty, nullptr, "ah.deltascaled.slot");
    IRB.CreateStore(DeltaScaled, DeltaScaledSlot);

    // Hardware fault branch
    Value *IsTampered =
        IRB.CreateICmpNE(Delta, ConstantInt::get(I64Ty, 0), "ah.tampered");
    IRB.CreateCondBr(IsTampered, IntegFail, C);

    // Fail handler block
    IRBuilder<> FailIRB(IntegFail);
    insertViolentExit(FailIRB, triple);

    // Dynamic Debug Measurement at prologue
    Instruction *ContPt = &*C->getFirstNonPHIOrDbgOrLifetime();
    Value *DbgToken = getOrCreateDynamicDebugToken(F, ContPt, triple);

    // Anti-Taint Bidirectional Function I/O Entanglement (Schemes 1, 2, 3, 4)
    entangleFunctionIO(F, DbgToken, HCalc, EffBase, ContPt, triple);

    // Entangle into first eligible integer instruction in C
    for (Instruction &Inst : *C) {
      if (Inst.isBinaryOp() && Inst.getType()->isIntegerTy()) {
        Type *ITy = Inst.getType();
        if (ITy->getIntegerBitWidth() <= 64) {
          IRBuilder<> CIRB(C, ++Inst.getIterator());
          Value *LocalDelta =
              CIRB.CreateLoad(I64Ty, DeltaScaledSlot, "ah.deltascaled.load");
          Value *TruncDelta =
              CIRB.CreateZExtOrTrunc(LocalDelta, ITy, "ah.entangle.delta");
          Value *Entangled = CIRB.CreateXor(&Inst, TruncDelta, "ah.entangled");
          Inst.replaceAllUsesWith(Entangled);
          cast<User>(Entangled)->setOperand(0, &Inst);
          break;
        }
      }
    }
  }

  void BuildIntegrityConstructor(Module &M,
                                 const SmallVectorImpl<Function *> &funcs) {
    if (funcs.empty())
      return;
    FunctionType *CtorFTy =
        FunctionType::get(Type::getVoidTy(M.getContext()), false);
    Function *CtorFn = Function::Create(CtorFTy, GlobalValue::InternalLinkage,
                                        "__ah_init_integrity", &M);
    BasicBlock *CtorBB = BasicBlock::Create(M.getContext(), "entry", CtorFn);
    IRBuilder<> CIRB(CtorBB);
    Type *I64Ty = Type::getInt64Ty(M.getContext());
    Type *PtrTy = getOpaquePtrTy(M.getContext());

    Value *K1 = ConstantInt::get(I64Ty, 0x517cc1b727220a95ULL);
    Value *K2 = ConstantInt::get(I64Ty, 0x9e3779b97f4a7c15ULL);

    for (Function *F : funcs) {
      std::string gvName = "__ah_integ_" + F->getName().str();
      GlobalVariable *BaseGV = M.getGlobalVariable(gvName);
      if (!BaseGV)
        continue;

      Value *FPtrI = CIRB.CreatePtrToInt(F, I64Ty);
      Value *W0 = CIRB.CreateLoad(I64Ty, CIRB.CreateIntToPtr(FPtrI, PtrTy),
                                  /*isVolatile=*/true);
      Value *W1 = CIRB.CreateLoad(
          I64Ty,
          CIRB.CreateIntToPtr(CIRB.CreateAdd(FPtrI, ConstantInt::get(I64Ty, 8)),
                              PtrTy),
          /*isVolatile=*/true);

      Value *H0 = CIRB.CreateXor(W0, K1);
      Value *H1 = CIRB.CreateMul(CIRB.CreateXor(H0, W1), K2);
      Value *HClean =
          CIRB.CreateXor(H1, CIRB.CreateLShr(H1, ConstantInt::get(I64Ty, 27)));

      CIRB.CreateStore(HClean, BaseGV, /*isVolatile=*/true);
    }

    CIRB.CreateRetVoid();
    appendToGlobalCtors(M, CtorFn, 0);
  }

  // ── Scattered hook checks ────────────────────────────────────────────────
  //
  // Picks up to 3 non-entry, non-EH basic blocks throughout the function body
  // and inserts in-flight inline hook checks. This catches trampolines that
  // skip the entry prologue check, auditing F[0] and F[1] during function
  // execution.
  //
  // Per scattered injection point:
  //   • Load prologue bytes of the current function's machine code.
  //   • If a hook pattern is detected (jmp/br/brk/indirect/movabs):
  //       → Branch to a shared cold HookHandler.ah.scatter block per function
  //         (eliminating register coalescing explosions in the LLVM backend).
  //   • Otherwise: fall through to the rest of the basic block.
  void InjectScatteredHookChecks(Function *F) {
    if (!triple.isAArch64() && triple.getArch() != Triple::x86_64)
      return;

    // Collect candidate BBs: skip entry, EH pads, address-taken, and
    // handler/detect BBs
    SmallVector<BasicBlock *, 16> cands;
    for (BasicBlock &BB : *F) {
      if (&BB == &F->getEntryBlock())
        continue;
      if (BB.isEHPad() || BB.isLandingPad())
        continue;
      if (BB.hasAddressTaken())
        continue;
      StringRef nm = BB.getName();
      if (nm.contains("HookDetect") || nm.contains("Handler") ||
          nm.contains("scatter") || nm.contains("Integ") ||
          nm.contains("lpad") || nm.contains("eh") || nm.contains("catch") ||
          nm.contains("terminate"))
        continue;
      BasicBlock::iterator firstNonPHIIt = BB.getFirstNonPHIOrDbgOrLifetime();
      if (firstNonPHIIt == BB.end())
        continue;
      Instruction *firstNonPHI = &*firstNonPHIIt;
      if (isa<LandingPadInst>(firstNonPHI) || isa<CatchPadInst>(firstNonPHI) ||
          isa<CleanupPadInst>(firstNonPHI))
        continue;
      Instruction *term = BB.getTerminator();
      if (!term || isa<InvokeInst>(term) || isa<ResumeInst>(term) ||
          isa<CatchSwitchInst>(term) || isa<CatchReturnInst>(term) ||
          isa<CleanupReturnInst>(term))
        continue;
      // Need at least 2 real instructions before terminator
      unsigned instCount = 0;
      for (Instruction &I : BB) {
        if (!isa<PHINode>(&I) && !I.isDebugOrPseudoInst())
          ++instCount;
      }
      if (instCount < 3)
        continue;
      cands.push_back(&BB);
    }
    if (cands.empty())
      return;

    // Fisher-Yates shuffle with cryptoutils for per-compilation randomness
    for (unsigned i = (unsigned)cands.size() - 1; i > 0; --i)
      std::swap(cands[i], cands[cryptoutils->get_range(i + 1)]);

    unsigned numExtra = std::min(3u, (unsigned)cands.size());
    LLVMContext &Ctx = F->getContext();
    Type *Int8Ty = Type::getInt8Ty(Ctx);
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    Type *Int64Ty = Type::getInt64Ty(Ctx);
    Type *PtrTy = getOpaquePtrTy(Ctx);

    BasicBlock *SHandler = nullptr;

    for (unsigned ci = 0; ci < numExtra; ci++) {
      BasicBlock *Orig = cands[ci];
      BasicBlock *Bottom = Orig->splitBasicBlock(
          Orig->getFirstNonPHIOrDbgOrLifetime(), "scatter.ah.bot");
      if (!SHandler) {
        SHandler = BasicBlock::Create(Ctx, "HookHandler.ah.scatter", F);
        IRBuilder<> HB(SHandler);
        CreateCallbackAndJumpBack(&HB, nullptr);
      }

      Orig->getTerminator()->eraseFromParent();
      IRBuilder<> IRB(Orig);
      Value *IsHooked = nullptr;

      if (triple.getArch() == Triple::x86_64) {
        // x86_64 multi-pattern hook detection:
        //  - 0xE9: JMP rel32 (Substrate / MS Detours classic 5-byte hook)
        //  - 0xEB: JMP rel8 (short jump trampoline)
        //  - 0xCC: INT3 (hot-patch / debugger hook trap)
        //  - 0x68: PUSH imm32 (push-ret hook)
        //  - 0xFF 0x25: JMP [RIP+disp32] (canonical Frida/PLT 64-bit indirect
        //  jump)
        //  - 0x48 0xB8: MOVABS RAX, imm64 (Frida / manual 64-bit jump)
        Value *FPtrI = IRB.CreatePtrToInt(F, Int64Ty);
        Value *B0 = IRB.CreateLoad(Int8Ty, IRB.CreateIntToPtr(FPtrI, PtrTy),
                                   "sc.ah.b0");
        Value *IsE9 = IRB.CreateICmpEQ(
            B0, ConstantInt::get(Int8Ty, X86_64_JMP_REL32), "sc.ah.e9");
        Value *IsEB = IRB.CreateICmpEQ(
            B0, ConstantInt::get(Int8Ty, X86_64_JMP_SHORT), "sc.ah.eb");
        Value *IsCC = IRB.CreateICmpEQ(
            B0, ConstantInt::get(Int8Ty, X86_64_INT3), "sc.ah.cc");
        Value *Is68 =
            IRB.CreateICmpEQ(B0, ConstantInt::get(Int8Ty, 0x68u), "sc.ah.push");

        Value *FPtrI_1 = IRB.CreateAdd(FPtrI, ConstantInt::get(Int64Ty, 1));
        Value *B1 = IRB.CreateLoad(Int8Ty, IRB.CreateIntToPtr(FPtrI_1, PtrTy),
                                   "sc.ah.b1");
        Value *IsFF =
            IRB.CreateICmpEQ(B0, ConstantInt::get(Int8Ty, X86_64_JMP_INDIR));
        Value *Is25 =
            IRB.CreateICmpEQ(B1, ConstantInt::get(Int8Ty, X86_64_JMP_INDIR_B1));
        Value *IsFF25 = IRB.CreateAnd(IsFF, Is25, "sc.ah.ff25");

        Value *Is48 =
            IRB.CreateICmpEQ(B0, ConstantInt::get(Int8Ty, X86_64_MOVABS_RAX));
        Value *IsB8 = IRB.CreateICmpEQ(B1, ConstantInt::get(Int8Ty, 0xB8u));
        Value *IsMovAbs = IRB.CreateAnd(Is48, IsB8, "sc.ah.movabs");

        Value *H1 =
            IRB.CreateOr(IRB.CreateOr(IsE9, IsEB), IRB.CreateOr(IsCC, Is68));
        Value *H2 = IRB.CreateOr(IsFF25, IsMovAbs);
        IsHooked = IRB.CreateOr(H1, H2, "sc.ah.hooked");
      } else if (triple.isAArch64()) {
        // AArch64 multi-pattern hook detection:
        //  - B rel26 (canonical direct branch)
        //  - BRK (software breakpoint)
        //  - LDR x16/x17, [PC, #8] (Frida/Detours long-jump trampoline)
        Value *FPtr = IRB.CreateBitCast(F, PtrTy);
        Value *Instr0 = IRB.CreateLoad(Int32Ty, FPtr, "sc.ah.i0");
        Value *LS_B = IRB.CreateLShr(Instr0, ConstantInt::get(Int32Ty, 26));
        Value *IsB = IRB.CreateICmpEQ(
            LS_B, ConstantInt::get(Int32Ty, AARCH64_SIGNATURE_B));
        Value *LS_BRK = IRB.CreateLShr(Instr0, ConstantInt::get(Int32Ty, 21));
        Value *IsBRK = IRB.CreateICmpEQ(
            LS_BRK, ConstantInt::get(Int32Ty, AARCH64_SIGNATURE_BRK));
        Value *IsLDR16 =
            IRB.CreateICmpEQ(Instr0, ConstantInt::get(Int32Ty, 0x58000050u));
        Value *IsLDR17 =
            IRB.CreateICmpEQ(Instr0, ConstantInt::get(Int32Ty, 0x58000051u));
        Value *H1 = IRB.CreateOr(IsB, IsBRK);
        Value *H2 = IRB.CreateOr(IsLDR16, IsLDR17);
        IsHooked = IRB.CreateOr(H1, H2, "sc.ah.hooked");
      }

      if (IsHooked) {
        IRB.CreateCondBr(IsHooked, SHandler, Bottom);
      } else {
        IRB.CreateBr(Bottom);
      }
    }
  }
};
} // namespace llvm

ModulePass *llvm::createAntiHookPass(bool flag) { return new AntiHook(flag); }
char AntiHook::ID = 0;
INITIALIZE_PASS(AntiHook, "antihookobf", "AntiHook", false, false)
