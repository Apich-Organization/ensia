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

// AntiHooking.cpp — hook detection and syscall-based bypass.
//
// OLLVM-Next enhancements:
//  ① x86_64 inline hook detection: scan function prologue for common hooking
//    byte patterns (E9 rel32 jmp, 48 B8 movabs+FF E0 jmp rax) used by
//    Substrate, fishhook, and dylib injectors.
//  ② Direct BSD syscall bypass: exit via `syscall` on x86_64 Darwin and
//    enhanced `svc` on AArch64 Darwin instead of libc abort() — libc is
//    hookable by fishhook, the kernel syscall gate is not.
//  ③ RDTSC-gated noise before syscall to confuse dynamic tracers and timing
//    side-channel analysis.  Multi-stage dual syscall issuance as fallback.
//  ④ LLVM 17+ opaque-pointer compatibility: all getPointerTo() replaced with
//    PointerType::getUnqual(); local getOpaquePtrTy() helper for versioning.
//  ⑤ LLVM 16+ CallSite: getCalledValue() → getCalledOperand() everywhere.

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
#if LLVM_VERSION_MAJOR >= 17
#include "llvm/ADT/SmallString.h"
#include "llvm/TargetParser/Triple.h"
#else
#include "llvm/ADT/Triple.h"
#endif
#include "include/AntiHook.h"
#include "include/CryptoUtils.h"
#include "include/Utils.h"
#include "include/compat/CallSite.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <fstream>
#include <sstream>
#include <iomanip>

// Arm A64 Instruction Set for A-profile architecture 2022-12, Page 56
#define AARCH64_SIGNATURE_B 0b000101
// Arm A64 Instruction Set for A-profile architecture 2022-12, Page 75
#define AARCH64_SIGNATURE_BR 0b1101011000011111000000
// Arm A64 Instruction Set for A-profile architecture 2022-12, Page 79
#define AARCH64_SIGNATURE_BRK 0b11010100001

// x86_64 common hooking opcode prefixes
#define X86_64_JMP_REL32   0xE9u   // jmp rel32 (Substrate / MS Detours classic)
#define X86_64_MOVABS_RAX  0x48u   // REX.W prefix → movabs rax, imm64 + jmp rax
#define X86_64_INT3        0xCCu   // INT3 — Detours hot-patch / debugger trap
#define X86_64_JMP_SHORT   0xEBu   // jmp rel8 — Detours compact trampoline
#define X86_64_MOV_EDI_EDI_B0 0x8Bu // MOV EDI, EDI = 8B FF (Detours 2.x marker)
#define X86_64_MOV_EDI_EDI_B1 0xFFu

// AArch64 Windows Detours-style hook opcodes (16-byte trampoline)
// byte[0:3] can be B rel26 (same as Darwin/Linux) or LDR x17, [pc,#8]
#define AARCH64_WIN_LDR_X17_PC8 0x58000051u // LDR x17, [PC, #8]

using namespace llvm;

// Opaque-pointer-safe helper
static inline Type *getOpaquePtrTy(LLVMContext &Ctx) {
#if LLVM_VERSION_MAJOR >= 17
  return PointerType::getUnqual(Ctx);
#else
  return Type::getInt8Ty(Ctx)->getPointerTo();
#endif
}

static cl::opt<std::string>
    PreCompiledIRPath("adhexrirpath",
                      cl::desc("External Path Pointing To Pre-compiled Anti "
                               "Hooking Handler IR"),
                      cl::value_desc("filename"), cl::init(""));

static cl::opt<bool> CheckInlineHook("ah_inline", cl::init(true), cl::NotHidden,
                                     cl::desc("Check Inline Hook for AArch64"));
static bool CheckInlineHookTemp = true;

static cl::opt<bool>
    CheckObjectiveCRuntimeHook("ah_objcruntime", cl::init(true), cl::NotHidden,
                               cl::desc("Check Objective-C Runtime Hook"));
static bool CheckObjectiveCRuntimeHookTemp = true;

static cl::opt<bool> AntiRebindSymbol("ah_antirebind", cl::init(false),
                                      cl::NotHidden,
                                      cl::desc("Make fishhook unavailable"));
static bool AntiRebindSymbolTemp = false;

// OLLVM-Next new options
static cl::opt<bool>
    CheckInlineHookX86("ah_inline_x86", cl::init(true), cl::NotHidden,
                       cl::desc("[AntiHook]Check Inline Hook for x86_64"));
static bool CheckInlineHookX86Temp = true;

static cl::opt<bool>
    DirectSyscallExit("ah_direct_syscall", cl::init(true), cl::NotHidden,
                      cl::desc("[AntiHook]Use direct syscall (not libc abort) "
                               "as hook-detected handler — bypasses libc hooks"));
static bool DirectSyscallExitTemp = true;

// ── Windows-specific options ──────────────────────────────────────────────────
static cl::opt<bool>
    CheckInlineHookWin("ah_inline_win", cl::init(true), cl::NotHidden,
                       cl::desc("[AntiHook]Check Windows-specific prologue hook "
                                "patterns (Detours INT3, MOV EDI EDI, etc.)"));
static bool CheckInlineHookWinTemp = true;

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
      SmallString<32> Path;
      if (sys::path::home_directory(Path)) {
        sys::path::append(Path, "Ensia");
        sys::path::append(Path,
                          "PrecompiledAntiHooking-" +
                              Triple::getArchTypeName(triple.getArch()) + "-" +
                              Triple::getOSTypeName(triple.getOS()) + ".bc");
        PreCompiledIRPath = Path.c_str();
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
      errs() << "Failed To Link PreCompiled AntiHooking IR From:"
             << PreCompiledIRPath << "\n";
    }
#if LLVM_VERSION_MAJOR >= 17
    opaquepointers = true;
#else
    opaquepointers = !M.getContext().supportsTypedPointers();
#endif

    if (triple.getVendor() == Triple::VendorType::Apple &&
        StructType::getTypeByName(M.getContext(), "struct._objc_method")) {
      // Use opaque pointer type for all ObjC API declarations
      Type *OpaquePtrTy = getOpaquePtrTy(M.getContext());
      M.getOrInsertFunction("objc_getClass",
                            FunctionType::get(OpaquePtrTy, {OpaquePtrTy}, false));
      M.getOrInsertFunction("sel_registerName",
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
    for (Function &F : M) {
      if (toObfuscate(flag, &F, "antihook")) {
        if (ObfVerbose) errs() << "Running AntiHooking On " << F.getName() << "\n";
        if (!this->initialized)
          initialize(M);
        if (!toObfuscateBoolOption(&F, "ah_inline", &CheckInlineHookTemp))
          CheckInlineHookTemp = CheckInlineHook;
        if (!toObfuscateBoolOption(&F, "ah_direct_syscall", &DirectSyscallExitTemp))
          DirectSyscallExitTemp = DirectSyscallExit;
        if (!toObfuscateBoolOption(&F, "ah_inline_x86", &CheckInlineHookX86Temp))
          CheckInlineHookX86Temp = CheckInlineHookX86;

        // AArch64 inline hook detection (existing — covers Darwin + Linux)
        if (triple.isAArch64() && !triple.isOSWindows() &&
            CheckInlineHookTemp) {
          HandleInlineHookAArch64(&F);
        }
        // x86_64 inline hook detection (Darwin / Linux)
        if ((triple.getArch() == Triple::x86_64 ||
             triple.getArch() == Triple::x86_64) &&
            !triple.isOSWindows() && CheckInlineHookX86Temp) {
          HandleInlineHookX86_64(&F);
        }
        // Windows inline hook detection (x86_64 and AArch64)
        if (!toObfuscateBoolOption(&F, "ah_inline_win", &CheckInlineHookWinTemp))
          CheckInlineHookWinTemp = CheckInlineHookWin;
        if (triple.isOSWindows() && CheckInlineHookWinTemp) {
          if (triple.getArch() == Triple::x86_64 ||
              triple.getArch() == Triple::x86_64)
            HandleInlineHookWindows(&F);
          else if (triple.isAArch64())
            HandleInlineHookWindowsAArch64(&F);
        }

        if (!toObfuscateBoolOption(&F, "ah_antirebind", &AntiRebindSymbolTemp))
          AntiRebindSymbolTemp = AntiRebindSymbol;
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
#if LLVM_VERSION_MAJOR >= 18
                  !Called->getName().starts_with("clang.")) {
#else
                  !Called->getName().startswith("clang.")) {
#endif
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
          CheckObjectiveCRuntimeHookTemp = CheckObjectiveCRuntimeHook;
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
#if LLVM_VERSION_MAJOR >= 18
                  if (U4->getName().starts_with("_OBJC_$_INSTANCE_METHODS") ||
                      U4->getName().starts_with("_OBJC_$_CLASS_METHODS"))
                    methodListGV = dyn_cast<GlobalVariable>(U4);
                } else
                  for (User *U5 : U4->users()) {
                    if (U5->getName().starts_with("_OBJC_$_INSTANCE_METHODS") ||
                        U5->getName().starts_with("_OBJC_$_CLASS_METHODS"))
#else
                  if (U4->getName().startswith("_OBJC_$_INSTANCE_METHODS") ||
                      U4->getName().startswith("_OBJC_$_CLASS_METHODS"))
                    methodListGV = dyn_cast<GlobalVariable>(U4);
                } else
                  for (User *U5 : U4->users()) {
                    if (U5->getName().startswith("_OBJC_$_INSTANCE_METHODS") ||
                        U5->getName().startswith("_OBJC_$_CLASS_METHODS"))
#endif
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
#if LLVM_VERSION_MAJOR >= 18
              methodListGV->getName().starts_with("_OBJC_$_CLASS_METHODS");
#else
              methodListGV->getName().startswith("_OBJC_$_CLASS_METHODS");
#endif
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
    return true;
  }

  // ── AArch64 inline hook detection ───────────────────────────────────────────
  void HandleInlineHookAArch64(Function *F) {
    BasicBlock *A = &(F->getEntryBlock());
    BasicBlock *C = A->splitBasicBlock(A->getFirstNonPHIOrDbgOrLifetime());
    BasicBlock *B =
        BasicBlock::Create(F->getContext(), "HookDetectedHandler", F);
    BasicBlock *Detect = BasicBlock::Create(F->getContext(), "", F);
    BasicBlock *Detect2 = BasicBlock::Create(F->getContext(), "", F);
    A->getTerminator()->eraseFromParent();
    BranchInst::Create(Detect, A);

    IRBuilder<> IRBDetect(Detect);
    IRBuilder<> IRBDetect2(Detect2);
    IRBuilder<> IRBB(B);

    LLVMContext &Ctx = F->getContext();
    Type *Int64Ty = Type::getInt64Ty(Ctx);
    Type *Int32Ty = Type::getInt32Ty(Ctx);
    Type *PtrTy = getOpaquePtrTy(Ctx); // OLLVM-Next: opaque pointer

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
    IRBDetect.CreateCondBr(Or, B, Detect2);

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

  // ── x86_64 inline hook detection (OLLVM-Next new) ───────────────────────────
  //
  // Detects prologue patches of the form:
  //   E9 xx xx xx xx           jmp rel32       (Substrate/DYLD_INSERT classic)
  //   48 B8 xx..xx FF E0       movabs rax+jmp  (Frida-style long stub)
  //
  // Reads byte[0] and byte[1] of the function prologue via GEP on i8.
  // Branch: if hook detected → HookDetectedHandler; else → original BB.
  void HandleInlineHookX86_64(Function *F) {
    BasicBlock *A = &(F->getEntryBlock());
    BasicBlock *C = A->splitBasicBlock(A->getFirstNonPHIOrDbgOrLifetime());
    BasicBlock *B =
        BasicBlock::Create(F->getContext(), "HookDetectedHandler.x86", F);
    BasicBlock *Detect =
        BasicBlock::Create(F->getContext(), "HookDetect.x86", F);
    BasicBlock *Detect2 =
        BasicBlock::Create(F->getContext(), "HookDetect2.x86", F);
    A->getTerminator()->eraseFromParent();
    BranchInst::Create(Detect, A);

    IRBuilder<> IRBDetect(Detect);
    IRBuilder<> IRBDetect2(Detect2);
    IRBuilder<> IRBB(B);

    LLVMContext &Ctx = F->getContext();
    Type *Int8Ty = Type::getInt8Ty(Ctx);
    Type *Int64Ty = Type::getInt64Ty(Ctx);
    Type *PtrTy = getOpaquePtrTy(Ctx);

    // byte[0] of function
    Value *FPtr = IRBDetect.CreateBitCast(F, PtrTy);
    Value *Byte0 = IRBDetect.CreateLoad(Int8Ty, FPtr, "ah.x86.b0");
    // Check for 0xE9 (jmp rel32)
    Value *IsJmpRel32 = IRBDetect.CreateICmpEQ(
        Byte0, ConstantInt::get(Int8Ty, X86_64_JMP_REL32), "ah.x86.jmp");
    // Check for 0x48 (REX.W prefix, likely movabs rax, imm64)
    Value *IsREXW = IRBDetect.CreateICmpEQ(
        Byte0, ConstantInt::get(Int8Ty, X86_64_MOVABS_RAX), "ah.x86.rex");
    Value *IsSuspect = IRBDetect.CreateOr(IsJmpRel32, IsREXW, "ah.x86.susp");
    IRBDetect.CreateCondBr(IsSuspect, B, Detect2);

    // If REX.W: verify byte[1] == 0xB8 (movabs rax encoding)
    Value *FPtrInt = IRBDetect2.CreatePtrToInt(F, Int64Ty);
    Value *Byte1Ptr = IRBDetect2.CreateIntToPtr(
        IRBDetect2.CreateAdd(FPtrInt, ConstantInt::get(Int64Ty, 1)), PtrTy);
    Value *Byte1 = IRBDetect2.CreateLoad(Int8Ty, Byte1Ptr, "ah.x86.b1");
    Value *IsMovabsRax = IRBDetect2.CreateICmpEQ(
        Byte1, ConstantInt::get(Int8Ty, 0xB8u), "ah.x86.movabs");
    IRBDetect2.CreateCondBr(IsMovabsRax, B, C);

    CreateCallbackAndJumpBack(&IRBB, C);
  }

  // ── Windows x86_64 inline hook detection ────────────────────────────────────
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
    BasicBlock *Det1 =
        BasicBlock::Create(F->getContext(), "WinHookDetect1.x64", F);
    BasicBlock *Det2 =
        BasicBlock::Create(F->getContext(), "WinHookDetect2.x64", F);
    BasicBlock *Det3 =
        BasicBlock::Create(F->getContext(), "WinHookDetect3.x64", F);
    A->getTerminator()->eraseFromParent();
    BranchInst::Create(Det1, A);

    IRBuilder<> IRBDet1(Det1);
    IRBuilder<> IRBDet2(Det2);
    IRBuilder<> IRBDet3(Det3);
    IRBuilder<> IRBB(B);

    LLVMContext &Ctx = F->getContext();
    Type *I8Ty  = Type::getInt8Ty(Ctx);
    Type *I64Ty = Type::getInt64Ty(Ctx);
    Type *PtrTy = getOpaquePtrTy(Ctx);

    // ── Detect1: byte[0] == 0xCC (INT3) OR 0xE9 (JMP rel32) OR 0xEB (JMP short)
    Value *FPtr  = IRBDet1.CreateBitCast(F, PtrTy);
    Value *B0    = IRBDet1.CreateLoad(I8Ty, FPtr, "wh.b0");
    Value *IsCC  = IRBDet1.CreateICmpEQ(B0, ConstantInt::get(I8Ty, X86_64_INT3));
    Value *IsE9  = IRBDet1.CreateICmpEQ(B0, ConstantInt::get(I8Ty, X86_64_JMP_REL32));
    Value *IsEB  = IRBDet1.CreateICmpEQ(B0, ConstantInt::get(I8Ty, X86_64_JMP_SHORT));
    Value *IsSusp1 = IRBDet1.CreateOr(IRBDet1.CreateOr(IsCC, IsE9), IsEB);
    IRBDet1.CreateCondBr(IsSusp1, B, Det2);

    // ── Detect2: byte[0:1] == 0x8B 0xFF (MOV EDI, EDI — Detours hot-patch marker)
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
    Value *D3B0 = IRBDet3.CreateLoad(I8Ty,
        IRBDet3.CreateIntToPtr(FPtrInt, PtrTy), "wh.d3b0");
    Value *D3B1 = IRBDet3.CreateLoad(I8Ty,
        IRBDet3.CreateIntToPtr(
            IRBDet3.CreateAdd(FPtrInt, ConstantInt::get(I64Ty, 1)), PtrTy),
        "wh.d3b1");
    Value *IsREXW   = IRBDet3.CreateICmpEQ(
        D3B0, ConstantInt::get(I8Ty, X86_64_MOVABS_RAX));
    Value *IsMovAbs = IRBDet3.CreateICmpEQ(
        D3B1, ConstantInt::get(I8Ty, 0xB8u));
    Value *IsLongStub = IRBDet3.CreateAnd(IsREXW, IsMovAbs);
    IRBDet3.CreateCondBr(IsLongStub, B, C);

    CreateCallbackAndJumpBack(&IRBB, C);
  }

  // ── Windows AArch64 inline hook detection ───────────────────────────────────
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
    BasicBlock *Det1 =
        BasicBlock::Create(F->getContext(), "WinHookDetect1.arm64", F);
    BasicBlock *Det2 =
        BasicBlock::Create(F->getContext(), "WinHookDetect2.arm64", F);
    A->getTerminator()->eraseFromParent();
    BranchInst::Create(Det1, A);

    IRBuilder<> IRBDet1(Det1);
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
    Value *LS_B  = IRBDet1.CreateLShr(Instr0, ConstantInt::get(I32Ty, 26));
    Value *IsB   = IRBDet1.CreateICmpEQ(
        LS_B, ConstantInt::get(I32Ty, AARCH64_SIGNATURE_B));
    // BRK: top 11 bits == 0b11010100001 (= AARCH64_SIGNATURE_BRK)
    Value *LS_BRK = IRBDet1.CreateLShr(Instr0, ConstantInt::get(I32Ty, 21));
    Value *IsBRK  = IRBDet1.CreateICmpEQ(
        LS_BRK, ConstantInt::get(I32Ty, AARCH64_SIGNATURE_BRK));
    IRBDet1.CreateCondBr(IRBDet1.CreateOr(IsB, IsBRK), B, Det2);

    // ── Detect2: check for LDR X17, [PC, #8] (Detours long-jump first word)
    Value *FPtrInt = IRBDet2.CreatePtrToInt(F, I64Ty);
    Value *Instr0v2 = IRBDet2.CreateLoad(I32Ty,
        IRBDet2.CreateIntToPtr(FPtrInt, PtrTy), "wha.i0v2");
    Value *IsLdrX17 = IRBDet2.CreateICmpEQ(
        Instr0v2, ConstantInt::get(I32Ty, AARCH64_WIN_LDR_X17_PC8));
    IRBDet2.CreateCondBr(IsLdrX17, B, C);

    CreateCallbackAndJumpBack(&IRBB, C);
  }

  // ── ObjC runtime hook detection ─────────────────────────────────────────────
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

    Type *PtrTy = getOpaquePtrTy(M->getContext()); // OLLVM-Next: opaque pointer

    Value *GetClass = IRBA.CreateCall(M->getFunction("objc_getClass"),
                                      {IRBA.CreateGlobalStringPtr(classname)});
    Value *GetSelector = IRBA.CreateCall(M->getFunction("sel_registerName"),
                                         {IRBA.CreateGlobalStringPtr(selname)});
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

  // ── Hook-detected callback + jump back ──────────────────────────────────────
  //
  // OLLVM-Next strategy:
  //  • Custom AHCallBack: use it if linked in.
  //  • Darwin AArch64: multi-stage svc with PRNG-varied immediate.
  //  • Darwin x86_64: direct BSD exit syscall bypassing libc.
  //  • Linux/Android x86_64: prctl(PR_SET_DUMPABLE,0) then UD2 hardware trap.
  //    The UD2 raises SIGILL via the CPU's invalid-opcode exception (#UD), not
  //    via any signal() or raise() call. Core dumps are disabled first to
  //    prevent forensic analysis of the crash state.
  //  • Linux/Android AArch64: prctl then BRK #0xDEAD (SIGTRAP from hw).
  //  • Other targets: libc abort() as fallback.
  //
  // The Linux raw-syscall approach for prctl:
  //   x86_64: SYS_prctl=157, arg0=PR_SET_DUMPABLE=4, arg1=0
  //   arm64:  SYS_prctl=167, same args
  // After prctl, the hardware fault instruction causes an OS signal delivered
  // by the kernel directly from the exception handler — completely bypassing
  // any libc abort/signal infrastructure that a hook could intercept.
  void CreateCallbackAndJumpBack(IRBuilder<> *IRBB, BasicBlock *C) {
    Module *M = C->getModule();
    Function *AHCallBack = M->getFunction("AHCallBack");
    if (AHCallBack) {
      IRBB->CreateCall(AHCallBack);
    } else if (DirectSyscallExitTemp && triple.isOSDarwin() &&
               triple.isAArch64()) {
      // ── AArch64 Darwin: direct BSD exit syscall bypass ───────────────────
      // x16=1 → SYS_exit; svc #0x80 is the XNU BSD syscall gate on iOS/macOS.
      // We randomise the svc immediate for pattern uniqueness (any non-reserved
      // immediate triggers SIGILL on macOS if the kernel rejects it, achieving
      // abort semantics via a different exception path).
      //
      // Noise: eor x9, x9, x9 + add/sub round-trip (net zero, confuses LLIL).
      uint32_t noiseImm = cryptoutils->get_range(1, 0x1000);
      uint32_t exitCode = cryptoutils->get_range(256);
      std::string asmStr;
      // Layer 1: noise to confuse dynamic analysis
      asmStr += "eor x9, x9, x9\n\t";
      asmStr += "add x9, x9, #" + std::to_string(noiseImm) + "\n\t";
      asmStr += "sub x9, x9, #" + std::to_string(noiseImm) + "\n\t";
      // Layer 2: set exit code (randomised for per-compilation uniqueness)
      asmStr += "mov x0, #" + std::to_string(exitCode) + "\n\t";
      // Layer 3: primary syscall — always x16=1 (SYS_exit on Darwin)
      asmStr += "mov x16, #1\n\t";
      asmStr += "svc #0x80\n\t";
      // Layer 4: secondary path with varied immediate (unreachable on success,
      // acts as fallback in emulators that don't model svc correctly)
      asmStr += "mov x16, #1\n\t";
      asmStr += "svc #" + std::to_string(cryptoutils->get_range(0x80, 0x1000)) + "\n\t";
      InlineAsm *IA = InlineAsm::get(
          FunctionType::get(IRBB->getVoidTy(), false),
          asmStr, "~{x0},~{x9},~{x16},~{dirflag},~{fpsr},~{flags}",
          /*hasSideEffects=*/true, false);
      IRBB->CreateCall(IA);
    } else if (DirectSyscallExitTemp && triple.isOSDarwin() &&
               (triple.getArch() == Triple::x86_64 ||
                triple.getArch() == Triple::x86_64)) {
      // ── x86_64 Darwin: direct BSD exit syscall bypass (OLLVM-Next new) ───
      //
      // BSD syscall ABI on macOS x86_64:
      //   rax = 0x2000000 (class 2 = BSD) | syscall_number
      //   SYS_exit = 1  →  rax = 0x2000001
      //   rdi = exit code
      //   `syscall` instruction bypasses the libSystem.B.dylib stub
      //
      // RDTSC inserted as junk timing noise: rdtsc result in edx:eax;
      // the `and` zeroes out eax (affects flags but not program logic).
      uint64_t exitCode = cryptoutils->get_range(256);
      uint64_t noiseConst = cryptoutils->get_uint32_t() & 0xFFFF;
      std::string asmStr;
      // RDTSC noise — execution time jitter confuses timing-based detectors
      asmStr += "rdtsc\n\t";
      asmStr += "andl $$0xFFFF, %eax\n\t"; // consume rdtsc without branching
      asmStr += "addl $$" + std::to_string(noiseConst) + ", %eax\n\t";
      asmStr += "subl $$" + std::to_string(noiseConst) + ", %eax\n\t";
      // Primary syscall: exit(exitCode)
      asmStr += "movq $$0x2000001, %rax\n\t";
      asmStr += "movq $$" + std::to_string(exitCode) + ", %rdi\n\t";
      asmStr += "syscall\n\t";
      // Fallback path (unreachable after successful syscall — present to
      // confuse CFG reconstruction tools that model `syscall` as non-fatal)
      asmStr += "movq $$0x2000001, %rax\n\t";
      asmStr += "xorq %rdi, %rdi\n\t";
      asmStr += "syscall\n\t";
      InlineAsm *IA = InlineAsm::get(
          FunctionType::get(IRBB->getVoidTy(), false),
          asmStr,
          "~{rax},~{rdi},~{rcx},~{rdx},~{dirflag},~{fpsr},~{flags}",
          /*hasSideEffects=*/true, false, InlineAsm::AD_ATT);
      IRBB->CreateCall(IA);
    } else if (DirectSyscallExitTemp &&
               (triple.isOSLinux() || triple.isAndroid()) &&
               (triple.getArch() == Triple::x86_64 ||
                triple.getArch() == Triple::x86_64)) {
      // ── Linux/Android x86_64: prctl + UD2 hardware fault ─────────────────
      //
      // Step 1: prctl(PR_SET_DUMPABLE, 0)  — raw syscall, no libc.
      //   rax=157 (SYS_prctl), rdi=4 (PR_SET_DUMPABLE), rsi=0
      //   This prevents the kernel from writing a core dump file, removing
      //   any forensic artifact from the fault that follows.
      //
      // Step 2: ud2 — x86 "Undefined Instruction" (opcode 0F 0B).
      //   The CPU raises #UD (Invalid Opcode Exception), the kernel delivers
      //   SIGILL to the process. No libc function is ever called; a hook on
      //   raise()/abort()/signal() cannot intercept this path.
      //
      // Noise: RDTSC-based junk between prctl and ud2 to break timing tracers.
      uint64_t noiseK = cryptoutils->get_uint32_t() & 0xFFFF;
      std::string asmStr;
      // RDTSC noise burst
      asmStr += "rdtsc\n\t";
      asmStr += "andl $$0xFFFF, %eax\n\t";
      asmStr += "addl $$" + std::to_string(noiseK) + ", %eax\n\t";
      asmStr += "subl $$" + std::to_string(noiseK) + ", %eax\n\t";
      // prctl(PR_SET_DUMPABLE=4, 0) — prevents core dump
      asmStr += "movq $$157, %rax\n\t";  // SYS_prctl
      asmStr += "movq $$4, %rdi\n\t";    // PR_SET_DUMPABLE
      asmStr += "xorq %rsi, %rsi\n\t";   // 0 = not dumpable
      asmStr += "xorq %rdx, %rdx\n\t";
      asmStr += "xorq %r10, %r10\n\t";
      asmStr += "syscall\n\t";
      // Hardware trap: #UD → SIGILL (not interceptable via libc hooks)
      asmStr += "ud2\n\t";
      // Unreachable fallback: SIGKILL via kill(getpid(), SIGKILL)
      asmStr += "movq $$39, %rax\n\t";   // SYS_getpid
      asmStr += "syscall\n\t";
      asmStr += "movq %rax, %rdi\n\t";   // pid
      asmStr += "movq $$9, %rsi\n\t";    // SIGKILL
      asmStr += "movq $$62, %rax\n\t";   // SYS_kill
      asmStr += "syscall\n\t";
      InlineAsm *IA = InlineAsm::get(
          FunctionType::get(IRBB->getVoidTy(), false),
          asmStr,
          "~{rax},~{rdi},~{rsi},~{rdx},~{r10},~{rcx},~{dirflag},~{fpsr},~{flags}",
          /*hasSideEffects=*/true, false, InlineAsm::AD_ATT);
      IRBB->CreateCall(IA);

    } else if (DirectSyscallExitTemp && triple.isOSWindows() &&
               (triple.getArch() == Triple::x86_64 ||
                triple.getArch() == Triple::x86_64)) {
      // ── Windows x86_64: __fastfail(FAST_FAIL_FATAL_APP_EXIT) ─────────────
      //
      // `int 0x29` is the Windows Kernel Fast Fail mechanism, architecturally
      // defined since Windows 8 / Server 2012.  ECX holds the fail-fast code.
      // FAST_FAIL_FATAL_APP_EXIT = 7.
      //
      // Properties that make this superior to TerminateProcess or abort():
      //   • Bypasses ALL user-space VEH / SEH exception handlers — the kernel
      //     handles the interrupt directly.
      //   • Cannot be intercepted by a DLL-injection hook on any user-mode API.
      //   • Not present in any symbol table as "a way to exit a process",
      //     so pattern scanners won't flag it.
      //   • The RDTSC noise before the int 0x29 confuses timing-based tracers.
      uint64_t noiseK = cryptoutils->get_uint32_t() & 0xFFFF;
      uint64_t fastFailCode = 7; // FAST_FAIL_FATAL_APP_EXIT
      std::string asmStr;
      // RDTSC jitter
      asmStr += "rdtsc\n\t";
      asmStr += "andl $$0xFFFF, %eax\n\t";
      asmStr += "addl $$" + std::to_string(noiseK) + ", %eax\n\t";
      asmStr += "subl $$" + std::to_string(noiseK) + ", %eax\n\t";
      // __fastfail: load fail-fast code into ECX, then int 0x29
      asmStr += "movl $$" + std::to_string(fastFailCode) + ", %ecx\n\t";
      asmStr += "int $$0x29\n\t";
      // Unreachable fallback — makes CFG reconstruction harder
      asmStr += "movl $$" +
                std::to_string(cryptoutils->get_range(1, 15)) + ", %ecx\n\t";
      asmStr += "int $$0x29\n\t";
      InlineAsm *IA = InlineAsm::get(
          FunctionType::get(IRBB->getVoidTy(), false),
          asmStr,
          "~{rax},~{rcx},~{rdx},~{dirflag},~{fpsr},~{flags}",
          /*hasSideEffects=*/true, false, InlineAsm::AD_ATT);
      IRBB->CreateCall(IA);

    } else if (DirectSyscallExitTemp && triple.isOSWindows() &&
               triple.isAArch64()) {
      // ── Windows AArch64: __fastfail via BRK #0xF003 ──────────────────────
      //
      // Windows ARM64 ABI for __fastfail:
      //   W16 = fail-fast code (FAST_FAIL_FATAL_APP_EXIT = 7)
      //   BRK #0xF003
      //
      // The BRK instruction causes a synchronous exception that the kernel
      // routes through the fast-fail path when W16 carries a valid code.
      // Like int 0x29 on x86_64, this bypasses all user-space exception
      // handling including VEH and C++ catch handlers.
      uint32_t noiseImm = cryptoutils->get_range(1, 0x100);
      std::string asmStr;
      // Timer-counter noise: always accessible in EL0 on Windows ARM64
      asmStr += "mrs x9, cntvct_el0\n\t";
      asmStr += "add x9, x9, #" + std::to_string(noiseImm) + "\n\t";
      asmStr += "sub x9, x9, #" + std::to_string(noiseImm) + "\n\t";
      // __fastfail(FAST_FAIL_FATAL_APP_EXIT=7)
      asmStr += "mov w16, #7\n\t";
      asmStr += "brk #0xF003\n\t";
      // Unreachable secondary: different fail-fast code for CFG noise
      asmStr += "mov w16, #" + std::to_string(cryptoutils->get_range(1,15)) + "\n\t";
      asmStr += "brk #0xF003\n\t";
      InlineAsm *IA = InlineAsm::get(
          FunctionType::get(IRBB->getVoidTy(), false),
          asmStr,
          "~{x9},~{x16},~{dirflag},~{fpsr},~{flags}",
          /*hasSideEffects=*/true, false);
      IRBB->CreateCall(IA);

    } else if (DirectSyscallExitTemp &&
               (triple.isOSLinux() || triple.isAndroid()) &&
               triple.isAArch64()) {
      // ── Linux/Android AArch64: prctl + BRK hardware fault ────────────────
      //
      // Step 1: prctl(PR_SET_DUMPABLE, 0)
      //   x8=167 (SYS_prctl on arm64), x0=4 (PR_SET_DUMPABLE), x1=0
      //
      // Step 2: brk #0xDEAD
      //   AArch64 BRK generates a synchronous exception (ESR_EL1.EC=0x3c),
      //   the kernel delivers SIGTRAP. Combined with the prctl, no core dump
      //   is produced and no libc hook can intercept the delivery path.
      //
      // Noise: counter register read (mrs x9, cntvct_el0) as timing junk.
      uint32_t noiseImm = cryptoutils->get_range(1, 0x200);
      std::string asmStr;
      // Timer-register noise
      asmStr += "mrs x9, cntvct_el0\n\t";
      asmStr += "add x9, x9, #" + std::to_string(noiseImm) + "\n\t";
      asmStr += "sub x9, x9, #" + std::to_string(noiseImm) + "\n\t";
      // prctl(PR_SET_DUMPABLE, 0)
      asmStr += "mov x8, #167\n\t";   // SYS_prctl (arm64 Linux)
      asmStr += "mov x0, #4\n\t";     // PR_SET_DUMPABLE
      asmStr += "mov x1, #0\n\t";     // not dumpable
      asmStr += "mov x2, #0\n\t";
      asmStr += "mov x3, #0\n\t";
      asmStr += "mov x4, #0\n\t";
      asmStr += "svc #0\n\t";
      // Hardware trap: BRK → SIGTRAP via kernel exception handler
      asmStr += "brk #0xDEAD\n\t";
      // Unreachable: SIGKILL via kill(getpid(), 9)
      asmStr += "mov x8, #172\n\t";   // SYS_getpid (arm64)
      asmStr += "svc #0\n\t";
      asmStr += "mov x1, #9\n\t";     // SIGKILL
      asmStr += "mov x8, #129\n\t";   // SYS_kill (arm64)
      asmStr += "svc #0\n\t";
      InlineAsm *IA = InlineAsm::get(
          FunctionType::get(IRBB->getVoidTy(), false),
          asmStr,
          "~{x0},~{x1},~{x2},~{x3},~{x4},~{x8},~{x9},~{dirflag},~{fpsr},~{flags}",
          /*hasSideEffects=*/true, false);
      IRBB->CreateCall(IA);

    } else {
      // Fallback: libc abort() — hookable but portable
      FunctionType *ABFT =
          FunctionType::get(Type::getVoidTy(M->getContext()), false);
      Function *abort_declare =
          cast<Function>(M->getOrInsertFunction("abort", ABFT).getCallee());
      abort_declare->addFnAttr(Attribute::AttrKind::NoReturn);
      IRBB->CreateCall(abort_declare);
    }
    IRBB->CreateBr(C);
  }
};
} // namespace llvm

ModulePass *llvm::createAntiHookPass(bool flag) { return new AntiHook(flag); }
char AntiHook::ID = 0;
INITIALIZE_PASS(AntiHook, "antihook", "AntiHook", false, false)
