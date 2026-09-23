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

#include "include/AntiClassDump.h"
#include "include/CryptoUtils.h"
#include "include/ObfConfig.h"
#include "include/Utils.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <algorithm>
#include <deque>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <vector>

using namespace llvm;

// Opaque-pointer-safe helper (same pattern as IndirectBranch / AntiHooking)
static inline Type *getOpaquePtrTy(LLVMContext &Ctx) {
  return PointerType::getUnqual(Ctx);
}

static cl::opt<bool>
    UseInitialize("acd-use-initialize", cl::init(true), cl::NotHidden,
                  cl::desc("[AntiClassDump]Inject codes to +initialize"));
static cl::opt<bool>
    RenameMethodIMP("acd-rename-methodimp", cl::init(false), cl::NotHidden,
                    cl::desc("[AntiClassDump]Rename methods imp"));

static cl::opt<bool> ScrambleMethodOrder(
    "acd-scramble-methods", cl::init(false), cl::NotHidden,
    cl::desc("[AntiClassDump]Shuffle ObjC method list order "
             "to defeat sequential class-dump enumeration"));
static cl::opt<bool>
    InjectDummySelectors("acd-dummy-selectors", cl::init(false), cl::NotHidden,
                         cl::desc("[AntiClassDump]Register ghost selectors at "
                                  "+initialize time to flood selector table"));
static cl::opt<uint32_t> DummySelectorCount(
    "acd-dummy-count", cl::init(8), cl::NotHidden,
    cl::desc("[AntiClassDump]Number of ghost selectors to inject "
             "(default 8)"));

static cl::opt<bool> EncryptStrings(
    "acd-encrypt-strings", cl::init(true), cl::NotHidden,
    cl::desc("[AntiClassDump]Dynamically decrypt selector and "
             "class names at runtime to eliminate plaintext metadata"));

static cl::opt<bool>
    AntiHookRuntime("acd-anti-hook", cl::init(true), cl::NotHidden,
                    cl::desc("[AntiClassDump]Detect Frida/Substrate hooks on "
                             "class_replaceMethod and sel_registerName"));

static cl::opt<bool>
    OpaqueBarriers("acd-opaque-barriers", cl::init(true), cl::NotHidden,
                   cl::desc("[AntiClassDump]Insert memory barriers on runtime "
                            "pointers to foil SMT/lifters"));

// Realistic security-themed decoy selectors for honeypot injection
static const char *kRealisticDecoySelectors[] = {
    "_validateAppReceiptStatus:error:",
    "_decryptSecurePayloadWithKey:iv:",
    "_verifyCertificateChain:withPolicy:",
    "_checkJailbreakEnvironmentSandboxed:",
    "_enforceSecurityPolicyStrict:",
    "_isDebuggerAttachedKernelCheck",
    "_computeHMACSHA256:key:output:",
    "_deviceFingerprintHardwareID",
    "_sharedLicenseManagerInstance",
    "_auditDynamicSymbolTableIntegrity:",
    "_authenticateSessionToken:expiryTimestamp:",
    "_validateExecutableCodeSignature:"};

struct EffectiveAcdConfig {
  bool use_initialize = true;
  bool rename_methodimp = false;
  bool scramble_methods = false;
  bool dummy_selectors = false;
  uint32_t dummy_count = 8;
  bool encrypt_strings = true;
  bool anti_hook = true;
  bool opaque_barriers = true;
};

namespace llvm {
struct AntiClassDump : public ModulePass {
  static char ID;
  bool appleptrauth;
  bool opaquepointers;
  Triple triple;
  AntiClassDump() : ModulePass(ID) {}
  StringRef getPassName() const override { return "AntiClassDump"; }

  bool doInitialization(Module &M) override {
    triple = Triple(M.getTargetTriple());
    if (triple.getVendor() != Triple::VendorType::Apple) {
      errs()
          << M.getTargetTriple().str()
          << " is Not Supported For LLVM AntiClassDump\nProbably GNU Step?\n";
      return false;
    }
    Type *OpaquePtrTy = getOpaquePtrTy(M.getContext());
    FunctionType *IMPType =
        FunctionType::get(OpaquePtrTy, {OpaquePtrTy, OpaquePtrTy}, true);
    PointerType *IMPPointerType = PointerType::getUnqual(IMPType);
    FunctionType *class_replaceMethod_type = FunctionType::get(
        IMPPointerType, {OpaquePtrTy, OpaquePtrTy, IMPPointerType, OpaquePtrTy},
        false);
    M.getOrInsertFunction("class_replaceMethod", class_replaceMethod_type);
    FunctionType *sel_registerName_type =
        FunctionType::get(OpaquePtrTy, {OpaquePtrTy}, false);
    M.getOrInsertFunction("sel_registerName", sel_registerName_type);
    FunctionType *objc_getClass_type =
        FunctionType::get(OpaquePtrTy, {OpaquePtrTy}, false);
    M.getOrInsertFunction("objc_getClass", objc_getClass_type);
    M.getOrInsertFunction("objc_getMetaClass", objc_getClass_type);
    FunctionType *class_getName_Type =
        FunctionType::get(OpaquePtrTy, {OpaquePtrTy}, false);
    M.getOrInsertFunction("class_getName", class_getName_Type);
    appleptrauth = hasApplePtrauth(&M);
    opaquepointers = true;
    return true;
  }

  bool runOnModule(Module &M) override {
    if (ObfVerbose)
      errs() << "Running AntiClassDump On " << M.getSourceFileName() << "\n";

    auto ec = GObfConfig.resolve(M.getSourceFileName(), "");
    EffectiveAcdConfig cfg;
    cfg.use_initialize =
        ec.anti_class_dump.use_initialize.value_or(UseInitialize);
    cfg.rename_methodimp =
        ec.anti_class_dump.rename_methodimp.value_or(RenameMethodIMP);
    cfg.scramble_methods =
        ec.anti_class_dump.scramble_methods.value_or(ScrambleMethodOrder);
    cfg.dummy_selectors =
        ec.anti_class_dump.dummy_selectors.value_or(InjectDummySelectors);
    cfg.dummy_count =
        ec.anti_class_dump.dummy_count.value_or(DummySelectorCount);
    cfg.encrypt_strings =
        ec.anti_class_dump.encrypt_strings.value_or(EncryptStrings);
    cfg.anti_hook = ec.anti_class_dump.anti_hook.value_or(AntiHookRuntime);
    cfg.opaque_barriers =
        ec.anti_class_dump.opaque_barriers.value_or(OpaqueBarriers);

    SmallVector<GlobalVariable *, 32> OLCGVs;
    for (GlobalVariable &GV : M.globals()) {
      if (GV.getName().starts_with("OBJC_LABEL_CLASS_$")) {
        OLCGVs.emplace_back(&GV);
      }
    }
    if (!OLCGVs.size()) {
      errs() << "No ObjC Class Found in :" << M.getSourceFileName() << "\n";
      return false;
    }
    for (GlobalVariable *OLCGV : OLCGVs) {
      ConstantArray *OBJC_LABEL_CLASS_CDS =
          dyn_cast<ConstantArray>(OLCGV->getInitializer());
      assert(OBJC_LABEL_CLASS_CDS &&
             "OBJC_LABEL_CLASS_$ Not ConstantArray. Is the target using "
             "unsupported legacy runtime?");
      SmallVector<std::string, 4> readyclses;
      std::deque<std::string> tmpclses;
      std::unordered_map<std::string, std::string> dependency;
      std::unordered_map<std::string, GlobalVariable *> GVMapping;
      for (unsigned int i = 0; i < OBJC_LABEL_CLASS_CDS->getNumOperands();
           i++) {
        ConstantExpr *clsEXPR =
            opaquepointers
                ? nullptr
                : dyn_cast<ConstantExpr>(OBJC_LABEL_CLASS_CDS->getOperand(i));
        GlobalVariable *CEGV = dyn_cast<GlobalVariable>(
            opaquepointers ? OBJC_LABEL_CLASS_CDS->getOperand(i)
                           : clsEXPR->getOperand(0));
        ConstantStruct *clsCS =
            dyn_cast<ConstantStruct>(CEGV->getInitializer());
        GlobalVariable *SuperClassGV =
            dyn_cast_or_null<GlobalVariable>(clsCS->getOperand(1));
        SuperClassGV = readPtrauth(SuperClassGV);
        std::string supclsName = "";
        std::string clsName = CEGV->getName().str();
        if (size_t pos = clsName.find("OBJC_CLASS_$_");
            pos != std::string::npos) {
          clsName.replace(pos, strlen("OBJC_CLASS_$_"), "");
        }
        if (SuperClassGV) {
          supclsName = SuperClassGV->getName().str();
          if (size_t pos = supclsName.find("OBJC_CLASS_$_");
              pos != std::string::npos) {
            supclsName.replace(pos, strlen("OBJC_CLASS_$_"), "");
          }
        }
        dependency[clsName] = supclsName;
        GVMapping[clsName] = CEGV;
        if (supclsName == "" ||
            (SuperClassGV && !SuperClassGV->hasInitializer())) {
          readyclses.emplace_back(clsName);
        } else {
          tmpclses.emplace_back(clsName);
        }
        while (tmpclses.size()) {
          std::string clstmp = tmpclses.front();
          tmpclses.pop_front();
          std::string SuperClassName = dependency[clstmp];
          if (SuperClassName != "" &&
              std::find(readyclses.begin(), readyclses.end(), SuperClassName) ==
                  readyclses.end()) {
            tmpclses.emplace_back(clstmp);
          } else {
            readyclses.emplace_back(clstmp);
          }
        }
        for (const std::string &className : readyclses) {
          handleClass(GVMapping[className], &M, cfg);
        }
      }
    }
    return true;
  }

  std::unordered_map<std::string, Value *>
  splitclass_ro_t(ConstantStruct *class_ro, Module *M) {
    std::unordered_map<std::string, Value *> info;
    StructType *objc_method_list_t_type =
        StructType::getTypeByName(M->getContext(), "struct.__method_list_t");
    for (unsigned i = 0; i < class_ro->getType()->getNumElements(); i++) {
      Constant *tmp = dyn_cast<Constant>(class_ro->getAggregateElement(i));
      if (!tmp || tmp->isNullValue())
        continue;
      Type *type = tmp->getType();
      if ((!opaquepointers &&
           type == PointerType::getUnqual(objc_method_list_t_type)) ||
          (opaquepointers &&
           (tmp->getName().starts_with("_OBJC_$_INSTANCE_METHODS") ||
            tmp->getName().starts_with("_OBJC_$_CLASS_METHODS")))) {
        GlobalVariable *methodListGV =
            readPtrauth(cast<GlobalVariable>(tmp->stripPointerCasts()));
        if (methodListGV && methodListGV->hasInitializer()) {
          ConstantStruct *methodListStruct =
              cast<ConstantStruct>(methodListGV->getInitializer());
          info["METHODLIST"] =
              cast<ConstantArray>(methodListStruct->getOperand(2));
        }
      }
    }
    return info;
  }

  ConstantArray *scrambleMethodList(ConstantArray *methodList) {
    unsigned n = methodList->getNumOperands();
    if (n < 2)
      return methodList;
    SmallVector<Constant *, 16> methods;
    for (unsigned i = 0; i < n; i++)
      methods.push_back(methodList->getOperand(i));
    // Fisher-Yates shuffle using cryptoutils PRNG
    for (unsigned i = n - 1; i > 0; i--)
      std::swap(methods[i], methods[cryptoutils->get_range(i + 1)]);
    return cast<ConstantArray>(
        ConstantArray::get(methodList->getType(), methods));
  }

  static std::string randomIMPName() {
    std::ostringstream oss;
    oss << "ACDm_";
    oss << std::hex << std::setfill('0') << std::setw(16)
        << cryptoutils->get_uint64_t();
    oss << "_";
    oss << std::hex << std::setfill('0') << std::setw(8)
        << cryptoutils->get_uint32_t();
    return oss.str();
  }

  // ── Dynamic Encrypted String Reconstruction (No Plaintext in .rodata) ──────
  Value *getDecryptedString(IRBuilder<> &IRB, Module &M, StringRef str,
                            const Twine &name, const EffectiveAcdConfig &cfg) {
    if (!cfg.encrypt_strings) {
      return IRB.CreateGlobalString(str, name);
    }

    size_t len = str.size();
    uint8_t key = static_cast<uint8_t>((cryptoutils->get_uint32_t() % 251) + 1);
    uint8_t delta =
        static_cast<uint8_t>((cryptoutils->get_uint32_t() % 127) + 1);

    std::vector<Constant *> encBytes;
    for (size_t i = 0; i <= len; i++) {
      uint8_t orig = (i < len) ? static_cast<uint8_t>(str[i]) : 0;
      uint8_t enc = orig ^ static_cast<uint8_t>(key + i * delta);
      encBytes.push_back(
          ConstantInt::get(Type::getInt8Ty(M.getContext()), enc));
    }

    ArrayType *ArrTy = ArrayType::get(Type::getInt8Ty(M.getContext()), len + 1);
    Constant *ArrInit = ConstantArray::get(ArrTy, encBytes);

    std::string gvName =
        ("_acd_s" + Twine::utohexstr(cryptoutils->get_uint64_t())).str();
    GlobalVariable *EncGV = new GlobalVariable(
        M, ArrTy, true, GlobalValue::PrivateLinkage, ArrInit, gvName);
    EncGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);

    Type *I8Ty = Type::getInt8Ty(M.getContext());
    Type *I64Ty = Type::getInt64Ty(M.getContext());
    Type *PtrTy = getOpaquePtrTy(M.getContext());

    Function *ParentFn = IRB.GetInsertBlock()->getParent();
    IRBuilder<> AllocaIRB(&ParentFn->getEntryBlock(),
                          ParentFn->getEntryBlock().begin());
    AllocaInst *StackBuf = AllocaIRB.CreateAlloca(
        I8Ty, ConstantInt::get(I64Ty, len + 1), "acd.buf");

    for (size_t i = 0; i <= len; i++) {
      Value *IdxVal = ConstantInt::get(I64Ty, i);
      Value *EncGEP = IRB.CreateInBoundsGEP(
          ArrTy, EncGV, {ConstantInt::get(I64Ty, 0), IdxVal});
      Value *EncByte = IRB.CreateLoad(I8Ty, EncGEP, "enc.b");
      uint8_t mask = static_cast<uint8_t>(key + i * delta);
      Value *DecByte =
          IRB.CreateXor(EncByte, ConstantInt::get(I8Ty, mask), "dec.b");
      Value *DestGEP = IRB.CreateInBoundsGEP(I8Ty, StackBuf, IdxVal);
      IRB.CreateStore(DecByte, DestGEP);
    }

    Value *ResPtr = IRB.CreateBitCast(StackBuf, PtrTy);
    if (cfg.opaque_barriers) {
      ResPtr = insertOpaqueBarrier(IRB, ResPtr);
    }
    return ResPtr;
  }

  // ── Runtime Anti-Hooking & Anti-Tracing Guard
  // ───────────────────────────────
  void injectRuntimeAntiHookGuard(IRBuilder<> &IRB, Module &M,
                                  const Triple &targetTriple) {
    Function *crm = M.getFunction("class_replaceMethod");
    Function *srn = M.getFunction("sel_registerName");
    if (!crm || !srn)
      return;

    LLVMContext &Ctx = M.getContext();
    Type *I8Ty = Type::getInt8Ty(Ctx);
    Type *I32Ty = Type::getInt32Ty(Ctx);
    Type *PtrTy = getOpaquePtrTy(Ctx);

    BasicBlock *CurBB = IRB.GetInsertBlock();
    Function *CurFn = CurBB->getParent();
    BasicBlock *HookTrapBB = BasicBlock::Create(Ctx, "acd.hook.trap", CurFn);
    BasicBlock *HookPassBB = BasicBlock::Create(Ctx, "acd.hook.pass", CurFn);

    IRBuilder<> TrapIRB(HookTrapBB);
    insertViolentExit(TrapIRB, targetTriple);
    if (!HookTrapBB->getTerminator())
      TrapIRB.CreateUnreachable();

    Value *IsHooked = ConstantInt::getFalse(Ctx);

    if (targetTriple.isAArch64()) {
      auto checkA64 = [&](Function *F) -> Value * {
        Value *FPtr = IRB.CreateBitCast(F, PtrTy);
        Value *Inst0 = IRB.CreateLoad(I32Ty, FPtr, "acd.ah.i0");
        Value *LS_B = IRB.CreateLShr(Inst0, ConstantInt::get(I32Ty, 26));
        Value *IsB = IRB.CreateICmpEQ(LS_B, ConstantInt::get(I32Ty, 0x05u));
        Value *LS_BRK = IRB.CreateLShr(Inst0, ConstantInt::get(I32Ty, 21));
        Value *IsBRK =
            IRB.CreateICmpEQ(LS_BRK, ConstantInt::get(I32Ty, 0x6A1u));
        Value *IsLdr16 =
            IRB.CreateICmpEQ(Inst0, ConstantInt::get(I32Ty, 0x58000050u));
        Value *IsLdr17 =
            IRB.CreateICmpEQ(Inst0, ConstantInt::get(I32Ty, 0x58000051u));
        return IRB.CreateOr(IRB.CreateOr(IsB, IsBRK),
                            IRB.CreateOr(IsLdr16, IsLdr17));
      };
      Value *H1 = checkA64(crm);
      Value *H2 = checkA64(srn);
      IsHooked = IRB.CreateOr(H1, H2);
    } else if (targetTriple.getArch() == Triple::x86_64) {
      auto checkX64 = [&](Function *F) -> Value * {
        Value *FPtr = IRB.CreateBitCast(F, PtrTy);
        Value *B0 = IRB.CreateLoad(I8Ty, FPtr, "acd.ah.b0");
        Value *IsE9 = IRB.CreateICmpEQ(B0, ConstantInt::get(I8Ty, 0xE9u));
        Value *IsCC = IRB.CreateICmpEQ(B0, ConstantInt::get(I8Ty, 0xCCu));
        Value *IsEB = IRB.CreateICmpEQ(B0, ConstantInt::get(I8Ty, 0xEBu));
        Value *IsFF = IRB.CreateICmpEQ(B0, ConstantInt::get(I8Ty, 0xFFu));
        return IRB.CreateOr(IRB.CreateOr(IsE9, IsCC), IRB.CreateOr(IsEB, IsFF));
      };
      Value *H1 = checkX64(crm);
      Value *H2 = checkX64(srn);
      IsHooked = IRB.CreateOr(H1, H2);
    }

    IRB.CreateCondBr(IsHooked, HookTrapBB, HookPassBB);
    IRB.SetInsertPoint(HookPassBB);
  }

  void handleClass(GlobalVariable *GV, Module *M,
                   const EffectiveAcdConfig &cfg) {
    assert(GV->hasInitializer() &&
           "ObjC Class Structure's Initializer Missing");
    ConstantStruct *CS = dyn_cast<ConstantStruct>(GV->getInitializer());
    StringRef ClassName = GV->getName();
    ClassName = ClassName.substr(strlen("OBJC_CLASS_$_"));
    StringRef SuperClassName = "";
    GlobalVariable *SuperClassGV = readPtrauth(
        dyn_cast<GlobalVariable>(CS->getOperand(1)->stripPointerCasts()));
    if (SuperClassGV) {
      SuperClassName = SuperClassGV->getName();
      if (SuperClassName.starts_with("OBJC_CLASS_$_"))
        SuperClassName = SuperClassName.substr(strlen("OBJC_CLASS_$_"));
    }
    errs() << "Handling Class:" << ClassName
           << " With SuperClass:" << SuperClassName << "\n";

    GlobalVariable *metaclassGV = readPtrauth(
        cast<GlobalVariable>(CS->getOperand(0)->stripPointerCasts()));
    GlobalVariable *class_ro = readPtrauth(
        cast<GlobalVariable>(CS->getOperand(4)->stripPointerCasts()));
    assert(metaclassGV->hasInitializer() && "MetaClass GV Initializer Missing");
    GlobalVariable *metaclass_ro = readPtrauth(cast<GlobalVariable>(
        metaclassGV->getInitializer()
            ->getOperand(metaclassGV->getInitializer()->getNumOperands() - 1)
            ->stripPointerCasts()));
    std::unordered_map<std::string, Value *> Info = splitclass_ro_t(
        cast<ConstantStruct>(metaclass_ro->getInitializer()), M);
    BasicBlock *EntryBB = nullptr;
    if (Info.find("METHODLIST") != Info.end()) {
      ConstantArray *method_list = cast<ConstantArray>(Info["METHODLIST"]);
      for (unsigned i = 0; i < method_list->getNumOperands(); i++) {
        ConstantStruct *methodStruct =
            cast<ConstantStruct>(method_list->getOperand(i));
        GlobalVariable *SELNameGV = cast<GlobalVariable>(
            opaquepointers ? methodStruct->getOperand(0)
                           : methodStruct->getOperand(0)->getOperand(0));
        ConstantDataSequential *SELNameCDS =
            cast<ConstantDataSequential>(SELNameGV->getInitializer());
        StringRef selname = SELNameCDS->getAsCString();
        if ((selname == "initialize" && cfg.use_initialize) ||
            (selname == "load" && !cfg.use_initialize)) {
          Function *IMPFunc = cast<Function>(readPtrauth(cast<GlobalVariable>(
              methodStruct->getOperand(2)->stripPointerCasts())));
          errs() << "Found Existing initializer\n";
          EntryBB = &(IMPFunc->getEntryBlock());
        }
      }
    } else {
      errs() << "Didn't Find ClassMethod List\n";
    }
    bool isNewInitializer = false;
    BasicBlock *OrigContBB = nullptr;
    if (!EntryBB) {
      errs() << "Creating initializer\n";
      FunctionType *InitializerType = FunctionType::get(
          Type::getVoidTy(M->getContext()), ArrayRef<Type *>(), false);
      Function *Initializer = Function::Create(
          InitializerType, GlobalValue::LinkageTypes::PrivateLinkage,
          "AntiClassDumpInitializer", M);
      EntryBB = BasicBlock::Create(M->getContext(), "entry", Initializer);
      isNewInitializer = true;
    } else {
      OrigContBB = EntryBB->splitBasicBlock(EntryBB->getFirstInsertionPt(),
                                            "orig.init.body");
      EntryBB->getTerminator()->eraseFromParent();
    }

    IRBuilder<> IRB(EntryBB);

    // 1. Inject Runtime Anti-Hooking & Anti-Tracing Guard
    if (cfg.anti_hook) {
      injectRuntimeAntiHookGuard(IRB, *M, triple);
    }

    // 2. Resolve Class Pointer
    Function *objc_getClass = M->getFunction("objc_getClass");
    Value *ClassNameVal =
        getDecryptedString(IRB, *M, ClassName, "objc.clsname", cfg);
    Value *Class = IRB.CreateCall(objc_getClass, {ClassNameVal});
    if (cfg.opaque_barriers) {
      Class = insertOpaqueBarrier(IRB, Class);
    }

    // 3. Inject Deceptive Decoy Selectors (Honey-Pot Flooding)
    if (cfg.dummy_selectors) {
      Function *sel_reg = M->getFunction("sel_registerName");
      uint32_t cnt = cfg.dummy_count;
      size_t poolSize = sizeof(kRealisticDecoySelectors) /
                        sizeof(kRealisticDecoySelectors[0]);
      for (uint32_t gi = 0; gi < cnt; gi++) {
        std::string ghostSel;
        if (gi < poolSize) {
          ghostSel = kRealisticDecoySelectors[gi];
        } else {
          std::ostringstream oss;
          oss << "_sec_" << std::hex << cryptoutils->get_uint64_t() << ":";
          ghostSel = oss.str();
        }
        Value *GhostSelVal =
            getDecryptedString(IRB, *M, ghostSel, "ghost.sel", cfg);
        Value *GhostReg = IRB.CreateCall(sel_reg, {GhostSelVal});
        if (cfg.opaque_barriers) {
          GhostReg = insertOpaqueBarrier(IRB, GhostReg);
          GlobalVariable *sinkGV = getOrCreateOpaqueSink(M);
          if (sinkGV) {
            IRB.CreateStore(GhostReg, sinkGV, /*isVolatile=*/true);
          }
        }
      }
    }

    ConstantStruct *metaclassCS =
        cast<ConstantStruct>(class_ro->getInitializer());
    ConstantStruct *classCS =
        cast<ConstantStruct>(metaclass_ro->getInitializer());

    // Helper to safely update class_ro or metaclass_ro method list operand
    // without corrupting LLVMContext's unique constant map
    auto updateClassROMethodList = [](GlobalVariable *roGV,
                                      Constant *newMethodListGV,
                                      bool opaquepointers, Module *Mod) {
      if (!roGV || !roGV->hasInitializer())
        return;
      ConstantStruct *oldCS = dyn_cast<ConstantStruct>(roGV->getInitializer());
      if (!oldCS)
        return;
      SmallVector<Constant *, 16> newElements;
      for (unsigned i = 0; i < oldCS->getNumOperands(); i++) {
        if (i == 5) {
          Constant *bitcastExpr =
              opaquepointers
                  ? newMethodListGV
                  : ConstantExpr::getBitCast(
                        newMethodListGV,
                        PointerType::getUnqual(StructType::getTypeByName(
                            Mod->getContext(), "struct.__method_list_t")));
          newElements.push_back(bitcastExpr);
        } else {
          newElements.push_back(oldCS->getOperand(i));
        }
      }
      Constant *newCS = ConstantStruct::get(oldCS->getType(), newElements);
      roGV->setInitializer(newCS);
    };

    if (!metaclassCS->getAggregateElement(5)->isNullValue()) {
      errs() << "Handling Instance Methods For Class:" << ClassName << "\n";
      HandleMethods(metaclassCS, IRB, M, Class, false, cfg);

      errs() << "Updating Instance Method Map For Class:" << ClassName << "\n";
      Type *objc_method_type =
          StructType::getTypeByName(M->getContext(), "struct._objc_method");
      ArrayType *AT = ArrayType::get(objc_method_type, 0);
      Constant *newMethodList = ConstantArray::get(AT, ArrayRef<Constant *>());
      GlobalVariable *methodListGV = readPtrauth(cast<GlobalVariable>(
          metaclassCS->getAggregateElement(5)->stripPointerCasts()));
      StructType *oldGVType =
          cast<StructType>(methodListGV->getInitializer()->getType());
      SmallVector<Type *, 3> newStructType;
      SmallVector<Constant *, 3> newStructValue;
      newStructType.emplace_back(oldGVType->getElementType(0));
      newStructValue.emplace_back(
          methodListGV->getInitializer()->getAggregateElement(0u));
      newStructType.emplace_back(oldGVType->getElementType(1));
      newStructValue.emplace_back(
          ConstantInt::get(oldGVType->getElementType(1), 0));
      newStructType.emplace_back(AT);
      newStructValue.emplace_back(newMethodList);
      StructType *newType =
          StructType::get(M->getContext(), ArrayRef<Type *>(newStructType));
      Constant *newMethodStruct =
          ConstantStruct::get(newType, ArrayRef<Constant *>(newStructValue));
      GlobalVariable *newMethodStructGV = new GlobalVariable(
          *M, newType, true, GlobalValue::LinkageTypes::PrivateLinkage,
          newMethodStruct, "ACDNewInstanceMethodMap");
      appendToCompilerUsed(*M, {newMethodStructGV});
      newMethodStructGV->copyAttributesFrom(methodListGV);

      updateClassROMethodList(class_ro, newMethodStructGV, opaquepointers, M);

      methodListGV->replaceAllUsesWith(
          opaquepointers ? cast<Constant>(newMethodStructGV)
                         : ConstantExpr::getBitCast(newMethodStructGV,
                                                    methodListGV->getType()));
      methodListGV->eraseFromParent();
      errs() << "Updated Instance Method Map of:" << class_ro->getName()
             << "\n";
    }

    GlobalVariable *methodListGV = nullptr;
    if (!classCS->getAggregateElement(5)->isNullValue()) {
      errs() << "Handling Class Methods For Class:" << ClassName << "\n";
      HandleMethods(classCS, IRB, M, Class, true, cfg);
      methodListGV = readPtrauth(cast<GlobalVariable>(
          classCS->getAggregateElement(5)->stripPointerCasts()));
    }
    errs() << "Updating Class Method Map For Class:" << ClassName << "\n";
    Type *objc_method_type =
        StructType::getTypeByName(M->getContext(), "struct._objc_method");
    ArrayType *AT = ArrayType::get(objc_method_type, 1);
    Constant *MethName = nullptr;
    if (cfg.use_initialize)
      MethName = cast<Constant>(IRB.CreateGlobalString("initialize"));
    else
      MethName = cast<Constant>(IRB.CreateGlobalString("load"));
    Constant *MethType = nullptr;
    if (triple.isOSDarwin() && triple.isArch64Bit()) {
      MethType = IRB.CreateGlobalString("v16@0:8");
    } else if (triple.isOSDarwin() && triple.isArch32Bit()) {
      MethType = IRB.CreateGlobalString("v8@0:4");
    } else {
      errs() << "Unknown Platform. Blindly applying method signature for "
                "macOS 64Bit\n";
      MethType = IRB.CreateGlobalString("v16@0:8");
    }
    Constant *BitCastedIMP = cast<Constant>(
        IRB.CreateBitCast(IRB.GetInsertBlock()->getParent(),
                          objc_getClass->getFunctionType()->getParamType(0)));
    std::vector<Constant *> methodStructContents;
    methodStructContents.emplace_back(MethName);
    methodStructContents.emplace_back(MethType);
    methodStructContents.emplace_back(BitCastedIMP);
    Constant *newMethod =
        ConstantStruct::get(cast<StructType>(objc_method_type),
                            ArrayRef<Constant *>(methodStructContents));
    Constant *newMethodList =
        ConstantArray::get(AT, ArrayRef<Constant *>(newMethod));
    std::vector<Type *> newStructType;
    std::vector<Constant *> newStructValue;
    newStructType.emplace_back(Type::getInt32Ty(M->getContext()));
    newStructValue.emplace_back(
        ConstantInt::get(Type::getInt32Ty(M->getContext()), 0x18));
    newStructType.emplace_back(Type::getInt32Ty(M->getContext()));
    newStructValue.emplace_back(
        ConstantInt::get(Type::getInt32Ty(M->getContext()), 1));
    newStructType.emplace_back(AT);
    newStructValue.emplace_back(newMethodList);
    StructType *newType =
        StructType::get(M->getContext(), ArrayRef<Type *>(newStructType));
    Constant *newMethodStruct =
        ConstantStruct::get(newType, ArrayRef<Constant *>(newStructValue));
    GlobalVariable *newMethodStructGV = new GlobalVariable(
        *M, newType, true, GlobalValue::LinkageTypes::PrivateLinkage,
        newMethodStruct, "ACDNewClassMethodMap");
    appendToCompilerUsed(*M, {newMethodStructGV});
    if (methodListGV)
      newMethodStructGV->copyAttributesFrom(methodListGV);

    updateClassROMethodList(metaclass_ro, newMethodStructGV, opaquepointers, M);

    if (methodListGV) {
      methodListGV->replaceAllUsesWith(
          ConstantExpr::getBitCast(newMethodStructGV, methodListGV->getType()));
      methodListGV->eraseFromParent();
    }

    if (isNewInitializer) {
      if (!IRB.GetInsertBlock()->getTerminator()) {
        IRB.CreateRetVoid();
      }
    } else if (OrigContBB) {
      if (!IRB.GetInsertBlock()->getTerminator()) {
        IRB.CreateBr(OrigContBB);
      }
    }

    errs() << "Updated Class Method Map of:" << class_ro->getName() << "\n";
  }

  void HandleMethods(ConstantStruct *class_ro, IRBuilder<> &IRB, Module *M,
                     Value *Class, bool isMetaClass,
                     const EffectiveAcdConfig &cfg) {
    Function *sel_registerName = M->getFunction("sel_registerName");
    Function *class_replaceMethod = M->getFunction("class_replaceMethod");
    Function *class_getName = M->getFunction("class_getName");
    Function *objc_getMetaClass = M->getFunction("objc_getMetaClass");
    StructType *objc_method_list_t_type =
        StructType::getTypeByName(M->getContext(), "struct.__method_list_t");
    for (unsigned int i = 0; i < class_ro->getType()->getNumElements(); i++) {
      Constant *tmp = dyn_cast<Constant>(class_ro->getAggregateElement(i));
      if (!tmp || tmp->isNullValue())
        continue;
      Type *type = tmp->getType();
      if ((!opaquepointers &&
           type == PointerType::getUnqual(objc_method_list_t_type)) ||
          (opaquepointers &&
           (tmp->getName().starts_with("_OBJC_$_INSTANCE_METHODS") ||
            tmp->getName().starts_with("_OBJC_$_CLASS_METHODS")))) {
        GlobalVariable *methodListGV =
            readPtrauth(cast<GlobalVariable>(tmp->stripPointerCasts()));
        assert(methodListGV->hasInitializer() &&
               "MethodListGV doesn't have initializer");
        ConstantStruct *methodListStruct =
            cast<ConstantStruct>(methodListGV->getInitializer());
        if (methodListStruct->getOperand(2)->isNullValue())
          return;
        ConstantArray *methodList =
            cast<ConstantArray>(methodListStruct->getOperand(2));

        if (cfg.scramble_methods)
          methodList = scrambleMethodList(methodList);

        for (unsigned int mi = 0; mi < methodList->getNumOperands(); mi++) {
          ConstantStruct *methodStruct =
              cast<ConstantStruct>(methodList->getOperand(mi));

          // 1. Selector name decryption and dynamic registration
          StringRef selStr =
              cast<ConstantDataSequential>(
                  cast<GlobalVariable>(
                      opaquepointers
                          ? methodStruct->getOperand(0)
                          : cast<ConstantExpr>(methodStruct->getOperand(0))
                                ->getOperand(0))
                      ->getInitializer())
                  ->getAsCString();
          Value *SELName =
              getDecryptedString(IRB, *M, selStr, "objc.selname", cfg);
          CallInst *SEL = IRB.CreateCall(sel_registerName, {SELName});
          Value *EffectiveSEL = SEL;
          if (cfg.opaque_barriers) {
            EffectiveSEL = insertOpaqueBarrier(IRB, SEL);
          }

          // 2. IMP resolution with anti-taint barrier
          Type *IMPType =
              class_replaceMethod->getFunctionType()->getParamType(2);
          Value *BitCastedIMP = IRB.CreateBitCast(
              appleptrauth
                  ? opaquepointers
                        ? cast<GlobalVariable>(methodStruct->getOperand(2))
                              ->getInitializer()
                              ->getOperand(0)
                        : cast<ConstantExpr>(
                              cast<GlobalVariable>(methodStruct->getOperand(2))
                                  ->getInitializer()
                                  ->getOperand(0))
                              ->getOperand(0)
                  : methodStruct->getOperand(2),
              IMPType);
          if (cfg.opaque_barriers) {
            BitCastedIMP = insertOpaqueBarrier(IRB, BitCastedIMP);
          }

          // 3. Class pointer resolution
          std::vector<Value *> replaceMethodArgs;
          if (isMetaClass) {
            CallInst *className = IRB.CreateCall(class_getName, {Class});
            CallInst *MetaClass =
                IRB.CreateCall(objc_getMetaClass, {className});
            Value *EffectiveMeta = MetaClass;
            if (cfg.opaque_barriers) {
              EffectiveMeta = insertOpaqueBarrier(IRB, MetaClass);
            }
            replaceMethodArgs.emplace_back(EffectiveMeta);
          } else {
            replaceMethodArgs.emplace_back(Class);
          }

          // 4. Method type encoding dynamic decryption
          StringRef typeStr =
              cast<ConstantDataSequential>(
                  cast<GlobalVariable>(
                      opaquepointers
                          ? methodStruct->getOperand(1)
                          : cast<ConstantExpr>(methodStruct->getOperand(1))
                                ->getOperand(0))
                      ->getInitializer())
                  ->getAsCString();
          Value *TypeVal =
              getDecryptedString(IRB, *M, typeStr, "objc.types", cfg);

          replaceMethodArgs.emplace_back(EffectiveSEL);
          replaceMethodArgs.emplace_back(BitCastedIMP);
          replaceMethodArgs.emplace_back(TypeVal);

          CallInst *ReplaceRes = IRB.CreateCall(
              class_replaceMethod, ArrayRef<Value *>(replaceMethodArgs));
          if (cfg.opaque_barriers) {
            Value *ResToken = insertOpaqueBarrier(IRB, ReplaceRes);
            GlobalVariable *sinkGV = getOrCreateOpaqueSink(M);
            if (sinkGV) {
              IRB.CreateStore(ResToken, sinkGV, /*isVolatile=*/true);
            }
          }

          // 5. Optional IMP Symbol Renaming
          if (cfg.rename_methodimp) {
            Function *MethodIMP = cast<Function>(
                appleptrauth
                    ? opaquepointers
                          ? cast<GlobalVariable>(methodStruct->getOperand(2))
                                ->getInitializer()
                                ->getOperand(0)
                          : cast<ConstantExpr>(
                                cast<GlobalVariable>(
                                    methodStruct->getOperand(2)->getOperand(0))
                                    ->getInitializer()
                                    ->getOperand(0))
                                ->getOperand(0)
                : opaquepointers ? methodStruct->getOperand(2)
                                 : methodStruct->getOperand(2)->getOperand(0));
            MethodIMP->setName(randomIMPName());
          }
        }
      }
    }
  }

  GlobalVariable *readPtrauth(GlobalVariable *GV) {
    if (!GV)
      return nullptr;
    if (GV->hasSection() && GV->getSection() == "llvm.ptrauth") {
      Value *V = GV->getInitializer()->getOperand(0);
      return dyn_cast<GlobalVariable>(
          opaquepointers ? V : cast<ConstantExpr>(V)->getOperand(0));
    }
    return GV;
  }
};
} // namespace llvm

ModulePass *llvm::createAntiClassDumpPass() { return new AntiClassDump(); }
char AntiClassDump::ID = 0;
INITIALIZE_PASS(AntiClassDump, "acdobf", "Enable Anti-ClassDump.", false, false)
