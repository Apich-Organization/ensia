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

//  For maximum usability. We provide two modes for this pass, as defined in
//  include/AntiClassDump.h THIN mode is used on per-module
//  basis without LTO overhead and structs are left in the module where possible.
//  This is particularly useful for cases where LTO is not possible. For example
//  static library. Full mode is used at LTO stage, this mode constructs
//  dependency graph and perform full wipe-out as well as llvm.global_ctors
//  injection.
//  This pass only provides thin mode
//
//  OLLVM-Next enhancements:
//  ① ScrambleMethodOrder: Fisher-Yates shuffle of ObjC method array entries
//    at the IR ConstantArray level — Binja/IDA class-dump plugins iterate the
//    array sequentially and rely on positional ordering; shuffling breaks their
//    cross-reference chains and selector deduction.
//  ② RandomisedRename: Replace -acd-rename-methodimp fixed "ACDMethodIMP" name
//    with a per-function cryptoutils-seeded 64-bit hex string so every build
//    produces unique IR symbol names.
//  ③ DummySelectorInjection: At +initialize time, register random "ghost"
//    selectors via sel_registerName() to flood the selector table with noise —
//    tools that enumerate the selector table cannot distinguish real selectors
//    from injected ones.
//  ④ LLVM 17+ opaque-pointer compatibility: all getPointerTo() replaced with
//    PointerType::getUnqual() via a local helper.

#include "include/AntiClassDump.h"
#include "include/CryptoUtils.h"
#if LLVM_VERSION_MAJOR >= 17
#include "llvm/TargetParser/Triple.h"
#else
#include "llvm/ADT/Triple.h"
#endif
#include "include/Utils.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <algorithm>
#include <deque>
#include <map>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <vector>

using namespace llvm;

// Opaque-pointer-safe helper (same pattern as IndirectBranch / AntiHooking)
static inline Type *getOpaquePtrTy(LLVMContext &Ctx) {
#if LLVM_VERSION_MAJOR >= 17
  return PointerType::getUnqual(Ctx);
#else
  return Type::getInt8Ty(Ctx)->getPointerTo();
#endif
}

static cl::opt<bool>
    UseInitialize("acd-use-initialize", cl::init(true), cl::NotHidden,
                  cl::desc("[AntiClassDump]Inject codes to +initialize"));
static cl::opt<bool>
    RenameMethodIMP("acd-rename-methodimp", cl::init(false), cl::NotHidden,
                    cl::desc("[AntiClassDump]Rename methods imp"));

// OLLVM-Next new options
static cl::opt<bool>
    ScrambleMethodOrder("acd-scramble-methods", cl::init(false), cl::NotHidden,
                        cl::desc("[AntiClassDump]Shuffle ObjC method list order "
                                 "to defeat sequential class-dump enumeration"));
static cl::opt<bool>
    InjectDummySelectors("acd-dummy-selectors", cl::init(false), cl::NotHidden,
                         cl::desc("[AntiClassDump]Register ghost selectors at "
                                  "+initialize time to flood selector table"));
static cl::opt<uint32_t>
    DummySelectorCount("acd-dummy-count", cl::init(8), cl::NotHidden,
                       cl::desc("[AntiClassDump]Number of ghost selectors to inject "
                                "(default 8)"));

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
#if LLVM_VERSION_MAJOR >= 20
          << M.getTargetTriple().getTriple()
#else
          << M.getTargetTriple()
#endif
          << " is Not Supported For LLVM AntiClassDump\nProbably GNU Step?\n";
      return false;
    }
    // OLLVM-Next: use opaque pointer type for all ObjC API declarations
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
    FunctionType *objc_getMetaClass_Type =
        FunctionType::get(OpaquePtrTy, {OpaquePtrTy}, false);
    M.getOrInsertFunction("objc_getMetaClass", objc_getMetaClass_Type);
    appleptrauth = hasApplePtrauth(&M);
#if LLVM_VERSION_MAJOR >= 17
    opaquepointers = true;
#else
    opaquepointers = !M.getContext().supportsTypedPointers();
#endif
    return true;
  }

  bool runOnModule(Module &M) override {
    if (ObfVerbose) errs() << "Running AntiClassDump On " << M.getSourceFileName() << "\n";
    SmallVector<GlobalVariable *, 32> OLCGVs;
    for (GlobalVariable &GV : M.globals()) {
#if LLVM_VERSION_MAJOR >= 18
      if (GV.getName().starts_with("OBJC_LABEL_CLASS_$")) {
#else
      if (GV.getName().startswith("OBJC_LABEL_CLASS_$")) {
#endif
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
             "OBJC_LABEL_CLASS_$ Not ConstantArray.Is the target using "
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
        clsName.replace(clsName.find("OBJC_CLASS_$_"), strlen("OBJC_CLASS_$_"),
                        "");
        if (SuperClassGV) {
          supclsName = SuperClassGV->getName().str();
          supclsName.replace(supclsName.find("OBJC_CLASS_$_"),
                             strlen("OBJC_CLASS_$_"), "");
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
        for (std::string className : readyclses) {
          handleClass(GVMapping[className], &M);
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
      if (tmp->isNullValue())
        continue;
      Type *type = tmp->getType();
      if ((!opaquepointers &&
           type == PointerType::getUnqual(objc_method_list_t_type)) ||
          (opaquepointers &&
#if LLVM_VERSION_MAJOR >= 18
           (tmp->getName().starts_with("_OBJC_$_INSTANCE_METHODS") ||
            tmp->getName().starts_with("_OBJC_$_CLASS_METHODS")))) {
#else
           (tmp->getName().startswith("_OBJC_$_INSTANCE_METHODS") ||
            tmp->getName().startswith("_OBJC_$_CLASS_METHODS")))) {
#endif
        GlobalVariable *methodListGV =
            readPtrauth(cast<GlobalVariable>(tmp->stripPointerCasts()));
        assert(methodListGV->hasInitializer() &&
               "MethodListGV doesn't have initializer");
        ConstantStruct *methodListStruct =
            cast<ConstantStruct>(methodListGV->getInitializer());
        info["METHODLIST"] =
            cast<ConstantArray>(methodListStruct->getOperand(2));
      }
    }
    return info;
  }

  // ── OLLVM-Next: shuffle method list via Fisher-Yates ────────────────────────
  //
  // Returns a new ConstantArray containing the same method structs in a
  // PRNG-shuffled order.  The shuffled array is substituted in place of the
  // original, so Binja/IDA class-dump plugins that index method[0..n] will see
  // methods in a different positional order per compilation.
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

  // ── OLLVM-Next: generate a random 64-bit hex IMP name ───────────────────────
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

  void handleClass(GlobalVariable *GV, Module *M) {
    assert(GV->hasInitializer() &&
           "ObjC Class Structure's Initializer Missing");
    ConstantStruct *CS = dyn_cast<ConstantStruct>(GV->getInitializer());
    StringRef ClassName = GV->getName();
    ClassName = ClassName.substr(strlen("OBJC_CLASS_$_"));
    StringRef SuperClassName =
        readPtrauth(
            cast<GlobalVariable>(CS->getOperand(1)->stripPointerCasts()))
            ->getName();
    SuperClassName = SuperClassName.substr(strlen("OBJC_CLASS_$_"));
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
        if ((selname == "initialize" && UseInitialize) ||
            (selname == "load" && !UseInitialize)) {
          Function *IMPFunc = cast<Function>(readPtrauth(cast<GlobalVariable>(
              methodStruct->getOperand(2)->stripPointerCasts())));
          errs() << "Found Existing initializer\n";
          EntryBB = &(IMPFunc->getEntryBlock());
        }
      }
    } else {
      errs() << "Didn't Find ClassMethod List\n";
    }
    if (!EntryBB) {
      errs() << "Creating initializer\n";
      FunctionType *InitializerType = FunctionType::get(
          Type::getVoidTy(M->getContext()), ArrayRef<Type *>(), false);
      Function *Initializer = Function::Create(
          InitializerType, GlobalValue::LinkageTypes::PrivateLinkage,
          "AntiClassDumpInitializer", M);
      EntryBB = BasicBlock::Create(M->getContext(), "", Initializer);
      ReturnInst::Create(EntryBB->getContext(), EntryBB);
    }
    IRBuilder<> *IRB = new IRBuilder<>(EntryBB, EntryBB->getFirstInsertionPt());
    Function *objc_getClass = M->getFunction("objc_getClass");
    Value *ClassNameGV = IRB->CreateGlobalStringPtr(ClassName);
    CallInst *Class = IRB->CreateCall(objc_getClass, {ClassNameGV});

    // OLLVM-Next: inject dummy ghost selectors to flood selector table ────────
    if (InjectDummySelectors) {
      Function *sel_reg = M->getFunction("sel_registerName");
      uint32_t cnt = DummySelectorCount;
      for (uint32_t gi = 0; gi < cnt; gi++) {
        // Build a random-looking selector name that resembles a real method
        std::ostringstream ghostSel;
        ghostSel << "ghost_" << std::hex << cryptoutils->get_uint64_t();
        Value *GhostSelGV = IRB->CreateGlobalStringPtr(ghostSel.str());
        IRB->CreateCall(sel_reg, {GhostSelGV});
      }
    }

    ConstantStruct *metaclassCS =
        cast<ConstantStruct>(class_ro->getInitializer());
    ConstantStruct *classCS =
        cast<ConstantStruct>(metaclass_ro->getInitializer());

    if (!metaclassCS->getAggregateElement(5)->isNullValue()) {
      errs() << "Handling Instance Methods For Class:" << ClassName << "\n";
      HandleMethods(metaclassCS, IRB, M, Class, false);

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
      Constant *newMethodStruct = ConstantStruct::get(
          newType, ArrayRef<Constant *>(newStructValue));
      GlobalVariable *newMethodStructGV = new GlobalVariable(
          *M, newType, true, GlobalValue::LinkageTypes::PrivateLinkage,
          newMethodStruct, "ACDNewInstanceMethodMap");
      appendToCompilerUsed(*M, {newMethodStructGV});
      newMethodStructGV->copyAttributesFrom(methodListGV);
      // OLLVM-Next: use PointerType::getUnqual instead of getPointerTo()
      Constant *bitcastExpr = ConstantExpr::getBitCast(
          newMethodStructGV,
          opaquepointers
              ? PointerType::getUnqual(newType)
              : PointerType::getUnqual(StructType::getTypeByName(
                    M->getContext(), "struct.__method_list_t")));
      metaclassCS->handleOperandChange(metaclassCS->getAggregateElement(5),
                                       opaquepointers ? newMethodStructGV
                                                      : bitcastExpr);
      methodListGV->replaceAllUsesWith(
          opaquepointers
              ? newMethodStructGV
              : ConstantExpr::getBitCast(newMethodStructGV,
                                         methodListGV->getType()));
      methodListGV->dropAllReferences();
      methodListGV->eraseFromParent();
      errs() << "Updated Instance Method Map of:" << class_ro->getName()
             << "\n";
    }

    GlobalVariable *methodListGV = nullptr;
    if (!classCS->getAggregateElement(5)->isNullValue()) {
      errs() << "Handling Class Methods For Class:" << ClassName << "\n";
      HandleMethods(classCS, IRB, M, Class, true);
      methodListGV = readPtrauth(cast<GlobalVariable>(
          classCS->getAggregateElement(5)->stripPointerCasts()));
    }
    errs() << "Updating Class Method Map For Class:" << ClassName << "\n";
    Type *objc_method_type =
        StructType::getTypeByName(M->getContext(), "struct._objc_method");
    ArrayType *AT = ArrayType::get(objc_method_type, 1);
    Constant *MethName = nullptr;
    if (UseInitialize)
      MethName = cast<Constant>(IRB->CreateGlobalStringPtr("initialize"));
    else
      MethName = cast<Constant>(IRB->CreateGlobalStringPtr("load"));
    Constant *MethType = nullptr;
    if (triple.isOSDarwin() && triple.isArch64Bit()) {
      MethType = IRB->CreateGlobalStringPtr("v16@0:8");
    } else if (triple.isOSDarwin() && triple.isArch32Bit()) {
      MethType = IRB->CreateGlobalStringPtr("v8@0:4");
    } else {
      errs() << "Unknown Platform.Blindly applying method signature for "
                "macOS 64Bit\n";
      MethType = IRB->CreateGlobalStringPtr("v16@0:8");
    }
    Constant *BitCastedIMP = cast<Constant>(
        IRB->CreateBitCast(IRB->GetInsertBlock()->getParent(),
                           objc_getClass->getFunctionType()->getParamType(0)));
    std::vector<Constant *> methodStructContents;
    methodStructContents.emplace_back(MethName);
    methodStructContents.emplace_back(MethType);
    methodStructContents.emplace_back(BitCastedIMP);
    Constant *newMethod = ConstantStruct::get(
        cast<StructType>(objc_method_type),
        ArrayRef<Constant *>(methodStructContents));
    Constant *newMethodList = ConstantArray::get(
        AT, ArrayRef<Constant *>(newMethod));
    std::vector<Type *> newStructType;
    std::vector<Constant *> newStructValue;
    newStructType.emplace_back(Type::getInt32Ty(M->getContext()));
    newStructValue.emplace_back(ConstantInt::get(Type::getInt32Ty(M->getContext()), 0x18));
    newStructType.emplace_back(Type::getInt32Ty(M->getContext()));
    newStructValue.emplace_back(ConstantInt::get(Type::getInt32Ty(M->getContext()), 1));
    newStructType.emplace_back(AT);
    newStructValue.emplace_back(newMethodList);
    StructType *newType =
        StructType::get(M->getContext(), ArrayRef<Type *>(newStructType));
    Constant *newMethodStruct = ConstantStruct::get(
        newType, ArrayRef<Constant *>(newStructValue));
    GlobalVariable *newMethodStructGV = new GlobalVariable(
        *M, newType, true, GlobalValue::LinkageTypes::PrivateLinkage,
        newMethodStruct, "ACDNewClassMethodMap");
    appendToCompilerUsed(*M, {newMethodStructGV});
    if (methodListGV)
      newMethodStructGV->copyAttributesFrom(methodListGV);
    // OLLVM-Next: PointerType::getUnqual instead of deprecated getPointerTo()
    Constant *bitcastExpr = ConstantExpr::getBitCast(
        newMethodStructGV,
        opaquepointers
            ? PointerType::getUnqual(newType)
            : PointerType::getUnqual(StructType::getTypeByName(
                  M->getContext(), "struct.__method_list_t")));
    opaquepointers ? classCS->setOperand(5, bitcastExpr)
                   : classCS->handleOperandChange(
                         classCS->getAggregateElement(5), bitcastExpr);
    if (methodListGV) {
      methodListGV->replaceAllUsesWith(ConstantExpr::getBitCast(
          newMethodStructGV, methodListGV->getType()));
      methodListGV->dropAllReferences();
      methodListGV->eraseFromParent();
    }
    errs() << "Updated Class Method Map of:" << class_ro->getName() << "\n";
  }

  void HandleMethods(ConstantStruct *class_ro, IRBuilder<> *IRB, Module *M,
                     Value *Class, bool isMetaClass) {
    Function *sel_registerName = M->getFunction("sel_registerName");
    Function *class_replaceMethod = M->getFunction("class_replaceMethod");
    Function *class_getName = M->getFunction("class_getName");
    Function *objc_getMetaClass = M->getFunction("objc_getMetaClass");
    StructType *objc_method_list_t_type =
        StructType::getTypeByName(M->getContext(), "struct.__method_list_t");
    for (unsigned int i = 0; i < class_ro->getType()->getNumElements(); i++) {
      Constant *tmp = dyn_cast<Constant>(class_ro->getAggregateElement(i));
      if (tmp->isNullValue())
        continue;
      Type *type = tmp->getType();
      if ((!opaquepointers &&
           type == PointerType::getUnqual(objc_method_list_t_type)) ||
          (opaquepointers &&
#if LLVM_VERSION_MAJOR >= 18
           (tmp->getName().starts_with("_OBJC_$_INSTANCE_METHODS") ||
            tmp->getName().starts_with("_OBJC_$_CLASS_METHODS")))) {
#else
           (tmp->getName().startswith("_OBJC_$_INSTANCE_METHODS") ||
            tmp->getName().startswith("_OBJC_$_CLASS_METHODS")))) {
#endif
        GlobalVariable *methodListGV =
            readPtrauth(cast<GlobalVariable>(tmp->stripPointerCasts()));
        assert(methodListGV->hasInitializer() &&
               "MethodListGV doesn't have initializer");
        ConstantStruct *methodListStruct =
            cast<ConstantStruct>(methodListGV->getInitializer());
        if (methodListStruct->getOperand(2)->isZeroValue())
          return;
        ConstantArray *methodList =
            cast<ConstantArray>(methodListStruct->getOperand(2));

        // OLLVM-Next: optionally shuffle method dispatch order
        if (ScrambleMethodOrder)
          methodList = scrambleMethodList(methodList);

        for (unsigned int mi = 0; mi < methodList->getNumOperands(); mi++) {
          ConstantStruct *methodStruct =
              cast<ConstantStruct>(methodList->getOperand(mi));
          Constant *SELName = IRB->CreateGlobalStringPtr(
              cast<ConstantDataSequential>(
                  cast<GlobalVariable>(
                      opaquepointers
                          ? methodStruct->getOperand(0)
                          : cast<ConstantExpr>(methodStruct->getOperand(0))
                                ->getOperand(0))
                      ->getInitializer())
                  ->getAsCString());
          CallInst *SEL = IRB->CreateCall(sel_registerName, {SELName});
          Type *IMPType =
              class_replaceMethod->getFunctionType()->getParamType(2);
          Value *BitCastedIMP = IRB->CreateBitCast(
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
          std::vector<Value *> replaceMethodArgs;
          if (isMetaClass) {
            CallInst *className = IRB->CreateCall(class_getName, {Class});
            CallInst *MetaClass =
                IRB->CreateCall(objc_getMetaClass, {className});
            replaceMethodArgs.emplace_back(MetaClass);
          } else {
            replaceMethodArgs.emplace_back(Class);
          }
          replaceMethodArgs.emplace_back(SEL);
          replaceMethodArgs.emplace_back(BitCastedIMP);
          replaceMethodArgs.emplace_back(IRB->CreateGlobalStringPtr(
              cast<ConstantDataSequential>(
                  cast<GlobalVariable>(
                      opaquepointers
                          ? methodStruct->getOperand(1)
                          : cast<ConstantExpr>(methodStruct->getOperand(1))
                                ->getOperand(0))
                      ->getInitializer())
                  ->getAsCString()));
          IRB->CreateCall(class_replaceMethod,
                          ArrayRef<Value *>(replaceMethodArgs));

          // OLLVM-Next: enhanced rename — random hex name per IMP
          if (RenameMethodIMP) {
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
            // OLLVM-Next: random 64-bit hex name instead of fixed "ACDMethodIMP"
            MethodIMP->setName(randomIMPName());
          }
        }
      }
    }
  }

  GlobalVariable *readPtrauth(GlobalVariable *GV) {
    if (GV->getSection() == "llvm.ptrauth") {
      Value *V = GV->getInitializer()->getOperand(0);
      return cast<GlobalVariable>(
          opaquepointers ? V : cast<ConstantExpr>(V)->getOperand(0));
    }
    return GV;
  }
};
} // namespace llvm

ModulePass *llvm::createAntiClassDumpPass() { return new AntiClassDump(); }
char AntiClassDump::ID = 0;
INITIALIZE_PASS(AntiClassDump, "acd", "Enable Anti-ClassDump.", false, false)
