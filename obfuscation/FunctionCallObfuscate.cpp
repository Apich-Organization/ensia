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

#include "include/FunctionCallObfuscate.h"
#include "include/json.hpp"
#if LLVM_VERSION_MAJOR >= 17
#include "llvm/ADT/SmallString.h"
#include "llvm/TargetParser/Triple.h"
#else
#include "llvm/ADT/Triple.h"
#endif
#include "include/Utils.h"
#include "include/compat/CallSite.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"
#include <fstream>

using namespace llvm;

static const int DARWIN_FLAG = 0x2 | 0x8;
static const int ANDROID64_FLAG = 0x00002 | 0x100;
static const int ANDROID32_FLAG = 0x0000 | 0x2;

static cl::opt<uint64_t>
    dlopen_flag("fco_flag",
                cl::desc("The value of RTLD_DEFAULT on your platform"),
                cl::value_desc("value"), cl::init(-1), cl::Optional);
static cl::opt<std::string>
    SymbolConfigPath("fcoconfig",
                     cl::desc("FunctionCallObfuscate Configuration Path"),
                     cl::value_desc("filename"), cl::init("+-x/"));
namespace llvm {
struct FunctionCallObfuscate : public FunctionPass {
  static char ID;
  nlohmann::json Configuration;
  bool flag;
  bool initialized;
  bool opaquepointers;
  Triple triple;
  FunctionCallObfuscate() : FunctionPass(ID) {
    this->flag = true;
    this->initialized = false;
  }
  FunctionCallObfuscate(bool flag) : FunctionPass(ID) {
    this->flag = flag;
    this->initialized = false;
  }
  StringRef getPassName() const override { return "FunctionCallObfuscate"; }
  bool initialize(Module &M) {
    // Basic Defs
    if (SymbolConfigPath == "+-x/") {
      SmallString<32> Path;
      if (sys::path::home_directory(Path)) { // Stolen from LineEditor.cpp
        sys::path::append(Path, "Ensia", "SymbolConfig.json");
        SymbolConfigPath = Path.c_str();
      }
    }
    std::ifstream infile(SymbolConfigPath);
    if (infile.good()) {
      errs() << "Loading Symbol Configuration From:" << SymbolConfigPath
             << "\n";
      infile >> this->Configuration;
    } else {
      errs() << "Failed To Load Symbol Configuration From:" << SymbolConfigPath
             << "\n";
    }
    this->triple = Triple(M.getTargetTriple());
    if (triple.getVendor() == Triple::VendorType::Apple) {
      Type *Int8PtrTy = Type::getInt8Ty(M.getContext())->getPointerTo();
      // Generic ObjC Runtime Declarations
      FunctionType *IMPType =
          FunctionType::get(Int8PtrTy, {Int8PtrTy, Int8PtrTy}, true);
      PointerType *IMPPointerType = PointerType::get(IMPType, 0);
      FunctionType *class_replaceMethod_type = FunctionType::get(
          IMPPointerType, {Int8PtrTy, Int8PtrTy, IMPPointerType, Int8PtrTy},
          false);
      M.getOrInsertFunction("class_replaceMethod", class_replaceMethod_type);
      FunctionType *sel_registerName_type =
          FunctionType::get(Int8PtrTy, {Int8PtrTy}, false);
      M.getOrInsertFunction("sel_registerName", sel_registerName_type);
      FunctionType *objc_getClass_type =
          FunctionType::get(Int8PtrTy, {Int8PtrTy}, false);
      M.getOrInsertFunction("objc_getClass", objc_getClass_type);
      M.getOrInsertFunction("objc_getMetaClass", objc_getClass_type);
      FunctionType *class_getName_Type =
          FunctionType::get(Int8PtrTy, {Int8PtrTy}, false);
      M.getOrInsertFunction("class_getName", class_getName_Type);
      FunctionType *objc_getMetaClass_Type =
          FunctionType::get(Int8PtrTy, {Int8PtrTy}, false);
      M.getOrInsertFunction("objc_getMetaClass", objc_getMetaClass_Type);
    }
    this->initialized = true;
#if LLVM_VERSION_MAJOR >= 17
    this->opaquepointers = true;
#else
    this->opaquepointers = !M.getContext().supportsTypedPointers();
#endif
    return true;
  }

  bool OnlyUsedByCompilerUsed(GlobalVariable *GV) {
    if (GV->getNumUses() == 1) {
      User *U = GV->user_back();
      if (U->getNumUses() == 1) {
        if (GlobalVariable *GVU = dyn_cast<GlobalVariable>(U->user_back())) {
          if (GVU->getName() == "llvm.compiler.used")
            return true;
        }
      }
    }
    return false;
  }

  void HandleObjC(Function *F) {
    SmallPtrSet<GlobalVariable *, 8> objcclassgv, objcselgv, selnamegv;
    bool compilerUsedChanged = false;
    for (Instruction &I : instructions(F))
      for (Value *Op : I.operands())
        if (GlobalVariable *G =
                dyn_cast<GlobalVariable>(Op->stripPointerCasts())) {
          if (!G->hasName() || !G->hasInitializer() ||
              !G->getSection().contains("objc"))
            continue;
#if LLVM_VERSION_MAJOR >= 18
          if (G->getName().starts_with("OBJC_CLASSLIST_REFERENCES"))
            objcclassgv.insert(G);
          else if (G->getName().starts_with("OBJC_SELECTOR_REFERENCES"))
#else
          if (G->getName().startswith("OBJC_CLASSLIST_REFERENCES"))
            objcclassgv.insert(G);
          else if (G->getName().startswith("OBJC_SELECTOR_REFERENCES"))
#endif
            objcselgv.insert(G);
        }
    Module *M = F->getParent();
    SmallVector<Instruction *, 8> toErase;
    for (GlobalVariable *GV : objcclassgv) {
      // Iterate all CLASSREF uses and replace with objc_getClass() call
      // Strings are encrypted in other passes
      std::string className = GV->getInitializer()->getName().str();
      className.replace(className.find("OBJC_CLASS_$_"),
                        strlen("OBJC_CLASS_$_"), "");
      for (User *U : GV->users())
        if (Instruction *I = dyn_cast<Instruction>(U)) {
          IRBuilder<> builder(I);
          Function *objc_getClass_Func =
              cast<Function>(M->getFunction("objc_getClass"));
          Value *newClassName =
              builder.CreateGlobalStringPtr(StringRef(className));
          CallInst *CI = builder.CreateCall(objc_getClass_Func, {newClassName});
          // We need to bitcast it back to avoid IRVerifier
          Value *BCI = builder.CreateBitCast(CI, I->getType());
          I->replaceAllUsesWith(BCI);
          toErase.emplace_back(I); // We cannot erase it directly or we will
                                   // have problems releasing the IRBuilder.
        }
    }
    for (GlobalVariable *GV : objcselgv) {
      // Selector Convert
      GlobalVariable *selgv = dyn_cast<GlobalVariable>(
          opaquepointers
              ? GV->getInitializer()
              : cast<ConstantExpr>(GV->getInitializer())->getOperand(0));
      selnamegv.insert(selgv);
      ConstantDataArray *CDA =
          dyn_cast<ConstantDataArray>(selgv->getInitializer());
      StringRef SELName = CDA->getAsString(); // This is REAL Selector Name
      for (User *U : GV->users())
        if (Instruction *I = dyn_cast<Instruction>(U)) {
          IRBuilder<> builder(I);
          Function *sel_registerName_Func =
              cast<Function>(M->getFunction("sel_registerName"));
          Value *newGlobalSELName = builder.CreateGlobalStringPtr(SELName);
          CallInst *CI =
              builder.CreateCall(sel_registerName_Func, {newGlobalSELName});
          // We need to bitcast it back to avoid IRVerifier
          Value *BCI = builder.CreateBitCast(CI, I->getType());
          I->replaceAllUsesWith(BCI);
          toErase.emplace_back(I); // We cannot erase it directly or we will
                                   // have problems releasing the IRBuilder.
        }
    }
    for (Instruction *I : toErase)
      I->eraseFromParent();
    for (GlobalVariable *GV : objcclassgv) {
      GV->removeDeadConstantUsers();
      if (OnlyUsedByCompilerUsed(GV)) {
        compilerUsedChanged = true;
        GV->replaceAllUsesWith(Constant::getNullValue(GV->getType()));
      }
      if (GV->getNumUses() == 0) {
        GV->dropAllReferences();
        GV->eraseFromParent();
        continue;
      }
    }
    for (GlobalVariable *GV : objcselgv) {
      GV->removeDeadConstantUsers();
      if (OnlyUsedByCompilerUsed(GV)) {
        compilerUsedChanged = true;
        GV->replaceAllUsesWith(Constant::getNullValue(GV->getType()));
      }
      if (GV->getNumUses() == 0) {
        GV->dropAllReferences();
        GV->eraseFromParent();
      }
    }
    for (GlobalVariable *GV : selnamegv) {
      GV->removeDeadConstantUsers();
      if (OnlyUsedByCompilerUsed(GV)) {
        compilerUsedChanged = true;
        GV->replaceAllUsesWith(Constant::getNullValue(GV->getType()));
      }
      if (GV->getNumUses() == 0) {
        GV->dropAllReferences();
        GV->eraseFromParent();
      }
    }
    // Fixup llvm.compiler.used, so Verifier won't emit errors
    if (compilerUsedChanged) {
      GlobalVariable *CompilerUsedGV =
          F->getParent()->getGlobalVariable("llvm.compiler.used");
      if (!CompilerUsedGV)
        return;
      ConstantArray *CompilerUsed =
          dyn_cast<ConstantArray>(CompilerUsedGV->getInitializer());
      if (!CompilerUsed) {
        CompilerUsedGV->dropAllReferences();
        CompilerUsedGV->eraseFromParent();
        return;
      }
      std::vector<Constant *> elements = {};
      for (unsigned int i = 0; i < CompilerUsed->getNumOperands(); i++) {
        Constant *Op = CompilerUsed->getAggregateElement(i);
        if (!Op->isNullValue())
          elements.emplace_back(Op);
      }
      if (elements.size()) {
        ConstantArray *NewCA = cast<ConstantArray>(
            ConstantArray::get(CompilerUsed->getType(), elements));
        CompilerUsedGV->setInitializer(NewCA);
      } else {
        CompilerUsedGV->dropAllReferences();
        CompilerUsedGV->eraseFromParent();
      }
    }
  }
  bool runOnFunction(Function &F) override {
    // Construct Function Prototypes
    if (!toObfuscate(flag, &F, "fco"))
      return false;
    if (ObfVerbose) errs() << "Running FunctionCallObfuscate On " << F.getName() << "\n";
    Module *M = F.getParent();
    if (!this->initialized)
      initialize(*M);
    // Windows (MSVC / MinGW) is now supported via GetModuleHandleA /
    // GetProcAddress.  Every other OS that is neither Darwin, Android, nor
    // Windows is still unsupported and we bail out early.
    bool isWindows = triple.isOSWindows();
    if (!triple.isAndroid() && !triple.isOSDarwin() && !isWindows) {
      errs() << "Unsupported Target Triple: "
#if LLVM_VERSION_MAJOR >= 20
             << M->getTargetTriple().getTriple() << "\n";
#else
             << M->getTargetTriple() << "\n";
#endif
      return false;
    }
    FixFunctionConstantExpr(&F);
    HandleObjC(&F);
    Type *Int32Ty = Type::getInt32Ty(M->getContext());
    Type *Int8PtrTy = Type::getInt8Ty(M->getContext())->getPointerTo();

    // Platform-specific dynamic-linker declarations.
    // Unix/Darwin/Android  : dlopen(const char*, int)  / dlsym(void*, const char*)
    // Windows              : GetModuleHandleA(LPCSTR)  / GetProcAddress(HMODULE, LPCSTR)
    //
    // On Windows, GetModuleHandleA(NULL) returns a handle to the current
    // executable image.  To resolve symbols that live in a DLL rather than the
    // main EXE, add a "library" field to SymbolConfig.json and extend this
    // logic to call LoadLibraryA(lib) instead.
    Function *resolve_lib_decl = nullptr; // dlopen / GetModuleHandleA
    Function *resolve_sym_decl = nullptr; // dlsym  / GetProcAddress

    if (isWindows) {
      // HMODULE GetModuleHandleA(LPCSTR lpModuleName)
      FunctionType *gmh_type =
          FunctionType::get(Int8PtrTy, {Int8PtrTy}, false);
      // FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
      FunctionType *gpa_type =
          FunctionType::get(Int8PtrTy, {Int8PtrTy, Int8PtrTy}, false);
      resolve_lib_decl = cast<Function>(
          M->getOrInsertFunction("GetModuleHandleA", gmh_type).getCallee());
      resolve_sym_decl = cast<Function>(
          M->getOrInsertFunction("GetProcAddress", gpa_type).getCallee());
    } else {
      // dlopen / dlsym — Unix / Darwin / Android
      FunctionType *dlopen_type = FunctionType::get(
          Int8PtrTy, {Int8PtrTy, Int32Ty},
          false); // int has a length of 32 on both 32/64-bit platforms
      FunctionType *dlsym_type =
          FunctionType::get(Int8PtrTy, {Int8PtrTy, Int8PtrTy}, false);
      resolve_lib_decl = cast<Function>(
          M->getOrInsertFunction("dlopen", dlopen_type).getCallee());
      resolve_sym_decl = cast<Function>(
          M->getOrInsertFunction("dlsym", dlsym_type).getCallee());
    }

    // Begin Iteration
    for (BasicBlock &BB : F) {
      for (Instruction &Inst : BB) {
        if (isa<CallInst>(&Inst) || isa<InvokeInst>(&Inst)) {
          CallSite CS(&Inst);
          Function *calledFunction = CS.getCalledFunction();
          if (!calledFunction) {
            /*
              Note:
              For Indirect Calls:
                CalledFunction is NULL and calledValue is usually a bitcasted
              function pointer. We'll need to strip out the hiccups and obtain
              the called Function* from there
            */
            calledFunction =
                dyn_cast<Function>(CS.getCalledValue()->stripPointerCasts());
          }
          // Simple Extracting Failed
          // Use our own implementation
          if (!calledFunction)
            continue;
#if LLVM_VERSION_MAJOR >= 18
          if (calledFunction->getName().starts_with("ensia_"))
#else
          if (calledFunction->getName().startswith("ensia_"))
#endif
            continue;

          // It's only safe to restrict our modification to external symbols
          // Otherwise stripped binary will crash
          if (!calledFunction->empty() ||
              calledFunction->getName().equals_insensitive("dlsym") ||
              calledFunction->getName().equals_insensitive("dlopen") ||
              calledFunction->getName().equals_insensitive("GetModuleHandleA") ||
              calledFunction->getName().equals_insensitive("GetProcAddress") ||
              calledFunction->isIntrinsic())
            continue;

          if (this->Configuration.find(calledFunction->getName().str()) !=
              this->Configuration.end()) {
            std::string sname =
                this->Configuration[calledFunction->getName().str()]
                    .get<std::string>();
            StringRef calledFunctionName = StringRef(sname);
            BasicBlock *EntryBlock = CS->getParent();
            IRBuilder<> IRB(EntryBlock, EntryBlock->getFirstInsertionPt());

            Value *Handle = nullptr;
            Value *fp = nullptr;

            if (isWindows) {
              // GetModuleHandleA(NULL) — handle to the current process image.
              // Symbols in DLLs require LoadLibraryA; see comment above.
              Handle = IRB.CreateCall(resolve_lib_decl,
                                      {Constant::getNullValue(Int8PtrTy)});
              fp = IRB.CreateCall(
                  resolve_sym_decl,
                  {Handle, IRB.CreateGlobalStringPtr(calledFunctionName)});
            } else {
              if (triple.isOSDarwin()) {
                dlopen_flag = DARWIN_FLAG;
              } else if (triple.isAndroid()) {
                if (triple.isArch64Bit())
                  dlopen_flag = ANDROID64_FLAG;
                else
                  dlopen_flag = ANDROID32_FLAG;
              } else {
                errs() << "[FunctionCallObfuscate] Unsupported Target Triple:"
#if LLVM_VERSION_MAJOR >= 20
                       << M->getTargetTriple().getTriple() << "\n";
#else
                       << M->getTargetTriple() << "\n";
#endif
                errs() << "[FunctionCallObfuscate] Applying Default Signature:"
                       << dlopen_flag << "\n";
              }
              Handle = IRB.CreateCall(
                  resolve_lib_decl,
                  {Constant::getNullValue(Int8PtrTy),
                   ConstantInt::get(Int32Ty, dlopen_flag)});
              fp = IRB.CreateCall(
                  resolve_sym_decl,
                  {Handle, IRB.CreateGlobalStringPtr(calledFunctionName)});
            }

            Value *bitCastedFunction =
                IRB.CreateBitCast(fp, CS.getCalledValue()->getType());
            CS.setCalledFunction(bitCastedFunction);
          }
        }
      }
    }
    return true;
  }
};
FunctionPass *createFunctionCallObfuscatePass(bool flag) {
  return new FunctionCallObfuscate(flag);
}
} // namespace llvm
char FunctionCallObfuscate::ID = 0;
INITIALIZE_PASS(FunctionCallObfuscate, "fcoobf",
                "Enable Function CallSite Obfuscation.", false, false)
