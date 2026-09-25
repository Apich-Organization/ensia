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

#include "include/Utils.h"
#include "include/CryptoUtils.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include <sstream>

using namespace llvm;

namespace llvm {

bool ObfuscationMaxMode = false;
bool ObfuscationHighMode = false;
bool ObfuscationMedMode = false;
bool ObfuscationLowMode = false;
bool ObfuscationFCOActive = false;
bool ObfVerbose = false;
bool ObfTrace = false;

// ─── manuallyLowerSwitches
// ──────────────────────────────────────────────────── Replace every SwitchInst
// in F with a binary-search-tree of ICmp+BranchInsts. Used by ChaosStateMachine
// and Flattening instead of the nested PassBuilder/LowerSwitchPass approach,
// which deadlocks in LLVM 22.x when invoked from inside an already-running
// new-PM pass (shared AnalysisManager mutex).

static void
lowerSwitchBST(Value *cond, BasicBlock *switchBB, BasicBlock *defaultBB,
               SmallVectorImpl<std::pair<ConstantInt *, BasicBlock *>> &cases,
               int lo, int hi, Function *F) {
  if (lo > hi) {
    BranchInst::Create(defaultBB, switchBB);
    return;
  }
  if (lo == hi) {
    IRBuilder<> IRB(switchBB);
    Value *eq = IRB.CreateICmpEQ(cond, cases[lo].first);
    BranchInst::Create(cases[lo].second, defaultBB, eq, switchBB);
    return;
  }
  int mid = (lo + hi) / 2;
  IRBuilder<> IRB(switchBB);
  Value *le = IRB.CreateICmpSLE(cond, cases[mid].first);
  BasicBlock *leftBB = BasicBlock::Create(F->getContext(), "sw.bst.l", F);
  BasicBlock *rightBB = BasicBlock::Create(F->getContext(), "sw.bst.r", F);
  BranchInst::Create(leftBB, rightBB, le, switchBB);
  lowerSwitchBST(cond, leftBB, defaultBB, cases, lo, mid, F);
  lowerSwitchBST(cond, rightBB, defaultBB, cases, mid + 1, hi, F);
}

void manuallyLowerSwitches(Function *F) {
  SmallVector<SwitchInst *, 4> switches;
  for (BasicBlock &BB : *F) {
    if (BB.empty() || !BB.back().isTerminator())
      continue;
    if (SwitchInst *SI = dyn_cast<SwitchInst>(BB.getTerminator()))
      switches.push_back(SI);
  }

  if (!switches.empty()) {
    fixStack(F);
  }

  for (SwitchInst *SI : switches) {
    BasicBlock *switchBB = SI->getParent();
    Value *cond = SI->getCondition();
    BasicBlock *defaultBB = SI->getDefaultDest();

    SmallVector<std::pair<ConstantInt *, BasicBlock *>, 16> cases;
#if defined(ENSIA_RUST_PLUGIN)
    char *useBuffer = *(char **)((char *)SI - 8);
    uint32_t numOperands = *(uint32_t *)((char *)SI + 4) & 0x7ffffff;
    uint32_t numCases = (numOperands >= 2) ? (numOperands - 2) : 0;
    uint32_t reservedSpace = *(uint32_t *)((char *)SI + 72);
    if (reservedSpace < numOperands)
      reservedSpace = numOperands;
    ConstantInt **caseValues =
        (ConstantInt **)(useBuffer + (size_t)reservedSpace * 32);

    for (uint32_t i = 0; i < numCases; ++i) {
      ConstantInt *val = caseValues[i];
      BasicBlock *dest = *(BasicBlock **)(useBuffer + (2 + i) * 32);
      if (val && dest && isa<ConstantInt>(val))
        cases.push_back({val, dest});
    }
#else
    for (auto &C : SI->cases())
      cases.push_back({C.getCaseValue(), C.getCaseSuccessor()});
#endif
    llvm::sort(cases, [](const auto &a, const auto &b) {
      if (a.first->getBitWidth() <= 64 && b.first->getBitWidth() <= 64)
        return a.first->getSExtValue() < b.first->getSExtValue();
      return a.first->getValue().slt(b.first->getValue());
    });

    SI->eraseFromParent();
    lowerSwitchBST(cond, switchBB, defaultBB, cases, 0, (int)cases.size() - 1,
                   F);
  }
}

// Shamefully borrowed from ../Scalar/RegToMem.cpp :(
bool valueEscapes(Instruction *Inst) {
  BasicBlock *BB = Inst->getParent();
  for (Value::use_iterator UI = Inst->use_begin(), E = Inst->use_end(); UI != E;
       ++UI) {
    Instruction *I = cast<Instruction>(*UI);
    if (I->getParent() != BB || isa<PHINode>(I)) {
      return true;
    }
  }
  return false;
}

void fixStack(Function *f) {
  if (f->isDeclaration() || f->empty())
    return;

  BasicBlock *bbEntry = &f->getEntryBlock();

  // Find the first non-alloca instruction in bbEntry
  BasicBlock::iterator allocaInsertPt = bbEntry->begin();
  while (allocaInsertPt != bbEntry->end() && isa<AllocaInst>(*allocaInsertPt))
    ++allocaInsertPt;

  // 1. Move any AllocaInst that is not in the entry block to bbEntry
  SmallVector<AllocaInst *, 8> nonEntryAllocas;
  for (BasicBlock &BB : *f) {
    if (&BB == bbEntry)
      continue;
    for (Instruction &I : BB) {
      if (AllocaInst *AI = dyn_cast<AllocaInst>(&I))
        nonEntryAllocas.push_back(AI);
    }
  }
  for (AllocaInst *AI : nonEntryAllocas) {
    if (allocaInsertPt != bbEntry->end())
      AI->moveBefore(allocaInsertPt);
    else
      AI->moveBefore(bbEntry->getTerminator()->getIterator());
  }

  // Refresh insertion point after moving allocas
  allocaInsertPt = bbEntry->begin();
  while (allocaInsertPt != bbEntry->end() && isa<AllocaInst>(*allocaInsertPt))
    ++allocaInsertPt;
  if (allocaInsertPt == bbEntry->end())
    allocaInsertPt = bbEntry->getTerminator()->getIterator();

  // 2. Phase 1: Demote ALL PHI nodes first so no PHI nodes remain.
  // When all PHI nodes are converted to allocas/stores/loads, no PHI edges
  // can cause DemoteRegToStack to generate loads in predecessor blocks.
  SmallVector<PHINode *, 16> phis;
  for (BasicBlock &BB : *f) {
    for (Instruction &I : BB) {
      if (PHINode *P = dyn_cast<PHINode>(&I))
        phis.push_back(P);
    }
  }
  for (PHINode *P : phis) {
    DemotePHIToStack(P, allocaInsertPt);
  }

  // 3. Phase 2: Demote all escaping non-alloca values.
  // With all PHIs eliminated, DemoteRegToStack only inserts loads locally
  // before the user instructions, so inserted loads never escape.
  SmallVector<Instruction *, 32> escaping;
  for (BasicBlock &BB : *f) {
    for (Instruction &I : BB) {
      if (isa<AllocaInst>(&I))
        continue;
      if (valueEscapes(&I) || I.isUsedOutsideOfBlock(&BB))
        escaping.push_back(&I);
    }
  }
  for (Instruction *I : escaping) {
    DemoteRegToStack(*I, false, allocaInsertPt);
  }
}

// Unlike O-LLVM which uses __attribute__ that is not supported by the ObjC
// CFE. We use a dummy call here and remove the call later Very dumb and
// definitely slower than the function attribute method Merely a hack
bool readFlag(Function *f, std::string attribute) {
#if defined(ENSIA_RUST_PLUGIN)
  return false;
#else
  if (!f || !f->getParent())
    return false;
  std::string prefix = "ensia_" + attribute;
  bool hasTargetDecl = false;
  for (const Function &otherF : *f->getParent()) {
    if (otherF.isDeclaration() && otherF.getName().starts_with(prefix)) {
      hasTargetDecl = true;
      break;
    }
  }
  if (!hasTargetDecl)
    return false;

  for (Instruction &I : instructions(f)) {
    Instruction *Inst = &I;
    if (CallInst *CI = dyn_cast<CallInst>(Inst)) {
      if (CI->getCalledFunction() != nullptr &&
          CI->getCalledFunction()->getName().starts_with("ensia_" +
                                                         attribute)) {
        CI->eraseFromParent();
        return true;
      }
    }
    if (InvokeInst *II = dyn_cast<InvokeInst>(Inst)) {
      if (II->getCalledFunction() != nullptr &&
          II->getCalledFunction()->getName().starts_with("ensia_" +
                                                         attribute)) {
        BasicBlock *normalDest = II->getNormalDest();
        BasicBlock *unwindDest = II->getUnwindDest();
        BasicBlock *parent = II->getParent();
        if (parent->size() == 1) {
          parent->replaceAllUsesWith(normalDest);
          II->eraseFromParent();
          parent->eraseFromParent();
        } else {
          BranchInst::Create(normalDest, II);
          II->eraseFromParent();
        }
        if (pred_size(unwindDest) == 0)
          unwindDest->eraseFromParent();
        return true;
      }
    }
  }
  return false;
#endif
}

bool toObfuscate(bool flag, Function *f, std::string attribute) {
  // Check if declaration and external linkage
  if (f->isDeclaration() || f->hasAvailableExternallyLinkage()) {
    return false;
  }
  std::string attr = attribute;
  std::string attrNo = "no" + attr;
  if (readAnnotationMetadata(f, attrNo) || readFlag(f, attrNo)) {
    return false;
  }
  if (readAnnotationMetadata(f, attr) || readFlag(f, attr)) {
    return true;
  }
  return flag;
}

bool toObfuscateBoolOption(Function *f, std::string option, bool *val) {
  std::string opt = option;
  std::string optDisable = "no" + option;
  if (readAnnotationMetadata(f, optDisable) || readFlag(f, optDisable)) {
    *val = false;
    return true;
  }
  if (readAnnotationMetadata(f, opt) || readFlag(f, opt)) {
    *val = true;
    return true;
  }
  return false;
}

static const char obfkindid[] = "MD_obf";

bool readAnnotationMetadataUint32OptVal(Function *f, std::string opt,
                                        uint32_t *val) {
  MDNode *Existing = f->getMetadata(obfkindid);
  if (Existing) {
    MDTuple *Tuple = cast<MDTuple>(Existing);
    for (auto &N : Tuple->operands()) {
      StringRef mdstr = cast<MDString>(N.get())->getString();
      std::string estr = opt + "=";
      if (mdstr.starts_with(estr)) {
        *val = atoi(mdstr.substr(strlen(estr.c_str())).str().c_str());
        return true;
      }
    }
  }
  return false;
}

bool readFlagUint32OptVal(Function *f, std::string opt, uint32_t *val) {
#if defined(ENSIA_RUST_PLUGIN)
  return false;
#else
  if (!f || !f->getParent())
    return false;
  std::string prefix = "ensia_" + opt;
  bool hasTargetDecl = false;
  for (const Function &otherF : *f->getParent()) {
    if (otherF.isDeclaration() && otherF.getName().starts_with(prefix)) {
      hasTargetDecl = true;
      break;
    }
  }
  if (!hasTargetDecl)
    return false;

  for (Instruction &I : instructions(f)) {
    Instruction *Inst = &I;
    if (CallInst *CI = dyn_cast<CallInst>(Inst)) {
      if (CI->getCalledFunction() != nullptr &&
          CI->getCalledFunction()->getName().starts_with("ensia_" + opt)) {
        if (ConstantInt *C = dyn_cast<ConstantInt>(CI->getArgOperand(0))) {
          *val = (uint32_t)C->getValue().getZExtValue();
          CI->eraseFromParent();
          return true;
        }
      }
    }
    if (InvokeInst *II = dyn_cast<InvokeInst>(Inst)) {
      if (II->getCalledFunction() != nullptr &&
          II->getCalledFunction()->getName().starts_with("ensia_" + opt)) {
        if (ConstantInt *C = dyn_cast<ConstantInt>(II->getArgOperand(0))) {
          *val = (uint32_t)C->getValue().getZExtValue();
          BasicBlock *normalDest = II->getNormalDest();
          BasicBlock *unwindDest = II->getUnwindDest();
          BasicBlock *parent = II->getParent();
          if (parent->size() == 1) {
            parent->replaceAllUsesWith(normalDest);
            II->eraseFromParent();
            parent->eraseFromParent();
          } else {
            BranchInst::Create(normalDest, II);
            II->eraseFromParent();
          }
          if (pred_size(unwindDest) == 0)
            unwindDest->eraseFromParent();
          return true;
        }
      }
    }
  }
  return false;
#endif
}

bool toObfuscateUint32Option(Function *f, std::string option, uint32_t *val) {
  if (readAnnotationMetadataUint32OptVal(f, option, val) ||
      readFlagUint32OptVal(f, option, val))
    return true;
  return false;
}

bool hasApplePtrauth(Module *M) {
  for (GlobalVariable &GV : M->globals())
    if (GV.getSection() == "llvm.ptrauth")
      return true;
  return false;
}

void FixBasicBlockConstantExpr(BasicBlock *BB) {
  // Replace ConstantExpr with equal instructions
  // Otherwise replacing on Constant will crash the compiler
  // Things to note:
  // - Phis must be placed at BB start so CEs must be placed prior to current BB
  assert(!BB->empty() && "BasicBlock is empty!");
  assert(BB->getParent() && "BasicBlock must be in a Function!");
  Instruction *FunctionInsertPt =
      &*(BB->getParent()->getEntryBlock().getFirstInsertionPt());

  for (Instruction &I : *BB) {
    if (isa<LandingPadInst>(I) || isa<FuncletPadInst>(I) ||
        isa<IntrinsicInst>(I))
      continue;
    for (unsigned int i = 0; i < I.getNumOperands(); i++)
      if (ConstantExpr *C = dyn_cast<ConstantExpr>(I.getOperand(i))) {
        IRBuilder<NoFolder> IRB(&I);
        if (isa<PHINode>(I))
          IRB.SetInsertPoint(FunctionInsertPt);
        Instruction *Inst = IRB.Insert(C->getAsInstruction());
        I.setOperand(i, Inst);
      }
  }
}

void FixFunctionConstantExpr(Function *Func) {
  // Replace ConstantExpr with equal instructions
  // Otherwise replacing on Constant will crash the compiler
  for (BasicBlock &BB : *Func)
    FixBasicBlockConstantExpr(&BB);
}

void turnOffOptimization(Function *f) {
  f->removeFnAttr(Attribute::AttrKind::MinSize);
  f->removeFnAttr(Attribute::AttrKind::OptimizeForSize);
  if (!f->hasFnAttribute(Attribute::AttrKind::OptimizeNone) &&
      !f->hasFnAttribute(Attribute::AttrKind::AlwaysInline)) {
    f->addFnAttr(Attribute::AttrKind::OptimizeNone);
    f->addFnAttr(Attribute::AttrKind::NoInline);
  }
}

static inline std::vector<std::string> splitString(std::string str) {
  std::stringstream ss(str);
  std::string word;
  std::vector<std::string> words;
  while (ss >> word)
    words.emplace_back(word);
  return words;
}

void annotation2Metadata(Module &M) {
  GlobalVariable *Annotations = M.getGlobalVariable("llvm.global.annotations");
  if (!Annotations)
    return;
  auto *C = dyn_cast<ConstantArray>(Annotations->getInitializer());
  if (!C)
    return;
  for (unsigned int i = 0; i < C->getNumOperands(); i++)
    if (ConstantStruct *CS = dyn_cast<ConstantStruct>(C->getOperand(i))) {
      GlobalValue *StrC =
          dyn_cast<GlobalValue>(CS->getOperand(1)->stripPointerCasts());
      if (!StrC)
        continue;
      ConstantDataSequential *StrData =
          dyn_cast<ConstantDataSequential>(StrC->getOperand(0));
      if (!StrData)
        continue;
      Function *Fn = dyn_cast<Function>(CS->getOperand(0)->stripPointerCasts());
      if (!Fn)
        continue;

      // Add annotation to the function.
      std::vector<std::string> strs =
          splitString(StrData->getAsCString().str());
      for (std::string str : strs)
        writeAnnotationMetadata(Fn, str);
    }
}

bool readAnnotationMetadata(Function *f, std::string annotation) {
  MDNode *Existing = f->getMetadata(obfkindid);
  if (Existing) {
    MDTuple *Tuple = cast<MDTuple>(Existing);
    for (auto &N : Tuple->operands())
      if (cast<MDString>(N.get())->getString() == annotation)
        return true;
  }
  return false;
}

void writeAnnotationMetadata(Function *f, std::string annotation) {
  LLVMContext &Context = f->getContext();
  MDBuilder MDB(Context);

  MDNode *Existing = f->getMetadata(obfkindid);
  SmallVector<Metadata *, 4> Names;
  bool AppendName = true;
  if (Existing) {
    MDTuple *Tuple = cast<MDTuple>(Existing);
    for (auto &N : Tuple->operands()) {
      if (cast<MDString>(N.get())->getString() == annotation)
        AppendName = false;
      Names.emplace_back(N.get());
    }
  }
  if (AppendName)
    Names.emplace_back(MDB.createString(annotation));

  MDNode *MD = MDTuple::get(Context, Names);
  f->setMetadata(obfkindid, MD);
}

// AreUsersInOneFunction — fully recursive multi-level user-chain walk.
//
// Returns true if every reachable Instruction that (transitively) uses GV
// belongs to at most one Function.  This is stricter than the old single-level
// ConstantExpr check: it handles arbitrarily deep CE chains, ConstantAggregate
// nesting (ConstantArray / ConstantStruct / ConstantVector), and GlobalAlias
// forwarding.
//
// Conservative rule: any user that is not one of the above four categories is
// treated as "may be accessed from anywhere" → return false immediately.
bool AreUsersInOneFunction(GlobalVariable *GV) {
  SmallPtrSet<const Function *, 6> userFunctions;
  SmallPtrSet<const Value *, 32> visited;

  // Returns false if a non-handled user class is encountered.
  std::function<bool(const Value *)> walk = [&](const Value *V) -> bool {
    if (!visited.insert(V).second)
      return true; // cycle guard — already processed, no new info

    for (const User *U : V->users()) {
      if (const Instruction *I = dyn_cast<Instruction>(U)) {
        // Direct instruction use — record its parent function.
        userFunctions.insert(I->getFunction());
        if (userFunctions.size() > 1)
          return false; // fast-exit: already seen two distinct functions

      } else if (isa<ConstantExpr>(U) || isa<ConstantAggregate>(U)) {
        // Constant expression / aggregate — may itself be used in instructions
        // or nested inside further constants.  Walk recursively.
        if (!walk(U))
          return false;

      } else if (const GlobalAlias *GA = dyn_cast<GlobalAlias>(U)) {
        // GlobalAlias forwards the value — walk its users too.
        if (!walk(GA))
          return false;

      } else if (isa<GlobalVariable>(U)) {
        // Another global variable initializer references this GV (e.g., a
        // global array whose elements are pointers to this GV).  Walk it.
        if (!walk(U))
          return false;

      } else {
        // Unknown user category — conservatively declare "used globally".
        return false;
      }
    }
    return true;
  };

  if (!walk(GV))
    return false;
  return userFunctions.size() <= 1;
}

void tagSynthetic(Instruction *I) {
  if (!I)
    return;
  LLVMContext &Ctx = I->getContext();
  I->setMetadata("ensia.synthetic", MDNode::get(Ctx, {}));
}

bool isSynthetic(const Instruction *I) {
  if (!I)
    return false;
  if (I->hasMetadata("ensia.synthetic") || I->hasMetadata("constenc.done"))
    return true;
  StringRef name = I->getName();
  if (name.starts_with("ensia.") || name.starts_with("csm.") ||
      name.starts_with("bcf.") || name.starts_with("vobf.") ||
      name.starts_with("mba.") || name.starts_with("sub.") ||
      name.starts_with("constenc.") || name.starts_with("bpp.") ||
      name.starts_with("gf8.") || name.starts_with("strcry.") ||
      name.starts_with("barrier."))
    return true;
  return false;
}

static bool moduleIsX86(Module *M) {
  if (!M)
    return false;
  Triple triple(M->getTargetTriple());
  return triple.getArch() == Triple::x86_64 || triple.getArch() == Triple::x86;
}

static bool moduleIsAArch64(Module *M) {
  if (!M)
    return false;
  Triple triple(M->getTargetTriple());
  return triple.getArch() == Triple::aarch64 || triple.getArch() == Triple::arm;
}

GlobalVariable *getOrCreateOpaqueSink(Module *M) {
  if (!M)
    return nullptr;
  GlobalVariable *GV = M->getGlobalVariable("__ensia_opaque_sink", true);
  if (!GV) {
    Type *I64Ty = Type::getInt64Ty(M->getContext());
    GV = new GlobalVariable(*M, I64Ty, /*isConstant=*/false,
                            GlobalValue::InternalLinkage,
                            ConstantInt::get(I64Ty, 0), "__ensia_opaque_sink");
  }
  return GV;
}

std::string getPolymorphicBarrierAsm(const Triple &triple) {
  if (triple.getArch() == Triple::x86_64) {
    // Dynamic runtime contextual barriers derived from stack canary,
    // thread-local storage (FS segment), stack alignment masks, and register
    // state. Zero static "$$0" or "$$-1" literals that pattern scanners look
    // for!
    static const char *x86_64Barriers[] = {
        // 1. Stack canary (FS:0x28) dynamic self-cancellation: x ^ c ^ c == x
        "movzbl %fs:0x28, %eax; xorb %al, $0; movzbl %fs:0x28, %eax; xorb %al, "
        "$0",
        // 2. Stack canary dynamic add/sub self-cancellation: x + c - c == x
        "movzbl %fs:0x28, %eax; addb %al, $0; movzbl %fs:0x28, %eax; subb %al, "
        "$0",
        // 3. Dynamic stack pointer alignment mask (%rsp is 16-byte aligned at
        // function call, %rsp & 15 == 0)
        "movq %rsp, %rax; andb $$15, %al; addb %al, $0; subb %al, $0",
        // 4. Thread Control Block self-cancellation (%fs:0x00 is self pointer
        // in glibc)
        "movzbl %fs:0x0, %eax; xorb %al, $0; movzbl %fs:0x0, %eax; xorb %al, "
        "$0",
        // 5. Dynamic stack canary inversion self-cancellation: x ^ ~c ^ ~c == x
        "movzbl %fs:0x28, %eax; notb %al; xorb %al, $0; xorb %al, $0",
        // 6. Stack canary rotate self-cancellation
        "movzbl %fs:0x28, %eax; andb $$7, %al; movb %al, %cl; rolb %cl, $0; "
        "rorb %cl, $0"};
    unsigned idx = cryptoutils->get_range(sizeof(x86_64Barriers) /
                                          sizeof(x86_64Barriers[0]));
    return x86_64Barriers[idx];
  } else if (triple.getArch() == Triple::x86) {
    // 32-bit x86: GS segment is TLS base (%gs:0x14 is stack canary in 32-bit
    // glibc)
    static const char *x86_32Barriers[] = {
        "movzbl %gs:0x14, %eax; xorb %al, $0; movzbl %gs:0x14, %eax; xorb %al, "
        "$0",
        "movl %esp, %eax; andb $$15, %al; addb %al, $0; subb %al, $0",
        "movzbl %gs:0x14, %eax; addb %al, $0; movzbl %gs:0x14, %eax; subb %al, "
        "$0"};
    unsigned idx = cryptoutils->get_range(sizeof(x86_32Barriers) /
                                          sizeof(x86_32Barriers[0]));
    return x86_32Barriers[idx];
  } else if (triple.isAArch64() || triple.getArch() == Triple::arm) {
    // AArch64: TPIDR_EL0 (Thread ID register) dynamic contextual barrier on
    // memory slot $0
    static const char *armBarriers[] = {
        "ldrb w16, $0; mrs x17, tpidr_el0; eor w16, w16, w17; eor w16, w16, "
        "w17; strb w16, $0",
        "ldrb w16, $0; mrs x17, tpidr_el0; add w16, w16, w17; sub w16, w16, "
        "w17; strb w16, $0",
        "prfm pldl1keep, $0; dmb ishld; isb",
        "prfm pstl1keep, $0; dmb ish; isb"};
    unsigned idx =
        cryptoutils->get_range(sizeof(armBarriers) / sizeof(armBarriers[0]));
    return armBarriers[idx];
  }
  return "nop";
}

template <typename BuilderTy>
static Value *insertOpaqueBarrierImpl(BuilderTy &IRB, Value *V) {
  if (!V)
    return V;
  Type *T = V->getType();
  if (T->isVoidTy())
    return V;
  BasicBlock *BB = IRB.GetInsertBlock();
  if (!BB)
    return V;
  Function *F = BB->getParent();
  if (!F)
    return V;

  Module *M = F->getParent();
  LLVMContext &Ctx = V->getContext();
  BasicBlock &Entry = F->getEntryBlock();
  IRBuilder<> EntryIRB(&Entry, Entry.getFirstInsertionPt());
  AllocaInst *slot = EntryIRB.CreateAlloca(T, nullptr, "barrier.slot");
  slot->setMetadata("ensia.barrier.slot", MDNode::get(Ctx, {}));

  IRB.CreateStore(V, slot);

  Triple triple(M->getTargetTriple());
  std::string asmCode = getPolymorphicBarrierAsm(triple);
  std::string clobbers = "=*m,*m,~{memory},~{dirflag},~{fpsr},~{flags}";
  if (triple.getArch() == Triple::x86_64 || triple.getArch() == Triple::x86) {
    clobbers = "=*m,*m,~{rax},~{rcx},~{dirflag},~{fpsr},~{flags},~{memory}";
  } else if (triple.isAArch64() || triple.getArch() == Triple::arm) {
    clobbers = "=*m,*m,~{x16},~{x17},~{cc},~{memory}";
  }

  FunctionType *AsmFTy = FunctionType::get(
      Type::getVoidTy(Ctx),
      {PointerType::get(Ctx, 0), PointerType::get(Ctx, 0)}, false);
  InlineAsm *IA = InlineAsm::get(AsmFTy, asmCode, clobbers,
                                 /*hasSideEffects=*/true);
  CallInst *CI = IRB.CreateCall(AsmFTy, IA, {slot, slot});
  CI->addParamAttr(0, Attribute::get(Ctx, Attribute::ElementType, T));
  CI->addParamAttr(1, Attribute::get(Ctx, Attribute::ElementType, T));

  // Genuine side-effect: volatile sink to internal module global
  // Prevents dead-code elimination, alias folding, and backward slicing.
  GlobalVariable *sinkGV = getOrCreateOpaqueSink(M);
  if (sinkGV) {
    Value *sinkVal = nullptr;
    if (T->isIntegerTy()) {
      if (T->getIntegerBitWidth() <= 64)
        sinkVal = IRB.CreateZExtOrTrunc(V, Type::getInt64Ty(Ctx), "");
    } else if (T->isPointerTy()) {
      sinkVal = IRB.CreatePtrToInt(V, Type::getInt64Ty(Ctx), "");
    }
    if (sinkVal) {
      if (Instruction *sinkInst = dyn_cast<Instruction>(sinkVal))
        sinkInst->setMetadata("ensia.synthetic", MDNode::get(Ctx, {}));
      Instruction *st = IRB.CreateStore(sinkVal, sinkGV, /*isVolatile=*/true);
      st->setMetadata("ensia.synthetic", MDNode::get(Ctx, {}));
    }
  }

  Instruction *loadInst = IRB.CreateLoad(T, slot, "");
  loadInst->setMetadata("ensia.synthetic", MDNode::get(Ctx, {}));
  return loadInst;
}

Value *insertOpaqueBarrier(IRBuilder<NoFolder> &IRB, Value *V) {
  return insertOpaqueBarrierImpl(IRB, V);
}

Value *insertOpaqueBarrier(IRBuilder<> &IRB, Value *V) {
  return insertOpaqueBarrierImpl(IRB, V);
}

std::string getViolentExitAsm(const Triple &triple) {
  uint64_t noiseK = cryptoutils->get_uint32_t() & 0xFFFF;
  uint64_t nonCanon =
      ((uint64_t)(cryptoutils->get_uint32_t()) & 0x00007FFFFFFFFFFFull) |
      0x8000000000000000ull;
  uint32_t chaosSeed = cryptoutils->get_range(1, 0xBEFF);
  std::ostringstream ncoss;
  ncoss << std::hex << nonCanon;

  std::string s;

  if (triple.getArch() == Triple::x86_64) {
    // Timing jitter / noise
    s += "rdtsc\n\t";
    s += "andl $$0xFFFF, %eax\n\t";
    s += "addl $$" + std::to_string(noiseK) + ", %eax\n\t";
    s += "subl $$" + std::to_string(noiseK) + ", %eax\n\t";

    if (triple.isOSWindows()) {
      // Windows x86_64:
      // Layer 1: Kernel Fast Fail (int 0x29 with FAST_FAIL_FATAL_APP_EXIT = 7)
      // Bypasses all user-mode VEH / SEH exception handlers
      s += "movl $$7, %ecx\n\t";
      s += "int $$0x29\n\t";

      // Layer 2: Kernel memory write to trigger KPP / BugCheck
      uint64_t privAddr =
          0xFFFFF80000000000ull | (cryptoutils->get_uint32_t() & 0xFFFFFFFFull);
      std::ostringstream privoss;
      privoss << std::hex << privAddr;
      s += "movabsq $$0x" + privoss.str() + ", %rax\n\t";
      s += "movq $$0, (%rax)\n\t";

      // Layer 3: Hardware Division by Zero (#DE)
      s += "xorl %edx, %edx\n\t";
      s += "xorl %eax, %eax\n\t";
      s += "idivl %eax\n\t";

      // Layer 4: Obliterate stack pointer & bad ret
      s += "xorq %rsp, %rsp\n\t";
      s += "retq\n\t";

      // Layer 5: Non-canonical jump (#GP)
      s += "movabsq $$0x" + ncoss.str() + ", %r15\n\t";
      s += "jmpq *%r15\n\t";

    } else if (triple.isOSDarwin()) {
      // Darwin / macOS x86_64:
      // Layer 1: Direct BSD SYS_kill(0, SIGKILL=9) -> syscall 37 (0x2000025)
      s += "movq $$0x2000025, %rax\n\t";
      s += "movq $$0, %rdi\n\t";
      s += "movq $$9, %rsi\n\t";
      s += "syscall\n\t";

      // Layer 2: Direct BSD SYS_exit(137) -> syscall 1 (0x2000001)
      s += "movq $$0x2000001, %rax\n\t";
      s += "movq $$137, %rdi\n\t";
      s += "syscall\n\t";

      // Layer 3: Hardware Division by Zero (#DE)
      s += "xorl %edx, %edx\n\t";
      s += "xorl %eax, %eax\n\t";
      s += "idivl %eax\n\t";

      // Layer 4: Obliterate stack pointer & bad ret
      s += "xorq %rsp, %rsp\n\t";
      s += "retq\n\t";

      // Layer 5: Non-canonical jump (#GP)
      s += "movabsq $$0x" + ncoss.str() + ", %r15\n\t";
      s += "jmpq *%r15\n\t";

    } else {
      // Linux / Android x86_64:
      // Layer 1: Disable core dumps (SYS_prctl=157, PR_SET_DUMPABLE=4, 0)
      s += "movq $$157, %rax\n\t";
      s += "movq $$4, %rdi\n\t";
      s += "xorq %rsi, %rsi\n\t";
      s += "xorq %rdx, %rdx\n\t";
      s += "xorq %r10, %r10\n\t";
      s += "syscall\n\t";

      // Layer 2: Direct raw syscall SYS_exit_group(137) (syscall 231)
      s += "movq $$231, %rax\n\t";
      s += "movq $$137, %rdi\n\t";
      s += "syscall\n\t";

      // Layer 3: Hardware Division by Zero (#DE)
      s += "xorl %edx, %edx\n\t";
      s += "xorl %eax, %eax\n\t";
      s += "idivl %eax\n\t";

      // Layer 4: Ring 3 Privilege Violation (#GP) via user-mode cli / hlt
      s += "cli\n\t";
      s += "hlt\n\t";

      // Layer 5: Obliterate stack pointer & bad ret
      s += "xorq %rsp, %rsp\n\t";
      s += "retq\n\t";

      // Layer 6: Non-canonical address jump (#GP)
      s += "movabsq $$0x" + ncoss.str() + ", %r15\n\t";
      s += "jmpq *%r15\n\t";
    }

    // Chaos Layer: Q32 logistic-map infinite loop
    s += "movabsq $$" + std::to_string(chaosSeed | 0x10001ULL) + ", %r14\n\t";
    s += "91:\n\t";
    s += "movabsq $$0x100000000, %rcx\n\t";
    s += "subq %r14, %rcx\n\t";
    s += "movq %r14, %rax\n\t";
    s += "mulq %rcx\n\t";
    s += "shrq $$32, %rax\n\t";
    s += "shlq $$2, %rax\n\t";
    s += "movq %rax, %r14\n\t";
    s += "jmp 91b\n\t";
    s += "92:\n\tjmp 92b\n\t";

  } else if (triple.isAArch64()) {
    s += "mrs x9, cntvct_el0\n\t";
    s += "add x9, x9, #" + std::to_string(noiseK & 0xFFF) + "\n\t";
    s += "sub x9, x9, #" + std::to_string(noiseK & 0xFFF) + "\n\t";

    if (triple.isOSWindows()) {
      // Windows ARM64 Fast-Fail:
      // W16 = 7 (FAST_FAIL_FATAL_APP_EXIT), BRK #0xF003
      s += "mov w16, #7\n\t";
      s += "brk #0xF003\n\t";

      // Synchronous Data Abort: store 0 to NULL
      s += "mov x0, #0\n\t";
      s += "str xzr, [x0]\n\t";

      // SP alignment fault & bad return
      s += "mov sp, x0\n\t";
      s += "ret\n\t";

      // Privileged memory write
      uint64_t privAddr =
          0xFFFF000000000000ull | (cryptoutils->get_uint32_t() & 0xFFFFFFFFull);
      s += "movz x15, #" + std::to_string(privAddr & 0xFFFF) + "\n\t";
      s += "movk x15, #" + std::to_string((privAddr >> 16) & 0xFFFF) +
           ", lsl #16\n\t";
      s += "movk x15, #" + std::to_string((privAddr >> 32) & 0xFFFF) +
           ", lsl #32\n\t";
      s += "movk x15, #" + std::to_string((privAddr >> 48) & 0xFFFF) +
           ", lsl #48\n\t";
      s += "str xzr, [x15]\n\t";

    } else if (triple.isOSDarwin()) {
      // macOS / iOS AArch64:
      // Layer 1: Direct BSD SYS_exit(137): x0=137, x16=1, svc #0x80
      s += "mov x0, #137\n\t";
      s += "mov x16, #1\n\t";
      s += "svc #0x80\n\t";

      // Layer 2: Synchronous Data Abort (null dereference)
      s += "mov x0, #0\n\t";
      s += "str xzr, [x0]\n\t";

      // Layer 3: SP alignment fault
      s += "mov sp, x0\n\t";
      s += "ret\n\t";

      // Layer 4: Synchronous exception trap
      s += "brk #0xDEAD\n\t";

    } else {
      // Linux / Android AArch64:
      // Layer 1: prctl(PR_SET_DUMPABLE=4, 0)
      s += "mov x8, #167\n\t";
      s += "mov x0, #4\n\t";
      s += "mov x1, #0\n\t";
      s += "mov x2, #0\n\t";
      s += "mov x3, #0\n\t";
      s += "mov x4, #0\n\t";
      s += "svc #0\n\t";

      // Layer 2: Direct syscall SYS_exit_group(137) (syscall 94)
      s += "mov x8, #94\n\t";
      s += "mov x0, #137\n\t";
      s += "svc #0\n\t";

      // Layer 3: Synchronous Data Abort
      s += "mov x0, #0\n\t";
      s += "str xzr, [x0]\n\t";

      // Layer 4: SP alignment fault & bad ret
      s += "mov sp, x0\n\t";
      s += "ret\n\t";

      // Layer 5: Privileged instruction trap (access EL1 register from EL0)
      s += "msr sctlr_el1, xzr\n\t";

      // Layer 6: Synchronous exception trap
      s += "brk #0xDEAD\n\t";
    }

    // Non-canonical branch
    s += "movz x15, #" + std::to_string(nonCanon & 0xFFFF) + "\n\t";
    s += "movk x15, #" + std::to_string((nonCanon >> 16) & 0xFFFF) +
         ", lsl #16\n\t";
    s += "movk x15, #" + std::to_string((nonCanon >> 32) & 0xFFFF) +
         ", lsl #32\n\t";
    s += "movk x15, #" + std::to_string((nonCanon >> 48) & 0xFFFF) +
         ", lsl #48\n\t";
    s += "br x15\n\t";

    // Chaos Layer: Q32 logistic-map infinite loop
    s += "movz x14, #" + std::to_string((chaosSeed | 0x10001ULL) & 0xFFFF) +
         "\n\t";
    s += "movk x14, #" +
         std::to_string(((chaosSeed | 0x10001ULL) >> 16) & 0xFFFF) +
         ", lsl #16\n\t";
    s += "91:\n\t";
    s += "mov x0, #1\n\t";
    s += "lsl x0, x0, #32\n\t";
    s += "sub x0, x0, x14\n\t";
    s += "mul x0, x14, x0\n\t";
    s += "lsr x0, x0, #32\n\t";
    s += "lsl x0, x0, #2\n\t";
    s += "mov x14, x0\n\t";
    s += "b 91b\n\t";
    s += "92:\n\tb 92b\n\t";
  }

  return s;
}

void insertViolentExit(IRBuilder<> &IRB, const Triple &triple) {
  LLVMContext &Ctx = IRB.getContext();
  FunctionType *VoidFTy = FunctionType::get(Type::getVoidTy(Ctx), false);
  if (triple.getArch() == Triple::x86_64) {
    std::string asmStr = getViolentExitAsm(triple);
    InlineAsm *IA = InlineAsm::get(
        VoidFTy, asmStr,
        "~{rax},~{rcx},~{rdx},~{rsi},~{rdi},~{r8},~{r9},~{r10},~{r11},~{r14},~{"
        "r15},~{dirflag},~{fpsr},~{flags}",
        /*hasSideEffects=*/true, false, InlineAsm::AD_ATT);
    IRB.CreateCall(IA);
    IRB.CreateUnreachable();
  } else if (triple.isAArch64()) {
    std::string asmStr = getViolentExitAsm(triple);
    InlineAsm *IA = InlineAsm::get(
        VoidFTy, asmStr,
        "~{x0},~{x1},~{x2},~{x3},~{x4},~{x8},~{x9},~{x14},~{x15},~{x16},~{"
        "cc},~{memory}",
        /*hasSideEffects=*/true, false);
    IRB.CreateCall(IA);
    IRB.CreateUnreachable();
  } else {
    // Generic fallback: abort() with NoReturn + Unreachable
    Module *M = IRB.GetInsertBlock()->getModule();
    FunctionCallee AbortFn = M->getOrInsertFunction(
        "abort", FunctionType::get(Type::getVoidTy(Ctx), false));
    if (Function *F = dyn_cast<Function>(AbortFn.getCallee()))
      F->addFnAttr(Attribute::NoReturn);
    IRB.CreateCall(AbortFn);
    IRB.CreateUnreachable();
  }
}

// ── Anti-Taint & Data-Flow Entanglement Primitives ──────────────────────────

GlobalVariable *getOrCreateLaunderLUT(Module *M) {
  const char *name = "__ensia_launder_lut";
  GlobalVariable *GV = M->getGlobalVariable(name);
  if (GV)
    return GV;
  LLVMContext &Ctx = M->getContext();
  Type *I8Ty = Type::getInt8Ty(Ctx);
  ArrayType *ArrTy = ArrayType::get(I8Ty, 256);
  SmallVector<Constant *, 256> elements;
  elements.reserve(256);
  for (unsigned i = 0; i < 256; i++) {
    elements.push_back(ConstantInt::get(I8Ty, i));
  }
  Constant *Init = ConstantArray::get(ArrTy, elements);
  GV = new GlobalVariable(*M, ArrTy, /*isConstant=*/true,
                          GlobalValue::PrivateLinkage, Init, name);
  GV->setAlignment(Align(16));
  return GV;
}

Value *insertTaintLaunder(IRBuilder<> &IRB, Value *Val) {
  if (!Val)
    return Val;
  Type *Ty = Val->getType();
  if (!Ty->isIntegerTy())
    return Val;
  unsigned bitWidth = Ty->getIntegerBitWidth();
  if (bitWidth < 8) {
    Value *Zero = ConstantInt::get(Ty, 0);
    Value *One = ConstantInt::get(Ty, 1);
    Value *Cmp = IRB.CreateICmpNE(Val, Zero, "tl.cmp");
    return IRB.CreateSelect(Cmp, One, Zero, "tl.sel");
  }

  Module *M = IRB.GetInsertBlock()->getModule();
  GlobalVariable *LUT = getOrCreateLaunderLUT(M);
  LLVMContext &Ctx = IRB.getContext();
  Type *I8Ty = Type::getInt8Ty(Ctx);
  Type *I64Ty = Type::getInt64Ty(Ctx);

  unsigned numBytes = bitWidth / 8;
  if (numBytes == 0)
    numBytes = 1;
  Value *Acc = ConstantInt::get(Ty, 0);

  for (unsigned b = 0; b < numBytes; b++) {
    Value *ShiftAmt = ConstantInt::get(Ty, b * 8);
    Value *ByteVal =
        IRB.CreateTrunc(IRB.CreateLShr(Val, ShiftAmt), I8Ty, "tl.b");
    Value *BarrieredByte = insertOpaqueBarrier(IRB, ByteVal);
    Value *ByteIdx64 = IRB.CreateZExt(BarrieredByte, I64Ty, "tl.idx");
    Value *BytePtr = IRB.CreateGEP(I8Ty, LUT, ByteIdx64, "tl.lut.gep");
    Value *CleanByte =
        IRB.CreateLoad(I8Ty, BytePtr, /*isVolatile=*/true, "tl.clean.b");

    // Tier 2: Implicit control-flow laundering across ALL 8 bits.
    // Every single bit is independently synthesized from pure constants (1 <<
    // bit) vs 0 based strictly on control-flow comparisons. Dynamic Taint
    // Analysis engines do not propagate data taint tags across
    // constant-selected control dependencies.
    Value *Recomb = ConstantInt::get(I8Ty, 0);
    for (unsigned bit = 0; bit < 8; bit++) {
      Value *BitMask = ConstantInt::get(I8Ty, 1 << bit);
      Value *BitTest = IRB.CreateAnd(CleanByte, BitMask, "tl.btest");
      Value *BitIsSet =
          IRB.CreateICmpNE(BitTest, ConstantInt::get(I8Ty, 0), "tl.bis");
      Value *BitClean = IRB.CreateSelect(BitIsSet, BitMask,
                                         ConstantInt::get(I8Ty, 0), "tl.bsel");
      Recomb = IRB.CreateOr(Recomb, BitClean, "tl.recomb");
    }
    CleanByte = Recomb;

    Value *ExtClean = IRB.CreateZExt(CleanByte, Ty);
    Value *ShiftClean = IRB.CreateShl(ExtClean, ShiftAmt);
    Acc = IRB.CreateOr(Acc, ShiftClean);
  }

  return insertOpaqueBarrier(IRB, Acc);
}

Value *insertVectorTaintDiffusion(IRBuilder<> &IRB, Value *Val,
                                  Value *EntropyToken) {
  if (!Val)
    return Val;
  Type *Ty = Val->getType();
  if (!Ty->isIntegerTy())
    return Val;

  unsigned bw = Ty->getIntegerBitWidth();
  LLVMContext &Ctx = IRB.getContext();

  if (bw == 32) {
    Type *I32Ty = Type::getInt32Ty(Ctx);
    VectorType *VecTy = FixedVectorType::get(I32Ty, 4);

    Value *E32 = EntropyToken;
    if (!E32) {
      E32 = ConstantInt::get(I32Ty, 0x9e3779b9U);
    } else if (E32->getType() != I32Ty) {
      E32 = IRB.CreateZExtOrTrunc(E32, I32Ty);
    }

    Value *V = UndefValue::get(VecTy);
    V = IRB.CreateInsertElement(V, Val, (uint64_t)0, "vtd.v0");
    V = IRB.CreateInsertElement(V, E32, (uint64_t)1, "vtd.v1");
    V = IRB.CreateInsertElement(V, IRB.CreateXor(Val, E32), (uint64_t)2,
                                "vtd.v2");
    V = IRB.CreateInsertElement(
        V, IRB.CreateMul(Val, ConstantInt::get(I32Ty, 0x517cc1b7U)),
        (uint64_t)3, "vtd.v3");

    // Barrier on vector forces real SIMD machine instructions (movd, pshufd,
    // etc.)
    V = insertOpaqueBarrier(IRB, V);
    Value *Shuffled = IRB.CreateShuffleVector(V, UndefValue::get(VecTy),
                                              {2, 0, 3, 1}, "vtd.shuf");
    Shuffled = insertOpaqueBarrier(IRB, Shuffled);
    Value *Res = IRB.CreateExtractElement(Shuffled, (uint64_t)1, "vtd.res");
    return insertOpaqueBarrier(IRB, Res);
  }

  if (bw == 64) {
    Type *I64Ty = Type::getInt64Ty(Ctx);
    VectorType *VecTy = FixedVectorType::get(I64Ty, 2);

    Value *E64 = EntropyToken;
    if (!E64) {
      E64 = ConstantInt::get(I64Ty, 0x9e3779b97f4a7c15ULL);
    } else if (E64->getType() != I64Ty) {
      E64 = IRB.CreateZExtOrTrunc(E64, I64Ty);
    }

    Value *V = UndefValue::get(VecTy);
    V = IRB.CreateInsertElement(V, Val, (uint64_t)0, "vtd64.v0");
    V = IRB.CreateInsertElement(V, E64, (uint64_t)1, "vtd64.v1");

    V = insertOpaqueBarrier(IRB, V);
    Value *Shuffled = IRB.CreateShuffleVector(V, UndefValue::get(VecTy), {1, 0},
                                              "vtd64.shuf");
    Shuffled = insertOpaqueBarrier(IRB, Shuffled);
    Value *Res = IRB.CreateExtractElement(Shuffled, (uint64_t)1, "vtd64.res");
    return insertOpaqueBarrier(IRB, Res);
  }

  if (bw < 32) {
    Type *I32Ty = Type::getInt32Ty(Ctx);
    Value *Ext = IRB.CreateZExt(Val, I32Ty);
    Value *Diff = insertVectorTaintDiffusion(IRB, Ext, EntropyToken);
    return IRB.CreateTrunc(Diff, Ty);
  }

  return Val;
}

Value *getOrCreateDynamicDebugToken(Function *F, Instruction *InsertPt,
                                    const Triple &triple) {
  LLVMContext &Ctx = F->getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Type *PtrTy = PointerType::getUnqual(Ctx);
  FunctionType *DbgFTy = FunctionType::get(I64Ty, false);

  if (triple.getArch() == Triple::x86_64) {
    F->addFnAttr(Attribute::NoRedZone);
  }

  std::string s;

  if ((triple.isOSLinux() || triple.isAndroid()) &&
      triple.getArch() == Triple::x86_64) {
    GlobalVariable *adbRan =
        F->getParent()->getGlobalVariable("ensia_adb_ran", true);
    if (!adbRan) {
      adbRan = new GlobalVariable(*F->getParent(), Type::getInt8Ty(Ctx), false,
                                  GlobalValue::InternalLinkage,
                                  ConstantInt::get(Type::getInt8Ty(Ctx), 0),
                                  "ensia_adb_ran");
      adbRan->setVisibility(GlobalValue::HiddenVisibility);
    }

    s += "xorq %r8, %r8\n\t";
    // 1. RDTSC timing jitter around SYS_getpid
    s += "rdtsc\n\t";
    s += "shlq $$32, %rdx\n\t";
    s += "orq %rax, %rdx\n\t";
    s += "movq %rdx, %r14\n\t";
    s += "movq $$39, %rax\n\t";
    s += "syscall\n\t";
    s += "rdtsc\n\t";
    s += "shlq $$32, %rdx\n\t";
    s += "orq %rax, %rdx\n\t";
    s += "subq %r14, %rdx\n\t";
    s += "cmpq $$0x20000000, %rdx\n\t";
    s += "jbe 10f\n\t";
    s += "movabsq $$0xDEAD0001, %r10\n\t";
    s += "orq %r10, %r8\n\t";
    s += "10:\n\t";
    // 2. TF trap flag in EFLAGS check (debugger single stepping)
    // Red-zone safe: adjust rsp by 128 bytes before pushfq to prevent
    // clobbering leaf function red zone
    s += "subq $$128, %rsp\n\t";
    s += "pushfq\n\t";
    s += "popq %rdx\n\t";
    s += "addq $$128, %rsp\n\t";
    s += "testq $$0x100, %rdx\n\t";
    s += "jz 11f\n\t";
    s += "movabsq $$0xDEAD0002, %r10\n\t";
    s += "orq %r10, %r8\n\t";
    s += "11:\n\t";
    s += "movq %r8, $0\n\t";

    InlineAsm *IA =
        InlineAsm::get(DbgFTy, s,
                       "=r,~{rax},~{rcx},~{rdx},~{rsi},~{rdi},~{r8},~{r10},~{"
                       "r11},~{r14},~{dirflag},~{fpsr},~{flags}",
                       true, false, InlineAsm::AD_ATT);
    CallInst *CI = CallInst::Create(DbgFTy, IA, {}, "adb.tok", InsertPt);

    IRBuilder<> IRB(InsertPt);
    Value *IsDbg =
        IRB.CreateICmpNE(CI, ConstantInt::get(I64Ty, 0), "adb.is_dbg");
    Instruction *ThenTerm =
        SplitBlockAndInsertIfThen(IsDbg, InsertPt, /*unreachable=*/true);
    IRBuilder<> ExitIRB(ThenTerm);
    insertViolentExit(ExitIRB, triple);
    ThenTerm->eraseFromParent();
    return CI;
  }

  if (triple.isOSDarwin() && triple.getArch() == Triple::x86_64) {
    s += "xorq %r8, %r8\n\t";
    // 1. Darwin SYS_ptrace(PT_DENY_ATTACH = 31, 0, 0, 0) -> syscall 26
    // (0x200001A)
    s += "movq $$0x200001A, %rax\n\t";
    s += "movq $$31, %rdi\n\t";
    s += "xorq %rsi, %rsi\n\t";
    s += "xorq %rdx, %rdx\n\t";
    s += "xorq %rcx, %rcx\n\t";
    s += "syscall\n\t";
    // 2. TF trap flag in EFLAGS
    s += "subq $$128, %rsp\n\t";
    s += "pushfq\n\t";
    s += "popq %rdx\n\t";
    s += "addq $$128, %rsp\n\t";
    s += "testq $$0x100, %rdx\n\t";
    s += "jz 10f\n\t";
    s += "movabsq $$0xDEAD0002, %r10\n\t";
    s += "orq %r10, %r8\n\t";
    s += "10:\n\t";
    // 3. Timing jitter check
    s += "rdtsc\n\t";
    s += "shlq $$32, %rdx\n\t";
    s += "orq %rax, %rdx\n\t";
    s += "movq %rdx, %r14\n\t";
    s += "nop\n\tnop\n\tnop\n\tnop\n\t";
    s += "rdtsc\n\t";
    s += "shlq $$32, %rdx\n\t";
    s += "orq %rax, %rdx\n\t";
    s += "subq %r14, %rdx\n\t";
    s += "cmpq $$0x20000000, %rdx\n\t";
    s += "jbe 11f\n\t";
    s += "movabsq $$0xDEAD0001, %r10\n\t";
    s += "orq %r10, %r8\n\t";
    s += "11:\n\t";
    s += "movq %r8, $0\n\t";

    InlineAsm *IA =
        InlineAsm::get(DbgFTy, s,
                       "=r,~{rax},~{rcx},~{rdx},~{rsi},~{rdi},~{r8},~{r10},~{"
                       "r11},~{r14},~{dirflag},~{fpsr},~{flags}",
                       true, false, InlineAsm::AD_ATT);
    CallInst *CI = CallInst::Create(DbgFTy, IA, {}, "adb.tok", InsertPt);

    IRBuilder<> IRB(InsertPt);
    Value *IsDbg =
        IRB.CreateICmpNE(CI, ConstantInt::get(I64Ty, 0), "adb.is_dbg");
    Instruction *ThenTerm =
        SplitBlockAndInsertIfThen(IsDbg, InsertPt, /*unreachable=*/true);
    IRBuilder<> ExitIRB(ThenTerm);
    insertViolentExit(ExitIRB, triple);
    ThenTerm->eraseFromParent();
    return CI;
  }

  if (triple.isOSWindows() && triple.getArch() == Triple::x86_64) {
    s += "xorq %r8, %r8\n\t";
    // 1. PEB BeingDebugged (gs:96 + 2)
    s += "movq %gs:96, %rax\n\t";
    s += "movzbl 2(%rax), %ecx\n\t";
    s += "testl %ecx, %ecx\n\t";
    s += "jz 10f\n\t";
    s += "movabsq $$0xDEAD0001, %r10\n\t";
    s += "orq %r10, %r8\n\t";
    s += "10:\n\t";
    // 2. NtGlobalFlag (gs:96 + 188)
    s += "movl 188(%rax), %ecx\n\t";
    s += "andl $$0x70, %ecx\n\t";
    s += "jz 11f\n\t";
    s += "movabsq $$0xDEAD0002, %r10\n\t";
    s += "orq %r10, %r8\n\t";
    s += "11:\n\t";
    // 3. KUSER_SHARED_DATA (0x7FFE02D4)
    s += "movabsq $$0x7FFE02D4, %rax\n\t";
    s += "movzbl (%rax), %ecx\n\t";
    s += "testl %ecx, %ecx\n\t";
    s += "jz 12f\n\t";
    s += "movabsq $$0xDEAD0004, %r10\n\t";
    s += "orq %r10, %r8\n\t";
    s += "12:\n\t";
    // 4. Trap Flag
    s += "pushfq\n\t";
    s += "popq %rdx\n\t";
    s += "testq $$0x100, %rdx\n\t";
    s += "jz 13f\n\t";
    s += "movabsq $$0xDEAD0008, %r10\n\t";
    s += "orq %r10, %r8\n\t";
    s += "13:\n\t";
    s += "movq %r8, $0\n\t";

    InlineAsm *IA = InlineAsm::get(DbgFTy, s,
                                   "=r,~{rax},~{rcx},~{rdx},~{r8},~{r10},~{r11}"
                                   ",~{dirflag},~{fpsr},~{flags}",
                                   true, false, InlineAsm::AD_ATT);
    CallInst *CI = CallInst::Create(DbgFTy, IA, {}, "adb.tok", InsertPt);

    IRBuilder<> IRB(InsertPt);
    Value *IsDbg =
        IRB.CreateICmpNE(CI, ConstantInt::get(I64Ty, 0), "adb.is_dbg");
    Instruction *ThenTerm =
        SplitBlockAndInsertIfThen(IsDbg, InsertPt, /*unreachable=*/true);
    IRBuilder<> ExitIRB(ThenTerm);
    insertViolentExit(ExitIRB, triple);
    ThenTerm->eraseFromParent();
    return CI;
  }

  if (triple.isAArch64()) {
    s += "mov x11, #0\n\t";
    // cntvct_el0 timing jitter
    s += "mrs x12, cntvct_el0\n\t";
    s += "nop\n\tnop\n\tnop\n\tnop\n\t";
    s += "mrs x13, cntvct_el0\n\t";
    s += "sub x14, x13, x12\n\t";
    s += "mov x10, #0x40000\n\t";
    s += "cmp x14, x10\n\t";
    s += "b.lo 10f\n\t";
    s += "movz x9, #1\n\t";
    s += "movk x9, #0xDEAD, lsl #16\n\t";
    s += "orr x11, x11, x9\n\t";
    s += "10:\n\t";
    if (triple.isOSDarwin()) {
      // PT_DENY_ATTACH on Darwin AArch64
      s += "mov x0, #31\n\t";
      s += "mov x1, #0\n\t";
      s += "mov x2, #0\n\t";
      s += "mov x3, #0\n\t";
      s += "mov x16, #26\n\t";
      s += "svc #0x80\n\t";
    } else if (triple.isOSWindows()) {
      // Windows ARM64 PEB BeingDebugged check (TEB in x18)
      s += "ldr x12, [x18, #0x60]\n\t";
      s += "ldrb w13, [x12, #2]\n\t";
      s += "cbz w13, 12f\n\t";
      s += "movz x9, #2\n\t";
      s += "movk x9, #0xDEAD, lsl #16\n\t";
      s += "orr x11, x11, x9\n\t";
      s += "12:\n\t";
    }
    s += "mov $0, x11\n\t";

    InlineAsm *IA =
        InlineAsm::get(DbgFTy, s,
                       "=r,~{x0},~{x1},~{x2},~{x3},~{x8},~{x9},~{x10},~{x11},~{"
                       "x12},~{x13},~{x14},~{x16},~{cc},~{memory}",
                       true, false);
    CallInst *CI = CallInst::Create(DbgFTy, IA, {}, "adb.tok", InsertPt);

    IRBuilder<> IRB(InsertPt);
    Value *IsDbg =
        IRB.CreateICmpNE(CI, ConstantInt::get(I64Ty, 0), "adb.is_dbg");
    Instruction *ThenTerm =
        SplitBlockAndInsertIfThen(IsDbg, InsertPt, /*unreachable=*/true);
    IRBuilder<> ExitIRB(ThenTerm);
    insertViolentExit(ExitIRB, triple);
    ThenTerm->eraseFromParent();
    return CI;
  }

  return ConstantInt::get(I64Ty, 0);
}

void entangleFunctionIO(Function *F, Value *DbgToken, Value *HookToken,
                        Value *HookBase, Instruction *InsertPt,
                        const Triple &triple) {
  if (F->isDeclaration() || F->empty())
    return;
  if (F->getMetadata("ensia_io_entangled"))
    return;
  F->setMetadata("ensia_io_entangled", MDNode::get(F->getContext(), {}));

  LLVMContext &Ctx = F->getContext();
  Type *I64Ty = Type::getInt64Ty(Ctx);

  if (!InsertPt) {
    BasicBlock &Entry = F->getEntryBlock();
    BasicBlock::iterator EntryIt = Entry.begin();
    while (isa<AllocaInst>(EntryIt))
      ++EntryIt;
    InsertPt = &*EntryIt;
  }

  IRBuilder<> IRB(InsertPt);

  Value *DT = DbgToken ? DbgToken : ConstantInt::get(I64Ty, 0);
  Value *HT = HookToken ? HookToken : ConstantInt::get(I64Ty, 0);
  Value *HB = HookBase ? HookBase : ConstantInt::get(I64Ty, 0);

  Value *K1 = ConstantInt::get(I64Ty, 0x517cc1b727220a95ULL);
  Value *K2 = ConstantInt::get(I64Ty, 0x9e3779b97f4a7c15ULL);

  // Scheme 1: Environment Keying
  // T_env = (HT * K1) ^ (DT * K2)
  Value *T_env =
      IRB.CreateXor(IRB.CreateMul(HT, K1), IRB.CreateMul(DT, K2), "env.tok");
  // T_exp = (HB * K1) ^ 0
  Value *T_exp = IRB.CreateMul(HB, K1, "env.exp");

  bool hasEntangledArg = false;

  // Scheme 1, 2, 4: Entangle Arguments
  unsigned argIdx = 0;
  for (Argument &Arg : F->args()) {
    Type *ArgTy = Arg.getType();
    if (ArgTy->isIntegerTy()) {
      unsigned bw = ArgTy->getIntegerBitWidth();
      if (bw >= 8 && bw <= 64) {
        uint64_t rotShift = (argIdx + 1) * 11;
        Value *RotEnv =
            IRB.CreateOr(IRB.CreateShl(T_env, rotShift % 64),
                         IRB.CreateLShr(T_env, (64 - (rotShift % 64)) % 64));
        Value *RotExp =
            IRB.CreateOr(IRB.CreateShl(T_exp, rotShift % 64),
                         IRB.CreateLShr(T_exp, (64 - (rotShift % 64)) % 64));
        Value *M_env = IRB.CreateTrunc(RotEnv, ArgTy, "m.env");
        Value *M_exp = IRB.CreateTrunc(RotExp, ArgTy, "m.exp");

        Value *ArgMasked = IRB.CreateXor(&Arg, M_env, "arg.masked");
        // Scheme 2: Implicit flow taint laundering
        Value *ArgLaundered = insertTaintLaunder(IRB, ArgMasked);
        // Scheme 4: SIMD vector diffusion
        ArgLaundered = insertVectorTaintDiffusion(
            IRB, ArgLaundered, IRB.CreateTrunc(T_env, ArgTy));
        Value *ArgReal = IRB.CreateXor(ArgLaundered, M_exp, "arg.real");

        Arg.replaceUsesWithIf(ArgReal,
                              [&](Use &U) { return U.getUser() != ArgMasked; });
        hasEntangledArg = true;
      }
    }
    argIdx++;
  }

  // Scheme 3, 2, 4: Entangle Return Values
  for (BasicBlock &BB : *F) {
    if (BB.empty() || !BB.back().isTerminator())
      continue;
    Instruction *Term = BB.getTerminator();
    if (!Term)
      continue;
    if (ReturnInst *RI = dyn_cast<ReturnInst>(Term)) {
      Value *RetVal = RI->getReturnValue();
      if (RetVal && RetVal->getType()->isIntegerTy()) {
        Type *RetTy = RetVal->getType();
        unsigned bw = RetTy->getIntegerBitWidth();
        if (bw >= 8 && bw <= 64) {
          IRBuilder<> RetIRB(RI);
          uint64_t rotShift = 23;
          Value *RotEnv =
              RetIRB.CreateOr(RetIRB.CreateShl(T_env, rotShift),
                              RetIRB.CreateLShr(T_env, 64 - rotShift));
          Value *RotExp =
              RetIRB.CreateOr(RetIRB.CreateShl(T_exp, rotShift),
                              RetIRB.CreateLShr(T_exp, 64 - rotShift));
          Value *M_env = RetIRB.CreateTrunc(RotEnv, RetTy);
          Value *M_exp = RetIRB.CreateTrunc(RotExp, RetTy);

          Value *RetMasked = RetIRB.CreateXor(RetVal, M_exp, "ret.masked");
          Value *RetLaundered = insertTaintLaunder(RetIRB, RetMasked);
          RetLaundered = insertVectorTaintDiffusion(
              RetIRB, RetLaundered, RetIRB.CreateTrunc(T_env, RetTy));
          Value *RetFinal = RetIRB.CreateXor(RetLaundered, M_env, "ret.final");
          RI->setOperand(0, RetFinal);
        }
      }
    }
  }

  // Fallback / No-SPOF protection: If function had no integer arguments,
  // entangle the first eligible internal integer operation in the entry block
  if (!hasEntangledArg) {
    Value *Delta = IRB.CreateXor(T_env, T_exp, "env.delta");
    BasicBlock &Entry = F->getEntryBlock();
    for (Instruction &Inst : Entry) {
      if (&Inst == InsertPt || isa<AllocaInst>(&Inst) || isa<PHINode>(&Inst))
        continue;
      if (Inst.isBinaryOp() && Inst.getType()->isIntegerTy()) {
        Type *ITy = Inst.getType();
        if (ITy->getIntegerBitWidth() <= 64) {
          IRBuilder<> OpIRB(&Entry, ++Inst.getIterator());
          Value *TruncDelta =
              OpIRB.CreateZExtOrTrunc(Delta, ITy, "env.trunc.delta");
          Value *LaunderedDelta = insertTaintLaunder(OpIRB, TruncDelta);
          LaunderedDelta = insertVectorTaintDiffusion(
              OpIRB, LaunderedDelta, OpIRB.CreateTrunc(T_env, ITy));
          Value *Entangled =
              OpIRB.CreateXor(&Inst, LaunderedDelta, "env.entangled");
          Inst.replaceAllUsesWith(Entangled);
          cast<User>(Entangled)->setOperand(0, &Inst);
          break;
        }
      }
    }
  }
}

} // namespace llvm
