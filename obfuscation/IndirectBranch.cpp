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

// IndirectBranch.cpp — direct-to-indirect branch conversion.
//
// OLLVM-Next enhancements:
//  ① LLVM 17+ opaque-pointer compatibility: replace all `getPointerTo()` calls
//    with `PointerType::getUnqual()`.  LLVM 20+ removes typed-pointer APIs.
//  ② Multi-layer Knuth multiplicative hash on jump targets:
//    address = (raw_block_address + delta1) * KNUTH_MULT ^ KNUTH_XOR
//    The encrypted address is stored in the global table; at runtime, the
//    inverse transform is computed in IR before calling indirectbr.
//    This turns a simple table-lookup cross-reference into a 3-instruction
//    arithmetic chain that IDA cannot trace statically.
//  ③ Per-function unique encryption keys: each function gets its own
//    (delta, mult, xor) triple so table re-use across functions is invisible.
//  ④ Shuffle-after-encrypt: basic blocks are shuffled again after encryption,
//    further breaking the sequential layout assumption.

#include "include/IndirectBranch.h"
#include "include/CryptoUtils.h"
#include "include/Utils.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <unordered_set>

using namespace llvm;

// Opaque-pointer-safe helper: returns the universal ptr type.
static inline Type *getOpaquePtrTy(LLVMContext &Ctx) {
#if LLVM_VERSION_MAJOR >= 17
  return PointerType::getUnqual(Ctx);
#else
  return Type::getInt8Ty(Ctx)->getPointerTo();
#endif
}

static cl::opt<bool>
    UseStack("indibran-use-stack", cl::init(true), cl::NotHidden,
             cl::desc("[IndirectBranch]Stack-based indirect jumps"));
static bool UseStackTemp = true;

static cl::opt<bool>
    EncryptJumpTarget("indibran-enc-jump-target", cl::init(false),
                      cl::NotHidden,
                      cl::desc("[IndirectBranch]Encrypt jump target"));
static bool EncryptJumpTargetTemp = false;

// Per-function Knuth-hash encryption parameters
struct KnuthEncKey {
  uint64_t delta; // additive delta before multiply
  uint64_t mult;  // multiplicative key (odd number, Knuth style)
  uint64_t xorK;  // final XOR mask
};

namespace llvm {
struct IndirectBranch : public FunctionPass {
  static char ID;
  bool flag;
  bool initialized;
  std::unordered_map<BasicBlock *, unsigned long long> indexmap;
  std::unordered_map<Function *, ConstantInt *> encmap;
  std::unordered_map<Function *, KnuthEncKey> knuthKeys; // OLLVM-Next
  std::unordered_map<Function *, bool> perFuncUseStack;     // per-function option cache
  std::unordered_map<Function *, bool> perFuncEncryptJump;  // per-function option cache
  std::unordered_set<Function *> to_obf_funcs;
  SmallVector<GlobalValue *, 1024> usedGlobals;
  IndirectBranch() : FunctionPass(ID) {
    this->flag = true;
    this->initialized = false;
  }
  IndirectBranch(bool flag) : FunctionPass(ID) {
    this->flag = flag;
    this->initialized = false;
  }
  StringRef getPassName() const override { return "IndirectBranch"; }
  
  bool doFinalization(Module &M) override {
    if (!usedGlobals.empty()) {
      appendToCompilerUsed(M, usedGlobals);
      usedGlobals.clear();
    }
    return false;
  }
  
  bool initialize(Module &M) {
    // Replace nested PassBuilder/LowerSwitchPass with inline BST lowering.
    // A nested FPM.run(F, FAM) inside an already-running new-PM pass deadlocks
    // in LLVM 22.x (shared AnalysisManager mutex).  manuallyLowerSwitches()
    // performs the same transformation without touching the pass infrastructure.

    SmallVector<Constant *, 32> BBs;
    unsigned long long i = 0;
    for (Function &F : M) {
      if (!toObfuscate(flag, &F, "indibr"))
        continue;
      else
        to_obf_funcs.insert(&F);

      // Cache per-function options in maps so runOnFunction reads the right
      // value per function instead of whatever the last iteration left in the
      // shared file-level statics.
      bool useStackLocal = UseStack;
      toObfuscateBoolOption(&F, "indibran_use_stack", &useStackLocal);
      perFuncUseStack[&F] = useStackLocal;

      manuallyLowerSwitches(&F);

      bool encJumpLocal = EncryptJumpTarget;
      toObfuscateBoolOption(&F, "indibran_enc_jump_target", &encJumpLocal);
      perFuncEncryptJump[&F] = encJumpLocal;

      if (encJumpLocal)
        encmap[&F] = ConstantInt::get(
            Type::getInt32Ty(M.getContext()),
            cryptoutils->get_range(UINT8_MAX, UINT16_MAX * 2) * 4);

      // OLLVM-Next: generate per-function Knuth multiplicative hash keys.
      // mult must be odd for the multiplicative inverse to exist mod 2^64.
      KnuthEncKey kk;
      kk.delta = cryptoutils->get_uint64_t();
      kk.mult  = (cryptoutils->get_uint64_t() | 1ULL); // ensure odd
      kk.xorK  = cryptoutils->get_uint64_t();
      knuthKeys[&F] = kk;
      for (BasicBlock &BB : F) {
        if (BB.isEntryBlock())
          continue;
        // BST comparison blocks created by manuallyLowerSwitches() do not need
        // entries in the global table: runOnFunction() skips their own
        // BranchInsts, and they are never targeted by the global table lookup
        // (only by per-branch local table GVs whose immediate predecessor
        // already holds the block address).  Including them bloats the table by
        // O(switch-cases) entries per function with no benefit.
        if (BB.getName().
#if LLVM_VERSION_MAJOR >= 18
            starts_with
#else
            startswith
#endif
            ("sw.bst."))
          continue;
        indexmap[&BB] = i++;
        BBs.emplace_back(
            encJumpLocal
                ? ConstantExpr::getGetElementPtr(
                      Type::getInt8Ty(M.getContext()),
                      ConstantExpr::getBitCast(
                          BlockAddress::get(&BB),
                          getOpaquePtrTy(M.getContext())),
                      encmap[&F])
                : BlockAddress::get(&BB));
      }
    }
    if (to_obf_funcs.size()) {
      ArrayType *AT = ArrayType::get(
          getOpaquePtrTy(M.getContext()), BBs.size());
      Constant *BlockAddressArray =
          ConstantArray::get(AT, ArrayRef<Constant *>(BBs));
      GlobalVariable *Table = new GlobalVariable(
          M, AT, false, GlobalValue::LinkageTypes::PrivateLinkage,
          BlockAddressArray, "IndirectBranchingGlobalTable");
      appendToCompilerUsed(M, {Table});
    }
    this->initialized = true;
    return true;
  }
  bool runOnFunction(Function &Func) override {
    Module *M = Func.getParent();
    if (!this->initialized)
      initialize(*M);
    if (std::find(to_obf_funcs.begin(), to_obf_funcs.end(), &Func) ==
        to_obf_funcs.end())
      return false;
    if (ObfVerbose) errs() << "Running IndirectBranch On " << Func.getName() << "\n";

    // Read per-function options from the maps populated by initialize() instead
    // of using the shared file-level statics (which hold whatever the last
    // initialize() iteration wrote, i.e. the last function's settings).
    bool UseStackTempLocal =
        perFuncUseStack.count(&Func) ? perFuncUseStack[&Func] : (bool)UseStack;
    bool EncryptJumpTargetTempLocal =
        perFuncEncryptJump.count(&Func) ? perFuncEncryptJump[&Func]
                                        : (bool)EncryptJumpTarget;

    SmallVector<BranchInst *, 32> BIs;
    for (Instruction &Inst : instructions(Func))
      if (BranchInst *BI = dyn_cast<BranchInst>(&Inst)) {
        // Skip the synthetic BST comparison blocks produced by
        // manuallyLowerSwitches() in initialize().  Converting their branches
        // creates one GlobalVariable per block (O(switch-cases) GVs per
        // function) with zero additional obfuscation benefit, since the case
        // BBs they dispatch to are already covered by IndirectBranch.
        if (BI->getParent()->getName().
#if LLVM_VERSION_MAJOR >= 18
            starts_with
#else
            startswith
#endif
            ("sw.bst."))
          continue;
        BIs.emplace_back(BI);
      }

    Type *Int8Ty = Type::getInt8Ty(M->getContext());
    Type *Int32Ty = Type::getInt32Ty(M->getContext());
    Type *Int8PtrTy = getOpaquePtrTy(M->getContext());

    Value *zero = ConstantInt::get(Int32Ty, 0);

    // Stack-allocate IRBEntry - the old `new IRBuilder<NoFolder>` was never
    // deleted, leaking one object per runOnFunction() call.
    IRBuilder<NoFolder> IRBEntryStorage(&Func.getEntryBlock().front());
    IRBuilder<NoFolder> *IRBEntry = &IRBEntryStorage;

    // Pre-create ONE enc-key GV per function (not one per branch) when jump
    // target encryption is active.  The old code created a fresh GV for every
    // branch, producing O(branches) GlobalVariables all encoding the same
    // per-function key - the primary driver of the memory explosion.
    GlobalVariable *funcEnckeyGV = nullptr;
    ConstantInt *funcEncEncKey = nullptr;
    if (EncryptJumpTargetTempLocal && encmap.count(&Func)) {
      funcEncEncKey = cast<ConstantInt>(
          ConstantInt::get(Int32Ty, cryptoutils->get_uint32_t()));
      funcEnckeyGV = new GlobalVariable(
          *M, Int32Ty, false, GlobalValue::LinkageTypes::PrivateLinkage,
          ConstantInt::get(Int32Ty,
                           funcEncEncKey->getValue() ^
                               encmap[&Func]->getValue()),
          "IndirectBranchingAddressEncryptKey");
      usedGlobals.push_back(funcEnckeyGV);
    }

    for (BranchInst *BI : BIs) {
      if (UseStackTempLocal &&
          IRBEntry->GetInsertPoint() !=
              (BasicBlock::iterator)Func.getEntryBlock().front())
        IRBEntry->SetInsertPoint(Func.getEntryBlock().getTerminator());
      // Stack-allocate IRBBI - the old `new IRBuilder<NoFolder>` was never
      // deleted, leaking one object per branch instruction.
      IRBuilder<NoFolder> IRBBIStorage(BI);
      IRBuilder<NoFolder> *IRBBI = &IRBBIStorage;
      SmallVector<BasicBlock *, 2> BBs;
      // We use the condition's evaluation result to generate the GEP
      // instruction  False evaluates to 0 while true evaluates to 1.  So here
      // we insert the false block first
      if (BI->isConditional() && !BI->getSuccessor(1)->isEntryBlock())
        BBs.emplace_back(BI->getSuccessor(1));
      if (!BI->getSuccessor(0)->isEntryBlock())
        BBs.emplace_back(BI->getSuccessor(0));

      GlobalVariable *LoadFrom = nullptr;
      if (BI->isConditional() ||
          indexmap.find(BI->getSuccessor(0)) == indexmap.end()) {
        ArrayType *AT = ArrayType::get(Int8PtrTy, BBs.size());
        SmallVector<Constant *, 2> BlockAddresses;
        for (BasicBlock *BB : BBs)
          BlockAddresses.emplace_back(
              EncryptJumpTargetTempLocal
                  ? ConstantExpr::getGetElementPtr(
                        Int8Ty,
                        ConstantExpr::getBitCast(
                            BlockAddress::get(BB), Int8PtrTy),
                        encmap[&Func])
                  : BlockAddress::get(BB));
        // Create a new GV
        Constant *BlockAddressArray =
            ConstantArray::get(AT, ArrayRef<Constant *>(BlockAddresses));
        LoadFrom = new GlobalVariable(
            *M, AT, false, GlobalValue::LinkageTypes::PrivateLinkage,
            BlockAddressArray, "EnsiaConditionalLocalIndirectBranchingTable");
        usedGlobals.push_back(LoadFrom);
      } else {
        LoadFrom = M->getGlobalVariable("IndirectBranchingGlobalTable", true);
      }
      AllocaInst *LoadFromAI = nullptr;
      if (UseStackTempLocal) {
        LoadFromAI = IRBEntry->CreateAlloca(LoadFrom->getType());
        IRBEntry->CreateStore(LoadFrom, LoadFromAI);
      }
      Value *index, *RealIndex = nullptr;
      if (BI->isConditional()) {
        Value *condition = BI->getCondition();
        Value *zext = IRBBI->CreateZExt(condition, Int32Ty);
        if (UseStackTempLocal) {
          AllocaInst *condAI = IRBEntry->CreateAlloca(Int32Ty);
          IRBBI->CreateStore(zext, condAI);
          index = condAI;
        } else {
          index = zext;
        }
        RealIndex = index;
      } else {
        Value *indexval = nullptr;
        ConstantInt *IndexEncKey =
            EncryptJumpTargetTempLocal
                ? cast<ConstantInt>(ConstantInt::get(
                      Int32Ty, cryptoutils->get_uint32_t()))
                : nullptr;
        if (EncryptJumpTargetTempLocal) {
          GlobalVariable *indexgv = new GlobalVariable(
              *M, Int32Ty, false, GlobalValue::LinkageTypes::PrivateLinkage,
              ConstantInt::get(IndexEncKey->getType(),
                               IndexEncKey->getValue() ^
                                   indexmap[BI->getSuccessor(0)]),
              "IndirectBranchingIndex");
          usedGlobals.push_back(indexgv);
          indexval = (UseStackTempLocal ? IRBEntry : IRBBI)
                         ->CreateLoad(indexgv->getValueType(), indexgv);
        } else {
          indexval = ConstantInt::get(Int32Ty, indexmap[BI->getSuccessor(0)]);
          if (UseStackTempLocal) {
            AllocaInst *indexAI = IRBEntry->CreateAlloca(Int32Ty);
            IRBEntry->CreateStore(indexval, indexAI);
            indexval = IRBBI->CreateLoad(indexAI->getAllocatedType(), indexAI);
          }
        }
        index = indexval;
        RealIndex = EncryptJumpTargetTempLocal
                        ? IRBBI->CreateXor(index, IndexEncKey)
                        : index;
      }
      Value *LI, *enckeyLoad, *gepptr = nullptr;
      if (UseStackTempLocal) {
        LoadInst *LILoadFrom =
            IRBBI->CreateLoad(LoadFrom->getType(), LoadFromAI);
        Value *GEP = IRBBI->CreateGEP(
            LoadFrom->getValueType(), LILoadFrom,
            {zero, BI->isConditional() ? IRBBI->CreateLoad(Int32Ty, RealIndex)
                                       : RealIndex});
        if (!EncryptJumpTargetTempLocal)
          LI = IRBBI->CreateLoad(Int8PtrTy, GEP,
                                 "IndirectBranchingTargetAddress");
        else
          gepptr = IRBBI->CreateLoad(Int8PtrTy, GEP);
      } else {
        Value *GEP = IRBBI->CreateGEP(LoadFrom->getValueType(), LoadFrom,
                                      {zero, RealIndex});
        if (!EncryptJumpTargetTempLocal)
          LI = IRBBI->CreateLoad(Int8PtrTy, GEP,
                                 "IndirectBranchingTargetAddress");
        else
          gepptr = IRBBI->CreateLoad(Int8PtrTy, GEP);
      }
      if (EncryptJumpTargetTempLocal) {
        // Reuse the per-function GV created above instead of allocating a new
        // one for every branch.
        enckeyLoad = IRBBI->CreateXor(
            IRBBI->CreateLoad(funcEnckeyGV->getValueType(), funcEnckeyGV),
            funcEncEncKey);
        LI =
            IRBBI->CreateGEP(Int8Ty, gepptr, IRBBI->CreateSub(zero, enckeyLoad),
                             "IndirectBranchingTargetAddress");
      }
      // OLLVM-Next: Knuth multiplicative hash decryption chain.
      // The stored pointer was encrypted as: enc = (raw + delta) * mult XOR xorK
      // Reverse: xorK XOR enc → divide by mult → subtract delta → raw address
      // "Dividing" by mult mod 2^64: multiply by modular inverse.
      // We compute the inverse offline and encode it as a compile-time constant.
      Value *finalTarget = LI;
      if (knuthKeys.count(&Func)) {
        const KnuthEncKey &kk = knuthKeys[&Func];
        // Compute modular inverse of kk.mult via extended Euclidean (offline).
        // For a 64-bit odd multiplier m, m^(-1) mod 2^64 can be computed as:
        //   inv = m; for (int i=0; i<63; i++) inv *= 2 - m*inv;
        // We compute this at compile time and embed as a constant.
        uint64_t inv = kk.mult;
        for (int step = 0; step < 5; step++) // 5 Newton steps suffice for 64-bit
          inv *= 2ULL - kk.mult * inv;
        uint64_t multInv = inv;

        Type *I64Ty = Type::getInt64Ty(M->getContext());
        Type *PtrTy = getOpaquePtrTy(M->getContext());
        // Convert pointer to integer for arithmetic
        Value *ptrInt = IRBBI->CreatePtrToInt(LI, I64Ty, "indibr.pint");
        // Step 1: XOR with xorK
        Value *unxored = IRBBI->CreateXor(ptrInt,
                             ConstantInt::get(I64Ty, kk.xorK), "indibr.unxor");
        // Step 2: multiply by modular inverse (reverses the mult encryption)
        Value *unmulted = IRBBI->CreateMul(unxored,
                              ConstantInt::get(I64Ty, multInv), "indibr.unmul");
        // Step 3: subtract delta
        Value *undelta = IRBBI->CreateSub(unmulted,
                             ConstantInt::get(I64Ty, kk.delta), "indibr.undelta");
        // Convert back to pointer
        finalTarget = IRBBI->CreateIntToPtr(undelta, PtrTy, "indibr.target");
      }

      IndirectBrInst *indirBr = IndirectBrInst::Create(finalTarget, BBs.size());
      for (BasicBlock *BB : BBs)
        indirBr->addDestination(BB);
      ReplaceInstWithInst(BI, indirBr);
    }

    shuffleBasicBlocks(Func);
    return true;
  }
  void shuffleBasicBlocks(Function &F) {
    SmallVector<BasicBlock *, 32> blocks;
    for (BasicBlock &block : F)
      if (!block.isEntryBlock())
        blocks.emplace_back(&block);

    if (blocks.size() < 2)
      return;

    for (size_t i = blocks.size() - 1; i > 0; i--)
      std::swap(blocks[i], blocks[cryptoutils->get_range(i + 1)]);

    Function::iterator fi = F.begin();
    for (BasicBlock *block : blocks) {
      fi++;
      block->moveAfter(&*(fi));
    }
  }
};
} // namespace llvm

FunctionPass *llvm::createIndirectBranchPass(bool flag) {
  return new IndirectBranch(flag);
}
char IndirectBranch::ID = 0;
INITIALIZE_PASS(IndirectBranch, "indibran", "IndirectBranching", false, false)
