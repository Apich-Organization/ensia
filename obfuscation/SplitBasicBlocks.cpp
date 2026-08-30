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

#include "include/CryptoUtils.h"
#include "include/ObfConfig.h"
#include "include/Split.h"
#include "include/Utils.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/CommandLine.h"

using namespace llvm;

static cl::opt<uint32_t> SplitNum("split_num", cl::init(2),
                                  cl::desc("Split <split_num> time each BB"));
static thread_local uint32_t SplitNumTemp = 2;

static cl::opt<bool> StackConfusion(
    "split_stackconf",
    cl::desc("[SplitBB] Inject balanced push/pop sequences to confuse LLIL "
             "stack-offset analysis in Binary Ninja"),
    cl::init(true), cl::Optional);
static thread_local bool StackConfusionTemp = true;

static bool moduleIsX86_64(Function *F) {
  StringRef triple = F->getParent()->getTargetTriple().getTriple();
  return triple.contains("x86_64") || triple.contains("amd64");
}
static bool moduleIsAArch64(Function *F) {
  StringRef triple = F->getParent()->getTargetTriple().getTriple();
  return triple.contains("aarch64") || triple.contains("arm64");
}

// Inject a balanced push/pop sequence at the beginning of BB (after PHI nodes).
static void injectStackConfusion(BasicBlock *BB, Function *F) {
  if (!StackConfusionTemp)
    return;

  Instruction *insertPt = &*BB->getFirstNonPHIOrDbgOrLifetime();
  if (!insertPt)
    return;

  if (moduleIsX86_64(F)) {
    // Safe register-only junk sequence on scratch registers r10 and r11
    // (Never touches rsp/stack to strictly respect x86-64 System V ABI red-zone).
    std::string asmStr = "xorq %r10, %r10\n\t"
                         "addq $$0x13371337, %r10\n\t"
                         "subq $$0x13371337, %r10\n\t"
                         "xorq %r11, %r11\n\t"
                         "addq $$0x12345678, %r11\n\t"
                         "subq $$0x12345678, %r11\n\t";
    std::string constraints = "~{r10},~{r11},~{dirflag},~{fpsr},~{flags}";

    FunctionType *AsmFTy =
        FunctionType::get(Type::getVoidTy(BB->getContext()), false);
    InlineAsm *IA = InlineAsm::get(AsmFTy, asmStr, constraints,
                                   /*hasSideEffects=*/true, InlineAsm::AD_ATT);
    CallInst::Create(AsmFTy, IA, {}, "", insertPt);
    turnOffOptimization(F);

  } else if (moduleIsAArch64(F)) {
    // Safe register-only junk sequence on scratch registers x9 and x10
    std::string asmStr = "eor x9, x9, x9\n\t"
                         "add x9, x9, #0x42\n\t"
                         "sub x9, x9, #0x42\n\t"
                         "eor x10, x10, x10\n\t"
                         "add x10, x10, #0x77\n\t"
                         "sub x10, x10, #0x77\n\t";
    FunctionType *AsmFTy =
        FunctionType::get(Type::getVoidTy(BB->getContext()), false);
    InlineAsm *IA = InlineAsm::get(AsmFTy, asmStr,
                                   "~{x9},~{x10},~{dirflag},~{fpsr},~{flags}",
                                   /*hasSideEffects=*/true, InlineAsm::AD_ATT);
    CallInst::Create(AsmFTy, IA, {}, "", insertPt);
    turnOffOptimization(F);
  }
}

namespace {
struct SplitBasicBlock : public FunctionPass {
  static char ID; // Pass identification, replacement for typeid
  bool flag;
  SplitBasicBlock() : FunctionPass(ID) { this->flag = true; }
  SplitBasicBlock(bool flag) : FunctionPass(ID) { this->flag = flag; }

  bool runOnFunction(Function &F) override {
    {
      auto ec =
          GObfConfig.resolve(F.getParent()->getSourceFileName(), F.getName());
      if (!toObfuscateUint32Option(&F, "split_num", &SplitNumTemp))
        SplitNumTemp = ec.split.splits.value_or((uint32_t)SplitNum);
      if (!toObfuscateBoolOption(&F, "split_stackconf", &StackConfusionTemp))
        StackConfusionTemp =
            ec.split.stack_confusion.value_or((bool)StackConfusion);
    }

    // Check if the number of applications is correct
    if (!((SplitNumTemp > 1) && (SplitNumTemp <= 10))) {
      errs()
          << "Split application basic block percentage -split_num=x must be 1 "
             "< x <= 10";
      return false;
    }

    // Do we obfuscate
    if (toObfuscate(flag, &F, "split")) {
      if (ObfVerbose)
        errs() << "Running BasicBlockSplit On " << F.getName() << "\n";
      split(&F);
    }

    return true;
  }
  void split(Function *F) {
    SmallVector<BasicBlock *, 16> origBB;
    size_t split_ctr = 0;

    // Save all basic blocks
    for (BasicBlock &BB : *F)
      origBB.emplace_back(&BB);

    for (BasicBlock *currBB : origBB) {
      if (currBB->size() < 2 || containsPHI(currBB) ||
          containsSwiftError(currBB))
        continue;

      if ((size_t)SplitNumTemp > currBB->size() - 1)
        split_ctr = currBB->size() - 1;
      else
        split_ctr = (size_t)SplitNumTemp;

      // Generate splits point (count number of the LLVM instructions in the
      // current BB)
      SmallVector<size_t, 32> llvm_inst_ord;
      for (size_t i = 1; i < currBB->size(); ++i)
        llvm_inst_ord.emplace_back(i);

      // Shuffle
      split_point_shuffle(llvm_inst_ord);
      std::sort(llvm_inst_ord.begin(), llvm_inst_ord.begin() + split_ctr);

      // Split
      size_t llvm_inst_prev_offset = 0;
      BasicBlock::iterator curr_bb_it = currBB->begin();
      BasicBlock *curr_bb_offset = currBB;

      for (size_t i = 0; i < split_ctr; ++i) {
        for (size_t j = 0; j < llvm_inst_ord[i] - llvm_inst_prev_offset; ++j)
          ++curr_bb_it;

        llvm_inst_prev_offset = llvm_inst_ord[i];

        // Skip splitting inside the alloca run of a probe-stack entry block.
        // The probe thunk expects all allocas to stay in the entry block;
        // moving one out causes stack probing to under-probe, leading to a
        // guard-page segfault.  Skip any split point that still points at
        // an alloca and let the iterator advance to a non-alloca instruction.
        if (F->hasFnAttribute("probe-stack") && currBB->isEntryBlock()) {
          // Advance past any trailing allocas at this split point
          while (curr_bb_it != curr_bb_offset->end() &&
                 isa<AllocaInst>(curr_bb_it))
            ++curr_bb_it;
          if (curr_bb_it == curr_bb_offset->end())
            continue;
        }

        BasicBlock *newBB = curr_bb_offset->splitBasicBlock(
            curr_bb_it, curr_bb_offset->getName() + ".split");
        curr_bb_offset = newBB;
        if (cryptoutils->get_range(2) == 0)
          injectStackConfusion(newBB, F);
      }
    }
  }

  bool containsPHI(BasicBlock *BB) {
    for (Instruction &I : *BB)
      if (isa<PHINode>(&I))
        return true;
    return false;
  }

  bool containsSwiftError(BasicBlock *BB) {
    for (Instruction &I : *BB)
      if (AllocaInst *AI = dyn_cast<AllocaInst>(&I))
        if (AI->isSwiftError())
          return true;
    return false;
  }

  void split_point_shuffle(SmallVector<size_t, 32> &vec) {
    int n = vec.size();
    for (int i = n - 1; i > 0; --i)
      std::swap(vec[i], vec[cryptoutils->get_range(i + 1)]);
  }
};
} // namespace

char SplitBasicBlock::ID = 0;
INITIALIZE_PASS(SplitBasicBlock, "splitobf", "Enable BasicBlockSpliting.",
                false, false)

FunctionPass *llvm::createSplitBasicBlockPass(bool flag) {
  return new SplitBasicBlock(flag);
}
