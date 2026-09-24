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
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"
#include <set>

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

static cl::alias SplitNumAlias1("split-num", cl::desc("Alias for -split_num"),
                                cl::aliasopt(SplitNum));
static cl::alias SplitNumAlias2("split_splits",
                                cl::desc("Alias for -split_num"),
                                cl::aliasopt(SplitNum));
static cl::alias SplitNumAlias3("split-splits",
                                cl::desc("Alias for -split_num"),
                                cl::aliasopt(SplitNum));
static cl::alias StackConfusionAlias1("split-stackconf",
                                      cl::desc("Alias for -split_stackconf"),
                                      cl::aliasopt(StackConfusion));
static cl::alias StackConfusionAlias2("split_stack_confusion",
                                      cl::desc("Alias for -split_stackconf"),
                                      cl::aliasopt(StackConfusion));
static cl::alias StackConfusionAlias3("split-stack-confusion",
                                      cl::desc("Alias for -split_stackconf"),
                                      cl::aliasopt(StackConfusion));

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
    // (Never touches rsp/stack to strictly respect x86-64 System V ABI
    // red-zone). Randomize constants to eliminate static signature.
    uint32_t k1 = cryptoutils->get_uint32_t() & 0x7fffffff;
    uint32_t k2 = cryptoutils->get_uint32_t() & 0x7fffffff;
    std::string asmStr;
    raw_string_ostream OS(asmStr);
    OS << "xorq %r10, %r10\n\t"
       << "addq $$0x" << format_hex_no_prefix(k1, 8) << ", %r10\n\t"
       << "subq $$0x" << format_hex_no_prefix(k1, 8) << ", %r10\n\t"
       << "xorq %r11, %r11\n\t"
       << "addq $$0x" << format_hex_no_prefix(k2, 8) << ", %r11\n\t"
       << "subq $$0x" << format_hex_no_prefix(k2, 8) << ", %r11\n\t";
    std::string constraints = "~{r10},~{r11},~{dirflag},~{fpsr},~{flags}";

    FunctionType *AsmFTy =
        FunctionType::get(Type::getVoidTy(BB->getContext()), false);
    InlineAsm *IA = InlineAsm::get(AsmFTy, OS.str(), constraints,
                                   /*hasSideEffects=*/true, InlineAsm::AD_ATT);
    CallInst::Create(AsmFTy, IA, {}, "", insertPt);
    turnOffOptimization(F);

  } else if (moduleIsAArch64(F)) {
    // Safe register-only junk sequence on scratch registers x9 and x10
    uint32_t k1 = (cryptoutils->get_range(0xFFF) + 1);
    uint32_t k2 = (cryptoutils->get_range(0xFFF) + 1);
    std::string asmStr;
    raw_string_ostream OS(asmStr);
    OS << "eor x9, x9, x9\n\t"
       << "add x9, x9, #" << k1 << "\n\t"
       << "sub x9, x9, #" << k1 << "\n\t"
       << "eor x10, x10, x10\n\t"
       << "add x10, x10, #" << k2 << "\n\t"
       << "sub x10, x10, #" << k2 << "\n\t";
    FunctionType *AsmFTy =
        FunctionType::get(Type::getVoidTy(BB->getContext()), false);
    InlineAsm *IA =
        InlineAsm::get(AsmFTy, OS.str(), "~{x9},~{x10},~{cc},~{memory}",
                       /*hasSideEffects=*/true);
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
    bool shouldObf = flag;
    {
      auto ec =
          GObfConfig.resolve(F.getParent()->getSourceFileName(), F.getName());
      shouldObf = ec.split.enabled.value_or(flag);
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
    if (toObfuscate(shouldObf, &F, "split")) {
      if (ObfVerbose)
        errs() << "Running BasicBlockSplit On " << F.getName() << "\n";
      split(&F);
    }

    return true;
  }
  void split(Function *F) {
    SmallVector<BasicBlock *, 16> origBB;

    // Save all basic blocks
    for (BasicBlock &BB : *F)
      origBB.emplace_back(&BB);

    for (BasicBlock *currBB : origBB) {
      size_t bb_size = currBB->size();
      if (bb_size < 2 || containsPHI(currBB) || containsSwiftError(currBB))
        continue;

      if (currBB->isEntryBlock()) {
        size_t nonAllocaCount = 0;
        for (Instruction &I : *currBB) {
          if (!isa<AllocaInst>(&I))
            nonAllocaCount++;
        }
        if (nonAllocaCount < 2)
          continue;
      }

      size_t split_ctr = std::min((size_t)SplitNumTemp, bb_size - 1);

      // Generate splits point
      SmallVector<size_t, 32> llvm_inst_ord;
      if (bb_size <= 64) {
        for (size_t i = 1; i < bb_size; ++i)
          llvm_inst_ord.emplace_back(i);
        split_point_shuffle(llvm_inst_ord);
        std::sort(llvm_inst_ord.begin(), llvm_inst_ord.begin() + split_ctr);
      } else {
        // Direct random sampling for large basic blocks (O(split_ctr log
        // split_ctr) instead of O(N))
        std::set<size_t> chosen;
        while (chosen.size() < split_ctr) {
          chosen.insert(1 + (size_t)cryptoutils->get_range(bb_size - 1));
        }
        for (size_t pt : chosen)
          llvm_inst_ord.push_back(pt);
      }

      // Split
      size_t llvm_inst_prev_offset = 0;
      BasicBlock::iterator curr_bb_it = currBB->begin();
      BasicBlock *curr_bb_offset = currBB;

      for (size_t i = 0; i < split_ctr; ++i) {
        for (size_t j = 0; j < llvm_inst_ord[i] - llvm_inst_prev_offset &&
                           curr_bb_it != curr_bb_offset->end();
             ++j)
          ++curr_bb_it;

        llvm_inst_prev_offset = llvm_inst_ord[i];

        if (curr_bb_it == curr_bb_offset->end())
          break;

        // Ensure all allocas remain strictly in the entry block.
        // Moving allocas into split blocks corrupts LLVM entry alloca
        // invariants, breaks probe-stack thunks, and induces stack layout
        // corruption.
        if (currBB->isEntryBlock()) {
          while (curr_bb_it != curr_bb_offset->end() &&
                 isa<AllocaInst>(curr_bb_it))
            ++curr_bb_it;
          if (curr_bb_it == curr_bb_offset->end())
            break;
        }

        BasicBlock *prevBB = curr_bb_offset;
        BasicBlock *newBB = curr_bb_offset->splitBasicBlock(
            curr_bb_it, curr_bb_offset->getName() + ".split");
        curr_bb_offset = newBB;
        if (cryptoutils->get_range(2) == 0)
          injectStackConfusion(newBB, F);

        // Mandatory chaining: replace unconditional branch in prevBB with an
        // opaque predicate to prevent LLVM's simplifycfg from collapsing the
        // split blocks back together.
        Instruction *term = prevBB->getTerminator();
        if (term && isa<BranchInst>(term) &&
            cast<BranchInst>(term)->isUnconditional()) {
          IRBuilder<> IRB(term);
          Type *I32Ty = Type::getInt32Ty(F->getContext());
          // Invariant: ((x * (x + 1)) & 1) == 0 for all integers x
          // Wrapped through insertOpaqueBarrier so LLVM cannot fold it at
          // compile time!
          Value *seed =
              ConstantInt::get(I32Ty, cryptoutils->get_uint32_t() | 1);
          Value *opqSeed = insertOpaqueBarrier(IRB, seed);
          Value *seedPlus1 = IRB.CreateAdd(opqSeed, ConstantInt::get(I32Ty, 1));
          Value *prod = IRB.CreateMul(opqSeed, seedPlus1);
          Value *parity =
              IRB.CreateAnd(prod, ConstantInt::get(I32Ty, 1), "split.parity");
          Value *isZero = IRB.CreateICmpEQ(parity, ConstantInt::get(I32Ty, 0),
                                           "split.opq.cond");

          // Create bogus cold target block branching back to newBB
          BasicBlock *bogusBB = BasicBlock::Create(
              F->getContext(), prevBB->getName() + ".bogus", F);
          IRBuilder<> BogusIRB(bogusBB);
          BogusIRB.CreateBr(newBB);

          term->eraseFromParent();
          BranchInst::Create(newBB, bogusBB, isZero, prevBB);
        }
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
