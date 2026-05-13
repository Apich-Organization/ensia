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

#include "include/BogusControlFlow.h"
#include "include/CryptoUtils.h"
#include "include/Utils.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ValueMapper.h"

using namespace llvm;

// ─── OLLVM-Next: hardware-bound opaque predicates ────────────────────────────
//
// Three tiers of predicates, chosen based on target architecture:
//
//  Tier A — x86/x86_64 CPUID:
//    Execute CPUID leaf 1; EDX bit 25 (SSE) is always 1 on any CPU that can
//    run a modern OS.  Static analyzers cannot evaluate CPUID without emulating
//    the hardware.  Symbolic execution tools (angr, KLEE) produce "HW unknown".
//
//  Tier B — x86/x86_64 RDTSC:
//    RDTSC returns a 64-bit tick count.  Predicate: (rdtsc | 1) != 0, which is
//    trivially true but looks non-deterministic to a static analyzer because
//    the counter value is unknown at analysis time.
//
//  Tier C — AArch64 MRS:
//    Read CNTVCT_EL0 (virtual timer counter).  Same property as RDTSC.
//
//  Tier D — Software fallback:
//    Classic global-variable opaque predicate (original BCF scheme).
//
// Architecture detection uses the LLVM target triple stored in the Module.

static bool targetIsX86(Module &M) {
#if LLVM_VERSION_MAJOR >= 20
  StringRef triple = M.getTargetTriple().getTriple();
#else
  StringRef triple = M.getTargetTriple();
#endif
  return triple.contains("x86") || triple.contains("i686") ||
         triple.contains("i386");
}
static bool targetIsAArch64(Module &M) {
#if LLVM_VERSION_MAJOR >= 20
  StringRef triple = M.getTargetTriple().getTriple();
#else
  StringRef triple = M.getTargetTriple();
#endif
  return triple.contains("aarch64") || triple.contains("arm64");
}

// Returns an i1 Value that is ALWAYS TRUE at runtime but appears hardware-
// dependent to a static/symbolic analyzer.
static Value *buildHardwareTruePredicate(Module &M, IRBuilder<> &IRB) {
  LLVMContext &Ctx = M.getContext();
  Type *I32Ty = Type::getInt32Ty(Ctx);
  Type *I64Ty = Type::getInt64Ty(Ctx);

  if (targetIsX86(M)) {
    // CPUID leaf 1: EDX bit 25 = SSE support — always set on x86_64 Linux/Win/Mac
    // Clobber: EAX, EBX (push/pop in asm), ECX, EDX, flags
    FunctionType *AsmTy = FunctionType::get(I32Ty, {}, false);
    InlineAsm *cpuidAsm = InlineAsm::get(
        AsmTy,
        // AT&T syntax; save/restore RBX (required for PIC code)
        "push %rbx\n\t"
        "mov $$1, %eax\n\t"
        "cpuid\n\t"
        "mov %edx, $0\n\t"
        "pop %rbx",
        "=r,~{eax},~{ecx},~{edx},~{dirflag},~{fpsr},~{flags}",
        /*hasSideEffects=*/true, InlineAsm::AD_ATT);
    Value *edx  = IRB.CreateCall(AsmTy, cpuidAsm, {}, "bcf.cpuid.edx");
    Value *sse  = IRB.CreateAnd(edx, ConstantInt::get(I32Ty, 1u << 25), "bcf.sse.bit");
    return IRB.CreateICmpNE(sse, ConstantInt::get(I32Ty, 0), "bcf.hw.pred");

  } else if (targetIsAArch64(M)) {
    // Read virtual counter — always non-zero after the first clock cycle
    FunctionType *AsmTy = FunctionType::get(I64Ty, {}, false);
    InlineAsm *mrsAsm = InlineAsm::get(
        AsmTy,
        "mrs $0, cntvct_el0",
        "=r,~{dirflag},~{fpsr},~{flags}",
        /*hasSideEffects=*/true, InlineAsm::AD_ATT);
    Value *tsc = IRB.CreateCall(AsmTy, mrsAsm, {}, "bcf.mrs.tsc");
    // (tsc | 1) is always non-zero
    Value *orOne = IRB.CreateOr(tsc, ConstantInt::get(I64Ty, 1), "bcf.tsc.or1");
    return IRB.CreateICmpNE(orOne, ConstantInt::get(I64Ty, 0), "bcf.hw.pred");

  } else {
    // Software fallback: (y < 10 || x * (x+1) % 2 == 0) — classic BCF predicate
    // Just return a null predicate; caller falls back to global-variable predicate.
    return nullptr;
  }
}

// Returns an i1 Value driven by RDTSC that cannot be resolved statically.
// Used for a second-level obfuscation layer in the altered-block branch.
static Value *buildTSCNoisePredicate(Module &M, IRBuilder<> &IRB) {
  LLVMContext &Ctx = M.getContext();
  if (!targetIsX86(M))
    return nullptr;

  Type *I64Ty = Type::getInt64Ty(Ctx);
  FunctionType *AsmTy = FunctionType::get(I64Ty, {}, false);
  InlineAsm *rdtscAsm = InlineAsm::get(
      AsmTy,
      "rdtsc\n\t"
      "shl $$32, %rdx\n\t"
      "or %rax, %rdx\n\t"
      "mov %rdx, $0",
      "=r,~{rax},~{rdx},~{dirflag},~{fpsr},~{flags}",
      /*hasSideEffects=*/true, InlineAsm::AD_ATT);
  Value *tsc   = IRB.CreateCall(AsmTy, rdtscAsm, {}, "bcf.rdtsc");
  Value *orOne = IRB.CreateOr(tsc, ConstantInt::get(I64Ty, 1LL), "bcf.tsc.or");
  return IRB.CreateICmpNE(orOne, ConstantInt::get(I64Ty, 0LL), "bcf.tsc.pred");
}

// Build a 3-way AND entropy-chain predicate (always true, maximally opaque).
//   Tier 1: CPUID-SSE (hardware)     — opaque to symbolic execution
//   Tier 2: RDTSC|1 != 0             — opaque to static analysis
//   Tier 3: loaded global != sentinel — opaque to constant folding
// Falls back to a 2-way or 1-way combination if the architecture cannot
// support all three tiers.
static Value *buildEntropyChainPredicate(Module &M, IRBuilder<> &IRB,
                                         GlobalVariable *sentinelGV) {
  LLVMContext &Ctx = M.getContext();
  Type *I1Ty  = Type::getInt1Ty(Ctx);
  Type *I32Ty = Type::getInt32Ty(Ctx);
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Value *result = ConstantInt::getTrue(Ctx);

  if (targetIsX86(M)) {
    // Tier 1: CPUID — EDX bit 25 = SSE (always 1 on x86_64)
    FunctionType *CpuidTy = FunctionType::get(I32Ty, {}, false);
    InlineAsm *cpuidIA = InlineAsm::get(CpuidTy,
        "push %rbx\n\t"
        "mov $$1, %eax\n\t"
        "cpuid\n\t"
        "mov %edx, $0\n\t"
        "pop %rbx",
        "=r,~{eax},~{ecx},~{edx},~{dirflag},~{fpsr},~{flags}",
        true, InlineAsm::AD_ATT);
    Value *edx = IRB.CreateCall(CpuidTy, cpuidIA, {}, "bcf.ec.edx");
    Value *sse = IRB.CreateAnd(edx, ConstantInt::get(I32Ty, 1u << 25));
    Value *t1  = IRB.CreateICmpNE(sse, ConstantInt::get(I32Ty, 0), "bcf.ec.t1");
    result = IRB.CreateAnd(result, t1, "bcf.ec.r1");

    // Tier 2: RDTSC — (rdtsc | 1) != 0
    FunctionType *RdtscTy = FunctionType::get(I64Ty, {}, false);
    InlineAsm *rdtscIA = InlineAsm::get(RdtscTy,
        "rdtsc\n\t"
        "shl $$32, %rdx\n\t"
        "or %rax, %rdx\n\t"
        "mov %rdx, $0",
        "=r,~{rax},~{rdx},~{dirflag},~{fpsr},~{flags}",
        true, InlineAsm::AD_ATT);
    Value *tsc  = IRB.CreateCall(RdtscTy, rdtscIA, {}, "bcf.ec.tsc");
    Value *or1  = IRB.CreateOr(tsc, ConstantInt::get(I64Ty, 1LL));
    Value *t2   = IRB.CreateICmpNE(or1, ConstantInt::get(I64Ty, 0), "bcf.ec.t2");
    result = IRB.CreateAnd(result, t2, "bcf.ec.r2");

  } else if (targetIsAArch64(M)) {
    // Tier 1+2 combined: cntvct_el0 | 1 != 0 (virtual timer, always ticking)
    FunctionType *MrsTy = FunctionType::get(I64Ty, {}, false);
    InlineAsm *mrsIA = InlineAsm::get(MrsTy,
        "mrs $0, cntvct_el0",
        "=r,~{dirflag},~{fpsr},~{flags}",
        true, InlineAsm::AD_ATT);
    Value *tsc = IRB.CreateCall(MrsTy, mrsIA, {}, "bcf.ec.mrs");
    Value *or1 = IRB.CreateOr(tsc, ConstantInt::get(I64Ty, 1LL));
    Value *t1  = IRB.CreateICmpNE(or1, ConstantInt::get(I64Ty, 0), "bcf.ec.t1");
    result = IRB.CreateAnd(result, t1, "bcf.ec.r1");
  }

  // Tier 3: global-variable load != sentinel (opaque to constant folding)
  // sentinelGV is initialized to a non-sentinel value and marked volatile.
  if (sentinelGV) {
    Value *gvLoad = IRB.CreateLoad(sentinelGV->getValueType(), sentinelGV,
                                   true, "bcf.ec.gvload");
    uint32_t sentinel = 0xDEADC0DEu;
    Value *t3 = IRB.CreateICmpNE(gvLoad,
                                 ConstantInt::get(I32Ty, sentinel),
                                 "bcf.ec.t3");
    result = IRB.CreateAnd(result, t3, "bcf.ec.r3");
  }
  return result;
}

// Options for the pass
static const uint32_t defaultObfRate = 70, defaultObfTime = 1;

static cl::opt<uint32_t>
    ObfProbRate("bcf_prob",
                cl::desc("Choose the probability [%] each basic blocks will be "
                         "obfuscated by the -bcf pass"),
                cl::value_desc("probability rate"), cl::init(defaultObfRate),
                cl::Optional);
static uint32_t ObfProbRateTemp = defaultObfRate;

static cl::opt<uint32_t>
    ObfTimes("bcf_loop",
             cl::desc("Choose how many time the -bcf pass loop on a function"),
             cl::value_desc("number of times"), cl::init(defaultObfTime),
             cl::Optional);
static uint32_t ObfTimesTemp = defaultObfTime;

static cl::opt<uint32_t> ConditionExpressionComplexity(
    "bcf_cond_compl",
    cl::desc("The complexity of the expression used to generate branching "
             "condition"),
    cl::value_desc("Complexity"), cl::init(3), cl::Optional);
static uint32_t ConditionExpressionComplexityTemp = 3;

static cl::opt<bool>
    OnlyJunkAssembly("bcf_onlyjunkasm",
                     cl::desc("only add junk assembly to altered basic block"),
                     cl::value_desc("only add junk assembly"), cl::init(false),
                     cl::Optional);
static bool OnlyJunkAssemblyTemp = false;

static cl::opt<bool> JunkAssembly(
    "bcf_junkasm",
    cl::desc("Whether to add junk assembly to altered basic block"),
    cl::value_desc("add junk assembly"), cl::init(false), cl::Optional);
static bool JunkAssemblyTemp = false;

static cl::opt<uint32_t> MaxNumberOfJunkAssembly(
    "bcf_junkasm_maxnum",
    cl::desc("The maximum number of junk assembliy per altered basic block"),
    cl::value_desc("max number of junk assembly"), cl::init(4), cl::Optional);
static uint32_t MaxNumberOfJunkAssemblyTemp = 4;

static cl::opt<uint32_t> MinNumberOfJunkAssembly(
    "bcf_junkasm_minnum",
    cl::desc("The minimum number of junk assembliy per altered basic block"),
    cl::value_desc("min number of junk assembly"), cl::init(2), cl::Optional);
static uint32_t MinNumberOfJunkAssemblyTemp = 2;

static cl::opt<bool> CreateFunctionForOpaquePredicate(
    "bcf_createfunc", cl::desc("Create function for each opaque predicate"),
    cl::value_desc("create function"), cl::init(false), cl::Optional);
static bool CreateFunctionForOpaquePredicateTemp = false;

// ─── OLLVM-Next: nested BCF + entropy-chain predicate ─────────────────────────
//
// -bcf_nested: apply BCF recursively to the generated alteredBB blocks.
//   In the standard BCF pass, the "altered" (dead) block is never itself
//   obfuscated — leaving a recognisable pattern where one successor has no
//   BCF structure.  With nested mode, generated blocks are fed back into
//   the BCF queue, creating a fractal-like obfuscated control graph.
//
// -bcf_entropy_chain: replace the simple hardware predicate with a 3-way AND
//   chain:  (CPUID-SSE-bit) AND (RDTSC|1 != 0) AND (global_load predicate).
//   All three sub-predicates are always true at runtime, but each is opaque
//   to a different class of analyzer:
//     • CPUID: opaque to symbolic execution (hardware dependency)
//     • RDTSC: opaque to static analysis (non-deterministic counter)
//     • global var: opaque to compile-time constant folding (external load)
//   The triple-AND defeats each class independently; an analyzer must solve
//   all three simultaneously to resolve the branch.

static cl::opt<bool> BCFNested(
    "bcf_nested",
    cl::desc("[BCF] Apply BCF recursively to generated bogus blocks "
             "(fractal-style CFG obfuscation; higher compile time)"),
    cl::init(false), cl::Optional);
static bool BCFNestedTemp = false;

static cl::opt<bool> BCFEntropyChain(
    "bcf_entropy_chain",
    cl::desc("[BCF] Use 3-way AND entropy-chain hardware predicate "
             "(CPUID & RDTSC & global load) — defeats 3 independent analyzers"),
    cl::init(false), cl::Optional);
static bool BCFEntropyChainTemp = false;

static const Instruction::BinaryOps ops[] = {
    Instruction::Add, Instruction::Sub, Instruction::And, Instruction::Or,
    Instruction::Xor, Instruction::Mul, Instruction::UDiv};
static const CmpInst::Predicate preds[] = {
    CmpInst::ICMP_EQ,  CmpInst::ICMP_NE,  CmpInst::ICMP_UGT,
    CmpInst::ICMP_UGE, CmpInst::ICMP_ULT, CmpInst::ICMP_ULE};

namespace llvm {
static bool OnlyUsedBy(Value *V, Value *Usr) {
  for (User *U : V->users())
    if (U != Usr)
      return false;
  return true;
}
static void RemoveDeadConstant(Constant *C) {
  assert(C->use_empty() && "Constant is not dead!");
  SmallVector<Constant *, 4> Operands;
  for (Value *Op : C->operands())
    if (OnlyUsedBy(Op, C))
      Operands.emplace_back(cast<Constant>(Op));
  if (GlobalVariable *GV = dyn_cast<GlobalVariable>(C)) {
    if (!GV->hasLocalLinkage())
      return; // Don't delete non-static globals.
    GV->eraseFromParent();
  } else if (!isa<Function>(C))
    if (isa<ArrayType>(C->getType()) || isa<StructType>(C->getType()) ||
        isa<VectorType>(C->getType()))
      C->destroyConstant();

  // If the constant referenced anything, see if we can delete it as well.
  for (Constant *O : Operands)
    RemoveDeadConstant(O);
}
struct BogusControlFlow : public FunctionPass {
  static char ID; // Pass identification
  bool flag;
  SmallVector<const ICmpInst *, 8> needtoedit;
  BogusControlFlow() : FunctionPass(ID) { this->flag = true; }
  BogusControlFlow(bool flag) : FunctionPass(ID) { this->flag = flag; }
  /* runOnFunction
   *
   * Overwrite FunctionPass method to apply the transformation
   * to the function. See header for more details.
   */
  bool runOnFunction(Function &F) override {
    if (!toObfuscateUint32Option(&F, "bcf_loop", &ObfTimesTemp))
      ObfTimesTemp = ObfTimes;

    // Check if the percentage is correct
    if (ObfTimesTemp <= 0) {
      errs() << "BogusControlFlow application number -bcf_loop=x must be x > 0";
      return false;
    }

    if (!toObfuscateUint32Option(&F, "bcf_prob", &ObfProbRateTemp))
      ObfProbRateTemp = ObfProbRate;
    // MaxObf: prob=100, times=3.
    if (ObfuscationMaxMode) {
      ObfProbRateTemp = 100;
      if (ObfTimesTemp < 3) ObfTimesTemp = 3;
    }

    // Check if the number of applications is correct
    if (!((ObfProbRate > 0) && (ObfProbRate <= 100))) {
      errs() << "BogusControlFlow application basic blocks percentage "
                "-bcf_prob=x must be 0 < x <= 100";
      return false;
    }

    if (!toObfuscateUint32Option(&F, "bcf_junkasm_maxnum",
                                 &MaxNumberOfJunkAssemblyTemp))
      MaxNumberOfJunkAssemblyTemp = MaxNumberOfJunkAssembly;
    if (!toObfuscateUint32Option(&F, "bcf_junkasm_minnum",
                                 &MinNumberOfJunkAssemblyTemp))
      MinNumberOfJunkAssemblyTemp = MinNumberOfJunkAssembly;

    // Check if the number of applications is correct
    if (MaxNumberOfJunkAssemblyTemp < MinNumberOfJunkAssemblyTemp) {
      errs() << "BogusControlFlow application numbers of junk asm "
                "-bcf_junkasm_maxnum=x must be x >= bcf_junkasm_minnum";
      return false;
    }

    // If fla annotations
    if (toObfuscate(flag, &F, "bcf") && !F.isPresplitCoroutine() &&
        !readAnnotationMetadata(&F, "bcfopfunc")) {
      if (ObfVerbose) errs() << "Running BogusControlFlow On " << F.getName() << "\n";
      bogus(F);
      doF(F);
    }

    return true;
  } // end of runOnFunction()

  void bogus(Function &F) {
    if (!toObfuscateBoolOption(&F, "bcf_junkasm", &JunkAssemblyTemp))
      JunkAssemblyTemp = JunkAssembly;
    if (!toObfuscateBoolOption(&F, "bcf_onlyjunkasm", &OnlyJunkAssemblyTemp))
      OnlyJunkAssemblyTemp = OnlyJunkAssembly;
    if (!toObfuscateBoolOption(&F, "bcf_nested", &BCFNestedTemp))
      BCFNestedTemp = BCFNested;
    if (!toObfuscateBoolOption(&F, "bcf_entropy_chain", &BCFEntropyChainTemp))
      BCFEntropyChainTemp = BCFEntropyChain;
    // MaxObf: override to extremes.
    // NOTE: BCFNestedTemp is intentionally NOT forced true in MaxObf mode.
    // With times=3 and prob=100, nested expansion causes exponential BB growth
    // (each outer iteration rebuilds from the already-enlarged function), making
    // the pass appear to freeze.  times=3 + prob=100 + entropy-chain is already
    // the heaviest meaningful configuration.
    if (ObfuscationMaxMode) {
      BCFEntropyChainTemp = true;
    }

    uint32_t NumObfTimes = ObfTimesTemp;

    // Real begining of the pass
    // Loop for the number of time we run the pass on the function
    uint32_t bogusIter = 0;
    do {
      bogusIter++;
      // Put all the function's block in a list
      std::list<BasicBlock *> basicBlocks;
      for (BasicBlock &BB : F)
        if (!BB.isEHPad() && !BB.isLandingPad() && !containsSwiftError(&BB) &&
            !containsMustTailCall(&BB) && !containsCoroBeginInst(&BB))
          basicBlocks.emplace_back(&BB);

      // Count to limit nested expansion (prevent exponential blowup)
      size_t origSize = basicBlocks.size();
      size_t processed = 0;

      while (!basicBlocks.empty()) {
        BasicBlock *basicBlock = basicBlocks.front();
        basicBlocks.pop_front();
        // Basic Blocks' selection
        if (cryptoutils->get_range(100) <= ObfProbRateTemp) {
          // Record existing successors before we modify the block
          size_t bbsBefore = 0;
          if (BCFNestedTemp) {
            // Count blocks so we know which ones are new
            for (BasicBlock &BB : F)
              bbsBefore++;
          }
          addBogusFlow(basicBlock, F);

          // In nested mode: add newly created blocks back to the queue
          // (but only blocks from the original set to avoid infinite recursion)
          if (BCFNestedTemp && processed < origSize * 2) {
            size_t bbsAfter = 0;
            for (BasicBlock &BB : F)
              bbsAfter++;
            if (bbsAfter > bbsBefore) {
              // New blocks were created; find and enqueue them
              size_t skip = bbsBefore;
              for (BasicBlock &BB : F) {
                if (skip > 0) { skip--; continue; }
                if (!BB.isEHPad() && !BB.isLandingPad() &&
                    !containsSwiftError(&BB) && !containsMustTailCall(&BB) &&
                    !containsCoroBeginInst(&BB) &&
                    !BB.getName().contains("originalBB") &&
                    cryptoutils->get_range(3) == 0) // 33% chance to recurse
                  basicBlocks.emplace_back(&BB);
              }
            }
          }
        }
        processed++;
      } // end of while(!basicBlocks.empty())
    } while (--NumObfTimes > 0);
  }

  bool containsCoroBeginInst(BasicBlock *b) {
    for (Instruction &I : *b)
      if (IntrinsicInst *II = dyn_cast<IntrinsicInst>(&I))
        if (II->getIntrinsicID() == Intrinsic::coro_begin)
          return true;
    return false;
  }

  bool containsMustTailCall(BasicBlock *b) {
    for (Instruction &I : *b)
      if (CallInst *CI = dyn_cast<CallInst>(&I))
        if (CI->isMustTailCall())
          return true;
    return false;
  }

  bool containsSwiftError(BasicBlock *b) {
    for (Instruction &I : *b)
      if (AllocaInst *AI = dyn_cast<AllocaInst>(&I))
        if (AI->isSwiftError())
          return true;
    return false;
  }

  /* addBogusFlow
   *
   * Add bogus flow to a given basic block, according to the header's
   * description
   */
  void addBogusFlow(BasicBlock *basicBlock, Function &F) {
    // Split the block: first part with only the phi nodes and debug info and
    // terminator
    //                  created by splitBasicBlock. (-> No instruction)
    //                  Second part with every instructions from the original
    //                  block
    // We do this way, so we don't have to adjust all the phi nodes, metadatas
    // and so on for the first block. We have to let the phi nodes in the first
    // part, because they actually are updated in the second part according to
    // them.
    BasicBlock::iterator i1 = basicBlock->begin();
    if (basicBlock->getFirstNonPHIOrDbgOrLifetime() != basicBlock->end())
      i1 = basicBlock->getFirstNonPHIOrDbgOrLifetime();

    // When "probe-stack" is present, moving allocas out of the entry block
    // can segfault (the probe thunk expects all allocas to stay in the entry
    // block).  Split after the last alloca run instead so all allocas remain.
    if (F.hasFnAttribute("probe-stack") && basicBlock->isEntryBlock()) {
      // Find the first non alloca instruction
      while ((i1 != basicBlock->end()) && isa<AllocaInst>(i1))
        i1++;

      // If there are no other kind of instruction we just don't split that
      // entry block
      if (i1 == basicBlock->end())
        return;
    }

    BasicBlock *originalBB = basicBlock->splitBasicBlock(i1, "originalBB");

    // Creating the altered basic block on which the first basicBlock will jump
    BasicBlock *alteredBB =
        createAlteredBasicBlock(originalBB, "alteredBB", &F);

    // Now that all the blocks are created,
    // we modify the terminators to adjust the control flow.

    if (!OnlyJunkAssemblyTemp)
      alteredBB->getTerminator()->eraseFromParent();
    basicBlock->getTerminator()->eraseFromParent();

    // Preparing a condition..
    // For now, the condition is an always true comparaison between 2 float
    // This will be complicated after the pass (in doFinalization())

    // We need to use ConstantInt instead of ConstantFP as ConstantFP results in
    // strange dead-loop when injected into Xcode
    Value *LHS = ConstantInt::get(Type::getInt32Ty(F.getContext()), 1);
    Value *RHS = ConstantInt::get(Type::getInt32Ty(F.getContext()), 1);

    // The always true condition. End of the first block
#if LLVM_VERSION_MAJOR >= 19
    ICmpInst *condition = new ICmpInst(basicBlock->end(), ICmpInst::ICMP_EQ,
                                       LHS, RHS, "BCFPlaceHolderPred");
#else
    ICmpInst *condition = new ICmpInst(*basicBlock, ICmpInst::ICMP_EQ, LHS, RHS,
                                       "BCFPlaceHolderPred");
#endif
    needtoedit.emplace_back(condition);

    // Jump to the original basic block if the condition is true or
    // to the altered block if false.
    BranchInst::Create(originalBB, alteredBB, condition, basicBlock);

    // The altered block loop back on the original one.
    BranchInst::Create(originalBB, alteredBB);

    // The end of the originalBB is modified to give the impression that
    // sometimes it continues in the loop, and sometimes it return the desired
    // value (of course it's always true, so it always use the original
    // terminator..
    //  but this will be obfuscated too;) )

    // iterate on instruction just before the terminator of the originalBB
    BasicBlock::iterator i = originalBB->end();

    // Split at this point (we only want the terminator in the second part)
    BasicBlock *originalBBpart2 =
        originalBB->splitBasicBlock(--i, "originalBBpart2");
    // the first part go either on the return statement or on the begining
    // of the altered block.. So we erase the terminator created when splitting.
    originalBB->getTerminator()->eraseFromParent();
    // We add at the end a new always true condition
#if LLVM_VERSION_MAJOR >= 19
    ICmpInst *condition2 = new ICmpInst(originalBB->end(), CmpInst::ICMP_EQ,
                                        LHS, RHS, "BCFPlaceHolderPred");
#else
    ICmpInst *condition2 = new ICmpInst(*originalBB, CmpInst::ICMP_EQ, LHS, RHS,
                                        "BCFPlaceHolderPred");
#endif
    needtoedit.emplace_back(condition2);
    // Do random behavior to avoid pattern recognition.
    // This is achieved by jumping to a random BB
    switch (cryptoutils->get_range(2)) {
    case 0: {
      BranchInst::Create(originalBBpart2, originalBB, condition2, originalBB);
      break;
    }
    case 1: {
      BranchInst::Create(originalBBpart2, alteredBB, condition2, originalBB);
      break;
    }
    default:
      llvm_unreachable("wtf?");
    }
  } // end of addBogusFlow()

  /* createAlteredBasicBlock
   *
   * This function return a basic block similar to a given one.
   * It's inserted just after the given basic block.
   * The instructions are similar but junk instructions are added between
   * the cloned one. The cloned instructions' phi nodes, metadatas, uses and
   * debug locations are adjusted to fit in the cloned basic block and
   * behave nicely.
   */
  BasicBlock *createAlteredBasicBlock(BasicBlock *basicBlock,
                                      const Twine &Name = "gen",
                                      Function *F = nullptr) {
    BasicBlock *alteredBB = OnlyJunkAssemblyTemp
                                ? BasicBlock::Create(F->getContext(), "", F)
                                : nullptr;
    if (!OnlyJunkAssemblyTemp) {
      // Useful to remap the informations concerning instructions.
      ValueToValueMapTy VMap;
      alteredBB = CloneBasicBlock(basicBlock, VMap, Name, F);
      // Remap operands.
      BasicBlock::iterator ji = basicBlock->begin();
      for (BasicBlock::iterator i = alteredBB->begin(), e = alteredBB->end();
           i != e; ++i) {
        // Loop over the operands of the instruction
        for (User::op_iterator opi = i->op_begin(), ope = i->op_end();
             opi != ope; ++opi) {
          // get the value for the operand
          Value *v = MapValue(*opi, VMap, RF_NoModuleLevelChanges, 0);
          if (v != 0)
            *opi = v;
        }
        // Remap phi nodes' incoming blocks.
        if (PHINode *pn = dyn_cast<PHINode>(i)) {
          for (unsigned j = 0, e = pn->getNumIncomingValues(); j != e; ++j) {
            Value *v = MapValue(pn->getIncomingBlock(j), VMap, RF_None, 0);
            if (v != 0)
              pn->setIncomingBlock(j, cast<BasicBlock>(v));
          }
        }
        // Remap attached metadata.
        SmallVector<std::pair<unsigned, MDNode *>, 4> MDs;
        i->getAllMetadata(MDs);
        // important for compiling with DWARF, using option -g.
        i->setDebugLoc(ji->getDebugLoc());
        ji++;
      } // The instructions' informations are now all correct

      // Insert junk instructions throughout the dead block to create synthetic
      // data-dependency chains that confuse decompilers and pattern matchers.
      // ICmp/FCmp are handled with dyn_cast outside the isBinaryOp() guard
      // because CmpInst is not a BinaryOperator subclass.
      for (BasicBlock::iterator i = alteredBB->begin(), e = alteredBB->end();
           i != e; ++i) {
        if (i->isBinaryOp()) {
          unsigned int opcode = i->getOpcode();
          Instruction *op, *op1 = nullptr;
          Twine *var = new Twine("_");
          // Integer binary ops
          if (opcode == Instruction::Add || opcode == Instruction::Sub ||
              opcode == Instruction::Mul || opcode == Instruction::UDiv ||
              opcode == Instruction::SDiv || opcode == Instruction::URem ||
              opcode == Instruction::SRem || opcode == Instruction::Shl ||
              opcode == Instruction::LShr || opcode == Instruction::AShr ||
              opcode == Instruction::And || opcode == Instruction::Or ||
              opcode == Instruction::Xor) {
            for (int random = (int)cryptoutils->get_range(10); random < 10;
                 ++random) {
              switch (cryptoutils->get_range(8)) {
              case 0:
                break;
              case 1:
                op = BinaryOperator::CreateNeg(i->getOperand(0), *var, &*i);
                op1 = BinaryOperator::Create(Instruction::Add, op,
                                             i->getOperand(1), "gen", &*i);
                break;
              case 2:
                op1 = BinaryOperator::Create(Instruction::Sub, i->getOperand(0),
                                             i->getOperand(1), *var, &*i);
                op = BinaryOperator::Create(Instruction::Mul, op1,
                                            i->getOperand(1), "gen", &*i);
                break;
              case 3:
                op = BinaryOperator::Create(Instruction::Shl, i->getOperand(0),
                                            i->getOperand(1), *var, &*i);
                break;
              case 4: // XOR operands together, then add to first
                op = BinaryOperator::Create(Instruction::Xor, i->getOperand(0),
                                            i->getOperand(1), *var, &*i);
                op1 = BinaryOperator::Create(Instruction::Add, op,
                                             i->getOperand(0), "gen", &*i);
                break;
              case 5: // AND then OR chain (creates multi-level dependency)
                op = BinaryOperator::Create(Instruction::And, i->getOperand(0),
                                            i->getOperand(1), *var, &*i);
                op1 = BinaryOperator::Create(Instruction::Or, op,
                                             i->getOperand(1), "gen", &*i);
                break;
              case 6: { // Shift left by 1 then right by 1 (lossy round-trip)
                Type *Ty = i->getOperand(0)->getType();
                Value *one = ConstantInt::get(Ty, 1);
                op  = BinaryOperator::Create(Instruction::Shl,  i->getOperand(0),
                                             one, *var, &*i);
                op1 = BinaryOperator::Create(Instruction::LShr, op, one,
                                             "gen", &*i);
                break;
              }
              case 7: // Mul then Sub (creates diverging dependency tree)
                op = BinaryOperator::Create(Instruction::Mul, i->getOperand(0),
                                            i->getOperand(1), *var, &*i);
                op1 = BinaryOperator::Create(Instruction::Sub, op,
                                             i->getOperand(0), "gen", &*i);
                break;
              }
            }
          }
          // Float binary ops
          if (opcode == Instruction::FAdd || opcode == Instruction::FSub ||
              opcode == Instruction::FMul || opcode == Instruction::FDiv ||
              opcode == Instruction::FRem) {
            for (int random = (int)cryptoutils->get_range(10); random < 10;
                 ++random) {
              switch (cryptoutils->get_range(6)) {
              case 0:
                break;
              case 1:
                op = UnaryOperator::CreateFNeg(i->getOperand(0), *var, &*i);
                op1 = BinaryOperator::Create(Instruction::FAdd, op,
                                             i->getOperand(1), "gen", &*i);
                break;
              case 2:
                op = BinaryOperator::Create(Instruction::FSub, i->getOperand(0),
                                            i->getOperand(1), *var, &*i);
                op1 = BinaryOperator::Create(Instruction::FMul, op,
                                             i->getOperand(1), "gen", &*i);
                break;
              case 3: { // FSub 0.0 then FAdd (identity chain)
                Type *Ty = i->getOperand(0)->getType();
                Value *zero = ConstantFP::get(Ty, 0.0);
                op = BinaryOperator::Create(Instruction::FSub, i->getOperand(0),
                                            zero, *var, &*i);
                op1 = BinaryOperator::Create(Instruction::FAdd, op,
                                             i->getOperand(1), "gen", &*i);
                break;
              }
              case 4: { // FMul -1.0 then FNeg (double negation, net identity)
                Type *Ty = i->getOperand(0)->getType();
                Value *negOne = ConstantFP::get(Ty, -1.0);
                op  = BinaryOperator::Create(Instruction::FMul, i->getOperand(0),
                                             negOne, *var, &*i);
                op1 = UnaryOperator::CreateFNeg(op, "gen", &*i);
                break;
              }
              case 5: { // FDiv 1.0 then FMul (scale-by-one dependency)
                Type *Ty = i->getOperand(0)->getType();
                Value *one = ConstantFP::get(Ty, 1.0);
                op  = BinaryOperator::Create(Instruction::FDiv, i->getOperand(0),
                                             one, *var, &*i);
                op1 = BinaryOperator::Create(Instruction::FMul, op,
                                             i->getOperand(1), "gen", &*i);
                break;
              }
              }
            }
          }
        }
        // ICmpInst mutation — predicate scrambling + operand noise injection.
        // This block is intentionally outside isBinaryOp() because ICmpInst
        // inherits from CmpInst, not BinaryOperator.
        if (ICmpInst *currentI = dyn_cast<ICmpInst>(&*i)) {
          switch (cryptoutils->get_range(6)) {
          case 0:
            break;
          case 1:
            currentI->swapOperands();
            break;
          case 2: {
            switch (cryptoutils->get_range(10)) {
            case 0: currentI->setPredicate(ICmpInst::ICMP_EQ);  break;
            case 1: currentI->setPredicate(ICmpInst::ICMP_NE);  break;
            case 2: currentI->setPredicate(ICmpInst::ICMP_UGT); break;
            case 3: currentI->setPredicate(ICmpInst::ICMP_UGE); break;
            case 4: currentI->setPredicate(ICmpInst::ICMP_ULT); break;
            case 5: currentI->setPredicate(ICmpInst::ICMP_ULE); break;
            case 6: currentI->setPredicate(ICmpInst::ICMP_SGT); break;
            case 7: currentI->setPredicate(ICmpInst::ICMP_SGE); break;
            case 8: currentI->setPredicate(ICmpInst::ICMP_SLT); break;
            case 9: currentI->setPredicate(ICmpInst::ICMP_SLE); break;
            }
            break;
          }
          case 3: { // XOR first operand with zero (adds instruction, same value)
            Value *xorZero = BinaryOperator::Create(
                Instruction::Xor, currentI->getOperand(0),
                ConstantInt::get(currentI->getOperand(0)->getType(), 0),
                "_", currentI);
            currentI->setOperand(0, xorZero);
            break;
          }
          case 4: { // Negate both operands and swap (reverses ordering predicate)
            Value *negLHS = BinaryOperator::CreateNeg(
                currentI->getOperand(0), "_", currentI);
            Value *negRHS = BinaryOperator::CreateNeg(
                currentI->getOperand(1), "gen", currentI);
            currentI->setOperand(0, negLHS);
            currentI->setOperand(1, negRHS);
            currentI->swapOperands();
            break;
          }
          case 5: { // Add same random constant to both sides (constant-offset equivalence)
            Type *OpTy = currentI->getOperand(0)->getType();
            Value *c = ConstantInt::get(OpTy, cryptoutils->get_uint32_t());
            Value *lhsNew = BinaryOperator::Create(Instruction::Add,
                currentI->getOperand(0), c, "_", currentI);
            Value *rhsNew = BinaryOperator::Create(Instruction::Add,
                currentI->getOperand(1), c, "gen", currentI);
            currentI->setOperand(0, lhsNew);
            currentI->setOperand(1, rhsNew);
            break;
          }
          }
        }
        // FCmpInst mutation — same structure as ICmp above.
        if (FCmpInst *currentI = dyn_cast<FCmpInst>(&*i)) {
          switch (cryptoutils->get_range(6)) {
          case 0:
            break;
          case 1:
            currentI->swapOperands();
            break;
          case 2: {
            switch (cryptoutils->get_range(10)) {
            case 0: currentI->setPredicate(FCmpInst::FCMP_OEQ); break;
            case 1: currentI->setPredicate(FCmpInst::FCMP_ONE); break;
            case 2: currentI->setPredicate(FCmpInst::FCMP_UGT); break;
            case 3: currentI->setPredicate(FCmpInst::FCMP_UGE); break;
            case 4: currentI->setPredicate(FCmpInst::FCMP_ULT); break;
            case 5: currentI->setPredicate(FCmpInst::FCMP_ULE); break;
            case 6: currentI->setPredicate(FCmpInst::FCMP_OGT); break;
            case 7: currentI->setPredicate(FCmpInst::FCMP_OGE); break;
            case 8: currentI->setPredicate(FCmpInst::FCMP_OLT); break;
            case 9: currentI->setPredicate(FCmpInst::FCMP_OLE); break;
            }
            break;
          }
          case 3: { // FNeg both operands and swap (flip ordering direction)
            Value *negLHS = UnaryOperator::CreateFNeg(
                currentI->getOperand(0), "_", currentI);
            Value *negRHS = UnaryOperator::CreateFNeg(
                currentI->getOperand(1), "gen", currentI);
            currentI->setOperand(0, negLHS);
            currentI->setOperand(1, negRHS);
            currentI->swapOperands();
            break;
          }
          case 4: { // FMul first operand by 1.0 (IEEE identity, adds node)
            Type *Ty = currentI->getOperand(0)->getType();
            Value *one = ConstantFP::get(Ty, 1.0);
            Value *mul = BinaryOperator::Create(Instruction::FMul,
                currentI->getOperand(0), one, "_", currentI);
            currentI->setOperand(0, mul);
            break;
          }
          case 5: { // FDiv first operand by 1.0 (scale-by-one noise)
            Type *Ty = currentI->getOperand(0)->getType();
            Value *one = ConstantFP::get(Ty, 1.0);
            Value *div = BinaryOperator::Create(Instruction::FDiv,
                currentI->getOperand(0), one, "_", currentI);
            currentI->setOperand(0, div);
            break;
          }
          }
        }
      }
      // Remove DIs from AlterBB
      SmallVector<CallInst *, 4> toRemove;
      SmallVector<Constant *, 4> DeadConstants;
      for (Instruction &I : *alteredBB) {
        if (CallInst *CI = dyn_cast<CallInst>(&I)) {
          if (CI->getCalledFunction() != nullptr &&
#if LLVM_VERSION_MAJOR >= 18
              CI->getCalledFunction()->getName().starts_with("llvm.dbg"))
#else
              CI->getCalledFunction()->getName().startswith("llvm.dbg"))
#endif
            toRemove.emplace_back(CI);
        }
      }
      // Shamefully stolen from IPO/StripSymbols.cpp
      for (CallInst *CI : toRemove) {
        Value *Arg1 = CI->getArgOperand(0);
        Value *Arg2 = CI->getArgOperand(1);
        assert(CI->use_empty() && "llvm.dbg intrinsic should have void result");
        CI->eraseFromParent();
        if (Arg1->use_empty()) {
          if (Constant *C = dyn_cast<Constant>(Arg1))
            DeadConstants.emplace_back(C);
          else
            RecursivelyDeleteTriviallyDeadInstructions(Arg1);
        }
        if (Arg2->use_empty())
          if (Constant *C = dyn_cast<Constant>(Arg2))
            DeadConstants.emplace_back(C);
      }
      while (!DeadConstants.empty()) {
        Constant *C = DeadConstants.back();
        DeadConstants.pop_back();
        if (GlobalVariable *GV = dyn_cast<GlobalVariable>(C)) {
          if (GV->hasLocalLinkage())
            RemoveDeadConstant(GV);
        } else {
          RemoveDeadConstant(C);
        }
      }
    }
    if (JunkAssemblyTemp || OnlyJunkAssemblyTemp) {
      std::string junk = "";
      for (uint32_t i = cryptoutils->get_range(MinNumberOfJunkAssemblyTemp,
                                               MaxNumberOfJunkAssemblyTemp);
           i > 0; i--)
        junk += ".long " + std::to_string(cryptoutils->get_uint32_t()) + "\n";
      InlineAsm *IA = InlineAsm::get(
          FunctionType::get(Type::getVoidTy(alteredBB->getContext()), false),
          junk, "", true, false);
      if (OnlyJunkAssemblyTemp)
        CallInst::Create(IA, {}, "", alteredBB);
      else
        CallInst::Create(IA, {}, "",
                         alteredBB->getFirstNonPHIOrDbgOrLifetime());
      turnOffOptimization(basicBlock->getParent());
    }
    return alteredBB;
  } // end of createAlteredBasicBlock()

  /* doF
   *
   * This part obfuscate the always true predicates generated in addBogusFlow()
   * of the function.
   */
  bool doF(Function &F) {
    if (!toObfuscateBoolOption(&F, "bcf_createfunc",
                               &CreateFunctionForOpaquePredicateTemp))
      CreateFunctionForOpaquePredicateTemp = CreateFunctionForOpaquePredicate;
    if (!toObfuscateUint32Option(&F, "bcf_cond_compl",
                                 &ConditionExpressionComplexityTemp))
      ConditionExpressionComplexityTemp = ConditionExpressionComplexity;
    // MaxObf: crank up complexity
    if (ObfuscationMaxMode) {
      if (ConditionExpressionComplexityTemp < 6)
        ConditionExpressionComplexityTemp = 6;
      BCFEntropyChainTemp = true;
    }

    SmallVector<Instruction *, 8> toEdit, toDelete;
    // Looking for the conditions and branches to transform
    for (BasicBlock &BB : F) {
      Instruction *tbb = BB.getTerminator();
      if (BranchInst *br = dyn_cast<BranchInst>(tbb)) {
        if (br->isConditional()) {
          ICmpInst *cond = dyn_cast<ICmpInst>(br->getCondition());
          if (cond && std::find(needtoedit.begin(), needtoedit.end(), cond) !=
                          needtoedit.end()) {
            toDelete.emplace_back(cond); // The condition
            toEdit.emplace_back(tbb);    // The branch using the condition
          }
        }
      }
    }
    Module &M = *F.getParent();
    Type *I1Ty  = Type::getInt1Ty(M.getContext());
    Type *I32Ty = Type::getInt32Ty(M.getContext());

    // Determine once whether hardware predicates are available for this target
    bool useHWPred = targetIsX86(M) || targetIsAArch64(M);

    // Create the sentinel GlobalVariable for the entropy-chain tier-3 predicate.
    // Initialized to a value != 0xDEADC0DE so the predicate is always true.
    // Marked non-constant so constant propagation cannot resolve it.
    GlobalVariable *sentinelGV = nullptr;
    if (BCFEntropyChainTemp) {
      uint32_t initVal = cryptoutils->get_uint32_t();
      while (initVal == 0xDEADC0DEu)
        initVal = cryptoutils->get_uint32_t();
      sentinelGV = new GlobalVariable(
          M, I32Ty, /*isConstant=*/false,
          GlobalValue::PrivateLinkage,
          ConstantInt::get(I32Ty, initVal), "bcf.sentinel");
    }

    // Replacing all the branches we found.
    // Use a per-predicate counter so each LHSGV/RHSGV GlobalVariable gets a
    // unique name on the first attempt.  Without this, LLVM's ValueSymbolTable
    // must linearly scan "LHSGV0".."LHSGV(N-1)" for every new "LHSGV" → O(N²)
    // string ops that appear as a freeze for large N (>500 predicates).
    uint32_t predIdx = 0;
    for (Instruction *i : toEdit) {
      // Previously We Use LLVM EE To Calculate LHS and RHS
      // Since IRBuilder<> uses ConstantFolding to fold constants.
      // The return instruction is already returning constants
      // The variable names below are the artifact from the Emulation Era
      Function *emuFunction = Function::Create(
          FunctionType::get(I32Ty, false),
          GlobalValue::LinkageTypes::PrivateLinkage, "EnsiaBCFEmuFunction", M);
      BasicBlock *emuEntryBlock =
          BasicBlock::Create(emuFunction->getContext(), "", emuFunction);

      Function *opFunction = nullptr;
      IRBuilder<> *IRBOp = nullptr;
      if (CreateFunctionForOpaquePredicateTemp) {
        opFunction = Function::Create(FunctionType::get(I1Ty, false),
                                      GlobalValue::LinkageTypes::PrivateLinkage,
                                      "EnsiaBCFOpaquePredicateFunction", M);
        BasicBlock *opTrampBlock =
            BasicBlock::Create(opFunction->getContext(), "", opFunction);
        BasicBlock *opEntryBlock =
            BasicBlock::Create(opFunction->getContext(), "", opFunction);
        // Insert a br to make it can be obfuscated by IndirectBranch
        BranchInst::Create(opEntryBlock, opTrampBlock);
        writeAnnotationMetadata(opFunction, "bcfopfunc");
        IRBOp = new IRBuilder<>(opEntryBlock);
      }
      Instruction *tmp = &*(i->getParent()->getFirstNonPHIOrDbgOrLifetime());
      IRBuilder<> *IRBReal = new IRBuilder<>(tmp);
      IRBuilder<> IRBEmu(emuEntryBlock);
      // First,Construct a real RHS that will be used in the actual condition
      Constant *RealRHS = ConstantInt::get(I32Ty, cryptoutils->get_uint32_t());
      // Prepare Initial LHS and RHS to bootstrap the emulator
      Constant *LHSC =
          ConstantInt::get(I32Ty, cryptoutils->get_range(1, UINT32_MAX));
      Constant *RHSC =
          ConstantInt::get(I32Ty, cryptoutils->get_range(1, UINT32_MAX));
      // Use unique per-predicate names to avoid O(N²) ValueSymbolTable probing.
      std::string lhsName = "bcf.lhs." + std::to_string(predIdx);
      std::string rhsName = "bcf.rhs." + std::to_string(predIdx);
      predIdx++;
      GlobalVariable *LHSGV =
          new GlobalVariable(M, Type::getInt32Ty(M.getContext()), false,
                             GlobalValue::PrivateLinkage, LHSC, lhsName);
      GlobalVariable *RHSGV =
          new GlobalVariable(M, Type::getInt32Ty(M.getContext()), false,
                             GlobalValue::PrivateLinkage, RHSC, rhsName);
      LoadInst *LHS =
          (CreateFunctionForOpaquePredicateTemp ? IRBOp : IRBReal)
              ->CreateLoad(LHSGV->getValueType(), LHSGV, "Initial LHS");
      LoadInst *RHS =
          (CreateFunctionForOpaquePredicateTemp ? IRBOp : IRBReal)
              ->CreateLoad(RHSGV->getValueType(), RHSGV, "Initial LHS");

      // To Speed-Up Evaluation
      Value *emuLHS = LHSC;
      Value *emuRHS = RHSC;
      Instruction::BinaryOps initialOp =
          ops[cryptoutils->get_range(sizeof(ops) / sizeof(ops[0]))];
      Value *emuLast =
          IRBEmu.CreateBinOp(initialOp, emuLHS, emuRHS, "EmuInitialCondition");
      Value *Last = (CreateFunctionForOpaquePredicateTemp ? IRBOp : IRBReal)
                        ->CreateBinOp(initialOp, LHS, RHS, "InitialCondition");
      for (uint32_t i = 0; i < ConditionExpressionComplexityTemp; i++) {
        Constant *newTmp =
            ConstantInt::get(I32Ty, cryptoutils->get_range(1, UINT32_MAX));
        Instruction::BinaryOps initialOp2 =
            ops[cryptoutils->get_range(sizeof(ops) / sizeof(ops[0]))];
        emuLast = IRBEmu.CreateBinOp(initialOp2, emuLast, newTmp,
                                     "EmuInitialCondition");
        Last = (CreateFunctionForOpaquePredicateTemp ? IRBOp : IRBReal)
                   ->CreateBinOp(initialOp2, Last, newTmp, "InitialCondition");
      }
      // Randomly Generate Predicate
      CmpInst::Predicate pred =
          preds[cryptoutils->get_range(sizeof(preds) / sizeof(preds[0]))];
      if (CreateFunctionForOpaquePredicateTemp) {
        IRBOp->CreateRet(IRBOp->CreateICmp(pred, Last, RealRHS));
        Last = IRBReal->CreateCall(opFunction);
      } else {
        // OLLVM-Next: chain a hardware or entropy-chain predicate with AND.
        // Both are always true at runtime but opaque to different classes of
        // analyzer — see comments at buildEntropyChainPredicate().
        // In MaxObf mode: always apply the entropy chain (not 50% random) to
        // compensate for the reduced BCF iteration count (2 instead of 3).
        Value *swPred = IRBReal->CreateICmp(pred, Last, RealRHS);
        bool doEntropyChain = BCFEntropyChainTemp &&
            (ObfuscationMaxMode || cryptoutils->get_range(2) == 0);
        if (doEntropyChain) {
          Value *ecPred = buildEntropyChainPredicate(M, *IRBReal, sentinelGV);
          if (ecPred)
            swPred = IRBReal->CreateAnd(swPred, ecPred, "bcf.ec.and");
        } else if (useHWPred && cryptoutils->get_range(2) == 0) {
          Value *hwPred = buildHardwareTruePredicate(M, *IRBReal);
          if (hwPred)
            swPred = IRBReal->CreateAnd(swPred, hwPred, "bcf.hw.and");
        }
        Last = swPred;
      }
      emuLast = IRBEmu.CreateICmp(pred, emuLast, RealRHS);
      ReturnInst *RI = IRBEmu.CreateRet(emuLast);
      ConstantInt *emuCI = cast<ConstantInt>(RI->getReturnValue());
      APInt emulateResult = emuCI->getValue();
      if (emulateResult == 1) {
        // Our ConstantExpr evaluates to true;
        BranchInst::Create(((BranchInst *)i)->getSuccessor(0),
                           ((BranchInst *)i)->getSuccessor(1), Last,
                           i->getParent());
      } else {
        // False, swap operands
        BranchInst::Create(((BranchInst *)i)->getSuccessor(1),
                           ((BranchInst *)i)->getSuccessor(0), Last,
                           i->getParent());
      }
      emuFunction->eraseFromParent();
      i->eraseFromParent(); // erase the branch
    }
    // Erase all the associated conditions we found
    for (Instruction *i : toDelete)
      i->eraseFromParent();
    return true;
  } // end of doFinalization
}; // end of struct BogusControlFlow : public FunctionPass
} // namespace llvm

char BogusControlFlow::ID = 0;
INITIALIZE_PASS(BogusControlFlow, "bcfobf", "Enable BogusControlFlow.", false,
                false)
FunctionPass *llvm::createBogusControlFlowPass(bool flag) {
  return new BogusControlFlow(flag);
}
