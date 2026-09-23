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

#include "include/ChaosStateMachine.h"
#include "include/CryptoUtils.h"
#include "include/ObfConfig.h"
#include "include/Utils.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Support/CommandLine.h"
#include <unordered_set>

using namespace llvm;

static cl::opt<bool> ChaosNestedDispatch(
    "csm_nested",
    cl::desc("[ChaosStateMachine] Enable two-level nested switch dispatch"),
    cl::init(false), cl::Optional);
static thread_local bool ChaosNestedDispatchTemp = false;

static cl::opt<uint32_t>
    ChaosWarmup("csm_warmup",
                cl::desc("[ChaosStateMachine] Logistic map warmup iterations "
                         "(skip initial transient)"),
                cl::init(64), cl::Optional);

static cl::opt<uint32_t> ChaosMaxBlocks(
    "csm_maxblocks",
    cl::desc(
        "[ChaosStateMachine] True safety-net: skip functions whose BB count "
        "after LowerSwitch exceeds this value (catastrophic-size guard only; "
        "normal operation is controlled by pass ordering, default 10000)"),
    cl::init(10000), cl::Optional);

// Per-compilation fallback constants generated dynamically to prevent pattern
// matching
static uint32_t CSM_FALLBACK_ZERO = 0;
static uint32_t CSM_FALLBACK_RESULT = 0;
static uint32_t CSM_ATTRACTOR_M1 = 0;
static uint32_t CSM_ATTRACTOR_M1_INV = 0;
static uint32_t CSM_ATTRACTOR_C1 = 0;
static uint32_t CSM_ATTRACTOR_K1 = 0;
static uint32_t CSM_ATTRACTOR_K2 = 0;

static uint32_t modInverse32(uint32_t a) {
  uint32_t inv = a;
  for (int i = 0; i < 5; i++)
    inv *= 2u - a * inv;
  return inv;
}

static void initCSMConstants() {
  if (CSM_FALLBACK_ZERO == 0) {
    CSM_FALLBACK_ZERO = (cryptoutils->get_uint32_t() | 0x10000000u);
    CSM_FALLBACK_RESULT = (cryptoutils->get_uint32_t() | 0xC0000000u);
    CSM_ATTRACTOR_M1 =
        cryptoutils->get_uint32_t() | 1u; // odd for modular inverse
    CSM_ATTRACTOR_M1_INV = modInverse32(CSM_ATTRACTOR_M1);
    CSM_ATTRACTOR_C1 = cryptoutils->get_uint32_t() | 0x1010101u;
    CSM_ATTRACTOR_K1 = cryptoutils->get_uint32_t();
    CSM_ATTRACTOR_K2 = cryptoutils->get_uint32_t();
  }
}

// Q32 fixed-point chaos map step: state space expanded from 2^16 to 2^32,
// preventing small-domain lookup table generation and symbolic bitvector
// simplification.
uint32_t llvm::chaosMapStep(uint32_t x) {
  initCSMConstants();
  uint64_t xc = (uint64_t)x;
  if (xc == 0)
    xc = (uint64_t)CSM_FALLBACK_ZERO; // avoid absorbing fixed point at 0
  uint64_t inv = (1ULL << 32) - xc;
  uint64_t prod = xc * inv; // Q64
  uint64_t p32 = prod >> 32;
  uint32_t nxt = (uint32_t)((p32 * 4294967291ULL) >> 30);
  return nxt ? nxt : CSM_FALLBACK_RESULT; // avoid fixed point at 0 in result
}

// Discrete cellular automaton / non-linear bit diffusion over attractor basin
static uint32_t diffuseState(uint32_t s) {
  uint32_t rot = (s << 11) | (s >> 21);
  return (rot ^ (s * 0x9e3779b9u)) + 0x7f4a7c15u;
}

static Value *buildDiffuseIR(IRBuilder<NoFolder> &IRB, Value *s,
                             LLVMContext &Ctx) {
  Type *I32Ty = Type::getInt32Ty(Ctx);
  Value *shl = IRB.CreateShl(s, ConstantInt::get(I32Ty, 11));
  Value *lshr = IRB.CreateLShr(s, ConstantInt::get(I32Ty, 21));
  Value *rot = IRB.CreateOr(shl, lshr, "csm.diff.rot");
  Value *mul =
      IRB.CreateMul(s, ConstantInt::get(I32Ty, 0x9e3779b9u), "csm.diff.mul");
  Value *xorVal = IRB.CreateXor(rot, mul, "csm.diff.xor");
  return IRB.CreateAdd(xorVal, ConstantInt::get(I32Ty, 0x7f4a7c15u),
                       "csm.diff.val");
}

// Multi-step invertible attractor basin encoding: transforms target case into
// encoded state. Requires executing multiple non-linear iterations to decode.
static uint32_t encodeAttractor(uint32_t target) {
  initCSMConstants();
  uint32_t x1 = ((target << 7) | (target >> 25)) ^ CSM_ATTRACTOR_K1;
  uint32_t x2 = (x1 * CSM_ATTRACTOR_M1) + CSM_ATTRACTOR_C1;
  uint32_t x3 = ((x2 << 13) | (x2 >> 19)) ^ CSM_ATTRACTOR_K2;
  return x3;
}

static Value *buildDecodeAttractorIR(IRBuilder<NoFolder> &IRB, Value *x3,
                                     LLVMContext &Ctx) {
  initCSMConstants();
  Type *I32Ty = Type::getInt32Ty(Ctx);
  Value *unK2 = IRB.CreateXor(x3, ConstantInt::get(I32Ty, CSM_ATTRACTOR_K2),
                              "csm.dec.unk2");
  Value *lshr13 = IRB.CreateLShr(unK2, ConstantInt::get(I32Ty, 13));
  Value *shl19 = IRB.CreateShl(unK2, ConstantInt::get(I32Ty, 19));
  Value *x2 = IRB.CreateOr(lshr13, shl19, "csm.dec.x2");
  Value *subC1 = IRB.CreateSub(x2, ConstantInt::get(I32Ty, CSM_ATTRACTOR_C1),
                               "csm.dec.subc1");
  Value *x1 = IRB.CreateMul(
      subC1, ConstantInt::get(I32Ty, CSM_ATTRACTOR_M1_INV), "csm.dec.x1");
  Value *unK1 = IRB.CreateXor(x1, ConstantInt::get(I32Ty, CSM_ATTRACTOR_K1),
                              "csm.dec.unk1");
  Value *lshr7 = IRB.CreateLShr(unK1, ConstantInt::get(I32Ty, 7));
  Value *shl25 = IRB.CreateShl(unK1, ConstantInt::get(I32Ty, 25));
  Value *target = IRB.CreateOr(lshr7, shl25, "csm.dec.target");
  return target;
}

// Build a warmup + unique chaos sequence of length `len`.
// warmupOverride=0 → use the ChaosWarmup cl::opt value.
static SmallVector<uint32_t, 32>
buildChaosSequence(uint32_t seed, unsigned len, uint32_t warmupOverride = 0) {
  // Warm up to escape the initial transient of the logistic map
  uint32_t x = (seed != 0) ? seed : (cryptoutils->get_uint32_t() | 0x40000000u);
  uint32_t warmupSteps =
      warmupOverride ? warmupOverride : (uint32_t)ChaosWarmup;
  for (uint32_t i = 0; i < warmupSteps; i++)
    x = chaosMapStep(x);

  std::unordered_set<uint32_t> seen;
  SmallVector<uint32_t, 32> seq;
  seq.reserve(len);

  uint32_t stuck_counter = 0;
  while (seq.size() < len) {
    x = chaosMapStep(x);
    if (!seen.count(x)) {
      seen.insert(x);
      seq.push_back(x);
      stuck_counter = 0;
    } else {
      stuck_counter++;
      if (stuck_counter > 5) {
        x ^= cryptoutils->get_uint32_t();
        stuck_counter = 0;
      }
    }
  }
  return seq;
}

// ─── Runtime IR: logistic map state transition in Q32
// ─────────────────────────

static Value *buildLogisticIR(IRBuilder<NoFolder> &IRB, Value *state,
                              LLVMContext &Ctx) {
  initCSMConstants();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Type *I32Ty = Type::getInt32Ty(Ctx);

  Value *s64 = IRB.CreateZExt(state, I64Ty, "csm.s64");
  Value *s64_bar = insertOpaqueBarrier(IRB, s64);
  Value *isZero = IRB.CreateICmpEQ(s64_bar, ConstantInt::get(I64Ty, 0));
  Value *xc = IRB.CreateSelect(
      isZero, ConstantInt::get(I64Ty, (uint64_t)CSM_FALLBACK_ZERO), s64_bar,
      "csm.xc");
  Value *inv =
      IRB.CreateSub(ConstantInt::get(I64Ty, 1ULL << 32), xc, "csm.inv");
  Value *prod = IRB.CreateMul(xc, inv, "csm.prod");
  Value *p32 = IRB.CreateLShr(prod, ConstantInt::get(I64Ty, 32), "csm.p32");
  Value *sc =
      IRB.CreateMul(p32, ConstantInt::get(I64Ty, 4294967291ULL), "csm.sc");
  Value *nxt64 = IRB.CreateLShr(sc, ConstantInt::get(I64Ty, 30), "csm.nxt64");
  Value *nxt32 = IRB.CreateTrunc(nxt64, I32Ty, "csm.nxt32");
  Value *nxtZero = IRB.CreateICmpEQ(nxt32, ConstantInt::get(I32Ty, 0));
  Value *guard =
      IRB.CreateSelect(nxtZero, ConstantInt::get(I32Ty, CSM_FALLBACK_RESULT),
                       nxt32, "csm.guarded");
  return guard;
}

static Value *computeDataFeedback(IRBuilder<NoFolder> &IRB, Function *F,
                                  uint32_t initSeed, BasicBlock *BB = nullptr) {
  LLVMContext &Ctx = F->getContext();
  Type *I32Ty = Type::getInt32Ty(Ctx);
  Value *dataFeedback = ConstantInt::get(I32Ty, initSeed);
  for (Argument &Arg : F->args()) {
    Value *argVal = nullptr;
    if (Arg.getType()->isIntegerTy()) {
      argVal = IRB.CreateZExtOrTrunc(&Arg, I32Ty);
    } else if (Arg.getType()->isPointerTy()) {
      Value *ptrInt = IRB.CreatePtrToInt(&Arg, Type::getInt64Ty(Ctx));
      argVal = IRB.CreateTrunc(ptrInt, I32Ty);
    }
    if (argVal) {
      Value *mul33 = IRB.CreateMul(dataFeedback, ConstantInt::get(I32Ty, 33),
                                   "csm.dfb.mul");
      dataFeedback = IRB.CreateXor(mul33, argVal, "csm.dfb.acc");
    }
  }

  if (BB) {
    SmallVector<Instruction *, 8> targets;
    for (Instruction &I : *BB) {
      if (isSynthetic(&I) || I.getName().starts_with("csm."))
        continue;
      if (I.getType()->isIntegerTy() && !isa<PHINode>(&I)) {
        targets.push_back(&I);
        if (targets.size() >= 4)
          break;
      }
    }
    for (Instruction *I : targets) {
      Value *val = IRB.CreateZExtOrTrunc(I, I32Ty);
      Value *mul33 = IRB.CreateMul(dataFeedback, ConstantInt::get(I32Ty, 33),
                                   "csm.dfb.mul");
      dataFeedback = IRB.CreateXor(mul33, val, "csm.dfb.bb");
    }
  }

  return dataFeedback;
}

// ─── Main flattening routine
// ──────────────────────────────────────────────────

namespace {
struct ChaosStateMachine : public FunctionPass {
  static char ID;
  bool flag;
  ChaosStateMachine() : FunctionPass(ID) { this->flag = true; }
  ChaosStateMachine(bool flag) : FunctionPass(ID) { this->flag = flag; }

  uint32_t warmupOverride = 0; // per-invocation warmup resolved from config
  uint32_t maxBlocksOverride = 0;

  bool runOnFunction(Function &F) override {
    if (!toObfuscate(flag, &F, "csm") || F.isPresplitCoroutine())
      return false;
    {
      auto ec =
          GObfConfig.resolve(F.getParent()->getSourceFileName(), F.getName());
      if (!toObfuscateBoolOption(&F, "csm_nested", &ChaosNestedDispatchTemp))
        ChaosNestedDispatchTemp =
            ec.csm.nested_dispatch.value_or((bool)ChaosNestedDispatch);
      warmupOverride = ec.csm.warmup.value_or(0);
      if (!toObfuscateUint32Option(&F, "csm_maxblocks", &maxBlocksOverride))
        maxBlocksOverride =
            ec.csm.max_blocks.value_or((uint32_t)ChaosMaxBlocks);
    }
    // MaxObf: enable nested dispatch (doubles CFG nodes, defeats analyzer
    // path-enumeration without adding basic block count to the function body).
    if (ObfuscationMaxMode) {
      ChaosNestedDispatchTemp = true;
      if (warmupOverride < 256)
        warmupOverride = 256;
    }

    if (ObfVerbose)
      errs() << "Running ChaosStateMachine On " << F.getName() << "\n";
    flatten(&F);
    return true;
  }

  void flatten(Function *F) {
    // ── Phase 1: lower switches, validate preconditions ──────────────────────
    // Use inline BST lowering instead of nested PassBuilder/LowerSwitchPass.
    // A nested PassBuilder inside an already-running new-PM pass deadlocks in
    // LLVM 22.x (shared AnalysisManager mutex).
    manuallyLowerSwitches(F);

    SmallVector<BasicBlock *, 16> origBBs;
    for (BasicBlock &BB : *F) {
      if (BB.isEHPad() || BB.isLandingPad()) {
        if (ObfVerbose)
          errs() << F->getName()
                 << ": ChaosStateMachine skipped (EH pad present)\n";
        return;
      }
      if (!isa<BranchInst>(BB.getTerminator()) &&
          !isa<ReturnInst>(BB.getTerminator()))
        return;
      origBBs.push_back(&BB);
    }
    if (origBBs.size() <= 1)
      return;

    // Size guard: running CSM on a function that was already processed by
    // ControlFlowFlattening causes LowerSwitchPass to expand the CFF switch
    // into a binary-comparison tree, giving O(N²) or worse IR growth.
    // Bail out early when the post-LowerSwitch block count exceeds the limit.
    uint32_t maxBlocks =
        maxBlocksOverride ? maxBlocksOverride : (uint32_t)ChaosMaxBlocks;
    if (origBBs.size() > maxBlocks) {
      if (ObfVerbose)
        errs() << F->getName() << ": ChaosStateMachine skipped (too many BBs: "
               << origBBs.size() << " > csm_maxblocks=" << maxBlocks << ")\n";
      return;
    }

    // ── Phase 2: prepare entry / remove first BB from rotation ───────────────
    origBBs.erase(origBBs.begin());

    Function::iterator fi = F->begin();
    BasicBlock *entryBB = &*fi;

    // If entry ends with a conditional, split it so the state alloca sits alone
    BasicBlock *entrySucc = nullptr;
    {
      BranchInst *br = dyn_cast<BranchInst>(entryBB->getTerminator());
      if (br && br->isConditional()) {
        BasicBlock::iterator splitPt = entryBB->end();
        --splitPt;
        if (entryBB->size() > 1)
          --splitPt;
        BasicBlock *splitBB =
            entryBB->splitBasicBlock(splitPt, "csm.entry.split");
        origBBs.insert(origBBs.begin(), splitBB);
        entrySucc = splitBB;
      } else if (br && br->isUnconditional()) {
        entrySucc = br->getSuccessor(0);
      }
    }

    // ── Phase 3: build chaos sequence ────────────────────────────────────────
    uint32_t seed = cryptoutils->get_uint32_t();
    unsigned numBBs = origBBs.size();
    SmallVector<uint32_t, 32> caseVals =
        buildChaosSequence(seed, numBBs, warmupOverride);

    // Feistel mask
    uint32_t feistelK = cryptoutils->get_uint32_t();
    uint32_t initDfbSeed = cryptoutils->get_uint32_t();

    // Precompute: for each block i, expected next diffused state
    SmallVector<uint32_t, 32> nextExpected(numBBs);
    for (unsigned i = 0; i < numBBs; i++)
      nextExpected[i] = diffuseState(chaosMapStep(caseVals[i]));

    // ── Phase 4: state alloca & initial store
    // ─────────────────────────────────
    LLVMContext &Ctx = F->getContext();
    Type *I32Ty = Type::getInt32Ty(Ctx);
    const DataLayout &DL = F->getParent()->getDataLayout();

    Instruction *oldTerm = entryBB->getTerminator();
    AllocaInst *stateAlloca =
        new AllocaInst(I32Ty, DL.getAllocaAddrSpace(), "csm.state", oldTerm);
    // Find initial target block index corresponding to entrySucc
    unsigned initIdx = 0;
    if (entrySucc) {
      for (unsigned j = 0; j < origBBs.size(); j++) {
        if (origBBs[j] == entrySucc) {
          initIdx = j;
          break;
        }
      }
    }
    // Store the attractor-encoded and feistel-masked initial case
    IRBuilder<NoFolder> IRBEntry(oldTerm);
    Value *dataFeedbackEntry = computeDataFeedback(IRBEntry, F, initDfbSeed);
    Value *maskValEntry = IRBEntry.CreateXor(ConstantInt::get(I32Ty, feistelK),
                                             dataFeedbackEntry, "csm.initmask");
    uint32_t initEnc = encodeAttractor(caseVals[initIdx]);
    Value *initValMasked = IRBEntry.CreateXor(ConstantInt::get(I32Ty, initEnc),
                                              maskValEntry, "csm.initstate");
    Value *opaqueInit = insertOpaqueBarrier(IRBEntry, initValMasked);
    IRBEntry.CreateStore(opaqueInit, stateAlloca);
    oldTerm->eraseFromParent();

    // ── Phase 5: loop structure
    // ───────────────────────────────────────────────
    BasicBlock *loopEntry = BasicBlock::Create(Ctx, "csm.loop", F, entryBB);
    BasicBlock *loopEnd = BasicBlock::Create(Ctx, "csm.loopend", F, entryBB);
    BasicBlock *swDefault = BasicBlock::Create(Ctx, "csm.default", F, loopEnd);
    BranchInst::Create(loopEnd, swDefault);
    BranchInst::Create(loopEntry, loopEnd);

    entryBB->moveBefore(loopEntry);
    BranchInst::Create(loopEntry, entryBB);

    SmallVector<std::pair<BasicBlock *, Value *>, 16> loopEndIncoming;
    loopEndIncoming.push_back(
        {swDefault, ConstantInt::get(I32Ty, initDfbSeed)});

    // ── Phase 6: chaos dispatch switch ───────────────────────────────────────
    IRBuilder<NoFolder> IRBLoop(loopEntry);
    PHINode *dfbPhiLoopEntry = IRBLoop.CreatePHI(I32Ty, 2, "csm.dfb.phi");
    dfbPhiLoopEntry->addIncoming(dataFeedbackEntry, entryBB);

    Value *rawState = IRBLoop.CreateLoad(I32Ty, stateAlloca, "csm.raw");
    Value *maskValLoop = IRBLoop.CreateXor(ConstantInt::get(I32Ty, feistelK),
                                           dfbPhiLoopEntry, "csm.loopmask");
    Value *demasked = IRBLoop.CreateXor(rawState, maskValLoop, "csm.demasked");
    Value *barDemasked = insertOpaqueBarrier(IRBLoop, demasked);
    Value *chaosState = buildDecodeAttractorIR(IRBLoop, barDemasked, Ctx);

    SwitchInst *switchI =
        SwitchInst::Create(chaosState, swDefault, numBBs, loopEntry);

    for (unsigned i = 0; i < numBBs; i++) {
      origBBs[i]->moveBefore(loopEnd);
      BasicBlock *dispatchTarget = origBBs[i];
      if (ChaosNestedDispatchTemp && numBBs >= 4) {
        BasicBlock *realBB = origBBs[i];
        BasicBlock *relay = BasicBlock::Create(Ctx, "csm.relay", F, realBB);
        IRBuilder<NoFolder> IRBR(relay);
        Value *rs = IRBR.CreateLoad(I32Ty, stateAlloca, "csm.relay.raw");
        Value *rs_dec = IRBR.CreateXor(rs, ConstantInt::get(I32Ty, feistelK));
        uint32_t innerMask = 0xF; // 16 possible inner targets
        Value *inner = IRBR.CreateAnd(
            rs_dec, ConstantInt::get(I32Ty, innerMask), "csm.inner");
        SwitchInst *innerSw =
            SwitchInst::Create(inner, realBB, innerMask + 1, relay);
        for (uint32_t k = 0; k <= innerMask; k++)
          innerSw->addCase(cast<ConstantInt>(ConstantInt::get(I32Ty, k)),
                           realBB);
        dispatchTarget = relay;
      }
      switchI->addCase(cast<ConstantInt>(ConstantInt::get(I32Ty, caseVals[i])),
                       dispatchTarget);
    }

    // ── Phase 7: per-block state update ──────────────────────────────────────
    for (unsigned i = 0; i < numBBs; i++) {
      BasicBlock *BB = origBBs[i];
      Instruction *term = BB->getTerminator();

      auto getSuccIdx = [&](BasicBlock *succ) -> int {
        for (unsigned j = 0; j < numBBs; j++)
          if (origBBs[j] == succ)
            return (int)j;
        if (succ == entryBB)
          return (int)initIdx;
        return -1;
      };

      if (term->getNumSuccessors() == 0)
        continue;

      IRBuilder<NoFolder> IRB(term);
      Value *dataFeedbackBB = computeDataFeedback(IRB, F, initDfbSeed, BB);
      Value *maskValBB = IRB.CreateXor(ConstantInt::get(I32Ty, feistelK),
                                       dataFeedbackBB, "csm.mask");
      Value *stateDemasked =
          chaosState; // use the correctly unmasked state from loopEntry

      if (term->getNumSuccessors() == 1) {
        BasicBlock *succ = term->getSuccessor(0);
        int j = getSuccIdx(succ);
        if (j >= 0) {
          uint32_t targetCase = caseVals[j];
          uint32_t targetEnc = encodeAttractor(targetCase);
          uint32_t delta1 = cryptoutils->get_uint32_t();
          uint32_t vAdd = nextExpected[i] + delta1;
          uint32_t delta2 = vAdd ^ targetEnc;

          Value *nextLog = buildLogisticIR(IRB, stateDemasked, Ctx);
          Value *nextRaw = buildDiffuseIR(IRB, nextLog, Ctx);
          Value *barNext = insertOpaqueBarrier(IRB, nextRaw);
          Value *nextVAdd = IRB.CreateAdd(
              barNext, ConstantInt::get(I32Ty, delta1), "csm.vadd");
          Value *nextDecoded = IRB.CreateXor(
              nextVAdd, ConstantInt::get(I32Ty, delta2), "csm.next");
          Value *nextMasked =
              IRB.CreateXor(nextDecoded, maskValBB, "csm.masked");
          Value *opaqueNext = insertOpaqueBarrier(IRB, nextMasked);
          IRB.CreateStore(opaqueNext, stateAlloca);
          term->eraseFromParent();
          loopEndIncoming.push_back({BB, dataFeedbackBB});
          BranchInst::Create(loopEnd, BB);
        } else {
          // Successor is an external/exit block — jump to it directly
          term->eraseFromParent();
          BranchInst::Create(succ, BB);
        }
      } else if (term->getNumSuccessors() == 2) {
        BranchInst *br = cast<BranchInst>(term);
        Value *cond = br->getCondition();
        BasicBlock *succTrue = br->getSuccessor(0);
        BasicBlock *succFalse = br->getSuccessor(1);

        int jT = getSuccIdx(succTrue);
        int jF = getSuccIdx(succFalse);

        if (jT >= 0 && jF >= 0) {
          uint32_t targetEncT = encodeAttractor(caseVals[jT]);
          uint32_t targetEncF = encodeAttractor(caseVals[jF]);
          uint32_t delta1 = cryptoutils->get_uint32_t();
          uint32_t vAdd = nextExpected[i] + delta1;
          uint32_t delta2T = vAdd ^ targetEncT;
          uint32_t delta2F = vAdd ^ targetEncF;

          Value *nextLog = buildLogisticIR(IRB, stateDemasked, Ctx);
          Value *nextRaw = buildDiffuseIR(IRB, nextLog, Ctx);
          Value *barNext = insertOpaqueBarrier(IRB, nextRaw);
          Value *nextVAdd = IRB.CreateAdd(
              barNext, ConstantInt::get(I32Ty, delta1), "csm.vadd");

          // Branchless selection between delta2T and delta2F
          Value *condExt = IRB.CreateZExt(cond, I32Ty, "csm.c.ext");
          Value *mask =
              IRB.CreateSub(ConstantInt::get(I32Ty, 0), condExt, "csm.c.mask");
          Value *diff = ConstantInt::get(I32Ty, delta2T ^ delta2F);
          Value *maskedDiff = IRB.CreateAnd(mask, diff, "csm.c.diff");
          Value *delta2Val = IRB.CreateXor(ConstantInt::get(I32Ty, delta2F),
                                           maskedDiff, "csm.c.delta2");
          Value *nextDecoded = IRB.CreateXor(nextVAdd, delta2Val, "csm.next");
          Value *nextMasked =
              IRB.CreateXor(nextDecoded, maskValBB, "csm.masked");
          Value *opaqueNext = insertOpaqueBarrier(IRB, nextMasked);
          IRB.CreateStore(opaqueNext, stateAlloca);
          term->eraseFromParent();
          loopEndIncoming.push_back({BB, dataFeedbackBB});
          BranchInst::Create(loopEnd, BB);
        } else if (jT >= 0 && jF < 0) {
          uint32_t targetEncT = encodeAttractor(caseVals[jT]);
          uint32_t delta1 = cryptoutils->get_uint32_t();
          uint32_t vAdd = nextExpected[i] + delta1;
          uint32_t delta2T = vAdd ^ targetEncT;

          Value *nextLog = buildLogisticIR(IRB, stateDemasked, Ctx);
          Value *nextRaw = buildDiffuseIR(IRB, nextLog, Ctx);
          Value *barNext = insertOpaqueBarrier(IRB, nextRaw);
          Value *nextVAdd = IRB.CreateAdd(
              barNext, ConstantInt::get(I32Ty, delta1), "csm.vadd");
          Value *nextDecoded = IRB.CreateXor(
              nextVAdd, ConstantInt::get(I32Ty, delta2T), "csm.next");
          Value *nextMasked =
              IRB.CreateXor(nextDecoded, maskValBB, "csm.masked");
          Value *opaqueNext = insertOpaqueBarrier(IRB, nextMasked);
          IRB.CreateStore(opaqueNext, stateAlloca);
          term->eraseFromParent();
          loopEndIncoming.push_back({BB, dataFeedbackBB});
          BranchInst::Create(loopEnd, succFalse, cond, BB);
        } else if (jT < 0 && jF >= 0) {
          uint32_t targetEncF = encodeAttractor(caseVals[jF]);
          uint32_t delta1 = cryptoutils->get_uint32_t();
          uint32_t vAdd = nextExpected[i] + delta1;
          uint32_t delta2F = vAdd ^ targetEncF;

          Value *nextLog = buildLogisticIR(IRB, stateDemasked, Ctx);
          Value *nextRaw = buildDiffuseIR(IRB, nextLog, Ctx);
          Value *barNext = insertOpaqueBarrier(IRB, nextRaw);
          Value *nextVAdd = IRB.CreateAdd(
              barNext, ConstantInt::get(I32Ty, delta1), "csm.vadd");
          Value *nextDecoded = IRB.CreateXor(
              nextVAdd, ConstantInt::get(I32Ty, delta2F), "csm.next");
          Value *nextMasked =
              IRB.CreateXor(nextDecoded, maskValBB, "csm.masked");
          Value *opaqueNext = insertOpaqueBarrier(IRB, nextMasked);
          IRB.CreateStore(opaqueNext, stateAlloca);
          term->eraseFromParent();
          loopEndIncoming.push_back({BB, dataFeedbackBB});
          BranchInst::Create(succTrue, loopEnd, cond, BB);
        } else {
          // Both targets external
          term->eraseFromParent();
          BranchInst::Create(succTrue, succFalse, cond, BB);
        }
      }
    }

    // Now populate dfbPhiLoopEnd and dfbPhiLoopEntry
    IRBuilder<NoFolder> IRBLoopEnd(loopEnd->getFirstNonPHI());
    PHINode *dfbPhiLoopEnd =
        IRBLoopEnd.CreatePHI(I32Ty, loopEndIncoming.size(), "csm.dfb.phi.end");
    for (auto &pair : loopEndIncoming) {
      dfbPhiLoopEnd->addIncoming(pair.second, pair.first);
    }
    dfbPhiLoopEntry->addIncoming(dfbPhiLoopEnd, loopEnd);
    if (ObfVerbose)
      errs() << "ChaosStateMachine: fixing stack for " << F->getName() << "\n";
    fixStack(F);

    // Stamp this function so the downstream classic Flattening pass knows it
    // has already received the stronger chaos-based CFF and should be skipped.
    // Flattening checks for this attribute in its runOnFunction guard.
    F->addFnAttr("ensia.csm.done");
  }
};
} // anonymous namespace

char ChaosStateMachine::ID = 0;
INITIALIZE_PASS(ChaosStateMachine, "csmobf",
                "Enable ChaosStateMachine (Logistic Map CFF).", false, false)

FunctionPass *llvm::createChaosStateMachinePass(bool flag) {
  return new ChaosStateMachine(flag);
}
