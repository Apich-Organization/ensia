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
#include "llvm/Support/CommandLine.h"
#include <unordered_set>

using namespace llvm;

static cl::opt<bool> ChaosNestedDispatch(
    "csm_nested",
    cl::desc("[ChaosStateMachine] Enable two-level nested switch dispatch"),
    cl::init(false), cl::Optional);
static bool ChaosNestedDispatchTemp = false;

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

static void initCSMConstants() {
  if (CSM_FALLBACK_ZERO == 0) {
    CSM_FALLBACK_ZERO = (cryptoutils->get_uint16_t() | 0x1000u);
    CSM_FALLBACK_RESULT = (cryptoutils->get_uint16_t() | 0xC000u);
  }
}

uint32_t llvm::chaosMapStep(uint32_t x) {
  initCSMConstants();
  uint64_t xc = (uint64_t)(x & 0xFFFFu);
  if (xc == 0)
    xc = CSM_FALLBACK_ZERO; // avoid absorbing fixed point at 0
  uint64_t inv = 65536ULL - xc;
  uint64_t prod = xc * inv;                           // Q32
  uint32_t nxt = (uint32_t)((prod * 65533ULL) >> 30); // Q16 result
  return nxt ? nxt : CSM_FALLBACK_RESULT; // avoid fixed point at 0 in result
}

// Build a warmup + unique chaos sequence of length `len`.
// warmupOverride=0 → use the ChaosWarmup cl::opt value.
static SmallVector<uint32_t, 32>
buildChaosSequence(uint32_t seed, unsigned len, uint32_t warmupOverride = 0) {
  // Warm up to escape the initial transient of the logistic map
  uint32_t x = (seed != 0) ? seed : (cryptoutils->get_uint16_t() | 0x4000u);
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
        x ^= cryptoutils->get_uint16_t();
        stuck_counter = 0;
      }
    }
  }
  return seq;
}

// ─── Runtime IR: logistic map state transition ───────────────────────────────

static Value *buildLogisticIR(IRBuilder<NoFolder> &IRB, Value *state,
                              LLVMContext &Ctx) {
  initCSMConstants();
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Type *I32Ty = Type::getInt32Ty(Ctx);

  Value *s64 = IRB.CreateZExt(state, I64Ty, "csm.s64");
  Value *xc_raw =
      IRB.CreateAnd(s64, ConstantInt::get(I64Ty, 0xFFFF), "csm.xc_raw");
  Value *xcIsZero = IRB.CreateICmpEQ(xc_raw, ConstantInt::get(I64Ty, 0));
  Value *xc = IRB.CreateSelect(
      xcIsZero, ConstantInt::get(I64Ty, CSM_FALLBACK_ZERO), xc_raw, "csm.xc");
  Value *inv = IRB.CreateSub(ConstantInt::get(I64Ty, 65536), xc, "csm.inv");
  Value *prod = IRB.CreateMul(xc, inv, "csm.prod");
  Value *sc = IRB.CreateMul(prod, ConstantInt::get(I64Ty, 65533), "csm.sc");
  Value *nxt64 = IRB.CreateLShr(sc, ConstantInt::get(I64Ty, 30), "csm.nxt64");
  Value *nxt32 = IRB.CreateTrunc(nxt64, I32Ty, "csm.nxt32");
  Value *isZero = IRB.CreateICmpEQ(nxt32, ConstantInt::get(I32Ty, 0));
  Value *guard =
      IRB.CreateSelect(isZero, ConstantInt::get(I32Ty, CSM_FALLBACK_RESULT),
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
      Value *mul33 = IRB.CreateMul(dataFeedback, ConstantInt::get(I32Ty, 33));
      dataFeedback = IRB.CreateXor(mul33, argVal, "csm.dfb.acc");
    }
  }

  if (BB) {
    SmallVector<Instruction *, 32> targets;
    for (Instruction &I : *BB) {
      if (I.getName().starts_with("csm."))
        continue;
      if (I.getType()->isIntegerTy() && !isa<PHINode>(&I)) {
        targets.push_back(&I);
      }
    }
    for (Instruction *I : targets) {
      Value *val = IRB.CreateZExtOrTrunc(I, I32Ty);
      Value *mul33 = IRB.CreateMul(dataFeedback, ConstantInt::get(I32Ty, 33));
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

    // Precompute: for each block i, L_i = chaosMapStep(caseVals[i])
    SmallVector<uint32_t, 32> logisticNext(numBBs);
    for (unsigned i = 0; i < numBBs; i++)
      logisticNext[i] = chaosMapStep(caseVals[i]);

    // ── Phase 4: state alloca & initial store
    // ─────────────────────────────────
    LLVMContext &Ctx = F->getContext();
    Type *I32Ty = Type::getInt32Ty(Ctx);
    const DataLayout &DL = F->getParent()->getDataLayout();

    Instruction *oldTerm = entryBB->getTerminator();
    AllocaInst *stateAlloca =
        new AllocaInst(I32Ty, DL.getAllocaAddrSpace(), "csm.state", oldTerm);
    // Store the feistel-masked initial case (block 0)
    IRBuilder<NoFolder> IRBEntry(oldTerm);
    Value *dataFeedbackEntry = computeDataFeedback(IRBEntry, F, initDfbSeed);
    Value *maskValEntry = IRBEntry.CreateXor(ConstantInt::get(I32Ty, feistelK),
                                             dataFeedbackEntry, "csm.initmask");
    Value *initValMasked = IRBEntry.CreateXor(
        ConstantInt::get(I32Ty, caseVals[0]), maskValEntry, "csm.initstate");
    IRBEntry.CreateStore(initValMasked, stateAlloca);
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
    Value *chaosState = IRBLoop.CreateXor(rawState, maskValLoop, "csm.decoded");

    SwitchInst *switchI =
        SwitchInst::Create(chaosState, swDefault, numBBs, loopEntry);

    for (unsigned i = 0; i < numBBs; i++) {
      origBBs[i]->moveBefore(loopEnd);
      switchI->addCase(cast<ConstantInt>(ConstantInt::get(I32Ty, caseVals[i])),
                       origBBs[i]);
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
          return 0;
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
          uint32_t corr = logisticNext[i] ^ targetCase;
          Value *nextRaw = buildLogisticIR(IRB, stateDemasked, Ctx);
          Value *nextDecoded =
              IRB.CreateXor(nextRaw, ConstantInt::get(I32Ty, corr), "csm.next");
          Value *nextMasked =
              IRB.CreateXor(nextDecoded, maskValBB, "csm.masked");
          IRB.CreateStore(nextMasked, stateAlloca);
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
          uint32_t caseT = caseVals[jT];
          uint32_t caseF = caseVals[jF];
          uint32_t corrT = logisticNext[i] ^ caseT;
          uint32_t corrF = logisticNext[i] ^ caseF;

          Value *nextRaw = buildLogisticIR(IRB, stateDemasked, Ctx);
          Value *corrSel =
              IRB.CreateSelect(cond, ConstantInt::get(I32Ty, corrT),
                               ConstantInt::get(I32Ty, corrF), "csm.corr");
          Value *nextDecoded = IRB.CreateXor(nextRaw, corrSel, "csm.next");
          Value *nextMasked =
              IRB.CreateXor(nextDecoded, maskValBB, "csm.masked");
          IRB.CreateStore(nextMasked, stateAlloca);
          term->eraseFromParent();
          loopEndIncoming.push_back({BB, dataFeedbackBB});
          BranchInst::Create(loopEnd, BB);
        } else if (jT >= 0 && jF < 0) {
          uint32_t caseT = caseVals[jT];
          uint32_t corrT = logisticNext[i] ^ caseT;
          Value *nextRaw = buildLogisticIR(IRB, stateDemasked, Ctx);
          Value *nextDecoded = IRB.CreateXor(
              nextRaw, ConstantInt::get(I32Ty, corrT), "csm.next");
          Value *nextMasked =
              IRB.CreateXor(nextDecoded, maskValBB, "csm.masked");
          IRB.CreateStore(nextMasked, stateAlloca);
          term->eraseFromParent();
          loopEndIncoming.push_back({BB, dataFeedbackBB});
          BranchInst::Create(loopEnd, succFalse, cond, BB);
        } else if (jT < 0 && jF >= 0) {
          uint32_t caseF = caseVals[jF];
          uint32_t corrF = logisticNext[i] ^ caseF;
          Value *nextRaw = buildLogisticIR(IRB, stateDemasked, Ctx);
          Value *nextDecoded = IRB.CreateXor(
              nextRaw, ConstantInt::get(I32Ty, corrF), "csm.next");
          Value *nextMasked =
              IRB.CreateXor(nextDecoded, maskValBB, "csm.masked");
          IRB.CreateStore(nextMasked, stateAlloca);
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

    // ── Phase 8: optional nested dispatch for extra path-explosion ───────────
    if (ChaosNestedDispatchTemp && numBBs >= 4) {
      // For each switch case, insert a relay block that performs a second
      // dispatch keyed on the lower nibble of the (already decoded) chaos
      // state. This doubles the number of CFG nodes a tool must enumerate.
      uint32_t innerMask = 0xF; // 16 possible inner targets
      for (unsigned i = 0; i < numBBs; i++) {
        BasicBlock *realBB = origBBs[i];
        BasicBlock *relay = BasicBlock::Create(Ctx, "csm.relay", F, realBB);
        // Re-point the switch case to relay instead of realBB
        switchI->removeCase(switchI->findCaseValue(
            cast<ConstantInt>(ConstantInt::get(I32Ty, caseVals[i]))));
        switchI->addCase(
            cast<ConstantInt>(ConstantInt::get(I32Ty, caseVals[i])), relay);

        IRBuilder<NoFolder> IRBR(relay);
        Value *rs = IRBR.CreateLoad(I32Ty, stateAlloca, "csm.relay.raw");
        Value *rs_dec = IRBR.CreateXor(rs, ConstantInt::get(I32Ty, feistelK));
        Value *inner = IRBR.CreateAnd(
            rs_dec, ConstantInt::get(I32Ty, innerMask), "csm.inner");
        // Inner switch: all cases lead to realBB — confusing but correct
        SwitchInst *innerSw =
            SwitchInst::Create(inner, realBB, innerMask + 1, relay);
        for (uint32_t k = 0; k <= innerMask; k++)
          innerSw->addCase(cast<ConstantInt>(ConstantInt::get(I32Ty, k)),
                           realBB);
      }
    }

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
