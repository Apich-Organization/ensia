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

// ChaosStateMachine.cpp — Control-flow flattening driven by a Q16 logistic map.
//
// Mathematical foundation
// ───────────────────────
// Logistic map:  x_{n+1} = r · x_n · (1 − x_n),  r ≈ 3.9999 (chaotic regime)
//
// Fixed-point encoding (Q16):  x_fp ∈ [0, 65535] represents x_real ∈ [0, 1).
// Integer recurrence:
//   product = x_fp × (65536 − x_fp)          (fits in 32 bits)
//   x_next  = (product × 65533) >> 30         (65533 ≈ r · 2^14)
//
// In the LLVM IR the state transition is rendered as a 64-bit multiply chain:
//   %s64   = zext i32 %state to i64
//   %xc    = and  i64 %s64,  65535
//   %inv   = sub  i64 65536, %xc
//   %prod  = mul  i64 %xc,   %inv
//   %sc    = mul  i64 %prod, 65533
//   %next  = lshr i64 %sc,   30
//   %state_new = trunc i64 %next to i32
//
// Binja MLIL cannot collapse a quadratic recurrence over a loaded variable to
// a constant; symbolic execution faces path explosion at each switch iteration.
//
// Block-exit state update (correctness proof):
//   Let caseVals[i] = chaos label for block i (precomputed sequence).
//   At block i exit heading to block j:
//     • Compile-time: L_i = chaosMapStep(caseVals[i])
//     • Compile-time: corr_ij = L_i XOR caseVals[j]
//     • Runtime IR:   stored = logistic_IR(%state) XOR corr_ij
//       = chaosMapStep(caseVals[i]) XOR (chaosMapStep(caseVals[i]) XOR caseVals[j])
//       = caseVals[j]   ✓
//
// The switch in loopEntry then dispatches on caseVals[j], jumping to block j.
//
// Additional confusion layer: every case value is XOR'd with a per-function
// Feistel-round constant (feistelK) before being used as a switch case.
// The state alloca stores the pre-feistel value; the switch comparison uses
// (state XOR feistelK). A static analyzer must uncover feistelK to proceed.

#include "include/ChaosStateMachine.h"
#include "include/CryptoUtils.h"
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

static cl::opt<uint32_t> ChaosWarmup(
    "csm_warmup",
    cl::desc("[ChaosStateMachine] Logistic map warmup iterations (skip initial transient)"),
    cl::init(64), cl::Optional);

static cl::opt<uint32_t> ChaosMaxBlocks(
    "csm_maxblocks",
    cl::desc("[ChaosStateMachine] True safety-net: skip functions whose BB count "
             "after LowerSwitch exceeds this value (catastrophic-size guard only; "
             "normal operation is controlled by pass ordering, default 10000)"),
    cl::init(10000), cl::Optional);

// ─── Compile-time logistic map ───────────────────────────────────────────────

uint32_t llvm::chaosMapStep(uint32_t x) {
  uint64_t xc   = (uint64_t)(x & 0xFFFFu);
  if (xc == 0) xc = 0x1337; // avoid absorbing fixed point at 0
  uint64_t inv  = 65536ULL - xc;
  uint64_t prod = xc * inv;                    // Q32
  uint32_t nxt  = (uint32_t)((prod * 65533ULL) >> 30); // Q16 result
  return nxt ? nxt : 0xC0DE; // avoid fixed point at 0 in result
}

// Build a warmup + unique chaos sequence of length `len`.
static SmallVector<uint32_t, 32>
buildChaosSequence(uint32_t seed, unsigned len) {
  // Warm up to escape the initial transient of the logistic map
  uint32_t x = (seed != 0) ? seed : 0x4B1D;
  for (uint32_t i = 0; i < ChaosWarmup; i++)
    x = chaosMapStep(x);

  std::unordered_set<uint32_t> seen;
  SmallVector<uint32_t, 32> seq;
  seq.reserve(len);
  while (seq.size() < len) {
    x = chaosMapStep(x);
    if (!seen.count(x)) {
      seen.insert(x);
      seq.push_back(x);
    }
  }
  return seq;
}

// ─── Runtime IR: logistic map state transition ───────────────────────────────

// Build IR that computes chaosMapStep(%state) using 64-bit integer arithmetic.
// Returns the new i32 state value (does NOT store it).
static Value *buildLogisticIR(IRBuilder<NoFolder> &IRB, Value *state,
                               LLVMContext &Ctx) {
  Type *I64Ty = Type::getInt64Ty(Ctx);
  Type *I32Ty = Type::getInt32Ty(Ctx);

  Value *s64   = IRB.CreateZExt(state, I64Ty, "csm.s64");
  Value *xc    = IRB.CreateAnd(s64, ConstantInt::get(I64Ty, 0xFFFF), "csm.xc");
  Value *inv   = IRB.CreateSub(ConstantInt::get(I64Ty, 65536), xc, "csm.inv");
  Value *prod  = IRB.CreateMul(xc, inv, "csm.prod");
  Value *sc    = IRB.CreateMul(prod, ConstantInt::get(I64Ty, 65533), "csm.sc");
  Value *nxt64 = IRB.CreateLShr(sc, ConstantInt::get(I64Ty, 30), "csm.nxt64");
  Value *nxt32 = IRB.CreateTrunc(nxt64, I32Ty, "csm.nxt32");
  // Guard against the absorbing fixed point 0 in the IR (unlikely but safe):
  // if nxt32 == 0 then use 0xC0DE; implemented as: nxt32 | ((nxt32==0) * 0xC0DE)
  Value *isZero = IRB.CreateICmpEQ(nxt32, ConstantInt::get(I32Ty, 0));
  Value *guard  = IRB.CreateSelect(isZero, ConstantInt::get(I32Ty, 0xC0DE), nxt32,
                                   "csm.guarded");
  return guard;
}

// ─── Main flattening routine ──────────────────────────────────────────────────

namespace {
struct ChaosStateMachine : public FunctionPass {
  static char ID;
  bool flag;
  ChaosStateMachine() : FunctionPass(ID) { this->flag = true; }
  ChaosStateMachine(bool flag) : FunctionPass(ID) { this->flag = flag; }

  bool runOnFunction(Function &F) override {
    if (!toObfuscate(flag, &F, "csm") || F.isPresplitCoroutine())
      return false;
    if (!toObfuscateBoolOption(&F, "csm_nested", &ChaosNestedDispatchTemp))
      ChaosNestedDispatchTemp = ChaosNestedDispatch;
    // MaxObf: enable nested dispatch (doubles CFG nodes, defeats analyzer
    // path-enumeration without adding basic block count to the function body).
    if (ObfuscationMaxMode)
      ChaosNestedDispatchTemp = true;

    if (ObfVerbose) errs() << "Running ChaosStateMachine On " << F.getName() << "\n";
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
        if (ObfVerbose) errs() << F->getName()
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
    if (origBBs.size() > ChaosMaxBlocks) {
      if (ObfVerbose) errs() << F->getName() << ": ChaosStateMachine skipped (too many BBs: "
             << origBBs.size() << " > csm_maxblocks=" << ChaosMaxBlocks
             << ")\n";
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
        BasicBlock *splitBB = entryBB->splitBasicBlock(splitPt, "csm.entry.split");
        origBBs.insert(origBBs.begin(), splitBB);
      }
    }

    // ── Phase 3: build chaos sequence ────────────────────────────────────────
    uint32_t seed = cryptoutils->get_uint32_t();
    unsigned numBBs = origBBs.size();
    SmallVector<uint32_t, 32> caseVals = buildChaosSequence(seed, numBBs);

    // Feistel mask: XOR'd into every case value so the switch uses
    // (state XOR feistelK) as the discriminant instead of state directly.
    uint32_t feistelK = cryptoutils->get_uint32_t();

    // Precompute: for each block i, L_i = chaosMapStep(caseVals[i])
    SmallVector<uint32_t, 32> logisticNext(numBBs);
    for (unsigned i = 0; i < numBBs; i++)
      logisticNext[i] = chaosMapStep(caseVals[i]);

    // ── Phase 4: state alloca & initial store ─────────────────────────────────
    LLVMContext &Ctx   = F->getContext();
    Type *I32Ty        = Type::getInt32Ty(Ctx);
    const DataLayout &DL = F->getParent()->getDataLayout();

    Instruction *oldTerm = entryBB->getTerminator();
    AllocaInst *stateAlloca = new AllocaInst(I32Ty, DL.getAllocaAddrSpace(),
                                             "csm.state", oldTerm);
    // Store the feistel-masked initial case (block 0)
    uint32_t initVal = caseVals[0] ^ feistelK;
    new StoreInst(ConstantInt::get(I32Ty, initVal), stateAlloca, oldTerm);
    oldTerm->eraseFromParent();

    // ── Phase 5: loop structure ───────────────────────────────────────────────
    BasicBlock *loopEntry = BasicBlock::Create(Ctx, "csm.loop", F, entryBB);
    BasicBlock *loopEnd   = BasicBlock::Create(Ctx, "csm.loopend", F, entryBB);
    BasicBlock *swDefault = BasicBlock::Create(Ctx, "csm.default", F, loopEnd);
    BranchInst::Create(loopEnd, swDefault);
    BranchInst::Create(loopEntry, loopEnd);

    // entryBB currently has no terminator (oldTerm was erased in Phase 4).
    // Move it back to the front of the function so it remains the IR entry
    // block, then add a single unconditional branch into the dispatch loop.
    // NOTE: do NOT add a branch before moveBefore — that would insert a
    // terminator into entryBB twice, producing invalid IR.
    entryBB->moveBefore(loopEntry);
    BranchInst::Create(loopEntry, entryBB); // entryBB → loop (sole terminator)

    // ── Phase 6: chaos dispatch switch ───────────────────────────────────────
    // Load state, XOR with feistelK to recover raw chaos value, then switch.
    IRBuilder<NoFolder> IRBLoop(loopEntry);
    Value *rawState   = IRBLoop.CreateLoad(I32Ty, stateAlloca, "csm.raw");
    Value *chaosState = IRBLoop.CreateXor(
        rawState, ConstantInt::get(I32Ty, feistelK), "csm.decoded");

    SwitchInst *switchI = SwitchInst::Create(chaosState, swDefault, numBBs,
                                             loopEntry);

    for (unsigned i = 0; i < numBBs; i++) {
      origBBs[i]->moveBefore(loopEnd);
      switchI->addCase(cast<ConstantInt>(ConstantInt::get(I32Ty, caseVals[i])), origBBs[i]);
    }

    // ── Phase 7: per-block state update ──────────────────────────────────────
    // For each block, replace the original branch with a state-store + jump to loopEnd.
    for (unsigned i = 0; i < numBBs; i++) {
      BasicBlock *BB = origBBs[i];
      Instruction *term = BB->getTerminator();

      // Compute correction constant(s):
      //   corr_ij = logisticNext[i] XOR caseVals[j]  (for each successor j)
      auto getSuccIdx = [&](BasicBlock *succ) -> int {
        for (unsigned j = 0; j < numBBs; j++)
          if (origBBs[j] == succ)
            return (int)j;
        return -1; // returning to default/exit
      };

      if (term->getNumSuccessors() == 0) {
        // Return instruction — leave it alone
        continue;
      }

      IRBuilder<NoFolder> IRB(term);

      // stateAlloca always holds the feistel-MASKED value (caseVals[i] ^ feistelK).
      // The logistic map correction constants were pre-computed from the UNMASKED
      // caseVals[i], so we must decode before applying the map.
      // Crucially the decoded value only exists in an SSA register — it is never
      // stored to memory, so a process-memory dump still only sees masked values.
      //
      //   stored     = caseVals[i] ^ feistelK
      //   demasked   = stored ^ feistelK = caseVals[i]                (register only)
      //   nextRaw    = logistic(demasked) = chaosMapStep(caseVals[i]) (register only)
      //   nextDec    = nextRaw ^ corr     = caseVals[j]               (register only)
      //   nextMasked = nextDec ^ feistelK = caseVals[j] ^ feistelK    → stored ✓
      Value *stateLoad    = IRB.CreateLoad(I32Ty, stateAlloca, "csm.cur");
      Value *stateDemasked = IRB.CreateXor(stateLoad,
                                           ConstantInt::get(I32Ty, feistelK),
                                           "csm.demasked"); // register-only, never stored

      if (term->getNumSuccessors() == 1) {
        BasicBlock *succ = term->getSuccessor(0);
        int j = getSuccIdx(succ);
        uint32_t targetCase = (j >= 0) ? caseVals[j] : caseVals[numBBs - 1];
        uint32_t corr = logisticNext[i] ^ targetCase;
        Value *nextRaw    = buildLogisticIR(IRB, stateDemasked, Ctx);
        Value *nextDecoded = IRB.CreateXor(nextRaw, ConstantInt::get(I32Ty, corr),
                                           "csm.next");
        Value *nextMasked  = IRB.CreateXor(nextDecoded,
                                           ConstantInt::get(I32Ty, feistelK),
                                           "csm.masked");
        IRB.CreateStore(nextMasked, stateAlloca);
        term->eraseFromParent();
        BranchInst::Create(loopEnd, BB);
      } else if (term->getNumSuccessors() == 2) {
        BranchInst *br = cast<BranchInst>(term);
        Value *cond = br->getCondition();
        BasicBlock *succTrue  = br->getSuccessor(0);
        BasicBlock *succFalse = br->getSuccessor(1);

        int jT = getSuccIdx(succTrue);
        int jF = getSuccIdx(succFalse);
        uint32_t caseT = (jT >= 0) ? caseVals[jT] : caseVals[numBBs - 1];
        uint32_t caseF = (jF >= 0) ? caseVals[jF] : caseVals[numBBs - 1];
        uint32_t corrT = logisticNext[i] ^ caseT;
        uint32_t corrF = logisticNext[i] ^ caseF;

        Value *nextRaw    = buildLogisticIR(IRB, stateDemasked, Ctx);
        Value *corrSel    = IRB.CreateSelect(cond,
                                ConstantInt::get(I32Ty, corrT),
                                ConstantInt::get(I32Ty, corrF),
                                "csm.corr");
        Value *nextDecoded = IRB.CreateXor(nextRaw, corrSel, "csm.next");
        Value *nextMasked  = IRB.CreateXor(nextDecoded,
                                           ConstantInt::get(I32Ty, feistelK),
                                           "csm.masked");
        IRB.CreateStore(nextMasked, stateAlloca);
        term->eraseFromParent();
        BranchInst::Create(loopEnd, BB);
      }
    }

    // ── Phase 8: optional nested dispatch for extra path-explosion ───────────
    if (ChaosNestedDispatchTemp && numBBs >= 4) {
      // For each switch case, insert a relay block that performs a second
      // dispatch keyed on the lower nibble of the (already decoded) chaos state.
      // This doubles the number of CFG nodes a tool must enumerate.
      uint32_t innerMask = 0xF; // 16 possible inner targets
      for (unsigned i = 0; i < numBBs; i++) {
        BasicBlock *realBB = origBBs[i];
        BasicBlock *relay  = BasicBlock::Create(Ctx, "csm.relay", F, realBB);
        // Re-point the switch case to relay instead of realBB
        switchI->removeCase(switchI->findCaseValue(
            cast<ConstantInt>(ConstantInt::get(I32Ty, caseVals[i]))));
        switchI->addCase(cast<ConstantInt>(ConstantInt::get(I32Ty, caseVals[i])), relay);

        IRBuilder<NoFolder> IRBR(relay);
        Value *rs     = IRBR.CreateLoad(I32Ty, stateAlloca, "csm.relay.raw");
        Value *rs_dec = IRBR.CreateXor(rs, ConstantInt::get(I32Ty, feistelK));
        Value *inner  = IRBR.CreateAnd(rs_dec, ConstantInt::get(I32Ty, innerMask),
                                       "csm.inner");
        // Inner switch: all cases lead to realBB — confusing but correct
        SwitchInst *innerSw = SwitchInst::Create(inner, realBB, innerMask + 1, relay);
        for (uint32_t k = 0; k <= innerMask; k++)
          innerSw->addCase(cast<ConstantInt>(ConstantInt::get(I32Ty, k)), realBB);
      }
    }

    if (ObfVerbose) errs() << "ChaosStateMachine: fixing stack for " << F->getName() << "\n";
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
