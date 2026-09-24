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

#include "include/Flattening.h"
#include "include/ChaosStateMachine.h"
#include "include/CryptoUtils.h"
#include "include/ObfConfig.h"
#include "include/Utils.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"

using namespace llvm;

namespace {
struct Flattening : public FunctionPass {
  static char ID; // Pass identification, replacement for typeid
  bool flag;
  Flattening() : FunctionPass(ID) { this->flag = true; }
  Flattening(bool flag) : FunctionPass(ID) { this->flag = flag; }
  bool runOnFunction(Function &F) override;
  void flatten(Function *f);
};
} // namespace

char Flattening::ID = 0;
FunctionPass *llvm::createFlatteningPass(bool flag) {
  return new Flattening(flag);
}
INITIALIZE_PASS(Flattening, "cffobf", "Enable Control Flow Flattening.", false,
                false)
bool Flattening::runOnFunction(Function &F) {
  Function *tmp = &F;
  auto ec = GObfConfig.resolve(F.getParent()->getSourceFileName(), F.getName());
  bool shouldObf = ec.flatten.enabled.value_or(flag);
  // Do we obfuscate?
  if (toObfuscate(shouldObf, tmp, "fla") && !F.isPresplitCoroutine()) {
    // ChaosStateMachine already ran on this function and provided a stronger
    // logistic-map-based CFF.  Running Flattening on top would cascade:
    // Flattening's LowerSwitchPass expands the CSM switch into a binary
    // comparison tree → O(N²)+ IR growth.  Skip gracefully.
    if (F.hasFnAttribute("ensia.csm.done")) {
      if (ObfVerbose)
        errs() << "ControlFlowFlattening: skipping " << F.getName()
               << " (already flattened by ChaosStateMachine)\n";
      return false;
    }
    if (ObfVerbose)
      errs() << "Running ControlFlowFlattening On " << F.getName() << "\n";
    flatten(tmp);
  }

  return true;
}

void Flattening::flatten(Function *f) {
  SmallVector<BasicBlock *, 8> origBB;
  BasicBlock *loopEntry, *loopEnd;
  LoadInst *load;
  SwitchInst *switchI;
  AllocaInst *switchVar, *switchVarAddr;
  const DataLayout &DL = f->getParent()->getDataLayout();

  uint32_t chaosSeed = cryptoutils->get_uint32_t() | 1u;
  for (int wu = 0; wu < 37; wu++)
    chaosSeed = chaosMapStep(chaosSeed);

  // SCRAMBLER — now chaos-seeded
  std::unordered_map<uint32_t, uint32_t> scrambling_key;
  // END OF SCRAMBLER

  // Use shared inline BST lowering — avoids nested PassBuilder deadlock.
  manuallyLowerSwitches(f);

  for (BasicBlock &BB : *f) {
    if (BB.isEHPad() || BB.isLandingPad()) {
      if (ObfVerbose)
        errs() << f->getName()
               << " Contains Exception Handing Instructions and is unsupported "
                  "for flattening in the open-source version of Ensia.\n";
      return;
    }
    if (!isa<BranchInst>(BB.getTerminator()) &&
        !isa<ReturnInst>(BB.getTerminator()))
      return;
    origBB.emplace_back(&BB);
  }

  // Nothing to flatten
  if (origBB.size() <= 1)
    return;

  // Remove first BB
  origBB.erase(origBB.begin());

  // Get a pointer on the first BB
  Function::iterator tmp = f->begin();
  BasicBlock *insert = &*tmp;

  // If main begin with an if
  BranchInst *br = nullptr;
  if (isa<BranchInst>(insert->getTerminator()))
    br = cast<BranchInst>(insert->getTerminator());

  BasicBlock *entrySucc = nullptr;
  if ((br && br->isConditional()) ||
      insert->getTerminator()->getNumSuccessors() > 1) {
    BasicBlock::iterator i = insert->end();
    --i;

    if (insert->size() > 1) {
      --i;
    }

    BasicBlock *tmpBB = insert->splitBasicBlock(i, "first");
    origBB.insert(origBB.begin(), tmpBB);
    entrySucc = tmpBB;
  } else if (br && br->isUnconditional()) {
    entrySucc = br->getSuccessor(0);
  }

  // Remove jump
  Instruction *oldTerm = insert->getTerminator();

  // Create switch variable and set as it
  switchVar = new AllocaInst(Type::getInt32Ty(f->getContext()),
                             DL.getAllocaAddrSpace(), "switchVar", oldTerm);
  switchVarAddr =
      new AllocaInst(Type::getInt32Ty(f->getContext())->getPointerTo(),
                     DL.getAllocaAddrSpace(), "", oldTerm);

  // Remove jump
  oldTerm->eraseFromParent();

  unsigned initIdx = 0;
  if (entrySucc) {
    for (unsigned j = 0; j < origBB.size(); j++) {
      if (origBB[j] == entrySucc) {
        initIdx = j;
        break;
      }
    }
  }

  Value *initCase =
      ConstantInt::get(Type::getInt32Ty(f->getContext()),
                       cryptoutils->scramble32(initIdx, scrambling_key));
  IRBuilder<> IRBInit(insert);
  Value *opaqueInitCase = insertOpaqueBarrier(IRBInit, initCase);
  new StoreInst(opaqueInitCase, switchVar, /*isVolatile=*/true, insert);
  new StoreInst(switchVar, switchVarAddr, /*isVolatile=*/true, insert);

  // Create main loop
  loopEntry = BasicBlock::Create(f->getContext(), "loopEntry", f, insert);
  loopEnd = BasicBlock::Create(f->getContext(), "loopEnd", f, insert);

  load = new LoadInst(switchVar->getAllocatedType(), switchVar, "switchVar",
                      /*isVolatile=*/true, loopEntry);

  // Move first BB on top
  insert->moveBefore(loopEntry);
  BranchInst::Create(loopEntry, insert);

  // loopEnd: inject a gratuitous XOR/ADD chain on a stack slot that nets to
  // zero at runtime but forces analysis tools to track an extra data-flow path.
  {
    IRBuilder<> IRBEnd(loopEnd);
    AllocaInst *noiseSlot = new AllocaInst(
        Type::getInt32Ty(f->getContext()), DL.getAllocaAddrSpace(), "fla.noise",
        loopEnd->getParent()->getEntryBlock().getFirstNonPHIOrDbgOrLifetime());
    // Write a constant, then XOR it with itself (result always 0), store back.
    // Volatile prevents the optimizer from seeing through it completely.
    Value *noiseSeed = ConstantInt::get(Type::getInt32Ty(f->getContext()),
                                        cryptoutils->get_uint32_t());
    new StoreInst(noiseSeed, noiseSlot, /*volatile=*/true, loopEnd);
    LoadInst *noiseLoad =
        new LoadInst(Type::getInt32Ty(f->getContext()), noiseSlot, "fla.nld",
                     /*volatile=*/true, loopEnd);
    BinaryOperator::Create(Instruction::Xor, noiseLoad, noiseLoad, "fla.nxr",
                           loopEnd);
  }

  // loopEnd jump to loopEntry
  BranchInst::Create(loopEntry, loopEnd);

  BasicBlock *swDefault =
      BasicBlock::Create(f->getContext(), "switchDefault", f, loopEnd);
  BranchInst::Create(loopEnd, swDefault);

  // Create switch instruction itself with opaque condition
  IRBuilder<> IRBSw(loopEntry);
  Value *opaqueCond = insertOpaqueBarrier(IRBSw, load);
  switchI = SwitchInst::Create(opaqueCond, swDefault, 0, loopEntry);

  // Remove branch jump from 1st BB and make a jump to the while
  f->begin()->getTerminator()->eraseFromParent();

  BranchInst::Create(loopEntry, &*f->begin());

  // Put BB in the switch
  DenseMap<BasicBlock *, ConstantInt *> bbCaseMap;
  unsigned caseIdx = 0;
  for (BasicBlock *i : origBB) {
    // Move the BB inside the switch (only visual, no code logic)
    i->moveBefore(loopEnd);

    // Add case to switch
    ConstantInt *numCase = cast<ConstantInt>(
        ConstantInt::get(switchI->getCondition()->getType(),
                         cryptoutils->scramble32(caseIdx++, scrambling_key)));
    switchI->addCase(numCase, i);
    bbCaseMap[i] = numCase;
  }

  // Recalculate switchVar
  for (BasicBlock *i : origBB) {
    ConstantInt *numCase = nullptr;

    // If it's a non-conditional jump
    if (i->getTerminator()->getNumSuccessors() == 1) {
      BasicBlock *succ = i->getTerminator()->getSuccessor(0);
      numCase = bbCaseMap.lookup(succ);

      if (!numCase) {
        if (succ == insert) {
          numCase = cast<ConstantInt>(ConstantInt::get(
              switchI->getCondition()->getType(),
              cryptoutils->scramble32(initIdx, scrambling_key)));
        }
      }

      if (numCase) {
        Instruction *term = i->getTerminator();
        IRBuilder<> IRB(term);
        Value *opaqueCase = insertOpaqueBarrier(IRB, numCase);
        term->eraseFromParent();
        new StoreInst(opaqueCase,
                      new LoadInst(switchVarAddr->getAllocatedType(),
                                   switchVarAddr, "", /*isVolatile=*/true, i),
                      /*isVolatile=*/true, i);
        BranchInst::Create(loopEnd, i);
      } else {
        // Successor is outside switch — jump directly
        i->getTerminator()->eraseFromParent();
        BranchInst::Create(succ, i);
      }
      continue;
    }

    // If it's a conditional jump
    if (i->getTerminator()->getNumSuccessors() == 2) {
      BasicBlock *succTrue = i->getTerminator()->getSuccessor(0);
      BasicBlock *succFalse = i->getTerminator()->getSuccessor(1);
      ConstantInt *numCaseTrue = bbCaseMap.lookup(succTrue);
      ConstantInt *numCaseFalse = bbCaseMap.lookup(succFalse);

      if (!numCaseTrue && succTrue == insert) {
        numCaseTrue = cast<ConstantInt>(
            ConstantInt::get(switchI->getCondition()->getType(),
                             cryptoutils->scramble32(0, scrambling_key)));
      }
      if (!numCaseFalse && succFalse == insert) {
        numCaseFalse = cast<ConstantInt>(
            ConstantInt::get(switchI->getCondition()->getType(),
                             cryptoutils->scramble32(0, scrambling_key)));
      }

      BranchInst *br = cast<BranchInst>(i->getTerminator());
      Value *cond = br->getCondition();

      if (numCaseTrue && numCaseFalse) {
        Instruction *term = i->getTerminator();
        IRBuilder<> IRB(term);
        // Branchless algebraic mask computation instead of naked SelectInst:
        // cond: i1 -> zext to i32 (0 or 1)
        // mask: 0 - cond (0 or 0xFFFFFFFF)
        // diff: numCaseTrue ^ numCaseFalse
        // nextState = numCaseFalse ^ (mask & diff)
        Type *Ty = numCaseTrue->getType();
        Value *condExt = IRB.CreateZExt(cond, Ty, "fla.c.ext");
        Value *mask =
            IRB.CreateSub(ConstantInt::get(Ty, 0), condExt, "fla.c.mask");
        Value *diff = ConstantInt::get(Ty, numCaseTrue->getValue() ^
                                               numCaseFalse->getValue());
        Value *maskedDiff = IRB.CreateAnd(mask, diff, "fla.c.diff");
        Value *nextState =
            IRB.CreateXor(numCaseFalse, maskedDiff, "fla.c.state");
        Value *opaqueState = insertOpaqueBarrier(IRB, nextState);

        term->eraseFromParent();
        new StoreInst(opaqueState,
                      new LoadInst(switchVarAddr->getAllocatedType(),
                                   switchVarAddr, "", /*isVolatile=*/true, i),
                      /*isVolatile=*/true, i);
        BranchInst::Create(loopEnd, i);
      } else if (numCaseTrue && !numCaseFalse) {
        Instruction *term = i->getTerminator();
        IRBuilder<> IRB(term);
        Value *opaqueCase = insertOpaqueBarrier(IRB, numCaseTrue);
        term->eraseFromParent();
        new StoreInst(opaqueCase,
                      new LoadInst(switchVarAddr->getAllocatedType(),
                                   switchVarAddr, "", /*isVolatile=*/true, i),
                      /*isVolatile=*/true, i);
        BranchInst::Create(loopEnd, succFalse, cond, i);
      } else if (!numCaseTrue && numCaseFalse) {
        Instruction *term = i->getTerminator();
        IRBuilder<> IRB(term);
        Value *opaqueCase = insertOpaqueBarrier(IRB, numCaseFalse);
        term->eraseFromParent();
        new StoreInst(opaqueCase,
                      new LoadInst(switchVarAddr->getAllocatedType(),
                                   switchVarAddr, "", /*isVolatile=*/true, i),
                      /*isVolatile=*/true, i);
        BranchInst::Create(succTrue, loopEnd, cond, i);
      } else {
        i->getTerminator()->eraseFromParent();
        BranchInst::Create(succTrue, succFalse, cond, i);
      }
      continue;
    }
  }
  if (ObfVerbose)
    errs() << "Fixing Stack\n";
  fixStack(f);
  if (ObfVerbose)
    errs() << "Fixed Stack\n";
}
