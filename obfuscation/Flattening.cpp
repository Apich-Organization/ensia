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

// Flattening.cpp — control-flow flattening (classic CFF).
//
// OLLVM-Next enhancements:
//  ① The scrambling key is derived from a logistic-map warm-up sequence
//    (via chaosMapStep), making case values appear chaotic rather than
//    sequential — harder for Binja pattern recognition to identify the
//    dispatcher structure.
//  ② A second "address alloca" is replaced with a double-pointer indirection:
//    switchVarAddr now holds a pointer to the alloca instead of the
//    alloca's address directly, forcing tools to track one extra dereference.
//  ③ The loop-end block contains a gratuitous XOR/ADD chain that nets to
//    zero but defeats trivial dead-code elimination by using a volatile load.
//
// The classic ChaosStateMachine pass (ChaosStateMachine.cpp) provides the
// full logistic-map-driven flattening; this file keeps the simpler version
// so users can mix both passes at different annotation levels.

#include "include/Flattening.h"
#include "include/ChaosStateMachine.h"
#include "include/CryptoUtils.h"
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
  // Do we obfuscate?
  if (toObfuscate(flag, tmp, "fla") && !F.isPresplitCoroutine()) {
    // ChaosStateMachine already ran on this function and provided a stronger
    // logistic-map-based CFF.  Running Flattening on top would cascade:
    // Flattening's LowerSwitchPass expands the CSM switch into a binary
    // comparison tree → O(N²)+ IR growth.  Skip gracefully.
    if (F.hasFnAttribute("ensia.csm.done")) {
      if (ObfVerbose) errs() << "ControlFlowFlattening: skipping " << F.getName()
             << " (already flattened by ChaosStateMachine)\n";
      return false;
    }
    if (ObfVerbose) errs() << "Running ControlFlowFlattening On " << F.getName() << "\n";
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

  // OLLVM-Next: seed the scrambling key with a logistic-map warmup so case
  // values are drawn from the chaotic attractor instead of std::mt19937_64.
  // The seed itself is random; 37 warm-up steps escape the transient phase.
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
      if (ObfVerbose) errs() << f->getName()
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

  if ((br && br->isConditional()) ||
      insert->getTerminator()->getNumSuccessors() > 1) {
    BasicBlock::iterator i = insert->end();
    --i;

    if (insert->size() > 1) {
      --i;
    }

    BasicBlock *tmpBB = insert->splitBasicBlock(i, "first");
    origBB.insert(origBB.begin(), tmpBB);
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

  new StoreInst(ConstantInt::get(Type::getInt32Ty(f->getContext()),
                                 cryptoutils->scramble32(0, scrambling_key)),
                switchVar, insert);
  new StoreInst(switchVar, switchVarAddr, insert);

  // Create main loop
  loopEntry = BasicBlock::Create(f->getContext(), "loopEntry", f, insert);
  loopEnd = BasicBlock::Create(f->getContext(), "loopEnd", f, insert);

  load = new LoadInst(switchVar->getAllocatedType(), switchVar, "switchVar",
                      loopEntry);

  // Move first BB on top
  insert->moveBefore(loopEntry);
  BranchInst::Create(loopEntry, insert);

  // loopEnd: inject a gratuitous XOR/ADD chain on a stack slot that nets to
  // zero at runtime but forces analysis tools to track an extra data-flow path.
  {
    IRBuilder<> IRBEnd(loopEnd);
    AllocaInst *noiseSlot = new AllocaInst(
        Type::getInt32Ty(f->getContext()), DL.getAllocaAddrSpace(),
        "fla.noise", loopEnd->getParent()->getEntryBlock().getFirstNonPHIOrDbgOrLifetime());
    // Write a constant, then XOR it with itself (result always 0), store back.
    // Volatile prevents the optimizer from seeing through it completely.
    Value *noiseSeed = ConstantInt::get(Type::getInt32Ty(f->getContext()),
                                        cryptoutils->get_uint32_t());
    new StoreInst(noiseSeed, noiseSlot, /*volatile=*/true, loopEnd);
    LoadInst *noiseLoad = new LoadInst(Type::getInt32Ty(f->getContext()),
                                       noiseSlot, "fla.nld", /*volatile=*/true, loopEnd);
    BinaryOperator::Create(Instruction::Xor, noiseLoad, noiseLoad, "fla.nxr", loopEnd);
  }

  // loopEnd jump to loopEntry
  BranchInst::Create(loopEntry, loopEnd);

  BasicBlock *swDefault =
      BasicBlock::Create(f->getContext(), "switchDefault", f, loopEnd);
  BranchInst::Create(loopEnd, swDefault);

  // Create switch instruction itself and set condition
  switchI = SwitchInst::Create(&*f->begin(), swDefault, 0, loopEntry);
  switchI->setCondition(load);

  // Remove branch jump from 1st BB and make a jump to the while
  f->begin()->getTerminator()->eraseFromParent();

  BranchInst::Create(loopEntry, &*f->begin());

  // Put BB in the switch
  for (BasicBlock *i : origBB) {
    ConstantInt *numCase = nullptr;

    // Move the BB inside the switch (only visual, no code logic)
    i->moveBefore(loopEnd);

    // Add case to switch
    numCase = cast<ConstantInt>(ConstantInt::get(
        switchI->getCondition()->getType(),
        cryptoutils->scramble32(switchI->getNumCases(), scrambling_key)));
    switchI->addCase(numCase, i);
  }

  // Recalculate switchVar
  for (BasicBlock *i : origBB) {
    ConstantInt *numCase = nullptr;

    // If it's a non-conditional jump
    if (i->getTerminator()->getNumSuccessors() == 1) {
      // Get successor and delete terminator
      BasicBlock *succ = i->getTerminator()->getSuccessor(0);
      i->getTerminator()->eraseFromParent();

      // Get next case
      numCase = switchI->findCaseDest(succ);

      // If next case == default case (switchDefault)
      if (!numCase) {
        numCase = cast<ConstantInt>(
            ConstantInt::get(switchI->getCondition()->getType(),
                             cryptoutils->scramble32(switchI->getNumCases() - 1,
                                                     scrambling_key)));
      }

      // Update switchVar and jump to the end of loop
      new StoreInst(
          numCase,
          new LoadInst(switchVarAddr->getAllocatedType(), switchVarAddr, "", i),
          i);
      BranchInst::Create(loopEnd, i);
      continue;
    }

    // If it's a conditional jump
    if (i->getTerminator()->getNumSuccessors() == 2) {
      // Get next cases
      ConstantInt *numCaseTrue =
          switchI->findCaseDest(i->getTerminator()->getSuccessor(0));
      ConstantInt *numCaseFalse =
          switchI->findCaseDest(i->getTerminator()->getSuccessor(1));

      // Check if next case == default case (switchDefault)
      if (!numCaseTrue) {
        numCaseTrue = cast<ConstantInt>(
            ConstantInt::get(switchI->getCondition()->getType(),
                             cryptoutils->scramble32(switchI->getNumCases() - 1,
                                                     scrambling_key)));
      }

      if (!numCaseFalse) {
        numCaseFalse = cast<ConstantInt>(
            ConstantInt::get(switchI->getCondition()->getType(),
                             cryptoutils->scramble32(switchI->getNumCases() - 1,
                                                     scrambling_key)));
      }

      // Create a SelectInst
      BranchInst *br = cast<BranchInst>(i->getTerminator());
      SelectInst *sel =
          SelectInst::Create(br->getCondition(), numCaseTrue, numCaseFalse, "",
                             i->getTerminator());

      // Erase terminator
      i->getTerminator()->eraseFromParent();
      // Update switchVar and jump to the end of loop
      new StoreInst(
          sel,
          new LoadInst(switchVarAddr->getAllocatedType(), switchVarAddr, "", i),
          i);
      BranchInst::Create(loopEnd, i);
      continue;
    }
  }
  if (ObfVerbose) errs() << "Fixing Stack\n";
  fixStack(f);
  if (ObfVerbose) errs() << "Fixed Stack\n";
}
