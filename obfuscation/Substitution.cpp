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

#include "include/Substitution.h"
#include "include/CryptoUtils.h"
#include "include/ObfConfig.h"
#include "include/SubstituteImpl.h"
#include "include/Utils.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/Support/CommandLine.h"

using namespace llvm;

#define DEBUG_TYPE "substitution"

static cl::opt<uint32_t>
    ObfTimes("sub_loop",
             cl::desc("Choose how many time the -sub pass loops on a function"),
             cl::value_desc("number of times"), cl::init(1), cl::Optional);
static thread_local uint32_t ObfTimesTemp = 1;

static cl::opt<uint32_t>
    ObfProbRate("sub_prob",
                cl::desc("Choose the probability [%] each instructions will be "
                         "obfuscated by the InstructionSubstitution pass"),
                cl::value_desc("probability rate"), cl::init(50), cl::Optional);
static thread_local uint32_t ObfProbRateTemp = 50;

// Stats
STATISTIC(Add, "Add substituted");
STATISTIC(Sub, "Sub substituted");
STATISTIC(Mul, "Mul substituted");
STATISTIC(Shl, "Shl substituted");
STATISTIC(LShr, "LShr substituted");
STATISTIC(AShr, "AShr substituted");
STATISTIC(And, "And substituted");
STATISTIC(Or, "Or substituted");
STATISTIC(Xor, "Xor substituted");

namespace {

struct Substitution : public FunctionPass {
  static char ID; // Pass identification, replacement for typeid
  bool flag;
  Substitution(bool flag) : Substitution() { this->flag = flag; }
  Substitution() : FunctionPass(ID) { this->flag = true; }

  bool runOnFunction(Function &F) override {
    if (!toObfuscateUint32Option(&F, "sub_loop", &ObfTimesTemp)) {
      auto ec =
          GObfConfig.resolve(F.getParent()->getSourceFileName(), F.getName());
      ObfTimesTemp = ec.sub.iterations.value_or((uint32_t)ObfTimes);
    }
    if (!toObfuscateUint32Option(&F, "sub_prob", &ObfProbRateTemp)) {
      auto ec =
          GObfConfig.resolve(F.getParent()->getSourceFileName(), F.getName());
      ObfProbRateTemp = ec.sub.probability.value_or((uint32_t)ObfProbRate);
    }

    // Check if the percentage is correct
    if (ObfTimesTemp <= 0) {
      errs() << "Substitution application number -sub_loop=x must be x > 0";
      return false;
    }
    if (ObfProbRateTemp > 100) {
      errs() << "InstructionSubstitution application instruction percentage "
                "-sub_prob=x must be 0 < x <= 100";
      return false;
    }

    Function *tmp = &F;
    // Do we obfuscate
    if (toObfuscate(flag, tmp, "sub")) {
      if (ObfVerbose)
        errs() << "Running Instruction Substitution On " << F.getName() << "\n";
      substitute(tmp);
      return true;
    }

    return false;
  };
  bool substitute(Function *f) {
    // Loop for the number of time we run the pass on the function
    uint32_t times = ObfTimesTemp;
    DenseSet<Instruction *> existing;
    for (Instruction &inst : instructions(f))
      existing.insert(&inst);

    do {
      uint32_t eligible = 0;
      for (Instruction &inst : instructions(f)) {
        if (isSynthetic(&inst) || !existing.count(&inst))
          continue;
        if (inst.isBinaryOp() && inst.getType()->isIntegerTy())
          eligible++;
      }

      if (eligible == 0)
        break;

      uint32_t currentProb = ObfProbRateTemp;
      uint32_t maxTargets = 10000;
      if (eligible * currentProb / 100 > maxTargets) {
        currentProb = (maxTargets * 100) / eligible;
        if (currentProb == 0)
          currentProb = 1;
      }

      SmallVector<Instruction *, 32> toErase;
      for (Instruction &inst : instructions(f)) {
        if (isSynthetic(&inst) || !existing.count(&inst))
          continue;
        if (inst.isBinaryOp() && inst.getType()->isIntegerTy() &&
            cryptoutils->get_range(100) <= currentProb) {
          switch (inst.getOpcode()) {
          // ── Integer arithmetic ──────────────────────────────────────────
          case BinaryOperator::Add:
            SubstituteImpl::substituteAdd(cast<BinaryOperator>(&inst));
            toErase.push_back(&inst);
            ++Add;
            break;
          case BinaryOperator::Sub:
            SubstituteImpl::substituteSub(cast<BinaryOperator>(&inst));
            toErase.push_back(&inst);
            ++Sub;
            break;
          case BinaryOperator::Mul:
            SubstituteImpl::substituteMul(cast<BinaryOperator>(&inst));
            toErase.push_back(&inst);
            ++Mul;
            break;

          // ── Float arithmetic: NOT substituted ───────────────────────────
          case BinaryOperator::FAdd:
          case BinaryOperator::FSub:
          case BinaryOperator::FMul:
          case BinaryOperator::FDiv:
          case BinaryOperator::FRem:
            break;

          // ── Integer division/remainder: NOT substituted ─────────────────
          case BinaryOperator::UDiv:
          case BinaryOperator::SDiv:
          case BinaryOperator::URem:
          case BinaryOperator::SRem:
            break;

          // ── Shift operations ────────────────────────────────────────────
          case Instruction::Shl:
            SubstituteImpl::substituteShl(cast<BinaryOperator>(&inst));
            toErase.push_back(&inst);
            ++Shl;
            break;
          case Instruction::LShr:
            SubstituteImpl::substituteLShr(cast<BinaryOperator>(&inst));
            toErase.push_back(&inst);
            ++LShr;
            break;
          case Instruction::AShr:
            SubstituteImpl::substituteAShr(cast<BinaryOperator>(&inst));
            toErase.push_back(&inst);
            ++AShr;
            break;

          // ── Bitwise logical ─────────────────────────────────────────────
          case Instruction::And:
            SubstituteImpl::substituteAnd(cast<BinaryOperator>(&inst));
            toErase.push_back(&inst);
            ++And;
            break;
          case Instruction::Or:
            SubstituteImpl::substituteOr(cast<BinaryOperator>(&inst));
            toErase.push_back(&inst);
            ++Or;
            break;
          case Instruction::Xor:
            SubstituteImpl::substituteXor(cast<BinaryOperator>(&inst));
            toErase.push_back(&inst);
            ++Xor;
            break;

          default:
            break;
          } // End switch
        } // End isBinaryOp
      } // End for
      for (Instruction *I : toErase) {
        if (I->getNumUses() == 0)
          I->eraseFromParent();
      }
    } while (--times); // for times

    // Tag all newly created instructions so other passes do not compound on them
    for (Instruction &inst : instructions(f)) {
      if (!existing.count(&inst))
        tagSynthetic(&inst);
    }
    return true;
  }
};
} // namespace

char Substitution::ID = 0;
INITIALIZE_PASS(Substitution, "subobf", "Enable Instruction Substitution.",
                false, false)
FunctionPass *llvm::createSubstitutionPass(bool flag) {
  return new Substitution(flag);
}
