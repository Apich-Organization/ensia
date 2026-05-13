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
static uint32_t ObfTimesTemp = 1;

static cl::opt<uint32_t>
    ObfProbRate("sub_prob",
                cl::desc("Choose the probability [%] each instructions will be "
                         "obfuscated by the InstructionSubstitution pass"),
                cl::value_desc("probability rate"), cl::init(50), cl::Optional);
static uint32_t ObfProbRateTemp = 50;

// Stats
STATISTIC(Add,  "Add substituted");
STATISTIC(Sub,  "Sub substituted");
STATISTIC(Mul,  "Mul substituted");
STATISTIC(Shl,  "Shl substituted");
STATISTIC(LShr, "LShr substituted");
STATISTIC(AShr, "AShr substituted");
STATISTIC(And,  "And substituted");
STATISTIC(Or,   "Or substituted");
STATISTIC(Xor,  "Xor substituted");

namespace {

struct Substitution : public FunctionPass {
  static char ID; // Pass identification, replacement for typeid
  bool flag;
  Substitution(bool flag) : Substitution() { this->flag = flag; }
  Substitution() : FunctionPass(ID) { this->flag = true; }

  bool runOnFunction(Function &F) override {
    if (!toObfuscateUint32Option(&F, "sub_loop", &ObfTimesTemp))
      ObfTimesTemp = ObfTimes;
    if (!toObfuscateUint32Option(&F, "sub_prob", &ObfProbRateTemp))
      ObfProbRateTemp = ObfProbRate;

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
      if (ObfVerbose) errs() << "Running Instruction Substitution On " << F.getName() << "\n";
      substitute(tmp);
      return true;
    }

    return false;
  };
  bool substitute(Function *f) {
    // Loop for the number of time we run the pass on the function
    uint32_t times = ObfTimesTemp;
    do {
      uint32_t eligible = 0;
      for (Instruction &inst : instructions(f))
        if (inst.isBinaryOp() && inst.getType()->isIntegerTy())
          eligible++;

      if (eligible == 0) break;

      uint32_t currentProb = ObfProbRateTemp;
      uint32_t maxTargets = 10000;
      if (eligible * currentProb / 100 > maxTargets) {
        currentProb = (maxTargets * 100) / eligible;
        if (currentProb == 0) currentProb = 1;
      }

      SmallVector<Instruction *, 32> toErase;
      for (Instruction &inst : instructions(f))
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
          // FAdd/FSub/FMul operate over IEEE-754 reals, not Z/2^n.  The
          // integer MBA identities in SubstituteImpl are bitwise ring
          // operations and do not have floating-point equivalents.
          // Substituting FP ops would change rounding behaviour and violate
          // IEEE semantics, so they are intentionally excluded.
          case BinaryOperator::FAdd:
          case BinaryOperator::FSub:
          case BinaryOperator::FMul:
          case BinaryOperator::FDiv:
          case BinaryOperator::FRem:
            break;

          // ── Integer division/remainder: NOT substituted ─────────────────
          // UDiv/SDiv/URem/SRem: strength-reduction and LLVM mid-end passes
          // are very aggressive at inverting division rewrites.  SDiv also
          // has edge cases (INT_MIN / -1 = INT_MIN in LLVM semantics) that
          // make correctness-preserving substitution fragile.
          case BinaryOperator::UDiv:
          case BinaryOperator::SDiv:
          case BinaryOperator::URem:
          case BinaryOperator::SRem:
            break;

          // ── Shift operations ────────────────────────────────────────────
          // Only constant-shift-amount forms are substituted (verified safe).
          // Variable shifts are passed through unchanged by the substituteXxx
          // implementations themselves.
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
            // XOR distributes over AShr (sign extension is XOR-linear):
            //   (a ^ r) >>s k ^ (r >>s k) == a >>s k   for all a, r, k.
            // Only constant-k forms are handled; variable k falls through.
            SubstituteImpl::substituteAShr(cast<BinaryOperator>(&inst));
            toErase.push_back(&inst);
            ++AShr;
            break;

          // ── Bitwise ─────────────────────────────────────────────────────
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
      for (Instruction *I : toErase) {
        if (I->getNumUses() == 0)
          I->eraseFromParent();
      }
    } while (--times); // for times
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
