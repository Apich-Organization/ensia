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

#include "include/VectorObfuscation.h"
#include "include/CryptoUtils.h"
#include "include/ObfConfig.h"
#include "include/Utils.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include <cstring> // memcpy for float/double noise
#include <utility> // std::pair

using namespace llvm;

static cl::opt<uint32_t>
    VecProbRate("vec_prob",
                cl::desc("[VecObf] Probability [%] each eligible instruction "
                         "is vectorized"),
                cl::value_desc("probability"), cl::init(50), cl::Optional);
static thread_local uint32_t VecProbRateTemp = 50;

static cl::opt<uint32_t>
    VecWidth("vec_width",
             cl::desc("[VecObf] SIMD width in bits (128, 256, or 512)"),
             cl::value_desc("bits"), cl::init(256), cl::Optional);
static thread_local uint32_t VecWidthTemp = 256;

static cl::opt<bool>
    VecShuffle("vec_shuffle",
               cl::desc("[VecObf] Insert a random shufflevector after the "
                        "vector op to defeat lane-extraction pattern matching"),
               cl::init(false), cl::Optional);
static thread_local bool VecShuffleTemp = false;

static cl::opt<bool> VecICmp(
    "vec_icmp",
    cl::desc("[VecObf] Also lift integer comparison (icmp) instructions "
             "to vector comparisons"),
    cl::init(true), cl::Optional);
static thread_local bool VecICmpTemp = true;

// ─── Width → lane count
// ───────────────────────────────────────────────────────

static unsigned lanesFor(unsigned elemBits, unsigned totalBits) {
  unsigned lanes = totalBits / elemBits;
  return (lanes < 2) ? 2 : lanes;
}

// ─── Random noise value for a given element type ─────────────────────────────

static Constant *randomNoise(Type *elemTy, unsigned elemBits) {
  if (elemTy->isIntegerTy()) {
    uint64_t v = cryptoutils->get_uint64_t();
    if (elemBits < 64)
      v &= (1ULL << elemBits) - 1ULL;
    return ConstantInt::get(elemTy, v);
  }
  if (elemTy->isFloatTy()) {
    // Random bits reinterpreted as float (some will be NaN — that's fine for
    // noise lanes that are never used at runtime)
    uint32_t bits32 = cryptoutils->get_uint32_t();
    float f;
    memcpy(&f, &bits32, 4);
    return ConstantFP::get(elemTy, (double)f);
  }
  if (elemTy->isDoubleTy()) {
    uint64_t bits64 = cryptoutils->get_uint64_t();
    double d;
    memcpy(&d, &bits64, 8);
    return ConstantFP::get(elemTy, d);
  }
  return UndefValue::get(elemTy); // fallback
}

// ─── Build a fully-populated noise vector with realOp at lane K ──────────────

static Value *buildNoiseVector(IRBuilder<NoFolder> &IRB, Value *realOp,
                               unsigned K, unsigned lanes, Type *elemTy) {
  Type *vecTy = FixedVectorType::get(elemTy, lanes);

  if (auto *EEI = dyn_cast<ExtractElementInst>(realOp)) {
    if (auto *vTy = dyn_cast<FixedVectorType>(EEI->getVectorOperandType())) {
      if (vTy->getNumElements() == lanes) {
        if (auto *CIdx = dyn_cast<ConstantInt>(EEI->getIndexOperand())) {
          unsigned srcK = CIdx->getZExtValue();
          SmallVector<int, 16> mask(lanes);
          for (unsigned i = 0; i < lanes; i++)
            mask[i] = i;
          mask[K] = srcK;
          mask[srcK] = K;
          return IRB.CreateShuffleVector(EEI->getVectorOperand(), mask, "");
        }
      }
    }
  }

  unsigned elemBits = elemTy->isIntegerTy() ? elemTy->getIntegerBitWidth()
                                            : (elemTy->isFloatTy() ? 32 : 64);
  Value *vec = UndefValue::get(vecTy);

  Constant *randOffset =
      elemTy->isIntegerTy()
          ? ConstantInt::get(elemTy, cryptoutils->get_uint64_t())
          : nullptr;

  for (unsigned i = 0; i < lanes; i++) {
    Value *elem = realOp;
    if (i != K) {
      if (randOffset) {
        if (i % 2 == 1)
          elem = IRB.CreateAdd(realOp, randOffset);
        else
          elem = IRB.CreateXor(realOp, randOffset);
      } else {
        elem = randomNoise(elemTy, elemBits);
      }
    }
    vec = IRB.CreateInsertElement(vec, elem, (uint64_t)i, "");
  }
  return vec;
}

// ─── Build a uniform vector (same value in every lane) ───────────────────────
// Used for broadcast shift-amounts so no lane sees an out-of-range shift.

static Value *buildUniformVector(IRBuilder<NoFolder> &IRB, Value *elem,
                                 unsigned lanes, Type *elemTy) {
  Type *vecTy = FixedVectorType::get(elemTy, lanes);
  Value *vec = UndefValue::get(vecTy);
  for (unsigned i = 0; i < lanes; i++)
    vec = IRB.CreateInsertElement(vec, elem, (uint64_t)i, "");
  return vec;
}

// ─── Apply random shufflevector permutation
// ─────────────────────────────────── Returns {shuffled vector, new lane index
// for the real result}.

static std::pair<Value *, unsigned> applyShuffleNoise(IRBuilder<NoFolder> &IRB,
                                                      Value *vec, unsigned K,
                                                      unsigned lanes) {
  // Build a random bijective permutation of [0, lanes)
  SmallVector<int, 16> perm(lanes);
  for (unsigned i = 0; i < lanes; i++)
    perm[i] = (int)i;
  for (unsigned i = lanes; i > 1; i--)
    std::swap(perm[i - 1], perm[cryptoutils->get_range(i)]);

  // Find where K ended up in the permuted order (inverse permutation lookup)
  unsigned newK = K;
  for (unsigned i = 0; i < lanes; i++)
    if ((unsigned)perm[i] == K) {
      newK = i;
      break;
    }

  Value *shuffled = IRB.CreateShuffleVector(vec, perm, "");
  return {shuffled, newK};
}

// ─── Lift a scalar BinaryOperator to vector lane K ───────────────────────────

static bool liftBinOpToVector(BinaryOperator *bo, unsigned totalBits,
                              bool doShuffle) {
  Type *scalarTy = bo->getType();
  unsigned op = bo->getOpcode();
  bool isShift = (op == Instruction::Shl || op == Instruction::LShr ||
                  op == Instruction::AShr);

  // Determine element type for vector lifting
  unsigned elemBits = 0;
  if (scalarTy->isIntegerTy()) {
    elemBits = scalarTy->getIntegerBitWidth();
    // Only standard integer widths that map cleanly to SIMD element types
    if (elemBits != 8 && elemBits != 16 && elemBits != 32 && elemBits != 64)
      return false;
  } else if (scalarTy->isFloatTy()) {
    elemBits = 32;
  } else if (scalarTy->isDoubleTy()) {
    elemBits = 64;
  } else {
    return false; // unsupported type
  }

  // Float: only FAdd, FSub, FMul (no float shifts, no float bitwise)
  if (scalarTy->isFloatTy() || scalarTy->isDoubleTy()) {
    if (op != Instruction::FAdd && op != Instruction::FSub &&
        op != Instruction::FMul)
      return false;
  }

  unsigned lanes = lanesFor(elemBits, totalBits);
  unsigned K = cryptoutils->get_range(lanes); // real operand primary lane

  IRBuilder<NoFolder> IRB(bo);
  Value *a = bo->getOperand(0);
  Value *b = bo->getOperand(1);

  auto buildChainedVector = [&](Value *scalarOp,
                                bool isShiftOperand) -> Value * {
    Type *vecTy = FixedVectorType::get(scalarTy, lanes);

    // Attempt to chain from a previous extractelement
    if (!isShiftOperand) {
      if (auto *EEI = dyn_cast<ExtractElementInst>(scalarOp)) {
        if (auto *vTy =
                dyn_cast<FixedVectorType>(EEI->getVectorOperandType())) {
          if (vTy->getNumElements() == lanes) {
            if (auto *CIdx = dyn_cast<ConstantInt>(EEI->getIndexOperand())) {
              unsigned srcK = CIdx->getZExtValue();
              SmallVector<int, 16> mask(lanes);
              for (unsigned i = 0; i < lanes; i++)
                mask[i] = i;
              mask[K] = srcK; // Put the real value into lane K
              mask[srcK] = K; // Swap the junk from lane K into srcK
              // (If srcK == K, this is just an identity mask)
              return IRB.CreateShuffleVector(EEI->getVectorOperand(), mask, "");
            }
          }
        }
      }
    }

    // Fallback: build a new vector with junk lanes derived from the real scalar
    Value *vec = UndefValue::get(vecTy);
    Constant *randOffset =
        scalarTy->isIntegerTy()
            ? ConstantInt::get(scalarTy, cryptoutils->get_uint64_t())
            : nullptr;
    for (unsigned i = 0; i < lanes; i++) {
      Value *elem = scalarOp;
      if (i != K && randOffset && !isShiftOperand) {
        if (i % 2 == 1)
          elem = IRB.CreateAdd(scalarOp, randOffset);
        else
          elem = IRB.CreateXor(scalarOp, randOffset);
      }
      vec = IRB.CreateInsertElement(vec, elem, (uint64_t)i, "");
    }
    return vec;
  };

  Value *va = buildChainedVector(a, false);
  Value *vb = buildChainedVector(b, isShift);

  // Vector operation (same opcode as original scalar)
  Value *vres =
      IRB.CreateBinOp(static_cast<Instruction::BinaryOps>(op), va, vb, "");

  // Optional shuffle noise: permute the result vector before extraction
  unsigned extractLane = K;
  if (doShuffle) {
    std::pair<Value *, unsigned> shuf = applyShuffleNoise(IRB, vres, K, lanes);
    vres = shuf.first;
    extractLane = shuf.second;
  }

  // Extract real result from lane K (or shuffled lane)
  Value *result = IRB.CreateExtractElement(vres, (uint64_t)extractLane, "");
  bo->replaceAllUsesWith(result);
  return true;
}

// ─── Lift an ICmpInst to a vector comparison with bitmask reduction ─────────

static bool liftICmpToVector(ICmpInst *ici, unsigned totalBits,
                             bool doShuffle) {
  Type *scalarTy = ici->getOperand(0)->getType();
  if (!scalarTy->isIntegerTy())
    return false;
  unsigned elemBits = scalarTy->getIntegerBitWidth();
  if (elemBits != 8 && elemBits != 16 && elemBits != 32 && elemBits != 64)
    return false;

  unsigned lanes = lanesFor(elemBits, totalBits);
  unsigned K = cryptoutils->get_range(lanes);

  IRBuilder<NoFolder> IRB(ici);
  Value *a = ici->getOperand(0);
  Value *b = ici->getOperand(1);

  Value *va = buildNoiseVector(IRB, a, K, lanes, scalarTy);
  Value *vb = buildNoiseVector(IRB, b, K, lanes, scalarTy);

  // Vector comparison -> <N x i1>
  Value *vcmp = IRB.CreateICmp(ici->getPredicate(), va, vb, "");

  // Optional shuffle on the i1 vector
  unsigned extractLane = K;
  if (doShuffle) {
    std::pair<Value *, unsigned> shuf = applyShuffleNoise(IRB, vcmp, K, lanes);
    vcmp = shuf.first;
    extractLane = shuf.second;
  }

  // Extract scalar i1 comparison result from the vector
  Value *result = IRB.CreateExtractElement(vcmp, (uint64_t)extractLane, "vobf.cmp");
  ici->replaceAllUsesWith(result);
  return true;
}

// ─── Lift an FCmpInst to a vector comparison ────────────────────────────────
static bool liftFCmpToVector(FCmpInst *fci, unsigned totalBits,
                             bool doShuffle) {
  Type *scalarTy = fci->getOperand(0)->getType();
  if (!scalarTy->isFloatTy() && !scalarTy->isDoubleTy())
    return false;
  unsigned elemBits = scalarTy->isFloatTy() ? 32 : 64;

  unsigned lanes = lanesFor(elemBits, totalBits);
  unsigned K = cryptoutils->get_range(lanes);

  IRBuilder<NoFolder> IRB(fci);
  Value *a = fci->getOperand(0);
  Value *b = fci->getOperand(1);

  Value *va = buildNoiseVector(IRB, a, K, lanes, scalarTy);
  Value *vb = buildNoiseVector(IRB, b, K, lanes, scalarTy);

  Value *vcmp = IRB.CreateFCmp(fci->getPredicate(), va, vb, "vobf.fcmp");

  unsigned extractLane = K;
  if (doShuffle) {
    std::pair<Value *, unsigned> shuf = applyShuffleNoise(IRB, vcmp, K, lanes);
    vcmp = shuf.first;
    extractLane = shuf.second;
  }

  Value *result = IRB.CreateExtractElement(vcmp, (uint64_t)extractLane, "vobf.fcmp");
  fci->replaceAllUsesWith(result);
  return true;
}

// ─── Lift a SelectInst to a vector select ───────────────────────────────────

static bool liftSelectToVector(SelectInst *sel, unsigned totalBits,
                               bool doShuffle) {
  Type *scalarTy = sel->getType();
  if (!scalarTy->isIntegerTy() && !scalarTy->isFloatTy() &&
      !scalarTy->isDoubleTy())
    return false;
  unsigned elemBits = scalarTy->isIntegerTy()
                          ? scalarTy->getIntegerBitWidth()
                          : (scalarTy->isFloatTy() ? 32 : 64);
  if (elemBits != 8 && elemBits != 16 && elemBits != 32 && elemBits != 64)
    return false;

  unsigned lanes = lanesFor(elemBits, totalBits);
  unsigned K = cryptoutils->get_range(lanes);

  IRBuilder<NoFolder> IRB(sel);
  Value *cond = sel->getCondition();
  Value *trueVal = sel->getTrueValue();
  Value *falseVal = sel->getFalseValue();

  Value *vCond =
      buildUniformVector(IRB, cond, lanes, Type::getInt1Ty(sel->getContext()));
  Value *vTrue = buildNoiseVector(IRB, trueVal, K, lanes, scalarTy);
  Value *vFalse = buildNoiseVector(IRB, falseVal, K, lanes, scalarTy);

  Value *vSel = IRB.CreateSelect(vCond, vTrue, vFalse, "");

  unsigned extractLane = K;
  if (doShuffle) {
    std::pair<Value *, unsigned> shuf = applyShuffleNoise(IRB, vSel, K, lanes);
    vSel = shuf.first;
    extractLane = shuf.second;
  }

  Value *result = IRB.CreateExtractElement(vSel, (uint64_t)extractLane, "");
  sel->replaceAllUsesWith(result);
  return true;
}

// ─── Lift a CastInst to a vector cast ───────────────────────────────────────

static bool liftCastToVector(CastInst *ci, unsigned totalBits, bool doShuffle) {
  Type *srcTy = ci->getSrcTy();
  Type *dstTy = ci->getDestTy();
  if (!srcTy->isIntegerTy() || !dstTy->isIntegerTy())
    return false; // only integer casts for now (ZExt, SExt, Trunc)

  unsigned srcBits = srcTy->getIntegerBitWidth();
  unsigned dstBits = dstTy->getIntegerBitWidth();
  if (srcBits != 8 && srcBits != 16 && srcBits != 32 && srcBits != 64)
    return false;
  if (dstBits != 8 && dstBits != 16 && dstBits != 32 && dstBits != 64)
    return false;

  unsigned op = ci->getOpcode();
  if (op != Instruction::ZExt && op != Instruction::SExt &&
      op != Instruction::Trunc)
    return false;

  // We use the wider type to determine lanes, so the vector doesn't exceed
  // totalBits
  unsigned maxBits = std::max(srcBits, dstBits);
  unsigned lanes = lanesFor(maxBits, totalBits);
  unsigned K = cryptoutils->get_range(lanes);

  IRBuilder<NoFolder> IRB(ci);
  Value *srcVal = ci->getOperand(0);

  Value *vSrc = buildNoiseVector(IRB, srcVal, K, lanes, srcTy);
  Type *vDstTy = FixedVectorType::get(dstTy, lanes);

  Value *vCast =
      IRB.CreateCast(static_cast<Instruction::CastOps>(op), vSrc, vDstTy, "");

  unsigned extractLane = K;
  if (doShuffle) {
    std::pair<Value *, unsigned> shuf = applyShuffleNoise(IRB, vCast, K, lanes);
    vCast = shuf.first;
    extractLane = shuf.second;
  }

  Value *result = IRB.CreateExtractElement(vCast, (uint64_t)extractLane, "");
  ci->replaceAllUsesWith(result);
  return true;
}

// ─── FunctionPass
// ─────────────────────────────────────────────────────────────

namespace {
struct VectorObfuscation : public FunctionPass {
  static char ID;
  bool flag;
  VectorObfuscation() : FunctionPass(ID) { this->flag = true; }
  VectorObfuscation(bool flag) : FunctionPass(ID) { this->flag = flag; }

  bool runOnFunction(Function &F) override {
    if (!toObfuscate(flag, &F, "vobf"))
      return false;

    {
      auto ec =
          GObfConfig.resolve(F.getParent()->getSourceFileName(), F.getName());
      if (!toObfuscateUint32Option(&F, "vec_prob", &VecProbRateTemp))
        VecProbRateTemp = ec.vec.probability.value_or((uint32_t)VecProbRate);
      if (!toObfuscateUint32Option(&F, "vec_width", &VecWidthTemp))
        VecWidthTemp = ec.vec.width.value_or((uint32_t)VecWidth);
      if (!toObfuscateBoolOption(&F, "vec_shuffle", &VecShuffleTemp))
        VecShuffleTemp = ec.vec.shuffle.value_or((bool)VecShuffle);
      if (!toObfuscateBoolOption(&F, "vec_icmp", &VecICmpTemp))
        VecICmpTemp = ec.vec.lift_comparisons.value_or((bool)VecICmp);
    }

    if (ObfuscationMaxMode) {
      VecProbRateTemp = 80;
      VecWidthTemp = 256;
      VecShuffleTemp = true;
      VecICmpTemp = true;
    }

    VecProbRateTemp = std::min(VecProbRateTemp, (uint32_t)100);
    // Normalise width to supported SIMD widths
    if (VecWidthTemp < 128)
      VecWidthTemp = 128;
    else if (VecWidthTemp < 256)
      VecWidthTemp = 128;
    else if (VecWidthTemp < 512)
      VecWidthTemp = 256;
    else
      VecWidthTemp = 512;

    if (ObfVerbose)
      errs() << "Running VectorObfuscation On " << F.getName()
             << " (width=" << VecWidthTemp
             << (VecShuffleTemp ? ", shuffle" : "") << ")\n";

    SmallVector<Instruction *, 64> binTargets;
    SmallVector<ICmpInst *, 32> cmpTargets;
    SmallVector<FCmpInst *, 32> fcmpTargets;
    SmallVector<SelectInst *, 32> selTargets;
    SmallVector<CastInst *, 32> castTargets;

    uint32_t eligible = 0;
    for (Instruction &I : instructions(F)) {
      if (dyn_cast<BinaryOperator>(&I)) {
        eligible++;
      } else if (VecICmpTemp && dyn_cast<ICmpInst>(&I)) {
        eligible++;
      } else if (VecICmpTemp && dyn_cast<FCmpInst>(&I)) {
        eligible++;
      } else if (dyn_cast<SelectInst>(&I)) {
        eligible++;
      } else if (CastInst *CI = dyn_cast<CastInst>(&I)) {
        if (CI->getOpcode() == Instruction::ZExt ||
            CI->getOpcode() == Instruction::SExt ||
            CI->getOpcode() == Instruction::Trunc)
          eligible++;
      }
    }

    uint32_t currentProb = VecProbRateTemp;
    uint32_t maxTargets = 10000;
    if (eligible * currentProb / 100 > maxTargets) {
      currentProb = (maxTargets * 100) / eligible;
      if (currentProb == 0)
        currentProb = 1;
    }

    for (Instruction &I : instructions(F)) {
      if (cryptoutils->get_range(100) >= currentProb)
        continue; // skip based on probability

      if (BinaryOperator *BO = dyn_cast<BinaryOperator>(&I)) {
        unsigned op = BO->getOpcode();
        Type *T = BO->getType();
        bool eligible = false;
        // Integer arithmetic + shifts
        if (T->isIntegerTy()) {
          switch (op) {
          case Instruction::Add:
          case Instruction::Sub:
          case Instruction::Mul:
          case Instruction::And:
          case Instruction::Or:
          case Instruction::Xor:
          case Instruction::Shl:
          case Instruction::LShr:
          case Instruction::AShr:
            eligible = true;
            break;
          default:
            break;
          }
        }
        // Floating-point arithmetic
        if (T->isFloatTy() || T->isDoubleTy()) {
          switch (op) {
          case Instruction::FAdd:
          case Instruction::FSub:
          case Instruction::FMul:
            eligible = true;
            break;
          default:
            break;
          }
        }
        if (eligible)
          binTargets.push_back(BO);

      } else if (VecICmpTemp && dyn_cast<ICmpInst>(&I)) {
        if (ICmpInst *ICI = dyn_cast<ICmpInst>(&I)) {
          // Only lift if operand type is a liftable integer width
          if (ICI->getOperand(0)->getType()->isIntegerTy())
            cmpTargets.push_back(ICI);
        }
      } else if (VecICmpTemp && dyn_cast<FCmpInst>(&I)) {
        if (FCmpInst *FCI = dyn_cast<FCmpInst>(&I)) {
          fcmpTargets.push_back(FCI);
        }
      } else if (SelectInst *SI = dyn_cast<SelectInst>(&I)) {
        selTargets.push_back(SI);
      } else if (CastInst *CI = dyn_cast<CastInst>(&I)) {
        if (CI->getOpcode() == Instruction::ZExt ||
            CI->getOpcode() == Instruction::SExt ||
            CI->getOpcode() == Instruction::Trunc)
          castTargets.push_back(CI);
      }
    }

    // ── Lift and erase
    // ────────────────────────────────────────────────────────
    bool changed = false;
    SmallVector<Instruction *, 64> toErase;

    for (Instruction *I : binTargets) {
      if (BinaryOperator *BO = dyn_cast<BinaryOperator>(I))
        if (liftBinOpToVector(BO, VecWidthTemp, VecShuffleTemp)) {
          toErase.push_back(BO);
          changed = true;
        }
    }
    for (ICmpInst *ICI : cmpTargets) {
      if (liftICmpToVector(ICI, VecWidthTemp, VecShuffleTemp)) {
        toErase.push_back(ICI);
        changed = true;
      }
    }
    for (FCmpInst *FCI : fcmpTargets) {
      if (liftFCmpToVector(FCI, VecWidthTemp, VecShuffleTemp)) {
        toErase.push_back(FCI);
        changed = true;
      }
    }
    for (SelectInst *SI : selTargets) {
      if (liftSelectToVector(SI, VecWidthTemp, VecShuffleTemp)) {
        toErase.push_back(SI);
        changed = true;
      }
    }
    for (CastInst *CI : castTargets) {
      if (liftCastToVector(CI, VecWidthTemp, VecShuffleTemp)) {
        toErase.push_back(CI);
        changed = true;
      }
    }
    for (Instruction *I : toErase)
      I->eraseFromParent();

    return changed;
  }
};
} // anonymous namespace

char VectorObfuscation::ID = 0;
INITIALIZE_PASS(VectorObfuscation, "vobf",
                "Enable SIMD Vector-Space Obfuscation.", false, false)

FunctionPass *llvm::createVectorObfuscationPass(bool flag) {
  return new VectorObfuscation(flag);
}
