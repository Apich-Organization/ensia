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
 
// VectorObfuscation.cpp — Scalar-to-vector SIMD lifting pass.
//
// Strategy
// ────────
// For each eligible instruction on integer/float type, replace it with an
// equivalent computation inside a <LANES × ElemTy> vector:
//
//   Original:  %r = add i32 %a, %b
//
//   Obfuscated (LANES=4, lane K chosen at compile time):
//     %va  = insertelement <4 x i32> poison, %noise0, 0
//     ...   insertelement noise into non-K lanes
//     %va' = insertelement <4 x i32> %va,   %a,      K   ← real operand
//     %vb' = (similarly)
//     %vr  = add <4 x i32> %va', %vb'
//     %r   = extractelement <4 x i32> %vr, K
//
//   For shift ops (Shl/LShr/AShr), the shift-amount vector is broadcast
//   (same value in every lane) to avoid UB from out-of-range lane amounts.
//
//   For ICmp (integer comparisons), the result is lifted to a <N x i1> vector
//   comparison; extraction gives back an i1.
//
//   Optional shuffle noise (vec_shuffle=true):
//     After the vector op, apply a random fixed-permutation shufflevector, then
//     extract from the shuffled lane.  Decompilers that pattern-match
//     "insertelement → op → extractelement" fail on the interleaved shuffle.
//
// Width configuration (-vec_width=N):
//   128 (default) → <4 x i32>, <16 x i8>, <8 x i16>, <2 x i64>
//   256           → <8 x i32>, <32 x i8>, <16 x i16>, <4 x i64>
//   512           → <16 x i32>, <64 x i8>, <32 x i16>, <8 x i64>
//   (Float: <4 x f32>, <2 x f64> at 128-bit; scaled accordingly)
//
// IDA/Binja impact:
//   • Decompilers emit _mm_add_epi32/vcmpeqq wrappers — the "real" op is hidden
//     inside a lane-structured expression the tool never collapses.
//   • Shuffle noise forces SSE/AVX shuffle pattern recognition to fail.
//   • Per-site random lane K and noise constants defeat cross-site correlation.

#include "include/VectorObfuscation.h"
#include "include/CryptoUtils.h"
#include "include/Utils.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include <cstring>  // memcpy for float/double noise
#include <utility>  // std::pair

using namespace llvm;

static cl::opt<uint32_t>
    VecProbRate("vec_prob",
                cl::desc("[VecObf] Probability [%] each eligible instruction "
                         "is vectorized"),
                cl::value_desc("probability"), cl::init(50), cl::Optional);
static uint32_t VecProbRateTemp = 50;

static cl::opt<uint32_t>
    VecWidth("vec_width",
             cl::desc("[VecObf] SIMD width in bits (128, 256, or 512)"),
             cl::value_desc("bits"), cl::init(128), cl::Optional);
static uint32_t VecWidthTemp = 128;

static cl::opt<bool>
    VecShuffle("vec_shuffle",
               cl::desc("[VecObf] Insert a random shufflevector after the "
                        "vector op to defeat lane-extraction pattern matching"),
               cl::init(false), cl::Optional);
static bool VecShuffleTemp = false;

static cl::opt<bool>
    VecICmp("vec_icmp",
            cl::desc("[VecObf] Also lift integer comparison (icmp) instructions "
                     "to vector comparisons"),
            cl::init(true), cl::Optional);
static bool VecICmpTemp = true;

// ─── Width → lane count ───────────────────────────────────────────────────────

static unsigned lanesFor(unsigned elemBits, unsigned totalBits) {
  unsigned lanes = totalBits / elemBits;
  return (lanes < 2) ? 2 : lanes;
}

// ─── Random noise value for a given element type ─────────────────────────────

static Constant *randomNoise(Type *elemTy, unsigned elemBits) {
  if (elemTy->isIntegerTy()) {
    uint64_t v = cryptoutils->get_uint64_t();
    if (elemBits < 64) v &= (1ULL << elemBits) - 1ULL;
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
  unsigned elemBits = elemTy->isIntegerTy()
                          ? elemTy->getIntegerBitWidth()
                          : (elemTy->isFloatTy() ? 32 : 64);
  Type *vecTy = FixedVectorType::get(elemTy, lanes);
  Value *vec = UndefValue::get(vecTy);
  for (unsigned i = 0; i < lanes; i++) {
    Value *elem = (i == K) ? realOp : randomNoise(elemTy, elemBits);
    vec = IRB.CreateInsertElement(vec, elem, (uint64_t)i, "vobf.ins");
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
    vec = IRB.CreateInsertElement(vec, elem, (uint64_t)i, "vobf.bcast");
  return vec;
}

// ─── Apply random shufflevector permutation ───────────────────────────────────
// Returns {shuffled vector, new lane index for the real result}.

static std::pair<Value *, unsigned>
applyShuffleNoise(IRBuilder<NoFolder> &IRB, Value *vec, unsigned K,
                  unsigned lanes) {
  // Build a random bijective permutation of [0, lanes)
  SmallVector<int, 16> perm(lanes);
  for (unsigned i = 0; i < lanes; i++) perm[i] = (int)i;
  for (unsigned i = lanes; i > 1; i--)
    std::swap(perm[i - 1], perm[cryptoutils->get_range(i)]);

  // Find where K ended up in the permuted order (inverse permutation lookup)
  unsigned newK = K;
  for (unsigned i = 0; i < lanes; i++)
    if ((unsigned)perm[i] == K) { newK = i; break; }

  Value *shuffled = IRB.CreateShuffleVector(vec, perm, "vobf.shuf");
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
  unsigned K = cryptoutils->get_range(lanes); // real operand lane

  IRBuilder<NoFolder> IRB(bo);
  Value *a = bo->getOperand(0);
  Value *b = bo->getOperand(1);

  Value *va = buildNoiseVector(IRB, a, K, lanes, scalarTy);
  Value *vb;

  if (isShift) {
    // Broadcast shift amount to all lanes to prevent UB from out-of-range shifts
    // in noise lanes.  The shift itself is performed on all lanes uniformly;
    // only lane K's result is used.
    vb = buildUniformVector(IRB, b, lanes, scalarTy);
  } else {
    vb = buildNoiseVector(IRB, b, K, lanes, scalarTy);
  }

  // Vector operation (same opcode as original scalar)
  Value *vres = IRB.CreateBinOp(
      static_cast<Instruction::BinaryOps>(op), va, vb, "vobf.op");

  // Optional shuffle noise: permute the result vector before extraction
  unsigned extractLane = K;
  if (doShuffle) {
    std::pair<Value *, unsigned> shuf = applyShuffleNoise(IRB, vres, K, lanes);
    vres        = shuf.first;
    extractLane = shuf.second;
  }

  // Extract real result from lane K (or shuffled lane)
  Value *result = IRB.CreateExtractElement(vres, (uint64_t)extractLane,
                                           "vobf.ext");
  bo->replaceAllUsesWith(result);
  return true;
}

// ─── Lift an ICmpInst to a vector comparison ─────────────────────────────────

static bool liftICmpToVector(ICmpInst *ici, unsigned totalBits,
                              bool doShuffle) {
  Type *scalarTy = ici->getOperand(0)->getType();
  if (!scalarTy->isIntegerTy()) return false;
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

  // Vector integer comparison → <N x i1>
  Value *vcmp = IRB.CreateICmp(ici->getPredicate(), va, vb, "vobf.vcmp");

  // Optional shuffle on the i1 vector
  unsigned extractLane = K;
  if (doShuffle) {
    std::pair<Value *, unsigned> shuf = applyShuffleNoise(IRB, vcmp, K, lanes);
    vcmp        = shuf.first;
    extractLane = shuf.second;
  }

  // Extract the i1 result from lane K
  Value *result = IRB.CreateExtractElement(vcmp, (uint64_t)extractLane,
                                           "vobf.cext");
  ici->replaceAllUsesWith(result);
  return true;
}

// ─── FunctionPass ─────────────────────────────────────────────────────────────

namespace {
struct VectorObfuscation : public FunctionPass {
  static char ID;
  bool flag;
  VectorObfuscation() : FunctionPass(ID) { this->flag = true; }
  VectorObfuscation(bool flag) : FunctionPass(ID) { this->flag = flag; }

  bool runOnFunction(Function &F) override {
    if (!toObfuscate(flag, &F, "vobf"))
      return false;

    if (!toObfuscateUint32Option(&F, "vec_prob", &VecProbRateTemp))
      VecProbRateTemp = VecProbRate;
    if (!toObfuscateUint32Option(&F, "vec_width", &VecWidthTemp))
      VecWidthTemp = VecWidth;
    if (!toObfuscateBoolOption(&F, "vec_shuffle", &VecShuffleTemp))
      VecShuffleTemp = VecShuffle;
    if (!toObfuscateBoolOption(&F, "vec_icmp", &VecICmpTemp))
      VecICmpTemp = VecICmp;

    if (ObfuscationMaxMode) {
      VecProbRateTemp = 80;
      VecWidthTemp    = 256;
      VecShuffleTemp  = true;
      VecICmpTemp     = true;
    }

    VecProbRateTemp = std::min(VecProbRateTemp, (uint32_t)100);
    // Normalise width to supported SIMD widths
    if      (VecWidthTemp < 128)  VecWidthTemp = 128;
    else if (VecWidthTemp < 256)  VecWidthTemp = 128;
    else if (VecWidthTemp < 512)  VecWidthTemp = 256;
    else                          VecWidthTemp = 512;

    if (ObfVerbose) errs() << "Running VectorObfuscation On " << F.getName()
           << " (width=" << VecWidthTemp
           << (VecShuffleTemp ? ", shuffle" : "")
           << ")\n";

    // ── Collect eligible instructions ────────────────────────────────────────
    SmallVector<Instruction *, 64> binTargets;
    SmallVector<ICmpInst *, 32>    cmpTargets;

    for (Instruction &I : instructions(F)) {
      if (cryptoutils->get_range(100) >= VecProbRateTemp)
        continue; // skip based on probability

      if (BinaryOperator *BO = dyn_cast<BinaryOperator>(&I)) {
        unsigned op = BO->getOpcode();
        Type *T = BO->getType();
        bool eligible = false;
        // Integer arithmetic + shifts
        if (T->isIntegerTy()) {
          switch (op) {
          case Instruction::Add: case Instruction::Sub:
          case Instruction::Mul: case Instruction::And:
          case Instruction::Or:  case Instruction::Xor:
          case Instruction::Shl: case Instruction::LShr:
          case Instruction::AShr:
            eligible = true; break;
          default: break;
          }
        }
        // Floating-point arithmetic
        if (T->isFloatTy() || T->isDoubleTy()) {
          switch (op) {
          case Instruction::FAdd: case Instruction::FSub:
          case Instruction::FMul:
            eligible = true; break;
          default: break;
          }
        }
        if (eligible)
          binTargets.push_back(BO);

      } else if (VecICmpTemp) {
        if (ICmpInst *ICI = dyn_cast<ICmpInst>(&I)) {
          // Only lift if operand type is a liftable integer width
          if (ICI->getOperand(0)->getType()->isIntegerTy())
            cmpTargets.push_back(ICI);
        }
      }
    }

    // ── Lift and erase ────────────────────────────────────────────────────────
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
