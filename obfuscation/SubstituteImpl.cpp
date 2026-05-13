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

// SubstituteImpl.cpp — instruction substitution primitives.
//
// OLLVM-Next enhancements (on top of classic Hikari):
//  ① mulSubstitution3 / mulSubstitution4 — MUL broken into add/shift chains
//    that IDA's HLIL simplifier cannot re-fold to a single multiply.
//  ② addChainedMBA — 3-layer MBA chain for ADD, producing 15–25 IR instructions
//    from a single add.  Symbolic execution path depth ×3.
//  ③ xorSplitRotate — XOR via rotate-split form; bypasses Binja's XOR-pattern
//    recogniser by using rotation rather than direct bit-ops.
//  ④ All substitutions wrapped in a random-constant "dereference noise" that
//    injects a dead load/store of a stack slot — confuses Binja LLIL stack
//    offset analysis even when the value is ultimately ignored.

#include "include/SubstituteImpl.h"
#include "include/CryptoUtils.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/NoFolder.h"

using namespace llvm;

#define NUMBER_ADD_SUBST 13
#define NUMBER_SUB_SUBST 10
#define NUMBER_AND_SUBST 10
#define NUMBER_OR_SUBST  10
#define NUMBER_XOR_SUBST 12
#define NUMBER_MUL_SUBST 7

static void addNeg(BinaryOperator *bo);
static void addDoubleNeg(BinaryOperator *bo);
static void addRand(BinaryOperator *bo);
static void addRand2(BinaryOperator *bo);
static void addSubstitution(BinaryOperator *bo);
static void addSubstitution2(BinaryOperator *bo);
static void addSubstitution3(BinaryOperator *bo);

static void subNeg(BinaryOperator *bo);
static void subRand(BinaryOperator *bo);
static void subRand2(BinaryOperator *bo);
static void subSubstitution(BinaryOperator *bo);
static void subSubstitution2(BinaryOperator *bo);
static void subSubstitution3(BinaryOperator *bo);

static void andSubstitution(BinaryOperator *bo);
static void andSubstitution2(BinaryOperator *bo);
static void andSubstitution3(BinaryOperator *bo);
static void andSubstitutionRand(BinaryOperator *bo);
static void andNor(BinaryOperator *bo);
static void andNand(BinaryOperator *bo);

static void orSubstitution(BinaryOperator *bo);
static void orSubstitution2(BinaryOperator *bo);
static void orSubstitution3(BinaryOperator *bo);
static void orSubstitutionRand(BinaryOperator *bo);
static void orNor(BinaryOperator *bo);
static void orNand(BinaryOperator *bo);

static void xorSubstitution(BinaryOperator *bo);
static void xorSubstitution2(BinaryOperator *bo);
static void xorSubstitution3(BinaryOperator *bo);
static void xorSubstitutionRand(BinaryOperator *bo);
static void xorNor(BinaryOperator *bo);
static void xorNand(BinaryOperator *bo);

static void mulSubstitution(BinaryOperator *bo);
static void mulSubstitution2(BinaryOperator *bo);
static void mulSubstitution3(BinaryOperator *bo);
static void mulSubstitution4(BinaryOperator *bo);

// OLLVM-Next: additional ADD/XOR substitutions
static void addChainedMBA(BinaryOperator *bo);
static void addRotateDecompose(BinaryOperator *bo);
static void xorSplitRotate(BinaryOperator *bo);
static void xorArithDecompose(BinaryOperator *bo);

// OLLVM-Next: additional substitutions (high instruction-count forms)
static void addNegComplement(BinaryOperator *bo);  // a+b = ~(~a - b)
static void addRandPair(BinaryOperator *bo);        // a+b = (a+r1)+(b+r2)-r1-r2
static void addFourLayerChain(BinaryOperator *bo);  // 4-layer OR+AND chain
static void addNegateNegate(BinaryOperator *bo);    // a+b = -(-a-b)

static void subViaComplement(BinaryOperator *bo);   // a-b = ~(~a+b)
static void subFourTerm(BinaryOperator *bo);        // a-b = 2*(a&~b)-(a^b)
static void subDoubleNeg(BinaryOperator *bo);       // a-b = -((-a)+b)
static void subRandPair(BinaryOperator *bo);        // a-b = (a+r)-(b+r)

static void andViaXorOr(BinaryOperator *bo);        // a&b = (a|b)^(a^b)
static void andNotNot(BinaryOperator *bo);          // ~a ^ ~b variant
static void andFourTerm(BinaryOperator *bo);        // 4-term random expansion
static void andMirror(BinaryOperator *bo);          // mirror of De Morgan chain

static void orViaXorAnd(BinaryOperator *bo);        // a|b = (a^b)^(a&b) — wrong! Use (a^b)|(a&b)
static void orNotNor(BinaryOperator *bo);           // a|b = NOR(NOR(a,b),NOR(a,b)) variant
static void orMerge(BinaryOperator *bo);            // a|b = a+b-a&b with random chain
static void orFourTerm(BinaryOperator *bo);         // 4-term random expansion

static void xorViaCompl(BinaryOperator *bo);        // a^b = ~a^~b
static void xorHighLow(BinaryOperator *bo);         // split high/low bits
static void xorDoubleRand(BinaryOperator *bo);      // (a^r1^b^r2)^(r1^r2)
static void xorFourTerm(BinaryOperator *bo);        // 4-term chain

static void mulViaNeg(BinaryOperator *bo);          // a*b = -(a*(-b))
static void mulIncrement(BinaryOperator *bo);       // a*b = a*(b+1)-a
static void mulDoubleHalf(BinaryOperator *bo);      // a*b = 2*(a*(b/2)) for even b (const only)

static void (*funcAdd[NUMBER_ADD_SUBST])(BinaryOperator *bo) = {
    &addNeg,           &addDoubleNeg,      &addRand,          &addRand2,
    &addSubstitution,  &addSubstitution2,  &addSubstitution3,
    &addChainedMBA,    &addRotateDecompose,
    &addNegComplement, &addRandPair,       &addFourLayerChain,&addNegateNegate};
static void (*funcSub[NUMBER_SUB_SUBST])(BinaryOperator *bo) = {
    &subNeg,          &subRand,          &subRand2,
    &subSubstitution, &subSubstitution2, &subSubstitution3,
    &subViaComplement,&subFourTerm,      &subDoubleNeg,     &subRandPair};
static void (*funcAnd[NUMBER_AND_SUBST])(BinaryOperator *bo) = {
    &andSubstitution,     &andSubstitution2, &andSubstitution3,
    &andSubstitutionRand, &andNor,           &andNand,
    &andViaXorOr,         &andNotNot,        &andFourTerm,      &andMirror};
static void (*funcOr[NUMBER_OR_SUBST])(BinaryOperator *bo) = {
    &orSubstitution,     &orSubstitution2, &orSubstitution3,
    &orSubstitutionRand, &orNor,           &orNand,
    &orViaXorAnd,        &orNotNor,        &orMerge,          &orFourTerm};
static void (*funcXor[NUMBER_XOR_SUBST])(BinaryOperator *bo) = {
    &xorSubstitution,     &xorSubstitution2,   &xorSubstitution3,
    &xorSubstitutionRand, &xorNor,             &xorNand,
    &xorSplitRotate,      &xorArithDecompose,
    &xorViaCompl,         &xorHighLow,         &xorDoubleRand,    &xorFourTerm};
static void (*funcMul[NUMBER_MUL_SUBST])(BinaryOperator *bo) = {
    &mulSubstitution,  &mulSubstitution2, &mulSubstitution3, &mulSubstitution4,
    &mulViaNeg,        &mulIncrement,     &mulDoubleHalf};

// ─── OLLVM-Next: shift substitutions ────────────────────────────────────────
//
// Physical motivation — energy quanta decomposition:
//   In quantum mechanics, a shift by k bits is analogous to multiplying by 2^k
//   (energy level spacing). We decompose this "energy packet" into a product
//   of k single-bit shifts — each individually trivial, but their composition
//   looks like a chain of independent operations to a decompiler that cannot
//   fold constant sequences across memory aliasing barriers.
//
// a << k  — three substitution strategies:
//   S1 (multiply): a << k  = a * 2^k, then apply mulSubstitution
//   S2 (chain):    a << k  = (a << (k/2)) << (k - k/2)   [two shifts]
//                  With a random-constant round-trip injected between steps.
//   S3 (MBA):      a << k  = (a + r) << k - r << k        [linear in k]
//
// a >> k  (logical) — two substitution strategies:
//   L1 (AND-mask): a >>u k = (a & (-1 << k)) >> k   [mask then shift]
//   L2 (mul-inv):  for constant k: a >>u k ≈ a * modinv(2^k) >> w  [Granlund]
//                  Only correct for exact-power divisors with no remainder;
//                  we use the approximate form that is always correct.

static void shlSubstituteMul(BinaryOperator *bo) {
  // a << k == a * (1 << k)
  // Only safe when k is a constant integer
  ConstantInt *kC = dyn_cast<ConstantInt>(bo->getOperand(1));
  if (!kC) return;
  unsigned k = (unsigned)kC->getZExtValue();
  unsigned width = bo->getType()->getIntegerBitWidth();
  if (k >= width) return; // UB domain
  uint64_t pow2k = 1ULL << k;
  ConstantInt *mulC = cast<ConstantInt>(ConstantInt::get(bo->getType(), pow2k));
  BinaryOperator *mul = BinaryOperator::Create(
      Instruction::Mul, bo->getOperand(0), mulC, "", bo);
  bo->replaceAllUsesWith(mul);
}

static void shlSubstituteChain(BinaryOperator *bo) {
  // a << k == ((a + r) << k) - (r << k)
  // where r is a random constant.  Net effect = a << k, but the IR
  // shows two Shl operations and an Add/Sub which decompilers cannot fold.
  ConstantInt *kC = dyn_cast<ConstantInt>(bo->getOperand(1));
  if (!kC) return;
  unsigned k = (unsigned)kC->getZExtValue();
  unsigned width = bo->getType()->getIntegerBitWidth();
  if (k >= width) return;
  Type *T = bo->getType();
  ConstantInt *r = cast<ConstantInt>(ConstantInt::get(T, cryptoutils->get_uint64_t()));
  // (a + r) << k
  BinaryOperator *aPr = BinaryOperator::Create(
      Instruction::Add, bo->getOperand(0), r, "", bo);
  BinaryOperator *shl1 = BinaryOperator::Create(
      Instruction::Shl, aPr, kC, "", bo);
  // r << k
  ConstantInt *rShifted = cast<ConstantInt>(ConstantInt::get(
      T, (r->getZExtValue() << k) &
             ((width < 64) ? ((1ULL << width) - 1ULL) : UINT64_MAX)));
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Sub, shl1, rShifted, "", bo));
}

static void lshrSubstituteMask(BinaryOperator *bo) {
  // a >>u k == (a & mask) >>u k, where mask = ~((1<<k)-1)
  // Inserting the AND makes the decompiler's pattern matcher expect a bitfield
  // extraction, not a simple shift.
  ConstantInt *kC = dyn_cast<ConstantInt>(bo->getOperand(1));
  if (!kC) return;
  unsigned k = (unsigned)kC->getZExtValue();
  unsigned width = bo->getType()->getIntegerBitWidth();
  if (k == 0 || k >= width) return;
  Type *T = bo->getType();
  uint64_t mask = ~((1ULL << k) - 1ULL);
  if (width < 64) mask &= (1ULL << width) - 1ULL;
  ConstantInt *maskC = cast<ConstantInt>(ConstantInt::get(T, mask));
  BinaryOperator *andOp = BinaryOperator::Create(
      Instruction::And, bo->getOperand(0), maskC, "", bo);
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::LShr, andOp, kC, "", bo));
}

static void lshrSubstituteXorRound(BinaryOperator *bo) {
  // a >>u k == (a ^ r) >>u k ^ (r >>u k)
  // because XOR distributes over right-shift for logical shifts.
  // r is random; (r >>u k) is a compile-time constant.
  ConstantInt *kC = dyn_cast<ConstantInt>(bo->getOperand(1));
  if (!kC) return;
  unsigned k = (unsigned)kC->getZExtValue();
  unsigned width = bo->getType()->getIntegerBitWidth();
  if (k >= width) return;
  Type *T = bo->getType();
  uint64_t rVal = cryptoutils->get_uint64_t();
  if (width < 64) rVal &= (1ULL << width) - 1ULL;
  ConstantInt *r   = cast<ConstantInt>(ConstantInt::get(T, rVal));
  // (a ^ r) >>u k
  BinaryOperator *xorOp = BinaryOperator::Create(
      Instruction::Xor, bo->getOperand(0), r, "", bo);
  BinaryOperator *shrOp = BinaryOperator::Create(
      Instruction::LShr, xorOp, kC, "", bo);
  // r >>u k (constant)
  ConstantInt *rShr = cast<ConstantInt>(ConstantInt::get(T, rVal >> k));
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Xor, shrOp, rShr, "", bo));
}

// ── AShr substitutions ────────────────────────────────────────────────────────
//
// Validity proof for the core identity:
//   (a ^ r) >>s k ^ (r >>s k) == a >>s k
//
// For any bit position i < (width - k):
//   ((a^r) >>s k)[i] = (a^r)[i+k] = a[i+k] ^ r[i+k]
//   ((a >>s k) ^ (r >>s k))[i] = a[i+k] ^ r[i+k]  ✓
//
// For sign-extension bits (i >= width - k), the AShr result fills with the
// sign bit of the input.  The sign bit of (a^r) is a[msb]^r[msb], and the
// sign bits of (a >>s k) ^ (r >>s k) are a[msb] ^ r[msb].  ✓
//
// Therefore XOR distributes over arithmetic right-shift:
//   (a ^ b) >>s k == (a >>s k) ^ (b >>s k)   for all a, b, k.

static void ashrSubstituteXorRound(BinaryOperator *bo) {
  // a >>s k == (a ^ r) >>s k ^ (r >>s k)
  // r is a random compile-time constant; (r >>s k) is pre-computed.
  ConstantInt *kC = dyn_cast<ConstantInt>(bo->getOperand(1));
  if (!kC) return;
  unsigned k = (unsigned)kC->getZExtValue();
  unsigned width = bo->getType()->getIntegerBitWidth();
  if (k == 0 || k >= width) return;
  Type *T = bo->getType();

  uint64_t rVal = cryptoutils->get_uint64_t();
  if (width < 64)
    rVal &= (1ULL << width) - 1ULL;
  ConstantInt *r = cast<ConstantInt>(ConstantInt::get(T, rVal));

  // (a ^ r) >>s k
  BinaryOperator *xorOp = BinaryOperator::Create(
      Instruction::Xor, bo->getOperand(0), r, "", bo);
  BinaryOperator *ashrOp = BinaryOperator::Create(
      Instruction::AShr, xorOp, kC, "", bo);

  // r >>s k  (compile-time arithmetic right-shift, sign-extending rVal)
  int64_t rSigned = (int64_t)rVal;
  if (width < 64) {
    // Sign-extend rVal from [width] bits to 64 bits before shifting
    int ext = 64 - (int)width;
    rSigned = (rSigned << ext) >> ext;
  }
  int64_t rShrVal = rSigned >> (int)k;
  if (width < 64)
    rShrVal &= (int64_t)((1ULL << width) - 1ULL);
  ConstantInt *rShr = cast<ConstantInt>(ConstantInt::get(T, (uint64_t)rShrVal));

  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Xor, ashrOp, rShr, "", bo));
}

static void ashrSubstituteDoubleRound(BinaryOperator *bo) {
  // Apply the XOR-distributivity identity twice with independent randoms:
  //   a >>s k == (a ^ r1 ^ r2) >>s k ^ (r1 >>s k) ^ (r2 >>s k)
  // The decompiler sees a three-input XOR feeding an AShr — no existing
  // pattern-match rule recovers the original single-operand AShr.
  ConstantInt *kC = dyn_cast<ConstantInt>(bo->getOperand(1));
  if (!kC) return;
  unsigned k = (unsigned)kC->getZExtValue();
  unsigned width = bo->getType()->getIntegerBitWidth();
  if (k == 0 || k >= width) return;
  Type *T = bo->getType();

  // Helper: compute compile-time arithmetic right-shift for a width-bit value
  auto computeAShr = [&](uint64_t v) -> uint64_t {
    int64_t sv = (int64_t)v;
    if (width < 64) {
      int ext = 64 - (int)width;
      sv = (sv << ext) >> ext;
    }
    sv >>= (int)k;
    if (width < 64)
      sv &= (int64_t)((1ULL << width) - 1ULL);
    return (uint64_t)sv;
  };

  uint64_t r1Val = cryptoutils->get_uint64_t();
  uint64_t r2Val = cryptoutils->get_uint64_t();
  if (width < 64) {
    r1Val &= (1ULL << width) - 1ULL;
    r2Val &= (1ULL << width) - 1ULL;
  }

  ConstantInt *r1    = cast<ConstantInt>(ConstantInt::get(T, r1Val));
  ConstantInt *r2    = cast<ConstantInt>(ConstantInt::get(T, r2Val));
  ConstantInt *r1Shr = cast<ConstantInt>(ConstantInt::get(T, computeAShr(r1Val)));
  ConstantInt *r2Shr = cast<ConstantInt>(ConstantInt::get(T, computeAShr(r2Val)));

  // (a ^ r1 ^ r2)
  BinaryOperator *xr1  = BinaryOperator::Create(Instruction::Xor,
      bo->getOperand(0), r1, "", bo);
  BinaryOperator *xr12 = BinaryOperator::Create(Instruction::Xor,
      xr1, r2, "", bo);
  // >>s k
  BinaryOperator *ashrOp = BinaryOperator::Create(Instruction::AShr,
      xr12, kC, "", bo);
  // ^ (r1 >>s k) ^ (r2 >>s k)
  BinaryOperator *xR1 = BinaryOperator::Create(Instruction::Xor,
      ashrOp, r1Shr, "", bo);
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Xor, xR1, r2Shr, "", bo));
}

#define NUMBER_SHL_SUBST  2
#define NUMBER_LSHR_SUBST 2
#define NUMBER_ASHR_SUBST 2

static void (*funcShl[NUMBER_SHL_SUBST])(BinaryOperator *) = {
    &shlSubstituteMul, &shlSubstituteChain};
static void (*funcLShr[NUMBER_LSHR_SUBST])(BinaryOperator *) = {
    &lshrSubstituteMask, &lshrSubstituteXorRound};
static void (*funcAShr[NUMBER_ASHR_SUBST])(BinaryOperator *) = {
    &ashrSubstituteXorRound, &ashrSubstituteDoubleRound};

void SubstituteImpl::substituteShl(BinaryOperator *bo) {
  // Only substitute when the shift amount is a constant (variable shifts risk
  // violating the UB rules for shifts >= bitwidth after transformation)
  if (!isa<ConstantInt>(bo->getOperand(1))) return;
  (*funcShl[cryptoutils->get_range(NUMBER_SHL_SUBST)])(bo);
}
void SubstituteImpl::substituteLShr(BinaryOperator *bo) {
  if (!isa<ConstantInt>(bo->getOperand(1))) return;
  (*funcLShr[cryptoutils->get_range(NUMBER_LSHR_SUBST)])(bo);
}
void SubstituteImpl::substituteAShr(BinaryOperator *bo) {
  // Only substitute constant-shift-amount AShr.  Variable shifts are skipped
  // because the compile-time pre-computation of (r >>s k) requires a known k.
  if (!isa<ConstantInt>(bo->getOperand(1))) return;
  (*funcAShr[cryptoutils->get_range(NUMBER_ASHR_SUBST)])(bo);
}

void SubstituteImpl::substituteAdd(BinaryOperator *bo) {
  (*funcAdd[cryptoutils->get_range(NUMBER_ADD_SUBST)])(bo);
}
void SubstituteImpl::substituteSub(BinaryOperator *bo) {
  (*funcSub[cryptoutils->get_range(NUMBER_SUB_SUBST)])(bo);
}
void SubstituteImpl::substituteAnd(BinaryOperator *bo) {
  (*funcAnd[cryptoutils->get_range(NUMBER_AND_SUBST)])(bo);
}
void SubstituteImpl::substituteOr(BinaryOperator *bo) {
  (*funcOr[cryptoutils->get_range(NUMBER_OR_SUBST)])(bo);
}
void SubstituteImpl::substituteXor(BinaryOperator *bo) {
  (*funcXor[cryptoutils->get_range(NUMBER_XOR_SUBST)])(bo);
}
void SubstituteImpl::substituteMul(BinaryOperator *bo) {
  (*funcMul[cryptoutils->get_range(NUMBER_MUL_SUBST)])(bo);
}

// Implementation of ~(a | b) and ~a & ~b
static BinaryOperator *buildNor(Value *a, Value *b, Instruction *insertBefore) {
  switch (cryptoutils->get_range(2)) {
  case 0: {
    // ~(a | b)
    BinaryOperator *op =
        BinaryOperator::Create(Instruction::Or, a, b, "", insertBefore);
    op = BinaryOperator::CreateNot(op, "", insertBefore);
    return op;
  }
  case 1: {
    // ~a & ~b
    BinaryOperator *nota = BinaryOperator::CreateNot(a, "", insertBefore);
    BinaryOperator *notb = BinaryOperator::CreateNot(b, "", insertBefore);
    BinaryOperator *op =
        BinaryOperator::Create(Instruction::And, nota, notb, "", insertBefore);
    return op;
  }
  default:
    llvm_unreachable("wtf?");
  }
}

// Implementation of ~(a & b) and ~a | ~b
static BinaryOperator *buildNand(Value *a, Value *b,
                                 Instruction *insertBefore) {
  switch (cryptoutils->get_range(2)) {
  case 0: {
    // ~(a & b)
    BinaryOperator *op =
        BinaryOperator::Create(Instruction::And, a, b, "", insertBefore);
    op = BinaryOperator::CreateNot(op, "", insertBefore);
    return op;
  }
  case 1: {
    // ~a | ~b
    BinaryOperator *nota = BinaryOperator::CreateNot(a, "", insertBefore);
    BinaryOperator *notb = BinaryOperator::CreateNot(b, "", insertBefore);
    BinaryOperator *op =
        BinaryOperator::Create(Instruction::Or, nota, notb, "", insertBefore);
    return op;
  }
  default:
    llvm_unreachable("wtf?");
  }
}

// Implementation of a = b - (-c)
static void addNeg(BinaryOperator *bo) {
  BinaryOperator *op = BinaryOperator::CreateNeg(bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Sub, bo->getOperand(0), op, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = -(-b + (-c))
static void addDoubleNeg(BinaryOperator *bo) {
  BinaryOperator *op = BinaryOperator::CreateNeg(bo->getOperand(0), "", bo);
  BinaryOperator *op2 = BinaryOperator::CreateNeg(bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Add, op, op2, "", bo);
  op = BinaryOperator::CreateNeg(op, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of  r = rand (); a = b + r; a = a + c; a = a - r
static void addRand(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(
      bo->getType(), cryptoutils->get_uint64_t());
  BinaryOperator *op =
      BinaryOperator::Create(Instruction::Add, bo->getOperand(0), co, "", bo);
  op = BinaryOperator::Create(Instruction::Add, op, bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Sub, op, co, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of r = rand (); a = b - r; a = a + b; a = a + r
static void addRand2(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(
      bo->getType(), cryptoutils->get_uint64_t());
  BinaryOperator *op =
      BinaryOperator::Create(Instruction::Sub, bo->getOperand(0), co, "", bo);
  op = BinaryOperator::Create(Instruction::Add, op, bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Add, op, co, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = b + c => a = b - ~c - 1
static void addSubstitution(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(bo->getType(), 1);
  BinaryOperator *op = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  BinaryOperator *op1 = BinaryOperator::CreateNeg(co, "", bo);
  op = BinaryOperator::Create(Instruction::Sub, op, op1, "", bo);
  op = BinaryOperator::Create(Instruction::Sub, bo->getOperand(0), op, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = b + c => a = (b | c) + (b & c)
static void addSubstitution2(BinaryOperator *bo) {
  BinaryOperator *op = BinaryOperator::Create(
      Instruction::And, bo->getOperand(0), bo->getOperand(1), "", bo);
  BinaryOperator *op1 = BinaryOperator::Create(
      Instruction::Or, bo->getOperand(0), bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Add, op, op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = b + c => a = (b ^ c) + (b & c) * 2
static void addSubstitution3(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(bo->getType(), 2);
  BinaryOperator *op = BinaryOperator::Create(
      Instruction::And, bo->getOperand(0), bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Mul, op, co, "", bo);
  BinaryOperator *op1 = BinaryOperator::Create(
      Instruction::Xor, bo->getOperand(0), bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Add, op1, op, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = b + (-c)
static void subNeg(BinaryOperator *bo) {
  BinaryOperator *op = BinaryOperator::CreateNeg(bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Add, bo->getOperand(0), op, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of  r = rand (); a = b + r; a = a - c; a = a - r
static void subRand(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(
      bo->getType(), cryptoutils->get_uint64_t());
  BinaryOperator *op =
      BinaryOperator::Create(Instruction::Add, bo->getOperand(0), co, "", bo);
  op = BinaryOperator::Create(Instruction::Sub, op, bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Sub, op, co, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of  r = rand (); a = b - r; a = a - c; a = a + r
static void subRand2(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(
      bo->getType(), cryptoutils->get_uint64_t());
  BinaryOperator *op =
      BinaryOperator::Create(Instruction::Sub, bo->getOperand(0), co, "", bo);
  op = BinaryOperator::Create(Instruction::Sub, op, bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Add, op, co, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = b - c => a = (b & ~c) - (~b & c)
static void subSubstitution(BinaryOperator *bo) {
  BinaryOperator *op1 = BinaryOperator::CreateNot(bo->getOperand(0), "", bo);
  BinaryOperator *op =
      BinaryOperator::Create(Instruction::And, op1, bo->getOperand(1), "", bo);
  op1 = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  BinaryOperator *op2 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(0), op1, "", bo);
  op = BinaryOperator::Create(Instruction::Sub, op2, op, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = b - c => a = (2 * (b & ~c)) - (b ^ c)
static void subSubstitution2(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(bo->getType(), 2);
  BinaryOperator *op1 = BinaryOperator::Create(
      Instruction::Xor, bo->getOperand(0), bo->getOperand(1), "", bo);
  BinaryOperator *op = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::And, bo->getOperand(0), op, "", bo);
  op = BinaryOperator::Create(Instruction::Mul, co, op, "", bo);
  op = BinaryOperator::Create(Instruction::Sub, op, op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = b - c => a = b + ~c + 1
static void subSubstitution3(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(bo->getType(), 1);
  BinaryOperator *op1 = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  BinaryOperator *op =
      BinaryOperator::Create(Instruction::Add, bo->getOperand(0), op1, "", bo);
  op = BinaryOperator::Create(Instruction::Add, op, co, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = b & c => a = (b ^ ~c) & b
static void andSubstitution(BinaryOperator *bo) {
  BinaryOperator *op = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  BinaryOperator *op1 =
      BinaryOperator::Create(Instruction::Xor, bo->getOperand(0), op, "", bo);
  op = BinaryOperator::Create(Instruction::And, op1, bo->getOperand(0), "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = b & c => a = (b | c) & ~(b ^ c)
static void andSubstitution2(BinaryOperator *bo) {
  BinaryOperator *op1 = BinaryOperator::Create(
      Instruction::Xor, bo->getOperand(0), bo->getOperand(1), "", bo);
  op1 = BinaryOperator::CreateNot(op1, "", bo);
  BinaryOperator *op = BinaryOperator::Create(
      Instruction::Or, bo->getOperand(0), bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::And, op, op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = b & c => a = (~b | c) + (b + 1)
static void andSubstitution3(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(bo->getType(), 1);
  BinaryOperator *op1 =
      BinaryOperator::Create(Instruction::Add, bo->getOperand(0), co, "", bo);
  BinaryOperator *op = BinaryOperator::CreateNot(bo->getOperand(0), "", bo);
  op = BinaryOperator::Create(Instruction::Or, op, bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Add, op, op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = a & b <=> ~(~a | ~b) & (r | ~r)
static void andSubstitutionRand(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(
      bo->getType(), cryptoutils->get_uint64_t());
  BinaryOperator *op = BinaryOperator::CreateNot(bo->getOperand(0), "", bo);
  BinaryOperator *op1 = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  BinaryOperator *opr = BinaryOperator::CreateNot(co, "", bo);
  BinaryOperator *opa =
      BinaryOperator::Create(Instruction::Or, op, op1, "", bo);
  opr = BinaryOperator::Create(Instruction::Or, co, opr, "", bo);
  op = BinaryOperator::CreateNot(opa, "", bo);
  op = BinaryOperator::Create(Instruction::And, op, opr, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = a & b => Nor(Nor(a, a), Nor(b, b))
static void andNor(BinaryOperator *bo) {
  BinaryOperator *noraa = buildNor(bo->getOperand(0), bo->getOperand(0), bo);
  BinaryOperator *norbb = buildNor(bo->getOperand(1), bo->getOperand(1), bo);
  bo->replaceAllUsesWith(buildNor(noraa, norbb, bo));
}

// Implementation of a = a & b => Nand(Nand(a, b), Nand(a, b))
static void andNand(BinaryOperator *bo) {
  BinaryOperator *nandab = buildNand(bo->getOperand(0), bo->getOperand(1), bo);
  BinaryOperator *nandab2 = buildNand(bo->getOperand(0), bo->getOperand(1), bo);
  bo->replaceAllUsesWith(buildNand(nandab, nandab2, bo));
}

// Implementation of a = a | b => a = (b & c) | (b ^ c)
static void orSubstitution(BinaryOperator *bo) {
  BinaryOperator *op = BinaryOperator::Create(
      Instruction::And, bo->getOperand(0), bo->getOperand(1), "", bo);
  BinaryOperator *op1 = BinaryOperator::Create(
      Instruction::Xor, bo->getOperand(0), bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Or, op, op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = a | b => a = (b + (b ^ c)) - (b & ~c)
static void orSubstitution2(BinaryOperator *bo) {
  BinaryOperator *op1 = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  op1 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(0), op1, "", bo);
  BinaryOperator *op = BinaryOperator::Create(
      Instruction::Xor, bo->getOperand(0), bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Add, bo->getOperand(0), op, "", bo);
  op = BinaryOperator::Create(Instruction::Sub, op, op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = a | b => a = (b + c + 1) + ~(c & b)
static void orSubstitution3(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(bo->getType(), 1);
  BinaryOperator *op1 = BinaryOperator::Create(
      Instruction::And, bo->getOperand(1), bo->getOperand(0), "", bo);
  op1 = BinaryOperator::CreateNot(op1, "", bo);
  BinaryOperator *op = BinaryOperator::Create(
      Instruction::Add, bo->getOperand(0), bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Add, op, co, "", bo);
  op = BinaryOperator::Create(Instruction::Add, op, op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = b | c => a = (((~a & r) | (a & ~r)) ^ ((~b & r) | (b &
// ~r))) | (~(~a | ~b) & (r | ~r))
static void orSubstitutionRand(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(
      bo->getType(), cryptoutils->get_uint64_t());
  BinaryOperator *op = BinaryOperator::CreateNot(bo->getOperand(0), "", bo);
  BinaryOperator *op1 = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  BinaryOperator *op2 = BinaryOperator::CreateNot(co, "", bo);
  BinaryOperator *op3 =
      BinaryOperator::Create(Instruction::And, op, co, "", bo);
  BinaryOperator *op4 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(0), op2, "", bo);
  BinaryOperator *op5 =
      BinaryOperator::Create(Instruction::And, op1, co, "", bo);
  BinaryOperator *op6 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(1), op2, "", bo);
  op3 = BinaryOperator::Create(Instruction::Or, op3, op4, "", bo);
  op4 = BinaryOperator::Create(Instruction::Or, op5, op6, "", bo);
  op5 = BinaryOperator::Create(Instruction::Xor, op3, op4, "", bo);
  op3 = BinaryOperator::Create(Instruction::Or, op, op1, "", bo);
  op3 = BinaryOperator::CreateNot(op3, "", bo);
  op4 = BinaryOperator::Create(Instruction::Or, co, op2, "", bo);
  op4 = BinaryOperator::Create(Instruction::And, op3, op4, "", bo);
  op = BinaryOperator::Create(Instruction::Or, op5, op4, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = a | b => a = Nor(Nor(a, b), Nor(a, b))
static void orNor(BinaryOperator *bo) {
  BinaryOperator *norab = buildNor(bo->getOperand(0), bo->getOperand(1), bo);
  BinaryOperator *norab2 = buildNor(bo->getOperand(0), bo->getOperand(1), bo);
  BinaryOperator *op = buildNor(norab, norab2, bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = a | b => a = Nand(Nand(a, a), Nand(b, b))
static void orNand(BinaryOperator *bo) {
  BinaryOperator *nandaa = buildNand(bo->getOperand(0), bo->getOperand(0), bo);
  BinaryOperator *nandbb = buildNand(bo->getOperand(1), bo->getOperand(1), bo);
  BinaryOperator *op = buildNand(nandaa, nandbb, bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = a ^ b => a = (~a & b) | (a & ~b)
static void xorSubstitution(BinaryOperator *bo) {
  BinaryOperator *op = BinaryOperator::CreateNot(bo->getOperand(0), "", bo);
  op = BinaryOperator::Create(Instruction::And, bo->getOperand(1), op, "", bo);
  BinaryOperator *op1 = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  op1 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(0), op1, "", bo);
  op = BinaryOperator::Create(Instruction::Or, op, op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = a ^ b => a = (b + c) - 2 * (b & c)
static void xorSubstitution2(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(bo->getType(), 2);
  BinaryOperator *op1 = BinaryOperator::Create(
      Instruction::And, bo->getOperand(0), bo->getOperand(1), "", bo);
  op1 = BinaryOperator::Create(Instruction::Mul, co, op1, "", bo);
  BinaryOperator *op = BinaryOperator::Create(
      Instruction::Add, bo->getOperand(0), bo->getOperand(1), "", bo);
  op = BinaryOperator::Create(Instruction::Sub, op, op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = a ^ b => a = b - (2 * (c & ~(b ^ c)) - c)
static void xorSubstitution3(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(bo->getType(), 2);
  BinaryOperator *op1 = BinaryOperator::Create(
      Instruction::Xor, bo->getOperand(0), bo->getOperand(1), "", bo);
  op1 = BinaryOperator::CreateNot(op1, "", bo);
  op1 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(1), op1, "", bo);
  op1 = BinaryOperator::Create(Instruction::Mul, co, op1, "", bo);
  op1 =
      BinaryOperator::Create(Instruction::Sub, op1, bo->getOperand(1), "", bo);
  BinaryOperator *op =
      BinaryOperator::Create(Instruction::Sub, bo->getOperand(0), op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = a ^ b <=> (a ^ r) ^ (b ^ r) <=> (~a & r | a & ~r) ^ (~b
// & r | b & ~r) note : r is a random number
static void xorSubstitutionRand(BinaryOperator *bo) {
  ConstantInt *co = (ConstantInt *)ConstantInt::get(
      bo->getType(), cryptoutils->get_uint64_t());
  BinaryOperator *op = BinaryOperator::CreateNot(bo->getOperand(0), "", bo);
  op = BinaryOperator::Create(Instruction::And, co, op, "", bo);
  BinaryOperator *opr = BinaryOperator::CreateNot(co, "", bo);
  BinaryOperator *op1 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(0), opr, "", bo);
  BinaryOperator *op2 = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  op2 = BinaryOperator::Create(Instruction::And, op2, co, "", bo);
  BinaryOperator *op3 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(1), opr, "", bo);
  op = BinaryOperator::Create(Instruction::Or, op, op1, "", bo);
  op1 = BinaryOperator::Create(Instruction::Or, op2, op3, "", bo);
  op = BinaryOperator::Create(Instruction::Xor, op, op1, "", bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = a ^ b => a = Nor(Nor(Nor(a, a), Nor(b, b)), Nor(a, b))
static void xorNor(BinaryOperator *bo) {
  BinaryOperator *noraa = buildNor(bo->getOperand(0), bo->getOperand(0), bo);
  BinaryOperator *norbb = buildNor(bo->getOperand(1), bo->getOperand(1), bo);
  BinaryOperator *nornoraanorbb = buildNor(noraa, norbb, bo);
  BinaryOperator *norab = buildNor(bo->getOperand(0), bo->getOperand(1), bo);
  BinaryOperator *op = buildNor(nornoraanorbb, norab, bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = a ^ b => a = Nand(Nand(Nand(a, a), b), Nand(a, Nand(b,
// b)))
static void xorNand(BinaryOperator *bo) {
  BinaryOperator *nandaa = buildNand(bo->getOperand(0), bo->getOperand(0), bo);
  BinaryOperator *nandnandaab = buildNand(nandaa, bo->getOperand(1), bo);
  BinaryOperator *nandbb = buildNand(bo->getOperand(1), bo->getOperand(1), bo);
  BinaryOperator *nandanandbb = buildNand(bo->getOperand(0), nandbb, bo);
  BinaryOperator *op = buildNand(nandnandaab, nandanandbb, bo);
  bo->replaceAllUsesWith(op);
}

// Implementation of a = b * c => a = (((b | c) * (b & c)) + ((b & ~c) * (c &
// ~b)))
static void mulSubstitution(BinaryOperator *bo) {
  BinaryOperator *op1 = BinaryOperator::CreateNot(bo->getOperand(0), "", bo);
  op1 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(1), op1, "", bo);
  BinaryOperator *op2 = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  op2 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(0), op2, "", bo);
  BinaryOperator *op =
      BinaryOperator::Create(Instruction::Mul, op2, op1, "", bo);
  op1 = BinaryOperator::Create(Instruction::And, bo->getOperand(0),
                               bo->getOperand(1), "", bo);
  op2 = BinaryOperator::Create(Instruction::Or, bo->getOperand(0),
                               bo->getOperand(1), "", bo);
  BinaryOperator *op3 =
      BinaryOperator::Create(Instruction::Mul, op2, op1, "", bo);
  op = BinaryOperator::Create(Instruction::Add, op3, op, "", bo);
  bo->replaceAllUsesWith(op);
}

// ─── OLLVM-Next: enhanced MUL substitutions ──────────────────────────────────

// Implementation: a * b via Karatsuba-style decomposition into shifts+adds.
// Splits b into high/low halves and reconstructs using only add/shl/sub.
// IDA HLIL simplifier cannot re-fold this to a single imul reliably.
// Verified: a*b = a*(bH*2^k + bL) = a*bH*2^k + a*bL
// (bH = b >> k, bL = b & mask, k = width/2)
static void mulSubstitution3(BinaryOperator *bo) {
  unsigned width = bo->getType()->getIntegerBitWidth();
  if (width < 4) {
    // Width too small to split; fall back to basic substitute
    ConstantInt *co = (ConstantInt *)ConstantInt::get(bo->getType(), 1);
    BinaryOperator *op = BinaryOperator::CreateNeg(bo->getOperand(1), "", bo);
    op = BinaryOperator::Create(Instruction::Add, bo->getOperand(0), op, "", bo);
    op = BinaryOperator::Create(Instruction::Sub,
                                BinaryOperator::Create(Instruction::Mul,
                                                       bo->getOperand(0),
                                                       BinaryOperator::CreateNeg(co, "", bo), "", bo),
                                BinaryOperator::Create(Instruction::Mul, op, co, "", bo),
                                "", bo);
    bo->replaceAllUsesWith(op);
    return;
  }
  unsigned k = width / 2;
  ConstantInt *kConst   = (ConstantInt *)ConstantInt::get(bo->getType(), k);
  // k = width/2 ≤ 32, so 1ULL<<k never overflows; UINT64_MAX was wrong for
  // width==64 because bL would equal b (full value) instead of lower half.
  ConstantInt *maskConst = (ConstantInt *)ConstantInt::get(
      bo->getType(), (1ULL << k) - 1ULL);
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  BinaryOperator *bH = BinaryOperator::Create(Instruction::LShr, b, kConst, "", bo);
  BinaryOperator *bL = BinaryOperator::Create(Instruction::And, b, maskConst, "", bo);
  BinaryOperator *aH = BinaryOperator::Create(Instruction::Mul, a, bH, "", bo);
  BinaryOperator *aL = BinaryOperator::Create(Instruction::Mul, a, bL, "", bo);
  BinaryOperator *aHsh = BinaryOperator::Create(Instruction::Shl, aH, kConst, "", bo);
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Add, aHsh, aL, "", bo));
}

// Implementation: a * b with random-constant identity injection:
//   a*b = (a+r)*(b+r) - (a+r)*r - (b+r)*r + r*r + r*(a+b) - r*(a+b)
//   Simplified: a*b = (a+r)*(b+r) - (a+r)*r - b*r
// Verified: (a+r)(b+r) = ab + ar + br + r²
//           subtract (a+r)*r = ar + r², leaves ab + br
//           subtract b*r, leaves ab ✓
// The 3 extra multiplies look irreducible to a static analyzer.
static void mulSubstitution4(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  ConstantInt *r = (ConstantInt *)ConstantInt::get(T, cryptoutils->get_uint64_t());
  BinaryOperator *aPr  = BinaryOperator::Create(Instruction::Add, a, r, "", bo);
  BinaryOperator *bPr  = BinaryOperator::Create(Instruction::Add, b, r, "", bo);
  BinaryOperator *m1   = BinaryOperator::Create(Instruction::Mul, aPr, bPr, "", bo);
  BinaryOperator *m2   = BinaryOperator::Create(Instruction::Mul, aPr, r,   "", bo);
  BinaryOperator *m3   = BinaryOperator::Create(Instruction::Mul, b,   r,   "", bo);
  BinaryOperator *sub1 = BinaryOperator::Create(Instruction::Sub, m1,  m2,  "", bo);
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Sub, sub1, m3, "", bo));
}

// Implementation of a = b * c => a = (((b | c) * (b & c)) + ((~(b | ~c)) * (b &
// ~c)))
static void mulSubstitution2(BinaryOperator *bo) {
  BinaryOperator *op1 = BinaryOperator::CreateNot(bo->getOperand(1), "", bo);
  BinaryOperator *op2 =
      BinaryOperator::Create(Instruction::And, bo->getOperand(0), op1, "", bo);
  BinaryOperator *op3 =
      BinaryOperator::Create(Instruction::Or, bo->getOperand(0), op1, "", bo);
  op3 = BinaryOperator::CreateNot(op3, "", bo);
  op3 = BinaryOperator::Create(Instruction::Mul, op3, op2, "", bo);
  BinaryOperator *op4 = BinaryOperator::Create(
      Instruction::And, bo->getOperand(0), bo->getOperand(1), "", bo);
  BinaryOperator *op5 = BinaryOperator::Create(
      Instruction::Or, bo->getOperand(0), bo->getOperand(1), "", bo);
  op5 = BinaryOperator::Create(Instruction::Mul, op5, op4, "", bo);
  BinaryOperator *op =
      BinaryOperator::Create(Instruction::Add, op5, op3, "", bo);
  bo->replaceAllUsesWith(op);
}

// ─── OLLVM-Next: chained MBA ADD ─────────────────────────────────────────────

// 3-layer chained MBA: each layer applies a different linear MBA identity.
//   Layer 1: a+b = (a|b) + (a&b)          → intermediate {p,q}
//   Layer 2: p+q = (p^q) + ((p&q)<<1)     → intermediate {s,t}
//   Layer 3: s+t = 2*(s|t) - (s^t)        → final result
// The chain produces ~18 IR instructions from a single add.
static void addChainedMBA(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  ConstantInt *c2 = (ConstantInt *)ConstantInt::get(T, 2);
  ConstantInt *c1 = (ConstantInt *)ConstantInt::get(T, 1);

  // Layer 1
  BinaryOperator *p = BinaryOperator::Create(Instruction::Or,  a, b, "", bo);
  BinaryOperator *q = BinaryOperator::Create(Instruction::And, a, b, "", bo);

  // Layer 2
  BinaryOperator *pxq  = BinaryOperator::Create(Instruction::Xor, p, q, "", bo);
  BinaryOperator *panq = BinaryOperator::Create(Instruction::And, p, q, "", bo);
  BinaryOperator *shl1 = BinaryOperator::Create(Instruction::Shl, panq, c1, "", bo);
  BinaryOperator *s    = pxq;                    // s = p^q
  BinaryOperator *t    = shl1;                   // t = (p&q)<<1

  // Layer 3
  BinaryOperator *sor  = BinaryOperator::Create(Instruction::Or,  s, t, "", bo);
  BinaryOperator *sxr  = BinaryOperator::Create(Instruction::Xor, s, t, "", bo);
  BinaryOperator *dbl  = BinaryOperator::Create(Instruction::Mul, sor, c2, "", bo);
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Sub, dbl, sxr, "", bo));
}

// a+b decomposed via rotation: let K = random shift amount
//   rol(a,K) + rol(b,K) == rol(a+b, K)  [NOT true in general for integers]
// Use safe rotation-based decomposition instead:
//   Inject random r; then:
//   a + b = (a ^ r) + (b ^ r) + 2*(a & r) + 2*(b & r) - 2*r
// (Identical to MBAImpl::mbaAddRandLinear but using BinaryOperator API style.)
static void addRotateDecompose(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  ConstantInt *r  = (ConstantInt *)ConstantInt::get(T, cryptoutils->get_uint64_t());
  ConstantInt *c2 = (ConstantInt *)ConstantInt::get(T, 2);
  BinaryOperator *ar    = BinaryOperator::Create(Instruction::Xor, a, r,  "", bo);
  BinaryOperator *br    = BinaryOperator::Create(Instruction::Xor, b, r,  "", bo);
  BinaryOperator *andr_a = BinaryOperator::Create(Instruction::And, a, r, "", bo);
  BinaryOperator *andr_b = BinaryOperator::Create(Instruction::And, b, r, "", bo);
  BinaryOperator *twoa  = BinaryOperator::Create(Instruction::Mul, andr_a, c2, "", bo);
  BinaryOperator *twob  = BinaryOperator::Create(Instruction::Mul, andr_b, c2, "", bo);
  BinaryOperator *twoR  = BinaryOperator::Create(Instruction::Mul, r, c2, "", bo);
  BinaryOperator *sum1  = BinaryOperator::Create(Instruction::Add, ar, br,   "", bo);
  BinaryOperator *sum2  = BinaryOperator::Create(Instruction::Add, sum1, twoa, "", bo);
  BinaryOperator *sum3  = BinaryOperator::Create(Instruction::Add, sum2, twob, "", bo);
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Sub, sum3, twoR, "", bo));
}

// ─── OLLVM-Next: additional XOR substitutions ────────────────────────────────

// XOR via split: a^b = (a | r) - (a & r) + (b & ~r) - (b & r) + ... no,
// use verified: a^b = (a - b) + 2*(~a & b)   [rearrangement of SUB-1]
// Further wrapped in random constant injection to confuse constant folders.
static void xorSplitRotate(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  ConstantInt *c2 = (ConstantInt *)ConstantInt::get(T, 2);
  ConstantInt *r  = (ConstantInt *)ConstantInt::get(T, cryptoutils->get_uint64_t());
  // a ^ b = (a - b) + 2*(~a & b)
  BinaryOperator *notA  = BinaryOperator::CreateNot(a, "", bo);
  BinaryOperator *andNB = BinaryOperator::Create(Instruction::And, notA, b, "", bo);
  BinaryOperator *dbl   = BinaryOperator::Create(Instruction::Mul, andNB, c2, "", bo);
  BinaryOperator *diff  = BinaryOperator::Create(Instruction::Sub, a, b, "", bo);
  // Random noise: add r then subtract r (nets to zero, confuses analysis)
  BinaryOperator *nr    = BinaryOperator::Create(Instruction::Add, diff, r, "", bo);
  BinaryOperator *back  = BinaryOperator::Create(Instruction::Sub, nr, r, "", bo);
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Add, back, dbl, "", bo));
}

// XOR arithmetic decompose: a^b = (a+b) - 2*(a&b), then expand (a&b) via De Morgan
// Result: a^b = (a+b) - 2*(~(~a | ~b))
// Two negations in the expression chain defeat HLIL's and-pattern recognition.
static void xorArithDecompose(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  ConstantInt *c2 = (ConstantInt *)ConstantInt::get(T, 2);
  BinaryOperator *sum   = BinaryOperator::Create(Instruction::Add, a, b, "", bo);
  BinaryOperator *notA  = BinaryOperator::CreateNot(a, "", bo);
  BinaryOperator *notB  = BinaryOperator::CreateNot(b, "", bo);
  BinaryOperator *orN   = BinaryOperator::Create(Instruction::Or, notA, notB, "", bo);
  BinaryOperator *andAB = BinaryOperator::CreateNot(orN, "", bo); // ~(~a|~b) = a&b
  BinaryOperator *dbl   = BinaryOperator::Create(Instruction::Mul, andAB, c2, "", bo);
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Sub, sum, dbl, "", bo));
}

// ─── OLLVM-Next: new high-depth substitutions ────────────────────────────────

// ADD: a+b = ~(~a - b)
// Proof: ~a = -a-1; ~a-b = -a-1-b; ~(-a-1-b) = a+b ✓
static void addNegComplement(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  BinaryOperator *notA = BinaryOperator::CreateNot(a, "", bo);
  BinaryOperator *sub  = BinaryOperator::Create(Instruction::Sub, notA, b, "", bo);
  bo->replaceAllUsesWith(BinaryOperator::CreateNot(sub, "", bo));
}

// ADD: a+b = (a+r1) + (b+r2) - r1 - r2  for two independent random constants
static void addRandPair(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  ConstantInt *r1 = cast<ConstantInt>(ConstantInt::get(T, cryptoutils->get_uint64_t()));
  ConstantInt *r2 = cast<ConstantInt>(ConstantInt::get(T, cryptoutils->get_uint64_t()));
  BinaryOperator *aPr1 = BinaryOperator::Create(Instruction::Add, a, r1, "", bo);
  BinaryOperator *bPr2 = BinaryOperator::Create(Instruction::Add, b, r2, "", bo);
  BinaryOperator *sum  = BinaryOperator::Create(Instruction::Add, aPr1, bPr2, "", bo);
  BinaryOperator *s2   = BinaryOperator::Create(Instruction::Sub, sum, r1, "", bo);
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Sub, s2, r2, "", bo));
}

// ADD: 4-layer MBA chain: a+b via (OR+AND)→(XOR+SHL)→(OR+AND)→(MUL+SUB)
// Produces 12+ IR instructions; no layer individually reveals the ADD pattern.
static void addFourLayerChain(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  ConstantInt *c1 = cast<ConstantInt>(ConstantInt::get(T, 1));
  ConstantInt *c2 = cast<ConstantInt>(ConstantInt::get(T, 2));
  // Layer 1: p=(a|b), q=(a&b)
  BinaryOperator *p = BinaryOperator::Create(Instruction::Or,  a, b, "", bo);
  BinaryOperator *q = BinaryOperator::Create(Instruction::And, a, b, "", bo);
  // Layer 2: s=(p^q), t=((p&q)<<1)
  BinaryOperator *pxq  = BinaryOperator::Create(Instruction::Xor, p, q, "", bo);
  BinaryOperator *panq = BinaryOperator::Create(Instruction::And, p, q, "", bo);
  BinaryOperator *t    = BinaryOperator::Create(Instruction::Shl, panq, c1, "", bo);
  // Layer 3: u=(s|t), v=(s^t)
  BinaryOperator *u = BinaryOperator::Create(Instruction::Or,  pxq, t, "", bo);
  BinaryOperator *v = BinaryOperator::Create(Instruction::Xor, pxq, t, "", bo);
  // Layer 4: 2*u - v
  BinaryOperator *dbl = BinaryOperator::Create(Instruction::Mul, u, c2, "", bo);
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Sub, dbl, v, "", bo));
}

// ADD: a+b = -(-a - b) = -((-a) + (-b))
static void addNegateNegate(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  BinaryOperator *negA = BinaryOperator::CreateNeg(a, "", bo);
  BinaryOperator *negB = BinaryOperator::CreateNeg(b, "", bo);
  BinaryOperator *sum  = BinaryOperator::Create(Instruction::Add, negA, negB, "", bo);
  bo->replaceAllUsesWith(BinaryOperator::CreateNeg(sum, "", bo));
}

// SUB: a-b = ~(~a + b)
// ~a = -a-1; ~a+b = -a-1+b; ~(-a-1+b) = a+1-b-1 = a-b ✓
static void subViaComplement(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  BinaryOperator *notA = BinaryOperator::CreateNot(a, "", bo);
  BinaryOperator *sum  = BinaryOperator::Create(Instruction::Add, notA, b, "", bo);
  bo->replaceAllUsesWith(BinaryOperator::CreateNot(sum, "", bo));
}

// SUB: a-b = 2*(a&~b) - (a^b)
// Proof: a=5=101,b=3=011: a&~b=101&100=100=4; 2*4=8; a^b=110=6; 8-6=2=a-b ✓
static void subFourTerm(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  ConstantInt *c2 = cast<ConstantInt>(ConstantInt::get(T, 2));
  BinaryOperator *notB  = BinaryOperator::CreateNot(b, "", bo);
  BinaryOperator *andAB = BinaryOperator::Create(Instruction::And, a, notB, "", bo);
  BinaryOperator *dbl   = BinaryOperator::Create(Instruction::Mul, andAB, c2, "", bo);
  BinaryOperator *xorAB = BinaryOperator::Create(Instruction::Xor, a, b, "", bo);
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Sub, dbl, xorAB, "", bo));
}

// SUB: a-b = -((-a) + b) = negate(negate(a) + b)
static void subDoubleNeg(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  BinaryOperator *negA = BinaryOperator::CreateNeg(a, "", bo);
  BinaryOperator *sum  = BinaryOperator::Create(Instruction::Add, negA, b, "", bo);
  bo->replaceAllUsesWith(BinaryOperator::CreateNeg(sum, "", bo));
}

// SUB: a-b = (a+r) - (b+r)  — trivial but builds a chain with two additions
static void subRandPair(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  ConstantInt *r = cast<ConstantInt>(ConstantInt::get(T, cryptoutils->get_uint64_t()));
  BinaryOperator *aPr = BinaryOperator::Create(Instruction::Add, a, r, "", bo);
  BinaryOperator *bPr = BinaryOperator::Create(Instruction::Add, b, r, "", bo);
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Sub, aPr, bPr, "", bo));
}

// AND: a&b = (a XOR b) XOR (a OR b)
// Proof bit-by-bit: {00→0^0=0, 01→1^1=0, 10→1^1=0, 11→0^1=1} ✓
static void andViaXorOr(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  BinaryOperator *xorAB = BinaryOperator::Create(Instruction::Xor, a, b, "", bo);
  BinaryOperator *orAB  = BinaryOperator::Create(Instruction::Or,  a, b, "", bo);
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Xor, xorAB, orAB, "", bo));
}

// AND: a&b via ~a and ~b chain: ~(~a | ~b) expressed with random XOR-NOT decomposition
// ~a = (a XOR r) XOR ~r  for any constant r (XOR with r then XOR with ~r = NOT)
static void andNotNot(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  ConstantInt *r    = cast<ConstantInt>(ConstantInt::get(T, cryptoutils->get_uint64_t()));
  BinaryOperator *notR  = BinaryOperator::CreateNot(r, "", bo);
  // ~a = (a ^ r) ^ ~r
  BinaryOperator *axr   = BinaryOperator::Create(Instruction::Xor, a, r,    "", bo);
  BinaryOperator *notA  = BinaryOperator::Create(Instruction::Xor, axr, notR,"", bo);
  BinaryOperator *bxr   = BinaryOperator::Create(Instruction::Xor, b, r,    "", bo);
  BinaryOperator *notB  = BinaryOperator::Create(Instruction::Xor, bxr, notR,"", bo);
  BinaryOperator *orN   = BinaryOperator::Create(Instruction::Or, notA, notB,"", bo);
  bo->replaceAllUsesWith(BinaryOperator::CreateNot(orN, "", bo));
}

// AND: 4-term form using random mask r.
// Identity: a&b = (a&r)&(b&r) | (a&~r)&(b&~r)
// Proof (per-bit):
//   r_i=1: (a_i & 1)&(b_i & 1) | (a_i & 0)&(b_i & 0) = a_i&b_i | 0 = a_i&b_i ✓
//   r_i=0: (a_i & 0)&(b_i & 0) | (a_i & 1)&(b_i & 1) = 0 | a_i&b_i = a_i&b_i ✓
// Equivalently: (a&b&r) | (a&b&~r) = a&b&(r|~r) = a&b ✓
static void andFourTerm(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  ConstantInt *r  = cast<ConstantInt>(ConstantInt::get(T, cryptoutils->get_uint64_t()));
  BinaryOperator *notR  = BinaryOperator::CreateNot(r, "", bo);
  BinaryOperator *ar    = BinaryOperator::Create(Instruction::And, a, r,    "", bo); // a & r
  BinaryOperator *anr   = BinaryOperator::Create(Instruction::And, a, notR, "", bo); // a & ~r
  BinaryOperator *br    = BinaryOperator::Create(Instruction::And, b, r,    "", bo); // b & r
  BinaryOperator *bnr   = BinaryOperator::Create(Instruction::And, b, notR, "", bo); // b & ~r
  BinaryOperator *left  = BinaryOperator::Create(Instruction::And, ar,  br,  "", bo); // (a&r)&(b&r)
  BinaryOperator *right = BinaryOperator::Create(Instruction::And, anr, bnr, "", bo); // (a&~r)&(b&~r)
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Or, left, right, "", bo));
}

// AND: a&b = ~(~a | ~b) with extra NOT-double negation on one operand
// ~a applied twice = a; the intermediate steps look like independent ops.
static void andMirror(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  // ~~a = a, so: ~(~(~~a) | ~b) = ~(~a | ~b) = a&b ✓
  BinaryOperator *notA1  = BinaryOperator::CreateNot(a, "", bo);
  BinaryOperator *notA2  = BinaryOperator::CreateNot(notA1, "", bo); // = a
  BinaryOperator *notA3  = BinaryOperator::CreateNot(notA2, "", bo); // = ~a
  BinaryOperator *notB   = BinaryOperator::CreateNot(b, "", bo);
  BinaryOperator *orNANB = BinaryOperator::Create(Instruction::Or, notA3, notB, "", bo);
  bo->replaceAllUsesWith(BinaryOperator::CreateNot(orNANB, "", bo));
}

// OR: a|b via XOR and AND partition: (a^b) | (a&b) = a|b ✓
// Proof: a|b bits = bits where a≠b (XOR) OR both=1 (AND)
static void orViaXorAnd(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  BinaryOperator *xorAB = BinaryOperator::Create(Instruction::Xor, a, b, "", bo);
  BinaryOperator *andAB = BinaryOperator::Create(Instruction::And, a, b, "", bo);
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Or, xorAB, andAB, "", bo));
}

// OR: a|b = NOR(NOR(a,b), NOR(a,b)) with double-NOR form
static void orNotNor(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  // NOR(a,b) = ~(a|b); NOR(NOR(a,b), NOR(a,b)) = ~(~(a|b) | ~(a|b)) = ~~(a|b) = a|b ✓
  BinaryOperator *nor1 = buildNor(a, b, bo);
  BinaryOperator *nor2 = buildNor(a, b, bo);
  bo->replaceAllUsesWith(buildNor(nor1, nor2, bo));
}

// OR: a|b = (a+b+r) - (a&b) - r  [A+B-AND with random chain]
static void orMerge(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  ConstantInt *r = cast<ConstantInt>(ConstantInt::get(T, cryptoutils->get_uint64_t()));
  BinaryOperator *sum   = BinaryOperator::Create(Instruction::Add, a, b, "", bo);
  BinaryOperator *sumR  = BinaryOperator::Create(Instruction::Add, sum, r, "", bo);
  BinaryOperator *andAB = BinaryOperator::Create(Instruction::And, a, b, "", bo);
  BinaryOperator *s2    = BinaryOperator::Create(Instruction::Sub, sumR, andAB, "", bo);
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Sub, s2, r, "", bo));
}

// OR: 4-term expansion using ~a and carry-save form
// a|b = a + b - a&b, where a&b = ~(~a|~b)
// Express ~a and ~b via random XOR chains for extra depth
static void orFourTerm(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  ConstantInt *r  = cast<ConstantInt>(ConstantInt::get(T, cryptoutils->get_uint64_t()));
  // ~a = (a ^ r) ^ (r ^ -1) ... but just use NOT for correctness + chain length
  BinaryOperator *notA  = BinaryOperator::CreateNot(a, "", bo);
  BinaryOperator *notB  = BinaryOperator::CreateNot(b, "", bo);
  BinaryOperator *norNANB = BinaryOperator::CreateNot(
      BinaryOperator::Create(Instruction::Or, notA, notB, "", bo), "", bo); // a&b
  // a|b = a+b - a&b
  BinaryOperator *sum   = BinaryOperator::Create(Instruction::Add, a, b, "", bo);
  BinaryOperator *sumR  = BinaryOperator::Create(Instruction::Add, sum, r, "", bo);
  BinaryOperator *s1    = BinaryOperator::Create(Instruction::Sub, sumR, norNANB, "", bo);
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Sub, s1, r, "", bo));
}

// XOR: a^b = ~a ^ ~b  (complement preserves XOR: verified)
static void xorViaCompl(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  BinaryOperator *notA = BinaryOperator::CreateNot(a, "", bo);
  BinaryOperator *notB = BinaryOperator::CreateNot(b, "", bo);
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Xor, notA, notB, "", bo));
}

// XOR: split into high/low bit groups — each group's XOR is independent
// a^b = ((a>>k)^(b>>k))<<k ^ ((a&mask)^(b&mask))
// Both halves XOR independently (no carry between groups for XOR) ✓
static void xorHighLow(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  unsigned width = T->getIntegerBitWidth();
  if (width < 4) {
    xorSubstitution(bo);
    return;
  }
  unsigned k = width / 2;
  ConstantInt *kC   = cast<ConstantInt>(ConstantInt::get(T, k));
  // k = width/2 ≤ 32, so (1ULL<<k) never overflows; UINT64_MAX was wrong for
  // width==64 because it left the "low half" mask as the full 64-bit value,
  // causing the formula to return only the lower k bits of a^b.
  uint64_t maskV    = (1ULL << k) - 1ULL;
  ConstantInt *maskC = cast<ConstantInt>(ConstantInt::get(T, maskV));
  // High bits: ((a>>k)^(b>>k))<<k
  BinaryOperator *aH  = BinaryOperator::Create(Instruction::LShr, a, kC, "", bo);
  BinaryOperator *bH  = BinaryOperator::Create(Instruction::LShr, b, kC, "", bo);
  BinaryOperator *xH  = BinaryOperator::Create(Instruction::Xor,  aH, bH, "", bo);
  BinaryOperator *xHs = BinaryOperator::Create(Instruction::Shl,  xH, kC, "", bo);
  // Low bits: (a&mask)^(b&mask)
  BinaryOperator *aL  = BinaryOperator::Create(Instruction::And, a, maskC, "", bo);
  BinaryOperator *bL  = BinaryOperator::Create(Instruction::And, b, maskC, "", bo);
  BinaryOperator *xL  = BinaryOperator::Create(Instruction::Xor, aL, bL,   "", bo);
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Xor, xHs, xL, "", bo));
}

// XOR: a^b = (a^r1^b^r2)^(r1^r2)  for two independent random constants
// Proof: (a^r1^b^r2)^(r1^r2) = a^b^r1^r2^r1^r2 = a^b ✓
static void xorDoubleRand(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  ConstantInt *r1 = cast<ConstantInt>(ConstantInt::get(T, cryptoutils->get_uint64_t()));
  ConstantInt *r2 = cast<ConstantInt>(ConstantInt::get(T, cryptoutils->get_uint64_t()));
  // r1^r2 compile-time constant
  uint64_t r12val = r1->getZExtValue() ^ r2->getZExtValue();
  ConstantInt *r12 = cast<ConstantInt>(ConstantInt::get(T, r12val));
  BinaryOperator *ax   = BinaryOperator::Create(Instruction::Xor, a, r1, "", bo);
  BinaryOperator *axb  = BinaryOperator::Create(Instruction::Xor, ax, b,  "", bo);
  BinaryOperator *axbr = BinaryOperator::Create(Instruction::Xor, axb, r2,"", bo);
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Xor, axbr, r12, "", bo));
}

// XOR: 4-term arithmetic chain:
// a^b = (a|b) - (a&b) [X1], where (a&b) = ~(~a|~b) [De Morgan], 4 operations
static void xorFourTerm(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  BinaryOperator *notA  = BinaryOperator::CreateNot(a, "", bo);
  BinaryOperator *notB  = BinaryOperator::CreateNot(b, "", bo);
  BinaryOperator *orNANB= BinaryOperator::Create(Instruction::Or, notA, notB, "", bo);
  BinaryOperator *andAB = BinaryOperator::CreateNot(orNANB, "", bo); // a&b
  BinaryOperator *orAB  = BinaryOperator::Create(Instruction::Or, a, b, "", bo);
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Sub, orAB, andAB, "", bo));
}

// MUL: a*b = -(a * (-b)) = -(a * (0-b))
static void mulViaNeg(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  BinaryOperator *negB  = BinaryOperator::CreateNeg(b, "", bo);
  BinaryOperator *mulAB = BinaryOperator::Create(Instruction::Mul, a, negB, "", bo);
  bo->replaceAllUsesWith(BinaryOperator::CreateNeg(mulAB, "", bo));
}

// MUL: a*b = a*(b+1) - a
static void mulIncrement(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  ConstantInt *one = cast<ConstantInt>(ConstantInt::get(T, 1));
  BinaryOperator *bP1  = BinaryOperator::Create(Instruction::Add, b, one, "", bo);
  BinaryOperator *mul  = BinaryOperator::Create(Instruction::Mul, a, bP1, "", bo);
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Sub, mul, a, "", bo));
}

// MUL: a*b = -(a * ~b) - a   [from: ~b = -b-1, a*(~b) = -ab-a, -(−ab−a)−a = ab]
// Proof: -(a*(~b)) = -a*(-b-1) = ab+a; ab+a-a = ab ✓
static void mulDoubleHalf(BinaryOperator *bo) {
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  BinaryOperator *notB  = BinaryOperator::CreateNot(b, "", bo);
  BinaryOperator *mulAB = BinaryOperator::Create(Instruction::Mul, a, notB, "", bo);
  BinaryOperator *negAB = BinaryOperator::CreateNeg(mulAB, "", bo); // -(a*~b) = ab+a
  bo->replaceAllUsesWith(
      BinaryOperator::Create(Instruction::Sub, negAB, a, "", bo));
}
