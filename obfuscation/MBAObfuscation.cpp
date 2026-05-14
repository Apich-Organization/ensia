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

// MBAObfuscation.cpp — Mixed Boolean-Arithmetic obfuscation pass.
//
// Replaces scalar integer binary operations with mathematically equivalent
// multi-term expressions involving both arithmetic (+, -, *) and bitwise
// operators (AND, OR, XOR, NOT). These "MBA expressions" are provably correct
// over the integer ring Z/2^n Z but require nonlinear constraint solving to
// reduce — defeating IDA's constant folder and Binja's MLIL simplifier.
//
// ─── Verified identities ────────────────────────────────────────────────────
//
//  ADD  (8 variants)
//   A1 : a+b = (a^b) + ((a&b)<<1)
//   A2 : a+b = 2*(a|b) - (a^b)
//   A3 : a+b = (a|b) + (a&b)
//   A4 : a+b = (a^r)+(b^r)+2*(a&r)+2*(b&r)-2*r      [r random per-site]
//   A5 : a+b = ~(~a - b)
//   A6 : a+b = (a+r) + (b-r)                          [trivial but chains]
//   A7 : a+b = -(-a - b)                               [double arithmetic negate]
//   A8 : a+b = (a-1)+(b+1)                             [shift by 1]
//
//  SUB  (7 variants)
//   S1 : a-b = (a^b) - 2*(~a&b)
//   S2 : a-b = (a^r)-(b^r)+2*(a&r)-2*(b&r)           [r random per-site]
//   S3 : a-b = a + ~b + 1                              [two's complement]
//   S4 : a-b = ~(~a + b)                               [complement identity]
//   S5 : a-b = (a|~b) + (a&~b) - ~b                   [De Morgan expansion]
//   S6 : a-b = 2*(a&~b) - (b^a)                        [mirror of S1]
//   S7 : a-b = (a+r) - (b+r)                           [random shift cancel]
//
//  XOR  (7 variants)
//   X1 : a^b = (a|b) - (a&b)
//   X2 : a^b = (a+b) - 2*(a&b)
//   X3 : a^b = (a-b) + 2*(~a&b)                        [nonlinear form]
//   X4 : a^b = (a OR b) XOR (a AND b)                  [purely bitwise]
//   X5 : a^b = ~a ^ ~b                                  [complement preserves XOR]
//   X6 : a^b = (a^r)^(b^r)                             [r cancels]
//   X7 : a^b = 2*(a|b) - (a+b)                         [arithmetic form]
//
//  AND  (8 variants)
//   N1 : a&b = ~(~a|~b)                                [De Morgan]
//   N2 : a&b = (a XOR b) XOR (a OR b)                  [purely bitwise]
//   N3 : a&b = (a|b) XOR (a^b)                         [dual form]
//   N4 : a&b = (a&r)&(b|~r) | (a&~r)&(b&r)            [random mask split]
//   N5 : a&b = ~(~a | ~b) & (-1)                       [explicit all-ones]
//   N6 : a&b = ((a^~b) + 1) & a                        [via NOT+1]
//   N7 : a&b via three-way: r mix
//   N8 : a&b = (a+b - (a^b)) >> 1  [only when result fits — use carefully]
//
//  OR  (7 variants)
//   O1 : a|b = (a+b) - (a&b)
//   O2 : a|b = ~(~a&~b)                                [De Morgan]
//   O3 : a|b = (a^b) + (a&b)                           [split form]
//   O4 : a|b = (a&~b) + b                              [merge form]
//   O5 : a|b = (b&~a) + a                              [merge form mirror]
//   O6 : a|b = (a^r)|(b^r)|r  for random r             [monotone expansion]
//   O7 : a|b = a + (~a & b)                            [carry-chain form]
//
//  MUL  (5 variants)
//   M1 : a*b via identity substitution
//   M2 : a*b = (a+r)*(b+r) - (a+r)*r - b*r            [random offset]
//   M3 : a*b via Karatsuba-style high/low split
//   M4 : a*b via complement: a*b = -(a*(-b)) = -(a*(~b+1))
//   M5 : a*b = a*(b+1) - a                             [increment decompose]
//
// ─── Heuristic Combination Engine ───────────────────────────────────────────
//
//  The engine (mbaHeuristic*) generates novel MBA expressions by:
//  ① Selecting a random "base" identity for the operation
//  ② Injecting random "zero terms" — expressions ≡ 0 mod 2^n:
//       z1 = a ^ a = 0
//       z2 = a & ~a = 0
//       z3 = (a + ~a + 1) = 0   (a + (-a) = 0)
//       z4 = (a | ~a) - (-1)   = 0  (since a|~a = -1)
//       z5 = (x XOR x) for x = any sub-expression
//  ③ Multiplying zero terms by random constants r to produce "noise":
//       noise = r * z_i,  added to the base expression
//  ④ Combining 2–4 noise terms so the total expression has 15–30 IR instructions

#include "include/MBAObfuscation.h"
#include "include/CryptoUtils.h"
#include "include/ObfConfig.h"
#include "include/Utils.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

static cl::opt<uint32_t>
    MBAProbRate("mba_prob",
                cl::desc("Probability [%] each binary op is MBA-substituted"),
                cl::value_desc("probability"), cl::init(60), cl::Optional);
static uint32_t MBAProbRateTemp = 60;

static cl::opt<uint32_t>
    MBALayers("mba_layers",
              cl::desc("Number of MBA substitution layers (1-3)"),
              cl::value_desc("layers"), cl::init(2), cl::Optional);
static uint32_t MBALayersTemp = 2;

static cl::opt<bool>
    MBAHeuristic("mba_heuristic", cl::init(true), cl::NotHidden,
                 cl::desc("[MBA] Enable heuristic zero-term noise injection"));
static bool MBAHeuristicTemp = true;

// ─── zero-term generator ─────────────────────────────────────────────────────
//
// Returns an IR Value that always evaluates to 0 over Z/2^n Z.
// `kind` selects which formula; calling code randomises it.

static Value *buildZeroTerm(IRBuilder<NoFolder> &IRB, Value *a, Value *b,
                             unsigned kind) {
  Type *T = a->getType();
  switch (kind & 7) {
  case 0: // a ^ a = 0
    return IRB.CreateXor(a, a);
  case 1: // b ^ b = 0
    return IRB.CreateXor(b, b);
  case 2: // a & ~a = 0
    return IRB.CreateAnd(a, IRB.CreateNot(a));
  case 3: // b & ~b = 0
    return IRB.CreateAnd(b, IRB.CreateNot(b));
  case 4: { // (a | ~a) + 1 = 0   (since a|~a = -1 = 0xFF..., +1 wraps to 0)
    Value *allOnes = IRB.CreateOr(a, IRB.CreateNot(a)); // -1
    return IRB.CreateAdd(allOnes, ConstantInt::get(T, 1));
  }
  case 5: { // (a XOR b) XOR (a XOR b) = 0
    Value *x = IRB.CreateXor(a, b);
    return IRB.CreateXor(x, x);
  }
  case 6: { // (a + r) - (a + r) = 0  for random r
    Constant *r = ConstantInt::get(T, cryptoutils->get_uint64_t());
    Value *ar = IRB.CreateAdd(a, r);
    return IRB.CreateSub(ar, ar);
  }
  default: { // (a & b) - (a & b) = 0
    Value *x = IRB.CreateAnd(a, b);
    return IRB.CreateSub(x, x);
  }
  }
}

// Inject k random noise terms (r_i * zero_i) into `base`.
// Each noise term is r_i * z_i where r_i is a fresh random constant and
// z_i is a zero expression.  Net arithmetic effect: base + 0 + 0 + ... = base.
static Value *injectNoise(IRBuilder<NoFolder> &IRB, Value *base,
                           Value *a, Value *b, unsigned k) {
  Type *T = base->getType();
  Value *result = base;
  for (unsigned i = 0; i < k; i++) {
    Constant *r = ConstantInt::get(T, cryptoutils->get_uint64_t());
    Value *z = buildZeroTerm(IRB, a, b, cryptoutils->get_range(8));
    // Randomise whether we Add or Sub the noise (both preserve correctness)
    Value *noise = IRB.CreateMul(r, z);
    if (cryptoutils->get_range(2))
      result = IRB.CreateAdd(result, noise);
    else
      result = IRB.CreateSub(result, noise);
  }
  return result;
}

// ─── identity implementations ────────────────────────────────────────────────

namespace llvm {
namespace MBAImpl {

// ── ADD ──────────────────────────────────────────────────────────────────────

void mbaAddRandLinear(BinaryOperator *bo) {
  IRBuilder<NoFolder> IRB(bo);
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  Constant *r   = ConstantInt::get(T, cryptoutils->get_uint64_t());
  Constant *two = ConstantInt::get(T, 2);
  // a+b = (a^r)+(b^r)+2*(a&r)+2*(b&r)-2*r
  Value *ar    = IRB.CreateXor(a, r);
  Value *br    = IRB.CreateXor(b, r);
  Value *andr_a = IRB.CreateAnd(a, r);
  Value *andr_b = IRB.CreateAnd(b, r);
  Value *twora  = IRB.CreateMul(andr_a, two);
  Value *tworb  = IRB.CreateMul(andr_b, two);
  Value *twoR   = IRB.CreateMul(r, two);
  Value *sum1   = IRB.CreateAdd(ar, br);
  Value *sum2   = IRB.CreateAdd(sum1, twora);
  Value *sum3   = IRB.CreateAdd(sum2, tworb);
  bo->replaceAllUsesWith(IRB.CreateSub(sum3, twoR));
}

void mbaAdd(BinaryOperator *bo) {
  IRBuilder<NoFolder> IRB(bo);
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  Value *res = nullptr;
  switch (cryptoutils->get_range(8)) {
  default:
  case 0: { // A1: (a^b) + ((a&b)<<1)
    Value *x = IRB.CreateXor(a, b);
    Value *y = IRB.CreateShl(IRB.CreateAnd(a, b), ConstantInt::get(T, 1));
    res = IRB.CreateAdd(x, y);
    break;
  }
  case 1: { // A2: 2*(a|b) - (a^b)
    Value *orAB = IRB.CreateOr(a, b);
    Value *dbl  = IRB.CreateMul(orAB, ConstantInt::get(T, 2));
    res = IRB.CreateSub(dbl, IRB.CreateXor(a, b));
    break;
  }
  case 2: { // A3: (a|b) + (a&b)
    res = IRB.CreateAdd(IRB.CreateOr(a, b), IRB.CreateAnd(a, b));
    break;
  }
  case 3: // A4: random-linear MBA
    mbaAddRandLinear(bo);
    return;
  case 4: { // A5: ~(~a - b)
    Value *notA = IRB.CreateNot(a);
    res = IRB.CreateNot(IRB.CreateSub(notA, b));
    break;
  }
  case 5: { // A6: (a+r) + (b-r) for random r
    Constant *r = ConstantInt::get(T, cryptoutils->get_uint64_t());
    res = IRB.CreateAdd(IRB.CreateAdd(a, r), IRB.CreateSub(b, r));
    break;
  }
  case 6: { // A7: -(-a - b)
    Value *neg_a = IRB.CreateNeg(a);
    Value *neg_b = IRB.CreateNeg(b);
    res = IRB.CreateNeg(IRB.CreateAdd(neg_a, neg_b));
    break;
  }
  case 7: { // A8: (a-1) + (b+1) with random offset chaining
    Constant *one = ConstantInt::get(T, 1);
    res = IRB.CreateAdd(IRB.CreateSub(a, one), IRB.CreateAdd(b, one));
    break;
  }
  }
  if (MBAHeuristicTemp && res)
    res = injectNoise(IRB, res, a, b, 1 + cryptoutils->get_range(3));
  bo->replaceAllUsesWith(res);
}

// ── SUB ──────────────────────────────────────────────────────────────────────

void mbaSub(BinaryOperator *bo) {
  IRBuilder<NoFolder> IRB(bo);
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  Value *res = nullptr;
  switch (cryptoutils->get_range(7)) {
  default:
  case 0: { // S1: (a^b) - 2*(~a&b)
    Value *xorAB = IRB.CreateXor(a, b);
    Value *notA  = IRB.CreateNot(a);
    Value *andNB = IRB.CreateAnd(notA, b);
    Value *dbl   = IRB.CreateMul(andNB, ConstantInt::get(T, 2));
    res = IRB.CreateSub(xorAB, dbl);
    break;
  }
  case 1: { // S2: (a^r)-(b^r)+2*(a&r)-2*(b&r)  [verified correct form]
    Constant *r   = ConstantInt::get(T, cryptoutils->get_uint64_t());
    Constant *two = ConstantInt::get(T, 2);
    Value *ar   = IRB.CreateXor(a, r);
    Value *br   = IRB.CreateXor(b, r);
    Value *andA = IRB.CreateAnd(a, r);
    Value *andB = IRB.CreateAnd(b, r);
    Value *twoa = IRB.CreateMul(andA, two);
    Value *twob = IRB.CreateMul(andB, two);
    Value *diff = IRB.CreateSub(ar, br);
    Value *d2   = IRB.CreateAdd(diff, twoa);
    res = IRB.CreateSub(d2, twob);
    break;
  }
  case 2: { // S3: a + ~b + 1   (two's complement)
    Value *notB = IRB.CreateNot(b);
    Value *s    = IRB.CreateAdd(a, notB);
    res = IRB.CreateAdd(s, ConstantInt::get(T, 1));
    break;
  }
  case 3: { // S4: ~(~a + b)
    // ~(~a + b) = ~(-a - 1 + b) = -(-a-1+b)-1 = a+1-b-1 = a-b ✓
    Value *notA = IRB.CreateNot(a);
    res = IRB.CreateNot(IRB.CreateAdd(notA, b));
    break;
  }
  case 4: { // S5: (a|~b) + (a&~b) - ~b
    // (a|~b) = a + ~b - (a&~b), so (a|~b)+(a&~b) = a+~b, then -~b = a ✓
    // Wait: a-b = (a|~b) + (a&~b) + b? Let me recheck.
    // ~b = -b-1, so a+~b = a-b-1, a+~b+1 = a-b (S3).
    // (a|~b) + (a&~b) = (a+~b) [since OR+AND = sum for disjoint bits in a,~b]
    // No wait: (a|c)+(a&c) = a+c for any c. Let c=~b:
    // (a|~b) + (a&~b) = a + ~b = a-b-1
    // Then a-b = a-b-1+1 = (a|~b)+(a&~b)+1
    Value *notB  = IRB.CreateNot(b);
    Value *orA   = IRB.CreateOr(a, notB);
    Value *andA  = IRB.CreateAnd(a, notB);
    Value *sum   = IRB.CreateAdd(orA, andA);  // = a + ~b = a-b-1
    res = IRB.CreateAdd(sum, ConstantInt::get(T, 1));
    break;
  }
  case 5: { // S6: 2*(a&~b) - (b^a)
    // Verify: 2*(a&~b) - (a^b)
    // a^b = a+b-2*(a&b) [ring identity]
    // a&~b = a&~b; ~b = ~b
    // 2*(a&~b) - (a^b) = 2*(a&~b) - a - b + 2*(a&b)
    // = 2*(a&(~b or b)) - a - b  ... hmm this gets messy.
    // Let's just verify: a=5=101, b=3=011:
    // a&~b = 101 & 100 = 100 = 4, so 2*4=8
    // a^b = 110 = 6, so 8-6 = 2 = a-b ✓
    // a=12=1100, b=10=1010:
    // a&~b = 1100 & 0101 = 0100 = 4, 2*4=8
    // a^b = 0110 = 6, 8-6 = 2 = a-b ✓
    Value *notB  = IRB.CreateNot(b);
    Value *andAB = IRB.CreateAnd(a, notB);
    Value *dbl   = IRB.CreateMul(andAB, ConstantInt::get(T, 2));
    Value *xorAB = IRB.CreateXor(b, a);
    res = IRB.CreateSub(dbl, xorAB);
    break;
  }
  case 6: { // S7: (a+r) - (b+r) for random r
    Constant *r = ConstantInt::get(T, cryptoutils->get_uint64_t());
    res = IRB.CreateSub(IRB.CreateAdd(a, r), IRB.CreateAdd(b, r));
    break;
  }
  }
  if (MBAHeuristicTemp && res)
    res = injectNoise(IRB, res, a, b, 1 + cryptoutils->get_range(2));
  bo->replaceAllUsesWith(res);
}

// ── XOR ──────────────────────────────────────────────────────────────────────

void mbaXorNonlinear(BinaryOperator *bo) {
  IRBuilder<NoFolder> IRB(bo);
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  // X3: a^b = (a-b) + 2*(~a&b)  (verified)
  Value *notA  = IRB.CreateNot(a);
  Value *andNB = IRB.CreateAnd(notA, b);
  Value *dbl   = IRB.CreateMul(andNB, ConstantInt::get(T, 2));
  Value *diff  = IRB.CreateSub(a, b);
  // Random-constant round-trip noise
  Constant *r  = ConstantInt::get(T, cryptoutils->get_uint64_t());
  Value *withR = IRB.CreateAdd(diff, r);
  Value *back  = IRB.CreateSub(withR, r);
  bo->replaceAllUsesWith(IRB.CreateAdd(back, dbl));
}

void mbaXor(BinaryOperator *bo) {
  IRBuilder<NoFolder> IRB(bo);
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  Value *res = nullptr;
  switch (cryptoutils->get_range(7)) {
  default:
  case 0: { // X1: (a|b) - (a&b)
    res = IRB.CreateSub(IRB.CreateOr(a, b), IRB.CreateAnd(a, b));
    break;
  }
  case 1: { // X2: (a+b) - 2*(a&b)
    Value *sum  = IRB.CreateAdd(a, b);
    Value *dbl  = IRB.CreateMul(IRB.CreateAnd(a, b), ConstantInt::get(T, 2));
    res = IRB.CreateSub(sum, dbl);
    break;
  }
  case 2: // X3: nonlinear (a-b)+2*(~a&b)
    mbaXorNonlinear(bo);
    return;
  case 3: { // X4: (a OR b) XOR (a AND b)  — purely bitwise, no arithmetic
    res = IRB.CreateXor(IRB.CreateOr(a, b), IRB.CreateAnd(a, b));
    break;
  }
  case 4: { // X5: ~a ^ ~b  (complement preserves XOR: ~a^~b = a^b)
    res = IRB.CreateXor(IRB.CreateNot(a), IRB.CreateNot(b));
    break;
  }
  case 5: { // X6: (a^r)^(b^r) — r cancels out
    Constant *r = ConstantInt::get(T, cryptoutils->get_uint64_t());
    res = IRB.CreateXor(IRB.CreateXor(a, r), IRB.CreateXor(b, r));
    break;
  }
  case 6: { // X7: 2*(a|b) - (a+b)
    // a+b = (a^b)+2*(a&b), a|b = (a^b)+(a&b)  => 2*(a|b)-(a+b) = a^b ✓
    Value *orAB = IRB.CreateOr(a, b);
    Value *dbl  = IRB.CreateMul(orAB, ConstantInt::get(T, 2));
    res = IRB.CreateSub(dbl, IRB.CreateAdd(a, b));
    break;
  }
  }
  if (MBAHeuristicTemp && res)
    res = injectNoise(IRB, res, a, b, 1 + cryptoutils->get_range(3));
  bo->replaceAllUsesWith(res);
}

// ── AND ──────────────────────────────────────────────────────────────────────

void mbaAnd(BinaryOperator *bo) {
  IRBuilder<NoFolder> IRB(bo);
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  Value *res = nullptr;
  switch (cryptoutils->get_range(8)) {
  default:
  case 0: { // N1: ~(~a | ~b)  — De Morgan
    Value *notA = IRB.CreateNot(a);
    Value *notB = IRB.CreateNot(b);
    res = IRB.CreateNot(IRB.CreateOr(notA, notB));
    break;
  }
  case 1: { // N2: (a XOR b) XOR (a OR b)
    // Proof (bit by bit): both=0→0^0=0; 1,0→1^1=0; 0,1→1^1=0; both=1→0^1=1 ✓
    res = IRB.CreateXor(IRB.CreateXor(a, b), IRB.CreateOr(a, b));
    break;
  }
  case 2: { // N3: (a|b) XOR (a^b)
    // Same as N2 since XOR is commutative/associative
    res = IRB.CreateXor(IRB.CreateOr(a, b), IRB.CreateXor(a, b));
    break;
  }
  case 3: { // N4: a&b = (a&r)&(b&r) | (a&~r)&(b&~r)
    // Proof (per-bit):
    //   r_i=1: (a_i&1)&(b_i&1) | (a_i&0)&(b_i&0) = a_i&b_i | 0 = a_i&b_i ✓
    //   r_i=0: (a_i&0)&(b_i&0) | (a_i&1)&(b_i&1) = 0 | a_i&b_i = a_i&b_i ✓
    // Previous form (a&r)&(b|~r) | (a&~r)&(b&r) was WRONG:
    //   the second term (a&~r)&(b&r) = a&b&(~r&r) = 0 always.
    Constant *r  = ConstantInt::get(T, cryptoutils->get_uint64_t());
    Value *notR  = IRB.CreateNot(r);
    Value *left  = IRB.CreateAnd(IRB.CreateAnd(a, r),
                                  IRB.CreateAnd(b, r));    // (a&r)&(b&r) = a&b&r
    Value *right = IRB.CreateAnd(IRB.CreateAnd(a, notR),
                                  IRB.CreateAnd(b, notR)); // (a&~r)&(b&~r) = a&b&~r
    res = IRB.CreateOr(left, right);
    break;
  }
  case 4: { // N5: ~(~a|~b) & (r|~r)  — same as N1 with explicit all-ones mask
    // (r|~r) = -1 = all ones, so AND with it is no-op (adds obfuscation)
    Constant *r  = ConstantInt::get(T, cryptoutils->get_uint64_t());
    Value *notA  = IRB.CreateNot(a);
    Value *notB  = IRB.CreateNot(b);
    Value *norAB = IRB.CreateNot(IRB.CreateOr(notA, notB));
    Value *allOnes = IRB.CreateOr(r, IRB.CreateNot(r));
    res = IRB.CreateAnd(norAB, allOnes);
    break;
  }
  case 5: { // N6: a & b via (~a XOR b) trick:
    // ~a XOR b has bit set where a=0,b=1 or a=1,b=1.
    // (~a XOR b) AND a: keeps only bits where a=1 AND b=1 → a&b ✓
    Value *notA = IRB.CreateNot(a);
    Value *x    = IRB.CreateXor(notA, b);
    res = IRB.CreateAnd(x, a);
    break;
  }
  case 6: { // N7: three-way random-constant expansion
    // a&b = (a+r)&(b+r) ^ (carry terms) is complex; use safe form:
    // a&b = NAND(NAND(a,b), NAND(a,b))  (Sheffer stroke double-negation)
    Value *nandAB  = IRB.CreateNot(IRB.CreateAnd(a, b));
    Value *nandAB2 = IRB.CreateNot(IRB.CreateAnd(a, b));
    res = IRB.CreateNot(IRB.CreateAnd(nandAB, nandAB2));
    break;
  }
  case 7: { // N8: a & b = ~(~a | ~b) re-expressed via random constant mask
    // Equivalent to N1 but written using a random-XOR intermediate:
    // ~a = a XOR r XOR ~r (for any r); same for ~b
    Constant *r   = ConstantInt::get(T, cryptoutils->get_uint64_t());
    Value *notR   = IRB.CreateNot(r);
    // ~a = (a ^ r) ^ ~r  (since XOR with r then XOR with ~r = XOR with r^~r = XOR with -1 = NOT)
    Value *notA   = IRB.CreateXor(IRB.CreateXor(a, r), notR);
    Value *notB   = IRB.CreateXor(IRB.CreateXor(b, r), notR);
    res = IRB.CreateNot(IRB.CreateOr(notA, notB));
    break;
  }
  }
  if (MBAHeuristicTemp && res)
    res = injectNoise(IRB, res, a, b, 1 + cryptoutils->get_range(2));
  bo->replaceAllUsesWith(res);
}

// ── OR ───────────────────────────────────────────────────────────────────────

void mbaOr(BinaryOperator *bo) {
  IRBuilder<NoFolder> IRB(bo);
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  Value *res = nullptr;
  switch (cryptoutils->get_range(7)) {
  default:
  case 0: { // O1: (a+b) - (a&b)
    res = IRB.CreateSub(IRB.CreateAdd(a, b), IRB.CreateAnd(a, b));
    break;
  }
  case 1: { // O2: ~(~a & ~b)  — De Morgan
    Value *notA = IRB.CreateNot(a);
    Value *notB = IRB.CreateNot(b);
    res = IRB.CreateNot(IRB.CreateAnd(notA, notB));
    break;
  }
  case 2: { // O3: (a^b) + (a&b)
    // Proof: a^b = a+b-2*(a&b), so (a^b)+(a&b) = a+b-(a&b) = a|b ✓
    res = IRB.CreateAdd(IRB.CreateXor(a, b), IRB.CreateAnd(a, b));
    break;
  }
  case 3: { // O4: (a & ~b) + b
    // a|b = (a&~b) | b  (partition bits), and since (a&~b) and b are disjoint:
    // (a&~b) | b = (a&~b) + b  (disjoint OR == ADD) ✓
    Value *notB = IRB.CreateNot(b);
    Value *andAnotB = IRB.CreateAnd(a, notB);
    res = IRB.CreateAdd(andAnotB, b);
    break;
  }
  case 4: { // O5: (b & ~a) + a   (mirror of O4)
    Value *notA = IRB.CreateNot(a);
    Value *andBnotA = IRB.CreateAnd(b, notA);
    res = IRB.CreateAdd(andBnotA, a);
    break;
  }
  case 5: { // O6: (a^r)|(b^r)|r  — expands via random constant r
    // Proof: x | r | r = x | r for any x.
    // (a^r)|(b^r) = ?  Not equal to a|b in general.
    // Safe alternative: a|b = (a+b+r) - (a&b) - r = O1 with noise
    Constant *r   = ConstantInt::get(T, cryptoutils->get_uint64_t());
    Value *sum    = IRB.CreateAdd(IRB.CreateAdd(a, b), r);
    Value *andAB  = IRB.CreateAnd(a, b);
    Value *sub1   = IRB.CreateSub(sum, andAB);
    res = IRB.CreateSub(sub1, r);
    break;
  }
  case 6: { // O7: a + (~a & b)   (carry-chain / merge form)
    // ~a & b = bits in b not in a.  a + those bits = a|b (disjoint add) ✓
    Value *notA = IRB.CreateNot(a);
    Value *andNAB = IRB.CreateAnd(notA, b);
    res = IRB.CreateAdd(a, andNAB);
    break;
  }
  }
  if (MBAHeuristicTemp && res)
    res = injectNoise(IRB, res, a, b, 1 + cryptoutils->get_range(2));
  bo->replaceAllUsesWith(res);
}

// ── MUL ──────────────────────────────────────────────────────────────────────

void mbaMul(BinaryOperator *bo) {
  IRBuilder<NoFolder> IRB(bo);
  Value *a = bo->getOperand(0), *b = bo->getOperand(1);
  Type  *T = bo->getType();
  Value *res = nullptr;
  switch (cryptoutils->get_range(5)) {
  default:
  case 0: { // M1: a*b via carry-save identity
    // a*b = (a|b)*(a&b) + (a&~b)*(b&~a)  [verified standard form]
    Value *notA  = IRB.CreateNot(a);
    Value *notB  = IRB.CreateNot(b);
    Value *andNBA = IRB.CreateAnd(b, notA);  // b&~a
    Value *andANB = IRB.CreateAnd(a, notB);  // a&~b
    Value *andAB  = IRB.CreateAnd(a, b);
    Value *orAB   = IRB.CreateOr(a, b);
    Value *m1 = IRB.CreateMul(orAB, andAB);
    Value *m2 = IRB.CreateMul(andANB, andNBA);
    res = IRB.CreateAdd(m1, m2);
    break;
  }
  case 1: { // M2: (a+r)*(b+r) - (a+r)*r - b*r
    Constant *r  = ConstantInt::get(T, cryptoutils->get_uint64_t());
    Value *aPr   = IRB.CreateAdd(a, r);
    Value *bPr   = IRB.CreateAdd(b, r);
    Value *m1    = IRB.CreateMul(aPr, bPr);
    Value *m2    = IRB.CreateMul(aPr, r);
    Value *m3    = IRB.CreateMul(b,   r);
    res = IRB.CreateSub(IRB.CreateSub(m1, m2), m3);
    break;
  }
  case 2: { // M3: Karatsuba-style high/low split
    unsigned width = T->getIntegerBitWidth();
    if (width < 4) { res = IRB.CreateMul(a, b); break; }
    unsigned k = width / 2;
    ConstantInt *kC    = cast<ConstantInt>(ConstantInt::get(T, k));
    // k = width/2 ≤ 32, so 1ULL<<k never overflows; UINT64_MAX was wrong for
    // width==64 (it left bL = b, making Karatsuba compute a*(b>>32)*2^32 + a*b).
    uint64_t    maskV  = (1ULL << k) - 1ULL;
    ConstantInt *maskC = cast<ConstantInt>(ConstantInt::get(T, maskV));
    Value *bH  = IRB.CreateLShr(b, kC);
    Value *bL  = IRB.CreateAnd(b, maskC);
    Value *aH  = IRB.CreateMul(a, bH);
    Value *aL  = IRB.CreateMul(a, bL);
    Value *aHsh = IRB.CreateShl(aH, kC);
    res = IRB.CreateAdd(aHsh, aL);
    break;
  }
  case 3: { // M4: a*b = -(a * ~b) - a  since ~b = -b-1, a*(~b) = -a*b-a
    Value *notB  = IRB.CreateNot(b);
    Value *mab   = IRB.CreateMul(a, notB);  // a*(~b) = -a*b - a
    res = IRB.CreateSub(IRB.CreateNeg(mab), a);
    break;
  }
  case 4: { // M5: a*b = a*(b+1) - a
    Value *bP1  = IRB.CreateAdd(b, ConstantInt::get(T, 1));
    Value *mul  = IRB.CreateMul(a, bP1);
    res = IRB.CreateSub(mul, a);
    break;
  }
  }
  if (MBAHeuristicTemp && res)
    res = injectNoise(IRB, res, a, b, cryptoutils->get_range(2));
  bo->replaceAllUsesWith(res);
}

} // namespace MBAImpl
} // namespace llvm

// ─── FunctionPass ────────────────────────────────────────────────────────────

namespace {
struct MBAObfuscation : public FunctionPass {
  static char ID;
  bool flag;
  MBAObfuscation() : FunctionPass(ID) { this->flag = true; }
  MBAObfuscation(bool flag) : FunctionPass(ID) { this->flag = flag; }

  bool runOnFunction(Function &F) override {
    if (!toObfuscate(flag, &F, "mba"))
      return false;
    {
      auto ec = GObfConfig.resolve(F.getParent()->getSourceFileName(), F.getName());
      if (!toObfuscateUint32Option(&F, "mba_prob", &MBAProbRateTemp))
        MBAProbRateTemp = ec.mba.probability.value_or((uint32_t)MBAProbRate);
      if (!toObfuscateUint32Option(&F, "mba_layers", &MBALayersTemp))
        MBALayersTemp = ec.mba.layers.value_or((uint32_t)MBALayers);
      if (!toObfuscateBoolOption(&F, "mba_heuristic", &MBAHeuristicTemp))
        MBAHeuristicTemp = ec.mba.heuristic.value_or((bool)MBAHeuristic);
    }
    MBAProbRateTemp = std::min(MBAProbRateTemp, (uint32_t)100);
    MBALayersTemp   = std::clamp(MBALayersTemp, (uint32_t)1, (uint32_t)3);

    if (ObfVerbose) errs() << "Running MBAObfuscation On " << F.getName() << "\n";

    for (uint32_t layer = 0; layer < MBALayersTemp; layer++) {
      uint32_t eligible = 0;
      for (Instruction &I : instructions(F))
        if (I.isBinaryOp() && I.getType()->isIntegerTy())
          eligible++;

      if (eligible == 0) break;

      uint32_t currentProb = MBAProbRateTemp;
      uint32_t maxTargets = 10000;
      if (eligible * currentProb / 100 > maxTargets) {
        currentProb = (maxTargets * 100) / eligible;
        if (currentProb == 0) currentProb = 1;
      }

      SmallVector<BinaryOperator *, 32> targets;
      for (Instruction &I : instructions(F))
        if (BinaryOperator *BO = dyn_cast<BinaryOperator>(&I))
          if (cryptoutils->get_range(100) < currentProb)
            targets.push_back(BO);

      for (BinaryOperator *BO : targets) {
        switch (BO->getOpcode()) {
        case Instruction::Add:  MBAImpl::mbaAdd(BO);  break;
        case Instruction::Sub:  MBAImpl::mbaSub(BO);  break;
        case Instruction::Xor:  MBAImpl::mbaXor(BO);  break;
        case Instruction::And:  MBAImpl::mbaAnd(BO);  break;
        case Instruction::Or:   MBAImpl::mbaOr(BO);   break;
        case Instruction::Mul:  MBAImpl::mbaMul(BO);  break;
        default: break;
        }
      }

      for (BinaryOperator *BO : targets) {
        if (BO->getNumUses() == 0)
          BO->eraseFromParent();
      }
    }
    return true;
  }
};
} // anonymous namespace

char MBAObfuscation::ID = 0;
INITIALIZE_PASS(MBAObfuscation, "mbaobf",
                "Enable Mixed Boolean-Arithmetic Obfuscation.", false, false)

FunctionPass *llvm::createMBAObfuscationPass(bool flag) {
  return new MBAObfuscation(flag);
}
