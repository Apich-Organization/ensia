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

#ifndef _MBA_OBFUSCATION_H_
#define _MBA_OBFUSCATION_H_

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"

namespace llvm {

// MBA pass: replaces binary ops with Mixed Boolean-Arithmetic equivalents.
// Multi-term nonlinear MBA expressions defeat IDA/Binja constant folding
// and symbolic execution via exponential term explosion.
FunctionPass *createMBAObfuscationPass(bool flag);
void initializeMBAObfuscationPass(PassRegistry &Registry);

// Internal namespace for multi-layer MBA substitution primitives
namespace MBAImpl {

// Apply a random 2-4 term linear MBA identity for ADD
// Identities are verifiably correct over all inputs (bitwise ring).
void mbaAdd(BinaryOperator *bo);

// Apply a random linear MBA identity for SUB
void mbaSub(BinaryOperator *bo);

// Apply a random MBA identity for XOR
void mbaXor(BinaryOperator *bo);

// Apply a random MBA identity for AND
void mbaAnd(BinaryOperator *bo);

// Apply a random MBA identity for OR
void mbaOr(BinaryOperator *bo);

// Apply a random-constant linear MBA for ADD with injected random term r:
//   a + b = (a ^ r) + (b ^ r) + 2*(a & r) + 2*(b & r) - 2*r
// r is a fresh random compile-time constant; forces multi-operand IR chains.
void mbaAddRandLinear(BinaryOperator *bo);

// Nonlinear 3-term MBA for XOR:
//   a ^ b = (a - b) + 2*(~a & b)  [verified correct]
void mbaXorNonlinear(BinaryOperator *bo);

// Apply a random MBA identity for MUL (5 variants incl. Karatsuba split)
void mbaMul(BinaryOperator *bo);

} // namespace MBAImpl

} // namespace llvm

#endif // _MBA_OBFUSCATION_H_
