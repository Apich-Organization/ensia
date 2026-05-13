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

#ifndef _VECTOR_OBFUSCATION_H_
#define _VECTOR_OBFUSCATION_H_

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"

namespace llvm {

// VectorObfuscation: lifts scalar integer operations into SIMD vector lanes.
//
// Strategy — Scalar-to-Vector Expansion:
//   For each target BinaryOperator (add/sub/xor/and/or/mul) on integer types:
//     1. Create a <LANES x iN> vector (LANES = 4 default, 8 or 16 with annotation).
//     2. Insert real operands into a randomly chosen lane K.
//     3. Fill remaining lanes with compile-time random noise values.
//     4. Emit the vector operation.
//     5. Extract result from lane K.
//
// IDA / Binja decompiler impact:
//   • IDA outputs _mm_add_epi32 / _mm256_add_epi32 wrappers — HLIL is bloated.
//   • Binja MLIL cannot lift insertelement/extractelement chains to scalars
//     reliably when noise lanes are involved — produces opaque MLIL expressions.
//   • On ARM targets, maps to NEON vadd.i32 etc. — equal decompiler confusion.
//
// Width control:
//   Default : <4 x i32>  (128-bit, SSE2 / NEON)
//   Annotated "ollvm-simd=256" : <8 x i32>  (256-bit, AVX2)
//   Annotated "ollvm-simd=512" : <16 x i32> (512-bit, AVX-512)
//
// The pass gracefully handles i8/i16/i64 by choosing the smallest vector type
// that contains the scalar integer. Mixed-width ops fall back to i32 promotion.
FunctionPass *createVectorObfuscationPass(bool flag);
void initializeVectorObfuscationPass(PassRegistry &Registry);

} // namespace llvm

#endif // _VECTOR_OBFUSCATION_H_
