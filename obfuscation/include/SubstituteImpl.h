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

#ifndef _SUBSTITUTE_IMPL_H
#define _SUBSTITUTE_IMPL_H

#include "llvm/IR/InstrTypes.h"

namespace llvm {

namespace SubstituteImpl {

void substituteAdd(BinaryOperator *bo);
void substituteSub(BinaryOperator *bo);
void substituteAnd(BinaryOperator *bo);
void substituteOr(BinaryOperator *bo);
void substituteXor(BinaryOperator *bo);
void substituteMul(BinaryOperator *bo);
void substituteShl(BinaryOperator *bo);
void substituteLShr(BinaryOperator *bo);
// AShr: uses the identity (a ^ r) >>s k ^ (r >>s k) == a >>s k,
// which holds because XOR distributes over arithmetic right-shift
// (sign-extension bits are a function of the XOR of the sign bits).
void substituteAShr(BinaryOperator *bo);

} // namespace SubstituteImpl

} // namespace llvm

#endif
