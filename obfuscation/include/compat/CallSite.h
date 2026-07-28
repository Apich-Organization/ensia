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

#ifndef ENSIA_COMPAT_CALLSITE_H
#define ENSIA_COMPAT_CALLSITE_H

#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstrTypes.h"

namespace llvm {

class CallSite {
  CallBase *CB = nullptr;
public:
  CallSite() : CB(nullptr) {}
  CallSite(Instruction *I) : CB(dyn_cast_or_null<CallBase>(I)) {}
  CallSite(Value *V) : CB(dyn_cast_or_null<CallBase>(V)) {}
  CallSite(CallBase *CB) : CB(CB) {}

  bool isCall() const { return CB && isa<CallInst>(CB); }
  bool isInvoke() const { return CB && isa<InvokeInst>(CB); }
  bool isCallOrInvoke() const { return CB != nullptr; }
  explicit operator bool() const { return CB != nullptr; }

  CallBase *getInstruction() const { return CB; }
  CallBase *operator->() const { return CB; }
  Instruction &operator*() const { return *CB; }

  Function *getCalledFunction() const { return CB ? CB->getCalledFunction() : nullptr; }
  Value *getCalledOperand() const { return CB ? CB->getCalledOperand() : nullptr; }
  Value *getCalledValue() const { return CB ? CB->getCalledOperand() : nullptr; }

  unsigned getNumArgOperands() const { return CB ? CB->arg_size() : 0; }
  unsigned arg_size() const { return CB ? CB->arg_size() : 0; }
  Value *getArgOperand(unsigned i) const { return CB ? CB->getArgOperand(i) : nullptr; }

  CallingConv::ID getCallingConv() const { return CB ? CB->getCallingConv() : CallingConv::C; }
  Type *getType() const { return CB ? CB->getType() : nullptr; }
  Intrinsic::ID getIntrinsicID() const { return CB ? CB->getIntrinsicID() : Intrinsic::not_intrinsic; }

  void setCalledFunction(Value *V) {
    if (CB) CB->setCalledOperand(V);
  }
};

} // namespace llvm

#endif // ENSIA_COMPAT_CALLSITE_H
