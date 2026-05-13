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

#ifndef _OBFUSCATION_H_
#define _OBFUSCATION_H_

#include "include/AntiClassDump.h"
#include "include/AntiDebugging.h"
#include "include/AntiHook.h"
#include "include/BogusControlFlow.h"
#include "include/ConstantEncryption.h"
#include "include/CryptoUtils.h"
#include "include/Flattening.h"
#include "include/FunctionCallObfuscate.h"
#include "include/FunctionWrapper.h"
#include "include/IndirectBranch.h"
#include "include/Split.h"
#include "include/StringEncryption.h"
#include "include/Substitution.h"
#include "llvm/Support/Timer.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

namespace llvm {

class ObfuscationPass : public PassInfoMixin<ObfuscationPass> {
public:
  ObfuscationPass() {}
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
  static bool isRequired() { return true; }
};

ModulePass *createObfuscationLegacyPass();
void initializeObfuscationPass(PassRegistry &Registry);

} // namespace llvm

#endif
