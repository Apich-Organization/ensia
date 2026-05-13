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

#ifndef _UTILS_H_
#define _UTILS_H_

#include "llvm/IR/Module.h"
#include <string>

namespace llvm {

// Global flag: when true every pass runs at maximum intensity.
// Set by -enable-maxobf in Obfuscation.cpp.
extern bool ObfuscationMaxMode;

// Global flag: when true each pass prints a "Running X On Y" line for every
// function it processes.  Defaults to false because hundreds of stdlib
// functions generate enough output to fill a 64 KB stderr pipe, causing the
// WriteFile syscall to block with 0% CPU (appearing as a deadlock).
// Enable with -obf-verbose on the opt command line.
extern bool ObfVerbose;

// Global flag: when true, Obfuscation.cpp emits one "[OLLVM-Next][Nx]" line
// before and after each major step (StringEncryption, per-function loop,
// ConstantEncryption, IndirectBranch, FunctionWrapper).  Also prints each
// function name and each sub-pass tag inside the per-function loop.
// Maximum output: ~15 lines (module-level) + ~7 lines per function.
// Use -obf-trace on the opt command line to diagnose 0% CPU hangs.
extern bool ObfTrace;

void fixStack(Function *f);
void manuallyLowerSwitches(Function *F);
bool toObfuscate(bool flag, Function *f, std::string attribute);
bool toObfuscateBoolOption(Function *f, std::string option, bool *val);
bool toObfuscateUint32Option(Function *f, std::string option, uint32_t *val);
bool hasApplePtrauth(Module *M);
void FixFunctionConstantExpr(Function *Func);
void turnOffOptimization(Function *f);
void annotation2Metadata(Module &M);
bool readAnnotationMetadata(Function *f, std::string annotation);
void writeAnnotationMetadata(Function *f, std::string annotation);
bool AreUsersInOneFunction(GlobalVariable *GV);

} // namespace llvm

#endif
