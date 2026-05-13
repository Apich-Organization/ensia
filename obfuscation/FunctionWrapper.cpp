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

// FunctionWrapper.cpp — polymorphic function-call obfuscation.
//
// Each call site that opts in is wrapped in a unique intermediate function
// ("proxy") that performs one of several randomised transformations before
// calling the real callee:
//
//  Strategy A — Identity wrapper with random ABI noise:
//    The proxy allocates a random number of dead stack slots, touches them
//    via volatile stores, then calls through.  IDA/Binja cannot easily
//    collapse the indirection because they must prove the slots are dead.
//
//  Strategy B — Argument shuffle wrapper:
//    For integer scalar arguments, the proxy XORs each arg with a
//    per-proxy random constant and XORs back immediately before the call.
//    The call graph edge target is the proxy, not the callee, so static
//    call-graph reconstruction fails to connect the caller to the callee
//    directly.
//
//  Strategy C — Return-value masking wrapper:
//    If the callee returns an integer, the proxy XORs the return value with
//    a compile-time constant (zero-net effect: XOR in callee / XOR out in
//    proxy), making IDA's "return value tracking" produce garbage.
//    NOTE: currently a no-op XOR (key XOR key = 0) so correctness is trivially
//    maintained; the IR still shows an extra XOR that the optimizer will NOT
//    eliminate if called from another compilation unit (separate IR module).
//
// OLLVM-Next fixes:
//  ① Removed usage of deprecated `CS->getCalledValue()` (LLVM 16+).
//    Now uses `CS->getCalledOperand()` via the CallSite compat layer.
//  ② `CS->mutateFunctionType()` replaced with proper operand update.
//  ③ `std::nullopt` branch already correct for LLVM 16+; fallback removed.
//  ④ Each proxy is annotated with "noinline" + "optnone" so the pass pipeline
//    cannot inline or optimise it away.

#include "include/FunctionWrapper.h"
#include "include/CryptoUtils.h"
#include "include/Utils.h"
#include "include/compat/CallSite.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

static cl::opt<uint32_t>
    ProbRate("fw_prob",
             cl::desc("Choose the probability [%] For Each CallSite To Be "
                      "Obfuscated By FunctionWrapper"),
             cl::value_desc("Probability Rate"), cl::init(30), cl::Optional);
static uint32_t ProbRateTemp = 30;

static cl::opt<uint32_t> ObfTimes(
    "fw_times",
    cl::desc(
        "Choose how many time the FunctionWrapper pass loop on a CallSite"),
    cl::value_desc("Number of Times"), cl::init(2), cl::Optional);

// Proxy strategy selector
enum class ProxyStrategy { IdentityNoise, ArgShuffle, RetMask };
static ProxyStrategy pickStrategy() {
  switch (cryptoutils->get_range(3)) {
  case 0:  return ProxyStrategy::IdentityNoise;
  case 1:  return ProxyStrategy::ArgShuffle;
  default: return ProxyStrategy::RetMask;
  }
}

namespace llvm {
struct FunctionWrapper : public ModulePass {
  static char ID;
  bool flag;
  FunctionWrapper() : ModulePass(ID) { this->flag = true; }
  FunctionWrapper(bool flag) : ModulePass(ID) { this->flag = flag; }
  StringRef getPassName() const override { return "FunctionWrapper"; }

  bool runOnModule(Module &M) override {
    SmallVector<CallSite *, 16> callsites;
    for (Function &F : M) {
      if (!toObfuscate(flag, &F, "fw"))
        continue;
      if (ObfVerbose) errs() << "Running FunctionWrapper On " << F.getName() << "\n";
      if (!toObfuscateUint32Option(&F, "fw_prob", &ProbRateTemp))
        ProbRateTemp = ProbRate;
      if (ProbRateTemp > 100) {
        errs() << "FunctionWrapper: -fw_prob must be 0-100\n";
        return false;
      }
      for (Instruction &Inst : instructions(F))
        if ((isa<CallInst>(&Inst) || isa<InvokeInst>(&Inst)))
          if (cryptoutils->get_range(100) <= ProbRateTemp)
            callsites.push_back(new CallSite(&Inst));
    }
    // Collect all created proxy functions and call appendToCompilerUsed ONCE.
    // The old code called appendToCompilerUsed inside HandleCallSite (once per
    // call site).  appendToCompilerUsed reads and rewrites llvm.compiler.used
    // on every call, so N call sites → O(N²) work and O(N²) allocations of
    // temporary GlobalVariable initialisers that pile up in the LLVMContext.
    SmallVector<GlobalValue *, 16> newProxies;
    for (CallSite *CS : callsites)
      for (uint32_t i = 0; i < ObfTimes && CS != nullptr; i++)
        CS = HandleCallSite(CS, M, newProxies);
    if (!newProxies.empty())
      appendToCompilerUsed(M, newProxies);
    return true;
  }

  CallSite *HandleCallSite(CallSite *CS, Module &M,
                           SmallVectorImpl<GlobalValue *> &newProxies) {
    Value *calledFunction = CS->getCalledFunction();
    if (!calledFunction)
      calledFunction = cast<CallBase>(CS->getInstruction())->getCalledOperand()->stripPointerCasts();

    // Filter: only wrap direct calls to named non-intrinsic functions
    if (!calledFunction ||
        (!isa<ConstantExpr>(calledFunction) &&
         !isa<Function>(calledFunction)) ||
        CS->getIntrinsicID() != Intrinsic::not_intrinsic)
      return nullptr;

    SmallVector<unsigned int, 8> byvalArgNums;
    if (Function *tmp = dyn_cast<Function>(calledFunction)) {
#if LLVM_VERSION_MAJOR >= 18
      if (tmp->getName().starts_with("clang."))
#else
      if (tmp->getName().startswith("clang."))
#endif
        return nullptr;
      for (Argument &arg : tmp->args()) {
        if (arg.hasStructRetAttr() || arg.hasSwiftSelfAttr())
          return nullptr;
        if (arg.hasByValAttr())
          byvalArgNums.push_back(arg.getArgNo());
      }
    }

    // Build proxy function type
    SmallVector<Type *, 8> types;
    for (unsigned i = 0; i < CS->getNumArgOperands(); i++)
      types.push_back(CS->getArgOperand(i)->getType());
    FunctionType *ft =
        FunctionType::get(CS->getType(), ArrayRef<Type *>(types), false);

    // Create the proxy with a unique mangled name
    Function *proxy =
        Function::Create(ft, GlobalValue::InternalLinkage,
                         "EnsiaFW_" + std::to_string(cryptoutils->get_uint32_t()),
                         M);
    proxy->setCallingConv(CS->getCallingConv());
    // Prevent inlining / optimisation so the wrapper is not erased
    proxy->addFnAttr(Attribute::NoInline);
    proxy->addFnAttr(Attribute::OptimizeNone);
    newProxies.push_back(proxy);

    BasicBlock *entryBB = BasicBlock::Create(proxy->getContext(), "fw.entry", proxy);
    IRBuilder<> IRB(entryBB);

    ProxyStrategy strat = pickStrategy();

    // Collect proxy arguments
    SmallVector<Value *, 8> callArgs;
    for (Argument &arg : proxy->args()) {
      if (std::find(byvalArgNums.begin(), byvalArgNums.end(),
                    arg.getArgNo()) != byvalArgNums.end()) {
        callArgs.push_back(&arg);
        continue;
      }

      if (strat == ProxyStrategy::ArgShuffle &&
          arg.getType()->isIntegerTy() &&
          !byvalArgNums.empty() == false) {
        // XOR argument with a random constant; XOR back immediately.
        // Net effect: zero. But IR shows 2 XOR ops on the argument.
        uint64_t mask = cryptoutils->get_uint64_t();
        if (arg.getType()->getIntegerBitWidth() < 64)
          mask &= ((1ULL << arg.getType()->getIntegerBitWidth()) - 1ULL);
        Constant *maskC = ConstantInt::get(arg.getType(), mask);
        Value *masked   = IRB.CreateXor(&arg, maskC, "fw.mask");
        Value *unmasked = IRB.CreateXor(masked, maskC, "fw.unmask");
        AllocaInst *slot = IRB.CreateAlloca(arg.getType(), nullptr, "fw.slot");
        IRB.CreateStore(unmasked, slot);
        callArgs.push_back(IRB.CreateLoad(arg.getType(), slot, "fw.arg"));
      } else {
        // Identity: load through a volatile stack slot to pin the value
        AllocaInst *AI = IRB.CreateAlloca(arg.getType(), nullptr, "fw.ai");
        IRB.CreateStore(&arg, AI);
        callArgs.push_back(IRB.CreateLoad(arg.getType(), AI, "fw.lv"));
      }
    }

    // Strategy A: inject random dead stack slots touched via volatile stores
    if (strat == ProxyStrategy::IdentityNoise) {
      unsigned noiseSlots = cryptoutils->get_range(1, 4); // 1-3 noise slots
      for (unsigned n = 0; n < noiseSlots; n++) {
        AllocaInst *ns = IRB.CreateAlloca(Type::getInt64Ty(M.getContext()),
                                          nullptr, "fw.noise");
        uint64_t nval = cryptoutils->get_uint64_t();
        IRB.CreateStore(ConstantInt::get(Type::getInt64Ty(M.getContext()), nval),
                        ns, /*volatile=*/true);
      }
    }

    // Emit the real call
    Value *retval = IRB.CreateCall(
        ft,
        ConstantExpr::getBitCast(cast<Function>(calledFunction),
                                 PointerType::getUnqual(M.getContext())),
        ArrayRef<Value *>(callArgs));

    // Strategy C: mask return value (zero-net XOR)
    if (strat == ProxyStrategy::RetMask && ft->getReturnType()->isIntegerTy()) {
      uint64_t retMask = cryptoutils->get_uint64_t();
      unsigned retBits = ft->getReturnType()->getIntegerBitWidth();
      if (retBits < 64)
        retMask &= ((1ULL << retBits) - 1ULL);
      Constant *rmC = ConstantInt::get(ft->getReturnType(), retMask);
      Value *masked   = IRB.CreateXor(retval, rmC, "fw.retm");
      retval = IRB.CreateXor(masked, rmC, "fw.retu");
    }

    if (ft->getReturnType()->isVoidTy())
      IRB.CreateRetVoid();
    else
      IRB.CreateRet(retval);

    CS->setCalledFunction(proxy);
    Instruction *Inst = CS->getInstruction();
    delete CS;
    return new CallSite(Inst);
  }
};

ModulePass *createFunctionWrapperPass(bool flag) {
  return new FunctionWrapper(flag);
}
} // namespace llvm

char FunctionWrapper::ID = 0;
INITIALIZE_PASS(FunctionWrapper, "funcwra", "Enable FunctionWrapper.", false, false)
