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

#include "include/ConstantEncryption.h"
#include "include/CryptoUtils.h"
#include "include/SubstituteImpl.h"
#include "include/Utils.h"
#include "include/compat/CallSite.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <unordered_set>

using namespace llvm;

// ─── OLLVM-Next: ensemble (k-share) secret sharing ──────────────────────────
//
// Physical motivation — statistical ensemble principle:
//   A thermodynamic ensemble is defined so that no single "particle" (sample)
//   carries the full information; the macrostate only emerges from the full
//   ensemble.  We apply this idea to constant encryption:
//
//   Given constant C, generate k−1 uniform random shares r_1, …, r_{k-1}.
//   Define r_k = C ⊕ r_1 ⊕ … ⊕ r_{k-1}.
//   Then C = r_1 ⊕ r_2 ⊕ … ⊕ r_k  (XOR identity).
//
//   Each individual share r_i is uniformly random and reveals nothing about C
//   (information-theoretically, this is a (k,k)-threshold secret sharing
//   scheme — all k shares are required; k-1 shares give zero information).
//
//   At runtime the generated IR XORs all k global-variable shares together.
//   IDA/Binja cannot reconstruct C without tracing all k load→XOR chains
//   to a single expression — path explosion proportional to k!.
//
// -constenc_kshare=k : number of shares (2 = classic 1-key XOR, 3-5 = good)
// -constenc_feistel   : additionally encrypt through a 4-round Feistel cipher
//   before share-splitting.  Adds a nonlinear layer that pure XOR analysis
//   cannot factor through.

static cl::opt<bool>
    SubstituteXor("constenc_subxor",
                  cl::desc("Substitute xor operator of ConstantEncryption"),
                  cl::value_desc("Substitute xor operator"), cl::init(false),
                  cl::Optional);
static bool SubstituteXorTemp = false;

static cl::opt<uint32_t> SubstituteXorProb(
    "constenc_subxor_prob",
    cl::desc(
        "Choose the probability [%] each xor operator will be Substituted"),
    cl::value_desc("probability rate"), cl::init(40), cl::Optional);
static uint32_t SubstituteXorProbTemp = 40;

static cl::opt<bool>
    ConstToGV("constenc_togv",
              cl::desc("Replace ConstantInt with GlobalVariable"),
              cl::value_desc("ConstantInt to GlobalVariable"), cl::init(false),
              cl::Optional);
static bool ConstToGVTemp = false;

static cl::opt<uint32_t>
    ConstToGVProb("constenc_togv_prob",
                  cl::desc("Choose the probability [%] each ConstantInt will "
                           "replaced with GlobalVariable"),
                  cl::value_desc("probability rate"), cl::init(50),
                  cl::Optional);
static uint32_t ConstToGVProbTemp = 50;

static cl::opt<uint32_t> ObfTimes(
    "constenc_times",
    cl::desc(
        "Choose how many time the ConstantEncryption pass loop on a function"),
    cl::value_desc("Number of Times"), cl::init(1), cl::Optional);
static uint32_t ObfTimesTemp = 1;

static cl::opt<uint32_t> KShareCount(
    "constenc_kshare",
    cl::desc("[ConstantEncryption] Number of XOR shares for ensemble "
             "secret-sharing (2=classic XOR, 3-5 recommended, max 8)"),
    cl::value_desc("k"), cl::init(2), cl::Optional);
static uint32_t KShareCountTemp = 2;

static cl::opt<bool> FeistelTier(
    "constenc_feistel",
    cl::desc("[ConstantEncryption] Apply 4-round Feistel cipher before "
             "share-splitting (adds nonlinear layer defeating XOR analysis)"),
    cl::init(false), cl::Optional);
static bool FeistelTierTemp = false;

namespace llvm {
struct ConstantEncryption : public ModulePass {
  static char ID;
  bool flag;
  bool dispatchonce;
  std::unordered_set<GlobalVariable *> handled_gvs;
  SmallVector<GlobalValue *, 1024> usedGlobals;
  ConstantEncryption(bool flag) : ModulePass(ID) { this->flag = flag; }
  ConstantEncryption() : ModulePass(ID) { this->flag = true; }
  bool shouldEncryptConstant(Instruction *I) {
    if (isa<SwitchInst>(I) || isa<IntrinsicInst>(I) ||
        isa<GetElementPtrInst>(I) || isa<PHINode>(I) || I->isAtomic())
      return false;
    if (AllocaInst *AI = dyn_cast<AllocaInst>(I))
      if (AI->isSwiftError())
        return false;
    if (isa<CallInst>(I) || isa<InvokeInst>(I)) {
      CallSite CS(I);
      if (CS.getCalledFunction() &&
#if LLVM_VERSION_MAJOR >= 18
          CS.getCalledFunction()->getName().starts_with("ensia_")) {
#else
          CS.getCalledFunction()->getName().startswith("ensia_")) {
#endif
        return false;
      }
    }
    if (dispatchonce)
      if (AllocaInst *AI = dyn_cast<AllocaInst>(I)) {
        if (AI->getAllocatedType()->isIntegerTy())
          for (User *U : AI->users())
            if (LoadInst *LI = dyn_cast<LoadInst>(U))
              for (User *LU : LI->users())
                if (isa<CallInst>(LU) || isa<InvokeInst>(LU)) {
                  CallSite CS(LU);
                  Value *calledFunction = CS.getCalledFunction();
                  if (!calledFunction)
                    calledFunction = CS.getCalledValue()->stripPointerCasts();
                  if (!calledFunction ||
                      (!isa<ConstantExpr>(calledFunction) &&
                       !isa<Function>(calledFunction)) ||
                      CS.getIntrinsicID() != Intrinsic::not_intrinsic)
                    continue;
                  if (calledFunction->getName() == "_dispatch_once" ||
                      calledFunction->getName() == "dispatch_once")
                    return false;
                }
      }
    return true;
  }
  bool runOnModule(Module &M) override {
    dispatchonce = M.getFunction("dispatch_once");
    for (Function &F : M)
      if (toObfuscate(flag, &F, "constenc") && !F.isPresplitCoroutine()) {
        if (ObfVerbose) errs() << "Running ConstantEncryption On " << F.getName() << "\n";
        FixFunctionConstantExpr(&F);
        if (!toObfuscateUint32Option(&F, "constenc_times", &ObfTimesTemp))
          ObfTimesTemp = ObfTimes;
        if (!toObfuscateBoolOption(&F, "constenc_togv", &ConstToGVTemp))
          ConstToGVTemp = ConstToGV;
        if (!toObfuscateBoolOption(&F, "constenc_subxor", &SubstituteXorTemp))
          SubstituteXorTemp = SubstituteXor;
        if (!toObfuscateUint32Option(&F, "constenc_subxor_prob",
                                     &SubstituteXorProbTemp))
          SubstituteXorProbTemp = SubstituteXorProb;
        if (!toObfuscateUint32Option(&F, "constenc_kshare", &KShareCountTemp))
          KShareCountTemp = KShareCount;
        if (KShareCountTemp < 2) KShareCountTemp = 2;
        if (KShareCountTemp > 8) KShareCountTemp = 8;
        if (ObfuscationMaxMode) KShareCountTemp = 4;
        if (!toObfuscateBoolOption(&F, "constenc_feistel", &FeistelTierTemp))
          FeistelTierTemp = FeistelTier;
        if (ObfuscationMaxMode) FeistelTierTemp = true;
        if (SubstituteXorProbTemp > 100) {
          errs() << "-constenc_subxor_prob=x must be 0 < x <= 100";
          return false;
        }
        if (!toObfuscateUint32Option(&F, "constenc_togv_prob",
                                     &ConstToGVProbTemp))
          ConstToGVProbTemp = ConstToGVProb;
        if (ConstToGVProbTemp > 100) {
          errs() << "-constenc_togv_prob=x must be 0 < x <= 100";
          return false;
        }
        uint32_t times = ObfTimesTemp;
        while (times) {
          EncryptConstants(F);
          if (ConstToGVTemp) {
            Constant2GlobalVariable(F);
          }
          times--;
        }
      }
    if (!usedGlobals.empty()) {
      appendToCompilerUsed(M, usedGlobals);
      usedGlobals.clear();
    }
    return true;
  }

  bool isDispatchOnceToken(GlobalVariable *GV) {
    if (!dispatchonce)
      return false;
    for (User *U : GV->users()) {
      if (isa<CallInst>(U) || isa<InvokeInst>(U)) {
        CallSite CS(U);
        Value *calledFunction = CS.getCalledFunction();
        if (!calledFunction)
          calledFunction = CS.getCalledValue()->stripPointerCasts();
        if (!calledFunction ||
            (!isa<ConstantExpr>(calledFunction) &&
             !isa<Function>(calledFunction)) ||
            CS.getIntrinsicID() != Intrinsic::not_intrinsic)
          continue;
        if (calledFunction->getName() == "_dispatch_once" ||
            calledFunction->getName() == "dispatch_once") {
          Value *onceToken = U->getOperand(0);
          if (dyn_cast_or_null<GlobalVariable>(
                  onceToken->stripPointerCasts()) == GV)
            return true;
        }
      }
      if (StoreInst *SI = dyn_cast<StoreInst>(U))
        for (User *SU : SI->getPointerOperand()->users())
          if (LoadInst *LI = dyn_cast<LoadInst>(SU))
            for (User *LU : LI->users())
              if (isa<CallInst>(LU) || isa<InvokeInst>(LU)) {
                CallSite CS(LU);
                Value *calledFunction = CS.getCalledFunction();
                if (!calledFunction)
                  calledFunction = CS.getCalledValue()->stripPointerCasts();
                if (!calledFunction ||
                    (!isa<ConstantExpr>(calledFunction) &&
                     !isa<Function>(calledFunction)) ||
                    CS.getIntrinsicID() != Intrinsic::not_intrinsic)
                  continue;
                if (calledFunction->getName() == "_dispatch_once" ||
                    calledFunction->getName() == "dispatch_once")
                  return true;
              }
    }
    return false;
  }

  bool isAtomicLoaded(GlobalVariable *GV) {
    for (User *U : GV->users()) {
      if (LoadInst *LI = dyn_cast<LoadInst>(U)) {
        if (LI->isAtomic())
          return true;
      }
    }
    return false;
  }

  void EncryptConstants(Function &F) {
    SmallVector<std::pair<Instruction *, unsigned>, 64> targets;
    SmallVector<GlobalVariable *, 32> gvTargets;
    
    for (Instruction &I : instructions(F)) {
      if (!shouldEncryptConstant(&I))
        continue;
      CallInst *CI = dyn_cast<CallInst>(&I);
      for (unsigned i = 0; i < I.getNumOperands(); i++) {
        if (CI && CI->isBundleOperand(i))
          continue;
        Value *Op = I.getOperand(i);
        if (isa<ConstantInt>(Op))
          targets.push_back({&I, i});
        if (GlobalVariable *G = dyn_cast<GlobalVariable>(Op))
          if (G->hasInitializer() &&
              (G->hasPrivateLinkage() || G->hasInternalLinkage()) &&
              isa<ConstantInt>(G->getInitializer()))
            gvTargets.push_back(G);
      }
    }
    
    uint32_t eligible = targets.size() + gvTargets.size();
    if (eligible == 0) return;
    
    uint32_t currentProb = 100;
    uint32_t maxTargets = 1000000;
    if (eligible * currentProb / 100 > maxTargets) {
      currentProb = (maxTargets * 100) / eligible;
      if (currentProb == 0) currentProb = 1;
    }

    for (auto &T : targets) {
      if (cryptoutils->get_range(100) < currentProb)
        HandleConstantIntOperand(T.first, T.second);
    }
    for (GlobalVariable *G : gvTargets) {
      if (cryptoutils->get_range(100) < currentProb)
        HandleConstantIntInitializerGV(G);
    }
  }

  void Constant2GlobalVariable(Function &F) {
    Module &M = *F.getParent();
    const DataLayout &DL = M.getDataLayout();
    for (Instruction &I : instructions(F)) {
      if (!shouldEncryptConstant(&I))
        continue;
      CallInst *CI = dyn_cast<CallInst>(&I);
      InvokeInst *II = dyn_cast<InvokeInst>(&I);
      for (unsigned int i = 0; i < I.getNumOperands(); i++) {
        if (CI && CI->isBundleOperand(i))
          continue;
        if (II && II->isBundleOperand(i))
          continue;
        if (ConstantInt *CI = dyn_cast<ConstantInt>(I.getOperand(i))) {
          if (!(cryptoutils->get_range(100) <= ConstToGVProbTemp))
            continue;
          GlobalVariable *GV = new GlobalVariable(
              *F.getParent(), CI->getType(), false,
              GlobalValue::LinkageTypes::PrivateLinkage,
              ConstantInt::get(CI->getType(), CI->getValue()), "CToGV");
          usedGlobals.push_back(GV);
          I.setOperand(i, new LoadInst(GV->getValueType(), GV, "", &I));
        }
      }
    }
    for (Instruction &I : instructions(F)) {
      if (!shouldEncryptConstant(&I))
        continue;
      if (BinaryOperator *BO = dyn_cast<BinaryOperator>(&I)) {
        if (!BO->getType()->isIntegerTy())
          continue;
        if (!(cryptoutils->get_range(100) <= ConstToGVProbTemp))
          continue;
        IntegerType *IT = cast<IntegerType>(BO->getType());
        uint64_t dummy;
        if (IT == Type::getInt8Ty(IT->getContext()))
          dummy = cryptoutils->get_uint8_t();
        else if (IT == Type::getInt16Ty(IT->getContext()))
          dummy = cryptoutils->get_uint16_t();
        else if (IT == Type::getInt32Ty(IT->getContext()))
          dummy = cryptoutils->get_uint32_t();
        else if (IT == Type::getInt64Ty(IT->getContext()))
          dummy = cryptoutils->get_uint64_t();
        else
          continue;
        GlobalVariable *GV = new GlobalVariable(
            M, BO->getType(), false, GlobalValue::LinkageTypes::PrivateLinkage,
            ConstantInt::get(BO->getType(), dummy), "CToGV");
        StoreInst *SI =
            new StoreInst(BO, GV, false, DL.getABITypeAlign(BO->getType()));
        SI->insertAfter(BO);
        LoadInst *LI = new LoadInst(GV->getValueType(), GV, "", false,
                                    DL.getABITypeAlign(BO->getType()));
        LI->insertAfter(SI);
        BO->replaceUsesWithIf(LI, [SI](Use &U) { return U.getUser() != SI; });
      }
    }
  }

  void HandleConstantIntInitializerGV(GlobalVariable *GVPtr) {
    if (!(flag || AreUsersInOneFunction(GVPtr)) || isDispatchOnceToken(GVPtr) ||
        isAtomicLoaded(GVPtr))
      return;
    // Prepare Types and Keys
    std::pair<ConstantInt *, ConstantInt *> keyandnew;
    ConstantInt *Old = dyn_cast<ConstantInt>(GVPtr->getInitializer());
    bool hasHandled = true;
    if (handled_gvs.find(GVPtr) == handled_gvs.end()) {
      hasHandled = false;
      keyandnew = PairConstantInt(Old);
      handled_gvs.insert(GVPtr);
    }
    ConstantInt *XORKey = keyandnew.first;
    ConstantInt *newGVInit = keyandnew.second;
    if (hasHandled || !XORKey || !newGVInit)
      return;
    GVPtr->setInitializer(newGVInit);
    bool isSigned = XORKey->getValue().isSignBitSet() ||
                    newGVInit->getValue().isSignBitSet() ||
                    Old->getValue().isSignBitSet();
    for (User *U : GVPtr->users()) {
      BinaryOperator *XORInst = nullptr;
      if (LoadInst *LI = dyn_cast<LoadInst>(U)) {
        if (LI->getType() != XORKey->getType()) {
          Instruction *IntegerCast =
              BitCastInst::CreateIntegerCast(LI, XORKey->getType(), isSigned);
          IntegerCast->insertAfter(LI);
          XORInst =
              BinaryOperator::Create(Instruction::Xor, IntegerCast, XORKey);
          XORInst->insertAfter(IntegerCast);
          Instruction *IntegerCast2 =
              BitCastInst::CreateIntegerCast(XORInst, LI->getType(), isSigned);
          IntegerCast2->insertAfter(XORInst);
          LI->replaceUsesWithIf(IntegerCast2, [IntegerCast](Use &U) {
            return U.getUser() != IntegerCast;
          });
        } else {
          XORInst = BinaryOperator::Create(Instruction::Xor, LI, XORKey);
          XORInst->insertAfter(LI);
          LI->replaceUsesWithIf(
              XORInst, [XORInst](Use &U) { return U.getUser() != XORInst; });
        }
      } else if (StoreInst *SI = dyn_cast<StoreInst>(U)) {
        XORInst = BinaryOperator::Create(Instruction::Xor, SI->getOperand(0),
                                         XORKey, "", SI);
        SI->replaceUsesOfWith(SI->getValueOperand(), XORInst);
      }
      if (XORInst && SubstituteXorTemp &&
          cryptoutils->get_range(100) <= SubstituteXorProbTemp)
        SubstituteImpl::substituteXor(XORInst);
    }
  }

  // ── Feistel cipher for integer constants ─────────────────────────────────
  //
  // 4-round balanced Feistel on the integer value split into two equal halves.
  //
  // Round function F_r(x) = ((x & mask) * K_r[0] ^ K_r[1]) & mask
  //   where K_r[0] is odd (invertible mod 2^half), K_r[1] is arbitrary.
  //
  // Forward round: (L, R) → (L', R') = (R,  L ^ F_r(R))
  // Inverse round: (L', R') → (L, R) = (R' ^ F_r(L'),  L')
  //   Proof: L' = R, R' = L ^ F_r(R) = L ^ F_r(L')
  //          → L = R' ^ F_r(L'), R = L'  ✓
  //
  // Properties:
  //   • 4 rounds exceed the Luby–Rackoff PRP threshold
  //   • Nonlinear (multiplication defeats affine/XOR analysis)
  //   • IR decryption: ~8×(mul+xor+and) + 2×(shift+or) ≈ 26 IR instructions
  //
  // Round keys K_r[0..1] are generated at compile time and stored in
  // FeistelState, which is passed from feistelEncrypt to emitFeistelDecryptIR
  // so that the IR emitter uses the same keys used for encryption.

  struct FeistelState {
    uint64_t K[4][2]; // K[round][0=mulKey, 1=xorKey], both masked to half-width
    unsigned half;    // half bit-width of the constant (bits/2)
    uint64_t mask;    // (1 << half) - 1
  };

  // Compile-time: encrypt C using 4-round Feistel, filling fst with round keys.
  // Returns nullptr if the constant is too narrow (bits < 16).
  ConstantInt *feistelEncrypt(ConstantInt *C, FeistelState &fst) {
    unsigned bits = C->getBitWidth();
    if (bits < 16) return nullptr; // need at least 8-bit halves
    fst.half = bits / 2;
    fst.mask = (fst.half < 64) ? ((1ULL << fst.half) - 1ULL) : UINT64_MAX;

    uint64_t val = C->getZExtValue();
    uint64_t L = (val >> fst.half) & fst.mask;
    uint64_t R = val & fst.mask;

    for (int r = 0; r < 4; r++) {
      // Odd multiplier so it is invertible mod 2^half
      fst.K[r][0] = (cryptoutils->get_uint64_t() | 1ULL) & fst.mask;
      fst.K[r][1] = cryptoutils->get_uint64_t() & fst.mask;
      uint64_t F = ((R * fst.K[r][0]) ^ fst.K[r][1]) & fst.mask;
      uint64_t newR = (L ^ F) & fst.mask;
      L = R;
      R = newR;
    }
    uint64_t enc = ((L << fst.half) | R);
    if (bits < 64) enc &= (1ULL << bits) - 1ULL;
    return cast<ConstantInt>(ConstantInt::get(C->getType(), enc));
  }

  // IR-time: emit the 4-round inverse Feistel that recovers the original constant.
  // encVal is the IR Value carrying the encrypted constant (output of k-share XOR
  // or simple XOR decryption).  All instructions are inserted just before I.
  Value *emitFeistelDecryptIR(Instruction *I, Value *encVal,
                               IntegerType *T, const FeistelState &fst) {
    ConstantInt *halfC = cast<ConstantInt>(ConstantInt::get(T, fst.half));
    ConstantInt *maskC = cast<ConstantInt>(ConstantInt::get(T, fst.mask));

    // Extract halves: L = upper half, R = lower half
    Value *L = BinaryOperator::Create(
        Instruction::And,
        BinaryOperator::Create(Instruction::LShr, encVal, halfC, "", I),
        maskC, "", I);
    Value *R = BinaryOperator::Create(Instruction::And, encVal, maskC, "", I);

    // Apply 4 inverse rounds in reverse order (r = 3, 2, 1, 0)
    for (int r = 3; r >= 0; r--) {
      ConstantInt *K0 = cast<ConstantInt>(ConstantInt::get(T, fst.K[r][0]));
      ConstantInt *K1 = cast<ConstantInt>(ConstantInt::get(T, fst.K[r][1]));
      // F_r(L) = ((L * K0) ^ K1) & mask
      Value *mul = BinaryOperator::Create(Instruction::Mul, L, K0, "", I);
      Value *xorK = BinaryOperator::Create(Instruction::Xor, mul, K1, "", I);
      Value *F = BinaryOperator::Create(Instruction::And, xorK, maskC, "", I);
      // Inverse: newL = R ^ F(L),  newR = L
      Value *newL = BinaryOperator::Create(
          Instruction::And,
          BinaryOperator::Create(Instruction::Xor, R, F, "", I),
          maskC, "", I);
      Value *newR = L;
      L = newL;
      R = newR;
    }

    // Recombine: (L << half) | R
    Value *Lsh = BinaryOperator::Create(Instruction::Shl, L, halfC, "", I);
    return BinaryOperator::Create(Instruction::Or, Lsh, R, "", I);
  }

  // ── k-share ensemble secret sharing ─────────────────────────────────────
  //
  // Emit IR that reconstructs C from k global-variable shares by XOR-ing them.
  // Shares are stored as module-level GlobalVariables (private linkage).
  // Returns the IR Value representing C (the XOR of all k loads).
  Value *emitKShareDecrypt(Instruction *I, ConstantInt *C, unsigned k) {
    Module &M  = *I->getModule();
    IntegerType *T = cast<IntegerType>(C->getType());
    unsigned bits = T->getBitWidth();
    if (bits < 8 || k < 2) {
      // Narrow ints or k<2: fall back to single XOR
      return nullptr;
    }

    // Generate k−1 random shares; last share = C ^ xor(r_1..r_{k-1})
    SmallVector<uint64_t, 8> shares(k);
    uint64_t xorAccum = C->getZExtValue();
    for (unsigned i = 0; i < k - 1; i++) {
      uint64_t r = cryptoutils->get_uint64_t();
      if (bits < 64) r &= (1ULL << bits) - 1ULL;
      shares[i]  = r;
      xorAccum  ^= r;
    }
    shares[k - 1] = xorAccum; // last share makes XOR-of-all = C

    // Create k GlobalVariables for the shares
    SmallVector<GlobalVariable *, 8> gvs;
    for (unsigned i = 0; i < k; i++) {
      GlobalVariable *GV = new GlobalVariable(
          M, T, /*isConstant=*/false,
          GlobalValue::PrivateLinkage,
          ConstantInt::get(T, shares[i]),
          "constenc.share");
      usedGlobals.push_back(GV);
      gvs.push_back(GV);
    }

    // Emit XOR chain: load g0, load g1, ... XOR all together
    Value *acc = new LoadInst(T, gvs[0], "", I);
    for (unsigned i = 1; i < k; i++) {
      Value *ld = new LoadInst(T, gvs[i], "", I);
      acc = BinaryOperator::Create(Instruction::Xor, acc, ld,
                                   "", I);
      // Optionally substitute the XOR for additional depth
      if (SubstituteXorTemp &&
          cryptoutils->get_range(100) <= SubstituteXorProbTemp)
        SubstituteImpl::substituteXor(cast<BinaryOperator>(acc));
    }
    return acc;
  }

  void HandleConstantIntOperand(Instruction *I, unsigned opindex) {
    ConstantInt *origC = cast<ConstantInt>(I->getOperand(opindex));
    unsigned k = KShareCountTemp;

    // ── Feistel pre-encryption layer ────────────────────────────────────────
    // When -constenc_feistel is set, encrypt origC at compile time using a
    // 4-round balanced Feistel cipher, then apply the k-share / XOR layer to
    // the encrypted value.  At runtime the emitted IR first reconstructs the
    // encrypted constant (via the XOR chain), then decrypts via the 4-round
    // inverse Feistel to recover the original constant.
    //
    // This stacks two distinct layers:
    //   XOR-share obfuscation (information-theoretic security over the XOR key)
    //   + Feistel nonlinearity (multiplication defeats affine analysis)
    FeistelState fst{};
    bool useFeistel = FeistelTierTemp;
    ConstantInt *workC = origC;
    if (useFeistel) {
      ConstantInt *encC = feistelEncrypt(origC, fst);
      if (!encC)
        useFeistel = false; // constant too narrow (<16 bits) — skip Feistel
      else
        workC = encC;
    }

    // ── k-share ensemble or classic XOR ─────────────────────────────────────
    Value *reconstructed = nullptr;
    if (k >= 3) {
      reconstructed = emitKShareDecrypt(I, workC, k);
    }
    if (!reconstructed) {
      // Classic single-XOR: emit (New ^ Key) just before I
      auto kn = PairConstantInt(workC);
      if (!kn.first || !kn.second)
        return;
      BinaryOperator *xorInst =
          BinaryOperator::Create(Instruction::Xor, kn.second, kn.first, "", I);
      if (SubstituteXorTemp &&
          cryptoutils->get_range(100) <= SubstituteXorProbTemp)
        SubstituteImpl::substituteXor(xorInst);
      reconstructed = xorInst;
    }

    // ── Feistel inverse decryption IR ────────────────────────────────────────
    // The reconstructed value equals workC (== feistelEncrypt(origC)).
    // Emit the 4-round inverse Feistel to recover origC at runtime.
    if (useFeistel) {
      reconstructed = emitFeistelDecryptIR(
          I, reconstructed, cast<IntegerType>(origC->getType()), fst);
    }

    I->setOperand(opindex, reconstructed);
  }

  std::pair<ConstantInt * /*key*/, ConstantInt * /*new*/>
  PairConstantInt(ConstantInt *C) {
    if (!C)
      return std::make_pair(nullptr, nullptr);
    IntegerType *IT = cast<IntegerType>(C->getType());
    uint64_t K;
    if (IT == Type::getInt1Ty(IT->getContext()) ||
        IT == Type::getInt8Ty(IT->getContext()))
      K = cryptoutils->get_uint8_t();
    else if (IT == Type::getInt16Ty(IT->getContext()))
      K = cryptoutils->get_uint16_t();
    else if (IT == Type::getInt32Ty(IT->getContext()))
      K = cryptoutils->get_uint32_t();
    else if (IT == Type::getInt64Ty(IT->getContext()))
      K = cryptoutils->get_uint64_t();
    else
      return std::make_pair(nullptr, nullptr);
    ConstantInt *CI =
        cast<ConstantInt>(ConstantInt::get(IT, K ^ C->getValue()));
    return std::make_pair(ConstantInt::get(IT, K), CI);
  }
};

ModulePass *createConstantEncryptionPass(bool flag) {
  return new ConstantEncryption(flag);
}
} // namespace llvm
char ConstantEncryption::ID = 0;
INITIALIZE_PASS(ConstantEncryption, "constenc",
                "Enable ConstantInt GV Encryption.", false, false)
