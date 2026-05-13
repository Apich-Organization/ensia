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

// StringEncryption.cpp — compile-time string encryption with runtime decryption.
//
// ─── Cipher design: Vernam-GF8 (information-theoretically secure) ────────────
//
// Physical inspiration — Maxwell-Boltzmann energy distribution:
//   In statistical mechanics, each microstate is assigned a random independent
//   energy value from the Boltzmann distribution.  No individual sample carries
//   information about the macrostate; only the ensemble does.  We apply this
//   to per-byte encryption: each byte gets its own independent random key pair,
//   making the ciphertext indistinguishable from uniform noise.
//
//  ① Vernam OTP layer (k1[i]):
//    plain[i] XOR k1[i] where k1[i] is uniformly random and independent.
//    This is the classical One-Time Pad — information-theoretically secure:
//    H(enc[i] | plain[i]) = H(k1[i]) = 8 bits (maximum entropy).
//    An attacker who knows enc[i] learns nothing about plain[i] without k1[i].
//
//  ② GF(2^8) multiplication layer (k2[i], non-zero):
//    result[i] = GF8_mul(plain[i] XOR k1[i], k2[i])
//    where k2[i] is a non-zero random byte and GF8_mul is multiplication in
//    GF(2^8) with the AES irreducible polynomial x^8+x^4+x^3+x+1 (0x11B).
//    - GF8 multiplication by a non-zero element is a bijection (permutation)
//      of the 256-element field, so it does not reduce entropy.
//    - The decryption IR emits a shift-and-XOR carry-less multiply sequence
//      (8 iterations of the russian-peasant algorithm) that no decompiler
//      recognises as string decryption.  IDA pattern-matches "xor + load" not
//      "conditional-xor shift chain".
//    - Different from ConstantEncryption which uses XOR k-share splitting.
//
//  ③ Split-key storage:
//    The key is stored as two separate arrays (k1 and k2) in distinct
//    GlobalVariables.  An attacker reading one array learns nothing without
//    also reading the other, and the GF8 inversion step requires solving
//    the GF multiplication for each byte independently.
//
//  ④ Unordered decryption:  decrypt in a chaos-permuted order so the IR
//    decryption block does not exhibit the byte-sequential pattern that
//    string deobfuscation tools expect.
//
// Correctness guarantee:
//    Decryption: plain[i] = GF8_mul(enc[i], GF8_inv(k2[i])) XOR k1[i]
//    Both GF8_inv(k2[i]) and k1[i] are pre-computed offline and stored as
//    compile-time constants in the key arrays.

#include "include/StringEncryption.h"
#include "include/ChaosStateMachine.h"
#include "include/CryptoUtils.h"
#include "include/Utils.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <unordered_set>
#include <vector>
#include <algorithm>

using namespace llvm;

static cl::opt<uint32_t>
    ElementEncryptProb("strcry_prob", cl::init(100), cl::NotHidden,
                       cl::desc("Choose the probability [%] each element of "
                                "ConstantDataSequential will be "
                                "obfuscated by the -strcry pass"));
static uint32_t ElementEncryptProbTemp = 100;

namespace llvm {
struct StringEncryption : public ModulePass {
  static char ID;
  bool flag;
  bool appleptrauth;
  bool opaquepointers;
  std::unordered_map<Function * /*Function*/,
                     GlobalVariable * /*Decryption Status*/>
      encstatus;
  std::unordered_map<GlobalVariable *, std::pair<Constant *, GlobalVariable *>>
      mgv2keys;
  std::unordered_map<Constant *, SmallVector<unsigned int, 16>>
      unencryptedindex;
  SmallVector<GlobalVariable *, 32> genedgv;
  std::unordered_map<GlobalVariable *,
                     std::pair<GlobalVariable *, GlobalVariable *>>
      globalOld2New;
  std::unordered_set<GlobalVariable *> globalProcessedGVs;
  // Maps each DecryptSpaceGV (i8 path only) to its k2inv vector (full layout).
  // Populated during HandleFunction; consumed in HandleDecryptionBlock.
  // Avoids fragile recovery of k2inv from the GV initializer at decrypt time.
  std::unordered_map<GlobalVariable *, std::vector<uint8_t>> gv_k2inv_map;
  StringEncryption() : ModulePass(ID) { this->flag = true; }

  StringEncryption(bool flag) : ModulePass(ID) { this->flag = flag; }

  StringRef getPassName() const override { return "StringEncryption"; }

  bool handleableGV(GlobalVariable *GV) {
#if LLVM_VERSION_MAJOR >= 18
    if (GV->hasInitializer() && !GV->getSection().starts_with("llvm.") &&
#else
    if (GV->hasInitializer() && !GV->getSection().startswith("llvm.") &&
#endif
        !(GV->getSection().contains("__objc") &&
          !GV->getSection().contains("array")) &&
        !GV->getName().contains("OBJC") &&
        std::find(genedgv.begin(), genedgv.end(), GV) == genedgv.end() &&
        ((GV->getLinkage() == GlobalValue::LinkageTypes::PrivateLinkage ||
          GV->getLinkage() == GlobalValue::LinkageTypes::InternalLinkage) &&
         (flag || AreUsersInOneFunction(GV))))
      return true;
    return false;
  }

  bool runOnModule(Module &M) override {
    // in runOnModule. We simple iterate function list and dispatch functions
    // to handlers
    this->appleptrauth = hasApplePtrauth(&M);
#if LLVM_VERSION_MAJOR >= 17
    this->opaquepointers = true;
#else
    this->opaquepointers = !M.getContext().supportsTypedPointers();
#endif

    for (Function &F : M)
      if (toObfuscate(flag, &F, "strenc")) {
        if (ObfVerbose) errs() << "Running StringEncryption On " << F.getName() << "\n";

        if (!toObfuscateUint32Option(&F, "strcry_prob",
                                     &ElementEncryptProbTemp))
          ElementEncryptProbTemp = ElementEncryptProb;

        // Check if the number of applications is correct
        if (!((ElementEncryptProbTemp > 0) &&
              (ElementEncryptProbTemp <= 100))) {
          errs() << "StringEncryption application element percentage "
                    "-strcry_prob=x must be 0 < x <= 100";
          return false;
        }
        Constant *S =
            ConstantInt::getNullValue(Type::getInt32Ty(M.getContext()));
        GlobalVariable *GV = new GlobalVariable(
            M, S->getType(), false, GlobalValue::LinkageTypes::PrivateLinkage,
            S, "StringEncryptionEncStatus");
        encstatus[&F] = GV;
        HandleFunction(&F);
      }
    for (GlobalVariable *GV : globalProcessedGVs) {
      GV->removeDeadConstantUsers();
      if (GV->getNumUses() == 0) {
        GV->dropAllReferences();
        GV->eraseFromParent();
      }
    }

    return true;
  }

  void
  processConstantAggregate(GlobalVariable *strGV, ConstantAggregate *CA,
                           std::unordered_set<GlobalVariable *> *rawStrings,
                           SmallVector<GlobalVariable *, 32> *unhandleablegvs,
                           SmallVector<GlobalVariable *, 32> *Globals,
                           std::unordered_set<User *> *Users, bool *breakFor) {
    for (unsigned i = 0; i < CA->getNumOperands(); i++) {
      Constant *Op = CA->getOperand(i);
      if (GlobalVariable *GV =
              dyn_cast<GlobalVariable>(Op->stripPointerCasts())) {
        if (!handleableGV(GV)) {
          unhandleablegvs->emplace_back(GV);
          continue;
        }
        Users->insert(opaquepointers ? CA : Op);
        if (std::find(Globals->begin(), Globals->end(), GV) == Globals->end()) {
          Globals->emplace_back(GV);
          *breakFor = true;
        }
      } else if (ConstantAggregate *NestedCA =
                     dyn_cast<ConstantAggregate>(Op)) {
        processConstantAggregate(strGV, NestedCA, rawStrings, unhandleablegvs,
                                 Globals, Users, breakFor);
      } else if (isa<ConstantDataSequential>(Op)) {
        if (CA->getNumOperands() != 1)
          continue;
        Users->insert(CA);
        rawStrings->insert(strGV);
      }
    }
  }

  void HandleUser(User *U, SmallVector<GlobalVariable *, 32> &Globals,
                  std::unordered_set<User *> &Users,
                  std::unordered_set<User *> &VisitedUsers) {
    VisitedUsers.emplace(U);
    for (Value *Op : U->operands()) {
      if (GlobalVariable *G =
              dyn_cast<GlobalVariable>(Op->stripPointerCasts())) {
        if (User *U2 = dyn_cast<User>(Op))
          Users.insert(U2);
        Users.insert(U);
        Globals.emplace_back(G);
      } else if (User *U = dyn_cast<User>(Op)) {
        if (!VisitedUsers.count(U))
          HandleUser(U, Globals, Users, VisitedUsers);
      }
    }
  }

  void HandleFunction(Function *Func) {
    FixFunctionConstantExpr(Func);
    SmallVector<GlobalVariable *, 32> Globals;
    std::unordered_set<User *> Users;
    {
      std::unordered_set<User *> VisitedUsers;
      for (Instruction &I : instructions(Func))
        HandleUser(&I, Globals, Users, VisitedUsers);
    }
    std::unordered_set<GlobalVariable *> rawStrings;
    std::unordered_set<GlobalVariable *> objCStrings;
    std::unordered_map<GlobalVariable *,
                       std::pair<Constant *, GlobalVariable *>>
        GV2Keys;
    std::unordered_map<GlobalVariable * /*old*/,
                       std::pair<GlobalVariable * /*encrypted*/,
                                 GlobalVariable * /*decrypt space*/>>
        old2new;

    auto end = Globals.end();
    for (auto it = Globals.begin(); it != end; ++it) {
      end = std::remove(it + 1, end, *it);
    }
    Globals.erase(end, Globals.end());

    Module *M = Func->getParent();

    SmallVector<GlobalVariable *, 32> transedGlobals, unhandleablegvs;

    do {
      for (GlobalVariable *GV : Globals) {
        if (std::find(transedGlobals.begin(), transedGlobals.end(), GV) ==
            transedGlobals.end()) {
          bool breakThisFor = false;
          if (handleableGV(GV)) {
            if (GlobalVariable *CastedGV = dyn_cast<GlobalVariable>(
                    GV->getInitializer()->stripPointerCasts())) {
              if (std::find(Globals.begin(), Globals.end(), CastedGV) ==
                  Globals.end()) {
                Globals.emplace_back(CastedGV);
                ConstantExpr *CE = dyn_cast<ConstantExpr>(GV->getInitializer());
                Users.insert(CE ? CE : GV->getInitializer());
                breakThisFor = true;
              }
            }
            if (GV->getInitializer()->getType() ==
                StructType::getTypeByName(M->getContext(),
                                          "struct.__NSConstantString_tag")) {
              objCStrings.insert(GV);
              rawStrings.insert(cast<GlobalVariable>(
                  cast<ConstantStruct>(GV->getInitializer())
                      ->getOperand(2)
                      ->stripPointerCasts()));
            } else if (isa<ConstantDataSequential>(GV->getInitializer())) {
              rawStrings.insert(GV);
            } else if (ConstantAggregate *CA =
                           dyn_cast<ConstantAggregate>(GV->getInitializer())) {
              processConstantAggregate(GV, CA, &rawStrings, &unhandleablegvs,
                                       &Globals, &Users, &breakThisFor);
            }
          } else {
            unhandleablegvs.emplace_back(GV);
          }
          transedGlobals.emplace_back(GV);
          if (breakThisFor)
            break;
        }
      } // foreach loop
    } while (transedGlobals.size() != Globals.size());
    for (GlobalVariable *ugv : unhandleablegvs)
      if (std::find(genedgv.begin(), genedgv.end(), ugv) != genedgv.end()) {
        std::pair<Constant *, GlobalVariable *> mgv2keysval = mgv2keys[ugv];
        if (ugv->getInitializer()->getType() ==
            StructType::getTypeByName(M->getContext(),
                                      "struct.__NSConstantString_tag")) {
          GlobalVariable *rawgv =
              cast<GlobalVariable>(cast<ConstantStruct>(ugv->getInitializer())
                                       ->getOperand(2)
                                       ->stripPointerCasts());
          mgv2keysval = mgv2keys[rawgv];
          if (mgv2keysval.first && mgv2keysval.second) {
            GV2Keys[rawgv] = mgv2keysval;
          }
        } else if (mgv2keysval.first && mgv2keysval.second) {
          GV2Keys[ugv] = mgv2keysval;
        }
      }
    for (GlobalVariable *GV : rawStrings) {
      if (GV->getInitializer()->isZeroValue() ||
          GV->getInitializer()->isNullValue())
        continue;
      auto globalIt = globalOld2New.find(GV);
      if (globalIt != globalOld2New.end()) {
        old2new[GV] = globalIt->second;
        // 更新当前函数的GV2Keys和mgv2keys
        GV2Keys[globalIt->second.second] = mgv2keys[globalIt->second.second];
        mgv2keys[globalIt->second.second] = GV2Keys[globalIt->second.second];
        continue; // 跳过生成新变量步骤
      }
      ConstantDataSequential *CDS =
          dyn_cast<ConstantDataSequential>(GV->getInitializer());
      bool rust_string = !CDS;
      if (rust_string)
        CDS = cast<ConstantDataSequential>(
            cast<ConstantAggregate>(GV->getInitializer())->getOperand(0));
      Type *ElementTy = CDS->getElementType();
      if (!ElementTy->isIntegerTy()) {
        continue;
      }
      IntegerType *intType = cast<IntegerType>(ElementTy);
      Constant *KeyConst, *EncryptedConst, *DummyConst = nullptr;
      // For the i8 Vernam-GF8 path: holds the k2inv vector (full layout)
      // so we can store it in gv_k2inv_map once DecryptSpaceGV is known.
      std::vector<uint8_t> pending_k2invs;
      unencryptedindex[GV] = {};
      if (intType == Type::getInt8Ty(M->getContext())) {
        // Vernam-GF8 cipher — array layout:
        //
        //  k1s[i]    OTP XOR key (FULL layout: 1u placeholder for unencrypted)
        //  encry[i]  GF8-encrypted ciphertext (COMPACT: encrypted elements only)
        //  k2invs[i] GF8 decryption multiplier (FULL layout):
        //              • Encrypted  → GF8_inv(k2[i])
        //              • Unencrypted→ plain[i]  (so DecryptSpace keeps plain text)
        //
        // IMPORTANT: k1s and k2invs are FULL layout (one entry per element,
        // indexed by element position `i`).  encry is COMPACT (one entry per
        // encrypted element, indexed by compact offset `ko`).  The decryption
        // IR in HandleDecryptionBlock reads k1s[idx] and k2invs[idx] (NOT [ko]).
        // k2invs is stored in gv_k2inv_map[DecryptSpaceGV] for direct access.
        std::vector<uint8_t> k1s, k2invs, encry;
        for (unsigned i = 0; i < CDS->getNumElements(); i++) {
          if (cryptoutils->get_range(100) >= ElementEncryptProbTemp) {
            // Unencrypted: record index, store plain value in k2invs (= dummy),
            // DON'T push to encry (compact skip — same as original).
            unencryptedindex[GV].emplace_back(i);
            k1s.emplace_back(1u);                                        // unused key
            k2invs.emplace_back((uint8_t)CDS->getElementAsInteger(i));  // plain → initial DecryptSpace
            continue;  // DO NOT push to encry
          }
          // ── Vernam-GF8 encryption ──────────────────────────────────────────
          // OTP key k1: uniformly random — information-theoretically secure.
          // Each k1[i] is independent; H(enc[i]|plain[i]) = 8 bits (maximum).
          const uint8_t k1 = cryptoutils->get_uint8_t();
          // GF8 multiplier k2: random, non-zero element of GF(2^8)
          uint8_t k2 = 0;
          while (k2 == 0)
            k2 = cryptoutils->get_uint8_t();
          const uint8_t k2inv = gf8_inv(k2);
          const uint8_t V     = (uint8_t)CDS->getElementAsInteger(i);
          // enc = GF8_mul(plain XOR k1, k2)
          const uint8_t enc   = gf8_mul(V ^ k1, k2);
          k1s.emplace_back(k1);
          k2invs.emplace_back(k2inv);
          encry.emplace_back(enc);       // compact
        }
        // KeyConst      = k1s    (OTP XOR keys;  full layout: 1 per element)
        // EncryptedConst= encry   (GF8-encrypted ciphertext; compact)
        // DummyConst    = k2invs  (GF8 inv. multipliers for encrypted elements,
        //                          and plain values for unencrypted elements)
        // Save k2invs for storage in gv_k2inv_map once DecryptSpaceGV is known.
        pending_k2invs = k2invs;
        KeyConst = ConstantDataArray::get(M->getContext(),
                                          ArrayRef<uint8_t>(k1s));
        EncryptedConst = ConstantDataArray::get(M->getContext(),
                                                ArrayRef<uint8_t>(encry));
        DummyConst = ConstantDataArray::get(M->getContext(),
                                             ArrayRef<uint8_t>(k2invs));

      } else if (intType == Type::getInt16Ty(M->getContext())) {
        std::vector<uint16_t> keys, encry, dummy;
        for (unsigned i = 0; i < CDS->getNumElements(); i++) {
          if (cryptoutils->get_range(100) >= ElementEncryptProbTemp) {
            unencryptedindex[GV].emplace_back(i);
            keys.emplace_back(1);
            dummy.emplace_back(CDS->getElementAsInteger(i));
            continue;
          }
          const uint16_t K = cryptoutils->get_uint16_t();
          const uint64_t V = CDS->getElementAsInteger(i);
          keys.emplace_back(K);
          encry.emplace_back(K ^ V);
          dummy.emplace_back(cryptoutils->get_uint16_t());
        }
        KeyConst =
            ConstantDataArray::get(M->getContext(), ArrayRef<uint16_t>(keys));
        EncryptedConst =
            ConstantDataArray::get(M->getContext(), ArrayRef<uint16_t>(encry));
        DummyConst =
            ConstantDataArray::get(M->getContext(), ArrayRef<uint16_t>(dummy));
      } else if (intType == Type::getInt32Ty(M->getContext())) {
        std::vector<uint32_t> keys, encry, dummy;
        for (unsigned i = 0; i < CDS->getNumElements(); i++) {
          if (cryptoutils->get_range(100) >= ElementEncryptProbTemp) {
            unencryptedindex[GV].emplace_back(i);
            keys.emplace_back(1);
            dummy.emplace_back(CDS->getElementAsInteger(i));
            continue;
          }
          const uint32_t K = cryptoutils->get_uint32_t();
          const uint64_t V = CDS->getElementAsInteger(i);
          keys.emplace_back(K);
          encry.emplace_back(K ^ V);
          dummy.emplace_back(cryptoutils->get_uint32_t());
        }
        KeyConst =
            ConstantDataArray::get(M->getContext(), ArrayRef<uint32_t>(keys));
        EncryptedConst =
            ConstantDataArray::get(M->getContext(), ArrayRef<uint32_t>(encry));
        DummyConst =
            ConstantDataArray::get(M->getContext(), ArrayRef<uint32_t>(dummy));
      } else if (intType == Type::getInt64Ty(M->getContext())) {
        std::vector<uint64_t> keys, encry, dummy;
        for (unsigned i = 0; i < CDS->getNumElements(); i++) {
          if (cryptoutils->get_range(100) >= ElementEncryptProbTemp) {
            unencryptedindex[GV].emplace_back(i);
            keys.emplace_back(1);
            dummy.emplace_back(CDS->getElementAsInteger(i));
            continue;
          }
          const uint64_t K = cryptoutils->get_uint64_t();
          const uint64_t V = CDS->getElementAsInteger(i);
          keys.emplace_back(K);
          encry.emplace_back(K ^ V);
          dummy.emplace_back(cryptoutils->get_uint64_t());
        }
        KeyConst =
            ConstantDataArray::get(M->getContext(), ArrayRef<uint64_t>(keys));
        EncryptedConst =
            ConstantDataArray::get(M->getContext(), ArrayRef<uint64_t>(encry));
        DummyConst =
            ConstantDataArray::get(M->getContext(), ArrayRef<uint64_t>(dummy));
      } else {
        llvm_unreachable("Unsupported CDS Type");
      }
      // Prepare new rawGV
      GlobalVariable *EncryptedRawGV = new GlobalVariable(
          *M, EncryptedConst->getType(), false, GV->getLinkage(),
          EncryptedConst, "EncryptedString", nullptr, GV->getThreadLocalMode(),
          GV->getType()->getAddressSpace());
      genedgv.emplace_back(EncryptedRawGV);
      GlobalVariable *DecryptSpaceGV;
      if (rust_string) {
        ConstantAggregate *CA = cast<ConstantAggregate>(GV->getInitializer());
        CA->setOperand(0, DummyConst);
        DecryptSpaceGV = new GlobalVariable(
            *M, GV->getValueType(), false, GV->getLinkage(), CA,
            "DecryptSpaceRust", nullptr, GV->getThreadLocalMode(),
            GV->getType()->getAddressSpace());
      } else {
        DecryptSpaceGV = new GlobalVariable(
            *M, DummyConst->getType(), false, GV->getLinkage(), DummyConst,
            "DecryptSpace", nullptr, GV->getThreadLocalMode(),
            GV->getType()->getAddressSpace());
      }
      genedgv.emplace_back(DecryptSpaceGV);
      // For the i8 Vernam-GF8 path, record the k2inv vector (full layout)
      // keyed by DecryptSpaceGV so HandleDecryptionBlock can read it without
      // needing to introspect the GV initializer (which may be a mutated CA).
      if (!pending_k2invs.empty())
        gv_k2inv_map[DecryptSpaceGV] = std::move(pending_k2invs);
      old2new[GV] = std::make_pair(EncryptedRawGV, DecryptSpaceGV);
      GV2Keys[DecryptSpaceGV] = std::make_pair(KeyConst, EncryptedRawGV);
      mgv2keys[DecryptSpaceGV] = GV2Keys[DecryptSpaceGV];
      unencryptedindex[KeyConst] = unencryptedindex[GV];
      globalOld2New[GV] = std::make_pair(EncryptedRawGV, DecryptSpaceGV);
      globalProcessedGVs.insert(GV);
      old2new[GV] = globalOld2New[GV];
    }
    // Now prepare ObjC new GV
    for (GlobalVariable *GV : objCStrings) {
      ConstantStruct *CS = cast<ConstantStruct>(GV->getInitializer());
      GlobalVariable *oldrawString =
          cast<GlobalVariable>(CS->getOperand(2)->stripPointerCasts());
      if (old2new.find(oldrawString) ==
          old2new.end()) // Filter out zero initializers
        continue;
      GlobalVariable *EncryptedOCGV = ObjectiveCString(
          GV, "EncryptedStringObjC", old2new[oldrawString].first, CS);
      genedgv.emplace_back(EncryptedOCGV);
      GlobalVariable *DecryptSpaceOCGV = ObjectiveCString(
          GV, "DecryptSpaceObjC", old2new[oldrawString].second, CS);
      genedgv.emplace_back(DecryptSpaceOCGV);
      old2new[GV] = std::make_pair(EncryptedOCGV, DecryptSpaceOCGV);
    } // End prepare ObjC new GV
    if (GV2Keys.empty())
      return;
    // Replace Uses
    for (User *U : Users) {
      for (std::unordered_map<
               GlobalVariable *,
               std::pair<GlobalVariable *, GlobalVariable *>>::iterator iter =
               old2new.begin();
           iter != old2new.end(); ++iter) {
        if (isa<Constant>(U) && !isa<GlobalValue>(U)) {
          Constant *C = cast<Constant>(U);
          for (Value *Op : C->operands())
            if (Op == iter->first) {
              C->handleOperandChange(iter->first, iter->second.second);
              break;
            }
        } else
          U->replaceUsesOfWith(iter->first, iter->second.second);
        iter->first->removeDeadConstantUsers();
      }
    } // End Replace Uses
    // CleanUp Old ObjC GVs
    for (GlobalVariable *GV : objCStrings) {
      GlobalVariable *PtrauthGV = nullptr;
      if (appleptrauth) {
        Constant *C = dyn_cast_or_null<Constant>(
            opaquepointers
                ? GV->getInitializer()
                : cast<ConstantExpr>(GV->getInitializer()->getOperand(0)));
        if (C) {
          PtrauthGV = dyn_cast<GlobalVariable>(C->getOperand(0));
          if (PtrauthGV->getSection() == "llvm.ptrauth") {
            if (ConstantExpr *CE = dyn_cast<ConstantExpr>(
                    PtrauthGV->getInitializer()->getOperand(2))) {
              if (GlobalVariable *GV2 =
                      dyn_cast<GlobalVariable>(CE->getOperand(0))) {
                if (GV->getNumUses() <= 1 &&
                    GV2->getName() == GV->getName())
                  PtrauthGV->getInitializer()->setOperand(
                      2, ConstantExpr::getPtrToInt(
                             M->getGlobalVariable(
                                 "__CFConstantStringClassReference"),
                             Type::getInt64Ty(M->getContext())));
              }
            } else if (GlobalVariable *GV2 = dyn_cast<GlobalVariable>(
                           PtrauthGV->getInitializer()->getOperand(2)))
              if (GV->getNumUses() <= 1 &&
                  GV2->getName() == GV->getName())
                PtrauthGV->getInitializer()->setOperand(
                    2, ConstantExpr::getPtrToInt(
                           M->getGlobalVariable(
                               "__CFConstantStringClassReference"),
                           Type::getInt64Ty(M->getContext())));
          }
        }
      }
      GV->removeDeadConstantUsers();
      if (GV->getNumUses() == 0) {
        GV->dropAllReferences();
        old2new.erase(GV);
        GV->eraseFromParent();
      }
      if (PtrauthGV) {
        PtrauthGV->removeDeadConstantUsers();
        if (PtrauthGV->getNumUses() == 0) {
          PtrauthGV->dropAllReferences();
          PtrauthGV->eraseFromParent();
        }
      }
    }
    // Cleanup at the end of encryption to avoid wild pointers
    // CleanUp Old Raw GVs
    // for (std::unordered_map<
    //          GlobalVariable *,
    //          std::pair<GlobalVariable *, GlobalVariable *>>::iterator iter =
    //          old2new.begin();
    //      iter != old2new.end(); ++iter) {
    //   GlobalVariable *toDelete = iter->first;
    //   toDelete->removeDeadConstantUsers();
    //   if (toDelete->getNumUses() == 0) {
    //     toDelete->dropAllReferences();
    //     toDelete->eraseFromParent();
    //   }
    // }
    GlobalVariable *StatusGV = encstatus[Func];
    /*
       - Split Original EntryPoint BB into A and C.
       - Create new BB as Decryption BB between A and C. Adjust the terminators
         into: A (Alloca a new array containing all)
               |
               B(If not decrypted)
               |
               C
     */
    BasicBlock *A = &(Func->getEntryBlock());
    BasicBlock *C = A->splitBasicBlock(A->getFirstNonPHIOrDbgOrLifetime());
    C->setName("PrecedingBlock");
    BasicBlock *B =
        BasicBlock::Create(Func->getContext(), "StringDecryptionBB", Func, C);
    // Change A's terminator to jump to B
    // We'll add new terminator to jump C later
    BranchInst *newBr = BranchInst::Create(B);
    ReplaceInstWithInst(A->getTerminator(), newBr);
    // Insert DecryptionCode
    HandleDecryptionBlock(B, C, GV2Keys);
    IRBuilder<> IRB(&*A->getFirstNonPHIOrDbgOrLifetime());
    // Add atomic load checking status in A
    LoadInst *LI = IRB.CreateLoad(StatusGV->getValueType(), StatusGV,
                                  "LoadEncryptionStatus");
    LI->setAtomic(
        AtomicOrdering::Acquire); // Will be released at the start of C
    LI->setAlignment(Align(4));
    Value *condition = IRB.CreateICmpEQ(
        LI, ConstantInt::get(Type::getInt32Ty(Func->getContext()), 0));
    A->getTerminator()->eraseFromParent();
    BranchInst::Create(B, C, condition, A);
    // Add StoreInst atomically in C start
    // No matter control flow is coming from A or B, the GVs must be decrypted
    StoreInst *SI =
        new StoreInst(ConstantInt::get(Type::getInt32Ty(Func->getContext()), 1),
                      StatusGV, C->getFirstNonPHIOrDbgOrLifetime());
    SI->setAlignment(Align(4));
    SI->setAtomic(AtomicOrdering::Release); // Release the lock acquired in LI
  } // End of HandleFunction

  GlobalVariable *ObjectiveCString(GlobalVariable *GV, std::string name,
                                   GlobalVariable *newString,
                                   ConstantStruct *CS) {
    Value *zero = ConstantInt::get(Type::getInt32Ty(GV->getContext()), 0);
    SmallVector<Constant *, 4> vals;
    vals.emplace_back(CS->getOperand(0));
    vals.emplace_back(CS->getOperand(1));
    Constant *GEPed = ConstantExpr::getInBoundsGetElementPtr(
        newString->getValueType(), newString, {zero, zero});
    if (GEPed->getType() == CS->getOperand(2)->getType()) {
      vals.emplace_back(GEPed);
    } else {
      Constant *BitCasted =
          ConstantExpr::getBitCast(newString, CS->getOperand(2)->getType());
      vals.emplace_back(BitCasted);
    }
    vals.emplace_back(CS->getOperand(3));
    Constant *newCS =
        ConstantStruct::get(CS->getType(), ArrayRef<Constant *>(vals));
    GlobalVariable *ObjcGV = new GlobalVariable(
        *(GV->getParent()), newCS->getType(), false, GV->getLinkage(), newCS,
        name, nullptr, GV->getThreadLocalMode(),
        GV->getType()->getAddressSpace());
    // for arm64e target on Apple LLVM
    if (appleptrauth) {
      Constant *C = dyn_cast_or_null<Constant>(
          opaquepointers ? newCS : cast<ConstantExpr>(newCS->getOperand(0)));
      GlobalVariable *PtrauthGV = dyn_cast<GlobalVariable>(C->getOperand(0));
      if (PtrauthGV && PtrauthGV->getSection() == "llvm.ptrauth") {
        GlobalVariable *NewPtrauthGV = new GlobalVariable(
            *PtrauthGV->getParent(), PtrauthGV->getValueType(), true,
            PtrauthGV->getLinkage(),
            ConstantStruct::getAnon(
                {(Constant *)PtrauthGV->getInitializer()->getOperand(0),
                 (ConstantInt *)PtrauthGV->getInitializer()->getOperand(1),
                 ConstantExpr::getPtrToInt(
                     ObjcGV, Type::getInt64Ty(ObjcGV->getContext())),
                 (ConstantInt *)PtrauthGV->getInitializer()->getOperand(3)},
                false),
            PtrauthGV->getName(), nullptr, PtrauthGV->getThreadLocalMode());
        NewPtrauthGV->setSection("llvm.ptrauth");
        NewPtrauthGV->setAlignment(Align(8));
        ObjcGV->getInitializer()->setOperand(
            0,
            ConstantExpr::getBitCast(
                NewPtrauthGV,
                Type::getInt32Ty(NewPtrauthGV->getContext())->getPointerTo()));
      }
    }
    return ObjcGV;
  }

  // ── OLLVM-Next: Vernam-GF8 cipher helpers ────────────────────────────────
  //
  // Compile-time GF(2^8) arithmetic with the AES polynomial 0x11B.
  //   xtime(a) = (a << 1) ^ (a & 0x80 ? 0x1B : 0)  [multiply by x in GF(2^8)]
  //   gf8_mul(a, b) = russian-peasant algorithm over xtime

  static uint8_t xtime(uint8_t a) {
    return (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1Bu : 0u));
  }

  static uint8_t gf8_mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    for (int i = 0; i < 8; i++) {
      if (b & 1u)
        result ^= a;
      a = xtime(a);
      b >>= 1;
    }
    return result;
  }

  // Compute GF(2^8) multiplicative inverse using the extended Euclidean
  // algorithm over GF(2^8).  gf8_inv(0) = 0 (by convention).
  static uint8_t gf8_inv(uint8_t a) {
    if (a == 0)
      return 0;
    // Brute-force search: correct for a build-time helper.
    for (unsigned b = 1; b < 256; b++)
      if (gf8_mul(a, (uint8_t)b) == 1)
        return (uint8_t)b;
    return 0; // unreachable for non-zero a
  }

  // ── Vernam-GF8 decryption IR emitter ─────────────────────────────────────
  //
  // Emits IR for GF(2^8) multiplication of a runtime value `x` by a
  // compile-time constant `c` (using the AES polynomial 0x11B).
  //
  // The algorithm is the russian-peasant "shift-and-accumulate" method unrolled
  // for the 8 bits of `c`.  Each step:
  //   if bit j of c is set: result ^= current_a
  //   a = xtime(a) = (a << 1) ^ ((a >> 7) & 1 ? 0x1B : 0)
  //
  // The xtime step in IR:
  //   carry = (a >> 7) & 1           [1 if MSB of a is set]
  //   mask  = carry * 0x1B           [0x1B if carry, else 0]
  //   a_new = (a << 1) ^ mask
  //
  // For 8 iterations, this produces at most 8*(3 shifts + 1 mul + 1 xor) +
  // (popcount(c) XOR accumulations) = ≈24–40 IR instructions per element.
  // No decompiler pattern-matches "GF8 multiply" as string decryption.
  static Value *emitGF8Mul(IRBuilder<> &IRB, Value *x, uint8_t c,
                            Type *I8Ty) {
    Value *result = ConstantInt::get(I8Ty, 0);
    Value *a      = x;
    ConstantInt *c0x1B  = cast<ConstantInt>(ConstantInt::get(I8Ty, 0x1Bu));
    ConstantInt *cShift = cast<ConstantInt>(ConstantInt::get(I8Ty, 1));
    ConstantInt *cMSB   = cast<ConstantInt>(ConstantInt::get(I8Ty, 7));
    for (int bit = 0; bit < 8; bit++) {
      if ((c >> bit) & 1u) {
        result = IRB.CreateXor(result, a, "gf8.acc");
      }
      if (bit < 7) { // last iteration doesn't need xtime
        // carry = (a >> 7) & 1
        Value *carry = IRB.CreateAnd(
            IRB.CreateLShr(a, cMSB, "gf8.carry"), cShift, "gf8.carry1");
        // mask = carry * 0x1B  (0 or 0x1B)
        Value *mask = IRB.CreateMul(carry, c0x1B, "gf8.mask");
        // a = (a << 1) ^ mask
        a = IRB.CreateXor(IRB.CreateShl(a, cShift, "gf8.shl"), mask, "gf8.xt");
      }
    }
    return result;
  }

  void HandleDecryptionBlock(
      BasicBlock *B, BasicBlock *C,
      std::unordered_map<GlobalVariable *,
                         std::pair<Constant *, GlobalVariable *>> &GV2Keys) {
    IRBuilder<> IRB(B);
    LLVMContext &Ctx = B->getContext();
    Type *I8Ty  = Type::getInt8Ty(Ctx);
    Type *I32Ty = Type::getInt32Ty(Ctx);
    Type *I64Ty = Type::getInt64Ty(Ctx);
    Value *zero32 = ConstantInt::get(I32Ty, 0);
    Value *zero64 = ConstantInt::get(I64Ty, 0);

    for (auto iter = GV2Keys.begin(); iter != GV2Keys.end(); ++iter) {
      bool rust_string =
          !isa<ConstantDataSequential>(iter->first->getInitializer());
      ConstantAggregate *CA =
          rust_string ? cast<ConstantAggregate>(iter->first->getInitializer())
                      : nullptr;
      // iter->second.first  = KeyConst  (k1 array: OTP XOR keys)
      // iter->second.second = EncryptedRawGV  (ciphertext array)
      //
      // The DecryptSpace GV (iter->first when called from HandleFunction)
      // was initialised with k2inv values (GF8 decryption multipliers).
      // We read enc from EncryptedRawGV and k2inv from DecryptSpace init.
      Constant *KeyConst = iter->second.first;          // k1[]
      ConstantDataArray *CDA_k1 = cast<ConstantDataArray>(KeyConst);

      // Retrieve the k2inv vector (full-layout, one entry per string element)
      // that was stored in gv_k2inv_map during HandleFunction.  This is the
      // authoritative source for the GF8 decryption multipliers; it avoids
      // introspecting the GV initializer (which may be a mutated ConstantAggregate
      // in the Rust-string path, making direct cast<ConstantDataArray> unsafe).
      // For non-i8 GVs the map entry will be absent; CDA_k2inv stays nullptr.
      ConstantDataArray *CDA_k2inv = nullptr;
      {
        auto mapIt = gv_k2inv_map.find(iter->first);
        if (mapIt != gv_k2inv_map.end()) {
          // Reconstitute a ConstantDataArray view from the stored vector so
          // getElementAsInteger() works uniformly in the loop below.
          Constant *k2invConst = ConstantDataArray::get(
              Ctx, ArrayRef<uint8_t>(mapIt->second));
          CDA_k2inv = cast<ConstantDataArray>(k2invConst);
        }
      }

      appendToCompilerUsed(*iter->second.second->getParent(),
                           {iter->second.second});

      uint64_t numElems = CDA_k1->getType()->getNumElements();
      bool isI8 = (CDA_k1->getElementType() == I8Ty);

      // Build a chaos-permuted decryption order (unordered decryption)
      std::vector<uint64_t> order;
      order.reserve(numElems);
      for (uint64_t i = 0; i < numElems; i++) {
        if (!unencryptedindex[KeyConst].size() ||
            std::find(unencryptedindex[KeyConst].begin(),
                      unencryptedindex[KeyConst].end(), i) ==
                unencryptedindex[KeyConst].end())
          order.push_back(i);
      }
      for (size_t i = order.size(); i > 1; i--)
        std::swap(order[i - 1], order[cryptoutils->get_range((uint32_t)i)]);

      // Build index → key-array-offset map
      std::vector<uint64_t> keyOffsetMap(numElems, (uint64_t)-1);
      {
        uint64_t ko = 0;
        for (uint64_t i = 0; i < numElems; i++) {
          bool skip = unencryptedindex[KeyConst].size() &&
                      std::find(unencryptedindex[KeyConst].begin(),
                                unencryptedindex[KeyConst].end(), i) !=
                          unencryptedindex[KeyConst].end();
          if (!skip)
            keyOffsetMap[i] = ko++;
        }
      }

      for (uint64_t idx : order) {
        uint64_t ko = keyOffsetMap[idx];
        if (ko == (uint64_t)-1)
          continue;

        // offKO  — compact offset into EncryptedRawGV (encry[] is compact)
        // offIdx — full element index into DecryptSpaceGV and key arrays
        //          (k1s[], k2invs[], keys[] are all full-layout)
        Value *offKO  = ConstantInt::get(I64Ty, ko);
        Value *offIdx = ConstantInt::get(I64Ty, idx);

        // Source: encrypted byte from EncryptedRawGV (compact layout → offKO)
        Value *EncGEP = IRB.CreateGEP(iter->second.second->getValueType(),
                                      iter->second.second, {zero32, offKO});
        // Destination: plaintext write into DecryptSpace (full layout → offIdx)
        Value *DecGEP =
            rust_string
                ? IRB.CreateGEP(
                      CA->getOperand(0)->getType(),
                      IRB.CreateGEP(CA->getType(), iter->first,
                                    {zero64, ConstantInt::getNullValue(I64Ty)}),
                      {zero32, offIdx})
                : IRB.CreateGEP(iter->first->getValueType(), iter->first,
                                {zero32, offIdx});

        LoadInst *encLoad = IRB.CreateLoad(CDA_k1->getElementType(), EncGEP,
                                           "strcry.enc");
        Value *decoded = encLoad;

        if (isI8) {
          // ── Vernam-GF8 decryption ──────────────────────────────────────
          //
          // plain[i] = GF8_mul(enc[i], k2inv[i]) XOR k1[i]
          //
          // k1s[] and k2invs[] are FULL-LAYOUT arrays (one entry per element,
          // including unencrypted slots).  Index by `idx` (element position),
          // NOT by `ko` (compact offset into the encrypted-only `encry[]`).
          //
          // k2inv[i] is inlined as a compile-time immediate in the GF8 chain.
          // k1[i] is a compile-time constant XOR'd at the end.
          uint8_t k1    = (uint8_t)CDA_k1->getElementAsInteger(idx);
          uint8_t k2inv = (CDA_k2inv &&
                           idx < CDA_k2inv->getType()->getNumElements())
                              ? (uint8_t)CDA_k2inv->getElementAsInteger(idx)
                              : 1u; // fallback: identity (no GF8 mul effect)

          // Step 1: GF8_mul(enc, k2inv) — emit shift-XOR carry-less multiply
          decoded = emitGF8Mul(IRB, encLoad, k2inv, I8Ty);

          // Step 2: XOR with k1 (OTP reversal — plain = gf8_result ^ k1)
          decoded = IRB.CreateXor(decoded,
                                  ConstantInt::get(I8Ty, k1), "strcry.otpxor");
        } else {
          // Non-i8: plain XOR (wide types use simple XOR, no GF8 layer).
          // keys[] is full-layout — index by `idx`, not compact `ko`.
          decoded = IRB.CreateXor(decoded, CDA_k1->getElementAsConstant(idx));
        }

        IRB.CreateStore(decoded, DecGEP);
      }
    }
    IRB.CreateBr(C);
  } // End of HandleDecryptionBlock
};

ModulePass *createStringEncryptionPass(bool flag) {
  return new StringEncryption(flag);
}
} // namespace llvm

char StringEncryption::ID = 0;
INITIALIZE_PASS(StringEncryption, "strcry", "Enable String Encryption", false,
                false)
