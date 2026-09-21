#ifdef ENSIA_RUST_PLUGIN
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/SourceMgr.h"
#include <memory>

namespace llvm {

extern "C" {

#if (defined(LLVM_VERSION_MAJOR) && LLVM_VERSION_MAJOR <= 21) &&               \
    (!defined(ENSIA_TARGET_LLVM_VERSION) || ENSIA_TARGET_LLVM_VERSION >= 22)
// Shims for LLVM 21 -> LLVM 22/23 ConstantInt::get ABI change (4th boolean
// added in LLVM 22)
ConstantInt *_ZN4llvm11ConstantInt3getEPNS_4TypeEmbb(Type *Ty, uint64_t V,
                                                     bool isSigned,
                                                     bool isExplicit);
ConstantInt *_ZN4llvm11ConstantInt3getEPNS_11IntegerTypeEmbb(IntegerType *Ty,
                                                             uint64_t V,
                                                             bool isSigned,
                                                             bool isExplicit);

ConstantInt *_ZN4llvm11ConstantInt3getEPNS_4TypeEmb(Type *Ty, uint64_t V,
                                                    bool isSigned) {
  return _ZN4llvm11ConstantInt3getEPNS_4TypeEmbb(Ty, V, isSigned, false);
}

ConstantInt *_ZN4llvm11ConstantInt3getEPNS_11IntegerTypeEmb(IntegerType *Ty,
                                                            uint64_t V,
                                                            bool isSigned) {
  return _ZN4llvm11ConstantInt3getEPNS_11IntegerTypeEmbb(Ty, V, isSigned,
                                                         false);
}

// Shim for LLVM 21 -> LLVM 22 parseIRFile ABI change (5th parameter
// AsmParserContext* added in LLVM 22)
std::unique_ptr<Module>
_ZN4llvm11parseIRFileENS_9StringRefERNS_12SMDiagnosticERNS_11LLVMContextENS_15ParserCallbacksEPNS_16AsmParserContextE(
    StringRef Filename, SMDiagnostic &Err, LLVMContext &Context,
    ParserCallbacks Callbacks, void *AsmParserCtx);

std::unique_ptr<Module>
_ZN4llvm11parseIRFileENS_9StringRefERNS_12SMDiagnosticERNS_11LLVMContextENS_15ParserCallbacksE(
    StringRef Filename, SMDiagnostic &Err, LLVMContext &Context,
    ParserCallbacks Callbacks) {
  return _ZN4llvm11parseIRFileENS_9StringRefERNS_12SMDiagnosticERNS_11LLVMContextENS_15ParserCallbacksEPNS_16AsmParserContextE(
      Filename, Err, Context, Callbacks, nullptr);
}

#endif

} // extern "C"

} // namespace llvm

#endif
