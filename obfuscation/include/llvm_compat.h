#pragma once

#include "llvm/Config/llvm-config.h"

// ── PassPlugin Header Compatibility ──────────────────────────────────────────
// LLVM 21/22 locate PassPlugin.h in llvm/Passes/PassPlugin.h.
// LLVM 23+ moved PassPlugin.h to llvm/Plugins/PassPlugin.h.
#if (defined(LLVM_VERSION_MAJOR) && LLVM_VERSION_MAJOR >= 23) ||               \
    __has_include("llvm/Plugins/PassPlugin.h")
#include "llvm/Plugins/PassPlugin.h"
#else
#include "llvm/Passes/PassPlugin.h"
#endif

// ── PassPlugin API Version ───────────────────────────────────────────────────
// LLVM 21 uses PassPlugin API version 1.
// LLVM 22 (used in Rust toolchains) and LLVM 23+ use PassPlugin API version 2.
#ifndef ENSIA_PLUGIN_API_VERSION
#if defined(ENSIA_RUST_PLUGIN)
#if defined(ENSIA_TARGET_LLVM_VERSION) && (ENSIA_TARGET_LLVM_VERSION <= 21)
#define ENSIA_PLUGIN_API_VERSION 1
#elif defined(ENSIA_TARGET_LLVM_VERSION) && (ENSIA_TARGET_LLVM_VERSION >= 22)
#define ENSIA_PLUGIN_API_VERSION 2
#else
#define ENSIA_PLUGIN_API_VERSION 2
#endif
#elif defined(LLVM_VERSION_MAJOR) && (LLVM_VERSION_MAJOR >= 23)
#ifdef LLVM_PLUGIN_API_VERSION
#define ENSIA_PLUGIN_API_VERSION LLVM_PLUGIN_API_VERSION
#else
#define ENSIA_PLUGIN_API_VERSION 2
#endif
#elif defined(LLVM_VERSION_MAJOR) && (LLVM_VERSION_MAJOR >= 22)
#define ENSIA_PLUGIN_API_VERSION 2
#else
#ifdef LLVM_PLUGIN_API_VERSION
#define ENSIA_PLUGIN_API_VERSION LLVM_PLUGIN_API_VERSION
#else
#define ENSIA_PLUGIN_API_VERSION 1
#endif
#endif
#endif

namespace llvm {
namespace compat {

// Safe Constant zero/null evaluation across LLVM 21, 22, and 23
inline bool isNullOrZero(const Constant *C) {
  if (!C)
    return false;
#if defined(LLVM_VERSION_MAJOR) && LLVM_VERSION_MAJOR >= 23
  return C->isNullValue();
#else
  return C->isNullValue() || C->isZeroValue();
#endif
}

} // namespace compat
} // namespace llvm
