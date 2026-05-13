cmake_minimum_required(VERSION 3.20)
project(ollvm-next)

set(LT_LLVM_INSTALL_DIR  "" CACHE PATH "LLVM install prefix (e.g. /opt/homebrew/opt/llvm@20)")

list(APPEND CMAKE_PREFIX_PATH "${LT_LLVM_INSTALL_DIR}/lib/cmake/llvm/")

find_package(LLVM REQUIRED CONFIG)
if("${LLVM_VERSION_MAJOR}" VERSION_LESS 18)
  message(FATAL_ERROR "Found LLVM ${LLVM_VERSION_MAJOR}, but need LLVM 18 or above")
endif()
message(STATUS "OLLVM-Next building against LLVM ${LLVM_VERSION_MAJOR}.${LLVM_VERSION_MINOR}")

list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)

separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})
include_directories(${LLVM_INCLUDE_DIRS})

#===============================================================================
# Build configuration
#===============================================================================
# Match LLVM's C++ standard; clamp to C++20 minimum for new pass features.
# LLVM 18-19 use C++17; LLVM 20+ use C++20.  Set 20 here so our new code
# (if_consteval, std::span, ranges) compiles correctly.
if("${LLVM_VERSION_MAJOR}" VERSION_GREATER_EQUAL 20)
  set(CMAKE_CXX_STANDARD 20 CACHE STRING "")
else()
  set(CMAKE_CXX_STANDARD 17 CACHE STRING "")
endif()

add_subdirectory(obfuscation)
