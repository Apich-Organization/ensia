cmake_minimum_required(VERSION 4.3)
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

add_subdirectory(obfuscation)
