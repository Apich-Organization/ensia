cmake_minimum_required(VERSION 3.28)
project(Ensia LANGUAGES C CXX)

if(NOT DEFINED LLVM_FOUND)
  find_package(LLVM REQUIRED CONFIG)
  list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
  include(AddLLVM)
  include_directories(${LLVM_INCLUDE_DIRS})
  add_definitions(${LLVM_DEFINITIONS})
endif()

# Include LLVM CMake functions (such as llvm_map_components_to_libnames)
if(COMMAND LLVMMapComponentsToLibnames)
  # already available
elseif(EXISTS "${LLVM_CMAKE_DIR}/LLVM-Config.cmake")
  include("${LLVM_CMAKE_DIR}/LLVM-Config.cmake")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Position Independent Code
set(CMAKE_POSITION_INDEPENDENT_CODE ON FORCE)
# LTO enabled
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE FORCE)
# Flags
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG" CACHE STRING "Flags used by the CXX compiler for release builds." FORCE)
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -DDEBUG -g" CACHE STRING "Flags used by the CXX compiler for debug builds." FORCE)

set(ENSIA_SOURCES
        CryptoUtils.cpp
        Utils.cpp
        ObfConfig.cpp
        FunctionCallObfuscate.cpp
        BogusControlFlow.cpp
        SubstituteImpl.cpp
        Substitution.cpp
        Flattening.cpp
        SplitBasicBlocks.cpp
        AntiClassDump.cpp
        AntiDebugging.cpp
        AntiHooking.cpp
        StringEncryption.cpp
        IndirectBranch.cpp
        FunctionWrapper.cpp
        ConstantEncryption.cpp
        Obfuscation.cpp
        MBAObfuscation.cpp        # Mixed Boolean-Arithmetic substitution
        ChaosStateMachine.cpp     # Logistic-map-driven control-flow flattening
        VectorObfuscation.cpp     # Scalar-to-SIMD vector lifting
        )

add_library(Ensia SHARED ${ENSIA_SOURCES})

target_include_directories(Ensia PRIVATE
        ${CMAKE_SOURCE_DIR}/obfuscation
        ${CMAKE_CURRENT_SOURCE_DIR}
        )

add_dependencies(Ensia intrinsics_gen LLVMLinker)

if(WIN32)
  if(COMMAND llvm_map_components_to_libnames)
    llvm_map_components_to_libnames(llvm_libs Core Support Passes TransformUtils Analysis TargetParser Linker)
  endif()
  if(llvm_libs)
    target_link_libraries(Ensia PRIVATE ${llvm_libs})
  endif()
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # For MinGW on Windows, linking winpthread as static is required
    if(WIN32)
    set_target_properties(Ensia PROPERTIES
        LINK_FLAGS
        "-static -static-libgcc -Wl,-Bstatic,--whole-archive -lwinpthread -lstdc++ -Wl,--no-whole-archive -Wl,-Bdynamic"
    )
    endif()
endif()

# Embed git commit hash so the runtime banner is informative
execute_process(
        COMMAND git log -1 --format=%H
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
        OUTPUT_VARIABLE ENSIA_GIT_COMMIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
target_compile_definitions(Ensia PRIVATE
        "-DGIT_COMMIT_HASH=\"${ENSIA_GIT_COMMIT_HASH}\""
        # Expose LLVM major version to source (belt-and-suspenders alongside
        # the LLVM_VERSION_MAJOR macro that LLVM itself injects).
        "-DOLLVM_NEXT=1"
)

# Suppress warnings that are harmless but noisy with LLVM headers
target_compile_options(Ensia PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:
            -Wno-unused-parameter
            -Wno-deprecated-declarations
        >
)

# Optional target for Rustc plugin
execute_process(
    COMMAND rustc --print sysroot
    OUTPUT_VARIABLE RUSTC_SYSROOT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(RUSTC_SYSROOT AND EXISTS "${RUSTC_SYSROOT}/lib")
    file(GLOB RUST_LLVM_LIB "${RUSTC_SYSROOT}/lib/libLLVM*rust*.so*")
    if(RUST_LLVM_LIB)
        add_library(EnsiaRust SHARED ${ENSIA_SOURCES})
        set_target_properties(EnsiaRust PROPERTIES OUTPUT_NAME "Ensia_rust")
        target_include_directories(EnsiaRust PRIVATE
            ${CMAKE_SOURCE_DIR}/obfuscation
            ${CMAKE_CURRENT_SOURCE_DIR}
        )
        add_dependencies(EnsiaRust intrinsics_gen LLVMLinker)
        target_link_directories(EnsiaRust PRIVATE "${RUSTC_SYSROOT}/lib")

        # Extract the exact library name from the found file
        get_filename_component(RUST_LLVM_LIB_NAME "${RUST_LLVM_LIB}" NAME_WLE)
        # Remove the 'lib' prefix to pass it to target_link_libraries
        string(REGEX REPLACE "^lib" "" RUST_LLVM_LIB_LINK_NAME "${RUST_LLVM_LIB_NAME}")

        target_link_libraries(EnsiaRust PRIVATE ${RUST_LLVM_LIB_LINK_NAME})
        set_target_properties(EnsiaRust PROPERTIES
            BUILD_RPATH "${RUSTC_SYSROOT}/lib"
            INSTALL_RPATH "${RUSTC_SYSROOT}/lib"
        )
        target_compile_definitions(EnsiaRust PRIVATE
            "-DGIT_COMMIT_HASH=\"${ENSIA_GIT_COMMIT_HASH}\""
            "-DOLLVM_NEXT=1"
        )
        target_compile_options(EnsiaRust PRIVATE
            $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:
                -Wno-unused-parameter
                -Wno-deprecated-declarations
            >
        )
    endif()
endif()
