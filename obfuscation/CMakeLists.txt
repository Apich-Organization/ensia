cmake_minimum_required(VERSION 4.3)
project(Ensia LANGUAGES C CXX)

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

add_library(Ensia SHARED
        # ── Core infrastructure ──────────────────────────────────────────────
        CryptoUtils.cpp
        Utils.cpp
        # ── Original passes ──────────────────────────────────────────────────
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
        # ── OLLVM-Next new passes ────────────────────────────────────────────
        MBAObfuscation.cpp        # Mixed Boolean-Arithmetic substitution
        ChaosStateMachine.cpp     # Logistic-map-driven control-flow flattening
        VectorObfuscation.cpp     # Scalar-to-SIMD vector lifting
        )

target_include_directories(Ensia PRIVATE
        ${CMAKE_SOURCE_DIR}/obfuscation
        ${CMAKE_CURRENT_SOURCE_DIR}
        )

add_dependencies(Ensia intrinsics_gen LLVMLinker)

llvm_map_components_to_libnames(llvm_libs core support irreader linker passes)

if(WIN32)
target_link_libraries(Ensia PRIVATE ${llvm_libs})
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # For LLVM-19 on Windows, linking winpthread as static is required
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
