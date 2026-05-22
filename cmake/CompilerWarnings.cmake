# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Project-wide warning flags. Treat warnings as errors in CI; relax locally
# only via per-file or per-line pragmas with justification.

include_guard(GLOBAL)

function(abcpwn_set_warnings target)
    set(_gcc_clang_common
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Wcast-align
        -Wunused
        -Woverloaded-virtual
        -Wconversion
        -Wsign-conversion
        -Wnull-dereference
        -Wdouble-promotion
        -Wformat=2
        -Wimplicit-fallthrough
        -Wmissing-declarations
        -Wzero-as-null-pointer-constant
    )

    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        list(APPEND _gcc_clang_common
            -Wmisleading-indentation
            -Wduplicated-cond
            -Wduplicated-branches
            -Wlogical-op
            -Wuseless-cast
        )
    endif()

    target_compile_options(${target} PRIVATE ${_gcc_clang_common})

    if(ABCPWN_WERROR)
        target_compile_options(${target} PRIVATE -Werror)
    endif()
endfunction()
