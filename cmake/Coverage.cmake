# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# gcov / lcov instrumentation enabled with -DABCPWN_COVERAGE=ON.

include_guard(GLOBAL)

function(abcpwn_apply_coverage target)
    if(NOT ABCPWN_COVERAGE)
        return()
    endif()

    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        message(WARNING "abcpwn: coverage requested but compiler is ${CMAKE_CXX_COMPILER_ID}; skipping")
        return()
    endif()

    target_compile_options(${target} PRIVATE --coverage -O0 -g)
    target_link_options(${target} PRIVATE --coverage)
endfunction()
