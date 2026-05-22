# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Build hardening: stack protector, fortify source, RELRO, PIE, etc.
# Applied to release-style builds; debug builds skip some to keep
# iteration time low.

include_guard(GLOBAL)

function(abcpwn_apply_hardening target)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        return()
    endif()

    set(_compile_flags
        -fstack-protector-strong
        -fstack-clash-protection
        -fcf-protection=full
        -D_GLIBCXX_ASSERTIONS
    )
    set(_link_flags
        -Wl,-z,relro
        -Wl,-z,now
        -Wl,-z,noexecstack
        -Wl,-z,separate-code
    )

    if(CMAKE_BUILD_TYPE MATCHES "Release|MinSizeRel|RelWithDebInfo")
        list(APPEND _compile_flags -D_FORTIFY_SOURCE=3 -O2)
    endif()

    # PIE
    set_target_properties(${target} PROPERTIES POSITION_INDEPENDENT_CODE ON)

    target_compile_options(${target} PRIVATE ${_compile_flags})
    target_link_options(${target} PRIVATE ${_link_flags})
endfunction()
