# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Sanitizer flags. Selected via -DABCPWN_SANITIZER=<address|undefined|thread|memory>.

include_guard(GLOBAL)

function(abcpwn_apply_sanitizer target)
    if(NOT ABCPWN_SANITIZER)
        return()
    endif()

    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        message(WARNING "abcpwn: sanitizers requested but compiler is ${CMAKE_CXX_COMPILER_ID}; skipping")
        return()
    endif()

    set(_flags "")
    if(ABCPWN_SANITIZER STREQUAL "address")
        list(APPEND _flags -fsanitize=address -fno-omit-frame-pointer)
    elseif(ABCPWN_SANITIZER STREQUAL "undefined")
        list(APPEND _flags -fsanitize=undefined -fno-omit-frame-pointer)
    elseif(ABCPWN_SANITIZER STREQUAL "thread")
        list(APPEND _flags -fsanitize=thread)
    elseif(ABCPWN_SANITIZER STREQUAL "memory")
        if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
            message(FATAL_ERROR "abcpwn: memory sanitizer requires clang")
        endif()
        list(APPEND _flags -fsanitize=memory -fno-omit-frame-pointer -fsanitize-memory-track-origins)
    else()
        message(FATAL_ERROR "abcpwn: unknown sanitizer '${ABCPWN_SANITIZER}'")
    endif()

    target_compile_options(${target} PRIVATE ${_flags})
    target_link_options(${target} PRIVATE ${_flags})
endfunction()
