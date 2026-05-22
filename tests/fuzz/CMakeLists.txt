# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# libFuzzer harnesses. Built only when ABCPWN_BUILD_FUZZERS=ON and the
# active compiler is clang (the fuzz preset enforces this). Each
# harness is a standalone executable linked against abcpwn_core; it
# defines LLVMFuzzerTestOneInput and is invoked manually by the
# maintainer (or by .github/workflows/fuzz.yml nightly).

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(WARNING "abcpwn: ABCPWN_BUILD_FUZZERS=ON requires clang; "
                    "fuzz harnesses disabled for ${CMAKE_CXX_COMPILER_ID}")
    return()
endif()

set(_fuzz_flags "-fsanitize=fuzzer,address")

function(abcpwn_add_fuzz_harness name source)
    add_executable(${name} ${source})
    target_link_libraries(${name} PRIVATE abcpwn_core)
    target_compile_options(${name} PRIVATE ${_fuzz_flags})
    target_link_options(${name}    PRIVATE ${_fuzz_flags})
    set_target_properties(${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/fuzz")
endfunction()

abcpwn_add_fuzz_harness(fuzz_binary_loader   fuzz_binary_loader.cpp)
abcpwn_add_fuzz_harness(fuzz_seccomp_decoder fuzz_seccomp_decoder.cpp)
abcpwn_add_fuzz_harness(fuzz_fmt_parser      fuzz_fmt_parser.cpp)
abcpwn_add_fuzz_harness(fuzz_gadget_filter   fuzz_gadget_filter.cpp)
