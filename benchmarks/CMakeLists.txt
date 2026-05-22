# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Catch2-based microbenchmarks. Built when ABCPWN_BUILD_BENCHES=ON.
# Each bench links against abcpwn_core and uses Catch2's BENCHMARK
# macro -- no separate benchmark dependency needed.

if(NOT TARGET Catch2::Catch2WithMain)
    find_package(Catch2 3 CONFIG REQUIRED)
endif()

# Generate bench_paths.hpp so benchmark sources find the test
# fixtures dir without depending on test_paths.hpp (which lives in
# the tests build tree).
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/bench_paths.hpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/abcpwn/bench_paths.hpp"
    @ONLY)

function(abcpwn_add_bench name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name}
        PRIVATE abcpwn_core Catch2::Catch2WithMain)
    target_include_directories(${name}
        PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
    set_target_properties(${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/benchmarks")
endfunction()

abcpwn_add_bench(bench_info     bench_info.cpp)
abcpwn_add_bench(bench_disasm   bench_disasm.cpp)
abcpwn_add_bench(bench_gadget   bench_gadget.cpp)
abcpwn_add_bench(bench_libc_id  bench_libc_id.cpp)
