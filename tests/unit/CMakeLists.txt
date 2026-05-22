# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Unit tests aggregator. Test sources are added by later steps. We define
# an empty interface library that they can hook into.

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/test_paths.hpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/abcpwn/test_paths.hpp"
    @ONLY
)

add_library(abcpwn_test_common INTERFACE)
target_link_libraries(abcpwn_test_common
    INTERFACE
        abcpwn_core
        Catch2::Catch2WithMain
)
target_compile_features(abcpwn_test_common INTERFACE cxx_std_20)
target_include_directories(abcpwn_test_common
    INTERFACE "${CMAKE_CURRENT_BINARY_DIR}/generated"
)

function(abcpwn_add_unit_test name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE abcpwn_test_common)
    catch_discover_tests(${name})
endfunction()

abcpwn_add_unit_test(test_banner test_banner.cpp)
abcpwn_add_unit_test(test_safe_io test_safe_io.cpp)
abcpwn_add_unit_test(test_context test_context.cpp)
abcpwn_add_unit_test(test_progress test_progress.cpp)
abcpwn_add_unit_test(test_pretty test_pretty.cpp)
abcpwn_add_unit_test(test_json_writer test_json_writer.cpp)
abcpwn_add_unit_test(test_log test_log.cpp)
abcpwn_add_unit_test(test_binary_loader test_binary_loader.cpp)
