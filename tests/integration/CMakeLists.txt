# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# End-to-end integration tests. Each Catch2 test wires several
# ICommand classes through a constructed Context to exercise a
# realistic CTF flow without depending on the dispatcher binary;
# this keeps them fast and deterministic. The shell tests cover
# release-style flows (installer mock) and documentation hygiene.

function(abcpwn_add_integration_test name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE abcpwn_test_common)
    catch_discover_tests(${name})
endfunction()

abcpwn_add_integration_test(test_ret2win_flow       test_ret2win_flow.cpp)
abcpwn_add_integration_test(test_ret2libc_flow      test_ret2libc_flow.cpp)
abcpwn_add_integration_test(test_fmt_leak_flow      test_fmt_leak_flow.cpp)
abcpwn_add_integration_test(test_seccomp_flow       test_seccomp_flow.cpp)
abcpwn_add_integration_test(test_heap_flow          test_heap_flow.cpp)
abcpwn_add_integration_test(test_no_network         test_no_network.cpp)
abcpwn_add_integration_test(test_signal_handling    test_signal_handling.cpp)
abcpwn_add_integration_test(test_shellcode_executes test_shellcode_executes.cpp)

# Shell-script tests. Both run against the just-built abcpwn binary
# and the tracked docs/scripts/completions tree.
add_test(NAME test_installer
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/test_installer.sh"
            "$<TARGET_FILE:abcpwn>"
            "${CMAKE_SOURCE_DIR}")
add_test(NAME test_docs
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/test_docs.sh"
            "$<TARGET_FILE:abcpwn>"
            "${CMAKE_SOURCE_DIR}")
add_test(NAME test_about_network
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/test_about_network.sh"
            "$<TARGET_FILE:abcpwn>")
add_test(NAME test_no_stdout_pollution
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/test_no_stdout_pollution.sh"
            "$<TARGET_FILE:abcpwn>")
add_test(NAME test_readme_quickstart
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/test_readme_quickstart.sh"
            "$<TARGET_FILE:abcpwn>"
            "${CMAKE_SOURCE_DIR}")
add_test(NAME test_version_output
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/test_version_output.sh"
            "$<TARGET_FILE:abcpwn>")
add_test(NAME test_max_file_size
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/test_max_file_size.sh"
            "$<TARGET_FILE:abcpwn>")
add_test(NAME test_cli_exit_codes
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/test_cli_exit_codes.sh"
            "$<TARGET_FILE:abcpwn>")
add_test(NAME test_corrupt_elf
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/test_corrupt_elf.sh"
            "$<TARGET_FILE:abcpwn>")
add_test(NAME test_disasm_gadget_caps
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/test_disasm_gadget_caps.sh"
            "$<TARGET_FILE:abcpwn>")
add_test(NAME test_log_file
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/test_log_file.sh"
            "$<TARGET_FILE:abcpwn>")
add_test(NAME test_seccomp_dump
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/test_seccomp_dump.sh"
            "$<TARGET_FILE:abcpwn>")
add_test(NAME test_rop_multipop
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/test_rop_multipop.sh"
            "$<TARGET_FILE:abcpwn>")
add_test(NAME test_error_format
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/test_error_format.sh"
            "$<TARGET_FILE:abcpwn>")
add_test(NAME test_enum_validation
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/test_enum_validation.sh"
            "$<TARGET_FILE:abcpwn>")
add_test(NAME test_cyclic_limits
    COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/test_cyclic_limits.sh"
            "$<TARGET_FILE:abcpwn>")
