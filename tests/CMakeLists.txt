# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Tests aggregator. Each test target is added by per-step subdirectories
# that are wired in once the corresponding source is present.

include(CTest)
include(Catch)

set(ABCPWN_TESTS_FIXTURES_DIR "${CMAKE_SOURCE_DIR}/tests/fixtures"
    CACHE PATH "Path to test fixtures (binaries, libcs)")

set(ABCPWN_TESTS_SNAPSHOTS_DIR "${CMAKE_SOURCE_DIR}/tests/snapshots"
    CACHE PATH "Path to snapshot files")

# Unit subdirectory is added by step 3+ as test sources are written.
add_subdirectory(unit)

# End-to-end integration tests (per STEP/22 step 22). These chain
# multiple ICommand classes through a constructed Context to verify
# realistic CTF flows.
add_subdirectory(integration)

if(ABCPWN_BUILD_FUZZERS)
    add_subdirectory(fuzz)
endif()
