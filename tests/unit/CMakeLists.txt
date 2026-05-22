# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Unit tests aggregator. Test sources are added by later steps. We define
# an empty interface library that they can hook into.

add_library(abcpwn_test_common INTERFACE)
target_link_libraries(abcpwn_test_common
    INTERFACE
        abcpwn_core
        Catch2::Catch2WithMain
)
target_compile_features(abcpwn_test_common INTERFACE cxx_std_20)
