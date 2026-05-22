# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Per-step subdirectories will be wired in here as they land. For now
# the only source attached to abcpwn_core is the placeholder marker
# so CMake will accept the library target.

target_sources(abcpwn_core PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/core/build_marker.cpp"
)
