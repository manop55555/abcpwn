# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Per-step subdirectories will be wired in here as they land. For now
# the only source attached to abcpwn_core is the placeholder marker
# so CMake will accept the library target.

target_sources(abcpwn_core PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/core/build_marker.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/config.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/progress.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/safe_io.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/signal.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/formats/binary_loader.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/output/banner.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/output/json_writer.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/output/log.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/output/pretty.cpp"
)

target_link_libraries(abcpwn_core PUBLIC
    nlohmann_json::nlohmann_json
    spdlog::spdlog
    LIEF::LIEF
)
