# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Resolve every project dependency. vcpkg manifest mode pulls in:
#   LIEF, Capstone, CLI11, nlohmann_json, spdlog, Catch2
# FetchContent fills the rest (picosha2, optionally Keystone).

include_guard(GLOBAL)

include(FetchContent)
set(FETCHCONTENT_QUIET OFF)

# Pinned commits for FetchContent dependencies. Update via PR + CHANGELOG entry.
set(ABCPWN_PICOSHA2_COMMIT "27fcf6979298949e8a462e16d09a0351c18fcaf2"
    CACHE STRING "picosha2 pinned commit")
set(ABCPWN_KEYSTONE_TAG "0.9.2"
    CACHE STRING "Keystone tag for FetchContent (GPL-2 combined work)")

# --- vcpkg-managed dependencies ----------------------------------------------
find_package(LIEF CONFIG REQUIRED)
find_package(capstone CONFIG REQUIRED)
find_package(CLI11 CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)

if(ABCPWN_BUILD_TESTS)
    find_package(Catch2 3 CONFIG REQUIRED)
endif()

# --- header-only deps via FetchContent --------------------------------------
FetchContent_Declare(
    picosha2
    GIT_REPOSITORY https://github.com/okdshin/PicoSHA2.git
    GIT_TAG        ${ABCPWN_PICOSHA2_COMMIT}
    GIT_SHALLOW    FALSE
    UPDATE_DISCONNECTED TRUE
)
FetchContent_MakeAvailable(picosha2)

add_library(abcpwn_picosha2 INTERFACE)
target_include_directories(abcpwn_picosha2 INTERFACE ${picosha2_SOURCE_DIR})

# --- optional: network (libcurl) --------------------------------------------
if(ABCPWN_WITH_NETWORK)
    find_package(CURL REQUIRED)
endif()

# --- optional: Keystone (GPL-2 combined-work build) -------------------------
if(ABCPWN_WITH_KEYSTONE)
    message(STATUS "abcpwn: building GPL-2 combined work with Keystone ${ABCPWN_KEYSTONE_TAG}")
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")
    find_package(Keystone)
    if(NOT Keystone_FOUND)
        FetchContent_Declare(
            keystone
            GIT_REPOSITORY https://github.com/keystone-engine/keystone.git
            GIT_TAG        ${ABCPWN_KEYSTONE_TAG}
        )
        FetchContent_MakeAvailable(keystone)
    endif()
endif()

# --- optional: Unicorn (seccomp emulation) ----------------------------------
if(ABCPWN_WITH_UNICORN)
    find_package(unicorn CONFIG REQUIRED)
endif()
