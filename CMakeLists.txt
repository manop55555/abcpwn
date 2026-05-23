# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555

cmake_minimum_required(VERSION 3.25)

project(abcpwn
    VERSION 0.1.0
    DESCRIPTION "binary exploitation toolkit"
    HOMEPAGE_URL "https://github.com/manop55555/abcpwn"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

# --- options ----------------------------------------------------------------
option(ABCPWN_WITH_KEYSTONE "Build with Keystone assembler (GPL-2 combined work)" OFF)
option(ABCPWN_WITH_NETWORK  "Build with network features (libc download, pwninit)" OFF)
option(ABCPWN_WITH_UNICORN  "Build with Unicorn (for seccomp emulation)"           OFF)
option(ABCPWN_BUILD_TESTS   "Build tests"                                          ON)
option(ABCPWN_BUILD_FUZZERS "Build libFuzzer harnesses"                            OFF)
option(ABCPWN_BUILD_BENCHES "Build benchmark suite"                                OFF)
option(ABCPWN_BUILD_DOCS    "Build man page + completion scripts"                  ON)
option(ABCPWN_COVERAGE      "Enable code coverage instrumentation"                 OFF)
option(ABCPWN_WERROR        "Treat warnings as errors"                             OFF)

set(ABCPWN_SANITIZER "" CACHE STRING
    "Optional sanitizer: address | undefined | thread | memory")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

include(Platform)
include(CompilerWarnings)
include(Sanitizers)
include(Hardening)
include(Coverage)
include(Dependencies)

# --- version header (generated) ---------------------------------------------
configure_file(
    "${CMAKE_SOURCE_DIR}/cmake/version.hpp.in"
    "${CMAKE_BINARY_DIR}/generated/abcpwn/core/version.hpp"
    @ONLY
)

# --- core library -----------------------------------------------------------
add_library(abcpwn_core STATIC)
target_include_directories(abcpwn_core
    PUBLIC
        "${CMAKE_SOURCE_DIR}/include"
        "${CMAKE_BINARY_DIR}/generated"
)
target_compile_features(abcpwn_core PUBLIC cxx_std_20)
abcpwn_set_warnings(abcpwn_core)
abcpwn_apply_sanitizer(abcpwn_core)
abcpwn_apply_hardening(abcpwn_core)
abcpwn_apply_coverage(abcpwn_core)

# Source list is built up across subdirectories; each adds via
# target_sources(abcpwn_core PRIVATE ...) once that step lands.
add_subdirectory(src)

# --- executable -------------------------------------------------------------
add_executable(abcpwn src/main.cpp)
target_link_libraries(abcpwn PRIVATE abcpwn_core)
abcpwn_set_warnings(abcpwn)
abcpwn_apply_sanitizer(abcpwn)
abcpwn_apply_hardening(abcpwn)
abcpwn_apply_coverage(abcpwn)

# --- tests ------------------------------------------------------------------
if(ABCPWN_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(ABCPWN_BUILD_BENCHES)
    add_subdirectory(benchmarks)
endif()

# --- install: the binary itself --------------------------------------------
include(GNUInstallDirs)
install(TARGETS abcpwn
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
        COMPONENT abcpwn)

# --- summary ----------------------------------------------------------------
abcpwn_platform_summary()
