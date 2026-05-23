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
# Build provenance fields consumed by --version output. Each lookup
# tolerates missing inputs so a clean tarball / non-git build still
# configures.

# git commit (short SHA) - "unknown" if not a git checkout
find_package(Git QUIET)
if(GIT_EXECUTABLE AND EXISTS "${CMAKE_SOURCE_DIR}/.git")
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" -C "${CMAKE_SOURCE_DIR}" rev-parse --short HEAD
        OUTPUT_VARIABLE ABCPWN_GIT_COMMIT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
endif()
if(NOT ABCPWN_GIT_COMMIT)
    set(ABCPWN_GIT_COMMIT "unknown")
endif()

# Full SemVer string with pre-release suffix from `git describe`.
# `git describe --tags --abbrev=0` returns the most recent tag
# (e.g. v0.1.0-alpha.2). We strip the leading 'v' to get a clean
# SemVer string. If no tag exists or git is unavailable, fall back
# to PROJECT_VERSION so the field is always populated.
if(GIT_EXECUTABLE AND EXISTS "${CMAKE_SOURCE_DIR}/.git")
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" -C "${CMAKE_SOURCE_DIR}" describe --tags --abbrev=0
        OUTPUT_VARIABLE ABCPWN_SEMVER_STRING
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(ABCPWN_SEMVER_STRING MATCHES "^v(.+)$")
        set(ABCPWN_SEMVER_STRING "${CMAKE_MATCH_1}")
    endif()
endif()
if(NOT ABCPWN_SEMVER_STRING)
    set(ABCPWN_SEMVER_STRING "${PROJECT_VERSION}")
endif()

# build date - honor SOURCE_DATE_EPOCH for reproducible builds
if(DEFINED ENV{SOURCE_DATE_EPOCH})
    execute_process(
        COMMAND date -u -d "@$ENV{SOURCE_DATE_EPOCH}" +%Y-%m-%d
        OUTPUT_VARIABLE ABCPWN_BUILD_DATE
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
endif()
if(NOT ABCPWN_BUILD_DATE)
    string(TIMESTAMP ABCPWN_BUILD_DATE "%Y-%m-%d" UTC)
endif()

# arch + compiler
set(ABCPWN_ARCH_TRIPLE "${CMAKE_SYSTEM_PROCESSOR}-${CMAKE_SYSTEM_NAME}")
string(TOLOWER "${ABCPWN_ARCH_TRIPLE}" ABCPWN_ARCH_TRIPLE)
set(ABCPWN_CXX_COMPILER "${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")

# vcpkg baseline - parse from vcpkg-configuration.json if present,
# else from vcpkg.json
set(ABCPWN_VCPKG_BASELINE "unknown")
foreach(_vcpkg_file
        "${CMAKE_SOURCE_DIR}/vcpkg-configuration.json"
        "${CMAKE_SOURCE_DIR}/vcpkg.json")
    if(EXISTS "${_vcpkg_file}")
        file(READ "${_vcpkg_file}" _vcpkg_contents)
        string(REGEX MATCH "\"baseline\"[ \t\n]*:[ \t\n]*\"([0-9a-f]+)\""
               _baseline_match "${_vcpkg_contents}")
        if(CMAKE_MATCH_1)
            string(SUBSTRING "${CMAKE_MATCH_1}" 0 12 ABCPWN_VCPKG_BASELINE)
            break()
        endif()
    endif()
endforeach()

# LIEF + Capstone versions from find_package config
if(DEFINED LIEF_VERSION_STRING)
    set(ABCPWN_LIEF_VERSION "${LIEF_VERSION_STRING}")
elseif(DEFINED LIEF_VERSION)
    set(ABCPWN_LIEF_VERSION "${LIEF_VERSION}")
else()
    set(ABCPWN_LIEF_VERSION "unknown")
endif()
if(DEFINED capstone_VERSION)
    set(ABCPWN_CAPSTONE_VERSION "${capstone_VERSION}")
else()
    set(ABCPWN_CAPSTONE_VERSION "unknown")
endif()

# Feature flags as C++ bool literals
if(ABCPWN_WITH_KEYSTONE)
    set(ABCPWN_HAVE_KEYSTONE "true")
else()
    set(ABCPWN_HAVE_KEYSTONE "false")
endif()
if(ABCPWN_WITH_NETWORK)
    set(ABCPWN_HAVE_NETWORK "true")
else()
    set(ABCPWN_HAVE_NETWORK "false")
endif()
if(ABCPWN_WITH_UNICORN)
    set(ABCPWN_HAVE_UNICORN "true")
else()
    set(ABCPWN_HAVE_UNICORN "false")
endif()

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

# --- docs (man page + shell completions) -----------------------------------
include(Docs)

# --- install: the binary itself --------------------------------------------
include(GNUInstallDirs)
install(TARGETS abcpwn
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
        COMPONENT abcpwn)

# --- summary ----------------------------------------------------------------
abcpwn_platform_summary()
