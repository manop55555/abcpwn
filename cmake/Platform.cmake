# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Per-platform setup: deployment targets, link flags, RPATH.

include_guard(GLOBAL)

if(APPLE)
    if(NOT CMAKE_OSX_DEPLOYMENT_TARGET)
        set(CMAKE_OSX_DEPLOYMENT_TARGET "13.0" CACHE STRING "macOS deployment target" FORCE)
    endif()
endif()

if(UNIX AND NOT APPLE)
    # Static C/C++ stdlib for portable release binaries on Linux.
    if(CMAKE_BUILD_TYPE STREQUAL "Release" AND NOT ABCPWN_SHARED_RUNTIME)
        set(CMAKE_EXE_LINKER_FLAGS
            "${CMAKE_EXE_LINKER_FLAGS} -static-libstdc++ -static-libgcc")
    endif()
endif()

set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

function(abcpwn_platform_summary)
    message(STATUS "abcpwn platform:")
    message(STATUS "    system        ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_PROCESSOR}")
    message(STATUS "    compiler      ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
    message(STATUS "    build type    ${CMAKE_BUILD_TYPE}")
    message(STATUS "    keystone      ${ABCPWN_WITH_KEYSTONE}")
    message(STATUS "    network       ${ABCPWN_WITH_NETWORK}")
    message(STATUS "    unicorn       ${ABCPWN_WITH_UNICORN}")
    message(STATUS "    tests         ${ABCPWN_BUILD_TESTS}")
    message(STATUS "    fuzzers       ${ABCPWN_BUILD_FUZZERS}")
    message(STATUS "    sanitizer     ${ABCPWN_SANITIZER}")
endfunction()
