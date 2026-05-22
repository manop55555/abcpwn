# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Locate a system-installed Keystone library. When not found, the project
# build falls back to FetchContent (see cmake/Dependencies.cmake).

include_guard(GLOBAL)

find_path(KEYSTONE_INCLUDE_DIR
    NAMES keystone/keystone.h
    HINTS $ENV{KEYSTONE_ROOT}/include
)

find_library(KEYSTONE_LIBRARY
    NAMES keystone
    HINTS $ENV{KEYSTONE_ROOT}/lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Keystone
    REQUIRED_VARS KEYSTONE_LIBRARY KEYSTONE_INCLUDE_DIR
)

if(Keystone_FOUND AND NOT TARGET keystone::keystone)
    add_library(keystone::keystone UNKNOWN IMPORTED)
    set_target_properties(keystone::keystone PROPERTIES
        IMPORTED_LOCATION             "${KEYSTONE_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${KEYSTONE_INCLUDE_DIR}"
    )
endif()

mark_as_advanced(KEYSTONE_INCLUDE_DIR KEYSTONE_LIBRARY)
