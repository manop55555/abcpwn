# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Man page generation and shell-completion install rules.
# Gated on ABCPWN_BUILD_DOCS (default ON in CMakeLists.txt).
# Requires pandoc to produce the man page. When pandoc is absent,
# the install() rules for completions still apply but the man page
# target is skipped with a warning. CI environments that need a
# strict failure on pandoc-absent should add an explicit
# file-exists check on ${CMAKE_BINARY_DIR}/man/abcpwn.1 in the
# workflow rather than introducing a CMake-level toggle.

if(NOT ABCPWN_BUILD_DOCS)
    return()
endif()

include(GNUInstallDirs)

# ---------------------------------------------------------------
# Man page (pandoc-driven)
# ---------------------------------------------------------------

find_program(PANDOC pandoc)

if(NOT PANDOC)
    message(WARNING
        "pandoc not found; man page will not be generated. "
        "Install pandoc and reconfigure to enable. Shell "
        "completions install rules are unaffected.")
else()
    set(_abcpwn_man_src "${CMAKE_SOURCE_DIR}/man/abcpwn.1.md")
    set(_abcpwn_man_out_dir "${CMAKE_BINARY_DIR}/man")
    set(_abcpwn_man_out "${_abcpwn_man_out_dir}/abcpwn.1")

    file(MAKE_DIRECTORY "${_abcpwn_man_out_dir}")

    add_custom_command(
        OUTPUT  "${_abcpwn_man_out}"
        COMMAND "${PANDOC}" -s -t man
                "${_abcpwn_man_src}"
                -o "${_abcpwn_man_out}"
        DEPENDS "${_abcpwn_man_src}"
        COMMENT "Generating man page abcpwn.1 from abcpwn.1.md"
        VERBATIM
    )

    add_custom_target(abcpwn-man ALL DEPENDS "${_abcpwn_man_out}")

    install(FILES "${_abcpwn_man_out}"
            DESTINATION "${CMAKE_INSTALL_MANDIR}/man1"
            COMPONENT abcpwn-docs)
endif()

# ---------------------------------------------------------------
# Shell completions (always installed when ABCPWN_BUILD_DOCS=ON)
# Paths match STEP/17 lines 139 - 151 verbatim.
# ---------------------------------------------------------------

install(FILES "${CMAKE_SOURCE_DIR}/completions/abcpwn.bash"
        DESTINATION "${CMAKE_INSTALL_DATADIR}/bash-completion/completions"
        RENAME abcpwn
        COMPONENT abcpwn-docs)

install(FILES "${CMAKE_SOURCE_DIR}/completions/_abcpwn"
        DESTINATION "${CMAKE_INSTALL_DATADIR}/zsh/site-functions"
        COMPONENT abcpwn-docs)

install(FILES "${CMAKE_SOURCE_DIR}/completions/abcpwn.fish"
        DESTINATION "${CMAKE_INSTALL_DATADIR}/fish/vendor_completions.d"
        COMPONENT abcpwn-docs)
