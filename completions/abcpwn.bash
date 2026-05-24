# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# bash completion for abcpwn. Source manually with
#   . /path/to/abcpwn.bash
# or install to /usr/share/bash-completion/completions/abcpwn for
# automatic lazy-loading by the bash-completion package.

_abcpwn_complete() {
    local cur words cword
    _init_completion -n =: 2>/dev/null || {
        cur="${COMP_WORDS[COMP_CWORD]}"
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    }

    local subcommands="
        info syms strings search hash
        pack unpack hex unhex b64 xor errno signal constgrep
        asm disasm phd
        cyclic
        gadget rop one-gadget
        srop ret2dl dynelf aslr-bypass
        shellcode
        fmt
        got
        heap safe-link
        iofile vtable
        seccomp libc
        pwninit pwn template diff patch
    "

    local global_flags="
        --format --color --no-color --no-banner --config --log-file
        --allow-network --help --version
    "

    # If the user has not yet entered a subcommand, complete subcommand
    # names plus global flags.
    local found_sub=""
    local i
    for ((i=1; i < cword; i++)); do
        case "${words[i]}" in
            -*) continue ;;
            *) found_sub="${words[i]}"; break ;;
        esac
    done

    if [ -z "$found_sub" ]; then
        case "$cur" in
            -*)
                # shellcheck disable=SC2207
                COMPREPLY=( $(compgen -W "$global_flags" -- "$cur") )
                ;;
            *)
                # shellcheck disable=SC2207
                COMPREPLY=( $(compgen -W "$subcommands" -- "$cur") )
                ;;
        esac
        return 0
    fi

    # Past the subcommand: complete --help on flag-shaped tokens and
    # fall back to filename completion for positionals.
    case "$cur" in
        -*)
            # shellcheck disable=SC2207
            COMPREPLY=( $(compgen -W "--help $global_flags" -- "$cur") )
            ;;
        *)
            # shellcheck disable=SC2207
            COMPREPLY=( $(compgen -f -- "$cur") )
            ;;
    esac
}

complete -F _abcpwn_complete abcpwn
