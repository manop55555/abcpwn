# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# fish completion for abcpwn. Drop into
# ~/.config/fish/completions/abcpwn.fish for personal use, or
# /usr/share/fish/vendor_completions.d/abcpwn.fish for system-wide.

# Subcommand definitions: name + description. The descriptions
# mirror the binary's own help text.

# recon
complete -c abcpwn -n '__fish_use_subcommand' -a 'info'        -d 'show mitigations, arch, symbols, libc hint'
complete -c abcpwn -n '__fish_use_subcommand' -a 'syms'        -d 'list symbols (dynamic/static/imports/exports)'
complete -c abcpwn -n '__fish_use_subcommand' -a 'strings'     -d 'list printable strings in a binary'
complete -c abcpwn -n '__fish_use_subcommand' -a 'search'      -d 'search a binary for ASCII or hex byte patterns'
complete -c abcpwn -n '__fish_use_subcommand' -a 'hash'        -d 'compute file hash (sha256 default)'

# encoding
complete -c abcpwn -n '__fish_use_subcommand' -a 'pack'        -d 'pack an integer into raw bytes'
complete -c abcpwn -n '__fish_use_subcommand' -a 'unpack'      -d 'unpack raw bytes into an integer'
complete -c abcpwn -n '__fish_use_subcommand' -a 'hex'         -d 'encode raw input as hex bytes'
complete -c abcpwn -n '__fish_use_subcommand' -a 'unhex'       -d 'decode hex bytes into raw output'
complete -c abcpwn -n '__fish_use_subcommand' -a 'b64'         -d 'encode or decode base64'
complete -c abcpwn -n '__fish_use_subcommand' -a 'xor'         -d 'xor bytes against a repeating key'
complete -c abcpwn -n '__fish_use_subcommand' -a 'errno'       -d 'look up POSIX errno by number or name'
complete -c abcpwn -n '__fish_use_subcommand' -a 'constgrep'   -d 'search compiled-in constants'

# asm
complete -c abcpwn -n '__fish_use_subcommand' -a 'asm'         -d 'assemble source text into raw bytes'
complete -c abcpwn -n '__fish_use_subcommand' -a 'disasm'      -d 'disassemble raw bytes with capstone'
complete -c abcpwn -n '__fish_use_subcommand' -a 'phd'         -d 'pretty hex dump'

# pattern
complete -c abcpwn -n '__fish_use_subcommand' -a 'cyclic'      -d 'generate or search a cyclic sequence'

# rop
complete -c abcpwn -n '__fish_use_subcommand' -a 'gadget'      -d 'find ROP gadgets in a binary'
complete -c abcpwn -n '__fish_use_subcommand' -a 'rop'         -d 'build a ROP chain for a strategy'
complete -c abcpwn -n '__fish_use_subcommand' -a 'one-gadget'  -d 'find execve one-gadget candidates in libc'

# specialized
complete -c abcpwn -n '__fish_use_subcommand' -a 'srop'        -d 'build a sigreturn-oriented programming frame'
complete -c abcpwn -n '__fish_use_subcommand' -a 'ret2dl'      -d 'ret2dlresolve helper'
complete -c abcpwn -n '__fish_use_subcommand' -a 'dynelf'      -d 'consume leak pairs to identify libc'
complete -c abcpwn -n '__fish_use_subcommand' -a 'aslr-bypass' -d 'ASLR / PIE bypass helpers'

# shellcode
complete -c abcpwn -n '__fish_use_subcommand' -a 'shellcode'   -d 'emit a built-in shellcode payload'

# format string
complete -c abcpwn -n '__fish_use_subcommand' -a 'fmt'         -d 'format string analysis and payload generation'

# got
complete -c abcpwn -n '__fish_use_subcommand' -a 'got'         -d 'list GOT entries and build overwrite payloads'

# heap
complete -c abcpwn -n '__fish_use_subcommand' -a 'heap'        -d 'describe a heap exploitation primitive'
complete -c abcpwn -n '__fish_use_subcommand' -a 'safe-link'   -d 'encode or decode glibc safe-linking'

# file/c++
complete -c abcpwn -n '__fish_use_subcommand' -a 'iofile'      -d 'FILE-stream exploitation helper'
complete -c abcpwn -n '__fish_use_subcommand' -a 'vtable'      -d 'list/analyze/hijack C++ vtables in an ELF'

# sandbox
complete -c abcpwn -n '__fish_use_subcommand' -a 'seccomp'     -d 'decode and reason about seccomp BPF filters'
complete -c abcpwn -n '__fish_use_subcommand' -a 'libc'        -d 'identify and inspect glibc versions'

# workflow
complete -c abcpwn -n '__fish_use_subcommand' -a 'pwninit'     -d 'set up a CTF pwn challenge workspace'
complete -c abcpwn -n '__fish_use_subcommand' -a 'pwn'         -d 'I/O tubes for CTF pwn challenges'
complete -c abcpwn -n '__fish_use_subcommand' -a 'template'    -d 'emit a pwntools exploit skeleton'
complete -c abcpwn -n '__fish_use_subcommand' -a 'diff'        -d 'byte-level diff between two binaries'
complete -c abcpwn -n '__fish_use_subcommand' -a 'patch'       -d 'apply byte / NOP / asm patches to a binary'

# Global flags (apply at the top level and to subcommands)
complete -c abcpwn -l format     -d 'output format' -xa 'pretty json'
complete -c abcpwn -l color      -d 'color policy'  -xa 'auto always never'
complete -c abcpwn -l no-color   -d 'disable color output'
complete -c abcpwn -l no-banner  -d 'suppress the banner'
complete -c abcpwn -l config     -d 'path to a TOML config file' -r
complete -c abcpwn -l log-file   -d 'write a JSON log of the run' -r
complete -c abcpwn -l allow-network -d 'enable network for libc and pwninit'
complete -c abcpwn -s h -l help     -d 'print help'
complete -c abcpwn -l version       -d 'print version'
