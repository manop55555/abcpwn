% ABCPWN(1) abcpwn 0.1.0 | abcpwn manual
% manop55555
% 2026-05-22

# NAME

abcpwn - binary exploitation toolkit

# SYNOPSIS

**abcpwn** \[**--format** *fmt*\] \[**--color** *policy*\]
\[**--no-color**\] \[**--no-banner**\] \[**--config** *path*\]
\[**--log-file** *path*\] \[**--allow-network**\]
\[**--help**\] \[**--version**\] *subcommand* \[*args*...\]

# DESCRIPTION

**abcpwn** is a native C++20 command-line toolkit for binary
exploitation. It consolidates ELF, PE, and Mach-O inspection,
ROP gadget discovery, shellcode generation, format-string
primitives, glibc heap exploitation helpers, seccomp BPF analysis,
libc fingerprint resolution, GOT/PLT inspection,
sigreturn-oriented programming, and ret2dlresolve into one
native binary. The binary is dynamically linked against the
system libc and libm; every other dependency (LIEF, Capstone,
CLI11, nlohmann/json, spdlog) is statically bundled.

The default build makes no network calls. Two subcommands
(**libc download**, **pwninit**) can fetch remote data when the
global **--allow-network** flag is passed; otherwise they refuse
to connect.

There is no telemetry, no auto-update, and no spawning of the
analyzed binaries. **abcpwn** parses; it never executes its
target.

# GLOBAL OPTIONS

**--format** *pretty* | *json*
:   Output format. **pretty** is human-readable (default).
    **json** emits a stable, versioned schema for pipelines.

**--color** *auto* | *always* | *never*
:   Color policy. **auto** (default) honors `NO_COLOR` and
    `isatty(stdout)`.

**--no-color**
:   Equivalent to **--color never**.

**--no-banner**
:   Suppress the banner block on **--version** and bare
    invocations.

**--config** *path*
:   Read configuration from the named TOML file.

**--log-file** *path*
:   Write a JSON log of the run to the named path.

**--allow-network**
:   Permit the two network-using subcommands
    (**libc download**, **pwninit**) to make HTTPS requests.
    Without this flag, network-using subcommands exit with code
    12 (`NetworkDisabled`).

**--help**
:   Print help and exit.

**--version**
:   Print version, build metadata, and enabled features.

# COMMANDS

The 38 subcommands are organized into 13 groups. **abcpwn**
*subcommand* **--help** prints the canonical option list for any
subcommand.

**recon**: **info**, **syms**, **strings**, **search**, **hash**

**encoding**: **pack**, **unpack**, **hex**, **unhex**, **b64**,
**xor**, **errno**, **constgrep**

**asm**: **asm**, **disasm**, **phd**

**pattern**: **cyclic**

**rop**: **gadget**, **rop**, **one-gadget**

**specialized**: **srop**, **ret2dl**, **dynelf**, **aslr-bypass**

**shellcode**: **shellcode**

**format string**: **fmt**

**got/plt**: **got**

**heap**: **heap**, **safe-link**

**file/c++**: **iofile**, **vtable**

**sandbox**: **seccomp**, **libc**

**workflow**: **pwninit**, **pwn**, **template**, **diff**,
**patch**

See **abcpwn-commands**(7) for the full reference (or the
project's docs/COMMANDS.md).

# EXAMPLES

Inspect a binary:

    abcpwn info ./challenge

Find ROP gadgets matching a pattern:

    abcpwn gadget ./libc.so.6 --filter 'pop rdi'

Synthesize a ROP chain that calls execve("/bin/sh"):

    abcpwn rop ./challenge --execve

Generate a cyclic pattern and search for the offset of a leaked
four bytes:

    abcpwn cyclic 200
    abcpwn cyclic --search 0x6161616a

Emit JSON output for pipelines:

    abcpwn --format json info /bin/ls | jq .findings

# EXIT STATUS

Exit codes are stable across the v0.1 line and form part of the
CLI contract.

| Code | Name             | Meaning |
|------|------------------|---------|
| 0    | Ok               | success |
| 1    | Generic          | unspecified runtime failure |
| 2    | UsageError       | bad arguments or unknown flag |
| 3    | InternalError    | a bug in **abcpwn** itself |
| 4    | FeatureDisabled  | compiled without a requested feature |
| 5    | IoError          | generic I/O failure |
| 6    | PermissionDenied | file present but not readable |
| 7    | NotFound         | path does not exist |
| 8    | InvalidInput     | flag value did not validate |
| 9    | SizeExceeded     | input larger than the configured cap |
| 10   | Unsupported      | format/arch/feature not supported |
| 11   | Corrupted        | input failed structural validation |
| 12   | NetworkDisabled  | network needed; **--allow-network** absent |
| 13   | NetworkError     | network request failed |
| 14   | Cancelled        | interrupted by SIGINT |
| 15   | Timeout          | operation exceeded its time budget |
| 16   | NotImplemented   | a TODO code path; treat as a bug |

# ENVIRONMENT

`ABCPWN_MAX_FILE_SIZE`
:   Override the default 2 GB input-file size cap.

`NO_COLOR`
:   When set (to any value), disables ANSI color output. The
    **--no-color** flag has the same effect.

`XDG_CACHE_HOME`
:   Override the default cache directory
    (`~/.cache/abcpwn/`).

# FILES

`~/.cache/abcpwn/`
:   Default cache directory. Holds downloaded libc archives (when
    **--allow-network** is used), pre-computed gadget indexes per
    binary (keyed by SHA-256), and per-run temporary state.

`~/.config/abcpwn/`
:   User configuration directory. Honored by **--config** when no
    path is supplied.

`/usr/share/man/man1/abcpwn.1`
:   This manual page.

`/usr/share/bash-completion/completions/abcpwn`
:   Bash completion script.

`/usr/share/zsh/site-functions/_abcpwn`
:   Zsh completion function.

`/usr/share/fish/vendor_completions.d/abcpwn.fish`
:   Fish completion script.

# CONFORMING TO

The CLI surface is covered by Semantic Versioning 2.0.0. The
JSON output carries its own `schema_version` independent of
**abcpwn**'s version.

# SEE ALSO

**checksec**(1), **objdump**(1), **readelf**(1), **xxd**(1),
**nm**(1)

Project home: https://github.com/manop55555/abcpwn

Full command reference, tutorials, and architecture decisions
live in the project's `docs/` directory.

# AUTHOR

manop55555 <manop55555@users.noreply.github.com>

# REPORTING BUGS

General bug reports: https://github.com/manop55555/abcpwn/issues

Security vulnerabilities: https://github.com/manop55555/abcpwn/security/advisories/new
(do NOT use the public issue tracker for security reports).

# COPYRIGHT

Copyright (c) 2026 manop55555. Licensed under the Apache License,
Version 2.0. See **abcpwn**'s `LICENSE` file for the full text.

The optional **abcpwn-full** build variant links the Keystone
assembler engine, which is licensed GPL-2.0-only. The resulting
combined work is distributed under GPL-2.0. See
`LICENSE-THIRD-PARTY.md` in the project tree for details.
