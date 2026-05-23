# abcpwn

```
        P
        W           ┌─┐┌┐ ┌─┐┌─┐┬ ┬┌┐┌
        N           ├─┤├┴┐│  ├─┘│││││││
     ___|___        ┴ ┴└─┘└─┘┴  └┴┘┘└┘
       |A|
       |B|          binary exploitation toolkit  ·  v0.1.0
       |C|
       |0|          static analysis, ROP chain synthesis, shellcode
       |1|          generation, format string primitives, glibc heap
       |1|          exploitation, seccomp BPF analysis, libc fingerprint
       |0|          resolution, GOT/PLT inspection, sigreturn-oriented
       \ /          programming, and ret2dlresolve - all in a single
        '           native C++ binary. no telemetry. no auto-update.
```

[![CI](https://github.com/manop55555/abcpwn/actions/workflows/ci.yml/badge.svg)](https://github.com/manop55555/abcpwn/actions/workflows/ci.yml)
[![Sanitizers](https://github.com/manop55555/abcpwn/actions/workflows/sanitizers.yml/badge.svg)](https://github.com/manop55555/abcpwn/actions/workflows/sanitizers.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macos-blue.svg)](#supported-platforms)

Native C++20 CLI toolkit for binary exploitation. Dynamically linked
against system libc/libm; every third-party library (LIEF, Capstone,
CLI11, nlohmann/json, spdlog) is statically bundled into the binary.
No telemetry. No auto-update. No network calls by default.

`abcpwn` is a single binary that consolidates the day-to-day toolkit of a
CTF binary-exploitation player: ELF/PE/Mach-O inspection, ROP gadget
discovery, shellcode generation, format string primitives, glibc heap
exploitation helpers, seccomp BPF analysis, libc fingerprint resolution,
GOT/PLT inspection, sigreturn-oriented programming, and ret2dlresolve.

The intent is to replace a typical assortment of Python and Ruby wrappers
(`pwntools`, `ROPgadget`, `one_gadget`, `seccomp-tools`, `libc-database`,
`checksec`, `pwninit`) with one fast, deterministic, offline tool.

## Status

Pre-release. The 0.1.x line targets feature parity with the listed tools
across all 13 command groups. See [CHANGELOG.md](CHANGELOG.md) for the
release history. The CLI surface is approaching stable; breaking changes
are still possible in MINOR bumps until 1.0.

## Supported platforms

| OS    | Arch     | Status |
|-------|----------|--------|
| Linux | x86_64   | tier 1 |
| Linux | aarch64  | tier 1 |
| macOS | arm64    | tier 1 |
| macOS | x86_64   | tier 2 |

Windows is not supported as a host. Inspection of Windows PE binaries from
Linux or macOS is supported.

## Install

Pre-built binaries: [GitHub Releases](https://github.com/manop55555/abcpwn/releases).

One-liner:

```bash
curl -sSL https://raw.githubusercontent.com/manop55555/abcpwn/main/scripts/install.sh | bash
```

From source: see [BUILDING.md](BUILDING.md).

## Quick start

```bash
abcpwn info ./challenge                  # checksec equivalent
abcpwn syms ./challenge --type funcs     # symbol inspection
abcpwn gadget ./libc.so.6 --max-len 8    # ROP gadget discovery
abcpwn rop ./challenge --execve          # synthesize execve("/bin/sh") chain
abcpwn shellcode --preset sh --arch x86_64
abcpwn pwn ./challenge --tcp 1.2.3.4:1337
abcpwn --format json info /bin/ls | jq .findings
```

Full command reference: [docs/COMMANDS.md](docs/COMMANDS.md).

## Subcommands

38 subcommands across 13 groups.

| Group       | Commands                                                       |
|-------------|----------------------------------------------------------------|
| recon       | `info`, `syms`, `strings`, `search`, `hash`                    |
| encoding    | `pack`, `unpack`, `hex`, `unhex`, `b64`, `xor`, `errno`, `constgrep` |
| asm         | `asm`, `disasm`, `phd`                                         |
| pattern     | `cyclic`                                                       |
| rop         | `gadget`, `rop`, `one-gadget`                                  |
| specialized | `srop`, `ret2dl`, `dynelf`, `aslr-bypass`                      |
| shellcode   | `shellcode`                                                    |
| format      | `fmt`                                                          |
| got/plt     | `got`                                                          |
| heap        | `heap`, `safe-link`                                            |
| file/c++    | `iofile`, `vtable`                                             |
| sandbox     | `seccomp`, `libc`                                              |
| workflow    | `pwninit`, `pwn`, `template`, `diff`, `patch`                  |

## Documentation

- [BUILDING.md](BUILDING.md) - build from source, troubleshooting, profiling
- [SECURITY.md](SECURITY.md) - vulnerability disclosure
- [docs/COMMANDS.md](docs/COMMANDS.md) - every subcommand in detail
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - internal design
- [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) - threat model, mitigations, fuzzing
- [docs/PERFORMANCE.md](docs/PERFORMANCE.md) - performance methodology and numbers
- [docs/TUTORIALS.md](docs/TUTORIALS.md) - end-to-end walkthroughs
- [docs/FAQ.md](docs/FAQ.md) - common questions
- [docs/ROADMAP.md](docs/ROADMAP.md) - what is next
- [docs/ERROR_CODES.md](docs/ERROR_CODES.md) - exit codes and remediation
- [docs/SUPPORT.md](docs/SUPPORT.md) - supported versions
- [CHANGELOG.md](CHANGELOG.md) - release history
- [CONTRIBUTING.md](CONTRIBUTING.md) - contribution guide

## License

Apache-2.0 by default. The opt-in `abcpwn-full` build that statically links
the Keystone assembler engine is distributed under GPL-2 to satisfy the
combined-work clause. See [LICENSE](LICENSE) and
[LICENSE-THIRD-PARTY.md](LICENSE-THIRD-PARTY.md).

## Authorship

Sole author and maintainer: [manop55555](https://github.com/manop55555).
