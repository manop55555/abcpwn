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
[![Platforms](https://img.shields.io/badge/platforms-linux-blue.svg)](#supported-platforms)

Native C++20 CLI toolkit for binary exploitation. Dynamically linked
against system libc/libm; every third-party library (LIEF, Capstone,
CLI11, nlohmann/json, spdlog) is statically bundled into the binary.
No telemetry. No auto-update. No network calls by default.

`abcpwn` is a single binary that consolidates the day-to-day toolkit of a
CTF binary-exploitation player: ELF/PE/Mach-O inspection, ROP gadget
discovery, shellcode generation, format string primitives, glibc heap
exploitation helpers, seccomp BPF analysis, libc fingerprint resolution,
GOT/PLT inspection, sigreturn-oriented programming, and ret2dlresolve.

The intent is to consolidate a typical assortment of Python and Ruby
wrappers (`pwntools`, `ROPgadget`, `seccomp-tools`, `libc-database`,
`checksec`, `pwninit`, and the string-locating slice of `one_gadget`)
behind one fast, deterministic, offline tool. Full feature parity is
not claimed; see [docs/COMMANDS.md](docs/COMMANDS.md) for the precise
scope of each subcommand and [docs/ROADMAP.md](docs/ROADMAP.md) for
deferred work.

## Status

Pre-release. The 0.1.x line covers the day-to-day subset of the listed
tools across all 13 command groups; symbolic constraint extraction
(one_gadget) and a pwntools-compatible scripting surface are deferred
past v0.1. See [CHANGELOG.md](CHANGELOG.md) for the
release history. The CLI surface is approaching stable; breaking changes
are still possible in MINOR bumps until 1.0.

## Supported platforms

| OS    | Arch    | Status                          |
|-------|---------|---------------------------------|
| Linux | x86_64  | tier 1 (pre-built binary)       |
| WSL2  | x86_64  | tier 1 (use Linux binary)       |

Other platforms (Linux aarch64, macOS arm64/x86_64) can be built
from source — see [BUILDING.md](BUILDING.md). Pre-built binaries for
additional platforms are planned for v0.2.

Native Windows is not supported; use WSL2. Inspection of Windows PE
binaries from Linux is supported (LIEF handles PE).

## Install

Pre-built binaries: [GitHub Releases](https://github.com/manop55555/abcpwn/releases).

### Install from the release tarball

```bash
curl -LO https://github.com/manop55555/abcpwn/releases/download/v0.1.0-alpha.2/abcpwn-linux-x86_64.tar.gz
curl -LO https://github.com/manop55555/abcpwn/releases/download/v0.1.0-alpha.2/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf abcpwn-linux-x86_64.tar.gz
cd abcpwn-linux-x86_64

sudo install -m 755 abcpwn                /usr/local/bin/abcpwn
sudo install -m 644 abcpwn.1              /usr/local/share/man/man1/abcpwn.1
sudo install -m 644 completions/abcpwn.bash \
    /usr/local/share/bash-completion/completions/abcpwn
# stock Ubuntu's default $fpath includes vendor-completions/
sudo install -m 644 completions/_abcpwn   /usr/local/share/zsh/vendor-completions/_abcpwn
# fall-back path for source builds:
# sudo install -m 644 completions/_abcpwn /usr/local/share/zsh/site-functions/_abcpwn
sudo install -m 644 completions/abcpwn.fish \
    /usr/local/share/fish/vendor_completions.d/abcpwn.fish
```

### One-liner

```bash
curl -sSL https://raw.githubusercontent.com/manop55555/abcpwn/main/scripts/install.sh | bash
```

From source: see [BUILDING.md](BUILDING.md).

## Quick start

```bash
abcpwn info ./challenge                          # checksec equivalent
abcpwn syms ./challenge --dangerous              # find unsafe imports
abcpwn gadget ./libc.so.6 --depth 8              # ROP gadget discovery
abcpwn rop ./challenge --syscall 59 \
    --syscall-arg 0x404020 --syscall-arg 0 \
    --syscall-arg 0                              # execve("/bin/sh", 0, 0)
abcpwn shellcode --preset sh --arch x86_64
abcpwn pwn 1.2.3.4:1337                          # target is host:port positional
abcpwn --format json info /bin/ls | jq .findings
```

Full command reference: [docs/COMMANDS.md](docs/COMMANDS.md).

## Subcommands

38 subcommands across 13 groups.

| Group       | Commands                                                       |
|-------------|----------------------------------------------------------------|
| recon       | `info`, `syms`, `strings`, `search`, `hash`                    |
| encoding    | `pack`, `unpack`, `hex`, `unhex`, `b64`, `xor`, `errno`, `signal`, `constgrep` |
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

Apache-2.0 by default. The opt-in `release-with-keystone` build that
statically links the Keystone assembler engine is a combined work under
GPL-2; it is not distributed as a release artifact in v0.1 and must be
built from source. See [LICENSE](LICENSE) and
[LICENSE-THIRD-PARTY.md](LICENSE-THIRD-PARTY.md).

## Authorship

Sole author and maintainer: [manop55555](https://github.com/manop55555).
