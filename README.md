# abcpwn

[![CI](https://github.com/manop55555/abcpwn/actions/workflows/ci.yml/badge.svg)](https://github.com/manop55555/abcpwn/actions/workflows/ci.yml)
[![CodeQL](https://github.com/manop55555/abcpwn/actions/workflows/codeql.yml/badge.svg)](https://github.com/manop55555/abcpwn/actions/workflows/codeql.yml)
[![Sanitizers](https://github.com/manop55555/abcpwn/actions/workflows/sanitizers.yml/badge.svg)](https://github.com/manop55555/abcpwn/actions/workflows/sanitizers.yml)
[![Coverage](https://codecov.io/gh/manop55555/abcpwn/branch/main/graph/badge.svg)](https://codecov.io/gh/manop55555/abcpwn)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macos-blue.svg)](#supported-platforms)

Native C++20 CLI toolkit for binary exploitation. Statically linked. Zero
runtime dependencies. Zero telemetry.

```
<banner placeholder - rendered at runtime>
```

## What it does

`abcpwn` is a single static binary that consolidates the day-to-day toolkit
of a CTF binary-exploitation player: ELF/PE/Mach-O inspection, ROP gadget
discovery, shellcode generation, format string primitives, glibc heap
exploitation helpers, seccomp BPF analysis, libc fingerprint resolution,
GOT/PLT inspection, sigreturn-oriented programming, and ret2dlresolve.

The intent is to replace a typical assortment of Python wrappers
(`pwntools`, `ROPgadget`, `one_gadget`, `seccomp-tools`, `libc-database`,
`checksec`, `pwninit`) with one fast, deterministic, offline tool.

## Status

Pre-release. The 0.1.0 series targets feature parity with the listed Python
tools for the recon, encoding, assembly, ROP, and shellcode groups; the
remaining groups (heap, FILE/C++, sandbox) ship over the 0.1.x point
releases.

See [CHANGELOG](CHANGELOG.md) for the release history.

## Supported platforms

| OS    | Arch     | Status |
|-------|----------|--------|
| Linux | x86_64   | tier 1 |
| Linux | aarch64  | tier 1 |
| macOS | arm64    | tier 1 |
| macOS | x86_64   | tier 2 |

Windows is not supported as a host. Inspection of Windows PE binaries from
Linux/macOS is supported.

## Install

Pre-built binaries: [GitHub Releases](https://github.com/manop55555/abcpwn/releases).

One-liner:

```bash
curl -sSL https://raw.githubusercontent.com/manop55555/abcpwn/main/scripts/install.sh | bash
```

From source: see [BUILDING.md](BUILDING.md).

## Quick start

```bash
abcpwn info ./challenge          # checksec equivalent
abcpwn syms ./challenge --type funcs
abcpwn gadget ./libc.so.6 --max-len 8
abcpwn rop ./challenge --execve
abcpwn shellcode --preset sh --arch amd64
abcpwn pwn ./challenge --tcp 1.2.3.4:1337
```

Full command reference: [docs/COMMANDS.md](docs/COMMANDS.md).

## Documentation

- [BUILDING.md](BUILDING.md) — build from source
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — design overview
- [docs/COMMANDS.md](docs/COMMANDS.md) — every subcommand
- [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) — what `abcpwn` does and does not touch
- [docs/FAQ.md](docs/FAQ.md)
- [SECURITY.md](SECURITY.md) — vulnerability disclosure

## License

Apache-2.0 by default. An opt-in `abcpwn-full` build that statically links
Keystone is distributed under GPL-2 to satisfy the combined-work clause.
See [LICENSE](LICENSE) and [LICENSE-THIRD-PARTY.md](LICENSE-THIRD-PARTY.md).

## Authorship

Sole author and maintainer: [manop55555](https://github.com/manop55555).
