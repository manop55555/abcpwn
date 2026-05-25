# abcpwn

```
        P
        W           ┌─┐┌┐ ┌─┐┌─┐┬ ┬┌┐┌
        N           ├─┤├┴┐│  ├─┘│││││││
     ___|___        ┴ ┴└─┘└─┘┴  └┴┘┘└┘
       |A|
       |B|          binary exploitation toolkit  ·  v0.1.0
       |C|
       |0|          static analysis, ROP gadget search, shellcode,
       |1|          format-string primitives, glibc heap helpers,
       |1|          seccomp BPF analysis, libc fingerprinting, GOT/PLT
       |0|          inspection - one native C++ binary, offline by
       \ /          default. no telemetry. no auto-update.
        '
```

[![CI](https://github.com/manop55555/abcpwn/actions/workflows/ci.yml/badge.svg)](https://github.com/manop55555/abcpwn/actions/workflows/ci.yml)
[![CodeQL](https://github.com/manop55555/abcpwn/actions/workflows/codeql.yml/badge.svg)](https://github.com/manop55555/abcpwn/actions/workflows/codeql.yml)
[![Sanitizers](https://github.com/manop55555/abcpwn/actions/workflows/sanitizers.yml/badge.svg)](https://github.com/manop55555/abcpwn/actions/workflows/sanitizers.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![Release](https://img.shields.io/badge/release-v0.1.0-blue.svg)](https://github.com/manop55555/abcpwn/releases)

## Overview

abcpwn is a native C++ command-line toolkit for binary exploitation. It
provides offline analysis and exploit-primitive generation -- ELF/PE/Mach-O
inspection, ROP gadget search, format-string payloads, shellcode, glibc heap
and seccomp helpers -- from a single statically self-contained binary. It is
dynamically linked only against system libc/libm; the third-party libraries
(LIEF, Capstone, CLI11, nlohmann/json, spdlog, PicoSHA2) are statically
bundled. It makes no network calls by default, collects no telemetry, and
never executes the binaries it analyzes.

## Contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Usage examples](#usage-examples)
- [Process-driver integration](#process-driver-integration)
- [Supported platforms](#supported-platforms)
- [Authorized use](#authorized-use)
- [Security](#security)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Installation

Pre-built binary for Linux x86_64:

```bash
curl -LO https://github.com/manop55555/abcpwn/releases/latest/download/abcpwn-linux-x86_64.tar.gz
curl -LO https://github.com/manop55555/abcpwn/releases/latest/download/SHA256SUMS-linux-x86_64
sha256sum -c SHA256SUMS-linux-x86_64 --ignore-missing
tar -xzf abcpwn-linux-x86_64.tar.gz
cd abcpwn-linux-x86_64
sudo install -m 755 abcpwn /usr/local/bin/abcpwn
```

The tarball also ships the man page and shell completions. For the full
install layout and building from source, see [BUILDING.md](BUILDING.md).
Each release is keyless-signed with cosign and carries a CycloneDX SBOM
and an SLSA build-provenance attestation; verify them before installing
(see [Security](#security)).

## Quick start

Each command runs offline against a local file. Replace `./target` with
the binary under analysis.

```bash
abcpwn info ./target                       # mitigations report (PIE/RELRO/NX/canary)
abcpwn syms ./target --filter main         # symbols with addresses
abcpwn cyclic 200                          # de Bruijn pattern
abcpwn cyclic --find laaa                  # offset of a faulting value
abcpwn pack 0xdeadbeef                     # little-endian packing
abcpwn gadget ./target --depth 4           # ROP gadget search
abcpwn fmt --write 0x404018=0xdeadbeef --arg-position 6   # format-string payload
abcpwn --format json info ./target | jq .findings         # machine-readable output
```

## Commands

abcpwn exposes its subcommands in capability groups. Pretty output is the
default; `--format json` emits a structured envelope for scripting.

| Group           | Commands                                                            |
|-----------------|---------------------------------------------------------------------|
| Reconnaissance  | `info`, `syms`, `strings`, `search`, `hash`                         |
| Encoding        | `pack`, `unpack`, `hex`, `unhex`, `b64`, `xor`, `errno`, `signal`, `constgrep` |
| Disassembly     | `disasm`, `phd`                                                     |
| Patterns        | `cyclic`                                                            |
| ROP             | `gadget`, `rop`, `one-gadget`                                       |
| Specialized     | `srop`, `ret2dl`, `dynelf`, `aslr-bypass`                           |
| Shellcode       | `shellcode`                                                         |
| Format string   | `fmt`                                                               |
| GOT / PLT       | `got`                                                               |
| Heap            | `heap`, `safe-link`                                                 |
| File / C++      | `iofile`, `vtable`                                                  |
| Sandbox         | `seccomp`                                                           |
| Workflow        | `pwninit`, `template`, `diff`, `patch`                              |

Assembly: `asm` requires the Keystone build variant; the Apache-2.0 binary
returns `FeatureDisabled` (exit 4). Disassembly (`disasm`) is always
available.

The full reference is in [docs/COMMANDS.md](docs/COMMANDS.md).

## Usage examples

### Reconnaissance

```bash
abcpwn info ./target               # format, arch, and mitigations
abcpwn syms ./target --filter main # .dynsym + .symtab symbols with addresses
abcpwn search ./target '/bin/sh'   # locate bytes; reports file offset, vaddr, section
```

### Encoding

```bash
abcpwn pack 0xcafebabe --width 4 --be   # pack an integer to raw bytes
abcpwn errno 13                          # EACCES -> name and description
abcpwn xor deadbeef --key 41             # XOR a hex buffer with a key
```

### Disassembly

```bash
abcpwn disasm 4831ff48c7c03c0000000f05 --arch x86_64   # decode hex bytes
abcpwn phd ./target --length 64                        # hex dump with offsets
```

### Patterns

```bash
abcpwn cyclic 200            # generate a de Bruijn pattern
abcpwn cyclic --find laaa    # report the offset of a 4-byte subsequence
```

### ROP

```bash
abcpwn gadget ./target --depth 4 --max-results 200      # search gadgets
abcpwn rop ./target --syscall 59 \
    --syscall-arg 0x404020 --syscall-arg 0 --syscall-arg 0   # execve syscall chain
abcpwn one-gadget ./libc.so.6                           # locate /bin/sh offsets
```

### Specialized

```bash
abcpwn srop --arch x86_64 --rip 0x4011aa --rsp 0x404300   # build an SROP frame
abcpwn aslr-bypass --brute-force --entropy-bits 28        # brute-force estimate
```

### Shellcode

```bash
abcpwn shellcode --preset sh --arch x86_64                # /bin/sh shellcode
abcpwn shellcode --preset sh --arch x86_64 --bad-chars 000a   # avoid bad bytes
```

### Format string

```bash
abcpwn fmt --find-offset 'AAAA%x.%x.%x.%x'                  # find the arg index
abcpwn fmt --write 0x404020=0x4011aa --arg-position 6      # build a %hn payload
```

### GOT / PLT

```bash
abcpwn got ./target --symbol puts          # GOT slot and PLT stub address
```

### Heap

```bash
abcpwn heap tcache-poison --libc-version 2.34   # describe the primitive
abcpwn safe-link 0x404300 0x55aabbcc            # safe-linking encode
```

### File / C++

```bash
abcpwn iofile fsop-exec --libc-version 2.34   # FSOP layout
abcpwn vtable ./target --list                 # list C++ vtables
```

### Sandbox

```bash
abcpwn seccomp dump ./target   # locate and disassemble an embedded BPF filter
```

### Workflow

```bash
abcpwn template ret2libc ./target -o solve.py   # emit a solve skeleton
abcpwn diff ./before ./after                    # byte diff with section context
abcpwn pwninit ./target                         # stage a challenge workspace
```

## Process-driver integration

abcpwn produces deterministic, offline artifacts -- patterns, offsets,
gadgets, packed values, format-string payloads. Connecting to and driving
a target is the job of a process driver such as pwntools; abcpwn output
feeds directly into one:

```python
import subprocess
from pwn import process, p64

offset = int(subprocess.check_output(["abcpwn", "cyclic", "--find", "laaa"]))
io = process("./target")
io.sendline(b"A" * offset + p64(0x401234))
io.interactive()
```

## Supported platforms

| OS    | Arch   | Status                        |
|-------|--------|-------------------------------|
| Linux | x86_64 | tier 1 (pre-built binary)     |
| WSL2  | x86_64 | tier 1 (use the Linux binary) |

Linux aarch64 and macOS (arm64/x86_64) build from source; see
[BUILDING.md](BUILDING.md). Native Windows is not supported (use WSL2),
though inspecting Windows PE binaries from Linux works.

## Authorized use

abcpwn is intended for authorized security work: binary-exploitation
research, capture-the-flag competitions, teaching, and penetration testing
you have explicit permission to perform. It analyzes binaries and builds
exploit primitives offline; it does not attack remote systems and does not
execute the target it inspects.

You are responsible for how you use it. Applying these techniques to
systems you do not own or are not authorized to test may be unlawful.
Tools for unauthorized access are regulated by statutes such as Germany's
StGB section 202c, the United Kingdom's Computer Misuse Act 1990, and the
United States' Computer Fraud and Abuse Act. Review the law in your
jurisdiction before use.

abcpwn is provided "as is", without warranty of any kind, under the Apache
License 2.0 (see [LICENSE](LICENSE)). The authors accept no liability for
any damage or legal consequence arising from its use.

## Security

Each release ships a `SHA256SUMS-linux-x86_64` checksum file, a cosign
keyless signature (`.sig` and `.pem`), a CycloneDX SBOM, and an SLSA
build-provenance attestation. Verify the archive before installing:

```bash
cosign verify-blob \
  --certificate abcpwn-linux-x86_64.tar.gz.pem \
  --signature   abcpwn-linux-x86_64.tar.gz.sig \
  --certificate-identity-regexp '^https://github.com/manop55555/abcpwn/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  abcpwn-linux-x86_64.tar.gz

gh attestation verify abcpwn-linux-x86_64.tar.gz --repo manop55555/abcpwn
```

Assurance properties:

| Property             | Status                                                   |
|----------------------|----------------------------------------------------------|
| Release signing      | cosign keyless (Fulcio + Rekor)                          |
| Software bill        | CycloneDX SBOM per release                               |
| Build provenance     | SLSA attestation per release                             |
| Binary hardening     | PIE, full RELRO, NX, stack canary, FORTIFY               |
| Memory / UB / races  | ASan, UBSan, TSan run on every change                    |
| Static analysis      | CodeQL on every change                                   |
| Parser fuzzing       | libFuzzer harnesses on the parser-facing surfaces        |

The hardening-verification commands are in [SECURITY.md](SECURITY.md).
abcpwn parses attacker-controlled binaries, so a parser bug is a security
issue: report it privately via
[GitHub Security Advisories](https://github.com/manop55555/abcpwn/security/advisories/new),
not a public issue. The threat model is in
[docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).

## Documentation

- [docs/COMMANDS.md](docs/COMMANDS.md) - every subcommand in detail
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - internal design
- [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) - threat model, mitigations, fuzzing
- [docs/TUTORIALS.md](docs/TUTORIALS.md) - end-to-end walkthroughs
- [docs/FAQ.md](docs/FAQ.md) - common questions
- [docs/ERROR_CODES.md](docs/ERROR_CODES.md) - exit codes and remediation
- [docs/PERFORMANCE.md](docs/PERFORMANCE.md) - performance methodology and numbers
- [docs/SUPPORT.md](docs/SUPPORT.md) - supported versions
- [docs/CI.md](docs/CI.md) - continuous integration: triggers and gates
- [BUILDING.md](BUILDING.md) - build from source, troubleshooting, profiling
- [CHANGELOG.md](CHANGELOG.md) - release history

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, the
pre-commit checks, and pull-request expectations. Use
[Discussions](https://github.com/manop55555/abcpwn/discussions) for
questions and [Issues](https://github.com/manop55555/abcpwn/issues) for
bug reports.

## License

Apache-2.0. The opt-in `release-with-keystone` build that statically links
the Keystone assembler engine is a combined work under GPL-2; it is not
distributed as a release artifact and must be built from source. See
[LICENSE](LICENSE) and [LICENSE-THIRD-PARTY.md](LICENSE-THIRD-PARTY.md).

## Maintainer

[manop55555](https://github.com/manop55555).
