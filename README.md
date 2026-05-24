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

Native C++20 CLI toolkit for binary exploitation. It bundles the
offline, day-to-day primitives a binary-exploitation workflow needs --
ELF/PE/Mach-O inspection, ROP gadget search, format-string payloads,
shellcode, glibc heap and seccomp helpers -- into a single statically
self-contained binary with no telemetry, no auto-update, and no network
calls by default.

It is dynamically linked only against system libc/libm; every
third-party library (LIEF, Capstone, CLI11, nlohmann/json, spdlog,
PicoSHA2) is statically bundled into the binary.

## Install

Pre-built binary for Linux x86_64:
[GitHub Releases](https://github.com/manop55555/abcpwn/releases).

```bash
curl -LO https://github.com/manop55555/abcpwn/releases/latest/download/abcpwn-linux-x86_64.tar.gz
curl -LO https://github.com/manop55555/abcpwn/releases/latest/download/SHA256SUMS-linux-x86_64
sha256sum -c SHA256SUMS-linux-x86_64 --ignore-missing
tar -xzf abcpwn-linux-x86_64.tar.gz
cd abcpwn-linux-x86_64
sudo install -m 755 abcpwn /usr/local/bin/abcpwn
```

The tarball also ships the man page and shell completions; see
[BUILDING.md](BUILDING.md) for the full install layout. Each release is
keyless-signed with cosign and carries a CycloneDX SBOM and an SLSA
build-provenance attestation -- verify them before installing (see
[Verifying releases](#verifying-releases)).

From source (any platform): see [BUILDING.md](BUILDING.md).

## Quick start

Every command below runs offline against a local file and exits 0:

```bash
abcpwn info /bin/ls                       # checksec-style mitigations report
abcpwn cyclic 200                         # de Bruijn pattern (pwntools-compatible)
abcpwn cyclic --find laaa                 # -> offset 44 of that subsequence
abcpwn pack 0xdeadbeef                    # little-endian pack (p64-style)
abcpwn gadget /bin/ls --depth 3 --max-results 5   # ROP gadget search
abcpwn fmt --write 0x404018=0xdeadbeef --arg-position 6   # format-string payload
abcpwn --format json info /bin/ls | jq .findings          # scriptable JSON output
```

Full command reference: [docs/COMMANDS.md](docs/COMMANDS.md).

## What abcpwn is

An **offline primitives toolkit**: it analyzes binaries and builds
exploit building blocks, deterministically and without touching the
network or executing the target. It consolidates the everyday slices of
`pwntools`, `ROPgadget`, `seccomp-tools`, `libc-database`, `checksec`,
`pwninit`, and the string-locating part of `one_gadget` behind one fast
binary. 39 subcommands across 13 groups:

| Group       | Commands                                                       |
|-------------|----------------------------------------------------------------|
| recon       | `info`, `syms`, `strings`, `search`, `hash`                    |
| encoding    | `pack`, `unpack`, `hex`, `unhex`, `b64`, `xor`, `errno`, `signal`, `constgrep` |
| asm         | `asm`&dagger;, `disasm`, `phd`                                 |
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

&dagger; `asm` requires the optional Keystone build (GPL-2); the default
Apache-2.0 binary exits `FeatureDisabled` (exit 4). See
[BUILDING.md](BUILDING.md) and [docs/FAQ.md](docs/FAQ.md).

## What abcpwn is not (yet)

v0.1.0 covers analysis and offline primitives. These are on the
[v0.2 roadmap](docs/ROADMAP.md) and are intentionally absent or minimal
today:

- **Live process / socket I/O.** `pwn` is a placeholder (exits
  `NotImplemented`); abcpwn does not open tubes or drive a remote target.
  Pair it with a process driver (below).
- **Heap exploitation templates.** `heap` describes primitives; turn-key
  tcache/fastbin attack templates are deferred.
- **one-gadget constraint solving.** `one-gadget` locates candidates but
  does not solve register/memory constraints -- use the upstream
  `one_gadget` for that.
- **Automated SROP / ret2dlresolve / BROP chains.** `srop` and `ret2dl`
  are frame/structure helpers, not end-to-end chain builders.
- **Custom shellcode encoders.** Built-in presets only; the encoder is
  deferred.
- **A pwntools-compatible scripting API**, and **pre-built binaries for
  non-Linux-x86_64 platforms**.

## Pair with a process driver

abcpwn is the offline half of an exploit. For the I/O half, pipe its
output into a tube driver such as pwntools:

```python
import subprocess
from pwn import process, p64

# abcpwn (offline): find the overflow offset and pack the target address.
offset = int(subprocess.check_output(["abcpwn", "cyclic", "--find", "laaa"]))

# pwntools (I/O): send the crashing input the offset describes.
io = process("./vuln")
io.sendline(b"A" * offset + p64(0x401234))
io.interactive()
```

abcpwn handles the deterministic, offline work (patterns, offsets, gadget
search, packing, format-string payloads); the driver handles the live
connection.

## Supported platforms

| OS    | Arch    | Status                          |
|-------|---------|---------------------------------|
| Linux | x86_64  | tier 1 (pre-built binary)       |
| WSL2  | x86_64  | tier 1 (use the Linux binary)   |

Linux aarch64 and macOS (arm64/x86_64) build from source today
([BUILDING.md](BUILDING.md)); pre-built binaries for them are a v0.2
item. Native Windows is not supported -- use WSL2 -- but inspecting
Windows PE binaries from Linux works (LIEF handles PE).

## Defensive use and legal notice

abcpwn is a tool for **authorized** security work: binary-exploitation
research, CTF competitions, teaching, and penetration testing you have
explicit permission to perform. It analyzes binaries and builds exploit
primitives offline; it never attacks remote systems on its own and never
executes the target it inspects.

You are responsible for how you use it. Applying these techniques to
systems you do not own or are not authorized to test may be a crime.
"Hacking tools" and unauthorized access are regulated by laws such as
**Germany's StGB §202c**, the **United Kingdom's Computer Misuse Act
1990**, and the **United States' Computer Fraud and Abuse Act**, among
many others. Know the law in your jurisdiction before you act.

abcpwn is provided **"as is", without warranty of any kind**, under the
Apache License 2.0 (see [LICENSE](LICENSE)). The authors accept no
liability for any damage or legal consequence arising from its use.

## Security

### Verifying releases

Each release ships a `SHA256SUMS-linux-x86_64` checksum file, a cosign
keyless signature (`.sig` + `.pem`), a CycloneDX SBOM, and an SLSA
build-provenance attestation. To verify the signature:

```bash
cosign verify-blob \
  --certificate abcpwn-linux-x86_64.tar.gz.pem \
  --signature   abcpwn-linux-x86_64.tar.gz.sig \
  --certificate-identity-regexp '^https://github.com/manop55555/abcpwn/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  abcpwn-linux-x86_64.tar.gz

gh attestation verify abcpwn-linux-x86_64.tar.gz --repo manop55555/abcpwn
```

Full steps, plus the binary-hardening checks (PIE, full RELRO, NX, stack
canary, FORTIFY) you can run yourself, are in [SECURITY.md](SECURITY.md).

### Reporting a vulnerability

abcpwn parses attacker-controlled binaries, so a parser bug is a real
vulnerability. Report privately via
[GitHub Security Advisories](https://github.com/manop55555/abcpwn/security/advisories/new),
not a public issue. See [SECURITY.md](SECURITY.md) for the policy and the
threat model in [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).

## Documentation

- [BUILDING.md](BUILDING.md) - build from source, troubleshooting, profiling
- [docs/COMMANDS.md](docs/COMMANDS.md) - every subcommand in detail
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - internal design
- [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) - threat model, mitigations, fuzzing
- [docs/TUTORIALS.md](docs/TUTORIALS.md) - end-to-end walkthroughs
- [docs/FAQ.md](docs/FAQ.md) - common questions (incl. "why not pwntools?")
- [docs/ROADMAP.md](docs/ROADMAP.md) - what is planned for v0.2 and beyond
- [docs/ERROR_CODES.md](docs/ERROR_CODES.md) - exit codes and remediation
- [docs/PERFORMANCE.md](docs/PERFORMANCE.md) - performance methodology and numbers
- [docs/SUPPORT.md](docs/SUPPORT.md) - supported versions
- [docs/CI.md](docs/CI.md) - continuous integration: triggers and gates
- [CHANGELOG.md](CHANGELOG.md) - release history

## Contributing

Contributions welcome -- see [CONTRIBUTING.md](CONTRIBUTING.md) for the
dev setup, the pre-commit checks, and PR expectations. Use
[Discussions](https://github.com/manop55555/abcpwn/discussions) for
questions and [Issues](https://github.com/manop55555/abcpwn/issues) for
bugs.

## License

Apache-2.0 by default. The opt-in `release-with-keystone` build that
statically links the Keystone assembler engine is a combined work under
GPL-2; it is not distributed as a release artifact in v0.1 and must be
built from source. See [LICENSE](LICENSE) and
[LICENSE-THIRD-PARTY.md](LICENSE-THIRD-PARTY.md).

Sole author and maintainer:
[manop55555](https://github.com/manop55555).
