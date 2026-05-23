# FAQ

## Why C++ instead of Rust or Go?

LIEF and Capstone both have first-class C++ bindings. Rust would need
either maintained Rust bindings (extra surface to keep working) or
duplicated parsers (lots of work plus drift risk). Go is faster to
start than Python but slower than native C++ and has weaker control
over allocation behavior in hot paths.

C++20 lets the binary be statically linked, ship as a single file, and
start in single-digit milliseconds.

## Why not call the Python tools as subprocesses?

That defeats the purpose. The whole reason `abcpwn` exists is to not
have a Python interpreter at runtime. Subprocessing pwntools would
trade one set of dependencies for another and re-introduce the cold
start cost the project is built to avoid.

## Will you add kernel exploitation features?

No. Kernel exploitation (KASLR bypass, kernel ROP, syscall hijacking)
is a different problem domain with different tooling needs. See
[ROADMAP.md](ROADMAP.md).

## Will you add browser exploitation features?

No. V8, SpiderMonkey, and JavaScriptCore exploitation need entirely
different tooling and would balloon the binary size and attack
surface.

## Why is `asm` unavailable in the default build?

Keystone (the assembler engine) is licensed GPL-2 only, not "or
later". A binary that links Keystone is a combined work under GPL-2.
To keep the default `abcpwn` binary permissively licensed
(Apache-2.0), Keystone is opt-in.

Two ways to get assembly support:

- Use the `abcpwn-full` release archive (GPL-2 combined work).
- Rebuild from source with `-DABCPWN_WITH_KEYSTONE=ON`.

See [../LICENSE-THIRD-PARTY.md](../LICENSE-THIRD-PARTY.md).

## Does `abcpwn` replace pwntools entirely?

For the most common command-line steps of a binary-exploitation
workflow, yes: recon, encoding, gadget discovery, ROP chain
synthesis, shellcode generation, format string offset finding,
seccomp BPF analysis, libc fingerprinting.

For complex exploits with custom logic, pwntools as a Python library
still does things `abcpwn` cannot (custom I/O state machines,
arbitrary Python wrappers around tubes). The two complement each
other: use `abcpwn gadget` to find gadgets quickly, then
`abcpwn rop --format pwntools` to emit a pwntools-compatible chain
that slots into a Python solve script.

## How do I report a bug?

Open an issue at https://github.com/manop55555/abcpwn/issues.

For security bugs, use GitHub Security Advisories instead:
https://github.com/manop55555/abcpwn/security/advisories/new

## Is there a chat channel?

GitHub Discussions is the official forum:
https://github.com/manop55555/abcpwn/discussions

There is no Discord, IRC, or Slack.

## Does `abcpwn` work on Windows?

Not in v0.1. Windows is on the roadmap. Inspection of Windows PE
binaries from Linux or macOS is supported (LIEF handles PE).

## Can I use `abcpwn` in commercial software?

The default Apache-2.0 build (`abcpwn`) is fine for commercial use
under Apache-2.0 terms.

The `abcpwn-full` build (with Keystone) is GPL-2. If you redistribute
it, you must comply with GPL-2 (source on request or accompanying,
preserve copyright, include the GPL-2 license text).

## I get "killed: 9" on macOS

macOS Gatekeeper quarantine on downloaded binaries.

```bash
xattr -d com.apple.quarantine ./abcpwn
```

The one-liner installer handles this automatically.

## Why no emoji in output?

It is a deliberate design choice. Security tooling should be reliable
in any terminal, locale, and encoding. The ASCII markers (`[+]`,
`[-]`, `[!]`, `[*]`, `[?]`) work everywhere; emoji do not. The CI
pipeline enforces the absence of emoji project-wide via
`scripts/check-no-emoji.sh`.

## Does `abcpwn` send any telemetry?

No. `abcpwn` makes no network calls except `libc --download` and
`pwninit`, and both are gated behind the explicit `--allow-network`
flag. There is no opt-out or opt-in for telemetry because there is no
telemetry. Enforced by `scripts/check-no-telemetry.sh` in CI.

## Where does the cache go?

`~/.cache/abcpwn/` on Linux and macOS. Override with
`XDG_CACHE_HOME` or `--cache-dir`. The cache holds:

- Downloaded libc archives (if `--allow-network` was used).
- Capstone disassembly handles (in-memory only; not persisted).
- Pre-computed ROP gadget indexes per binary (keyed by SHA-256).

`abcpwn` never writes outside its cache directory and your current
working directory.

## How big is the binary?

Roughly 8 to 12 MB for the default Apache build, statically linked,
release optimized. The `-full` build with Keystone adds another
4 to 6 MB.

## Can I script `abcpwn`?

Yes. Use `--format json` for machine-readable output:

```bash
abcpwn --format json info /bin/ls | jq .findings
abcpwn --format json gadget ./libc.so.6 | jq '.gadgets[] | select(.bytes < 8)'
```

The JSON schema is versioned (`schema_version` field); additive
changes are non-breaking and field removals require a major version
bump.

## How do I run only one test?

```bash
ctest --preset debug -R "test_info"
ctest --preset asan -R "fmt_parser"
```

See [../BUILDING.md](../BUILDING.md) for the full test invocation
matrix.
