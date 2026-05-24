# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `seccomp dump <binary>` is implemented (verification #7). It
  statically locates a `sock_filter[]` BPF program embedded in a data
  section -- anchored on the conventional arch/nr load and validated by
  control-flow reachability -- and disassembles it with syscall-name
  annotations. abcpwn never executes the target, so runtime-built
  (libseccomp) filters report a clear message pointing at strace /
  seccomp-tools instead.

### Fixed

- man page EXAMPLES no longer references the removed `rop --execve`
  flag; the ROP example uses `--syscall` (matches the README Quick
  Start).
- README platforms badge dropped `macos`; macOS is build-from-source,
  not a tier-1 pre-built platform.
- zsh completion description for `syms` shortened to "list dynamic
  imports" to match `--help` (the `--type` variant was removed).
- `gadget` no longer silently truncates: the default `--max-results`
  cap was raised from 200000 to 1000000 (fits a typical libc), and
  hitting the cap now warns on stderr so the truncation is visible
  when stdout is redirected to a file.
- `disasm` no longer silently caps output: the default instruction cap
  was raised to 1000000, and both the 1 MiB input-file cap and the
  instruction cap now print a warning on stderr when they truncate.
- `gadget` no longer reports `NotFound` (exit 7) for a binary that
  parses but has no executable sections; that case is now `Unsupported`
  (exit 10), reserving `NotFound` for a genuinely missing path
  (verification #41).
- `--log-file PATH` works again: it was documented in the man page and
  completions but the CLI flag had been removed, so the binary rejected
  it (exit 2). It now writes a JSON record of the run (command,
  command_line, exit_code, ok, duration_ms, and error on failure) to
  PATH for both successful and failed runs (verification #20).
- `rop --syscall` now combines multi-pop gadgets: a single
  `pop rdi ; pop rsi ; pop rdx ; ret` can populate several argument
  registers at once (greedy set cover over the needed registers),
  instead of requiring a dedicated `pop <reg> ; ret` per register. It
  also covers all six syscall argument registers (rdi, rsi, rdx, r10,
  r8, r9) and finds a bare `syscall` gadget, not only `syscall ; ret`
  (verification #31).
- the version string is consistent across surfaces: the compact CLI
  header, `--version`, and the JSON `abcpwn_version` field all report
  the build-time SemVer (previously the header and JSON showed the
  short `0.1.0` while `--version` showed `0.1.0-alpha.4`). The
  decorative ASCII banner keeps its static brand mark (verification N3).
- error messages carry a single `[-] <cmd>: ` prefix; a command that
  self-prefixed its own message no longer produces a doubled command
  name such as `[-] pack: pack: ...` (DEF-1).
- `rop --syscall` reports `Unsupported` (exit 10), not `NotFound` (7),
  when the target lacks the gadgets to build the requested chain;
  `NotFound` is reserved for a genuinely missing path (DEF-1 / DEF-19,
  consistent with the gadget no-executable-sections fix).
- under `--format json`, a failing command emits a JSON error envelope
  on stdout (`{abcpwn_version, schema_version, command, args,
  error:{code, name, message}}`) instead of plaintext on stderr, so
  pipelines can parse failures. Covers both command errors and CLI
  parse errors, with the exit code preserved (DEF-4).
- global `--format` and `--color` reject unknown values with
  `InvalidInput` (exit 8) instead of silently falling back to
  pretty/auto; `--format` stays case-sensitive (DEF-6).
- `gadget --type` and `template <strategy>` reject unknown values with
  `UsageError` (exit 2) -- matching shellcode/heap/iofile -- instead of
  silently using `ret` / echoing the bogus strategy (DEF-8).
- `cyclic` no longer exhausts memory on a large `--subseq-length`
  (DEF-7). Generation is lazy -- only the requested length is produced,
  so `cyclic 10 -n 7` returns instantly instead of allocating ~8 GB and
  being OOM-killed. The `--find` search space is bounded: an oversized
  `alphabet^subseq-length` returns `SizeExceeded` (exit 9) with guidance
  instead of OOM (fixing an off-by-one in the prior cap).
- `phd` and `disasm --input-file` honor `ABCPWN_MAX_FILE_SIZE`, refusing
  oversized files with `SizeExceeded` (exit 9) like the other
  file-reading commands; they previously read any size (DEF-13).
- `info` returns `Corrupted` (exit 11) for a file whose architecture
  cannot be determined (e.g. random bytes after the ELF magic) instead
  of a confident, alarming NX/PIE/Canary report at exit 0; pass `--arch`
  to force analysis of an unrecognized binary (DEF-15).

### Added

- file-path subcommands accept `-` to read the target from standard
  input (`cat ./vuln | abcpwn info -`, `... | abcpwn gadget -`,
  `... | abcpwn hash -`). The read is binary-safe and honors
  `ABCPWN_MAX_FILE_SIZE`; empty stdin is handled gracefully. Implemented
  once in `safe_io::read_file`, so every command that loads a file
  (info, syms, strings, search, gadget, hash, disasm `--input-file`,
  phd, ...) gains it (DEF-16).
- a "Defensive use and legal notice" to the README (with a short
  equivalent in SECURITY.md): authorized-use-only scope, user
  responsibility, references to applicable law (Germany StGB §202c, UK
  Computer Misuse Act 1990, US CFAA), and the Apache-2.0 "as is"
  disclaimer in plain language (IMP-3).

### Changed

- `pwn` no longer fakes success: `host:port` and `unix:` targets
  previously returned a "plan" at exit 0 without opening any socket, and
  a local-binary target returned an `Unsupported` error that leaked
  internal source-policy text. All modes now return `NotImplemented`
  (exit 16) with a clear message; the target argument is still
  validated. The live process/socket tube driver lands in a later
  release (DEF-9).
- the subcommand count in the README and man page now reads 39 (the
  actual registered count); both previously said 38, and the man page
  omitted `signal` from the encoding group. `test_docs.sh` asserts the
  count prose stays in sync with the registered commands (DEF-2).
- `-q`/`--quiet` suppresses the banner and the timing footer (the
  info-level chrome), and `-v`/`-vv` raise the logger level and emit a
  debug dispatch line, so verbosity has an observable effect; both were
  previously accepted but inert (DEF-18).
- user-facing errors no longer leak the internal object name `Context`
  (`libc download`, `pwninit`) (DEF-21).
- an invalid `ABCPWN_MAX_FILE_SIZE` (non-numeric, zero, negative, or
  fractional) warns on stderr and keeps the default cap instead of being
  silently ignored; a leading `-` no longer wraps to a huge value that
  disabled the cap entirely (DEF-20).
- `rop` (no executable sections) and `libc offsets` (no in-binary DB
  entry) return `Unsupported` (exit 10) rather than `NotFound` (exit 7),
  reserving `NotFound` for a genuinely missing path (DEF-19).
- the man page documents option-value syntax: short options take `-d 8`
  or `-d8` (not `-d=8`), long options take `--depth 8` or `--depth=8`,
  and global options must precede the subcommand (DEF-11).
- the `disasm` time budget is configurable via `ABCPWN_DISASM_TIMEOUT_MS`
  (milliseconds), so the `Timeout` exit code (15) is reachable and
  testable; the default stays 30s (DEF-17).
- public-facing source comments and docs no longer cite internal design
  documents; `check-no-spec-leak.sh` now also rejects any tracked file
  that references the local-only spec set, preventing regressions
  (IMP-2).
- `docs/TUTORIALS.md` rewritten to be copy-pasteable: every shell block
  runs against system binaries (`/bin/ls`) or pure operations and uses
  only shipped flags. It previously referenced fixtures that never
  shipped, removed flags (`syms --type`, `cyclic --search`,
  `fmt --offset`), and unimplemented features (`shellcode --preset
  read-flag`, `seccomp emu`). `test_tutorial_walkthrough.sh` runs every
  bash block and asserts exit 0 (IMP-5).
- SECURITY.md documents the release verification that is actually live --
  cosign keyless signature, SLSA build-provenance attestation, and the
  CycloneDX SBOM -- with copy-pasteable `cosign verify-blob` and
  `gh attestation verify` commands, replacing the stale "signing is
  planned" note; the README points to it (IMP-7).
- ROADMAP gains a v0.1.1 entry to harden the binary loader against the
  upstream LIEF note-size OOM (the recurring `fuzz_binary_loader`
  crash); the auto-filed fuzz-crash issues are triaged to it (IMP-1).
- GitHub Discussions enabled for the repository, so the "open a
  discussion" links in the README, FAQ, SUPPORT, and CONTRIBUTING docs
  now resolve (IMP-6).
- shellcheck is pinned to v0.11.0 (the official static binary, checksum
  verified in CI) and wired into `scripts/check-all.sh` through
  `scripts/check-shellcheck.sh`, with a repo-root `.shellcheckrc` fixing
  the active check set. Local and CI previously ran different distro apt
  versions that disagreed on a style check, letting a finding pass local
  lint while failing CI (CI integrity).
- the CI `build` job no longer depends on `lint` (`needs:` removed): a
  lint failure used to skip the whole build+test matrix and hide whether
  the test suite passed. Lint and build now run independently and both
  must be green for CI to pass (CI integrity).
- the `sanitizers` and `coverage` workflows now also run on push to
  `main` (previously pull-request and manual-dispatch only), so a direct
  push to `main` is gated by ASan/UBSan/TSan and coverage, not just `ci`
  and `codeql`. New `docs/CI.md` documents every workflow's trigger
  matrix and what it gates (CI integrity).
- the nightly `fuzz` workflow no longer auto-opens a GitHub issue on a
  crash; in v0.1.x it uploads the crash artifact only. Every crash so
  far is the same known upstream LIEF note-size OOM (tracked for
  v0.1.1), and auto-filing refilled the issue tracker on every run.
  Auto-filing and gating return in v0.2 once that backlog clears
  (IMP-1 follow-up).

## [0.1.0-alpha.3] - 2026-05-24

Bulk QA pass: 41 findings from three independent rounds of
manual + scripted review resolved before the next tag. Most user-
facing changes are bug fixes and surface trims; the only new
features are conveniences (a `signal` subcommand symmetric with
`errno`, a `-f` short alias, an integer form for `cyclic --find`).
Release-pipeline output now includes a CycloneDX SBOM, cosign
keyless signatures over the archive and SBOM, the public docs/
reference tree, and CHANGELOG / BUILDING / SECURITY alongside
README inside the tarball.

### Added

- `signal` subcommand mirrors the `errno` lookup surface:
  `abcpwn signal 11`, `abcpwn signal SIGSEGV`, or `abcpwn signal
  SEGV` (the SIG prefix is added when absent). `abcpwn signal`
  with no argument lists all 25 named entries.
- `-f` short alias for the global `--format` flag.
- `cyclic --find` now accepts pwntools-style integer needles in
  hex (`0x61616168`) or decimal (`1633771880`), converted to
  little-endian bytes of the configured subsequence width. The
  ASCII subsequence form (`haaa`) still works unchanged.
- `gadget --max-results N` flag (default 200000) that lets users
  raise the unique-result cap; when the cap is hit, the command
  surfaces a Medium-severity `gadget set truncated` finding and
  names the cap in the summary so the listing is no longer
  silently partial.
- `ABCPWN_MAX_FILE_SIZE=<bytes>` environment override now applies
  to every binary-loading subcommand (`info`, `syms`, `gadget`,
  `rop`, `vtable`, `got`, `one-gadget`, `ret2dl`), not only the
  raw-bytes commands (`search`, `hash`, `strings`, `diff`,
  `patch`) that already honored it.
- `--allow-network` on a build produced without `ABCPWN_WITH_NETWORK`
  now emits a parse-time `[!]` warning on stderr explaining the
  flag has no effect; the command still runs (non-network
  subcommands are unaffected).
- JSON output now echoes the full invocation under
  `args.command_line`, restoring the round-trip story for jq /
  log-aggregator pipelines.
- `disasm` defaults to a 1 MiB input cap and a 200000 instruction
  cap for `--input-file`, with a 30-second internal time budget
  that surfaces `ErrorCode::Timeout` (exit 15) if `cs_disasm`
  somehow exceeded it. Users who need full-buffer decode can
  override with `--count <N>`.
- Truncated ELF inputs (file shorter than the documented
  e_ident-class header size) are rejected upfront with
  `ErrorCode::Corrupted` (exit 11) and a descriptive message,
  rather than continuing through LIEF's lenient parser to
  produce empty findings.
- `abcpwn --version` now reports the full SemVer string
  (`0.1.0-alpha.3`) sourced from `git describe --tags --abbrev=0`
  at build time, with a `PROJECT_VERSION` fallback for tarball
  builds that have no `.git`.
- `--no-color` global flag accepted as an alias for
  `--color=never` (the previous form remains).
- Release tarballs now ship `CHANGELOG.md`, `BUILDING.md`,
  `SECURITY.md`, and a copy of the public `docs/` tree alongside
  the existing `LICENSE`, `LICENSE-THIRD-PARTY.md`, `README.md`,
  man page, and completions.
- Release pipeline produces a CycloneDX 1.5 SBOM (anchore/sbom-action)
  and signs both the archive and the SBOM with cosign keyless
  (Fulcio + Rekor via GitHub OIDC); SLSA build-provenance
  attestation continues to land alongside.

### Changed

- Banner and timing footer always go to stderr; stdout carries
  only command data. The previous behavior leaked banner bytes
  into pipelines like `abcpwn unhex deadbeef | xxd`.
- `--no-banner` now suppresses the banner on `--version` and
  every other path; the bare-invocation help block still reaches
  stdout while the banner reaches stderr.
- JSON output base64-encodes raw bytes (`bytes_b64`, `bytes_hex`,
  `bytes_len`) instead of stuffing them into a UTF-8 string and
  triggering `nlohmann::json::type_error::316`.
- Banner text no longer claims "statically linked"; the binary
  dynamically links libc/libm and statically bundles third-party
  C++ libraries. Wording corrected across the ASCII banner,
  README intro, and man page DESCRIPTION.
- CLI11 parse errors (104 RequiredError, 106 ExtrasError, 109
  RequiresError, ...) are funneled through exit 2 (UsageError) at
  the top-level catch so the documented exit-code table is the
  single source of truth.
- shellcode encoding selector renamed from `--format` to
  `--output-format` to stop colliding with the global
  `--format pretty|json` value space; both flags can now be
  combined.
- `rop --syscall` falls back to multi-pop `pop <target> ; pop
  <safe> ; ret` gadgets when an exact `pop <target> ; ret` is
  absent (the common libc case), with `(padding slot N)` entries
  appended to the chain so the operator sees where to splice
  junk bytes.
- `pack` returns `ErrorCode::InvalidInput` when the value exceeds
  the requested width instead of silently truncating to the
  low-order bytes.
- `syms --dangerous` strips the `__isocNN_` ABI-versioning prefix
  before matching, so glibc 2.7+ wrappers (`__isoc99_scanf`,
  `__isoc23_scanf`) are now flagged.
- `disasm --arch ppc` / `--arch ppc64` default to big-endian (the
  dominant ABI convention); users on LE ports can opt out with
  `--be=false`.
- `cyclic` rejects requested lengths past the alphabet^subseq
  unique-window limit with `ErrorCode::SizeExceeded`.
- x86_64 `sh` shellcode preset now NUL-terminates `/bin//sh` (24
  bytes; was 23 and crashed in execve).
- `fmt --write` lays out directives first, padded to ptr-width,
  with target addresses at the end -- matches pwntools
  `fmtstr_payload` and avoids NUL bytes in the leading directive
  region.
- LIEF's own logger is silenced on first call into the loader; we
  surface our own `ErrorCode::Corrupted` diagnostics instead of
  leaking LIEF `[WARNING]` / `[ERROR]` lines to stderr.
- Man-page pandoc invocation now passes `--from=markdown-smart` so
  double-hyphen flags survive as literal `--` instead of the
  smartypants en-dash (`\(en`) collapse; `--format json` etc. can
  be copy-pasted out of `man abcpwn` without silent mis-parse.
- one-gadget output language matches what the command actually
  does (locates `/bin/sh` string offsets); the trailing note now
  recommends running the upstream Ruby `one_gadget` tool for
  full constraint extraction.
- LICENSE-THIRD-PARTY clarifies which libraries are present in
  the default release versus opt-in builds; the Keystone (GPL-2)
  and Unicorn (GPL-2) entries are now explicitly gated behind
  `ABCPWN_WITH_KEYSTONE` / `ABCPWN_WITH_UNICORN` so no reader
  mistakenly concludes the released artifact carries GPL-2
  obligations.
- README, COMMANDS, and the man page no longer mention an
  `abcpwn-full` release artifact; the GPL combined-work build
  is source-only via the `release-with-keystone` CMake preset
  in v0.1.
- `gadget` on a structurally-broken ELF now exits 11
  (`Corrupted`) instead of 7 (`NotFound`).

### Fixed

- Banner + timing on stdout broke every pipeline that consumed
  abcpwn output; both now reliably hit stderr.
- `--format json` triggered an uncaught `nlohmann::json::type_error::316`
  on any subcommand that emitted non-UTF-8 bytes; bytes are now
  base64-encoded.
- `cyclic <huge>` past the alphabet^subseq limit produced
  non-de-Bruijn output where `cyclic --find` would return wrong
  offsets; the command now refuses with `SizeExceeded`.
- `shellcode --preset sh --arch x86_64` produced a payload that
  could not actually spawn a shell because `/bin//sh` was not
  NUL-terminated; the 24-byte fix is now exercised by an
  integration test that mmaps RWX and forks the shellcode.
- `fmt --write` payload never performed the write because
  null-containing addresses were placed before the format
  directives; the layout now matches pwntools.
- `gadget --type all` silently truncated at 200000 results with
  no signal; the new `--max-results` flag and warning surface
  the cap and make it adjustable.
- README Quick Start examples now parse and run end-to-end (four
  of the seven were broken in alpha.2).
- Man-page `cyclic --search` example fixed to `--find` (the flag
  name has always been `--find`).
- `signal handlers install idempotently` and other infrastructure
  tests now pass in CI against the rebuilt-on-each-push artifact.

### Removed

- Unimplemented stub flags trimmed from the CLI surface:
  `rop --ret2win`, `rop --leak`, `rop --srop`, `rop --format`,
  `pwn --interactive`, `shellcode --reverse-addr`,
  `shellcode --bind-port`, `shellcode --preset` choices that
  weren't in the database (`bind`, `reverse`, `read-flag`,
  `cat-flag`), global `--log-file`, `dynelf --libc-db`.
- `seccomp` action choices `asm` and `emu` removed from `--help`
  and the dispatch table; `disasm` remains the supported path
  and `dump` returns Unsupported with a manual-extraction recipe.
- Gadget-cache prose removed from the man page FILES section and
  the `~/.cache/abcpwn/` `XDG_CACHE_HOME` entry; no on-disk cache
  was ever implemented and the language was misleading.

### Security

- LIEF logger globally silenced; corruption diagnostics are
  surfaced as `ErrorCode::Corrupted` findings instead of leaking
  to stderr.
- Truncated ELFs rejected upfront with a header-size sanity
  check before LIEF's lenient parser sees them.
- Release pipeline now produces CycloneDX SBOM + cosign keyless
  signature (Fulcio CA, Rekor transparency log) alongside the
  existing SLSA build-provenance attestation and SHA-256
  checksums.

## [0.1.0-alpha] - 2026-05-23

### Added

- Initial public CLI surface with 38 subcommands across 13 groups:
  - recon: `info`, `syms`, `strings`, `search`, `hash`
  - encoding: `pack`, `unpack`, `hex`, `unhex`, `b64`, `xor`, `errno`, `constgrep`
  - asm: `asm`, `disasm`, `phd`
  - pattern: `cyclic`
  - rop: `gadget`, `rop`, `one-gadget`
  - specialized: `srop`, `ret2dl`, `dynelf`, `aslr-bypass`
  - shellcode: `shellcode`
  - format string: `fmt`
  - got/plt: `got`
  - heap: `heap`, `safe-link`
  - file/c++: `iofile`, `vtable`
  - sandbox: `seccomp`, `libc`
  - workflow: `pwninit`, `pwn`, `template`, `diff`, `patch`
- Pre-built release binary for Linux x86_64 (also runs on WSL2).
  Other platforms (Linux aarch64, macOS arm64/x86_64) build from
  source; pre-built binaries for them are planned for v0.2.
- Apache-2.0 default release build; opt-in GPL-2 Keystone-enabled
  build via the `release-with-keystone` CMake preset (source-only,
  no v0.1 release artifact).
- Optional features behind CMake flags: `ABCPWN_WITH_KEYSTONE`,
  `ABCPWN_WITH_NETWORK`, `ABCPWN_WITH_UNICORN`.
- Pretty and JSON output formats (`--format pretty|json`).
- ASCII markers (`[+]`, `[-]`, `[!]`, `[*]`, `[?]`) and ANSI color
  support per the `NO_COLOR` convention.
- Banner with version block and the 38-command description.
- Global flags: `--allow-network`, `--no-color`, `--no-banner`,
  `--format`, `--config`, `--log-file`, `--about-network`,
  `--version`, `--help`.
- `--version` output: banner header + version
  string + git commit + build date + arch + compiler + feature
  flags + vcpkg baseline + LIEF and Capstone versions.
- `--about-network` prints the no-network policy in a form CTF
  organizers and security auditors can grep, including the
  `ABCPWN_NO_NETWORK=1` env override.
- `ABCPWN_NO_NETWORK=1` environment variable forces network
  access off even when `--allow-network` is passed
  (defense-in-depth for locked-down infrastructure).
- Static analysis suite in CI: clang-tidy, cppcheck, clang-format,
  shellcheck, plus the in-tree orchestrator (`scripts/check-all.sh`)
  that enforces SPDX headers, telemetry-free policy, URL allowlist,
  no `system`/`popen`/`exec*` in `src/`, and ASCII-only output.
- libFuzzer harnesses for `binary_loader`, `seccomp_decoder`,
  `fmt_parser`, `gadget_filter`; nightly fuzz workflow runs one
  hour per harness.
- Sanitizer presets (AddressSanitizer, UndefinedBehaviorSanitizer,
  ThreadSanitizer) wired through dedicated workflow on pull
  requests.
- Catch2 unit and integration tests; 186 tests at v0.1 baseline.
- Performance benchmarks via Catch2 with stored baseline.
- Documentation: README, BUILDING, SECURITY, CONTRIBUTING,
  CODE_OF_CONDUCT, LICENSE, LICENSE-THIRD-PARTY, CHANGELOG, plus
  the `docs/` reference set (ARCHITECTURE, COMMANDS, PERFORMANCE,
  SECURITY-MODEL, ERROR_CODES, FAQ, TUTORIALS, ROADMAP,
  STATIC_ANALYSIS, SUPPORT) and Architecture Decision Records in
  `docs/adr/`.
- Shell completions for bash, zsh, and fish.
- Man page (`abcpwn.1`) generated from `man/abcpwn.1.md` via pandoc.

### Changed

- Not applicable for the initial release.

### Deprecated

- None.

### Removed

- None.

### Fixed

- Not applicable for the initial release.

### Security

- All binary parsing is delegated to LIEF; no hand-written
  parsers in `src/`.
- Every parser path has a libFuzzer harness.
- No `system()`, `popen()`, or `exec*()` calls anywhere in `src/`.
- No network access without explicit `--allow-network` flag.
- No telemetry, no analytics, no auto-update.
- File-size cap (`ABCPWN_MAX_FILE_SIZE`, default 2 GB) and
  parse-depth cap (default 64) enforced on every input.
- Hardening flags applied to the release binary:
  `-fstack-protector-strong`, `-fPIE`, `-pie`, `_FORTIFY_SOURCE=3`
  on Release, `-Wl,-z,relro`, `-Wl,-z,now`, `-Wl,-z,noexecstack`
  on Linux, Intel CET on x86_64, ARM BTI/PAC on aarch64.
