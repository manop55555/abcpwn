# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- Tier 1 platform support: Linux x86_64, Linux aarch64, macOS arm64.
- Tier 2 platform support: macOS x86_64.
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
- `--version` output per `STEP/18`: banner header + version
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
