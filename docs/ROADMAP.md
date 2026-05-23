# Roadmap

## v0.1.x (current line)

- 38 subcommands across 13 groups.
- Tier 1 platforms: Linux x86_64, Linux aarch64, macOS arm64.
- Tier 2 platforms: macOS x86_64.
- Apache-2.0 and GPL-2 (`-full`) build variants.
- GitHub Releases distribution, `install.sh` one-liner.
- Pretty and JSON output formats.
- Static analysis (clang-tidy, cppcheck, clang-format, shellcheck) +
  in-tree orchestrator in CI.
- libFuzzer harnesses for the four parser-facing surfaces, nightly
  fuzz schedule.
- AddressSanitizer, UndefinedBehaviorSanitizer, ThreadSanitizer
  presets exercised on every pull request.

## v0.2 (next)

- Sigstore signing of release artifacts (cosign verify-blob workflow).
- Per-file NOLINT review for the clang-tidy categories temporarily
  disabled at the v0.1 baseline.
- Full include-what-you-use enforcement.
- Multi-arch release artifacts: `linux-aarch64`, `macos-arm64`,
  `macos-x86_64` (currently the release pipeline emits
  `linux-x86_64` only).
- TLS support in `pwn` I/O tubes for direct CTF infrastructure
  interaction.
- Additional shellcode presets (broader arch and syscall coverage).
- Improved libc database fetching with mirror selection.
- Homebrew tap publication.
- AUR package for Arch Linux users.

## v0.3

- WebAssembly target for browser-based exploit playground use cases
  (educational only).
- Plugin API for out-of-tree subcommand implementations, gated
  behind a `--enable-plugins` flag with a clear trust boundary.
- Native Nix flake for reproducible developer environments.

## v1.0

- API stability guarantee under semver.
- Long-term support policy with named release line.
- Tutorial site and reference exploit walkthroughs.

## Explicitly NOT on the roadmap

- **Kernel exploitation.** Different problem domain (KASLR bypass,
  kernel ROP, syscall hijacking, eBPF abuse) with distinct tooling
  needs.
- **Browser exploitation.** V8, SpiderMonkey, and JSC require their
  own engines, type-confusion machinery, and JIT-spray helpers.
- **GUI.** The project commits to a CLI-only surface; if visualisation
  is needed, pipe `--format json` into a separate tool.
- **Python bindings.** Would re-introduce the very runtime dependency
  the project exists to avoid.
- **Auto-update.** `abcpwn` never phones home; users install via
  package manager or release artifact and update on their own
  schedule.

## How items move between sections

Items in the next-major section move forward when:

- The feature is feasible to ship without breaking the API stability
  contract (see [../CHANGELOG.md](../CHANGELOG.md) and the semver
  rules in CONTRIBUTING.md).
- The test surface to demonstrate it has landed (unit + integration +
  fuzz where applicable).
- The documentation entry exists (this file moves the bullet from
  "next" into the released version's CHANGELOG when shipped).

Items in "not on the roadmap" are firm: they will be revisited only
if the project mission itself changes, which would warrant a separate
discussion in https://github.com/manop55555/abcpwn/discussions before
any work happens.
