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

- Re-enable SLSA provenance attestation in release.yml. v0.1
  ships with `actions/attest-build-provenance@v1` marked
  `continue-on-error: true` because the action requires either a
  public repo or a paid GHAS plan; on a user-owned private repo
  it fails to persist the attestation. When the repo path
  unlocks GHAS (visibility flip, transfer to an org with GHAS,
  or paid plan), remove the `continue-on-error` and verify the
  provenance file appears in release artifacts.
- Sigstore signing of release artifacts (cosign verify-blob workflow).
- Per-file NOLINT review for the clang-tidy categories temporarily
  disabled at the v0.1 baseline.
- Full include-what-you-use enforcement.
- Multi-arch release artifacts: `linux-aarch64`, `macos-arm64`,
  `macos-x86_64` (currently the release pipeline emits
  `linux-x86_64` only).
- Multi-platform CI matrix: add `linux-aarch64` gcc-13, macOS x86_64
  (macos-13), macOS arm64 (macos-14, macos-15) jobs to ci.yml.
- TLS support in `pwn` I/O tubes for direct CTF infrastructure
  interaction.
- Additional shellcode presets (broader arch and syscall coverage).
- Improved libc database fetching with mirror selection.
- Homebrew tap publication.
- AUR package for Arch Linux users.
- Parallel gadget search to bring `gadget libc.so.6` back under
  the v0.1-aspirational 1-second target. Forward-decode is
  sequential today; `std::execution::par_unseq` with a bounded
  thread count was raised in ADR 0003's alternatives and deferred
  here. Until shipped the v0.1 targets in
  [PERFORMANCE.md](PERFORMANCE.md) reflect sequential-scan reality
  (4-second soft target, 5-second hard limit on libc.so.6).
- Intel CET feature flag restoration in the release binary's
  `.note.gnu.property`. `cmake/Hardening.cmake` already passes
  `-fcf-protection=full` to the C++ compile, but the linker
  intersects feature-property notes across all input objects, and
  the vcpkg-installed LIEF and Capstone static archives are built
  without CET, dragging the final marking down to baseline. Fix
  by either rebuilding the vendored deps with `-fcf-protection=full`
  in a vcpkg overlay port, or by experimenting with
  `-Wl,-z,force-ibt`/`-Wl,-z,force-shstk`. PIE, NX, RELRO, stack
  canary, and FORTIFY are all verified present on the v0.1 binary;
  CET is the only hardening rule missing at the binary marker
  level.
- Codecov upload for coverage runs. Today coverage.yml uploads
  the LCOV trace as a workflow artifact only; Codecov integration
  needs either a public repo or a paid Codecov plan for private
  repos.
- Organic test growth from 185 toward 200+. Per session 11 audit:
  pad coverage with rapidcheck property tests (pack/unpack,
  hex/unhex, cyclic invariants) and per-command pretty/json
  snapshot tests under `tests/snapshots/`. Avoid padding for
  count's sake; tests should map to real regression surfaces.

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
