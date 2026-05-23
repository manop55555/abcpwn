# Security Model

`abcpwn` parses attacker-controlled binaries. A bug in the parser is a
real vulnerability. This document defines the threat model, the
guarantees the project provides, and the rules every contribution
must satisfy.

## Threat model

### Adversary

The adversary provides a malicious binary or input crafted to exploit
`abcpwn` itself. The adversary cannot:

- Modify `abcpwn`'s installation, configuration, or environment.
- Inject into `abcpwn`'s process beyond what the parsed input allows.

### Adversary goals

- Remote code execution in the `abcpwn` process.
- Denial of service (out-of-memory, infinite loop, crash).
- Memory corruption (read or write out of bounds).
- Information disclosure (read sensitive files, leak heap contents).

### Out of scope

- Side-channel attacks on the tool itself (timing, power).
- Attacks via compromised dependencies (mitigated by SBOM and
  pinned versions).
- Physical access attacks.

## Guarantees

1. **No execution of analyzed binaries.** `abcpwn` only parses; it
   never runs, loads, or interprets the target binary's code.
2. **No `system()`, `popen()`, or `exec*()`** anywhere in `src/`.
   Enforced by `scripts/check-no-system.sh`.
3. **No network by default.** Only `libc download` and `pwninit` make
   HTTPS requests, both gated by the global `--allow-network` flag.
4. **No telemetry.** No metrics, no crash reports, no analytics, no
   phone-home. Enforced by `scripts/check-no-telemetry.sh`.
5. **No auto-update.** `abcpwn` never checks for updates or downloads
   itself.
6. **Bounded resources.** Every input is size-capped
   (`ABCPWN_MAX_FILE_SIZE`, default 2 GB) and parse depth-limited
   (default 64).
7. **Memory-safe by construction.** No raw `new` / `delete`, no raw
   C strings at API boundaries, RAII throughout.
8. **Fuzzed parsers.** Every binary-parsing path has a libFuzzer
   harness; the nightly fuzz workflow runs one hour per harness.
9. **Sanitizer-clean.** Debug builds run with AddressSanitizer and
   UndefinedBehaviorSanitizer; CI fails on any sanitizer error.
10. **Reproducible builds.** With `-ffile-prefix-map` and a fixed
    `SOURCE_DATE_EPOCH`, the released binary is intended to be
    byte-identical when rebuilt on the same OS, compiler, and arch.

## Mandatory rules every PR must satisfy

### Rule 1 - `safe_io::open()` for all file inputs

All file reads go through `core/safe_io.hpp::open()` which:

- Canonicalizes the path via `std::filesystem::weakly_canonical()`.
- Confirms the file is a regular file (not a FIFO, device, or
  symlink to a device).
- Enforces the size cap before reading.
- Returns a `Result<FileHandle, FileError>` rather than throwing.

Direct `std::ifstream` use in source code is rejected at review.

### Rule 2 - No raw `new` / `delete`

Use `std::unique_ptr`, `std::shared_ptr`, RAII helpers. Enforced by
clang-tidy `cppcoreguidelines-owning-memory`,
`modernize-make-unique`, and `modernize-make-shared`.

### Rule 3 - No raw C strings at API boundaries

Use `std::string_view` and `std::span<const std::byte>`. Raw `char*`
appears only inside thin wrappers around LIEF, Capstone, and
Keystone.

### Rule 4 - No hand-parsing of binary formats

LIEF parses ELF, PE, and Mach-O. The project does not write its own
parsers. If LIEF lacks a feature, document the gap and defer.

### Rule 5 - No `system()`, `popen()`, `exec*()` in `src/`

The `scripts/check-no-system.sh` orchestrator entry greps the source
tree and fails the build on any match.

### Rule 6 - Network only in two files

Network code lives in:

- `src/commands/libc.cpp` (the `libc download` action).
- `src/commands/pwninit.cpp` (interpreter download).

Both inspect the context's `allow_network` flag and exit with
`NetworkDisabled` (exit code 12) when it is false.

### Rule 7 - No telemetry, no auto-update

There is no opt-in or opt-out for telemetry; there is no telemetry.
`scripts/check-no-telemetry.sh` greps for known SDK function names
(Sentry, Rollbar, Segment) and fails on any match. The URL allowlist
in `scripts/check-urls.sh` covers every host the source references
in tracked content.

### Rule 8 - Checked arithmetic on parsed sizes

Every arithmetic operation on a value derived from input uses
saturating arithmetic (`std::add_sat`, `std::sub_sat`, `std::mul_sat`)
or an explicit overflow check via `__builtin_add_overflow` and
friends. Silent integer overflow on parsed sizes is a bug.

### Rule 9 - Bounded loops over parsed data

Every loop that iterates over data derived from input must have an
upper bound derived from the file size cap, NOT from a count field in
the input:

```cpp
const auto safe_count = std::min(untrusted_count, MAX_ENTRIES);
for (std::size_t i = 0; i < safe_count; ++i) { ... }
```

### Rule 10 - Untrusted-data naming convention

Variables derived from parsed input are prefixed `untrusted_` until
validated. Code review enforces this; clang-tidy cannot.

### Rule 11 - Bounded recursion

Recursive parse paths carry an explicit depth parameter and bail
when the configured maximum (default 64) is reached. Stack overflow
is not the depth check.

### Rule 12 - Compiler hardening

`cmake/Hardening.cmake` applies:

- Common: `-fstack-protector-strong`, `-fPIE`, `-pie`.
- Release: `_FORTIFY_SOURCE=3` (or `=2` on older glibc).
- Linux: `-fstack-clash-protection`, `-Wl,-z,relro`, `-Wl,-z,now`,
  `-Wl,-z,noexecstack`.
- Linux x86_64: `-fcf-protection=full` (Intel CET).
- aarch64 (Linux and macOS): `-mbranch-protection=standard`
  (ARM BTI plus PAC).

### Rule 13 - Sanitizer-clean

Debug builds run with AddressSanitizer and UndefinedBehaviorSanitizer.
ThreadSanitizer runs in its own preset on PR. CI fails on any
sanitizer error.

### Rule 14 - Fuzzed parsers

`tests/fuzz/` contains four harnesses at the v0.1 baseline:

- `fuzz_binary_loader` - LIEF wrapper.
- `fuzz_seccomp_decoder` - cBPF decoder.
- `fuzz_fmt_parser` - format-string offset finder.
- `fuzz_gadget_filter` - ROP gadget filter.

Each runs one hour per night in `fuzz.yml`. Any crash, leak, OOM, or
timeout opens a GitHub issue automatically and fails the workflow.

### Rule 15 - Reproducible builds

Release builds add:

```cmake
add_compile_options(
    -ffile-prefix-map=${CMAKE_SOURCE_DIR}=.
    -fmacro-prefix-map=${CMAKE_SOURCE_DIR}=.
)
```

`SOURCE_DATE_EPOCH` is set from the git commit timestamp in
`release.yml`. The output should be byte-identical across
reproducible-build environments.

### Rule 16 - SPDX header

Every source file starts with the SPDX header. Enforced by
`scripts/check-spdx.sh` in the orchestrator.

## Static analysis suite

Run on every PR:

1. **clang-tidy** with `cert-*`, `cppcoreguidelines-*`, `bugprone-*`,
   `concurrency-*`, `clang-analyzer-*` (categories disabled at v0.1
   are listed in [STATIC_ANALYSIS.md](STATIC_ANALYSIS.md)).
2. **cppcheck** with `--enable=all --inconclusive` and the
   project-level suppression file `.cppcheck-suppress`.
3. **include-what-you-use** (informational at v0.1; gating in v0.2).
4. **clang-format-21** for style. Mismatches fail the lint job.
5. **shellcheck** for every shell script under `scripts/` and
   `tests/`.

## Fuzzing strategy

### Corpus

- Seed corpus committed at `tests/fuzz/seeds/<harness>/`.
- Generated corpus stored as a workflow artifact and restored on the
  next run.
- Crash inputs preserved at `tests/fuzz/crashes/<harness>/`.

### Harness shape

```cpp
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > 10 * 1024 * 1024) { return 0; }
    abcpwn::formats::BinaryLoader loader;
    [[maybe_unused]] auto result = loader.parse(std::span{data, size});
    return 0;
}
```

### Fuzz duration

- PR smoke fuzz: 5 minutes per harness (built but not currently in
  every PR run; gating moves to PR in v0.2 once timing is tuned).
- Nightly fuzz: one hour per harness.
- Release-time fuzz: four hours per harness before publishing a tag.

## Vulnerability disclosure

Reports go to
https://github.com/manop55555/abcpwn/security/advisories/new (private).
Acknowledgement within 7 days; fix and CVE assignment within 30 days
for critical issues.

See [../SECURITY.md](../SECURITY.md) for the full process summary.

## Supply chain

### SBOM

Releases include a CycloneDX JSON SBOM listing every transitive
dependency with its version and license.

### Provenance

Release artifacts carry SLSA Level 3 build provenance attestations
generated by `actions/attest-build-provenance@v1` in `release.yml`.

### Signatures

Sigstore (cosign) signing of release artifacts is planned for v0.2.
v0.1 releases ship checksums via `SHA256SUMS` only.

### Dependency pinning

- vcpkg manifest mode with `builtin-baseline` commit pinned in
  `vcpkg-configuration.json`.
- FetchContent uses fixed commit hashes for picosha2 and Keystone.
- GitHub Actions reference dependencies are pinned (Dependabot keeps
  these current).

## Incident response

1. Reporter submits via GitHub Security Advisory (private).
2. Maintainer acknowledges within 7 days.
3. Patch developed in a private fork.
4. CVE assigned via GitHub.
5. Fix released; advisory published.
6. `CHANGELOG.md` records the fix under `Security`.
7. Severely affected versions are yanked from the release page.
