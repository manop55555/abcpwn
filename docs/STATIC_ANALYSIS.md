# Static Analysis

`abcpwn` runs several static-analysis tools in CI. This document lists
which tools, which categories of findings are intentionally suppressed
at the v0.1 baseline, and why.

## Tools in the pipeline

| Tool          | Where             | Blocking? | Notes |
|---------------|-------------------|-----------|-------|
| clang-format  | `lint` job        | yes       | enforced version: 21 |
| clang-tidy-18 | `build` job (clang matrix) | no (`continue-on-error: true` in v0.1) | becomes blocking in v0.2 after a per-file NOLINT pass |
| cppcheck      | `build` job       | no (`continue-on-error: true` in v0.1) | known false-positive baseline |
| shellcheck    | `lint` job        | yes       | applied to scripts and integration tests |
| The orchestrator: `scripts/check-all.sh` | `lint` job | yes | runs the eight in-tree checks |
| ASan / UBSan / TSan | `sanitizers` workflow on PR | yes | one of each preset must pass |
| libFuzzer harnesses | `fuzz` workflow nightly | issues opened on crash | per-harness one-hour budget |

## clang-tidy categories disabled at v0.1

The categories below collide with the v0.1 design and are turned off
in `.clang-tidy`. Each is listed with the reason it does not apply
today. Re-enabling them is part of the v0.2 NOLINT pass.

- `portability-avoid-pragma-once` - `#pragma once` is used
  consistently across the codebase; switching to include guards is
  cosmetic churn.
- `misc-non-private-member-variables-in-classes` and
  `cppcoreguidelines-non-private-member-variables-in-classes` -
  small POD-like value types (`Finding`, `Section`, `Gadget`) expose
  public members on purpose to avoid getter ceremony.
- `hicpp-explicit-conversions` and `google-explicit-constructor` -
  `Result<T, E>` and `Unexpected<E>` rely on implicit construction
  from a value or an error to keep call sites readable.
- `performance-enum-size` - enums sized to `std::int32_t` map
  directly to process exit codes; shrinking would force a cast
  everywhere.
- `readability-redundant-member-init` - default-initialized members
  are written out explicitly for documentation value.
- `bugprone-exception-escape` - the existing `Result` API avoids the
  throwing path; the checker does not model `Result` semantics and
  reports false positives on `main()` boundaries.
- `cppcoreguidelines-pro-bounds-array-to-pointer-decay` and
  `hicpp-no-array-decay` - several Capstone interop sites pass
  string literals to C APIs.
- C-array, vararg, and `reinterpret_cast` checks - the LIEF interop
  layer reinterprets raw bytes deliberately and is the only place
  these patterns appear.
- `cppcoreguidelines-special-member-functions` and
  `hicpp-special-member-functions` - rule-of-five enforcement
  conflicts with several move-only types that intentionally delete
  copy operations only.
- `cppcoreguidelines-avoid-do-while` - the format-string parser uses
  `do { ... } while` for clarity; rewriting the loop is more
  confusing than the warning.
- `bugprone-narrowing-conversions` and
  `cppcoreguidelines-narrowing-conversions` - cast noise dominates
  the byte-level arithmetic in the gadget search and BPF decoder.
  The actual narrowing risks are covered by saturating arithmetic
  per the security model rules.
- `readability-function-cognitive-complexity` - the dispatcher in
  `main.cpp` and the gadget filter are deliberately long; splitting
  them would not improve readability.
- `readability-suspicious-call-argument` - false positives on
  symmetric APIs (e.g. `min(a, b)`).

The remaining clang-tidy categories (`cert-*`, `concurrency-*`,
`clang-analyzer-*`, the deeper `portability-*` checks) still fire on
every PR. Findings from those categories must be addressed or
explicitly suppressed at the call site with a comment that names a
reason.

## cppcheck baseline

Suppressions live in `.cppcheck-suppress`. Common entries and why
they exist:

- `useStlAlgorithm` - several raw `for` loops are written for clarity
  in code that touches byte-level state; an `std::transform` chain
  would be harder to read.
- `noExplicitConstructor` on `Result<T>` - intentional implicit
  construction from value or error.
- `unreadVariable` on `ch.valid` - the field is checked indirectly
  through a defaulted member.

The cppcheck step in CI runs with `--inconclusive` and
`continue-on-error: true`, so additional informational findings
appear in the run logs but do not block the build.

## Suppressing a finding at the call site

When a check is correct in general but wrong in a specific spot,
suppress per-line with a NOLINT comment naming the category and a
reason:

```cpp
// NOLINTNEXTLINE(bugprone-narrowing-conversions)
// reason: index already validated by safe_io::open
const auto i = static_cast<std::size_t>(parsed_offset);
```

Project-wide suppressions are not added casually. Each blanket
disable in `.clang-tidy` carries a comment block linking it to a
specific design choice in this file or another doc.

## Reproducing CI locally

```bash
cmake --preset debug
cmake --build --preset debug
clang-tidy-18 src/**/*.cpp -p build/debug/ --quiet
cppcheck --enable=all --inconclusive \
         --suppressions-list=.cppcheck-suppress \
         --suppress=missingIncludeSystem \
         -I include/ src/
shellcheck scripts/*.sh tests/fixtures/*.sh tests/integration/*.sh
scripts/check-all.sh
```

All five commands match what CI runs. The orchestrator
(`check-all.sh`) is the same script CI invokes in the `lint` job.
