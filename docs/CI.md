# Continuous integration

This document records what each GitHub Actions workflow does and, more
importantly, *when it runs*. A workflow that is not triggered by your
change cannot gate it -- so knowing the trigger matrix is the difference
between "the tests passed" and "the tests never ran".

## Trigger matrix

| Workflow      | push `main` | pull request | schedule        | tag `v*` | manual dispatch |
|---------------|:-----------:|:------------:|-----------------|:--------:|:---------------:|
| `ci`          | yes         | yes          | -               | -        | -               |
| `sanitizers`  | yes         | yes          | -               | -        | yes             |
| `coverage`    | yes         | yes          | -               | -        | yes             |
| `codeql`      | yes         | yes          | Mon 06:00 UTC   | -        | -               |
| `fuzz`        | -           | -            | daily 02:00 UTC | -        | yes             |
| `release`     | -           | -            | -               | yes      | yes             |

So a plain `git push` to `main` runs **`ci`, `sanitizers`, `coverage`,
and `codeql`**. `fuzz` runs nightly (not per push -- it runs each
libFuzzer harness for a time budget and files crash issues, which would
be noisy on every commit). `release` runs only when a `v*` tag is
pushed.

## What each workflow gates

- **`ci`** -- the primary gate. Two independent jobs:
  - `lint`: `scripts/check-all.sh` (format, SPDX, no-emoji, no-system,
    no-attribution, no-spec-leak, no-telemetry, URL allowlist, and
    shellcheck), plus clang-tidy/cppcheck on the build matrix.
  - `build` (matrix `linux-x64-gcc` on gcc-13, `linux-x64-clang` on
    clang-18): configure, build, and run the full `ctest` suite.

  `build` is **not** `needs: lint`. The two run in parallel and both
  must be green. This is deliberate: when `build` depended on `lint`, a
  lint failure skipped the entire build+test matrix, so a lint-only
  breakage silently hid whether the tests passed. Decoupled, the test
  result is always visible.

- **`sanitizers`** -- builds and runs the suite under AddressSanitizer,
  UndefinedBehaviorSanitizer, and ThreadSanitizer. Gates pushes to
  `main` and pull requests.

- **`coverage`** -- builds the `coverage` preset, runs the suite, and
  uploads the LCOV trace as a workflow artifact (no external upload in
  v0.1).

- **`codeql`** -- GitHub's static security analysis for C/C++.

- **`fuzz`** -- runs the libFuzzer harnesses on a nightly schedule and
  opens an issue for any new crash. Trigger it manually with
  `gh workflow run fuzz.yml` to exercise a specific commit.

- **`release`** -- on a `v*` tag (or manual dispatch with a tag input),
  builds the release artifact, signs it with cosign (keyless), emits a
  CycloneDX SBOM and an SLSA build-provenance attestation, and publishes
  a draft GitHub Release. See [../SECURITY.md](../SECURITY.md) for how to
  verify a release.

## shellcheck pinning

`ci` installs shellcheck from the official static release binary at a
pinned version (checksum verified) rather than from `apt`, because the
apt version differs by distro and the versions disagree on which checks
are enabled by default. The same version, plus the repo-root
`.shellcheckrc`, is what `scripts/check-shellcheck.sh` expects locally,
so the local pre-commit gate and CI enforce an identical check set. See
[../CONTRIBUTING.md](../CONTRIBUTING.md) for the local install.

## Branch protection (not enabled in v0.1)

`main` is not branch-protected -- acceptable for a single maintainer. If
protection is enabled later, the required status checks should be the
push-triggered jobs: `lint`, `linux-x64-gcc`, `linux-x64-clang`,
`Sanitizers`, and `Coverage` (and `CodeQL` if desired). List each job by
name; listing only the workflow is not sufficient once `ci` exposes
multiple independent jobs.
