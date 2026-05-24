<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 manop55555 -->

# ADR 0004 - Dual build variant for the Keystone assembler

- Status: accepted with v0.1 scope narrowed (see Status update)
- Date: 2026-05-22

## Context

`abcpwn asm` (and a few specialized commands like `patch --asm-at`)
need an assembler engine. The de facto choice for a multi-arch,
embeddable assembler in C is
[Keystone](https://github.com/keystone-engine/keystone).

Keystone is licensed **GPL-2 only** (not "or later"). A binary that
links Keystone is a combined work under GPL-2. The default
`abcpwn` license is Apache-2.0; we do not want to force everyone
who uses or redistributes `abcpwn` to take on GPL-2 obligations.

## Decision

Ship **two build variants**:

- `abcpwn` (default). Apache-2.0. Keystone is NOT linked. The
  `asm` subcommand returns `FeatureDisabled` (exit code 4). All
  non-assembly functionality is available.
- `abcpwn-full`. GPL-2 combined work. Keystone is linked. The
  `asm` subcommand is fully functional. Other commands that
  benefit from assembly (`patch --asm-at`) are also functional.

The toggle is a CMake flag `ABCPWN_WITH_KEYSTONE`. The two builds
share 100% of the rest of the source tree. The release pipeline
emits both archives.

License plumbing:

- The default release archive is labeled `abcpwn-<platform>` and
  ships `LICENSE` (Apache-2.0).
- The full release archive is labeled `abcpwn-full-<platform>`
  and ships `LICENSE` (Apache-2.0 plus GPL-2 notice) and the
  Keystone source archive alongside the binary to satisfy GPL-2's
  source-availability clause.
- `LICENSE-THIRD-PARTY.md` documents the split.

## Consequences

Easier:

- Apache-2.0 users get a permissively-licensed binary with no
  surprise GPL obligations.
- GPL-2 users get the full feature set without rebuilding.
- License lawyering is straightforward: each archive is one
  license per the spec.

Harder:

- The release pipeline must produce both archives. Per platform,
  that doubles the CI matrix.
- The internal API has to handle "Keystone present" and "Keystone
  absent" cleanly. We model it as a feature flag exposed through
  `Context` and let each command decide whether it can run.
- Documentation has to repeat the split in three places (README,
  BUILDING, LICENSE-THIRD-PARTY).

## Alternatives considered

- **Apache-only, no assembler.** Reject. `asm` is a useful
  command; locking it out entirely loses meaningful capability.
- **GPL-only, all builds combined.** Reject. Forces every user
  and downstream redistributor to take on GPL-2 obligations even
  if they only use the recon subcommands.
- **Use an Apache-compatible assembler.** No viable option exists
  in v0.1. LLVM MC is Apache-2.0 but the integration cost is high
  and it pulls in much more than we need. Re-evaluate after v1.0.
- **Runtime-load Keystone as a shared library.** Reject. Keystone
  upstream does not commit to a stable shared-library ABI, and
  GPL-2's combined-work clause applies regardless of how the
  linking happens.

## Status update (2026-05)

The dual-build plan is preserved at the source level (the
`ABCPWN_WITH_KEYSTONE` flag and the `release-with-keystone` CMake
preset both still work). However, the v0.1 release pipeline emits
only the Apache-2.0 artifact -- doubling the per-platform CI matrix
to ship a pre-built GPL-2 archive proved a poor tradeoff for v0.1
given the limited demand. Users who need the Keystone-enabled build
produce it from source. The "two archives" goal returns when there
is concrete demand signal (a release-track issue, a downstream
distribution request); until then, every reference to a
hypothetical `abcpwn-full` release artifact has been removed from
README, COMMANDS, ERROR_CODES, the man page, CHANGELOG, and
LICENSE-THIRD-PARTY to keep the docs honest about what the
pipeline actually publishes.
