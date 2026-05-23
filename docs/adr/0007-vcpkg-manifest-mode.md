<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 manop55555 -->

# ADR 0007 - vcpkg manifest mode for dependencies

- Status: accepted
- Date: 2026-05-22

## Context

`abcpwn` depends on several non-trivial C and C++ libraries (LIEF,
Capstone, CLI11, nlohmann/json, spdlog, Catch2). Each has its own
build system; building them all from source on every machine is
slow. Trusting whatever the system package manager ships pins us
to whatever versions Ubuntu, macOS Homebrew, and FreeBSD ports
happen to carry, which differ.

We need a portable dependency manager that:

- Resolves to specific versions, not "whatever is installed."
- Works the same on Linux, macOS, and FreeBSD.
- Supports static linking cleanly.
- Lets the project pin a baseline so two checkouts on two machines
  resolve to the same versions.

## Decision

Use **vcpkg in manifest mode** with a pinned baseline commit.

- The dependency list lives in `vcpkg.json` at the repository
  root.
- The pinned baseline lives in `vcpkg-configuration.json`.
- Optional features (`network`, `fuzz`, `unicorn`) are declared
  in the manifest and triggered by CMake flags.
- All CI jobs clone vcpkg fresh per run and let the manifest
  drive resolution; this is reproducible regardless of the local
  developer's vcpkg state.

vcpkg's `x-gha,readwrite` binary cache is enabled in CI so the
heavy compilations (LIEF, Capstone) are cached between runs.

## Consequences

Easier:

- Deterministic dependency versions across developer machines and
  CI runners.
- Cross-platform: the same `vcpkg.json` produces matching builds
  on Linux, macOS, and FreeBSD.
- Static linking is straightforward; vcpkg ports default to
  static builds.

Harder:

- First build of a clean tree is slow because vcpkg compiles
  dependencies from source. The CI binary cache mitigates this.
- Baseline updates require testing all affected dependencies at
  once. We accept this cost in exchange for the predictability.
- Contributors who do not have vcpkg installed need to bootstrap
  it. [BUILDING.md](../../BUILDING.md) walks through this.

## Alternatives considered

- **System package manager (`apt`, `brew`, `pkg`).** Reject.
  Version skew across distributions. We would track three
  different versions of LIEF, for example, and surface different
  bugs on different developer machines.
- **Conan.** Reject. Comparable feature set to vcpkg, but
  CMake-first integration is slightly cleaner with vcpkg
  toolchain files, and the recipe quality for our specific
  dependency set is more uniform.
- **CMake `FetchContent` for everything.** Reject. Builds every
  dependency from source every time. We do use FetchContent for
  small header-only deps (picosha2) and the optional Keystone
  fallback when no vcpkg port is available; vcpkg handles
  everything else.
- **Submodules.** Reject. Each submodule update is a merge
  conflict, and CMake integration across heterogeneous
  build systems is its own time sink.
