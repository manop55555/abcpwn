<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 manop55555 -->

# ADR 0003 - LIEF for binary parsing

- Status: accepted
- Date: 2026-05-22

## Context

`abcpwn` reads ELF, PE, and Mach-O binaries. The parser is the
single largest attack surface in the tool: a malformed binary is
the most likely input to crash, corrupt memory, or read out of
bounds. Hand-written parsers for three executable formats would be
a maintenance and security burden that outweighs the upside of
"controlling everything."

## Decision

Use [LIEF](https://github.com/lief-project/LIEF) as the sole
binary-format parsing library.

- Every read of binary structure goes through `formats::BinaryLoader`,
  which is a thin wrapper around LIEF.
- LIEF's `ParserConfig` is used to skip sections each command does
  not need (lazy parsing, see [ADR 0006](0006-no-network-by-default.md)
  for the related "do less" principle).
- No hand-rolled parsers in `src/`. If LIEF lacks something, we
  document the gap and defer to a future release.

## Consequences

Easier:

- One library, one set of fuzz targets, one well-tested
  implementation across three formats.
- LIEF receives security fixes upstream; we get them by bumping
  the vcpkg baseline.
- Cross-format consistency: an ELF symbol and a PE export resolve
  through the same code path.

Harder:

- LIEF dependency footprint is meaningful (LIEF, LLVM bits for
  demangling, et cetera). The static binary is about 8 to 12 MB.
- LIEF's API can change between minor versions. The wrapper layer
  insulates the rest of the codebase but the wrapper itself needs
  updates.
- LIEF lacks a few niche features (Mach-O encryption, specific PE
  resource trees) that we accept as gaps in v0.1.

## Alternatives considered

- **Hand-rolled parsers.** Reject. Three formats, each with
  thousands of edge cases (PE COFF imports, ELF dynamic section,
  Mach-O LC_ commands). The attack surface a single malformed
  binary opens is too high to maintain in-house.
- **objdump or readelf shell-outs.** Reject. Slow, depends on
  external tools, and CLAUDE.md forbids `system()` / `popen()` /
  `exec*()` anywhere in `src/`.
- **libbfd.** Reject. GPL-licensed; would force the default build
  to be GPL.
- **Per-format library mix.** Reject. Wrapping three separate
  libraries with different APIs and conventions costs more than
  the gap-coverage benefit.
