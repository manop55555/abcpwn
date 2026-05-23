<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 manop55555 -->

# ADR 0009 - spdlog for structured logging

- Status: accepted
- Date: 2026-05-22

## Context

`abcpwn` is primarily a CLI: most of its output is the command's
result (pretty or JSON), not log messages. But there is still a
need for opt-in diagnostic logging when something goes wrong:

- `--log-file <path>` writes a JSON log of the run for support
  questions and bug reports.
- Verbose internal traces (parser state transitions, gadget
  scanner statistics) are useful for performance regressions.
- Sanitizer builds and fuzz harnesses produce verbose stderr that
  the test infrastructure expects in a particular format.

The logger needs to:

- Default to "off" (the CLI surface is stdout-with-section-structure
  for results, not log messages).
- Support JSON output for machine-readable logs.
- Be fast in the disabled path (zero allocations when the log
  level is above the message's level).
- Ship in the static binary without pulling extra runtime
  dependencies.

## Decision

Use **[spdlog](https://github.com/gabime/spdlog)** as the logging
library.

- spdlog's compiled mode is used (header-only is too slow to
  compile at our usage volume).
- Log sinks:
  - stderr sink (off by default; controlled by `--verbose`).
  - file sink with JSON formatter when `--log-file <path>` is
    passed.
  - null sink (the default).
- Log levels follow spdlog conventions (`trace`, `debug`, `info`,
  `warn`, `error`, `critical`).
- Logger names are per module (`abcpwn.commands.gadget`,
  `abcpwn.formats.binary_loader`, et cetera), so users can filter
  with regex when inspecting `--log-file` output.
- `pattern` is set to a JSON-shaped template so every line is
  parseable without `jq` gymnastics.

## Consequences

Easier:

- One library for both human-readable and JSON logs.
- The disabled path is essentially free (level check is a single
  branch).
- MIT license is Apache-2.0 compatible.
- Per-module loggers make `--log-file` output greppable.

Harder:

- spdlog ships fmtlib internally. We were already using
  `std::format` (with `fmt::format` as the fallback under
  `__cpp_lib_format`), so we end up with two copies of fmtlib at
  link time. The static linker dedupes most of it; the binary
  size impact is in the kilobytes, not megabytes.
- spdlog's macro-based interface conflicts with strict
  clang-tidy categories (the macros expand to code that some
  checks flag); we disable a small number of categories at the
  call sites that use spdlog macros.

## Alternatives considered

- **Plain `std::cerr`.** Reject. No level control, no JSON
  output, no per-module routing. Would force us to build the
  surrounding infrastructure ourselves.
- **glog (Google logging).** Reject. Heavier dependency footprint
  than spdlog, less idiomatic API in modern C++.
- **fmtlog.** Reject. Smaller community and fewer integrators
  than spdlog; we prefer the ecosystem effect.
- **Per-binary roll-your-own.** Reject. Same logic as the CLI11
  decision in [ADR 0008](0008-cli11-for-cli-parsing.md): a tested,
  well-maintained library beats hand-rolled code for cross-cutting
  infrastructure.
