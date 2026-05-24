<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 manop55555 -->

# ADR 0008 - CLI11 for command-line parsing

- Status: accepted
- Date: 2026-05-22

## Context

`abcpwn` has 39 subcommands at v0.1, each with its own flag set,
positional arguments, and validation rules. Hand-rolling argument
parsing for each subcommand would be redundant and error-prone.
The CLI parser needs to:

- Support nested subcommands with their own option scopes.
- Generate `--help` text automatically (the help text is also the
  contract the test suite checks against).
- Validate types at parse time (so commands receive `uint64_t` for
  numeric flags, not `std::string`).
- Be header-mostly so it does not bloat the static binary.
- Be permissively licensed so it ships in the Apache-2.0 build.

## Decision

Use **[CLI11](https://github.com/CLIUtils/CLI11)** as the
command-line parser.

- Each subcommand registers itself with the dispatcher via a
  `CommandRegistry` entry that points at its CLI11 sub-app and
  its `ICommand::run()` implementation.
- Global flags (`--format`, `--color`, `--no-banner`, `--config`,
  `--log-file`, `--allow-network`) are bound at the root app and
  flow into the `Context` object passed to each command's `run()`.
- CLI11's built-in validators (existing file, range, alpha-numeric)
  cover most argument validation; custom validators handle the
  cases CLI11 does not have built in (hex strings, "addr:size:prot"
  triples, etc).
- Shell completions are generated from the same CLI11 structure
  via a small post-processor (see
  [`completions/`](../../completions)).

## Consequences

Easier:

- One library, one syntax, one help-text generator.
- Subcommand structure is declarative; adding a new subcommand
  is mostly a new file under `src/commands/` plus a registry line.
- Self-documenting: `abcpwn <sub> --help` is always the authoritative
  reference (the docs say so explicitly).
- BSD-3-Clause license is Apache-2.0 compatible.

Harder:

- CLI11's templates are heavy on the compiler. We accept the
  build-time cost; the binary size impact is small because CLI11
  is header-mostly and dead-code is eliminated at link.
- CLI11's error messages for malformed input are good but not
  perfect; we wrap a few common cases with custom validators to
  improve the diagnostics.

## Alternatives considered

- **`getopt_long`.** Reject. No subcommand support, no type
  conversion, no automatic help generation. Would require building
  the surrounding infrastructure ourselves.
- **argparse for C++.** Reject. Less mature than CLI11 for
  nested subcommand structures and validators.
- **Boost.Program_options.** Reject. Pulls in much of Boost; adds
  binary size and build time we do not need for a CLI parser.
- **Hand-rolled parser.** Reject. Re-implementing typed parsing,
  validation, help generation, and shell completions across 38
  subcommands is a maintenance liability we should not take on.
