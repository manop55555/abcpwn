<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 manop55555 -->

# ADR 0002 - C++20 as the language target

- Status: accepted
- Date: 2026-05-22

## Context

The project needs a systems language that:

1. Compiles to a single static binary that starts in a few
   milliseconds (Python and Ruby are out for that reason).
2. Has first-class bindings to the binary-analysis libraries we
   want to delegate to (LIEF, Capstone).
3. Gives the parser enough type-system support to encode
   "untrusted" data flow at the API boundary.
4. Is reasonably ergonomic for the kind of code we write (lots of
   parsing, formatted output, JSON, bytes manipulation).

## Decision

Target **C++20**.

Concretely the project relies on:

- `std::string_view` and `std::span<const std::byte>` for non-owning
  parameter passing.
- `std::format` (with `fmt::format` as the fallback when the
  toolchain lacks it).
- `[[nodiscard]]` on every `Result<T, E>`-returning function.
- C++20 ranges only where they earn their keep (a few places).
- `std::filesystem::weakly_canonical()` in `safe_io`.

The internal `Result<T, E>` is a variant-backed in-house type rather
than `std::expected` because not every supported toolchain ships
`std::expected` yet. The shape mirrors `std::expected` so a future
swap is a search-and-replace.

## Consequences

Easier:

- Standard, well-tested library types for views, formatting, and
  filesystem.
- LIEF and Capstone bindings are first-class C++.
- Static linking is straightforward.

Harder:

- Toolchain spread: gcc 13 is the CI floor; gcc 12 lacks parts of
  `std::format`, so we ship the `fmt::format` fallback under a
  feature-detection block.
- `std::regex` is intentionally not used in hot paths; this is a
  C++ standard-library wart, not a C++20 problem, but it bears
  noting.

## Alternatives considered

- **Rust.** Reject for v0.1: would require either maintaining
  bindings for LIEF/Capstone (a large effort) or duplicating
  parsers (a larger effort plus drift risk). Revisit after v1.0
  if/when the binding situation matures.
- **Go.** Reject: faster cold start than Python but slower than
  native C++. Allocation behavior is harder to reason about in hot
  loops.
- **C.** Reject: no `std::string_view`, no `std::variant`,
  no `std::filesystem`. We would re-invent half the standard
  library and the result would be less safe.
