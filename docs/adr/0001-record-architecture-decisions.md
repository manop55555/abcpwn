<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 manop55555 -->

# ADR 0001 - Record architecture decisions

- Status: accepted
- Date: 2026-05-22

## Context

`abcpwn` is a CLI toolkit with a small surface area but a tightly
constrained design: no network by default, no telemetry, no
auto-update, no `system()`/`popen()`/`exec*()` anywhere in `src/`,
specific library choices (LIEF, Capstone, CLI11), and a dual-license
build variant for the GPL-2 assembler. These choices need to be
discoverable to new contributors and durable across maintainership
changes.

A running design log helps but is not the public artifact. We need a
public, append-only record of the significant architectural choices
the project has made, with the rationale that led to each one.

## Decision

Adopt **Markdown Architectural Decision Records** (MADR) under
`docs/adr/`.

Each file is numbered (`NNNN-short-title.md`), uses the structure:

- title
- status (proposed, accepted, deprecated, superseded by NNNN)
- date (ISO 8601)
- context (what is the problem?)
- decision (what did we pick?)
- consequences (what does this make easier and harder?)
- alternatives (what else did we consider, and why not?)

Future ADRs reference earlier ones by number (`[ADR 0002](0002-cpp20-as-language-target.md)`).
Each ADR carries the SPDX header in HTML-comment form so license
metadata is uniformly discoverable.

## Consequences

Easier:

- New contributors can read `docs/adr/` to learn why the project
  looks the way it does without reading the entire git history.
- Project decisions become reviewable: a PR can propose a new ADR
  and the discussion is captured in one place.

Harder:

- Discipline required to write an ADR for new decisions. The bar
  is "architectural" - things like vendor swaps, fundamental design
  changes, hard policies. Small bug fixes do not need ADRs.

## Alternatives considered

- **No formal log.** Reject: the design choices in the project
  charter are dense enough that future contributors deserve more
  than `git log` and reverse-engineering.
- **One single design document.** Reject: a monolithic doc rots
  faster than a sequence of focused ADRs. ADRs are also easier to
  review individually.
- **Wiki pages.** Reject: docs in the repo travel with the source.
  A GitHub wiki is a separate artifact that can drift out of sync.
