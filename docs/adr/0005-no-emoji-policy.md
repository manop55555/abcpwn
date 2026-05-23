<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 manop55555 -->

# ADR 0005 - No emoji in source, output, or documentation

- Status: accepted
- Date: 2026-05-22

## Context

Security tooling lands in many terminals and locales: CTF infra
running over SSH on minimal images, embedded devices, CI logs
parsed by other tools, output piped through scripts that may not
preserve UTF-8 cleanly. Emoji rendering depends on font, terminal,
locale, and Unicode normalization. When any of those drift, emoji
become "?" placeholders or width-disrupting blocks that break
column-aligned output.

The project's output is meant to be machine-parseable and
human-readable in any terminal. Emoji are neither.

## Decision

**No emoji anywhere** in the project. Specifically forbidden:

- Source code (comments, string literals, log messages, error
  messages).
- CLI output (banner, command results, errors, help).
- Documentation (README, ADRs, this file, all other markdown).
- Commit messages.
- CI workflow files and issue templates.

ASCII markers are the substitute, with a fixed mapping:

| Meaning | Marker |
|---------|--------|
| Pass / OK | `[+]` |
| Fail / Bad | `[-]` |
| Warning | `[!]` |
| Info / Neutral | `[*]` |
| Question / Unknown | `[?]` |

Enforcement is automated. `scripts/check-no-emoji.sh` runs in CI
on every commit and greps the entire repo for Unicode codepoints
in the documented emoji ranges (U+1F300 to U+1F9FF, U+2600 to
U+27BF, U+1F000 to U+1F02F, U+1FA70 to U+1FAFF, U+E000 to U+F8FF
private use area).

The banner uses box-drawing characters (U+2500 block), which are
not emoji and render uniformly on any terminal that supports
UTF-8. Box-drawing characters are explicitly outside the
forbidden ranges.

## Consequences

Easier:

- Output is reliable across terminals, locales, and pipelines.
- Greppability: a script looking for `[-] failed` patterns gets
  exact matches.
- Width math is deterministic; right-aligned severity tags line up.
- No bikeshedding over which emoji means which status; everyone
  uses the same five markers.

Harder:

- Contributors used to richer terminal output may find the
  aesthetic dry. The trade-off is conscious.
- Some IDEs render `[+]` and `[-]` as plain text where they would
  inject emoji on Markdown; documents look more like code.

## Alternatives considered

- **Allow emoji in user-facing markdown, ban in CLI output.**
  Reject. Inconsistent guidance, and Markdown emoji often end up
  in terminal output when docs are previewed via `less` or
  copied into scripts.
- **Allow emoji only behind a feature flag.** Reject. Adds
  complexity and the CI grep would need exceptions; not worth it
  for an aesthetic toggle.
- **Use Nerd Font icons.** Reject. Same rendering-portability
  problem as emoji plus a font dependency.
