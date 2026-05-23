<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2026 manop55555 -->

# ADR 0006 - No network by default

- Status: accepted
- Date: 2026-05-22

## Context

`abcpwn` analyzes binaries. Most of its commands operate purely on
the input file and need no network. A few commands genuinely
benefit from network access:

- `libc download` fetches libc archives from a community database
  (https://libc.rip).
- `pwninit` downloads the matching dynamic linker for a challenge
  binary.

Networking by default is a security and privacy concern. Many
users run `abcpwn` against potentially-sensitive binaries on
machines with no internet exposure, in air-gapped CI, or on hosts
where outbound traffic must be approved. A tool that quietly makes
HTTPS requests is a tool you cannot trust in those environments.

## Decision

**Network access is opt-in.** The global `--allow-network` flag
must be passed explicitly for any subcommand to make a network
request. Without it, network-using commands exit immediately with
`NetworkDisabled` (exit code 12) and print:

```
[-] network access disabled (use --allow-network to enable)
```

Implementation constraints:

- Network code lives in exactly two source files:
  `src/commands/libc.cpp` and `src/commands/pwninit.cpp`.
  Enforced by code review and `scripts/check-no-telemetry.sh`'s
  URL allowlist.
- The URL allowlist (`scripts/check-urls.sh`) covers every HTTPS
  host referenced in tracked source files.
- Even when network is enabled, the connection is direct (no
  redirector, no third-party fronting CDN). The destination is
  the one named in the source.

## Consequences

Easier:

- The default behavior is auditable: no surprise outbound
  connections. CI environments without internet work out of the
  box for all non-network commands.
- Forensic and air-gapped use cases are first-class.
- Source-code grep for `http` reveals every network site.

Harder:

- New users hitting `libc download` for the first time see an
  error rather than the expected behavior. The error message
  names the fix, so the friction is small but real.
- Scripts that automate both kinds of work have to remember to
  pass `--allow-network`.

## Alternatives considered

- **Network by default, opt-out flag.** Reject. The privacy
  default should match the threat model: assume the user does
  not want outbound traffic unless they ask for it.
- **Prompt at runtime.** Reject. Interactive prompts break
  automation and undermine the deterministic-output goal.
- **Per-command opt-in (`libc download --allow-network`).**
  Reject. A global flag is harder to forget and makes the
  policy uniform across future network-using commands.
- **No network code at all.** Reject. `libc download` and
  `pwninit` are concretely useful, and opt-in network is a
  good middle ground.
