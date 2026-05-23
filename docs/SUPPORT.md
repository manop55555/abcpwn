# Support Policy

## Supported versions

| Version | Status | Latest patch | Notes |
|---------|--------|--------------|-------|
| 0.1.x   | active | 0.1.0        | initial public line; tier 1 platforms covered |

A version is `active` if it receives bug fixes and security
backports. Once a newer MAJOR is released, the previous MAJOR enters
maintenance mode for six months (security and critical fixes only),
then end-of-life.

## End-of-life policy

When a new MAJOR is released:

- The previous MAJOR receives security and critical-bug fixes for
  six months.
- After six months, no further fixes for the previous MAJOR.
- The current MAJOR is always actively maintained.

For pre-1.0 lines (0.x), the most recent 0.x line is the supported
line. Older 0.x lines are not maintained once a newer 0.x ships
unless a security issue is reported there.

## Platform support tiers

### Tier 1

Tier 1 platforms are tested on every commit and gate the release:

- Linux x86_64 (Ubuntu 24.04, glibc-based; static binary should run
  on most distributions).
- Linux aarch64 (Ubuntu 24.04 on the GitHub Actions arm runner).
- macOS arm64 (macOS 13+, M1 and newer).

A regression on a tier 1 platform blocks the release.

### Tier 2

Tier 2 platforms are tested on a best-effort basis and may lag:

- macOS x86_64 (macOS 13+, Intel).
- FreeBSD 14+.

Tier 2 regressions are tracked but do not block the release. PRs that
fix tier 2 regressions are welcome.

### Not supported

- Windows host. PE inspection from Linux or macOS works (LIEF parses
  PE); running `abcpwn` natively on Windows is not in the v0.1 scope.
- Cygwin / WSL1. WSL2 is undocumented but should work as Linux x86_64.
- musl-based distributions (Alpine). Building from source is likely
  to work; not gated in CI.

## How to ask for help

In order of preference:

1. **Skim [FAQ.md](FAQ.md)** for the most common questions.
2. **Search existing discussions** at
   https://github.com/manop55555/abcpwn/discussions before opening
   a new thread.
3. **Open a discussion** (not an issue) for usage questions, design
   questions, or "how do I do X with `abcpwn`" questions.
4. **Open an issue** at https://github.com/manop55555/abcpwn/issues
   for bug reports, behavior that contradicts the documentation,
   crashes, or regression reports.

Security issues are reported privately via GitHub Security Advisories
only:

  https://github.com/manop55555/abcpwn/security/advisories/new

Do not file security issues in public discussions or issues. See
[../SECURITY.md](../SECURITY.md) for the full disclosure process.

## Response expectations

This is a single-maintainer project. Best-effort response times:

- Security reports: acknowledged within 7 days.
- Bug reports with a reproducer: triaged within 30 days.
- Feature requests: responded to within 60 days, but may sit longer
  before the design is decided. Discussion is the right venue first.
- Pull requests: initial review within 14 days for non-trivial
  changes.

## Backports

Critical fixes (security, data loss, hard crash) are backported to:

- The current MAJOR (always).
- The previous MAJOR if it is still within its six-month maintenance
  window AND the issue is severe.

Backports use a patch version bump on the maintenance branch (for
example a fix from `main` lands on `v0.1.x` branch as `v0.1.1`).

## Communicating support changes

Changes to this policy are announced in:

- `CHANGELOG.md` (under the version that introduces the change).
- A discussion thread tagged `announcement`.
- The release notes for the affected version.
