# Contributing to abcpwn

Thanks for your interest in contributing.

## Quick start

1. Fork the repo on GitHub.
2. Clone your fork and create a feature branch:

   ```bash
   git checkout -b feature/short-description
   ```

3. Make your changes. Build and test locally:

   ```bash
   cmake --preset debug
   cmake --build --preset debug
   ctest --preset debug --output-on-failure
   ```

4. Run the orchestrator before staging:

   ```bash
   scripts/check-all.sh
   ```

5. Commit using a Conventional Commits message (see below).
6. Push your branch and open a pull request against `main`.

See [BUILDING.md](BUILDING.md) for full build prerequisites and platform
setup.

## Code style

- C++20. `.clang-format` and `.clang-tidy` are authoritative.
- Run `clang-format-21` (or the highest installed version) before
  committing. CI enforces format.
- Every source file begins with the SPDX header:

  ```cpp
  // SPDX-License-Identifier: Apache-2.0
  // Copyright (c) 2026 manop55555
  ```

  Use `#` instead of `//` for shell, cmake, yml, and python files. The
  SPDX text itself is identical, only the comment prefix changes.
- ASCII markers only (`[+]`, `[-]`, `[!]`, `[*]`, `[?]`). No emoji
  anywhere in source, output, comments, or commit messages.
- Project name is always lowercase: `abcpwn`.

## Conventional Commits

Commit messages follow the
[Conventional Commits](https://www.conventionalcommits.org) format:

- `feat:`     new feature (drives MINOR version bump)
- `fix:`      bug fix (drives PATCH version bump)
- `docs:`     documentation only
- `chore:`    housekeeping with no code change
- `ci:`       CI configuration
- `test:`     test changes
- `refactor:` code change without behavior change
- `perf:`     performance improvement
- `build:`    build system or dependency changes
- Add `!` for a breaking change: `feat!:`, `fix!:` (drives MAJOR bump)

Keep the subject line under 72 characters, imperative mood. Wrap the body
at 72 characters. Explain the why, not just the what.

## Pull request checklist

- [ ] Tests added or updated (unit, integration, or fuzz as appropriate)
- [ ] `CHANGELOG.md` entry under `[Unreleased]`
- [ ] Documentation updated if the change is user-visible
- [ ] `scripts/check-all.sh` exits zero
- [ ] `ctest --preset debug` passes
- [ ] No emoji anywhere
- [ ] No mention of internal spec or design-log file names

## Security issues

Do NOT file security issues as public pull requests or issues. Use GitHub
Security Advisories:

  https://github.com/manop55555/abcpwn/security/advisories/new

See [SECURITY.md](SECURITY.md) for the full disclosure process.

## License contribution agreement

By submitting a pull request, you agree that your contribution is licensed
under Apache-2.0, the project's license.

If your contribution touches the `-full` build variant (which links the
GPL-2 Keystone assembler), you agree the contribution is also licensed
under terms compatible with the GPL-2 combined work.

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Getting in touch

- Questions about usage: open a discussion at
  https://github.com/manop55555/abcpwn/discussions
- Bug reports: open an issue at
  https://github.com/manop55555/abcpwn/issues
- Security issues: see above
