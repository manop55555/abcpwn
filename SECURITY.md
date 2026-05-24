# Security Policy

`abcpwn` parses attacker-controlled binaries. A bug in the parser is a
real vulnerability. We take security seriously.

## Authorized use only

abcpwn is for authorized security work only -- research, CTF, teaching,
and penetration testing you are permitted to perform. You are
responsible for complying with the law in your jurisdiction (for
example Germany's StGB §202c, the UK Computer Misuse Act 1990, and the
US Computer Fraud and Abuse Act). The software is provided "as is"
under Apache-2.0, without warranty. See the README's "Defensive use and
legal notice" for the full statement.

## Reporting a Vulnerability

Please report security vulnerabilities through GitHub Security Advisories:

  https://github.com/manop55555/abcpwn/security/advisories/new

Do NOT open public issues for security vulnerabilities.
There is no email contact for security issues - use GitHub Security
Advisories only.

We will acknowledge your report within 7 days and aim to release a fix
within 30 days for critical issues.

## Security Guarantees

- `abcpwn` makes no network calls except `libc --download` and `pwninit`,
  both gated behind the global `--allow-network` flag.
- `abcpwn` collects no telemetry.
- `abcpwn` does not auto-update.
- `abcpwn` does not execute, run, or spawn the binaries it analyzes.
- All file input is bounded by `ABCPWN_MAX_FILE_SIZE` (default 2 GB).
- All binary parsing is delegated to LIEF.
- All parsers have libFuzzer harnesses and run nightly fuzz jobs.
- Debug builds run under AddressSanitizer, UndefinedBehaviorSanitizer, and
  ThreadSanitizer; CI fails on any sanitizer error.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | yes       |

See [docs/SUPPORT.md](docs/SUPPORT.md) for the long-term support policy.

## Verifying Releases

Every release archive is published with a `SHA256SUMS` file. Verify with:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

Sigstore-based signature verification is planned for a future release.

## Threat Model

See [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) for the full threat
model including the adversary capabilities considered, the mandatory
security rules every PR must satisfy, the static analysis suite, and the
fuzzing strategy.
