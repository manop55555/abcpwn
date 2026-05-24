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

Each release archive ships with a `SHA256SUMS-linux-x86_64` file, a Sigstore (cosign)
keyless signature, and a CycloneDX SBOM; the build also publishes an
SLSA build-provenance attestation. Verify in increasing order of
assurance:

1. Checksum:

```bash
sha256sum -c SHA256SUMS-linux-x86_64 --ignore-missing
```

2. Cosign keyless signature (binds the archive to this repository's
   release workflow via Fulcio, transparency-logged to Rekor). Needs
   [cosign](https://github.com/sigstore/cosign):

```bash
cosign verify-blob \
  --certificate abcpwn-linux-x86_64.tar.gz.pem \
  --signature   abcpwn-linux-x86_64.tar.gz.sig \
  --certificate-identity-regexp '^https://github.com/manop55555/abcpwn/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  abcpwn-linux-x86_64.tar.gz
```

   The same command verifies the SBOM (`abcpwn-linux-x86_64-sbom.cdx.json`
   with its own `.sig` / `.pem`).

3. SLSA build provenance, via the GitHub CLI:

```bash
gh attestation verify abcpwn-linux-x86_64.tar.gz --repo manop55555/abcpwn
```

The CycloneDX SBOM (`abcpwn-linux-x86_64-sbom.cdx.json`) inventories the
statically bundled dependencies for supply-chain auditing.

## Verifying binary hardening

The release binary is built with the standard Linux exploit mitigations.
Confirm them on the extracted `abcpwn`:

```bash
file abcpwn | grep -o 'pie executable'               # PIE
readelf -d abcpwn | grep -E 'BIND_NOW|FLAGS_1.*NOW'  # full RELRO
readelf -l abcpwn | grep GNU_STACK                   # RW (not RWE) = NX stack
readelf -a abcpwn | grep -c __stack_chk_fail         # stack canary (> 0)
strings abcpwn | grep -c '_chk'                      # _FORTIFY_SOURCE (> 0)
```

PIE, full RELRO, a non-executable stack, the stack canary, and FORTIFY
are all present on the v0.1.0 binary. Intel CET marking is not yet
emitted (the vendored static libraries are built without it); it is
tracked for v0.2 in [docs/ROADMAP.md](docs/ROADMAP.md).

## Dependencies

abcpwn statically bundles its third-party C++ libraries, resolved
through the vcpkg manifest (`vcpkg.json`). The two that parse
attacker-controlled input -- and so dominate the attack surface -- are
**LIEF 0.17.6** (binary loading) and **Capstone 5.0.7** (disassembly).
CLI11, nlohmann/json, spdlog, and PicoSHA2 are also bundled; the exact
pinned version of every component is recorded in the per-release
CycloneDX SBOM.

Consult the upstream projects for CVE status. When a security advisory
affects a bundled component, the project will issue a patch release that
bumps the pin.

## Threat Model

See [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) for the full threat
model including the adversary capabilities considered, the mandatory
security rules every PR must satisfy, the static analysis suite, and the
fuzzing strategy.
