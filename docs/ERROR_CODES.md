# Error Codes

`abcpwn` exits with a small set of well-defined codes. The mapping is
declared in `include/abcpwn/core/error.hpp` and is part of the stable
CLI contract.

## Exit code table

| Exit | Name              | Meaning |
|------|-------------------|---------|
| 0    | Ok                | success |
| 1    | Generic           | unspecified runtime failure (legacy fallback; new code should pick a more specific value) |
| 2    | UsageError        | bad CLI arguments, unknown flag, missing required option |
| 3    | InternalError     | a bug in `abcpwn` itself; opens the door to a bug report |
| 4    | FeatureDisabled   | the requested feature was compiled out (e.g. `asm` without `ABCPWN_WITH_KEYSTONE`) |
| 5    | IoError           | generic I/O failure (read short, write failure, EIO) |
| 6    | PermissionDenied  | file present but not readable / writable |
| 7    | NotFound          | file or directory referenced by the command does not exist |
| 8    | InvalidInput      | input is well-formed but semantically invalid (bad offset, unknown arch name, out-of-range size) |
| 9    | SizeExceeded      | input exceeds the configured size cap (`ABCPWN_MAX_FILE_SIZE`, default 2 GB) |
| 10   | Unsupported       | input format / arch / platform combination is not supported in this build |
| 11   | Corrupted         | input failed structural validation (truncated header, bad magic, invalid section) |
| 12   | NetworkDisabled   | command needs network but `--allow-network` was not passed |
| 13   | NetworkError      | network request failed (DNS, TLS, HTTP status, body decode) |
| 14   | Cancelled         | the process received SIGINT and unwound cleanly |
| 15   | Timeout           | operation exceeded its time budget |
| 16   | NotImplemented    | a code path the maintainer marked TODO; treat as bug |

## Remediation hints

### 2 (UsageError)

Run `abcpwn <subcommand> --help` for the canonical option list. Help
text is the authoritative source for accepted flags; the docs may
lag. Internal CLI11 parse errors (the underlying library's own exit
codes -- RequiredError, ExtrasError, RequiresError, ...) are funneled
through exit 2 as well, so any parse-time failure surfaces as
UsageError rather than an undocumented number.

### 3 (InternalError)

This indicates a bug. Reproduce with the offending command line
and capture both stdout and stderr:

```bash
abcpwn <args> > out.txt 2> err.txt
```

then open an issue at https://github.com/manop55555/abcpwn/issues
with the log file. For a security-relevant crash, use
https://github.com/manop55555/abcpwn/security/advisories/new instead.

### 4 (FeatureDisabled)

The default Apache-2.0 build omits Keystone, libcurl, and Unicorn.
Rebuild from source with the appropriate CMake flag to enable the
feature in question:

- `-DABCPWN_WITH_KEYSTONE=ON` (preset: `release-with-keystone`) for
  assembly via the `asm` subcommand. The Keystone-linked build is a
  GPL-2 combined work; v0.1 does not distribute it as a release
  artifact.
- `-DABCPWN_WITH_NETWORK=ON` for `libc download` and `pwninit` fetch.
- `-DABCPWN_WITH_UNICORN=ON` (no current subcommand consumes this
  flag; reserved for future emulation work).

See [../BUILDING.md](../BUILDING.md) for the build prerequisites.

### 5 - 7 (file errors)

- `5` covers transient I/O.
- `6` means the file is present but file-system permissions block
  access. Check `ls -l` and `getfacl` on Linux, or quarantine
  attributes (`xattr -l`) on macOS.
- `7` means the path does not resolve. The error message includes
  the canonicalized path so symlink chains are visible.

### 8 (InvalidInput)

The flag value did not validate. Common cases:

- `--arch` passed an unknown architecture name.
- `--offset` is non-numeric or out of file bounds.
- `--max-len` is zero or larger than the gadget length limit.

### 9 (SizeExceeded)

Override the default cap if the binary is genuinely large and
trusted:

```bash
ABCPWN_MAX_FILE_SIZE=$((4*1024*1024*1024)) abcpwn info ./huge
```

Default is 2 GB. The cap exists to bound memory use when parsing
attacker-controlled inputs.

### 10 (Unsupported)

The combination of format, arch, and feature flag is not implemented
in this build. Check the support matrix in
[COMMANDS.md](COMMANDS.md) for the subcommand. Most commands cover
x86, x86_64, aarch64; some lag for mips, ppc, riscv.

### 11 (Corrupted)

The parser rejected the input. This is expected for hand-crafted
malformed binaries used in CTF challenges. The error message
includes the byte offset where validation failed.

If you believe the input is valid (e.g. produced by a real toolchain
and accepted by other tools), open an issue with the binary
attached so the parser can be improved.

### 12 (NetworkDisabled)

Pass the global `--allow-network` flag explicitly:

```bash
abcpwn --allow-network libc id --offset puts:0x80
abcpwn --allow-network pwninit ./challenge
```

Network is opt-in to make offline use the default.

### 13 (NetworkError)

The destination did not respond, or the response did not parse.
Check connectivity, retry once, and if it persists check the upstream
(libc.rip for `libc download`, GitHub Releases for the libc that
`pwninit` resolves).

### 14 (Cancelled)

You pressed Ctrl-C. The exit code distinguishes user-cancelled from
genuine failure for scripts:

```bash
if abcpwn rop ./bin --execve; then
    echo success
elif [ $? -eq 14 ]; then
    echo "cancelled by user"
else
    echo "failed"
fi
```

### 15 (Timeout)

Operation hit its time budget (configurable per command). Increase
with `--timeout` where supported, or narrow the input.

### 16 (NotImplemented)

A code path the maintainer flagged as future work. Treat the same as
`InternalError` for reporting purposes; an issue with the exact
invocation helps prioritize.

## Stability contract

These exit codes are covered by semver per
[../CHANGELOG.md](../CHANGELOG.md):

- Adding a new code: MINOR bump.
- Changing the meaning of an existing code: MAJOR bump (breaking).
- Removing a code: MAJOR bump (breaking).

Scripts that branch on exit codes can rely on the values above for
the duration of the v0.1.x line.
