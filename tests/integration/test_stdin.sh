#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Regression test for stdin support (DEF-16). File-path subcommands now
# accept "-" to read the target from standard input; previously "-" was
# a literal path (info - -> rc=7). Implemented once in safe_io::read_file
# so every file-loading command gains it.
#
# Usage: test_stdin.sh <abcpwn-binary>

set -euo pipefail

ABCPWN_BIN="${1:?abcpwn binary path required}"
[ -x "$ABCPWN_BIN" ] || { echo "[-] $ABCPWN_BIN not executable" >&2; exit 1; }

gtarget=""
for c in /bin/ls /usr/bin/ls /bin/true; do [ -x "$c" ] && gtarget="$c" && break; done
[ -n "$gtarget" ] || { echo "[-] no ELF target available"; exit 1; }

# hash via stdin must byte-for-byte equal the hash of the file (proves a
# binary-safe stdin read).
h_file=$("$ABCPWN_BIN" --no-banner hash "$gtarget" 2>/dev/null | awk '{print $1}')
h_stdin=$("$ABCPWN_BIN" --no-banner hash - <"$gtarget" 2>/dev/null | awk '{print $1}')
[ -n "$h_file" ] || { echo "[-] hash of file produced no digest"; exit 1; }
[ "$h_file" = "$h_stdin" ] || { echo "[-] hash via stdin ($h_stdin) != file ($h_file)"; exit 1; }

# info via stdin analyses a valid binary (exit 0).
set +e
"$ABCPWN_BIN" --no-banner info - <"$gtarget" >/dev/null 2>/dev/null
rc=$?
set -e
[ "$rc" -eq 0 ] || { echo "[-] info - on a valid binary exited $rc"; exit 1; }

# Empty stdin is handled gracefully (non-zero, no hang).
set +e
"$ABCPWN_BIN" --no-banner info - </dev/null >/dev/null 2>/dev/null
rc=$?
set -e
[ "$rc" -ne 0 ] || { echo "[-] info - on empty stdin unexpectedly succeeded"; exit 1; }

# disasm reads bytes from stdin too.
out=$(printf '\x90\xc3' | "$ABCPWN_BIN" --no-banner disasm - --input-file --arch x86_64 2>/dev/null)
printf '%s' "$out" | grep -qi "nop" \
    || { echo "[-] disasm via stdin did not decode nop: $out"; exit 1; }

echo "[+] stdin OK: '-' reads from stdin for hash/info/disasm; empty stdin handled"
