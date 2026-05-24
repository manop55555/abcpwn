#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Regression test for the cyclic OOM (DEF-7). A large --subseq-length
# used to materialize the full alphabet^subseq de Bruijn space
# regardless of the requested length: `cyclic 10 -n 7` allocated ~8 GB
# and was OOM-killed (rc=137). Generation is now lazy, and the --find
# search space is bounded with a SizeExceeded error.
#
# Usage: test_cyclic_limits.sh <abcpwn-binary>

set -euo pipefail

ABCPWN_BIN="${1:?abcpwn binary path required}"
[ -x "$ABCPWN_BIN" ] || { echo "[-] $ABCPWN_BIN not executable" >&2; exit 1; }

fail() { echo "[-] $1"; exit 1; }

# Generate path: a short pattern with a large subseq is instant and
# returns exactly the requested length (lazy generation, no OOM).
set +e
out=$(timeout 20 "$ABCPWN_BIN" --no-banner cyclic 10 -n 7 2>/dev/null)
rc=$?
set -e
[ "$rc" -eq 0 ] || fail "cyclic 10 -n 7 exited $rc (OOM/timeout/SIGKILL was the DEF-7 bug)"
[ "${#out}" -eq 10 ] || fail "cyclic 10 -n 7 produced ${#out} bytes, expected 10"

# A larger subseq must still not blow up.
set +e
timeout 20 "$ABCPWN_BIN" --no-banner cyclic 32 -n 8 >/dev/null 2>/dev/null
rc=$?
set -e
[ "$rc" -eq 0 ] || fail "cyclic 32 -n 8 exited $rc (should be instant)"

# Find path: an oversized alphabet^subseq returns SizeExceeded (9), not
# OOM (137) and not a misleading NotFound.
set +e
timeout 20 "$ABCPWN_BIN" --no-banner cyclic --find 0x6161616161616168 -n 7 >/dev/null 2>/dev/null
rc=$?
set -e
[ "$rc" -eq 9 ] || fail "cyclic --find -n 7 exited $rc, expected 9 (SizeExceeded)"

# Typical find still works and matches pwntools' little-endian offset.
set +e
off=$(timeout 20 "$ABCPWN_BIN" --no-banner cyclic --find 0x6161616a 2>/dev/null)
set -e
[ "$off" = "36" ] || fail "cyclic --find 0x6161616a returned '$off', expected 36"

echo "[+] cyclic limits OK: lazy generation, bounded --find search space"
