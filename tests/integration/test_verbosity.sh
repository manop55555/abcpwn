#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Regression test for verbosity flags (DEF-18). -q/-v/-vv were accepted
# but inert: -q did not suppress the banner or the timing footer, and
# -v/-vv produced no observable output. Now -q suppresses the chrome and
# -v emits a debug dispatch line.
#
# Usage: test_verbosity.sh <abcpwn-binary>

set -euo pipefail

ABCPWN_BIN="${1:?abcpwn binary path required}"
[ -x "$ABCPWN_BIN" ] || { echo "[-] $ABCPWN_BIN not executable" >&2; exit 1; }

# -q: stderr must be empty (no banner header, no "(N ms)" footer).
q_err=$("$ABCPWN_BIN" -q cyclic 8 2>&1 >/dev/null || true)
[ -z "$q_err" ] || { echo "[-] -q still emits chrome on stderr: $q_err"; exit 1; }

# -q: stdout still carries the data (cyclic 8 is deterministic).
q_out=$("$ABCPWN_BIN" -q cyclic 8 2>/dev/null || true)
[ "$q_out" = "aaaabaaa" ] || { echo "[-] -q stdout = '$q_out', expected 'aaaabaaa'"; exit 1; }

# default: the banner is present on stderr (control case).
d_err=$("$ABCPWN_BIN" cyclic 8 2>&1 >/dev/null || true)
printf '%s' "$d_err" | grep -q "abcpwn" \
    || { echo "[-] default run lost the banner on stderr"; exit 1; }

# -v: a debug dispatch line appears on stderr.
v_err=$("$ABCPWN_BIN" -v cyclic 8 2>&1 >/dev/null || true)
printf '%s' "$v_err" | grep -qiE "debug|completed" \
    || { echo "[-] -v produced no debug line on stderr: $v_err"; exit 1; }

echo "[+] verbosity OK: -q suppresses chrome, -v emits a debug line"
