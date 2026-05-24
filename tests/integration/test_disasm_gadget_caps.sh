#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Regression test for the silent-truncation findings (verification #17
# and N1). gadget and disasm previously stopped at a default cap and
# either said nothing on stderr (disasm) or only noted it on stdout
# (gadget), so a run whose stdout was redirected to a file silently
# produced a partial result. Assert (a) the documented defaults were
# raised and (b) when a cap IS hit, a warning reaches STDERR so it
# survives stdout redirection.
#
# Usage: test_disasm_gadget_caps.sh <abcpwn-binary>

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "[-] usage: $0 <abcpwn-binary>" >&2
    exit 2
fi
ABCPWN_BIN="$1"
[ -x "$ABCPWN_BIN" ] || { echo "[-] $ABCPWN_BIN not executable" >&2; exit 1; }

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# --- #17 gadget -----------------------------------------------------------
# Default cap raised 200000 -> 1000000 so a typical libc is no longer
# silently truncated by default. The help text is the documented surface.
if ! "$ABCPWN_BIN" gadget --help 2>&1 | grep -q "1000000"; then
    echo "[-] gadget --help does not advertise the raised 1000000 default"
    exit 1
fi

# Pick a small, always-present ELF with executable sections.
gtarget=""
for c in /bin/ls /usr/bin/ls /bin/true /usr/bin/true "$ABCPWN_BIN"; do
    [ -x "$c" ] && gtarget="$c" && break
done
[ -n "$gtarget" ] || { echo "[-] no ELF target available for gadget test"; exit 1; }

# Force truncation with --max-results 1 and confirm the warning lands on
# STDERR (the bug: it only appeared on stdout, invisible under redirect).
gerr="$("$ABCPWN_BIN" --no-banner gadget "$gtarget" --max-results 1 --no-progress 2>&1 1>/dev/null || true)"
if ! printf '%s' "$gerr" | grep -qi "truncat"; then
    echo "[-] gadget truncation warning did not reach stderr"
    echo "    stderr was: $gerr"
    exit 1
fi

# --- N1 disasm ------------------------------------------------------------
# Default instruction cap raised to 1000000; documented on --count.
if ! "$ABCPWN_BIN" disasm --help 2>&1 | grep -q "1000000"; then
    echo "[-] disasm --count help does not advertise the raised default"
    exit 1
fi

# A file larger than the 1 MiB byte cap must warn on stderr (was silent).
# Random content keeps the decode short (disasm stops at the first
# undecodable byte); the byte-cap warning fires regardless of decode.
bigfile="$tmpdir/over_cap.bin"
head -c $((1024 * 1024 + 4096)) /dev/urandom > "$bigfile"
derr="$("$ABCPWN_BIN" --no-banner disasm "$bigfile" --input-file --arch x86_64 2>&1 1>/dev/null || true)"
if ! printf '%s' "$derr" | grep -qi "truncat"; then
    echo "[-] disasm byte-cap warning did not reach stderr"
    echo "    stderr was: $derr"
    exit 1
fi

# DEF-17: the disasm time budget is reachable and surfaces Timeout (15).
# ABCPWN_DISASM_TIMEOUT_MS=0 forces the post-decode deadline check to fire
# (the default 30s budget is otherwise unreachable under the byte cap).
set +e
ABCPWN_DISASM_TIMEOUT_MS=0 "$ABCPWN_BIN" --no-banner disasm 9090c3 --arch x86_64 \
    >/dev/null 2>/dev/null
to_rc=$?
set -e
if [ "$to_rc" -ne 15 ]; then
    echo "[-] ABCPWN_DISASM_TIMEOUT_MS=0 did not yield Timeout (15); got $to_rc"
    exit 1
fi

echo "[+] caps OK: raised defaults, truncation warns on stderr, Timeout reachable"
