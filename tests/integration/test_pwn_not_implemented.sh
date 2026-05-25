#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Regression for DEF-4: `pwn` is a placeholder in v0.1.0. Every target form
# must exit NotImplemented (16) with no fake "plan" output and without
# opening a socket -- it must not pretend to work.
#
# Usage: test_pwn_not_implemented.sh <abcpwn-binary>

set -uo pipefail

ABCPWN_BIN="${1:?abcpwn binary path required}"
[ -x "$ABCPWN_BIN" ] || { echo "[-] $ABCPWN_BIN not executable" >&2; exit 1; }

bad=0
for target in "127.0.0.1:1337" "unix:/tmp/abcpwn-nope.sock" "./abcpwn-nonexistent" "/bin/ls"; do
    set +e
    out=$("$ABCPWN_BIN" --no-banner pwn "$target" 2>&1)
    rc=$?
    set -e
    if [ "$rc" -ne 16 ]; then
        echo "[-] pwn '$target': expected exit 16 (NotImplemented), got $rc" >&2
        echo "$out" >&2
        bad=1
    fi
    if echo "$out" | grep -qiE 'plan|connected|recvuntil|sendline|recvline'; then
        echo "[-] pwn '$target' emitted plan-like / success output: $out" >&2
        bad=1
    fi
done

# The message must state it is not implemented (not a vague error).
out=$("$ABCPWN_BIN" --no-banner pwn 127.0.0.1:1337 2>&1 || true)
echo "$out" | grep -qiE 'not implemented' \
    || { echo "[-] pwn message should say 'not implemented': $out" >&2; bad=1; }

# Best-effort: confirm no connect() to the target (skip if strace is
# unavailable or ptrace is restricted in the environment).
if command -v strace > /dev/null 2>&1; then
    net=$(strace -f -e trace=network "$ABCPWN_BIN" --no-banner pwn 127.0.0.1:1337 2>&1 || true)
    if echo "$net" | grep -qE 'connect\([^)]*127\.0\.0\.1'; then
        echo "[-] pwn opened a connection despite NotImplemented:" >&2
        echo "$net" | grep connect >&2
        bad=1
    fi
fi

[ "$bad" -eq 0 ] || exit 1
echo "[+] pwn NotImplemented OK: all target forms exit 16, no plan output, no connect"
