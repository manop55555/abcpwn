#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Regression test for IMP-5: every ```bash block in docs/TUTORIALS.md
# must actually run and exit 0, so the tutorials stay copy-pasteable.
# This catches the kind of rot the tutorials had before -- references to
# removed flags (syms --type, cyclic --search), unimplemented presets
# (shellcode read-flag, seccomp emu), and fixtures that never shipped.
#
# Usage: test_tutorial_walkthrough.sh <abcpwn-binary> <source-root>

set -uo pipefail

ABCPWN_BIN="${1:?abcpwn binary path required}"
SOURCE_ROOT="${2:?source root required}"
TUT="$SOURCE_ROOT/docs/TUTORIALS.md"
[ -x "$ABCPWN_BIN" ] || { echo "[-] $ABCPWN_BIN not executable" >&2; exit 1; }
[ -f "$TUT" ] || { echo "[-] $TUT not found" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# Make `abcpwn` (as written in the tutorials) resolve to the binary
# under test, and run from a scratch directory.
ln -s "$ABCPWN_BIN" "$tmp/abcpwn"
export PATH="$tmp:$PATH"
cd "$tmp"

fail=0
n=0
in_block=0
block=""
while IFS= read -r line || [ -n "$line" ]; do
    if [ "$in_block" -eq 0 ] && [ "$line" = '```bash' ]; then
        in_block=1
        block=""
        continue
    fi
    if [ "$in_block" -eq 1 ] && [ "$line" = '```' ]; then
        n=$((n + 1))
        bash -c "set -e
$block" >/dev/null 2>"$tmp/err"
        rc=$?
        if [ "$rc" -ne 0 ]; then
            echo "[-] TUTORIALS.md bash block #$n exited $rc:"
            printf '%s\n' "$block"
            echo "--- stderr ---"
            cat "$tmp/err"
            fail=1
        fi
        in_block=0
        continue
    fi
    if [ "$in_block" -eq 1 ]; then
        block="$block$line"$'\n'
    fi
done < "$TUT"

if [ "$n" -lt 8 ]; then
    echo "[-] only $n bash blocks found in TUTORIALS.md; extraction likely broke" >&2
    exit 1
fi
[ "$fail" -eq 0 ] || exit 1
echo "[+] tutorial walkthrough OK: all $n bash blocks exit 0"
