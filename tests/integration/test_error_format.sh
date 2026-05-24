#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Regression test for the error-formatter standardization (DEF-1) and
# the rop missing-gadget exit code (DEF-19 cross-tier note).
#   - The dispatcher owns a single "[-] <cmd>: " prefix; a command that
#     self-prefixed its message must NOT produce a doubled command name
#     (was "[-] pack: pack: ...").
#   - rop "cannot build chain, missing gadgets" is not NotFound (7) --
#     the args were valid, the target just lacks the gadgets.
#
# Usage: test_error_format.sh <abcpwn-binary>

set -euo pipefail

ABCPWN_BIN="${1:?abcpwn binary path required}"
[ -x "$ABCPWN_BIN" ] || { echo "[-] $ABCPWN_BIN not executable" >&2; exit 1; }

# Assert a doubled-name substring is absent from a command's error.
assert_no_double() {
    local doubled="$1"; shift
    local out
    out="$("$ABCPWN_BIN" --no-banner "$@" 2>&1 </dev/null || true)"
    if printf '%s' "$out" | grep -qF "$doubled"; then
        echo "[-] doubled prefix '$doubled' present for: $*"
        echo "    got: $out"
        exit 1
    fi
}

assert_no_double "pack: pack:"       pack 1234 -w 3
assert_no_double "heap: heap:"       heap bogus
assert_no_double "rop: rop:"         rop /bin/ls --syscall 59 --syscall-arg 1
assert_no_double "seccomp: seccomp"  seccomp dump /bin/true

# The single prefix and the message itself must survive the strip.
pack_err="$("$ABCPWN_BIN" --no-banner pack 1234 -w 3 2>&1 || true)"
printf '%s' "$pack_err" | grep -qF "[-] pack: width must be" \
    || { echo "[-] pack error lost its message after stripping: $pack_err"; exit 1; }

# A genuinely missing file is still NotFound (7) -- the strip/exit-code
# changes must not disturb the real filesystem case.
set +e
"$ABCPWN_BIN" --no-banner info /no/such/path >/dev/null 2>/dev/null
info_rc=$?
set -e
[ "$info_rc" -eq 7 ] || { echo "[-] info on missing file: expected 7, got $info_rc"; exit 1; }

# rop "missing gadgets" must NOT be NotFound (7). /bin/ls has no syscall
# gadget, so this exercises the missing-gadget path.
gtarget=""
for c in /bin/ls /usr/bin/ls /bin/true; do [ -x "$c" ] && gtarget="$c" && break; done
if [ -n "$gtarget" ]; then
    set +e
    "$ABCPWN_BIN" --no-banner rop "$gtarget" --syscall 59 \
        --syscall-arg 1 --syscall-arg 2 --syscall-arg 3 >/dev/null 2>/dev/null
    rop_rc=$?
    set -e
    if [ "$rop_rc" -eq 7 ]; then
        echo "[-] rop missing-gadget still returns NotFound (7); should be a non-NotFound code"
        exit 1
    fi
fi

# DEF-4: under --format json, failures emit a JSON error envelope on
# stdout (not plaintext on stderr), with the exit code preserved.
def4_err=$("$ABCPWN_BIN" --format json info /nonexistent 2>&1 1>/dev/null || true)
if [ -n "$def4_err" ]; then
    echo "[-] json-mode error leaked to stderr: $def4_err"; exit 1
fi
def4_out=$("$ABCPWN_BIN" --format json info /nonexistent 2>/dev/null || true)
printf '%s' "$def4_out" | grep -q '"error"' \
    || { echo "[-] no JSON error object on stdout: $def4_out"; exit 1; }
printf '%s' "$def4_out" | grep -q '"NotFound"' \
    || { echo "[-] JSON error missing name: $def4_out"; exit 1; }
if command -v jq >/dev/null 2>&1; then
    printf '%s' "$def4_out" \
        | jq -e '.error.code==7 and .command=="info" and .schema_version==1' >/dev/null \
        || { echo "[-] JSON error envelope shape wrong: $def4_out"; exit 1; }
fi
# Parse errors are JSON too (the Context is not built yet at parse time).
po=$("$ABCPWN_BIN" --format json pack notanumber 2>/dev/null || true)
printf '%s' "$po" | grep -q '"error"' \
    || { echo "[-] CLI parse error not emitted as JSON: $po"; exit 1; }

echo "[+] error format OK: single prefix, rop not NotFound, JSON errors on stdout"
