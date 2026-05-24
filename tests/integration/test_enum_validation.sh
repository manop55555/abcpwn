#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Regression test for enum-flag validation (DEF-6, DEF-8). Unknown
# values were silently accepted (rc=0), hiding typos:
#   - global --format / --color fell back to pretty/auto;
#   - gadget --type fell back to `ret`; template echoed strategy=<bogus>.
# Globals now reject with InvalidInput (8); command enums with
# UsageError (2), matching shellcode/heap/iofile.
#
# Usage: test_enum_validation.sh <abcpwn-binary>

set -euo pipefail

ABCPWN_BIN="${1:?abcpwn binary path required}"
[ -x "$ABCPWN_BIN" ] || { echo "[-] $ABCPWN_BIN not executable" >&2; exit 1; }

gtarget=""
for c in /bin/ls /usr/bin/ls /bin/true; do [ -x "$c" ] && gtarget="$c" && break; done
[ -n "$gtarget" ] || { echo "[-] no ELF target available"; exit 1; }

assert_exit() { # expected cmd...
    local exp="$1"; shift
    set +e
    "$ABCPWN_BIN" "$@" >/dev/null 2>/dev/null
    local rc=$?
    set -e
    [ "$rc" -eq "$exp" ] || { echo "[-] expected exit $exp, got $rc for: $*"; exit 1; }
}

# DEF-6: global enum flags reject unknown values with InvalidInput (8).
assert_exit 8 --format xml info "$gtarget"
assert_exit 8 --format JSON info "$gtarget"   # case-sensitive: JSON != json
assert_exit 8 --color bogus info "$gtarget"
# ... and the diagnostic names the bad value. Capture first: under
# `pipefail` the non-zero abcpwn exit would otherwise fail the pipe even
# when grep matches.
fmt_err="$("$ABCPWN_BIN" --format xml info "$gtarget" 2>&1 || true)"
printf '%s' "$fmt_err" | grep -qF "invalid format 'xml'" \
    || { echo "[-] --format xml diagnostic missing: $fmt_err"; exit 1; }

# Valid global values are unaffected.
assert_exit 0 --format json cyclic 8
assert_exit 0 --color never cyclic 8
assert_exit 0 --no-color cyclic 8

# DEF-8: command enums reject unknown values with UsageError (2).
assert_exit 2 --no-banner gadget "$gtarget" -t bogus
assert_exit 2 --no-banner template bogus "$gtarget"
gad_err="$("$ABCPWN_BIN" --no-banner gadget "$gtarget" -t bogus 2>&1 || true)"
printf '%s' "$gad_err" | grep -qF "unknown type 'bogus'" \
    || { echo "[-] gadget -t bogus diagnostic missing: $gad_err"; exit 1; }

# Valid command enum values still run (not rejected).
assert_exit 0 --no-banner --color never gadget "$gtarget" -t jmp
assert_exit 0 --no-banner template ret2libc "$gtarget"

echo "[+] enum validation OK: globals -> InvalidInput(8), command enums -> UsageError(2)"
