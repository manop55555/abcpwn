#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Regression for DEF-9: documented exit codes must match actual behavior.
#   disasm --arch <unknown> -> 8  (InvalidInput: unknown arch name)
#   rop <no satisfiable chain> -> 10 (Unsupported), never 7 (NotFound)
#   <missing path> -> 7 (NotFound) -- 7 is reserved for a genuinely absent file
# See docs/ERROR_CODES.md.
#
# Usage: test_exit_codes.sh <abcpwn-binary>

set -euo pipefail

ABCPWN_BIN="${1:?abcpwn binary path required}"
[ -x "$ABCPWN_BIN" ] || { echo "[-] $ABCPWN_BIN not executable" >&2; exit 1; }

rc_of() {
    set +e
    "$ABCPWN_BIN" --no-banner "$@" >/dev/null 2>&1
    local rc=$?
    set -e
    echo "$rc"
}

# DEF-9a: an unknown --arch name is InvalidInput (8), not Unsupported (10).
rc=$(rc_of disasm 9090 --arch bogus)
[ "$rc" -eq 8 ] || { echo "[-] disasm --arch bogus: expected 8 (InvalidInput), got $rc" >&2; exit 1; }

# DEF-9b: a target that parses but yields no satisfiable chain is Unsupported
# (10) -- and must never be NotFound (7), which is reserved for a missing path.
# (/bin/ls may or may not expose a usable chain; the contract is "not 7".)
rc=$(rc_of rop /bin/ls --syscall 59 --syscall-arg 0 --syscall-arg 0 --syscall-arg 0)
[ "$rc" -ne 7 ] || { echo "[-] rop no-chain returned 7 (NotFound); should be 10 (Unsupported)" >&2; exit 1; }
{ [ "$rc" -eq 10 ] || [ "$rc" -eq 0 ]; } \
    || { echo "[-] rop no-chain: expected 10 (or 0 if a chain exists), got $rc" >&2; exit 1; }

# 7 (NotFound) is reserved for a genuinely missing path.
rc=$(rc_of rop /no/such/binary/abcpwn-test --syscall 59 --syscall-arg 0 --syscall-arg 0 --syscall-arg 0)
[ "$rc" -eq 7 ] || { echo "[-] rop on a missing path: expected 7 (NotFound), got $rc" >&2; exit 1; }

echo "[+] exit codes OK: disasm unknown-arch=8, rop no-chain=10 (not 7), missing-path=7"
