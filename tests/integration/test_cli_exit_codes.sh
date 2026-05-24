#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Verifies CLI11's internal exit codes (104 RequiredError, 106
# ExtrasError, 109 RequiresError, ...) are translated to exit 2
# (UsageError) at the top-level catch, matching docs/ERROR_CODES.md.
# Operators must not see undocumented exit codes from parse failures.

set -euo pipefail

ABCPWN_BIN="${1:?abcpwn binary path required}"

# Missing required positional -> CLI11 RequiredError (104) -> exit 2.
set +e
"$ABCPWN_BIN" --no-banner info >/dev/null 2>&1
rc=$?
set -e
if [ "$rc" -ne 2 ]; then
    echo "[-] missing required positional: expected exit 2, got $rc" >&2
    exit 1
fi

# Unknown subcommand -> CLI11 ExtrasError (106) -> exit 2.
set +e
"$ABCPWN_BIN" --no-banner nonesuchsubcommand >/dev/null 2>&1
rc=$?
set -e
if [ "$rc" -ne 2 ]; then
    echo "[-] unknown subcommand: expected exit 2, got $rc" >&2
    exit 1
fi

# Unknown global flag -> CLI11 ExtrasError (106) -> exit 2.
set +e
"$ABCPWN_BIN" --no-such-flag info /bin/ls >/dev/null 2>&1
rc=$?
set -e
if [ "$rc" -ne 2 ]; then
    echo "[-] unknown global flag: expected exit 2, got $rc" >&2
    exit 1
fi

# --help still exits 0.
set +e
"$ABCPWN_BIN" --help >/dev/null 2>&1
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
    echo "[-] --help: expected exit 0, got $rc" >&2
    exit 1
fi

echo "[+] test_cli_exit_codes ok"
