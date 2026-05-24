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

# -f short alias for --format works identically apart from the
# command_line echo in the JSON envelope (which captures argv
# verbatim and therefore differs between --format and -f).
out_long=$("$ABCPWN_BIN" --no-banner --format json errno 13 2>&1)
out_short=$("$ABCPWN_BIN" --no-banner -f json errno 13 2>&1)
# Strip the args.command_line line before comparing structural output.
strip=$(printf '%s\n' "$out_long" | grep -v 'command_line')
strip2=$(printf '%s\n' "$out_short" | grep -v 'command_line')
if [ "$strip" != "$strip2" ]; then
    echo "[-] -f and --format produced different output:" >&2
    printf '  --format:\n%s\n' "$out_long" >&2
    printf '  -f:\n%s\n' "$out_short" >&2
    exit 1
fi

# JSON args.command_line echoes the full invocation (TIER 4 #37).
echo "$out_long" | grep -q '"command_line"' || {
    echo "[-] --format json args block missing command_line key" >&2
    echo "$out_long" >&2
    exit 1
}
echo "$out_long" | grep -q 'errno 13' || {
    echo "[-] command_line did not echo the actual argv" >&2
    echo "$out_long" >&2
    exit 1
}

echo "[+] test_cli_exit_codes ok"
