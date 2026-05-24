#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Regression test for --log-file (verification #20). The flag was
# documented in the man page and completions but rejected by the
# binary (exit 2). It now writes a JSON record of the run -- for both
# successful and failed commands -- to the given path.
#
# Usage: test_log_file.sh <abcpwn-binary>

set -euo pipefail

ABCPWN_BIN="${1:?abcpwn binary path required}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
logf="$tmp/run.json"

have_jq=0
command -v jq >/dev/null 2>&1 && have_jq=1

# 1. A successful run must ACCEPT --log-file (was exit 2) and write the
#    log. Use cyclic, which never touches the filesystem otherwise.
set +e
"$ABCPWN_BIN" --no-banner --log-file "$logf" cyclic 32 >/dev/null 2>&1
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
    echo "[-] --log-file run exited $rc (expected 0); flag still rejected?"
    exit 1
fi
[ -f "$logf" ] || { echo "[-] --log-file did not create $logf"; exit 1; }

if [ "$have_jq" -eq 1 ]; then
    if ! jq -e '.command=="cyclic" and .ok==true and .exit_code==0
                and (.command_line|contains("cyclic"))
                and (.duration_ms|type=="number")' "$logf" >/dev/null; then
        echo "[-] success log missing/incorrect fields:"; cat "$logf"; exit 1
    fi
else
    for key in '"command"' '"command_line"' '"exit_code"' '"ok"' '"duration_ms"'; do
        grep -q "$key" "$logf" || { echo "[-] log missing key $key"; cat "$logf"; exit 1; }
    done
fi

# 2. A failing run is logged too, with ok=false and a non-zero exit.
#    The file is rewritten each run (truncate), so it reflects the
#    error case after this invocation.
set +e
"$ABCPWN_BIN" --no-banner --log-file "$logf" info /definitely/not/here >/dev/null 2>&1
set -e
[ -f "$logf" ] || { echo "[-] error run did not write the log"; exit 1; }
if [ "$have_jq" -eq 1 ]; then
    if ! jq -e '.ok==false and .exit_code!=0 and (.error|type=="string")' "$logf" >/dev/null; then
        echo "[-] error log missing/incorrect fields:"; cat "$logf"; exit 1
    fi
else
    grep -q '"ok": *false' "$logf" || { echo "[-] error run not logged with ok=false"; cat "$logf"; exit 1; }
fi

echo "[+] log-file OK: JSON run-record written for success and error runs"
