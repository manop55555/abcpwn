#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Verifies ABCPWN_MAX_FILE_SIZE is honored by binary-loading subcommands.
# Without the cap, `info /bin/ls` succeeds. With a 1-byte cap the same
# call must refuse with SizeExceeded (exit code 9 per docs/ERROR_CODES).

set -euo pipefail

ABCPWN_BIN="${1:?abcpwn binary path required}"

if [ ! -x "$ABCPWN_BIN" ]; then
    echo "[-] abcpwn not executable: $ABCPWN_BIN" >&2
    exit 1
fi

# Baseline: env unset; info /bin/ls should succeed.
unset ABCPWN_MAX_FILE_SIZE
if ! "$ABCPWN_BIN" --no-banner info /bin/ls >/dev/null 2>&1; then
    echo "[-] baseline info /bin/ls failed; bad fixture" >&2
    exit 1
fi

# Cap at 1 byte; /bin/ls is well over a byte, so the cap must trigger.
export ABCPWN_MAX_FILE_SIZE=1
set +e
"$ABCPWN_BIN" --no-banner info /bin/ls >/dev/null 2>err
rc=$?
set -e

if [ "$rc" -eq 0 ]; then
    echo "[-] expected non-zero exit with ABCPWN_MAX_FILE_SIZE=1, got 0" >&2
    cat err >&2
    exit 1
fi

if ! grep -qE 'too large|SizeExceeded|exceeds|size' err; then
    echo "[-] expected size-cap message on stderr; got:" >&2
    cat err >&2
    exit 1
fi

# Invalid value must not disable the default cap; baseline still passes
# (the default 2 GB cap is larger than /bin/ls so the call succeeds).
export ABCPWN_MAX_FILE_SIZE=garbage
if ! "$ABCPWN_BIN" --no-banner info /bin/ls >/dev/null 2>&1; then
    echo "[-] invalid ABCPWN_MAX_FILE_SIZE should leave default in place" >&2
    exit 1
fi

# Empty value: same as unset (no override).
export ABCPWN_MAX_FILE_SIZE=
if ! "$ABCPWN_BIN" --no-banner info /bin/ls >/dev/null 2>&1; then
    echo "[-] empty ABCPWN_MAX_FILE_SIZE should leave default in place" >&2
    exit 1
fi

# Zero value: parse succeeds but v == 0 means leave default in place.
export ABCPWN_MAX_FILE_SIZE=0
if ! "$ABCPWN_BIN" --no-banner info /bin/ls >/dev/null 2>&1; then
    echo "[-] ABCPWN_MAX_FILE_SIZE=0 should leave default in place" >&2
    exit 1
fi

echo "[+] test_max_file_size ok"
