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

# DEF-13: phd and disasm --input-file must honor the cap too -- they
# previously read files of any size with rc=0, bypassing the documented
# safety cap. /bin/ls is well over 1024 bytes.
export ABCPWN_MAX_FILE_SIZE=1024
for spec in "phd /bin/ls" "disasm /bin/ls --input-file"; do
    set +e
    # shellcheck disable=SC2086
    "$ABCPWN_BIN" --no-banner $spec >/dev/null 2>err
    rc=$?
    set -e
    if [ "$rc" -ne 9 ]; then
        echo "[-] '$spec' with cap 1024: expected SizeExceeded (9), got $rc" >&2
        cat err >&2
        exit 1
    fi
done

# DEF-20: an invalid ABCPWN_MAX_FILE_SIZE warns (was silently ignored)
# and keeps the default cap. A leading "-" must not wrap to a huge value
# that disables the cap (strtoull would turn "-1" into ULLONG_MAX).
for bad in abc 0 -1 1024.5; do
    export ABCPWN_MAX_FILE_SIZE="$bad"
    warn=$("$ABCPWN_BIN" --no-banner cyclic 4 2>&1 >/dev/null || true)
    if ! printf '%s' "$warn" | grep -qiE "not a positive integer|keeping the default"; then
        echo "[-] ABCPWN_MAX_FILE_SIZE=$bad did not warn; got: $warn" >&2
        exit 1
    fi
done
# "-1" must still enforce the cap on a large file (not disable it).
export ABCPWN_MAX_FILE_SIZE=-1
set +e
"$ABCPWN_BIN" --no-banner hash /bin/ls >/dev/null 2>/dev/null
rc=$?
set -e
[ "$rc" -eq 0 ] || { echo "[-] ABCPWN_MAX_FILE_SIZE=-1 broke a normal hash (rc=$rc)" >&2; exit 1; }
unset ABCPWN_MAX_FILE_SIZE

echo "[+] test_max_file_size ok"
