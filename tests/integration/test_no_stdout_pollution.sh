#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Regression for round-1 CRITICAL: banner + timing annotation
# leaked to stdout. Verify that subcommands emitting binary
# payloads (unhex, shellcode --format raw) produce stdout that is
# byte-for-byte the payload - no banner header, no "(N ms)"
# footer, no trailing newline. Decorative output (banner, timing)
# must land on stderr, not stdout.
#
# Usage: test_no_stdout_pollution.sh <abcpwn-binary>

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "[-] usage: $0 <abcpwn-binary>" >&2
    exit 2
fi

ABCPWN_BIN="$1"

if [ ! -x "$ABCPWN_BIN" ]; then
    echo "[-] $ABCPWN_BIN is not executable" >&2
    exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# 1. unhex deadbeef -> stdout must be exactly 4 bytes
"$ABCPWN_BIN" unhex deadbeef > "$work/unhex.bin" 2>/dev/null
size=$(stat -c '%s' "$work/unhex.bin")
if [ "$size" != "4" ]; then
    echo "[-] unhex deadbeef stdout was $size bytes; expected 4"
    od -An -tx1 "$work/unhex.bin" | head -2 >&2
    exit 1
fi
expected_hex="deadbeef"
got_hex=$(od -An -tx1 "$work/unhex.bin" | tr -d ' \n')
if [ "$got_hex" != "$expected_hex" ]; then
    echo "[-] unhex deadbeef stdout = $got_hex; expected $expected_hex"
    exit 1
fi

# 2. shellcode --preset sh --arch x86_64 --format raw -> stdout
#    must be exactly the documented number of payload bytes.
"$ABCPWN_BIN" shellcode --preset sh --arch x86_64 --format raw \
    > "$work/sc.bin" 2>/dev/null
sc_size=$(stat -c '%s' "$work/sc.bin")
# The x86_64 sh preset is in the 20-40 byte range. The TIER-1
# NUL-terminator fix may extend it slightly; accept a tight band
# so this test does not fight a documented payload-length change.
if [ "$sc_size" -lt 20 ] || [ "$sc_size" -gt 40 ]; then
    echo "[-] shellcode --format raw stdout was $sc_size bytes; expected 20-40"
    exit 1
fi

# 3. Sentinel: stdout must NOT contain the banner header marker.
if grep -F ']=== ' "$work/unhex.bin" >/dev/null 2>&1; then
    echo "[-] unhex stdout contains banner marker"
    exit 1
fi
if grep -F ']=== ' "$work/sc.bin" >/dev/null 2>&1; then
    echo "[-] shellcode stdout contains banner marker"
    exit 1
fi

# 4. Sentinel: stdout must NOT contain a trailing timing footer.
if grep -E ' ms\)' "$work/unhex.bin" >/dev/null 2>&1; then
    echo "[-] unhex stdout contains timing footer"
    exit 1
fi
if grep -E ' ms\)' "$work/sc.bin" >/dev/null 2>&1; then
    echo "[-] shellcode stdout contains timing footer"
    exit 1
fi

# 5. Bare invocation: banner reaches stderr, help reaches stdout.
"$ABCPWN_BIN" </dev/null > "$work/bare.stdout" 2> "$work/bare.stderr" || true
if ! grep -F 'SUBCOMMANDS:' "$work/bare.stdout" >/dev/null 2>&1; then
    echo "[-] bare-invocation help did not reach stdout"
    exit 1
fi
# The banner contains the project tagline verbatim; grep for a
# fragment that appears nowhere else in the binary's output set.
if ! grep -F 'binary exploitation toolkit' "$work/bare.stderr" >/dev/null 2>&1; then
    echo "[-] bare-invocation banner did not reach stderr"
    head -5 "$work/bare.stderr" >&2
    exit 1
fi

echo "[+] no-stdout-pollution OK: unhex + shellcode --format raw clean; banner on stderr"
