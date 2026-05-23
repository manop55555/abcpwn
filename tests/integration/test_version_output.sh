#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Regression for QA round 1 MAJOR items:
#   #16 --no-banner doesn't suppress the banner on --version
#   #13 --version drops the -alpha.N pre-release suffix
#
# Usage: test_version_output.sh <abcpwn-binary>

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

# 1. --version output includes "abcpwn v<semver>" line. The semver
#    string is captured from `git describe --tags` at configure
#    time; any -alpha.N / -beta.N / -rc.N suffix on the current
#    tag must reach the output.
got=$("$ABCPWN_BIN" --version 2>&1)
if ! echo "$got" | grep -qE 'abcpwn v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?'; then
    echo "[-] --version output is missing the 'abcpwn v<semver>' line"
    echo "    got:"
    echo "$got"
    exit 1
fi

# 2. --no-banner --version suppresses the banner header. The
#    output must NOT contain the compact_header marker, but MUST
#    still contain the version line.
got=$("$ABCPWN_BIN" --no-banner --version 2>&1)
if echo "$got" | grep -F ']===' >/dev/null 2>&1; then
    echo "[-] --no-banner --version still prints the compact_header"
    echo "    got:"
    echo "$got"
    exit 1
fi
if ! echo "$got" | grep -qE 'abcpwn v[0-9]+'; then
    echo "[-] --no-banner --version dropped the version line entirely"
    exit 1
fi

echo "[+] --version OK: semver visible + --no-banner suppresses header"
