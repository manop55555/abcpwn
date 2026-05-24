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

# 3. N3: the compact header, the --version detail line, and the JSON
#    abcpwn_version field must all report the SAME version string. They
#    previously disagreed (banner v0.1.0 vs detail v0.1.0-alpha.4 vs JSON
#    0.1.0); all three now derive from the build-time SemVer.
detail_ver=$("$ABCPWN_BIN" --no-banner --version 2>&1 \
    | sed -n 's/^abcpwn v\([0-9][^ ]*\).*/\1/p' | head -1)
if [ -z "$detail_ver" ]; then
    echo "[-] could not parse the version from --version"
    exit 1
fi
header_line=$("$ABCPWN_BIN" --version 2>&1 | head -1)
if ! echo "$header_line" | grep -qF "v${detail_ver} "; then
    echo "[-] compact header disagrees with --version detail ($detail_ver)"
    echo "    header: $header_line"
    exit 1
fi
json_ver=$("$ABCPWN_BIN" --format json cyclic 8 2>/dev/null \
    | tr ',' '\n' | sed -n 's/.*"abcpwn_version"[ :]*"\([^"]*\)".*/\1/p' | head -1)
if [ "$json_ver" != "$detail_ver" ]; then
    echo "[-] JSON abcpwn_version ($json_ver) disagrees with --version ($detail_ver)"
    exit 1
fi

echo "[+] --version OK: semver visible, --no-banner suppresses header, surfaces agree"
