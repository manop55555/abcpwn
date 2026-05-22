#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Verify a downloaded release artifact: SHA-256 against SHA256SUMS,
# optional sigstore cosign signature verification when --cosign is
# passed and cosign is installed.
#
# Usage: verify-release.sh <artifact.tar.gz> [<artifact.tar.gz> ...]
# Env:
#   ABCPWN_RELEASE_DIR  Directory holding SHA256SUMS, .sig, .cert
#                       (defaults to the artifact's directory)

set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "[-] usage: $0 <artifact.tar.gz> [more...]" >&2
    exit 2
fi

failed=0
for artifact in "$@"; do
    if [ ! -f "$artifact" ]; then
        echo "[-] not a file: $artifact"
        failed=1
        continue
    fi
    dir="${ABCPWN_RELEASE_DIR:-$(dirname "$artifact")}"
    base="$(basename "$artifact")"

    if [ ! -f "$dir/SHA256SUMS" ]; then
        echo "[-] missing $dir/SHA256SUMS"
        failed=1
        continue
    fi
    actual=$(sha256sum "$artifact" | awk '{print $1}')
    expected=$(awk -v b="$base" '$2 == b || $2 == "*"b {print $1}' "$dir/SHA256SUMS" | head -1)
    if [ -z "$expected" ]; then
        echo "[-] no SHA256 line for $base"
        failed=1
        continue
    fi
    if [ "$actual" != "$expected" ]; then
        echo "[-] SHA mismatch for $base: $actual != $expected"
        failed=1
        continue
    fi
    echo "[+] sha256 ok: $base"

    # Optional cosign verification.
    if [ "${1:-}" = "--cosign" ] && command -v cosign > /dev/null; then
        sig="$dir/${base}.sig"
        cert="$dir/${base}.cert"
        if [ ! -f "$sig" ] || [ ! -f "$cert" ]; then
            echo "[!] no cosign artifacts for $base; skipping"
            continue
        fi
        cosign verify-blob \
            --certificate "$cert" \
            --signature   "$sig" \
            --certificate-identity-regexp "^https://github.com/manop55555/abcpwn" \
            --certificate-oidc-issuer     "https://token.actions.githubusercontent.com" \
            "$artifact" \
            && echo "[+] cosign ok: $base"
    fi
done

if [ "$failed" -ne 0 ]; then
    exit 1
fi

echo "[+] all artifacts verified"
