#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# abcpwn one-liner installer (per STEP/17_DISTRIBUTION.md).
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/manop55555/abcpwn/main/scripts/install.sh | bash
# Options:
#   --prefix=PATH    Install prefix (default: $HOME/.local)
#   --version=VER    Specific version (default: latest)
#   --variant=NAME   apache (default) or full (with Keystone)
#   --no-verify      Skip checksum verification (NOT RECOMMENDED)

set -euo pipefail

REPO="manop55555/abcpwn"
PREFIX="$HOME/.local"
VERSION="latest"
VARIANT="apache"
VERIFY=1

for arg in "$@"; do
    case "$arg" in
        --prefix=*)  PREFIX="${arg#*=}" ;;
        --version=*) VERSION="${arg#*=}" ;;
        --variant=*) VARIANT="${arg#*=}" ;;
        --no-verify) VERIFY=0 ;;
        --help|-h)
            sed -n '2,15p' "$0" | sed 's/^# //;s/^#$//'
            exit 0
            ;;
        *)
            echo "[-] unknown argument: $arg" >&2
            exit 2
            ;;
    esac
done

# Detect OS and arch.
case "$(uname -s)" in
    Linux)  PLATFORM="linux"  ;;
    Darwin) PLATFORM="macos"  ;;
    *)      echo "[-] unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
    x86_64|amd64) ARCH="x86_64"  ;;
    aarch64|arm64) ARCH="arm64"  ;;
    *) echo "[-] unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac

if [ "$PLATFORM" = "macos" ] && [ "$ARCH" = "x86_64" ]; then
    ARCH="x86_64"   # macOS Intel uses the same suffix as Linux x86_64.
fi

case "$VARIANT" in
    apache) NAME_PREFIX="abcpwn" ;;
    full)   NAME_PREFIX="abcpwn-full" ;;
    *) echo "[-] unknown variant: $VARIANT (apache | full)" >&2; exit 1 ;;
esac

# Determine version.
if [ "$VERSION" = "latest" ]; then
    VERSION=$(curl -sSL "https://api.github.com/repos/$REPO/releases/latest" \
        | grep -o '"tag_name": *"[^"]*"' \
        | head -1 \
        | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    if [ -z "$VERSION" ]; then
        echo "[-] could not determine latest version" >&2
        exit 1
    fi
fi

ARTIFACT="${NAME_PREFIX}-${PLATFORM}-${ARCH}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "[*] downloading ${ARTIFACT} (version ${VERSION})"
curl -sSLf -o "$tmp/$ARTIFACT" "$BASE_URL/$ARTIFACT"

if [ "$VERIFY" -eq 1 ]; then
    echo "[*] verifying SHA-256"
    curl -sSLf -o "$tmp/SHA256SUMS" "$BASE_URL/SHA256SUMS"
    (cd "$tmp" && sha256sum -c --ignore-missing SHA256SUMS) > /dev/null
fi

echo "[*] extracting"
tar -C "$tmp" -xzf "$tmp/$ARTIFACT"
extracted_dir="$tmp/${NAME_PREFIX}-${PLATFORM}-${ARCH}"
if [ ! -d "$extracted_dir" ]; then
    echo "[-] archive layout unexpected; no $extracted_dir" >&2
    exit 1
fi

mkdir -p "$PREFIX/bin"
install -m 0755 "$extracted_dir/abcpwn" "$PREFIX/bin/abcpwn"
echo "[+] installed: $PREFIX/bin/abcpwn"

case ":$PATH:" in
    *":$PREFIX/bin:"*) ;;
    *)
        echo "[!] $PREFIX/bin is not in PATH. Append to your shell rc:"
        echo "    export PATH=\"$PREFIX/bin:\$PATH\""
        ;;
esac
