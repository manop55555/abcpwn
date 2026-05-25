#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Regression for DEF-6: `search` must report the virtual address and section
# of a hit in a mapped binary, not only the file offset (the file offset is
# not the ROP-usable address). Raw / non-binary input stays offset-only.
#
# Usage: test_search_vaddr.sh <abcpwn-binary>

set -euo pipefail

ABCPWN_BIN="${1:?abcpwn binary path required}"
[ -x "$ABCPWN_BIN" ] || { echo "[-] $ABCPWN_BIN not executable" >&2; exit 1; }

CC="$(command -v cc || command -v gcc || true)"
[ -n "$CC" ] || { echo "[*] no C compiler available; skipping" >&2; exit 0; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/t.c" <<'EOF'
#include <stdio.h>
char marker[] = "ABCPWN_MARKER_STRING";
int main(void) { return puts(marker) == 0; }
EOF
"$CC" -no-pie -o "$tmp/t" "$tmp/t.c" 2>/dev/null || "$CC" -o "$tmp/t" "$tmp/t.c"

out=$("$ABCPWN_BIN" --no-banner search "$tmp/t" "ABCPWN_MARKER_STRING" 2>&1 || true)
echo "$out" | grep -qE '0x[0-9a-f]+' || { echo "[-] no file offset in output:"; echo "$out"; exit 1; }
echo "$out" | grep -qE 'vaddr 0x[0-9a-f]+' \
    || { echo "[-] DEF-6: search did not report a virtual address:"; echo "$out"; exit 1; }
echo "$out" | grep -qE 'section ' \
    || { echo "[-] DEF-6: search did not report a section:"; echo "$out"; exit 1; }

# Cross-check the reported vaddr against nm's address for the `marker` symbol.
if command -v nm > /dev/null 2>&1; then
    raw=$(nm "$tmp/t" 2>/dev/null | awk '$3=="marker"{print $1}' | head -1)
    if [ -n "$raw" ]; then
        want="0x$(printf '%x' "0x$raw")"
        echo "$out" | grep -qE "vaddr ${want}([^0-9a-f]|$)" \
            || { echo "[-] vaddr mismatch: nm marker=$want, got:"; echo "$out"; exit 1; }
    fi
fi

# JSON carries vaddr + section.
j=$("$ABCPWN_BIN" --no-banner --format json search "$tmp/t" "ABCPWN_MARKER_STRING" 2>/dev/null || true)
echo "$j" | grep -q '"vaddr"' || { echo "[-] JSON missing vaddr field"; exit 1; }
echo "$j" | grep -q '"section"' || { echo "[-] JSON missing section field"; exit 1; }

# Raw / non-binary input: file offset only, no vaddr.
printf 'hello ABCPWN_MARKER_STRING world' > "$tmp/raw.txt"
out=$("$ABCPWN_BIN" --no-banner search "$tmp/raw.txt" "ABCPWN_MARKER_STRING" 2>&1 || true)
echo "$out" | grep -qE '0x[0-9a-f]+' || { echo "[-] raw search reported no offset:"; echo "$out"; exit 1; }
if echo "$out" | grep -qE 'vaddr '; then
    echo "[-] raw (non-binary) input must not report a vaddr:"; echo "$out"; exit 1
fi

echo "[+] search vaddr OK: ELF hits carry offset + vaddr + section (matches nm); raw input is offset-only"
