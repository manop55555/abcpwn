#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Regression for DEF-7: `got` must emit the PLT stub address paired with each
# GOT entry (the address a ROP chain actually calls), not only the GOT slot.
#
# Usage: test_got_plt.sh <abcpwn-binary>

set -euo pipefail

ABCPWN_BIN="${1:?abcpwn binary path required}"
[ -x "$ABCPWN_BIN" ] || { echo "[-] $ABCPWN_BIN not executable" >&2; exit 1; }

CC="$(command -v cc || command -v gcc || true)"
[ -n "$CC" ] || { echo "[*] no C compiler available; skipping" >&2; exit 0; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/t.c" <<'EOF'
#include <stdio.h>
int main(void) { puts("hi"); return 0; }
EOF
"$CC" -no-pie -o "$tmp/t" "$tmp/t.c" 2>/dev/null || "$CC" -o "$tmp/t" "$tmp/t.c"

out=$("$ABCPWN_BIN" --no-banner got "$tmp/t" --symbol puts 2>&1 || true)
echo "$out" | grep -qE 'GOT 0x[0-9a-f]+' \
    || { echo "[-] got --symbol puts missing GOT address:"; echo "$out"; exit 1; }
echo "$out" | grep -qE 'PLT 0x[0-9a-f]+' \
    || { echo "[-] got --symbol puts missing PLT stub address (DEF-7):"; echo "$out"; exit 1; }

got_plt=$(echo "$out" | grep -oE 'PLT 0x[0-9a-f]+' | grep -oE '0x[0-9a-f]+' | head -1)
[ "$got_plt" != "0x0" ] || { echo "[-] PLT address is zero"; exit 1; }

# Cross-check against objdump when available: the reported PLT stub must equal
# the puts@plt entry address.
if command -v objdump > /dev/null 2>&1; then
    raw=$(objdump -d "$tmp/t" 2>/dev/null | grep -oE '^[0-9a-f]+ <puts@plt>' \
          | grep -oE '^[0-9a-f]+' | head -1)
    if [ -n "$raw" ]; then
        want="0x$(printf '%x' "0x$raw")"
        [ "$got_plt" = "$want" ] \
            || { echo "[-] PLT mismatch: abcpwn=$got_plt objdump puts@plt=$want"; exit 1; }
    fi
fi

# JSON carries the plt_addr field.
"$ABCPWN_BIN" --no-banner --format json got "$tmp/t" --symbol puts 2>/dev/null \
    | grep -q '"plt_addr"' \
    || { echo "[-] JSON output missing plt_addr field"; exit 1; }

echo "[+] got PLT OK: GOT and PLT stub addresses paired (matches objdump puts@plt)"
