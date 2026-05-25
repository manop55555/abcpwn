#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Regression for DEF-1: syms must read .symtab (static) symbols with their
# addresses, not only .dynsym. A local/static function lives only in .symtab,
# which the previous implementation never read (returned "no symbols matched").
#
# Usage: test_syms_static.sh <abcpwn-binary>

set -euo pipefail

ABCPWN_BIN="${1:?abcpwn binary path required}"
[ -x "$ABCPWN_BIN" ] || { echo "[-] $ABCPWN_BIN not executable" >&2; exit 1; }

CC="$(command -v cc || command -v gcc || true)"
[ -n "$CC" ] || { echo "[*] no C compiler available; skipping" >&2; exit 0; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/t.c" <<'EOF'
#include <stdio.h>
int ret2win(void) { return puts("win"); }
int main(void) { return ret2win(); }
EOF

# Non-stripped so .symtab is present; -no-pie for a stable static address
# (fall back to the default if the toolchain rejects -no-pie).
"$CC" -no-pie -o "$tmp/twin" "$tmp/t.c" 2>/dev/null \
    || "$CC" -o "$tmp/twin" "$tmp/t.c"

run() { "$ABCPWN_BIN" --no-banner "$@" 2>&1 || true; }

# 1. ret2win is a .symtab-only symbol; default (--source all) lists it with a
#    real (non-zero, multi-digit) address.
out=$(run syms "$tmp/twin" --filter '^ret2win$')
echo "$out" | grep -qE 'ret2win +0x[0-9a-f]{3,}' \
    || { echo "[-] default syms did not list ret2win with an address:"; echo "$out"; exit 1; }

# 2. --source dynamic must EXCLUDE the static-only ret2win.
out=$(run syms "$tmp/twin" --source dynamic --filter '^ret2win$')
echo "$out" | grep -qi 'no symbols matched' \
    || { echo "[-] --source dynamic should not list the static ret2win:"; echo "$out"; exit 1; }

# 3. --source static must INCLUDE it.
out=$(run syms "$tmp/twin" --source static --filter '^ret2win$')
echo "$out" | grep -qE 'ret2win +0x[0-9a-f]{3,}' \
    || { echo "[-] --source static should list ret2win:"; echo "$out"; exit 1; }

# 4. JSON carries source: "static" for the static symbol.
out=$("$ABCPWN_BIN" --no-banner --format json syms "$tmp/twin" --filter '^ret2win$' 2>/dev/null || true)
echo "$out" | grep -q '"source": *"static"' \
    || { echo "[-] JSON missing source=static for ret2win:"; echo "$out"; exit 1; }

# 5. --source rejects an unknown value (exit 2, UsageError).
set +e
"$ABCPWN_BIN" --no-banner syms "$tmp/twin" --source bogus >/dev/null 2>&1
rc=$?
set -e
[ "$rc" -eq 2 ] || { echo "[-] --source bogus should exit 2, got $rc"; exit 1; }

# 6. --filter searches both tables: a broad filter surfaces the dynamic import
#    (puts) and the static symbol (ret2win) together.
out=$(run syms "$tmp/twin" --filter '.')
{ echo "$out" | grep -qE 'ret2win' && echo "$out" | grep -qiE 'puts'; } \
    || { echo "[-] --filter . should surface both static and dynamic symbols:"; echo "$out"; exit 1; }

echo "[+] syms static OK: .symtab symbols listed with addresses; --source filters tables; JSON source present"
