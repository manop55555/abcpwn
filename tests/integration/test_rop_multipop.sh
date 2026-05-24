#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Regression test for rop multi-pop gadget combination (verification
# #31). The old planner searched for a dedicated `pop <reg> ; ret` per
# register and rejected any gadget whose intermediate pops hit other
# target registers, so a single `pop rdi ; pop rsi ; pop rdx ; ret`
# (which sets three argument registers at once) was never used -- a
# 3-argument syscall reported rdi/rsi missing. The planner now covers
# the needed registers with a COMBINATION of pop-chain gadgets.
#
# Usage: test_rop_multipop.sh <abcpwn-binary>

set -euo pipefail

ABCPWN_BIN="${1:?abcpwn binary path required}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

CC_BIN=""
for c in "${CC:-}" cc gcc clang; do
    [ -n "$c" ] && command -v "$c" >/dev/null 2>&1 && CC_BIN="$c" && break
done
if [ -z "$CC_BIN" ]; then
    echo "[*] no C compiler available; skipping rop multipop fixture test"
    exit 0
fi

# Raw gadget bytes in .text:
#   5f 5e 5a c3 = pop rdi ; pop rsi ; pop rdx ; ret  (one gadget, 3 args)
#   58 c3       = pop rax ; ret
#   0f 05       = syscall
cat > "$tmp/ropfix.c" <<'EOF'
__asm__(
    ".text\n"
    ".globl ropgadgets\n"
    "ropgadgets:\n"
    ".byte 0x5f, 0x5e, 0x5a, 0xc3\n"
    ".byte 0x58, 0xc3\n"
    ".byte 0x0f, 0x05\n"
);
int main(void) { return 0; }
EOF
"$CC_BIN" -O0 "$tmp/ropfix.c" -o "$tmp/ropfix" 2>/dev/null \
    || { echo "[*] fixture compile failed; skipping"; exit 0; }

set +e
out="$("$ABCPWN_BIN" --no-banner rop "$tmp/ropfix" --syscall 59 \
        --syscall-arg 0x404040 --syscall-arg 0 --syscall-arg 0 2>&1)"
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
    echo "[-] rop could not build a 3-arg chain from a multi-pop gadget (exit $rc)"
    echo "$out"
    exit 1
fi
# The single multi-pop gadget must be the one chosen, and all three
# argument registers fed from it.
if ! printf '%s' "$out" | grep -qF "pop rdi ; pop rsi ; pop rdx ; ret"; then
    echo "[-] multi-pop gadget not used in the chain:"; echo "$out"; exit 1
fi
for needle in "rdi" "rsi" "rdx" "rax" "syscall"; do
    if ! printf '%s' "$out" | grep -qF "$needle"; then
        echo "[-] chain missing expected register/gadget: $needle"; echo "$out"; exit 1
    fi
done

echo "[+] rop multipop OK: one pop rdi/rsi/rdx gadget set all three args"
