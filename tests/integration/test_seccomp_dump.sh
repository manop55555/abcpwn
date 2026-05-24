#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Regression test for `seccomp dump` (verification #7). The action was
# advertised in --help but returned "not implemented" (exit 10). It now
# statically locates a sock_filter[] BPF program embedded in a data
# section and disassembles it (abcpwn never executes the target).
#
# Usage: test_seccomp_dump.sh <abcpwn-binary>

set -euo pipefail

ABCPWN_BIN="${1:?abcpwn binary path required}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# A C toolchain is needed to build the fixtures. The build that produced
# abcpwn already used one, so this is present in CI; skip gracefully if a
# stripped-down environment lacks it rather than failing spuriously.
CC_BIN=""
for c in "${CC:-}" cc gcc clang; do
    [ -n "$c" ] && command -v "$c" >/dev/null 2>&1 && CC_BIN="$c" && break
done
if [ -z "$CC_BIN" ]; then
    echo "[*] no C compiler available; skipping seccomp dump fixture test"
    exit 0
fi

# Fixture 1: a static seccomp filter in .rodata -- validate arch, KILL on
# wrong arch, then KILL execve(59), else ALLOW. Bytes are hand-encoded so
# the test does not depend on <linux/seccomp.h>.
cat > "$tmp/sccfix.c" <<'EOF'
static const unsigned char seccomp_bpf[] = {
    0x20,0x00,0x00,0x00, 0x04,0x00,0x00,0x00,
    0x15,0x00,0x01,0x00, 0x3e,0x00,0x00,0xc0,
    0x06,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x20,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x15,0x00,0x00,0x01, 0x3b,0x00,0x00,0x00,
    0x06,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x06,0x00,0x00,0x00, 0x00,0x00,0xff,0x7f,
};
int main(void) { const volatile unsigned char* keep = seccomp_bpf; return keep[0] & 0; }
EOF
"$CC_BIN" -O0 "$tmp/sccfix.c" -o "$tmp/sccfix" 2>/dev/null \
    || { echo "[*] fixture compile failed; skipping"; exit 0; }

set +e
out="$("$ABCPWN_BIN" --no-banner seccomp dump "$tmp/sccfix" 2>/dev/null)"
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
    echo "[-] seccomp dump exited $rc on a binary with a static filter"
    echo "$out"
    exit 1
fi
for needle in "A = arch" "A = sys_number" "return ALLOW" "return KILL" "SYS_execve"; do
    if ! printf '%s' "$out" | grep -qF "$needle"; then
        echo "[-] seccomp dump output missing expected token: $needle"
        echo "    got: $out"
        exit 1
    fi
done

# Fixture 2: a binary with no embedded filter -> Unsupported (10), with a
# message pointing at runtime-capture tooling.
cat > "$tmp/none.c" <<'EOF'
int main(void) { return 0; }
EOF
"$CC_BIN" -O0 "$tmp/none.c" -o "$tmp/none" 2>/dev/null \
    || { echo "[*] no-filter fixture compile failed; skipping that case"; echo "[+] seccomp dump OK (filter case)"; exit 0; }

set +e
err="$("$ABCPWN_BIN" --no-banner seccomp dump "$tmp/none" 2>&1 1>/dev/null)"
rc=$?
set -e
if [ "$rc" -ne 10 ]; then
    echo "[-] seccomp dump on a no-filter binary: expected exit 10, got $rc"
    echo "    stderr: $err"
    exit 1
fi
printf '%s' "$err" | grep -qiE "no static BPF filter|strace|seccomp-tools" \
    || { echo "[-] no-filter message not helpful: $err"; exit 1; }

echo "[+] seccomp dump OK: static filter disassembled; no-filter binary returns Unsupported"
