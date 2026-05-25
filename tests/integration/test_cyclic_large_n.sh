#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Regression for DEF-3: `cyclic -n 7` / `-n 8` must stream the de Bruijn
# sequence, not materialize all 26^n bytes (~8 GB at n=7, ~208 GB at n=8)
# before truncating. The eager generator was OOM-killed even for 16 bytes.
#
# Usage: test_cyclic_large_n.sh <abcpwn-binary>

set -euo pipefail

ABCPWN_BIN="${1:?abcpwn binary path required}"
[ -x "$ABCPWN_BIN" ] || { echo "[-] $ABCPWN_BIN not executable" >&2; exit 1; }

# Hard-cap virtual memory at 1 GiB and wall time at 5 s: the streaming
# generator needs only kilobytes, while the old eager generator would blow
# past 1 GiB (and the OOM killer) for n >= 7.
for n in 7 8; do
    out=$(timeout 5 bash -c "ulimit -v 1048576; exec '$ABCPWN_BIN' --no-banner cyclic -n $n 16" 2>/dev/null) \
        || { echo "[-] cyclic -n $n 16 failed (OOM / timeout / nonzero); DEF-3 regression" >&2; exit 1; }
    [ "${#out}" -ge 16 ] \
        || { echo "[-] cyclic -n $n 16 produced ${#out} bytes, expected >= 16" >&2; exit 1; }
    # de Bruijn B(26, n) begins with n 'a's followed by a 'b'.
    case "$out" in
        aaaaaaaab*) ;; # n = 8
        aaaaaaab*) ;;  # n = 7
        *) echo "[-] cyclic -n $n 16 unexpected prefix: $out" >&2; exit 1 ;;
    esac
done

# Past the uniqueness window the request is rejected with SizeExceeded (9),
# not silently truncated or OOM'd. 26^4 = 456976 is the max for n = 4.
set +e
"$ABCPWN_BIN" --no-banner cyclic -n 4 500000 > /dev/null 2>&1
rc=$?
set -e
[ "$rc" -eq 9 ] \
    || { echo "[-] cyclic -n 4 500000 should exit 9 (SizeExceeded), got $rc" >&2; exit 1; }

echo "[+] cyclic large-n OK: -n 7/8 stream within 1 GiB/5 s; over-window rejects with exit 9"
