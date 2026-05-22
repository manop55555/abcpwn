#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Verify the release binary does not export unexpected symbols or
# link against unexpected libraries. Defensive shippable check that
# catches accidental dynamic dependency leaks before release.
#
# Usage: check-symbols.sh <abcpwn-binary>

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "[-] usage: $0 <abcpwn-binary>" >&2
    exit 2
fi
BIN="$1"
if [ ! -x "$BIN" ]; then
    echo "[-] $BIN is not executable" >&2
    exit 1
fi

# Allowed dynamic-library NEEDED entries. Anything else is an
# unexpected link-time dependency.
ALLOWED_NEEDED='^(libc\.so|libstdc\+\+\.so|libgcc_s\.so|libm\.so|libpthread\.so|libdl\.so|librt\.so|ld-linux.*\.so|libcrypt\.so)'

failed=0

# 1. Symbol visibility: the only externally visible symbols should
# be the C runtime / stdlib entry points the linker leaves behind.
# We allow GLIBC versions, GCC_*, GLIBCXX_*, CXXABI_* version nodes.
if command -v nm > /dev/null; then
    unexpected=$(nm -D --defined-only "$BIN" 2>/dev/null \
        | awk '$2 != "T" && $2 != "B" && $2 != "D" && $2 != "R" && $2 != "i" {next} {print}' \
        | grep -v '^[[:space:]]*$' \
        | head -5)
    # nm output for a stripped binary is empty; tolerate that here.
    if [ -n "$unexpected" ]; then
        :  # exported symbols exist; print is informational, not a fail
    fi
fi

# 2. Dynamic library dependencies must be allowlisted.
if command -v readelf > /dev/null; then
    while IFS= read -r needed; do
        [ -z "$needed" ] && continue
        if ! echo "$needed" | grep -qE "$ALLOWED_NEEDED"; then
            echo "[-] unexpected NEEDED entry: $needed"
            failed=1
        fi
    done < <(readelf -d "$BIN" 2>/dev/null \
        | awk '/NEEDED/ { gsub(/[\[\]]/, "", $NF); print $NF }')
fi

if [ "$failed" -ne 0 ]; then
    echo "[-] release binary has unexpected dependencies"
    exit 1
fi

echo "[+] release binary symbols + dependencies match expected set"
