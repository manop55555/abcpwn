#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Orchestrator: runs every scripts/check-*.sh and aggregates results.
# Exits 0 only if every check passed. Use in pre-commit and pre-push.
#
# Usage:
#   scripts/check-all.sh
#
# Excludes itself from the iteration to avoid recursion.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELF="$(basename "${BASH_SOURCE[0]}")"
FAILED=()
PASSED=()

shopt -s nullglob
for s in "$SCRIPT_DIR"/check-*.sh; do
    name="$(basename "$s")"
    if [ "$name" = "$SELF" ]; then
        continue
    fi
    if [ ! -x "$s" ]; then
        chmod +x "$s"
    fi
    if "$s"; then
        PASSED+=("$name")
    else
        FAILED+=("$name")
    fi
done

echo
echo "--- check-all summary ---"
for n in "${PASSED[@]}"; do echo "[+] $n"; done
for n in "${FAILED[@]}"; do echo "[-] $n"; done

if [ "${#FAILED[@]}" -gt 0 ]; then
    echo "[-] ${#FAILED[@]} check(s) failed"
    exit 1
fi

echo "[+] all ${#PASSED[@]} checks passed"
exit 0
