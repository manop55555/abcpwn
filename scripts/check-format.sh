#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Run clang-format in dry-run-Werror mode across every committed
# C++ source. Picks the highest available clang-format-NN binary so
# the script works both locally (clang-format-21) and in CI
# (clang-format-18).

set -euo pipefail

# Prefer pinned versions in order; fall back to plain clang-format.
for candidate in clang-format-21 clang-format-20 clang-format-19 \
                 clang-format-18 clang-format; do
    if command -v "$candidate" > /dev/null 2>&1; then
        CLANG_FORMAT="$candidate"
        break
    fi
done

if [ -z "${CLANG_FORMAT:-}" ]; then
    echo "[-] clang-format not found"
    exit 1
fi

# Collect every tracked C++ source / header.
mapfile -t files < <(git ls-files \
    | grep -E '\.(cpp|hpp|h)$' \
    | grep -Ev '^tests/fixtures/' \
    || true)

if [ "${#files[@]}" -eq 0 ]; then
    echo "[+] no C++ files to check"
    exit 0
fi

"$CLANG_FORMAT" --dry-run --Werror "${files[@]}"
echo "[+] all ${#files[@]} files match .clang-format style"
