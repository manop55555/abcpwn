#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Reject any tracked file that contains forbidden AI / tool
# attribution strings per CLAUDE.md. Case-insensitive.

set -euo pipefail

# Pattern matches the canonical AI / tool attribution names. The
# `\b...\b` boundaries on common-English words keep false positives
# at zero (e.g., "claude" matches the name but not substrings like
# "claudia").
PATTERN='(\bclaude\b|\banthropic\b|\bchatgpt\b|\bgpt-4\b|\bgpt-5\b|\bopenai\b|\bcopilot\b|github\s+copilot|co-authored-by|generated\s+with|generated\s+by\s+ai|ai-generated|ai\s+generated|made\s+with\s+ai)'

if [ "$#" -eq 0 ]; then
    # Skip binary fixtures, the gitignore family, and the check
    # scripts themselves. Each of those legitimately lists the
    # forbidden tokens as part of the very mechanism that keeps
    # them out of the published tree: .gitignore names CLAUDE.md /
    # .claude/, the check scripts reference those names in their
    # comments / regexes. Listing them is what makes the rule
    # enforceable; it must not be self-flagged.
    mapfile -t targets < <(git ls-files \
        | grep -Ev '^tests/fixtures/(binaries|libcs)/' \
        | grep -Ev '^(\.gitignore|\.gitattributes)$' \
        | grep -Ev '^scripts/check-.+\.sh$')
else
    targets=("$@")
fi

failed=0
for f in "${targets[@]}"; do
    [ -f "$f" ] || continue
    if hits=$(grep -Hin -E "$PATTERN" "$f" 2>/dev/null); then
        echo "$hits"
        failed=1
    fi
done

if [ "$failed" -ne 0 ]; then
    echo "[-] forbidden attribution string(s) found"
    exit 1
fi

echo "[+] no forbidden attribution"
