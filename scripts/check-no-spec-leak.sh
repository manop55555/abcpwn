#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Reject any tracked file that would publish project specs or the
# local-only design log. The .gitignore + .git/info/exclude pair
# already prevents accidental staging; this script is a belt-and-
# suspenders pre-commit / pre-push check.

set -euo pipefail

FORBIDDEN_RE='^(CLAUDE\.md$|STEP/|STEP\.|\.claude/|\.claude.+|docs/DECISIONS\.md$)'

# Check what is currently tracked by git.
leaks=$(git ls-files | grep -E "$FORBIDDEN_RE" || true)
if [ -n "$leaks" ]; then
    echo "[-] tracked spec files (should be local-only):"
    echo "$leaks"
    exit 1
fi

# Also check what is currently staged (catches a mistake before the
# commit lands).
staged=$(git diff --cached --name-only | grep -E "$FORBIDDEN_RE" || true)
if [ -n "$staged" ]; then
    echo "[-] staged spec files (should be local-only):"
    echo "$staged"
    exit 1
fi

# Content check (IMP-2): public-facing tracked files must not REFERENCE
# the local-only spec set (CLAUDE.md, STEP/, DECISIONS.md). The check-*.sh
# enforcement scripts and .gitignore name these tokens by design and are
# excluded.
content_refs=$(git ls-files \
    | grep -vE '^scripts/check-' \
    | grep -vE '^(\.gitignore|\.gitattributes)$' \
    | xargs -r grep -nE 'CLAUDE\.md|STEP/|DECISIONS\.md' 2>/dev/null || true)
if [ -n "$content_refs" ]; then
    echo "[-] tracked files reference internal-spec docs (rewrite to self-contained text):"
    echo "$content_refs"
    exit 1
fi

echo "[+] no spec files tracked or staged, no internal-spec references"
