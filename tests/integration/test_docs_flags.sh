#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Regression for DEF-2: every long flag (--xxx) mentioned in a subcommand's
# docs/COMMANDS.md section must be accepted by that subcommand's --help, so
# the documentation cannot drift past the CLI ("--help never lags").
#
# Usage: test_docs_flags.sh <abcpwn-binary> <source-root>

set -uo pipefail

ABCPWN_BIN="${1:?abcpwn binary path required}"
SOURCE_ROOT="${2:?source root required}"
DOC="$SOURCE_ROOT/docs/COMMANDS.md"
[ -x "$ABCPWN_BIN" ] || { echo "[-] $ABCPWN_BIN not executable" >&2; exit 1; }
[ -f "$DOC" ] || { echo "[-] $DOC not found" >&2; exit 1; }

# Long flags accepted globally (valid in every subcommand section).
globals=$("$ABCPWN_BIN" --help 2>&1 | grep -oE -- '--[a-z][a-z0-9-]+' | sort -u)

# Emit "<subcommand> <flag>" for every --flag mentioned under a
# "### `<name>`" section in COMMANDS.md.
pairs=$(awk '
    /^### `[a-z]/ {
        s = $0
        sub(/^### `/, "", s); sub(/`.*/, "", s)
        cur = s; next
    }
    /^## / { cur = "" }
    cur != "" {
        line = $0
        while (match(line, /--[a-z][a-z0-9-]+/)) {
            print cur, substr(line, RSTART, RLENGTH)
            line = substr(line, RSTART + RLENGTH)
        }
    }
' "$DOC" | sort -u)

bad=0
while read -r cmd flag; do
    [ -n "$cmd" ] || continue
    # Global flags are valid everywhere.
    if echo "$globals" | grep -qxF -- "$flag"; then
        continue
    fi
    help=$("$ABCPWN_BIN" "$cmd" --help 2>&1 || true)
    if ! echo "$help" | grep -qE -- "(^|[^a-z-])${flag}([^a-z0-9-]|$)"; then
        echo "[-] COMMANDS.md '$cmd' documents '$flag', but '$cmd --help' does not accept it" >&2
        bad=1
    fi
done <<< "$pairs"

if [ "$bad" -ne 0 ]; then
    echo "[-] docs/COMMANDS.md references flags the binary does not accept (DEF-2)" >&2
    exit 1
fi
echo "[+] COMMANDS.md flags OK: every documented --flag is accepted by its subcommand --help"
