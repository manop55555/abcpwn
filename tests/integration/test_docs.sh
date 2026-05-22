#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Documentation hygiene check. v0.1 docs/COMMANDS.md does not yet
# exist (that lands in step 25), so this test focuses on the README
# + CHANGELOG + CONTRIBUTING-shaped files that DO exist, and on
# verifying that every subcommand the binary advertises has a
# stable name (lowercase, kebab-case where applicable, never
# embeds forbidden tokens).
#
# Usage: test_docs.sh <abcpwn-binary> <source-root>

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "[-] usage: $0 <abcpwn-binary> <source-root>" >&2
    exit 2
fi

ABCPWN_BIN="$1"
SOURCE_ROOT="$2"

# Step 1: every tracked markdown file must round-trip cleanly through
# the no-emoji + no-attribution scripts (the orchestrator covers
# this at every commit; the duplicate here makes the test executable
# stand alone).
"$SOURCE_ROOT/scripts/check-no-emoji.sh"        > /dev/null
"$SOURCE_ROOT/scripts/check-no-attribution.sh"  > /dev/null

# Step 2: subcommand-name hygiene. Pull the subcommand list from
# `abcpwn --help` and verify each name:
#   - is lowercase
#   - contains only [a-z0-9-]
#   - is not in the forbidden-token list
forbidden='\<claude\>|\<anthropic\>|\<chatgpt\>|\<openai\>|\<copilot\>'
help_out="$("$ABCPWN_BIN" --help 2>&1)"
# Real subcommand rows start with exactly two leading spaces followed
# by a lowercase letter. Continuation rows from wrapped descriptions
# start with more leading spaces (column-aligned to the description),
# so the regex anchor `^  [a-z]` filters them out.
sub_lines="$(printf '%s\n' "$help_out" \
    | awk '/^SUBCOMMANDS:/{flag=1; next} flag && /^  [a-z]/ {print}')"

if [ -z "$sub_lines" ]; then
    echo "[-] could not parse SUBCOMMANDS list from --help" >&2
    exit 1
fi

bad=0
while read -r name _rest; do
    [ -z "$name" ] && continue
    if [[ ! "$name" =~ ^[a-z0-9-]+$ ]]; then
        echo "[-] subcommand '$name' is not lowercase-kebab"
        bad=1
    fi
    if echo "$name" | grep -qEi "$forbidden"; then
        echo "[-] subcommand '$name' contains a forbidden token"
        bad=1
    fi
done <<< "$sub_lines"

if [ "$bad" -ne 0 ]; then
    exit 1
fi

# Step 3: README mentions the project name lowercase, never
# Abcpwn / ABCPWN / etc. (per STEP/02 brand rules).
if grep -E '\b(Abcpwn|ABCPWN|AbcPwn|ABCPwn|Abc Pwn)\b' "$SOURCE_ROOT/README.md" > /dev/null; then
    echo "[-] README.md contains a non-lowercase project name"
    exit 1
fi

# Step 4: link sanity. Every http(s) URL embedded in tracked docs
# should look reasonable -- non-empty path, no obvious typos. We do
# not actually fetch them (offline-friendly).
bad_url=0
while IFS= read -r url; do
    case "$url" in
        https://*|http://*) ;;
        *) continue ;;
    esac
    # strip trailing punctuation that pulled into the match
    clean="${url%%[\),.\]\>]*}"
    if ! [[ "$clean" =~ ^https?://[A-Za-z0-9._-]+(/[A-Za-z0-9._%/-]*)*$ ]]; then
        echo "[-] suspicious URL in tracked docs: $clean"
        bad_url=1
    fi
done < <(grep -rohE 'https?://[^[:space:]<>"`)]+' \
           --include='*.md' "$SOURCE_ROOT" \
           --exclude-dir=.git \
           --exclude-dir=STEP \
           --exclude-dir=build \
           --exclude-dir=vcpkg_installed \
           2>/dev/null \
         | sort -u)

if [ "$bad_url" -ne 0 ]; then
    exit 1
fi

echo "[+] docs hygiene OK: orchestrator scripts, subcommand names, README casing, URLs"
