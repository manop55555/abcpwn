#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Documentation hygiene check. Verifies that every subcommand the
# binary advertises has a stable name (lowercase, kebab-case where
# applicable, never embeds forbidden tokens) and that the public
# documentation set is internally consistent: required files exist,
# internal links resolve, and fenced code blocks are balanced.
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
# Abcpwn / ABCPWN / etc. (project brand rules).
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

# Step 5: every doc that step 25 was supposed to ship exists.
required_docs=(
    "README.md"
    "BUILDING.md"
    "SECURITY.md"
    "CONTRIBUTING.md"
    "CODE_OF_CONDUCT.md"
    "LICENSE"
    "LICENSE-THIRD-PARTY.md"
    "CHANGELOG.md"
    "CITATION.cff"
    "docs/ARCHITECTURE.md"
    "docs/COMMANDS.md"
    "docs/PERFORMANCE.md"
    "docs/SECURITY-MODEL.md"
    "docs/ERROR_CODES.md"
    "docs/FAQ.md"
    "docs/TUTORIALS.md"
    "docs/ROADMAP.md"
    "docs/STATIC_ANALYSIS.md"
    "docs/SUPPORT.md"
)
missing=0
for d in "${required_docs[@]}"; do
    if [ ! -f "$SOURCE_ROOT/$d" ]; then
        echo "[-] required doc missing: $d"
        missing=1
    fi
done
if [ "$missing" -ne 0 ]; then
    exit 1
fi

# Step 6: internal markdown links resolve. Scan tracked .md files
# under the source root (excluding the gitignored design log) and
# for every [text](path) where path is relative (no scheme, no
# leading '#'), confirm the target exists. Anchor-only refs and
# external schemes are skipped. The grep captures ](...) groups
# including the closing paren; bash parameter expansion strips the
# wrapper, avoiding sed regex fragility on anchor-only badge links.
broken_links=0
while IFS= read -r mdfile; do
    [ -z "$mdfile" ] && continue
    mddir=$(dirname "$mdfile")
    while IFS= read -r raw; do
        # raw looks like '](path)' or '] (path)'. Strip leading "]"
        # and any whitespace, then strip wrapping parens.
        link=${raw#\]}
        link=${link# *}
        link=${link#\(}
        link=${link%\)}
        # Drop any trailing #anchor portion from a doc-relative
        # target like docs/X.md#section.
        path=${link%%#*}
        [ -z "$path" ] && continue
        case "$path" in
            http://*|https://*|mailto:*|ftp://*) continue ;;
        esac
        target="$mddir/$path"
        if [ ! -e "$target" ]; then
            echo "[-] broken internal link in ${mdfile#"$SOURCE_ROOT"/}: $link"
            broken_links=1
        fi
    done < <(grep -oE '\][[:space:]]*\([^)]+\)' "$mdfile" 2>/dev/null || true)
done < <(git -C "$SOURCE_ROOT" ls-files '*.md' 2>/dev/null | sed "s|^|$SOURCE_ROOT/|")
if [ "$broken_links" -ne 0 ]; then
    exit 1
fi

# Step 7: fenced code blocks are balanced (every opening fence has
# a matching closing fence) and where the opening fence carries a
# language tag, the tag is from a recognized set. Unrecognized tags
# are NOT a failure (people use rare languages too), but unbalanced
# fences ARE.
fence_problems=0
while IFS= read -r mdfile; do
    [ -z "$mdfile" ] && continue
    fence_count=$(grep -cE '^```' "$mdfile" 2>/dev/null || true)
    if [ "$((fence_count % 2))" -ne 0 ]; then
        echo "[-] unbalanced triple-backtick fences in ${mdfile#"$SOURCE_ROOT"/}: $fence_count fence lines"
        fence_problems=1
    fi
done < <(git -C "$SOURCE_ROOT" ls-files '*.md' 2>/dev/null | sed "s|^|$SOURCE_ROOT/|")
if [ "$fence_problems" -ne 0 ]; then
    exit 1
fi

# Step 8: every canonical subcommand name appears in every shell
# completion file. Names are extracted source-statically from the
# command headers (each command's name() override returns a literal),
# so this check runs without a built binary. Each completion file is
# expected to live under completions/. Missing completion files are
# a hard fail because step 5 already verifies their presence.
mapfile -t canonical_names < <(
    grep -A1 -hE 'name\(\)\s*const\s*noexcept\s*override' \
         "$SOURCE_ROOT"/include/abcpwn/commands/*.hpp 2>/dev/null \
        | grep -oE 'return "[a-z][a-z0-9-]+"' \
        | sed 's/return "//;s/"$//' \
        | sort -u
)

if [ "${#canonical_names[@]}" -lt 30 ]; then
    echo "[-] could not extract canonical subcommand names from include/abcpwn/commands/ (found ${#canonical_names[@]}, expected 30+)"
    exit 1
fi

completion_problems=0
for completion in \
    "$SOURCE_ROOT/completions/abcpwn.bash" \
    "$SOURCE_ROOT/completions/_abcpwn" \
    "$SOURCE_ROOT/completions/abcpwn.fish"
do
    if [ ! -f "$completion" ]; then
        echo "[-] missing completion: ${completion#"$SOURCE_ROOT"/}"
        completion_problems=1
        continue
    fi
    for name in "${canonical_names[@]}"; do
        # Require the name to appear as a standalone token. Word-boundary
        # behavior differs between greps on different platforms; use a
        # conservative character-class check that brackets the token.
        if ! grep -qE "(^|[^a-z0-9-])${name}([^a-z0-9-]|$)" "$completion"; then
            echo "[-] completion ${completion#"$SOURCE_ROOT"/} missing subcommand: $name"
            completion_problems=1
        fi
    done
done
if [ "$completion_problems" -ne 0 ]; then
    exit 1
fi

# Step 8b (DEF-2): the "N subcommands" prose in the man page (the complete
# reference) must match the actual number of registered subcommands, so the
# count cannot drift out of sync again. The README intentionally lists only
# the working v0.1 subset by capability group, so it is not asserted here.
sub_count=${#canonical_names[@]}
if ! grep -qE "(^| )${sub_count} subcommands" "$SOURCE_ROOT/man/abcpwn.1.md"; then
    echo "[-] man/abcpwn.1.md does not state the actual subcommand count (${sub_count})"
    exit 1
fi

# Step 9: rendered man page preserves double-hyphen CLI flags. Pandoc's
# "smart" extension is on by default and rewrites "--flag" into the Roff
# en-dash escape "\(en" which displays as a single dash in man(1) and
# breaks copy-paste of CLI examples. Docs.cmake passes --from=markdown-smart
# to disable that; this step is the regression sentinel.
if command -v pandoc >/dev/null 2>&1; then
    rendered=$(pandoc -s --from=markdown-smart -t man "$SOURCE_ROOT/man/abcpwn.1.md" 2>/dev/null || true)
    if [ -z "$rendered" ]; then
        echo "[-] pandoc rendered the man page to an empty document"
        exit 1
    fi
    # The smartypants rewrites we care about: \(en (en-dash escape) and
    # \(em (em-dash escape) on any line that documents a CLI flag.
    # Either escape means "--" was collapsed and the rendered page no
    # longer matches the documented surface.
    if printf '%s\n' "$rendered" | grep -qE '\\\(en|\\\(em'; then
        echo "[-] rendered man page contains \\(en or \\(em escape; pandoc smartypants is munging --flags"
        exit 1
    fi
    # Spot-check: at least one well-known flag survives. Pandoc 3.x
    # emits each hyphen as the Roff escape "\-" giving "\-\-format";
    # older 2.x writers emit a bare "--format". Both are correct
    # groff for a literal double hyphen; the failure mode we are
    # guarding against is the en-dash collapse caught above.
    if ! printf '%s\n' "$rendered" | grep -qE '(\\-\\-format|--format)'; then
        echo "[-] rendered man page does not contain --format in either escaped or bare form"
        exit 1
    fi
fi

echo "[+] docs hygiene OK: orchestrator, subcommand names, README casing, URLs, required docs, internal links, code-fence balance, completion coverage, man-page flag rendering"
