#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Reject any file under source control that contains an emoji or
# other Unicode pictograph. ASCII markers only ([+] [-] [!] [*] [?])
# per STEP/02_BRAND.md. Run with no arguments to scan the full repo,
# or with one or more paths to scan only those.

set -euo pipefail

# Pictograph Unicode ranges per STEP/02:
#   1F300-1F9FF  Misc Symbols and Pictographs, Emoticons, Transport
#   2600-27BF    Misc Symbols, Dingbats
#   1F000-1F02F  Mahjong Tiles
#   1FA70-1FAFF  Symbols and Pictographs Extended-A
EMOJI_RE='[\x{1F300}-\x{1F9FF}]|[\x{2600}-\x{27BF}]|[\x{1F000}-\x{1F02F}]|[\x{1FA70}-\x{1FAFF}]'

# When run with no arguments, scan everything tracked by git plus
# everything currently staged. Otherwise scan only the given paths.
if [ "$#" -eq 0 ]; then
    mapfile -t targets < <(git ls-files \
        | grep -Ev '^tests/fixtures/(binaries|libcs)/')
else
    targets=("$@")
fi

# Skip binary fixtures (already filtered above for the no-arg case)
# and known-binary extensions.
matches=""
for f in "${targets[@]}"; do
    [ -f "$f" ] || continue
    case "$f" in
        tests/fixtures/binaries/*|tests/fixtures/libcs/*|*.so|*.a|*.o) continue ;;
    esac
    if grep -PIln "$EMOJI_RE" "$f" 2>/dev/null; then
        matches="${matches}${f}\n"
    fi
done

if [ -n "$matches" ]; then
    printf "[-] emoji or pictograph found in:\n%b" "$matches"
    exit 1
fi

echo "[+] no emoji found"
