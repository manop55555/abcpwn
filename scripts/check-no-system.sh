#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Per CLAUDE.md: no system(), popen(), or exec*() in src/. Tests are
# allowed to invoke subprocesses (the pwn command's I/O tubes are
# tested via subprocesses). This check strips C++ line comments and
# naively-quoted string contents from each line before matching so
# documentation that references the call name -- e.g., the shellcode
# database describing execve(...) shellcodes -- does not trip the
# check.

set -euo pipefail

# Match `<sep>(system|popen|exec[lv]p?e?)<ws>*(` where <sep> is a
# non-identifier character (so we don't match inside a longer
# identifier like `mysystem`).
PATTERN_AWK='(^|[^A-Za-z0-9_])(system|popen|exec[lv]p?e?)[[:space:]]*[(]'

found=0
while IFS= read -r -d '' file; do
    [ -f "$file" ] || continue
    if awk -v pat="$PATTERN_AWK" '
        {
            line = $0
            sub(/\/\/.*$/, "", line)        # strip C++ line comments
            gsub(/"[^"]*"/, "\"\"", line)    # blank out string literals
            if (line ~ pat) {
                printf "%s:%d: %s\n", FILENAME, NR, $0
                exit 2
            }
        }
    ' FILENAME="$file" "$file"; then
        :   # exit 0: no match in this file
    else
        rc=$?
        if [ "$rc" -eq 2 ]; then
            found=1
        else
            echo "[-] awk error on $file (rc=$rc)" >&2
            found=1
        fi
    fi
done < <(find src include -type f \( -name '*.cpp' -o -name '*.hpp' -o -name '*.h' \) -print0)

if [ "$found" -ne 0 ]; then
    echo "[-] forbidden API call found under src/ or include/"
    exit 1
fi

echo "[+] no forbidden API calls in src/ include/"
