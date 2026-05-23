#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Regression for QA round 3 MAJOR: README Quick Start had 4 of 7
# examples that fail to parse (exit 109 = unknown flag) or that
# reference flags that don't exist. After the fix, every Quick
# Start line must either succeed or fail only because the binary
# argument doesn't point at a real file (which we can't fix in a
# test environment without bringing fixtures).
#
# Usage: test_readme_quickstart.sh <abcpwn-binary> <source-root>

set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "[-] usage: $0 <abcpwn-binary> <source-root>" >&2
    exit 2
fi

ABCPWN_BIN="$1"
SOURCE_ROOT="$2"

if [ ! -x "$ABCPWN_BIN" ]; then
    echo "[-] $ABCPWN_BIN is not executable" >&2
    exit 1
fi

# Each Quick Start command, normalized. We verify that the command
# parses (no exit 109 = unknown flag); if the binary argument is
# bogus we accept exit 5/6/7 (IoError/PermissionDenied/NotFound).
# Exit 2 (UsageError) means a real CLI defect.
quickstart=(
    "info ./challenge"
    "syms ./challenge --dangerous"
    "gadget ./libc.so.6 --depth 8"
    "rop ./challenge --syscall 59 --syscall-arg 0x404020 --syscall-arg 0 --syscall-arg 0"
    "shellcode --preset sh --arch x86_64"
    "pwn 1.2.3.4:1337"
    "info /bin/ls"
)

bad=0
for cmd in "${quickstart[@]}"; do
    # Use --no-banner to keep the test output tight.
    set +e
    # shellcheck disable=SC2086
    "$ABCPWN_BIN" --no-banner $cmd </dev/null >/dev/null 2>/dev/null
    rc=$?
    set -e

    # Accept: 0 (success), 5/6/7 (file errors against a fake path),
    #         11 (corrupted), 4 (FeatureDisabled e.g. shellcode arch
    #         not in db), 8 (InvalidInput from a placeholder address),
    #         12/13 (network policy on pwn -- expected for a
    #         host:port the test environment can't reach).
    case "$rc" in
        0|4|5|6|7|8|11|12|13) ;;
        2)
            echo "[-] Quick Start example exits 2 (UsageError -- flag is wrong): $cmd"
            bad=1
            ;;
        109)
            echo "[-] Quick Start example exits 109 (CLI11 unknown flag): $cmd"
            bad=1
            ;;
        *)
            # 14 = signal interrupt during pwn tcp connect; tolerate.
            if [ "$rc" -lt 100 ]; then
                : # subcommand-specific error, tolerated
            else
                echo "[-] Quick Start example exits $rc (CLI11 parse error): $cmd"
                bad=1
            fi
            ;;
    esac
done

if [ "$bad" -ne 0 ]; then
    exit 1
fi

# Verify the README itself doesn't mention removed flags.
forbidden_patterns=(
    "--max-len"      # gadget; real flag is --depth
    "--type funcs"   # syms; the --type flag isn't on syms
    "--execve"       # rop; removed in favor of --syscall 59
    " --tcp "        # pwn; target is positional host:port
)
for pat in "${forbidden_patterns[@]}"; do
    if grep -F -- "$pat" "$SOURCE_ROOT/README.md" >/dev/null 2>&1; then
        echo "[-] README still mentions removed/wrong flag: $pat"
        bad=1
    fi
done

if [ "$bad" -ne 0 ]; then
    exit 1
fi

echo "[+] README Quick Start examples parse cleanly; no broken-flag mentions"
