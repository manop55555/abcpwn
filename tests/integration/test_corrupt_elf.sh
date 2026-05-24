#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Verifies that truncated / structurally-broken ELFs surface as
# ErrorCode::Corrupted (exit 11) rather than NotFound (exit 7) or
# silently parsing.

set -euo pipefail

ABCPWN_BIN="${1:?abcpwn binary path required}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Case 1: only the 4-byte ELF magic. No e_ident, no e_machine, no header.
printf '\x7fELF' > "$tmp/elf-magic-only"

# Case 2: ELF64 EI_CLASS but only 30 bytes total (header needs 64).
printf '\x7fELF\x02' > "$tmp/elf64-truncated"
head -c 25 /dev/urandom >> "$tmp/elf64-truncated"

# Case 3: ELF32 EI_CLASS but only 40 bytes total (header needs 52).
printf '\x7fELF\x01' > "$tmp/elf32-truncated"
head -c 36 /dev/urandom >> "$tmp/elf32-truncated"

for fixture in elf-magic-only elf64-truncated elf32-truncated; do
    set +e
    "$ABCPWN_BIN" --no-banner info "$tmp/$fixture" >/dev/null 2>err
    rc=$?
    set -e
    if [ "$rc" -ne 11 ]; then
        echo "[-] $fixture: expected exit 11 (Corrupted), got $rc" >&2
        cat err >&2
        exit 1
    fi
    if ! grep -qiE 'truncat|too small|corrupt' err; then
        echo "[-] $fixture: stderr did not mention corruption" >&2
        cat err >&2
        exit 1
    fi
done

# Gadget command (separate code path; also went via formats::load).
set +e
"$ABCPWN_BIN" --no-banner gadget "$tmp/elf64-truncated" >/dev/null 2>err
rc=$?
set -e
if [ "$rc" -ne 11 ]; then
    echo "[-] gadget on truncated ELF: expected exit 11, got $rc" >&2
    cat err >&2
    exit 1
fi

# #41: a binary LIEF can parse but that has no executable section
# CONTENT (a headers-only truncation) plainly EXISTS, so NotFound (7)
# -- "path does not exist" -- is the wrong code. gadget now routes it
# to a non-NotFound honest code (Unsupported, 10). A genuinely missing
# path must still be NotFound (7) from the loader.
gtarget=""
for c in /bin/ls /usr/bin/ls /bin/true /usr/bin/true; do
    [ -x "$c" ] && gtarget="$c" && break
done
if [ -n "$gtarget" ]; then
    head -c 100 "$gtarget" > "$tmp/headers-only"
    set +e
    "$ABCPWN_BIN" --no-banner gadget "$tmp/headers-only" >/dev/null 2>err
    rc=$?
    set -e
    if [ "$rc" -eq 7 ]; then
        echo "[-] gadget headers-only: returned NotFound (7); an existing, parseable file should not be NotFound" >&2
        cat err >&2
        exit 1
    fi
fi

set +e
"$ABCPWN_BIN" --no-banner gadget "$tmp/definitely-not-here.bin" >/dev/null 2>/dev/null
rc=$?
set -e
if [ "$rc" -ne 7 ]; then
    echo "[-] gadget on a missing path: expected NotFound (7), got $rc" >&2
    exit 1
fi

# LIEF logger silenced -- a malformed binary that LIEF parses leniently
# should produce no "LIEF" / "[WARNING]" / "[ERROR]" lines on stderr
# from the library itself; we surface our own diagnostics instead.
# Use a junk file that LIEF will try to parse and complain about.
printf '\x7fELF\x02\x01\x01\x00' > "$tmp/elf-partial"
head -c 60 /dev/urandom >> "$tmp/elf-partial"
set +e
"$ABCPWN_BIN" --no-banner info "$tmp/elf-partial" >/dev/null 2>err
rc=$?
set -e
# rc is allowed to be 0 or 11 here; we only care that LIEF's own log
# lines did not leak through. A literal "[WARNING]" / "[ERROR]" /
# "Can't read" header from the LIEF logger is the failure signal.
if grep -qE '^\[WARNING\]|^\[ERROR\]|^\[CRITICAL\]|Can'"'"'t read' err; then
    echo "[-] LIEF logger leaked to stderr:" >&2
    cat err >&2
    exit 1
fi

echo "[+] test_corrupt_elf ok"
