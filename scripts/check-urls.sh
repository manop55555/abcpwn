#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Verify every HTTP(S) URL in tracked sources, docs, and configs
# points at an allowlisted host. This catches typo'd domains and
# accidental references to user-controlled redirectors. Offline:
# checks pattern only, does not fetch.

set -euo pipefail

ALLOWED_HOSTS='(github\.com|raw\.githubusercontent\.com|codecov\.io|libc\.rip|libc-database|apache\.org|cmake\.org|json\.nlohmann\.me|cppreference\.com|en\.wikipedia\.org|osdev\.org|sigstore\.dev|spdx\.org|microsoft\.com|llvm\.org|keepachangelog\.com|semver\.org|img\.shields\.io|docs\.github\.com|api\.github\.com|token\.actions\.githubusercontent\.com)'

mapfile -t targets < <(git ls-files \
    | grep -E '\.(cpp|hpp|h|md|yml|yaml|json|toml|cmake|sh|py)$' \
    | grep -Ev '^tests/fixtures/(binaries|libcs)/' \
    || true)

failed=0
declare -A seen
while IFS= read -r line; do
    url=$(echo "$line" | sed -E 's/.*(https?:\/\/[A-Za-z0-9._/%~?=&#-]+).*/\1/' \
        | sed -E 's/[\),.;]+$//')
    [ -z "$url" ] && continue
    host=$(echo "$url" | sed -E 's|https?://([^/]+).*|\1|')
    [ -z "$host" ] && continue
    if [ -n "${seen[$host]:-}" ]; then continue; fi
    seen[$host]=1
    if ! echo "$host" | grep -qE "$ALLOWED_HOSTS"; then
        echo "[-] non-allowlisted host: $host  (first seen: $line)"
        failed=1
    fi
done < <(grep -nE 'https?://[A-Za-z0-9._/%~?=&#-]+' "${targets[@]}" 2>/dev/null \
    | grep -Ev 'STEP/|docs/DECISIONS\.md|\.git/' \
    || true)

if [ "$failed" -ne 0 ]; then
    echo "[-] one or more URLs reference a non-allowlisted host"
    exit 1
fi

echo "[+] every URL in tracked content uses an allowlisted host"
