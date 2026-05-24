#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Single definition of the shellcheck gate. CI invokes this very script
# (after installing the pinned shellcheck), and the orchestrator
# (check-all.sh) picks it up automatically, so the local pre-commit gate
# and CI can never disagree about which scripts are checked or how.
#
# The repo-root .shellcheckrc pins the active check set. shellcheck is
# itself pinned to PINNED_VERSION via the official static binary (see
# .github/workflows/ci.yml and CONTRIBUTING.md); a local version
# mismatch warns but does not block.

set -euo pipefail

PINNED_VERSION="0.11.0"

if ! command -v shellcheck > /dev/null 2>&1; then
    echo "[-] shellcheck not found. Install v${PINNED_VERSION} (see CONTRIBUTING.md)." >&2
    echo "[-]   https://github.com/koalaman/shellcheck/releases/tag/v${PINNED_VERSION}" >&2
    exit 1
fi

have="$(shellcheck --version | awk '/^version:/ {print $2}')"
if [ "$have" != "$PINNED_VERSION" ]; then
    echo "[!] shellcheck $have does not match the pinned $PINNED_VERSION;" >&2
    echo "[!] results may differ from CI -- install the pinned build" >&2
    echo "[!] per CONTRIBUTING.md to match exactly." >&2
fi

# Every tracked shell script; the repo-root .shellcheckrc applies to all.
mapfile -t files < <(git ls-files '*.sh')
if [ "${#files[@]}" -eq 0 ]; then
    echo "[-] no tracked shell scripts found (run from inside the repo)" >&2
    exit 1
fi

if shellcheck "${files[@]}"; then
    echo "[+] shellcheck clean (${#files[@]} scripts, v${have})"
else
    echo "[-] shellcheck reported issues" >&2
    exit 1
fi
