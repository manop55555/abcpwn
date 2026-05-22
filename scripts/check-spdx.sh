#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Verify every source file under source control carries the project
# SPDX header. Per CLAUDE.md and STEP/01_IDENTITY.md the header is
# exactly two lines:
#   SPDX-License-Identifier: Apache-2.0
#   Copyright (c) 2026 manop55555
# prefixed with the comment marker appropriate to the file's syntax.

set -euo pipefail

EXPECTED_LICENSE="SPDX-License-Identifier: Apache-2.0"
EXPECTED_COPYRIGHT="Copyright (c) 2026 manop55555"

if [ "$#" -eq 0 ]; then
    mapfile -t targets < <(git ls-files \
        | grep -E '\.(cpp|hpp|h|cmake|sh|yml|yaml|py)$' \
        | grep -Ev '^tests/fixtures/(binaries|libcs)/')
else
    targets=("$@")
fi

failed=0
for f in "${targets[@]}"; do
    [ -f "$f" ] || continue
    head -5 "$f" | grep -q "$EXPECTED_LICENSE" || {
        echo "[-] missing SPDX license header: $f"
        failed=1
    }
    head -5 "$f" | grep -q "$EXPECTED_COPYRIGHT" || {
        echo "[-] missing/wrong copyright: $f"
        failed=1
    }
done

if [ "$failed" -ne 0 ]; then
    exit 1
fi

echo "[+] all checked files have the SPDX header"
