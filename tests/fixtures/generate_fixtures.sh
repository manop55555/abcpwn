#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Regenerate the binary fixtures under tests/fixtures/binaries/. Run on
# a Linux machine with gcc available. The produced binaries are
# committed and used by binary_loader and per-command tests.

set -euo pipefail

cd "$(dirname "$0")"
mkdir -p binaries

cc=${CC:-cc}

build() {
    local name=$1; shift
    local src=$1; shift
    "${cc}" "$@" -o "binaries/${name}" "${src}"
    echo "[+] built binaries/${name}"
}

src_main_c=$(mktemp --suffix=.c)
trap 'rm -f "${src_main_c}"' EXIT
cat > "${src_main_c}" <<'EOF'
#include <stdio.h>
#include <string.h>
extern char* gets(char* s);  /* removed from C11; declared to force import */
int main(int argc, char** argv) {
    (void) argc;
    char buf[16];
    if (argc > 1) {
        strcpy(buf, argv[1]);
    } else {
        (void) gets(buf);
    }
    return 0;
}
EOF

# Hardened build: PIE, NX, full RELRO, canary, fortify. The presence of
# gets() ensures a "dangerous function" finding even with hardening on.
build hello-hardened "${src_main_c}" \
    -O0 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -pie -fPIE \
    -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack

# Stripped variant for the strings command tests.
build hello-stripped "${src_main_c}" -O2 -s

echo "[+] fixtures generated"
