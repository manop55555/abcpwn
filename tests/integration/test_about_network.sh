#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Verify the network-policy introspection surfaces: --about-network
# prints a coherent policy block, and ABCPWN_NO_NETWORK=1 forces
# allow_network off even when --allow-network is passed. Network
# absence is a core project invariant (see ADR 0006), so a regression
# here is shippable-blocker material.
#
# Usage: test_about_network.sh <abcpwn-binary>

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "[-] usage: $0 <abcpwn-binary>" >&2
    exit 2
fi

ABCPWN_BIN="$1"

if [ ! -x "$ABCPWN_BIN" ]; then
    echo "[-] $ABCPWN_BIN is not executable" >&2
    exit 1
fi

# 1. --about-network produces a non-empty policy block referencing
#    the invariant we care about (no network, telemetry-free, the
#    two network-using subcommands).
about_out="$("$ABCPWN_BIN" --about-network 2>&1)"
for needle in "no network calls" "libc download" "pwninit" "telemetry" "ABCPWN_NO_NETWORK"; do
    if ! echo "$about_out" | grep -qF "$needle"; then
        echo "[-] --about-network output missing expected token: $needle"
        echo "    got: $about_out"
        exit 1
    fi
done

# 2. --about-network exits 0 (it is informational, not a failure).
if ! "$ABCPWN_BIN" --about-network >/dev/null 2>&1; then
    echo "[-] --about-network exited non-zero"
    exit 1
fi

# 3. ABCPWN_NO_NETWORK=1 overrides --allow-network. Use a network-
#    using subcommand to trigger the policy check. We expect
#    NetworkDisabled (exit code 12) when the env var is set, since
#    the env override forces allow_network off regardless of the
#    --allow-network flag. The flip case (no env, --allow-network)
#    surfaces either NetworkDisabled (when ABCPWN_WITH_NETWORK=OFF
#    so the network feature is compiled out and the command reports
#    FeatureDisabled = exit 4) OR succeeds and contacts libc.rip.
#    We assert only the env-override behavior to keep this test
#    deterministic across builds with or without ABCPWN_WITH_NETWORK.

set +e
ABCPWN_NO_NETWORK=1 "$ABCPWN_BIN" --allow-network libc download nonexistent-libc-id >/dev/null 2>&1
override_exit=$?
set -e

# Expected: env override forces allow_network=false, so the libc
# command refuses with NetworkDisabled (12). The "FeatureDisabled"
# branch (4) is a build-shape concern that should not reach this
# path because allow_network=false short-circuits before the
# feature check.
case "$override_exit" in
    12) ;;
    *) echo "[-] ABCPWN_NO_NETWORK=1 did not force NetworkDisabled (got exit $override_exit)"; exit 1 ;;
esac

# 4. On a network=no build, --allow-network warns at parse time on
#    stderr. The flag has no effect (libc download still returns
#    FeatureDisabled), so silence would be misleading; the warning
#    is what gives the operator a chance to notice the build mismatch
#    before automation builds up around a no-op flag.
#    Detect "network=no" from --version to gate this assertion to the
#    builds where it applies.
if "$ABCPWN_BIN" --no-banner --version 2>&1 | grep -q 'network=no'; then
    warn_out="$("$ABCPWN_BIN" --no-banner --allow-network errno 13 2>&1 1>/dev/null)"
    if ! echo "$warn_out" | grep -qE 'ABCPWN_WITH_NETWORK|network.*compiled out|no effect'; then
        echo "[-] --allow-network on network=no build did not warn"
        echo "    stderr was: $warn_out"
        exit 1
    fi
fi

echo "[+] about-network OK: policy block, env override forces NetworkDisabled, parse-time warning"
