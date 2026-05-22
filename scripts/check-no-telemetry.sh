#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 manop55555
#
# Verify no telemetry library imports or unexpected HTTPS URLs in
# the source tree. Per CLAUDE.md the only files allowed to contain
# network code are src/commands/libc.cpp and src/commands/pwninit.cpp;
# those URLs must point at the project's own GitHub or at the
# libc-database service.

set -euo pipefail

# Concrete SDK function call patterns rather than bare brand names.
# `segment` alone collides with LIEF's segments(); telemetry SDKs use
# concrete suffixes like `_track` / `_capture` / `_identify`.
TELEMETRY_LIBS='(sentry_init|sentry_capture_event|rollbar_init|rollbar_notify|bugsnag_init|bugsnag_notify|appsignal_init|posthog_init|posthog_capture|amplitude_init|amplitude_track|mixpanel_init|mixpanel_track|segment_track|segment_identify|google_analytics_init|gtag_init|telemetry_init|crash_report_init)'

ALLOWED_URL_HOSTS='(libc\.rip|libc-database|raw\.githubusercontent\.com/manop55555|github\.com/manop55555|apache\.org/licenses)'

# 1. Telemetry library calls anywhere in src/ or include/.
tele=$(grep -rnE "$TELEMETRY_LIBS" \
    --include='*.cpp' --include='*.hpp' \
    src/ include/ 2>/dev/null || true)
if [ -n "$tele" ]; then
    echo "[-] telemetry library calls found:"
    echo "$tele"
    exit 1
fi

# 2. Every HTTPS URL in source code is allowlisted.
urls=$(grep -rohE 'https://[A-Za-z0-9._/%-]+' \
    --include='*.cpp' --include='*.hpp' \
    src/ include/ 2>/dev/null | sort -u || true)

failed=0
while IFS= read -r url; do
    [ -z "$url" ] && continue
    if ! echo "$url" | grep -qE "$ALLOWED_URL_HOSTS"; then
        echo "[-] unexpected URL in source: $url"
        failed=1
    fi
done <<< "$urls"

if [ "$failed" -ne 0 ]; then
    exit 1
fi

echo "[+] no telemetry, no unexpected URLs"
