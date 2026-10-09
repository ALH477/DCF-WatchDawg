#!/usr/bin/env bash
# ============================================================================
# DeMoD Communications Framework - Container health check
# ============================================================================
# Copyright (c) 2024-2025 DeMoD LLC. All Rights Reserved. LICENSE BSD 3
# ============================================================================
# Exit 0 if the watchdog is doing its job, 1 (with one line saying why) if not.
#   * the dcf_firewall input chain exists and still has its drop rule for
#     DCF_PORT (someone flushed the ruleset, or the install never happened);
#   * if telemetry is configured (TELEMETRY_SCRIPT is set), $WEB_ROOT/status.json
#     exists and is no older than max(3 x SYNC_INTERVAL, 60) seconds. The
#     telemetry script runs once per sync cycle, so a stale file means the
#     loop is stuck or failing.
# Uses the same environment as dcf-watchdog.sh and the same defaults.
# ============================================================================
set -euo pipefail

DCF_PORT="${DCF_PORT:-7777}"
SYNC_INTERVAL="${SYNC_INTERVAL:-10}"
WEB_ROOT="${WEB_ROOT:-/var/lib/demod/public}"

unhealthy() { echo "unhealthy: $*"; exit 1; }

[[ "$DCF_PORT" =~ ^[1-9][0-9]{0,4}$ ]] || unhealthy "DCF_PORT '${DCF_PORT:0:20}' is not a port"

chain=$(nft list chain ip dcf_firewall input 2>&1) || unhealthy "no dcf_firewall input chain: ${chain:0:120}"
grep -Eq "^[[:space:]]*udp dport $DCF_PORT drop[[:space:]]*$" <<<"$chain" ||
    unhealthy "the input chain has no 'udp dport $DCF_PORT drop' rule"

if [[ -n "${TELEMETRY_SCRIPT:-}" ]]; then
    [[ "$SYNC_INTERVAL" =~ ^[1-9][0-9]{0,3}$ ]] || SYNC_INTERVAL=10
    max=$(( 3 * SYNC_INTERVAL ))
    (( max >= 60 )) || max=60
    f="$WEB_ROOT/status.json"
    [[ -f "$f" ]] || unhealthy "$f does not exist"
    mtime=$(stat -c %Y -- "$f") || unhealthy "cannot stat $f"
    age=$(( $(date +%s) - mtime ))
    (( age <= max )) || unhealthy "$f is ${age}s old (limit ${max}s)"
fi
echo "healthy"
