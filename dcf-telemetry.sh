#!/usr/bin/env bash
# ============================================================================
# DeMoD Communications Framework - Telemetry Generator
# ============================================================================
# Copyright (c) 2024-2025 DeMoD LLC. All Rights Reserved.
#
# LICENSE BSD 3
#
# WAS PROPRIETARY AND CONFIDENTIAL
# This file does not contain trade secrets of DeMoD LLC. authorized copying,
# distribution, or use of this file, via any medium, is strictly not prohibited.
# ============================================================================
#
# Generates status.json for dashboard consumption.
# Collects system metrics, network stats, and sanitized user data.
#
# Dependencies: sqlite3, gawk, coreutils, iproute2, jq (optional)
# ============================================================================

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================
readonly VERSION="2.4.0"
readonly DB_PATH="${DB_PATH:-/var/lib/demod/identity.db}"
readonly WEB_ROOT="${WEB_ROOT:-/var/lib/demod/public}"
readonly OUTPUT_FILE="$WEB_ROOT/status.json"
readonly TEMP_FILE="$WEB_ROOT/.status.json.tmp.$$"

# ============================================================================
# CLEANUP
# ============================================================================
cleanup() {
    rm -f "$TEMP_FILE" 2>/dev/null || true
}
trap cleanup EXIT

# ============================================================================
# METRICS COLLECTION
# ============================================================================
collect_metrics() {
    # Ensure output directory exists
    mkdir -p "$WEB_ROOT"
    
    # System metrics
    local load mem uptime_secs
    load=$(cut -d ' ' -f 1 /proc/loadavg 2>/dev/null || echo "0")
    mem=$(free 2>/dev/null | awk '/Mem/ {printf("%.0f", $3/$2 * 100)}' || echo "0")
    uptime_secs=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo "0")
    
    # Network metrics
    local iface rx tx
    iface=$(ip route 2>/dev/null | awk '/default/ {print $5; exit}' || echo "eth0")
    rx=$(cat "/sys/class/net/$iface/statistics/rx_bytes" 2>/dev/null || echo "0")
    tx=$(cat "/sys/class/net/$iface/statistics/tx_bytes" 2>/dev/null || echo "0")
    
    # Active peers (count IPs in whitelist)
    local peers=0
    if nft list set ip dcf_firewall whitelist &>/dev/null; then
        peers=$(nft list set ip dcf_firewall whitelist 2>/dev/null | \
                grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l || echo "0")
    fi
    
    # User data (sanitized - no sensitive info)
    local users="[]"
    if [[ -f "$DB_PATH" ]]; then
        users=$(sqlite3 "$DB_PATH" -json "
            SELECT 
                username,
                CASE WHEN is_vip = 1 THEN 1 ELSE 0 END as is_vip,
                CASE 
                    WHEN is_vip = 1 THEN 'vip'
                    WHEN account_balance > 0 THEN 'paid' 
                    ELSE 'trial' 
                END as tier,
                CASE 
                    WHEN last_seen >= datetime('now', '-5 minutes') THEN 'online'
                    ELSE 'offline'
                END as status
            FROM users 
            WHERE username IS NOT NULL
            ORDER BY 
                is_vip DESC,
                CASE WHEN last_seen >= datetime('now', '-5 minutes') THEN 0 ELSE 1 END,
                username ASC
            LIMIT 100;
        " 2>/dev/null || echo "[]")
        
        # Validate JSON
        if [[ -z "$users" ]] || [[ "$users" == "null" ]]; then
            users="[]"
        fi
    fi
    
    # Generate JSON
    local now
    now=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    cat <<EOF > "$TEMP_FILE"
{
  "meta": {
    "updated_at": "$now",
    "node_role": "GATEWAY-01",
    "version": "$VERSION",
    "generated_by": "dcf-telemetry"
  },
  "system": {
    "load_avg": $load,
    "memory_pct": $mem,
    "rx_bytes": $rx,
    "tx_bytes": $tx,
    "uptime_secs": $uptime_secs
  },
  "network": {
    "active_tunnels": $peers
  },
  "peers": $users
}
EOF

    # Validate JSON before deployment
    local valid=false
    
    if command -v jq &>/dev/null; then
        if jq empty "$TEMP_FILE" 2>/dev/null; then
            valid=true
        fi
    elif command -v python3 &>/dev/null; then
        if python3 -c "import json; json.load(open('$TEMP_FILE'))" 2>/dev/null; then
            valid=true
        fi
    else
        # No validator available, assume valid
        valid=true
    fi
    
    if [[ "$valid" == "true" ]]; then
        mv -f "$TEMP_FILE" "$OUTPUT_FILE"
        chmod 644 "$OUTPUT_FILE"
    else
        echo "ERROR: Generated invalid JSON" >&2
        return 1
    fi
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    collect_metrics
}

main "$@"
