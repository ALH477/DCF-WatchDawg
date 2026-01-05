#!/usr/bin/env bash
# ============================================================================
# DeMoD Communications Framework - Firewall Watchdog
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
# Synchronizes SQLite user database with kernel-level nftables firewall.
# Runs every 10 seconds to update the IP whitelist for UDP game traffic.
#
# Dependencies: nftables, sqlite3, gawk, coreutils, iproute2
# ============================================================================

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================
readonly VERSION="2.4.0"
readonly DB_PATH="${DB_PATH:-/var/lib/demod/identity.db}"
readonly NFT_TABLE="dcf_firewall"
readonly NFT_SET="whitelist"
readonly NFT_SET_VIP="vip_permanent"
readonly DCF_PORT="${DCF_PORT:-7777}"
readonly FREE_BYTES="134217728"  # 128MB
readonly PRICE_FACTOR="4.65661287e-11"  # PRICE_PER_BYTE
readonly SYNC_INTERVAL="${SYNC_INTERVAL:-10}"
readonly LOG_LEVEL="${LOG_LEVEL:-info}"

# ============================================================================
# LOGGING
# ============================================================================
log() {
    local level="$1"
    shift
    local timestamp
    timestamp=$(date -Iseconds)
    
    case "$LOG_LEVEL" in
        debug) ;; # Log everything
        info)  [[ "$level" == "debug" ]] && return ;;
        warn)  [[ "$level" =~ ^(debug|info)$ ]] && return ;;
        error) [[ "$level" =~ ^(debug|info|warn)$ ]] && return ;;
    esac
    
    echo "{\"timestamp\":\"$timestamp\",\"level\":\"$level\",\"service\":\"dcf-watchdog\",\"message\":\"$*\"}"
}

log_info()  { log "info"  "$@"; }
log_warn()  { log "warn"  "$@"; }
log_error() { log "error" "$@"; }
log_debug() { log "debug" "$@"; }

# ============================================================================
# VALIDATION
# ============================================================================
validate_ipv4() {
    local ip="$1"
    
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 1
    fi
    
    local IFS='.'
    read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if (( octet > 255 )); then
            return 1
        fi
    done
    
    return 0
}

# ============================================================================
# FIREWALL MANAGEMENT
# ============================================================================
init_firewall() {
    log_info "Initializing firewall ruleset..."
    
    # Create table
    if ! nft list table ip "$NFT_TABLE" &>/dev/null; then
        nft add table ip "$NFT_TABLE"
        log_info "Created nftables table: $NFT_TABLE"
    fi
    
    # Create input chain
    if ! nft list chain ip "$NFT_TABLE" input &>/dev/null; then
        nft add chain ip "$NFT_TABLE" input "{ type filter hook input priority 0; policy accept; }"
        log_info "Created input chain"
    fi
    
    # Create whitelist set (dynamic)
    if ! nft list set ip "$NFT_TABLE" "$NFT_SET" &>/dev/null; then
        nft add set ip "$NFT_TABLE" "$NFT_SET" "{ type ipv4_addr; flags interval; timeout 1h; }"
        log_info "Created whitelist set: $NFT_SET"
    fi
    
    # Create VIP set (permanent)
    if ! nft list set ip "$NFT_TABLE" "$NFT_SET_VIP" &>/dev/null; then
        nft add set ip "$NFT_TABLE" "$NFT_SET_VIP" "{ type ipv4_addr; flags interval; }"
        log_info "Created VIP set: $NFT_SET_VIP"
    fi
    
    # Add rules if not present
    local rules
    rules=$(nft list chain ip "$NFT_TABLE" input 2>/dev/null || echo "")
    
    if ! echo "$rules" | grep -q "udp dport $DCF_PORT"; then
        # VIP bypass (checked first)
        nft add rule ip "$NFT_TABLE" input udp dport "$DCF_PORT" ip saddr @"$NFT_SET_VIP" accept
        # Standard whitelist
        nft add rule ip "$NFT_TABLE" input udp dport "$DCF_PORT" ip saddr @"$NFT_SET" accept
        # Drop everything else
        nft add rule ip "$NFT_TABLE" input udp dport "$DCF_PORT" drop
        log_info "Installed firewall rules for port $DCF_PORT"
    fi
}

sync_whitelist() {
    if [[ ! -f "$DB_PATH" ]]; then
        log_warn "Database not found: $DB_PATH"
        return 1
    fi
    
    # Query for authorized IPs:
    # - VIP users (unlimited)
    # - Trial users within 128MB limit
    # - Paid users with sufficient balance
    local query="
        SELECT DISTINCT last_ip 
        FROM users 
        WHERE last_ip IS NOT NULL 
          AND last_ip != ''
          AND last_seen >= datetime('now', '-1 hour')
          AND (
              is_vip = 1 
              OR data_used <= $FREE_BYTES 
              OR ((data_used - $FREE_BYTES) * $PRICE_FACTOR) <= account_balance
          );
    "
    
    local ips
    if ! ips=$(sqlite3 -readonly "$DB_PATH" "$query" 2>/dev/null); then
        log_error "Database query failed"
        return 1
    fi
    
    # Validate and collect IPs
    local valid_ips=()
    while IFS= read -r ip; do
        ip="${ip//[[:space:]]/}"
        if [[ -n "$ip" ]] && validate_ipv4 "$ip"; then
            valid_ips+=("$ip")
        fi
    done <<< "$ips"
    
    local ip_count=${#valid_ips[@]}
    
    if [[ $ip_count -eq 0 ]]; then
        nft flush set ip "$NFT_TABLE" "$NFT_SET" 2>/dev/null || true
        log_debug "Whitelist cleared (no authorized IPs)"
    else
        # Build atomic update
        local ip_list
        ip_list=$(IFS=','; echo "${valid_ips[*]}")
        
        # Atomic flush and repopulate
        if echo "flush set ip $NFT_TABLE $NFT_SET; add element ip $NFT_TABLE $NFT_SET { $ip_list }" | nft -f - 2>/dev/null; then
            log_debug "Whitelist updated: $ip_count IPs"
        else
            log_error "Failed to update whitelist"
            return 1
        fi
    fi
    
    return 0
}

sync_vip_list() {
    if [[ ! -f "$DB_PATH" ]]; then
        return 1
    fi
    
    local query="SELECT DISTINCT last_ip FROM users WHERE is_vip = 1 AND last_ip IS NOT NULL AND last_ip != '';"
    local ips
    
    if ! ips=$(sqlite3 -readonly "$DB_PATH" "$query" 2>/dev/null); then
        return 1
    fi
    
    local valid_ips=()
    while IFS= read -r ip; do
        ip="${ip//[[:space:]]/}"
        if [[ -n "$ip" ]] && validate_ipv4 "$ip"; then
            valid_ips+=("$ip")
        fi
    done <<< "$ips"
    
    if [[ ${#valid_ips[@]} -gt 0 ]]; then
        local ip_list
        ip_list=$(IFS=','; echo "${valid_ips[*]}")
        echo "flush set ip $NFT_TABLE $NFT_SET_VIP; add element ip $NFT_TABLE $NFT_SET_VIP { $ip_list }" | nft -f - 2>/dev/null || true
    fi
}

# ============================================================================
# SIGNAL HANDLERS
# ============================================================================
shutdown_handler() {
    log_info "Received shutdown signal"
    log_info "Watchdog stopped"
    exit 0
}

trap shutdown_handler SIGTERM SIGINT SIGHUP

# ============================================================================
# MAIN
# ============================================================================
main() {
    log_info "DeMoD Watchdog v$VERSION starting..."
    log_info "Database: $DB_PATH"
    log_info "Port: $DCF_PORT"
    log_info "Sync interval: ${SYNC_INTERVAL}s"
    
    # Initialize firewall
    init_firewall
    
    # Initial sync
    sync_vip_list
    sync_whitelist
    
    log_info "Watchdog active"
    
    # Main loop
    local cycle=0
    while true; do
        ((cycle++)) || true
        
        # Sync whitelist every cycle
        if ! sync_whitelist; then
            log_warn "Whitelist sync failed (cycle $cycle)"
        fi
        
        # Sync VIP list less frequently (every 6 cycles = 60s)
        if (( cycle % 6 == 0 )); then
            sync_vip_list
        fi
        
        # Run telemetry if configured
        if [[ -n "${TELEMETRY_SCRIPT:-}" ]] && [[ -x "$TELEMETRY_SCRIPT" ]]; then
            "$TELEMETRY_SCRIPT" 2>/dev/null || log_warn "Telemetry script failed"
        fi
        
        sleep "$SYNC_INTERVAL"
    done
}

main "$@"
