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
# Dependencies: nftables, sqlite3, gawk, coreutils, iproute2, dcf-gate
#               (gate/dcf-gate, built from the vendored C; see gate/PROVENANCE.md)
#
# Everything read from the database or the environment is untrusted: an address
# reaches nft only after dcf-gate (the vendored Exsecutor unit dcf_net_gate)
# has admitted it, and DCF_PORT / SYNC_INTERVAL are checked by the same gate
# before anything touches the kernel.
#
# Testing: this file can be sourced (main runs only when it is executed), and
# DCF_WATCHDOG_ONCE=1 runs exactly one init + sync cycle and exits (status 0,
# or 1 if a sync failed). See tests/run.sh.
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
# Billing rule, duplicated from DCF-ID (src/main.rs: FREE_TIER_BYTES,
# PRICE_PER_GB / BYTES_PER_GB). See README, "The quota rule exists twice".
readonly FREE_BYTES="134217728"  # 128MB
readonly PRICE_FACTOR="4.65661287e-11"  # PRICE_PER_BYTE
readonly SYNC_INTERVAL="${SYNC_INTERVAL:-10}"
readonly LOG_LEVEL="${LOG_LEVEL:-info}"
# At most this many addresses go into one nft batch (dcf-gate --max).
readonly MAX_BATCH=4096

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR

# Exit statuses for refusing to start (sysexits.h)
readonly EX_USAGE=64        # a configuration value was refused
readonly EX_UNAVAILABLE=69  # a required helper is missing or unsafe

# ============================================================================
# LOGGING
# ============================================================================
# JSON-escape a string into JSON_ESC: backslash, double quote, and every
# control character (so a value from the database or from nft's stderr cannot
# break the line apart or forge a second log record).
json_escape() {
    local s="$1" c hex
    local LC_ALL=C
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    s=${s//$'\b'/\\b}
    s=${s//$'\f'/\\f}
    while [[ "$s" =~ ([[:cntrl:]]) ]]; do
        c=${BASH_REMATCH[1]}
        printf -v hex '\\u%04x' "'$c"
        s=${s//"$c"/$hex}
    done
    JSON_ESC=$s
}

# One line, at most N bytes (default 300): for quoting other programs' output.
bounded() {
    local s="$1" max="${2:-300}"
    s=${s//$'\n'/ | }
    if (( ${#s} > max )); then s="${s:0:max}..."; fi
    printf '%s' "$s"
}

log() {
    local level="$1"
    shift
    local timestamp
    timestamp=$(date -Iseconds)

    case "$LOG_LEVEL:$level" in
        info:debug|warn:debug|warn:info|error:debug|error:info|error:warn) return 0 ;;
    esac

    json_escape "$*"
    echo "{\"timestamp\":\"$timestamp\",\"level\":\"$level\",\"service\":\"dcf-watchdog\",\"message\":\"$JSON_ESC\"}"
}

log_info()  { log "info"  "$@"; }
log_warn()  { log "warn"  "$@"; }
log_error() { log "error" "$@"; }
log_debug() { log "debug" "$@"; }

# ============================================================================
# VALIDATION
# ============================================================================
# The one definition of "an address", "a port" and "an interval" is the
# vendored gate. Locate it, and refuse a gate that someone else could replace.
DCF_GATE_BIN=""
SAFE_WHY=""

# dir_chain_safe DIR -> 0 if DIR and every directory above it is owned by uid 0
# or the running user and cannot be written by group or others. (Whoever can
# write one of them can rename the directory below it and put their own file
# where ours was.) A world-writable directory is accepted only if it is root's
# and sticky, like /tmp: there nobody can rename entries they do not own.
dir_chain_safe() {
    local d="$1" downer dmode
    while :; do
        read -r downer dmode < <(stat -L -c '%u %a' -- "$d") || { SAFE_WHY="cannot stat $d"; return 1; }
        if (( downer != 0 && downer != EUID )); then
            SAFE_WHY="directory $d is owned by uid $downer"; return 1
        fi
        if (( 8#$dmode & 8#022 )); then
            if ! { (( 8#$dmode & 8#1000 )) && (( downer == 0 )); }; then
                SAFE_WHY="directory $d is writable by group or others (mode $dmode)"; return 1
            fi
        fi
        [[ "$d" == / ]] && return 0
        d=$(dirname -- "$d")
    done
}

# safe_exec_file PATH -> 0 if PATH is an absolute path to an executable regular
# file that only root (or this user) can change: owned by uid 0 or the running
# user, no group/world write bit, and every directory above it (after resolving
# symlinks, and also along the path as given) passes dir_chain_safe.
# On refusal, SAFE_WHY says why.
safe_exec_file() {
    local p="$1" resolved owner mode pdir
    SAFE_WHY=""
    if [[ "$p" != /* ]]; then SAFE_WHY="not an absolute path"; return 1; fi
    if [[ ! -f "$p" || ! -x "$p" ]]; then SAFE_WHY="not an executable regular file"; return 1; fi
    resolved=$(readlink -f -- "$p") || { SAFE_WHY="cannot resolve the path"; return 1; }
    read -r owner mode < <(stat -L -c '%u %a' -- "$resolved") || { SAFE_WHY="cannot stat it"; return 1; }
    if (( owner != 0 && owner != EUID )); then SAFE_WHY="owned by uid $owner"; return 1; fi
    if (( 8#$mode & 8#022 )); then SAFE_WHY="writable by group or others (mode $mode)"; return 1; fi
    dir_chain_safe "$(dirname -- "$resolved")" || return 1
    pdir=$(readlink -f -- "$(dirname -- "$p")") || { SAFE_WHY="cannot resolve the directory"; return 1; }
    dir_chain_safe "$pdir" || return 1
    return 0
}

find_gate() {
    local cand
    for cand in "${DCF_GATE:-}" /usr/local/bin/dcf-gate "$SCRIPT_DIR/gate/dcf-gate"; do
        [[ -n "$cand" && -e "$cand" ]] || continue
        if safe_exec_file "$cand"; then
            DCF_GATE_BIN="$cand"
            return 0
        fi
        log_error "dcf-gate at $cand refused: $SAFE_WHY"
        return 1
    done
    log_error "dcf-gate not found (set DCF_GATE, or build it: make -C gate)"
    return 1
}

# validate_config: refuse to start on a bad value, before anything touches nft.
validate_config() {
    local bad=0 err

    case "$LOG_LEVEL" in
        debug|info|warn|error) ;;
        *) log_error "LOG_LEVEL must be one of debug, info, warn, error; got '$LOG_LEVEL'"; bad=1 ;;
    esac

    if ! find_gate; then
        exit "$EX_UNAVAILABLE"
    fi

    if ! err=$("$DCF_GATE_BIN" port "$DCF_PORT" 2>&1 >/dev/null); then
        log_error "DCF_PORT '$DCF_PORT' refused: $(bounded "$err")"
        bad=1
    fi
    if ! err=$("$DCF_GATE_BIN" interval "$SYNC_INTERVAL" 2>&1 >/dev/null); then
        log_error "SYNC_INTERVAL '$SYNC_INTERVAL' refused: $(bounded "$err")"
        bad=1
    fi
    if [[ -n "${TELEMETRY_SCRIPT:-}" ]] && ! safe_exec_file "$TELEMETRY_SCRIPT"; then
        log_error "TELEMETRY_SCRIPT '$TELEMETRY_SCRIPT' refused: $SAFE_WHY"
        bad=1
    fi

    if (( bad )); then
        exit "$EX_USAGE"
    fi
}

# ============================================================================
# FIREWALL MANAGEMENT
# ============================================================================
# nft_apply WHAT TEXT: feed TEXT to `nft -f -` as ONE transaction. On failure,
# log nft's own words (bounded) and return 1. Nothing is discarded silently.
nft_apply() {
    local what="$1" tx="$2" err rc=0
    err=$(printf '%s\n' "$tx" | nft -f - 2>&1) || rc=$?
    if (( rc != 0 )); then
        log_error "nft refused $what (exit $rc): $(bounded "$err")"
        return 1
    fi
    return 0
}

# Install table, chain, sets and rules in ONE nft transaction: all or nothing,
# and re-runnable. A kill at any moment leaves either nothing new or the whole
# ruleset, never a chain that accepts without its drop rule; a restart repairs
# whatever was there by rebuilding the chain from scratch. (Sets keep their
# elements.) DCF_PORT is checked again here: this text is parsed by nft.
init_firewall() {
    log_info "Initializing firewall ruleset..."

    local err
    if ! err=$("$DCF_GATE_BIN" port "$DCF_PORT" 2>&1 >/dev/null); then
        log_error "refusing to build rules for port '$DCF_PORT': $(bounded "$err")"
        return 1
    fi

    local tx
    tx=$(printf '%s\n' \
        "add table ip $NFT_TABLE" \
        "add chain ip $NFT_TABLE input { type filter hook input priority 0; policy accept; }" \
        "add set ip $NFT_TABLE $NFT_SET { type ipv4_addr; flags interval; timeout 1h; }" \
        "add set ip $NFT_TABLE $NFT_SET_VIP { type ipv4_addr; flags interval; }" \
        "flush chain ip $NFT_TABLE input" \
        "add rule ip $NFT_TABLE input udp dport $DCF_PORT ip saddr @$NFT_SET_VIP accept" \
        "add rule ip $NFT_TABLE input udp dport $DCF_PORT ip saddr @$NFT_SET accept" \
        "add rule ip $NFT_TABLE input udp dport $DCF_PORT drop")

    nft_apply "the firewall ruleset" "$tx" || return 1
    log_info "Installed firewall rules for port $DCF_PORT"
}

# ============================================================================
# SYNCHRONISATION
# ============================================================================
declare -A LAST_REJECTED=()

# sync_set SET LABEL QUERY
#
# QUERY selects one column: hex(CAST(last_ip AS BLOB)), so every database value,
# whatever bytes it holds (newline, NUL, spaces), is exactly one hex line and is
# judged as the value it is. The addresses dcf-gate admits become the whole new
# content of SET in one transaction (flush + add element, atomic).
#
# Reconciliation, not accumulation:
#   * the query SUCCEEDED and yields no admitted address -> the set is flushed
#     (the last revoked user must lose access too);
#   * the query or the gate FAILED -> the set is left as it was (fail-static),
#     and an ERROR says so. Whitelist entries still expire on their own after
#     the set's 1h timeout; vip_permanent has no timeout and keeps its content
#     until a sync succeeds.
sync_set() {
    local set="$1" label="$2" query="$3"
    local rows rc=0 gout

    if [[ ! -f "$DB_PATH" ]]; then
        log_error "$label: database not found: $DB_PATH; keeping the previous $set"
        return 1
    fi

    rows=$(sqlite3 -readonly "$DB_PATH" "$query" 2>&1) || rc=$?
    if (( rc != 0 )); then
        log_error "$label: database query failed (exit $rc): $(bounded "$rows"); keeping the previous $set"
        return 1
    fi

    rc=0
    gout=$(printf '%s' "$rows${rows:+$'\n'}" | "$DCF_GATE_BIN" ipv4 --hex --max "$MAX_BATCH" --report 3 2>&1) || rc=$?

    local -a addrs=()
    local line read_n="" admitted_n="" rejected_n=0 capped_n=0
    while IFS= read -r line; do
        case "$line" in
            "dcf-gate: ipv4 read="*)
                if [[ "$line" =~ read=([0-9]+)\ admitted=([0-9]+)\ rejected=([0-9]+)\ duplicate=([0-9]+)\ capped=([0-9]+) ]]; then
                    read_n=${BASH_REMATCH[1]}; admitted_n=${BASH_REMATCH[2]}
                    rejected_n=${BASH_REMATCH[3]}; capped_n=${BASH_REMATCH[5]}
                fi ;;
            "dcf-gate: reject "*) log_debug "$label: ${line#dcf-gate: }" ;;
            "dcf-gate: rejected-by "*) log_debug "$label: ${line#dcf-gate: }" ;;
            "dcf-gate: "*) log_warn "$label: $line" ;;
            "") ;;
            *) addrs+=("$line") ;;
        esac
    done <<<"$gout"

    if (( rc != 0 )) || [[ -z "$read_n" ]] || (( ${#addrs[@]} != admitted_n )); then
        log_error "$label: dcf-gate failed (exit $rc): $(bounded "$gout"); keeping the previous $set"
        return 1
    fi

    if (( rejected_n > 0 )); then
        # Warn when the number changes, debug while it stays the same, so one
        # permanently bad row does not fill the log every cycle.
        local lvl=log_debug
        [[ "${LAST_REJECTED[$set]:-0}" != "$rejected_n" ]] && lvl=log_warn
        "$lvl" "$label: gate rejected $rejected_n of $read_n address value(s) from the database"
    fi
    LAST_REJECTED[$set]=$rejected_n
    if (( capped_n > 0 )); then
        log_error "$label: batch cap of $MAX_BATCH reached: capped $capped_n further address(es); they are NOT in $set"
    fi

    local tx="flush set ip $NFT_TABLE $set"
    if (( ${#addrs[@]} > 0 )); then
        local ip_list
        ip_list=$(IFS=','; echo "${addrs[*]}")
        tx+=$'\n'"add element ip $NFT_TABLE $set { $ip_list }"
    fi
    nft_apply "the $set update" "$tx" || return 1

    if (( ${#addrs[@]} > 0 )); then
        log_debug "$label updated: ${#addrs[@]} IPs"
    else
        log_debug "$label cleared (no authorized IPs)"
    fi
    return 0
}

sync_whitelist() {
    # Authorized addresses:
    # - VIP users (unlimited)
    # - Trial users within 128MB limit
    # - Paid users with sufficient balance
    # "Seen in the last hour" compares instants: datetime() normalises
    # DCF-ID's RFC 3339 text (2026-10-09T01:22:33.123456789+00:00) to
    # 'YYYY-MM-DD HH:MM:SS'; NULL and unparseable last_seen are NULL, so stale.
    local query="
        SELECT DISTINCT hex(CAST(last_ip AS BLOB))
        FROM users
        WHERE last_ip IS NOT NULL
          AND last_ip != ''
          AND datetime(last_seen) >= datetime('now', '-1 hour')
          AND (
              is_vip = 1
              OR data_used <= $FREE_BYTES
              OR ((data_used - $FREE_BYTES) * $PRICE_FACTOR) <= account_balance
          );
    "
    sync_set "$NFT_SET" "Whitelist" "$query"
}

sync_vip_list() {
    local query="SELECT DISTINCT hex(CAST(last_ip AS BLOB)) FROM users WHERE is_vip = 1 AND last_ip IS NOT NULL AND last_ip != '';"
    sync_set "$NFT_SET_VIP" "VIP list" "$query"
}

# One reconciliation of both sets. Returns 1 if either failed (and kept its
# previous content).
sync_cycle() {
    local rc=0
    sync_vip_list || rc=1
    sync_whitelist || rc=1
    return "$rc"
}

# Run the telemetry script if configured, and only if it is still a file that
# nobody but root can have changed (checked every cycle, not once).
run_telemetry() {
    [[ -n "${TELEMETRY_SCRIPT:-}" ]] || return 0
    if ! safe_exec_file "$TELEMETRY_SCRIPT"; then
        log_error "TELEMETRY_SCRIPT '$TELEMETRY_SCRIPT' refused, not run: $SAFE_WHY"
        return 0
    fi
    local err
    if ! err=$("$TELEMETRY_SCRIPT" 2>&1 >&3); then
        log_warn "Telemetry script failed: $(bounded "$err")"
    fi
} 3>&1

# ============================================================================
# SIGNAL HANDLERS
# ============================================================================
shutdown_handler() {
    log_info "Received shutdown signal"
    log_info "Watchdog stopped"
    exit 0
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    trap shutdown_handler SIGTERM SIGINT SIGHUP

    validate_config

    log_info "DeMoD Watchdog v$VERSION starting..."
    log_info "Database: $DB_PATH"
    log_info "Port: $DCF_PORT"
    log_info "Sync interval: ${SYNC_INTERVAL}s"

    # Initialize firewall
    if ! init_firewall; then
        log_error "Could not install the firewall ruleset; not starting"
        exit 1
    fi

    log_info "Watchdog active"

    # Main loop: every cycle reconciles both sets with the database
    local cycle=0 failed=0
    while true; do
        cycle=$((cycle + 1))

        failed=0
        if ! sync_cycle; then
            failed=1
            log_warn "Sync failed (cycle $cycle)"
        fi

        # Run telemetry if configured
        run_telemetry

        # Test hook: stop after the first full cycle
        if [[ "${DCF_WATCHDOG_ONCE:-}" == "1" ]]; then
            log_info "DCF_WATCHDOG_ONCE set: single cycle done"
            exit "$failed"
        fi

        sleep "$SYNC_INTERVAL"
    done
}

# Run only when executed; sourcing (the test suite does) defines the functions
# and nothing else.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
