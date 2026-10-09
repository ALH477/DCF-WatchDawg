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
# A database query that has not answered in this many seconds is a failed query.
# The firewall install waits for the first one, so it must not wait forever.
readonly QUERY_TIMEOUT="${DCF_QUERY_TIMEOUT:-10}"

# This script's directory, by builtins only: no external program runs before
# harden_env has pinned PATH.
_src="${BASH_SOURCE[0]}"
[[ "$_src" == */* ]] && _src="${_src%/*}" || _src=.
SCRIPT_DIR="$(cd "$_src" && pwd)"
readonly SCRIPT_DIR
unset _src
# shellcheck source=dcf-common.sh
. "$SCRIPT_DIR/dcf-common.sh"

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
# The one definition of "an address", "a port" and "an interval" is the vendored
# gate (find_gate, in dcf-common.sh, locates it and refuses one that someone else
# could replace).

# validate_config: refuse to start on a bad value, before anything touches nft.
validate_config() {
    local bad=0 err

    case "$LOG_LEVEL" in
        debug|info|warn|error) ;;
        *) log_error "LOG_LEVEL must be one of debug, info, warn, error; got '$LOG_LEVEL'"; bad=1 ;;
    esac

    if ! find_gate; then
        log_error "$GATE_WHY"
        exit "$EX_UNAVAILABLE"
    fi

    if ! err=$("$GATE_BIN" port "$DCF_PORT" 2>&1 >/dev/null); then
        log_error "DCF_PORT '$DCF_PORT' refused: $(bounded "$err")"
        bad=1
    fi
    if ! err=$("$GATE_BIN" interval "$SYNC_INTERVAL" 2>&1 >/dev/null); then
        log_error "SYNC_INTERVAL '$SYNC_INTERVAL' refused: $(bounded "$err")"
        bad=1
    fi
    if ! err=$("$GATE_BIN" interval "$QUERY_TIMEOUT" 2>&1 >/dev/null); then
        log_error "DCF_QUERY_TIMEOUT '$QUERY_TIMEOUT' refused: $(bounded "$err")"
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

# ============================================================================
# SYNCHRONISATION
# ============================================================================
declare -A LAST_REJECTED=()

# Who is authorized. `data_used` and `account_balance` are compared only as
# numbers, never as text (SQLite sorts every number below every text, so a text
# balance would cover any bill), and usage below zero is not "under the free
# tier": such a row is corrupt, and a corrupt row is not a reason to let anyone
# in. NULL stays what it was, a refusal; a VIP is unconditional.
# "Seen in the last hour" compares instants: datetime() normalises DCF-ID's RFC
# 3339 text (2026-10-09T01:22:33.123456789+00:00) to 'YYYY-MM-DD HH:MM:SS';
# NULL and unparseable last_seen are NULL, so stale.
# Each query selects ONE column, hex(CAST(last_ip AS BLOB)), so every database
# value, whatever bytes it holds (newline, NUL, spaces), is exactly one hex line
# and is judged as the value it is.
readonly WHITELIST_QUERY="
    SELECT DISTINCT hex(CAST(last_ip AS BLOB))
    FROM users
    WHERE last_ip IS NOT NULL
      AND last_ip != ''
      AND datetime(last_seen) >= datetime('now', '-1 hour')
      AND (
          is_vip = 1
          OR (
              typeof(data_used) IN ('integer', 'real')
              AND data_used >= 0
              AND (
                  data_used <= $FREE_BYTES
                  OR (
                      typeof(account_balance) IN ('integer', 'real')
                      AND ((data_used - $FREE_BYTES) * $PRICE_FACTOR) <= account_balance
                  )
              )
          )
      );
"
readonly VIP_QUERY="SELECT DISTINCT hex(CAST(last_ip AS BLOB)) FROM users WHERE is_vip = 1 AND last_ip IS NOT NULL AND last_ip != '';"

# collect_set SET LABEL QUERY
# Run QUERY, pass its rows through the gate, and describe the result without
# touching the kernel: returns 0 with COLLECTED_N (how many addresses) and
# COLLECTED_ELEMS ("" or an `add element` line for SET); returns 1, with an ERROR
# logged and nothing changed, if the database or the gate failed.
collect_set() {
    local set="$1" label="$2" query="$3"
    local rows rc=0 gout
    COLLECTED_N=0
    COLLECTED_ELEMS=""

    if [[ ! -f "$DB_PATH" ]]; then
        log_error "$label: database not found: $DB_PATH; keeping the previous $set"
        return 1
    fi

    rows=$(timeout "$QUERY_TIMEOUT" sqlite3 -readonly "$DB_PATH" "$query" 2>&1) || rc=$?
    if (( rc != 0 )); then
        log_error "$label: database query failed (exit $rc): $(bounded "$rows"); keeping the previous $set"
        return 1
    fi

    rc=0
    gout=$(printf '%s' "$rows${rows:+$'\n'}" | "$GATE_BIN" ipv4 --hex --max "$MAX_BATCH" --report 3 2>&1) || rc=$?

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

    COLLECTED_N=${#addrs[@]}
    if (( COLLECTED_N > 0 )); then
        local ip_list
        ip_list=$(IFS=','; echo "${addrs[*]}")
        COLLECTED_ELEMS="add element ip $NFT_TABLE $set { $ip_list }"
    fi
    return 0
}

# sync_set SET LABEL QUERY
# Reconciliation, not accumulation: the addresses the gate admits become the
# whole new content of SET in one transaction (flush + add element, atomic).
#   * the query SUCCEEDED and yields no admitted address -> the set is flushed
#     (the last revoked user must lose access too);
#   * the query or the gate FAILED -> the set is left as it was (fail-static),
#     and an ERROR says so. Whitelist entries still expire on their own after
#     the set's 1h timeout; vip_permanent has no timeout and keeps its content
#     until a sync succeeds.
sync_set() {
    local set="$1" label="$2" query="$3"
    collect_set "$set" "$label" "$query" || return 1

    local tx="flush set ip $NFT_TABLE $set"
    if [[ -n "$COLLECTED_ELEMS" ]]; then
        tx+=$'\n'"$COLLECTED_ELEMS"
    fi
    nft_apply "the $set update" "$tx" || return 1

    if (( COLLECTED_N > 0 )); then
        log_debug "$label updated: $COLLECTED_N IPs"
    else
        log_debug "$label cleared (no authorized IPs)"
    fi
    return 0
}

sync_whitelist() { sync_set "$NFT_SET" "Whitelist" "$WHITELIST_QUERY"; }
sync_vip_list()  { sync_set "$NFT_SET_VIP" "VIP list" "$VIP_QUERY"; }

# One reconciliation of both sets. Returns 1 if either failed (and kept its
# previous content).
sync_cycle() {
    local rc=0
    sync_vip_list || rc=1
    sync_whitelist || rc=1
    return "$rc"
}

# ============================================================================
# FIREWALL INSTALL
# ============================================================================
# The table dcf_firewall belongs to this daemon. Every start REBUILDS it, in ONE
# nft transaction:
#
#     add table ip dcf_firewall          \ makes the next line safe when the
#     delete table ip dcf_firewall       / table did not exist yet
#     add table ip dcf_firewall          and then the whole definition, with the
#     add chain ... add set ... add rule ...   initial elements of both sets
#
# Whatever was there before (a set with other flags, a chain on another hook,
# extra rules, extra chains) goes with the old table, so no such leftover can make
# the install fail or leave the port open. The batch is atomic: a packet is judged
# by the old ruleset or by the new one, never by none, and a kill at any moment
# leaves one or the other whole.
#
# The rebuilt sets are not empty: their contents are read from the database just
# before and go in the same batch, so a restart does not make anyone wait for the
# first sync. If the database cannot be read at that moment the sets come up EMPTY
# (closed: nobody is let in) and the loop's first cycle retries; the drop rule does
# not wait for the database beyond QUERY_TIMEOUT seconds per query.
#
# If the install is still refused (nft missing, no CAP_NET_ADMIN, a kernel without
# nf_tables) the batch changed nothing, the daemon exits 1 with nft's own error,
# and the host's own firewall policy stays in force: the port is exactly as open
# as it was before.
init_firewall() {
    log_info "Initializing firewall ruleset..."

    local err
    if ! err=$("$GATE_BIN" port "$DCF_PORT" 2>&1 >/dev/null); then
        log_error "refusing to build rules for port '$DCF_PORT': $(bounded "$err")"
        return 1
    fi

    local vip_elems="" wl_elems="" empty_start=0
    if collect_set "$NFT_SET_VIP" "VIP list" "$VIP_QUERY"; then vip_elems=$COLLECTED_ELEMS; else empty_start=1; fi
    if collect_set "$NFT_SET" "Whitelist" "$WHITELIST_QUERY"; then wl_elems=$COLLECTED_ELEMS; else empty_start=1; fi
    if (( empty_start )); then
        log_warn "starting with empty address sets (the database could not be read): nobody is let in until a sync succeeds"
    fi

    local tx
    tx=$(printf '%s\n' \
        "add table ip $NFT_TABLE" \
        "delete table ip $NFT_TABLE" \
        "add table ip $NFT_TABLE" \
        "add chain ip $NFT_TABLE input { type filter hook input priority 0; policy accept; }" \
        "add set ip $NFT_TABLE $NFT_SET { type ipv4_addr; flags interval; timeout 1h; }" \
        "add set ip $NFT_TABLE $NFT_SET_VIP { type ipv4_addr; flags interval; }" \
        "add rule ip $NFT_TABLE input udp dport $DCF_PORT ip saddr @$NFT_SET_VIP accept" \
        "add rule ip $NFT_TABLE input udp dport $DCF_PORT ip saddr @$NFT_SET accept" \
        "add rule ip $NFT_TABLE input udp dport $DCF_PORT drop")
    [[ -z "$vip_elems" ]] || tx+=$'\n'"$vip_elems"
    [[ -z "$wl_elems" ]] || tx+=$'\n'"$wl_elems"

    nft_apply "the firewall ruleset" "$tx" || return 1
    log_info "Installed firewall rules for port $DCF_PORT"
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

    # first: PATH is pinned and the inherited environment dropped, before any
    # external program runs
    if ! harden_env; then
        log_error "$SAFE_WHY"
        exit "$EX_UNAVAILABLE"
    fi
    validate_config

    log_info "DeMoD Watchdog v$VERSION starting..."
    log_info "Database: $DB_PATH"
    log_info "Port: $DCF_PORT"
    log_info "Sync interval: ${SYNC_INTERVAL}s"

    # Initialize firewall
    if ! init_firewall; then
        log_error "Could not install the firewall ruleset; not starting. The host's own firewall policy stays in force: UDP port $DCF_PORT is NOT protected by this daemon"
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
