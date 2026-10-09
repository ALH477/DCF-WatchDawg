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
# Dependencies: sqlite3, gawk, coreutils, iproute2, jq (optional), dcf-gate
#               (gate/dcf-gate; shared with dcf-watchdog.sh, see gate/PROVENANCE.md)
#
# This runs as root and writes into a directory that a web server reads, so:
# the output directory must be owned by the running user and not writable by
# anyone else (checked, not assumed), the temporary file is created with
# mktemp (O_EXCL, mode 0600, unpredictable name) and moved into place, every
# number is validated by dcf-gate before it is written into the JSON, and the
# database is opened read-only.
#
# TELEMETRY_PEERS controls what is published about users:
#   names  (default) each user's name, tier, VIP flag and online status
#   count  no names: "peers" is empty and "peer_counts" has totals
#   off    no peer information at all
# ============================================================================

set -euo pipefail
umask 077

# ============================================================================
# CONFIGURATION
# ============================================================================
readonly VERSION="2.4.0"
readonly DB_PATH="${DB_PATH:-/var/lib/demod/identity.db}"
readonly WEB_ROOT="${WEB_ROOT:-/var/lib/demod/public}"
readonly OUTPUT_FILE="$WEB_ROOT/status.json"
readonly TELEMETRY_PEERS="${TELEMETRY_PEERS:-names}"
TEMP_FILE=""
# This script's directory, by builtins only: no external program runs before
# harden_env has pinned PATH.
_src="${BASH_SOURCE[0]}"
[[ "$_src" == */* ]] && _src="${_src%/*}" || _src=.
SCRIPT_DIR="$(cd "$_src" && pwd)"
readonly SCRIPT_DIR
unset _src
# shellcheck source=dcf-common.sh
. "$SCRIPT_DIR/dcf-common.sh"

# ============================================================================
# CLEANUP
# ============================================================================
cleanup() {
    if [[ -n "$TEMP_FILE" ]]; then
        rm -f -- "$TEMP_FILE" 2>/dev/null || true
    fi
}
trap cleanup EXIT

die() {
    echo "dcf-telemetry: $*" >&2
    exit "${DIE_STATUS:-1}"
}

# ============================================================================
# SAFETY CHECKS
# ============================================================================
check_config() {
    case "$TELEMETRY_PEERS" in
        names|count|off) ;;
        *) DIE_STATUS=64 die "TELEMETRY_PEERS must be names, count or off; got '${TELEMETRY_PEERS:0:40}'" ;;
    esac
}

# WEB_ROOT must be a real directory that only this user can write to. Anyone
# who can create entries in it could pre-place a symlink or swap the file
# between our write and our rename.
WEB_ID=""
check_web_root() {
    # (a trailing slash would make the -L test follow the link: strip it)
    local w="$WEB_ROOT"
    while [[ "$w" == */ && "$w" != / ]]; do w=${w%/}; done
    if [[ -L "$w" ]]; then
        die "WEB_ROOT '$WEB_ROOT' is a symbolic link; refusing"
    fi
    if [[ ! -e "$w" ]]; then
        ( umask 022; mkdir -p -- "$w" )
    fi
    if [[ -L "$w" || ! -d "$w" ]]; then
        die "WEB_ROOT '$WEB_ROOT' is not a directory; refusing"
    fi
    local owner mode
    read -r owner mode < <(stat -c '%u %a' -- "$w") || die "cannot stat WEB_ROOT '$WEB_ROOT'"
    if (( owner != EUID )); then
        die "WEB_ROOT '$WEB_ROOT' is owned by uid $owner, not by the running uid $EUID; refusing"
    fi
    if (( 8#$mode & 8#022 )); then
        die "WEB_ROOT '$WEB_ROOT' is writable by group or others (mode $mode); refusing"
    fi
    if [[ -d "$OUTPUT_FILE" ]]; then
        die "'$OUTPUT_FILE' is a directory; refusing"
    fi
    WEB_ID=$(stat -c '%d:%i' -- "$w")
}

# Just before the rename: still the directory that was checked, not a link put
# in its place since. (The directories ABOVE WEB_ROOT are not checked; a volume
# root has to be writable by whoever writes the database. README, known limits.)
recheck_web_root() {
    local w="$WEB_ROOT"
    while [[ "$w" == */ && "$w" != / ]]; do w=${w%/}; done
    if [[ -L "$w" ]] || [[ "$(stat -c '%d:%i' -- "$w" 2>/dev/null)" != "$WEB_ID" ]]; then
        die "WEB_ROOT '$WEB_ROOT' changed while status.json was being written; refusing"
    fi
}

# A number from the system, destined for the JSON text unquoted. NUM gets the
# value if dcf-gate admits it as a number of the stated kind, else 0 (and a
# note on stderr). Nothing else is ever interpolated into a number position.
#   int  `dcf-gate number`: a JSON integer, 1..20 digits, no leading zero
#   dec  `dcf-gate load`:   as int (6 digits), optionally . and 1..6 digits
NUM=0
number() {
    local name="$1" v="$2" kind="$3" sub=number
    [[ "$kind" == dec ]] && sub=load
    if "$GATE_BIN" "$sub" "$v" >/dev/null 2>&1; then
        NUM="$v"
    else
        printf 'dcf-telemetry: %s is not a number (%q); publishing 0\n' "$name" "${v:0:40}" >&2
        NUM=0
    fi
}

# ============================================================================
# METRICS COLLECTION
# ============================================================================
collect_metrics() {
    # first: PATH is pinned and the inherited environment dropped, before any
    # external program runs
    harden_env || DIE_STATUS=69 die "$SAFE_WHY"
    check_config
    find_gate || DIE_STATUS=69 die "$GATE_WHY"
    check_web_root

    # System metrics
    local load mem uptime_secs
    load=$(cut -d ' ' -f 1 /proc/loadavg 2>/dev/null || echo "0")
    mem=$(free 2>/dev/null | awk '/Mem/ {printf("%.0f", $3/$2 * 100)}' || echo "0")
    uptime_secs=$(awk '{print int($1)}' /proc/uptime 2>/dev/null || echo "0")
    number load_avg "$load" dec;           load=$NUM
    number memory_pct "$mem" int;          mem=$NUM
    number uptime_secs "$uptime_secs" int; uptime_secs=$NUM

    # Network metrics
    local iface rx tx
    iface=$(ip route 2>/dev/null | awk '/default/ {print $5; exit}' || echo "eth0")
    rx=$(cat "/sys/class/net/$iface/statistics/rx_bytes" 2>/dev/null || echo "0")
    tx=$(cat "/sys/class/net/$iface/statistics/tx_bytes" 2>/dev/null || echo "0")
    number rx_bytes "$rx" int; rx=$NUM
    number tx_bytes "$tx" int; tx=$NUM

    # Active peers (count IPs in whitelist)
    local peers=0
    if nft list set ip dcf_firewall whitelist &>/dev/null; then
        peers=$(nft list set ip dcf_firewall whitelist 2>/dev/null | \
                grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l || echo "0")
        peers=${peers//[[:space:]]/}    # some wc implementations pad the count
    fi
    number active_tunnels "$peers" int; peers=$NUM

    # User data (sanitized - no sensitive info). "online" compares instants:
    # datetime() turns DCF-ID's RFC 3339 text into 'YYYY-MM-DD HH:MM:SS' (NULL
    # if it cannot), where comparing the raw text would put 'T' above ' '.
    local users="[]" counts=""
    if [[ -f "$DB_PATH" && "$TELEMETRY_PEERS" != off ]]; then
        local online_expr="datetime(last_seen) >= datetime('now', '-5 minutes')"
        if [[ "$TELEMETRY_PEERS" == names ]]; then
            if ! users=$(sqlite3 -readonly -json "$DB_PATH" "
                SELECT
                    username,
                    CASE WHEN is_vip = 1 THEN 1 ELSE 0 END as is_vip,
                    CASE
                        WHEN is_vip = 1 THEN 'vip'
                        WHEN account_balance > 0 THEN 'paid'
                        ELSE 'trial'
                    END as tier,
                    CASE
                        WHEN $online_expr THEN 'online'
                        ELSE 'offline'
                    END as status
                FROM users
                WHERE username IS NOT NULL
                ORDER BY
                    is_vip DESC,
                    CASE WHEN $online_expr THEN 0 ELSE 1 END,
                    username ASC
                LIMIT 100;
            " 2>/dev/null); then
                echo "dcf-telemetry: user query failed; publishing no peers" >&2
                users="[]"
            fi
            # Validate JSON
            if [[ -z "$users" ]] || [[ "$users" == "null" ]]; then
                users="[]"
            fi
        else
            local total online
            if total=$(sqlite3 -readonly "$DB_PATH" "SELECT count(*) FROM users WHERE username IS NOT NULL;" 2>/dev/null) &&
               online=$(sqlite3 -readonly "$DB_PATH" "SELECT count(*) FROM users WHERE username IS NOT NULL AND $online_expr;" 2>/dev/null); then
                number peer_total "$total" int;   total=$NUM
                number peer_online "$online" int; online=$NUM
                counts=",
  \"peer_counts\": {\"total\":$total,\"online\":$online}"
            else
                echo "dcf-telemetry: user count query failed; publishing no counts" >&2
            fi
        fi
    fi

    # Generate JSON
    local now
    now=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    TEMP_FILE=$(mktemp -- "$WEB_ROOT/.status.json.XXXXXXXXXX") || die "cannot create a temporary file in '$WEB_ROOT'"

    printf '%s\n' "{
  \"meta\": {
    \"updated_at\": \"$now\",
    \"node_role\": \"GATEWAY-01\",
    \"version\": \"$VERSION\",
    \"generated_by\": \"dcf-telemetry\"
  },
  \"system\": {
    \"load_avg\": $load,
    \"memory_pct\": $mem,
    \"rx_bytes\": $rx,
    \"tx_bytes\": $tx,
    \"uptime_secs\": $uptime_secs
  },
  \"network\": {
    \"active_tunnels\": $peers
  },
  \"peers\": $users$counts
}" > "$TEMP_FILE"

    # Validate JSON before deployment. A validator is required: text nobody has
    # checked is not published (the image installs jq).
    local valid=false

    if command -v jq &>/dev/null; then
        if jq empty "$TEMP_FILE" 2>/dev/null; then
            valid=true
        fi
    elif command -v python3 &>/dev/null; then
        if python3 -c "import json,sys; json.load(open(sys.argv[1], encoding='utf-8'))" "$TEMP_FILE" 2>/dev/null; then
            valid=true
        fi
    else
        echo "dcf-telemetry: no JSON validator (jq or python3) is installed; not publishing" >&2
        return 1
    fi

    if [[ "$valid" == "true" ]]; then
        recheck_web_root
        chmod 644 "$TEMP_FILE"
        mv -f -- "$TEMP_FILE" "$OUTPUT_FILE"
        TEMP_FILE=""
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

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
