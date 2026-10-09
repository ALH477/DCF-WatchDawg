#!/usr/bin/env bash
# W2 -- revocation is enforced when the list becomes empty; a failed query keeps
# the previous state and says so; an nft failure is never swallowed.
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"; t_start "$@"

db=$TMP/id.db
export DB_PATH=$db LOG_LEVEL=info

if [[ "$DCF_TEST_NFT_MODE" != real ]]; then
    mkdb "$db" '["vip","8.8.8.8","now",0,0,1]'
    wd_once >/dev/null
    mkdb "$db" '["vip","8.8.8.8","now",0,0,0]'     # the last VIP is revoked
    : > "$NFT_SHIM_LOG"
    wd_once >/dev/null
    if grep -q 'flush set ip dcf_firewall vip_permanent' "$NFT_SHIM_LOG"; then
        ok "(shim) revoking the last VIP sends a flush of vip_permanent"
    else
        bad "(shim) revoking the last VIP sends a flush of vip_permanent" "$(cat "$NFT_SHIM_LOG")"
    fi
    skip "kernel state, fail-static and error-logging cases" "need a real nft"
    t_finish; exit
fi

fault_path

# -- 1. the last VIP is revoked ------------------------------------------------
nft_reset
mkdb "$db" '["vip","8.8.8.8","now",0,0,1]' '["bob","8.8.4.4","now",0,0,0]'
out=$(wd_once)
assert_eq "VIP 8.8.8.8 is in vip_permanent" "8.8.8.8" "$(set_elems vip_permanent)"
mkdb "$db" '["vip","8.8.8.8","now",0,0,0]' '["bob","8.8.4.4","now",0,0,0]'
out=$(wd_once)
assert_eq "last VIP revoked: vip_permanent is emptied on the next sync" "" "$(set_elems vip_permanent)"

# -- 2. one of two VIPs revoked (worked before; must keep working) ---------------
nft_reset
mkdb "$db" '["v1","8.8.8.8","now",0,0,1]' '["v2","1.1.1.1","now",0,0,1]'
wd_once >/dev/null
mkdb "$db" '["v1","8.8.8.8","now",0,0,1]' '["v2","1.1.1.1","now",0,0,0]'
wd_once >/dev/null
assert_eq "one of two VIPs revoked: only the other remains" "8.8.8.8" "$(set_elems vip_permanent)"

# -- 3. the whitelist empties too (worked before) -------------------------------
nft_reset
mkdb "$db" '["bob","8.8.4.4","now",0,0,0]'
wd_once >/dev/null
assert_eq "bob is whitelisted" "8.8.4.4" "$(set_elems whitelist)"
mkdb "$db" '["bob","8.8.4.4","now",999999999999,0,0]'    # past the free tier, no balance
wd_once >/dev/null
assert_eq "bob out of quota: whitelist emptied" "" "$(set_elems whitelist)"

# -- 4. a FAILED query keeps the previous state and logs an error ---------------
# This is about a RUNNING daemon: between two of its cycles the database goes bad.
# (A restart rebuilds the table, and with an unreadable database the sets come up
# empty: tests/t_firewall.sh.) So here the daemon really loops, one cycle a second.
daemon_start() {   # daemon_start -> background daemon, log in $TMP/daemon.log, pid in DPID
    : > "$TMP/daemon.log"
    SYNC_INTERVAL=1 LOG_LEVEL=debug "$BASH" "$WATCHDOG" > "$TMP/daemon.log" 2>&1 &
    DPID=$!
}
daemon_wait() {    # daemon_wait PATTERN COUNT -> waits (at most 10 s) for COUNT log lines matching PATTERN
    local i
    for ((i = 0; i < 100; i++)); do
        [[ $(grep -c -- "$1" "$TMP/daemon.log") -ge $2 ]] && return 0
        sleep 0.1
    done
    return 1
}
daemon_stop() { kill "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; }

nft_reset
mkdb "$db" '["vip","8.8.8.8","now",0,0,1]' '["bob","8.8.4.4","now",0,0,0]'
daemon_start
daemon_wait 'Whitelist updated: 2 IPs' 2 || bad "the daemon ran two cycles" "$(cat "$TMP/daemon.log")"
assert_eq "(daemon running) vip_permanent holds the VIP" "8.8.8.8" "$(set_elems vip_permanent)"
printf 'this is not a database' > "$db"
daemon_wait 'database query failed' 2 || bad "the daemon noticed the broken database" "$(cat "$TMP/daemon.log")"
assert_eq "DB unreadable: vip_permanent kept (fail-static)" "8.8.8.8" "$(set_elems vip_permanent)"
assert_eq "DB unreadable: whitelist kept (fail-static)" $'8.8.4.4\n8.8.8.8' "$(set_elems whitelist)"
if grep '"level":"error"' "$TMP/daemon.log" | grep -q 'database query failed'; then ok "DB unreadable: an error is logged"
else bad "DB unreadable: an error is logged" "$(cat "$TMP/daemon.log")"; fi
assert_eq "DB unreadable: the drop rule is still there" "udp dport 7777 drop" "$(chain_rules | tail -1)"
# and it recovers by itself
mkdb "$db" '["vip","8.8.8.8","now",0,0,1]'
daemon_wait 'VIP list updated' 3 || true
assert_eq "DB readable again: the sets are reconciled with it (bob is gone)" "8.8.8.8" "$(set_elems whitelist)"
daemon_stop

nft_reset
mkdb "$db" '["vip","8.8.8.8","now",0,0,1]'
daemon_start
daemon_wait 'VIP list updated' 2 || true
sqlite3 "$db" 'DROP TABLE users'       # a query error, not an empty result
daemon_wait 'database query failed' 1 || bad "the daemon noticed the missing table" "$(cat "$TMP/daemon.log")"
assert_eq "no users table (query error): vip_permanent kept, not flushed" "8.8.8.8" "$(set_elems vip_permanent)"
daemon_stop

# the one-shot run (a restart) on an unreadable database exits non-zero and says so
nft_reset
mkdb "$db" '["vip","8.8.8.8","now",0,0,1]'
printf 'this is not a database' > "$db"
out=$(wd_once); rc=$?
if [[ $rc -ne 0 ]]; then ok "DB unreadable at start: the run exits non-zero"; else bad "DB unreadable at start: the run exits non-zero" "rc=$rc"; fi
if grep -q '"level":"error"' <<<"$out"; then ok "DB unreadable at start: an error is logged"; else bad "DB unreadable at start: an error is logged" "$out"; fi

# -- 5. nft failures are logged with nft's own text -----------------------------
nft_reset
mkdb "$db" '["vip","8.8.8.8","now",0,0,1]' '["bob","8.8.4.4","now",0,0,0]'
fault_reset
out=$(PATH=$FAULT_PATH DCF_PATH=$FAULT_DCF_PATH NFT_FAIL_STDIN_RE='^flush set ip dcf_firewall vip_permanent' NFT_FAIL_MSG='synthetic-vip-failure' wd_once)
if grep '"level":"error"' <<<"$out" | grep -q 'synthetic-vip-failure'; then ok "a refused VIP update is logged as an error with nft's text"
else bad "a refused VIP update is logged as an error with nft's text" "$out"; fi

nft_reset
mkdb "$db" '["bob","8.8.4.4","now",0,0,0]'
fault_reset
out=$(PATH=$FAULT_PATH DCF_PATH=$FAULT_DCF_PATH NFT_FAIL_STDIN_RE='^flush set ip dcf_firewall whitelist' NFT_FAIL_MSG='synthetic-wl-failure' wd_once)
if grep '"level":"error"' <<<"$out" | grep -q 'synthetic-wl-failure'; then ok "a refused whitelist update is logged as an error with nft's text"
else bad "a refused whitelist update is logged as an error with nft's text" "$out"; fi

# the empty-result flush used to be `2>/dev/null || true`
nft_reset
mkdb "$db" '["nobody",null,"now",0,0,0]'
fault_reset
out=$(PATH=$FAULT_PATH DCF_PATH=$FAULT_DCF_PATH NFT_FAIL_STDIN_RE='flush set ip dcf_firewall (whitelist|vip_permanent)' NFT_FAIL_MSG='synthetic-flush-failure' wd_once)
if grep '"level":"error"' <<<"$out" | grep -q 'synthetic-flush-failure'; then ok "a refused flush (empty result) is logged as an error with nft's text"
else bad "a refused flush (empty result) is logged as an error with nft's text" "$out"; fi

t_finish
