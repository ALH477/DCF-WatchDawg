#!/usr/bin/env bash
# W1 -- the firewall is installed all-or-nothing, and a restart always repairs it.
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"; t_start "$@"

db=$TMP/id.db
mkdb "$db" '["alice","8.8.4.4","now",0,0,0]' '["vip","8.8.8.8","now",0,0,1]'
export DB_PATH=$db LOG_LEVEL=error

want=$'udp dport 7777 ip saddr @vip_permanent accept\nudp dport 7777 ip saddr @whitelist accept\nudp dport 7777 drop'

if needs_real_nft "clean install: the chain is exactly VIP accept, whitelist accept, drop"; then
    nft_reset
    wd_once >/dev/null; rc=$?
    assert_eq "clean install exits 0" 0 "$rc"
    assert_eq "clean install: the chain is exactly VIP accept, whitelist accept, drop" "$want" "$(chain_rules)"
    assert_eq "clean install: policy accept (as before)" "policy accept" "$(chain_policy)"
    wd_once >/dev/null
    assert_eq "second start is idempotent: still exactly three rules" "$want" "$(chain_rules)"
fi

# ---- crash sweep: SIGKILL the whole process group before the k-th nft call.
# After every k, (a) a clean restart must leave the three rules in place, and
# (b) the state the crash left must be "no chain" or "complete chain", never a
# chain that accepts without the drop.
if needs_real_nft "crash sweep"; then
    fault_path
    nft_reset; fault_reset
    PATH=$FAULT_PATH DCF_PATH=$FAULT_DCF_PATH wd_once >/dev/null
    total=$(fault_calls)
    echo "# a clean run makes $total nft calls; sweeping the kill point over 1..$total"
    viol_a=0; viol_b=0; detail_a=""; detail_b=""
    for ((k = 1; k <= total; k++)); do
        nft_reset; fault_reset
        # (the shell's own "Killed" notice goes to the group's stderr, hence the braces)
        { PATH=$FAULT_PATH DCF_PATH=$FAULT_DCF_PATH NFT_DIE_AT=$k DCF_WATCHDOG_ONCE=1 setsid -w bash "$WATCHDOG" >/dev/null 2>&1; } 2>/dev/null
        # (b) the state the crash left behind
        rules=$(chain_rules)
        if [[ -n "$rules" && "$rules" != "$want" ]]; then
            viol_b=$((viol_b + 1)); detail_b+="  kill before call $k leaves: $(tr '\n' ';' <<<"$rules")"$'\n'
        fi
        # (a) restart with the real nft
        fault_reset
        wd_once >/dev/null
        if [[ "$(chain_rules)" != "$want" ]]; then
            viol_a=$((viol_a + 1)); detail_a+="  kill before call $k, then restart: $(chain_rules | tr '\n' ';')"$'\n'
        fi
    done
    if [[ $viol_a -eq 0 ]]; then ok "a kill at any of the $total nft calls is repaired by the next start"
    else bad "a kill at any of the $total nft calls is repaired by the next start ($viol_a of $total points leave a broken chain)" "$detail_a"; fi
    if [[ $viol_b -eq 0 ]]; then ok "a kill at any point leaves no chain or a complete chain (atomic install)"
    else bad "a kill at any point leaves no chain or a complete chain ($viol_b of $total points leave a partial one)" "$detail_b"; fi
fi

# ---- upgrading from a chain the OLD code left half-built (2 accepts, no drop)
if needs_real_nft "upgrade from a half-built chain"; then
    nft_reset
    nft add table ip dcf_firewall
    nft add chain ip dcf_firewall input '{ type filter hook input priority 0; policy accept; }'
    nft add set ip dcf_firewall whitelist '{ type ipv4_addr; flags interval; timeout 1h; }'
    nft add set ip dcf_firewall vip_permanent '{ type ipv4_addr; flags interval; }'
    nft add rule ip dcf_firewall input udp dport 7777 ip saddr @vip_permanent accept
    nft add rule ip dcf_firewall input udp dport 7777 ip saddr @whitelist accept
    wd_once >/dev/null
    assert_eq "a start on top of the old half-built chain (no drop) completes it" "$want" "$(chain_rules)"
fi

# ---- the idempotence guard used to be grep "udp dport $DCF_PORT": a substring match
if needs_real_nft "port 777 after port 7777"; then
    nft_reset
    DCF_PORT=7777 wd_once >/dev/null
    DCF_PORT=777 wd_once >/dev/null
    assert_eq "restart on port 777 after 7777: only port-777 rules remain, with the drop" \
        $'udp dport 777 ip saddr @vip_permanent accept\nudp dport 777 ip saddr @whitelist accept\nudp dport 777 drop' "$(chain_rules)"
fi

# ---- a PRE-EXISTING dcf_firewall table that does not look like ours. The daemon owns
# this table and rebuilds it at start; whatever was in it, the port must end up
# dropped for a source that is not whitelisted, in the same state as a clean install.
if needs_real_nft "pre-existing table"; then
    net_up 10.9.0.2 10.9.0.3
    mkdb "$db" '["alice","10.9.0.2","now",0,0,0]'
    clean_shape=$'chain input {\nset vip_permanent {\nset whitelist {'

    conflict() {   # conflict NAME SETUP-COMMANDS...   (each command is run with nft as given)
        local name=$1; shift
        nft_reset
        local c
        for c in "$@"; do eval "nft $c" || { bad "$name: setup command failed: $c"; return; }; done
        wd_once >"$TMP/out.txt"; local rc=$?
        assert_eq "$name: the start succeeds" 0 "$rc"
        assert_eq "$name: the chain is exactly VIP accept, whitelist accept, drop" "$want" "$(chain_rules)"
        assert_eq "$name: the whitelist has the daemon's flags" "flags interval,timeout" "$(set_flags whitelist)"
        assert_eq "$name: the table holds exactly our chain and our two sets" "$clean_shape" "$(table_shape)"
        assert_eq "$name: a whitelisted source gets through" "RX" "$(probe 10.9.0.2)"
        assert_eq "$name: a source that is not whitelisted is dropped" "NORX" "$(probe 10.9.0.3)"
        assert_eq "$name: ... and so is loopback" "NORX" "$(probe 127.0.0.1)"
    }
    conflict "whitelist set with other flags" \
        "add table ip dcf_firewall" "add set ip dcf_firewall whitelist '{ type ipv4_addr; flags interval; }'"
    conflict "vip set of another type" \
        "add table ip dcf_firewall" "add set ip dcf_firewall vip_permanent '{ type ipv4_addr; }'"
    conflict "input chain at another priority" \
        "add table ip dcf_firewall" "add chain ip dcf_firewall input '{ type filter hook input priority -100; policy accept; }'"
    conflict "input chain on another hook" \
        "add table ip dcf_firewall" "add chain ip dcf_firewall input '{ type filter hook prerouting priority 0; policy accept; }'"
    conflict "input chain that is not a base chain" \
        "add table ip dcf_firewall" "add chain ip dcf_firewall input"
    conflict "input chain with policy drop" \
        "add table ip dcf_firewall" "add chain ip dcf_firewall input '{ type filter hook input priority 0; policy drop; }'"
    conflict "extra chains, sets and rules, and an accept ahead of ours" \
        "add table ip dcf_firewall" \
        "add chain ip dcf_firewall input '{ type filter hook input priority 0; policy accept; }'" \
        "add rule ip dcf_firewall input udp dport 7777 accept" \
        "add chain ip dcf_firewall evil '{ type filter hook input priority -300; policy accept; }'" \
        "add rule ip dcf_firewall evil udp dport 7777 accept" \
        "add set ip dcf_firewall mine '{ type ipv4_addr; }'" \
        "add chain ip dcf_firewall helper"

    # a table that is not ours is not touched
    nft_reset
    nft add table ip other
    nft add chain ip other input '{ type filter hook input priority 10; policy accept; }'
    nft add rule ip other input udp dport 9999 counter
    before=$(nft list table ip other)
    wd_once >/dev/null
    assert_eq "an unrelated table is left exactly as it was" "$before" "$(nft list table ip other)"
    assert_eq "... and ours is complete beside it" "$want" "$(chain_rules)"

    # a kill at every nft call on top of a mismatched table: the table is either as it was or
    # completely new, and the next start finishes the job
    nft_reset
    nft add table ip dcf_firewall
    nft add set ip dcf_firewall whitelist '{ type ipv4_addr; flags interval; }'
    nft add chain ip dcf_firewall input '{ type filter hook input priority 0; policy accept; }'
    nft add rule ip dcf_firewall input udp dport 7777 ip saddr @whitelist accept
    old_shape=$(table_shape); old_rules=$(chain_rules)
    fault_path
    fault_reset
    total=$(( $(PATH=$FAULT_PATH DCF_PATH=$FAULT_DCF_PATH wd_once >/dev/null; fault_calls) ))
    mixed=0; detail=""
    for ((k = 1; k <= total; k++)); do
        nft_reset
        nft add table ip dcf_firewall
        nft add set ip dcf_firewall whitelist '{ type ipv4_addr; flags interval; }'
        nft add chain ip dcf_firewall input '{ type filter hook input priority 0; policy accept; }'
        nft add rule ip dcf_firewall input udp dport 7777 ip saddr @whitelist accept
        fault_reset
        { PATH=$FAULT_PATH DCF_PATH=$FAULT_DCF_PATH NFT_DIE_AT=$k DCF_WATCHDOG_ONCE=1 setsid -w bash "$WATCHDOG" >/dev/null 2>&1; } 2>/dev/null
        if [[ "$(table_shape)" == "$old_shape" && "$(chain_rules)" == "$old_rules" ]]; then :
        elif [[ "$(chain_rules)" == "$want" && "$(set_flags whitelist)" == "flags interval,timeout" && "$(table_shape)" == "$clean_shape" ]]; then :
        else mixed=$((mixed + 1)); detail+="  kill before call $k: $(chain_rules | tr '\n' ';') / $(set_flags whitelist)"$'\n'; fi
        fault_reset
        wd_once >/dev/null
        if [[ "$(chain_rules)" != "$want" || "$(set_flags whitelist)" != "flags interval,timeout" ]]; then
            mixed=$((mixed + 1)); detail+="  kill before call $k, then restart: $(chain_rules | tr '\n' ';')"$'\n'
        fi
    done
    if [[ $mixed -eq 0 ]]; then ok "on a mismatched table, a kill at any of the $total nft calls leaves the old table or the whole new one, and a restart repairs it"
    else bad "on a mismatched table, a kill at any of the $total nft calls leaves the old table or the whole new one, and a restart repairs it ($mixed bad points)" "$detail"; fi

    # when the install is refused, say so loudly and leave the host's policy alone
    nft_reset
    nft add table ip dcf_firewall
    nft add set ip dcf_firewall whitelist '{ type ipv4_addr; flags interval; }'
    old_shape=$(table_shape)
    fault_reset
    out=$(PATH=$FAULT_PATH DCF_PATH=$FAULT_DCF_PATH NFT_FAIL_STDIN_RE='^add table' NFT_FAIL_MSG='synthetic-install-failure' wd_once); rc=$?
    assert_eq "a refused install exits 1" 1 "$rc"
    if grep '"level":"error"' <<<"$out" | grep -q 'synthetic-install-failure'; then ok "a refused install logs nft's own error"
    else bad "a refused install logs nft's own error" "$out"; fi
    assert_has "... and says what that means for the port" "$out" "not protected by this daemon"
    assert_eq "a refused install changes nothing" "$old_shape" "$(table_shape)"

    # a restart takes nothing from a whitelisted source: stream numbered datagrams while the
    # daemon is restarted ten times; none of the whitelisted source's may be lost, none of the
    # other's may arrive
    nft_reset
    mkdb "$db" '["alice","10.9.0.2","now",0,0,0]'
    wd_once >/dev/null
    python3 "$T_DIR/udp.py" stream 3 10.9.0.2 10.9.0.3 >"$TMP/stream.txt" &
    spid=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do wd_once >/dev/null; done
    wait "$spid"
    assert_eq "ten restarts while datagrams flow: whitelisted source loses nothing, the other nothing arrives" \
        "RECV $(awk '/^10.9.0.2/{split($2,a,"=");split($3,b,"=");print (a[2]==b[2]) ? "all" : "LOST " (a[2]-b[2])}' "$TMP/stream.txt") $(awk '/^10.9.0.3/{split($3,b,"=");print b[2]}' "$TMP/stream.txt")" \
        "RECV all 0"

    # restart with an unreadable database: the rebuilt table comes up empty (closed), not open
    nft_reset
    wd_once >/dev/null
    printf 'not a database' > "$db"
    out=$(wd_once); rc=$?
    assert_eq "restart with an unreadable database exits 1" 1 "$rc"
    assert_eq "... the drop rule is there" "$want" "$(chain_rules)"
    assert_eq "... and nobody is let in" "NORX" "$(probe 10.9.0.2)"
    mkdb "$db" '["alice","10.9.0.2","now",0,0,0]'
fi

# ---- shim mode: all that can be checked is what is sent. [UNTESTED] against a kernel.
if [[ "$DCF_TEST_NFT_MODE" == shim ]]; then
    : > "$NFT_SHIM_LOG"
    wd_once >/dev/null
    if grep -q 'ARGV: \[add\] \[rule\]' "$NFT_SHIM_LOG"; then
        bad "(shim) the rules are installed in one 'nft -f' transaction, not one 'nft add rule' at a time" "$(grep -F '[add] [rule]' "$NFT_SHIM_LOG" | head -5)"
    else
        ok "(shim) no per-rule 'nft add rule' calls"
    fi
    # one STDIN block must carry the whole install: chain, flush, both accepts, the drop
    if python3 - "$NFT_SHIM_LOG" <<'PY'
import re, sys
log = open(sys.argv[1]).read()
blocks = re.findall(r"STDIN-BEGIN\n(.*?)\nSTDIN-END", log, re.S)
need = ["add chain ip dcf_firewall input", "flush chain ip dcf_firewall input",
        "udp dport 7777 ip saddr @vip_permanent accept", "udp dport 7777 ip saddr @whitelist accept", "udp dport 7777 drop"]
sys.exit(0 if any(all(n in b for n in need) for b in blocks) else 1)
PY
    then ok "(shim) one transaction carries the chain, a flush, both accepts and the drop"
    else bad "(shim) one transaction carries the chain, a flush, both accepts and the drop" "$(cat "$NFT_SHIM_LOG")"; fi
    skip "(shim) kernel state after a kill" "needs real nft"
fi

t_finish
