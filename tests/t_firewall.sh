#!/usr/bin/env bash
# W1 -- the firewall is installed all-or-nothing, and a restart always repairs it.
. "$(dirname "$0")/lib.sh"; t_start "$@"

db=$TMP/id.db
mkdb "$db" '["alice","8.8.4.4","now",0,0,0]' '["vip","8.8.8.8","now",0,0,1]'
export DB_PATH=$db LOG_LEVEL=error

want=$'udp dport 7777 ip saddr @vip_permanent accept\nudp dport 7777 ip saddr @whitelist accept\nudp dport 7777 drop'

if needs_real_nft "clean install: the chain is exactly VIP accept, whitelist accept, drop"; then
    nft_reset
    out=$(wd_once); rc=$?
    assert_eq "clean install exits 0" 0 "$rc"
    assert_eq "clean install: the chain is exactly VIP accept, whitelist accept, drop" "$want" "$(chain_rules)"
    assert_eq "clean install: policy accept (as before)" "policy accept" "$(chain_policy)"
    out=$(wd_once); rc=$?
    assert_eq "second start is idempotent: still exactly three rules" "$want" "$(chain_rules)"
fi

# ---- crash sweep: SIGKILL the whole process group before the k-th nft call.
# After every k, (a) a clean restart must leave the three rules in place, and
# (b) the state the crash left must be "no chain" or "complete chain", never a
# chain that accepts without the drop.
if needs_real_nft "crash sweep"; then
    fault_path
    nft_reset; fault_reset
    PATH=$FAULT_PATH wd_once >/dev/null
    total=$(fault_calls)
    echo "# a clean run makes $total nft calls; sweeping the kill point over 1..$total"
    viol_a=0; viol_b=0; detail_a=""; detail_b=""
    for ((k = 1; k <= total; k++)); do
        nft_reset; fault_reset
        # (the shell's own "Killed" notice goes to the group's stderr, hence the braces)
        { PATH=$FAULT_PATH NFT_DIE_AT=$k DCF_WATCHDOG_ONCE=1 setsid -w bash "$WATCHDOG" >/dev/null 2>&1; } 2>/dev/null
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

# ---- the idempotence guard used to be grep "udp dport $DCF_PORT": a substring match
if needs_real_nft "port 777 after port 7777"; then
    nft_reset
    DCF_PORT=7777 wd_once >/dev/null
    DCF_PORT=777 wd_once >/dev/null
    assert_eq "restart on port 777 after 7777: only port-777 rules remain, with the drop" \
        $'udp dport 777 ip saddr @vip_permanent accept\nudp dport 777 ip saddr @whitelist accept\nudp dport 777 drop' "$(chain_rules)"
fi

# ---- shim mode: all that can be checked is what is sent
if [[ "$DCF_TEST_NFT_MODE" == shim ]]; then
    : > "$NFT_SHIM_LOG"
    wd_once >/dev/null
    log=$(cat "$NFT_SHIM_LOG")
    n=$(grep -c '^STDIN-BEGIN' <<<"$log")
    # the install must be ONE transaction carrying the chain, its three rules and the drop
    tx=$(awk '/^STDIN-BEGIN/{b=1;next} /^STDIN-END/{b=0} b' <<<"$log" | grep -c . || true)
    if grep -q 'ARGV: \[add\] \[rule\]' <<<"$log"; then
        bad "firewall rules are installed in one nft -f transaction, not one 'nft add rule' at a time" "$(grep 'add\] \[rule' <<<"$log" | head -5)"
    else
        ok "no per-rule 'nft add rule' calls"
    fi
    skip "(shim) kernel state after a kill" "needs real nft"
fi

t_finish
