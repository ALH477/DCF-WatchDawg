#!/usr/bin/env bash
# W4 -- configuration is validated at startup, before anything touches nft:
# DCF_PORT and SYNC_INTERVAL through the gate, LOG_LEVEL against its four values.
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"; t_start "$@"

db=$TMP/id.db
mkdb "$db" '["alice","8.8.4.4","now",0,0,0]'
export DB_PATH=$db LOG_LEVEL=info

run() {   # run VAR=VALUE...   sets RUN_OUT and RC. A hard 20 s ceiling so a busy loop cannot hang the suite.
    # shellcheck disable=SC2034  # RUN_OUT is for a human reading a failure
    RUN_OUT=$(env "$@" DCF_WATCHDOG_ONCE=1 timeout 20 bash "$WATCHDOG" 2>&1); RC=$?
}

# ---------------------------------------------------------------- DCF_PORT
if true; then
    # nft joins its argv words and parses the result, and '#' starts a comment: this value
    # turns all three rules into an unconditional accept for the port.
    nft_reset
    run 'DCF_PORT=7777 accept #'
    if [[ "$DCF_TEST_NFT_MODE" == real ]] && chain_rules | grep -Eq '^udp dport 7777 accept$'; then
        bad "W4 injection: DCF_PORT='7777 accept #' yields an unconditional 'udp dport 7777 accept' rule" "$(chain_rules)"
    else
        ok "W4 injection: DCF_PORT='7777 accept #' yields no unconditional accept rule"
    fi
    for bad in "7777 accept #" "7777 counter" "7777 accept" "0-65535 accept" "7777;flush ruleset" "0" "65536" "07777" " 7777" "7777 " "7777
accept" "+7777" "0x1e61" "-1" "99999999999999999999"; do
        nft_reset
        run "DCF_PORT=$bad"; rc=$RC
        label=${bad//$'\n'/\\n}
        assert_eq "W4 DCF_PORT='$label' is refused with exit 64" 64 "$rc"
        if nft_untouched; then
            ok "W4 DCF_PORT='$label' left the ruleset untouched"
        else
            bad "W4 DCF_PORT='$label' touched nft before being refused" "$(nft list ruleset 2>/dev/null)"
        fi
    done
    nft_reset
    run DCF_PORT=7777 SYNC_INTERVAL=10; rc=$RC
    assert_eq "W4 DCF_PORT=7777 still starts" 0 "$rc"
    nft_reset
    run DCF_PORT=1; assert_eq "W4 DCF_PORT=1 starts" 0 "$RC"
    nft_reset
    run DCF_PORT=65535; assert_eq "W4 DCF_PORT=65535 starts" 0 "$RC"
fi

# ---------------------------------------------------------------- SYNC_INTERVAL
# Not ONCE: the daemon must be refused at startup, not busy-loop. Measure with a ceiling.
for bad in 0 -1 abc 1.5 3601 "10 20" 010 1e3; do
    nft_reset
    env "SYNC_INTERVAL=$bad" LOG_LEVEL=debug timeout 5 bash "$WATCHDOG" >/dev/null 2>&1; rc=$?
    assert_eq "W4 SYNC_INTERVAL='$bad' is refused with exit 64 (not 124 = still running at the 5 s ceiling)" 64 "$rc"
done
cycles=$(env SYNC_INTERVAL=0 LOG_LEVEL=debug timeout 2 bash "$WATCHDOG" 2>&1 | grep -c 'Whitelist updated' || true)
if [[ "$cycles" -le 1 ]]; then ok "W4 SYNC_INTERVAL=0 does not busy-loop ($cycles sync(s) in 2 s)"
else bad "W4 SYNC_INTERVAL=0 busy-loops: $cycles whitelist updates in 2 s"; fi

nft_reset
run SYNC_INTERVAL=3600; assert_eq "W4 SYNC_INTERVAL=3600 starts" 0 "$RC"

# ---------------------------------------------------------------- LOG_LEVEL
for bad in verbose DEBUG Info "info " 0; do
    nft_reset
    run "LOG_LEVEL=$bad"; rc=$RC
    assert_eq "W4 LOG_LEVEL='$bad' is refused with exit 64" 64 "$rc"
done
for good in debug info warn error; do
    nft_reset
    run "LOG_LEVEL=$good"; assert_eq "W4 LOG_LEVEL=$good starts" 0 "$RC"
done

# an empty variable still means "use the default" (${VAR:-default}), as it always did
nft_reset
run DCF_PORT= SYNC_INTERVAL= LOG_LEVEL=
assert_eq "W4 empty DCF_PORT / SYNC_INTERVAL / LOG_LEVEL fall back to the defaults and start" 0 "$RC"
if [[ "$DCF_TEST_NFT_MODE" == real ]]; then
    assert_eq "W4 ... and protect the default port 7777" "udp dport 7777 drop" "$(chain_rules | tail -1)"
fi

t_finish
