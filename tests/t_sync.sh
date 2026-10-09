#!/usr/bin/env bash
# W3 (address gate) and W5 (freshness) -- what ends up in the whitelist, end to end:
# DB rows -> dcf-watchdog.sh -> a real nft.
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"; t_start "$@"

db=$TMP/id.db
export DB_PATH=$db LOG_LEVEL=info

if [[ "$DCF_TEST_NFT_MODE" != real ]]; then
    skip "whitelist contents" "need a real nft; mode is shim"
    t_finish; exit
fi

# whitelist ROW...   -> the whitelist's addresses, space separated
whitelist() {
    nft_reset
    mkdb "$db" "$@" || return $?
    wd_once > "$TMP/last_out"
    set_elems whitelist | tr '\n' ' ' | sed 's/ $//'
}

# ------------------------------------------------------------ W3: the address gate
got=$(whitelist '["alice","8.8.4.4","now",0,0,0]' '["mallory","1.2.3.08","now",0,0,0]')
assert_eq "W3 poison: one '1.2.3.08' row must not stop everyone else being whitelisted" "8.8.4.4" "$got"

got=$(whitelist '["oct","010.2.3.4","now",0,0,0]')
assert_eq "W3 octal: '010.2.3.4' must not become 8.2.3.4 (nft reads a leading 0 as octal)" "" "$got"

got=$(whitelist '["a","1.2.3. 4","now",0,0,0]' '["b","1. 2.3.4","now",0,0,0]' '["c"," 8.8.4.4","now",0,0,0]' \
                '["d","8.8.4.4 ","now",0,0,0]' '["e",".8.8.4.4","now",0,0,0]' '["f","8.8.4.4\t","now",0,0,0]')
assert_eq "W3 whitespace: nothing is stripped before the gate, so none of these are whitelisted" "" "$got"

got=$(whitelist '["a","127.0.0.1","now",0,0,0]' '["b","0.0.0.0","now",0,0,0]' '["c","0.1.2.3","now",0,0,0]' \
                '["d","169.254.1.1","now",0,0,0]' '["e","224.0.0.1","now",0,0,0]' '["f","239.255.255.250","now",0,0,0]' \
                '["g","240.0.0.1","now",0,0,0]' '["h","255.255.255.255","now",0,0,0]' \
                '["p1","10.1.2.3","now",0,0,0]' '["p2","172.16.0.1","now",0,0,0]' '["p3","192.168.1.1","now",0,0,0]' \
                '["s1","100.64.0.1","now",0,0,0]' '["g1","8.8.8.8","now",0,0,0]')
assert_eq "W3 classes: global, private and shared are admitted; this-net, loopback, link-local, multicast, reserved are not" \
    "8.8.8.8 10.1.2.3 100.64.0.1 172.16.0.1 192.168.1.1" "$(tr ' ' '\n' <<<"$got" | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n | tr '\n' ' ' | sed 's/ $//')"

got=$(whitelist '["a","1.2.3.4/32","now",0,0,0]' '["b","1.2.3.4 accept","now",0,0,0]' '["c","8.8.4.4}; flush ruleset; #","now",0,0,0]' \
                '["d","1.2.3.256","now",0,0,0]' '["e","0x7f.0.0.1","now",0,0,0]' '["f","8.8.4","now",0,0,0]' '["g","01.2.3.4","now",0,0,0]' \
                '["h","","now",0,0,0]' '["i",null,"now",0,0,0]' '["j","８.８.４.４","now",0,0,0]' '["k","8.8.4.4.","now",0,0,0]')
assert_eq "W3 garbage: nft syntax, hex, short, fullwidth digits, empty and NULL are all refused" "" "$got"

got=$(whitelist '["a","8.8.4.4\u0000junk","now",0,0,0]' '["b","9.9.9.9\u0000","now",0,0,0]')
assert_eq "W3 NUL: a value with an embedded NUL is refused, not truncated into an admitted prefix" "" "$got"

got=$(whitelist '["a","9.9.9.9","now",0,0,0]' '["b","9.9.9.9","now",0,0,0]' '["c","9.9.9.9","now",0,0,0]')
assert_eq "W3 dedupe: three users behind one address give one element" "9.9.9.9" "$got"

got=$(whitelist '["a","8.8.4.4\n9.9.9.9","now",0,0,0]')
assert_eq "W3 newline: one DB value holding two addresses is one rejected value, not two whitelisted ones" "" "$got"

got=$(whitelist '["a","8.8.4.4","now",0,0,0]' '["b","1.2.3.08","now",0,0,0]' '["c","127.0.0.1","now",0,0,0]' '["d","x","now",0,0,0]')
LAST_OUT=$(cat "$TMP/last_out")
if grep -Eq 'rejected 3\b' <<<"$LAST_OUT"; then ok "W3 the rejected count is logged"
else bad "W3 the rejected count is logged (3 bad values)" "$LAST_OUT"; fi

# the cap: 5000 distinct addresses, the batch is bounded to 4096
rows=()
for ((i = 0; i < 5000; i++)); do
    rows+=("$(printf '["u%d","%d.%d.%d.1","now",0,0,0]' "$i" $((20 + i / 65536)) $((i / 256 % 256)) $((i % 256)))")
done
nft_reset
mkdb "$db" "${rows[@]}"
LAST_OUT=$(wd_once)
n=$(set_elems whitelist | wc -l)
assert_eq "W3 cap: 5000 distinct addresses -> a batch of 4096" 4096 "$n"
if grep -Eq 'capped 904\b|904 .*(over|cap|dropped)' <<<"$LAST_OUT"; then ok "W3 cap: the 904 dropped addresses are logged"
else bad "W3 cap: the 904 dropped addresses are logged" "$LAST_OUT"; fi

# ------------------------------------------------------------ W5: freshness
sd=$(python3 "$T_DIR/mkdb.py" "$TMP/probe.db" '["x","1.1.1.1","sameday_stale",0,0,0]'; echo $?)
if [[ "$sd" == 77 ]]; then
    skip "W5 same-date stale row" "UTC clock is within an hour of midnight, so no same-date row is stale"
    rows=()
else
    rows=('["stale_sameday","1.1.1.1","sameday_stale",0,0,0]')
fi
got=$(whitelist "${rows[@]}" \
    '["fresh_nanos","8.8.4.4","now",0,0,0]' \
    '["fresh_space","8.8.8.8","space_ago:60",0,0,0]' \
    '["stale_10h","1.0.0.1","ago:36000",0,0,0]' \
    '["stale_space","1.0.0.2","space_ago:7200",0,0,0]' \
    '["null_seen","9.9.9.9",null,0,0,0]' \
    '["junk_seen","9.9.9.10","raw:garbage",0,0,0]' \
    '["empty_seen","9.9.9.11","raw:",0,0,0]' \
    '["offset_fresh","4.4.4.4","offset_now:+05:30",0,0,0]' \
    '["offset_neg","4.4.4.5","offset_now:-08:00",0,0,0]')
assert_eq "W5 freshness: rows older than an hour, with NULL or garbage last_seen, are not whitelisted; RFC3339 with ns and offsets parse" \
    "4.4.4.4 4.4.4.5 8.8.4.4 8.8.8.8" "$got"

# SQLite's own parser, both the nix CLI and python's linked library: the format DCF-ID writes
v=$(sqlite3 :memory: "select datetime('2026-10-09T01:22:33.123456789+00:00'), datetime('2026-10-09T01:22:33.123Z'), datetime('2026-10-09T07:22:33+05:30')")
assert_eq "W5 sqlite3 CLI parses chrono's nine-digit RFC3339 and offsets" "2026-10-09 01:22:33|2026-10-09 01:22:33|2026-10-09 01:52:33" "$v"
v=$(python3 -c "import sqlite3;print(sqlite3.connect(':memory:').execute(\"select datetime('2026-10-09T01:22:33.123456789+00:00')\").fetchone()[0])")
assert_eq "W5 python's libsqlite $(python3 -c 'import sqlite3;print(sqlite3.sqlite_version)') parses it too" "2026-10-09 01:22:33" "$v"

t_finish
