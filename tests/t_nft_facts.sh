#!/usr/bin/env bash
# What nft itself does with the spellings this repository's gate exists for.
# These are measurements of the installed nft, not tests of this repository:
# they back claims in the README, and fail loudly if another nft version
# behaves differently (in which case the README claim needs another look).
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"; t_start "$@"
if ! needs_real_nft "nft facts"; then t_finish; exit; fi
echo "# $(nft --version)"

setup() { nft flush ruleset; nft add table ip t; nft add set ip t s '{ type ipv4_addr; flags interval; }'; }
elems() { nft -j list set ip t s | python3 -c '
import json, sys
out = []
for i in json.load(sys.stdin)["nftables"]:
    for e in i.get("set", {}).get("elem", []):
        out.append(e if isinstance(e, str) else json.dumps(e, sort_keys=True))
print(" ".join(sorted(out)))'; }
add() { printf 'add element ip t s { %s }\n' "$1" | nft -f - 2>&1; }

setup; err=$(add '1.2.3.08'); rc=$?
assert_eq "nft rejects 1.2.3.08 (exit status)" 1 "$rc"
assert_has "... with a name-resolution error" "$err" "Could not resolve hostname"
assert_eq "... and adds nothing" "" "$(elems)"

setup; add '1.2.3.4 ' >/dev/null; assert_eq "nft accepts '1.2.3.4 ' (trailing space) as 1.2.3.4" "1.2.3.4" "$(elems)"
setup; add '01.2.3.4' >/dev/null; assert_eq "nft reads 01.2.3.4 as 1.2.3.4" "1.2.3.4" "$(elems)"
setup; add '010.2.3.4' >/dev/null; assert_eq "nft reads 010.2.3.4 as OCTAL: 8.2.3.4" "8.2.3.4" "$(elems)"
setup; add '011.2.3.4' >/dev/null; assert_eq "nft reads 011.2.3.4 as OCTAL: 9.2.3.4" "9.2.3.4" "$(elems)"

setup; add '5.5.5.5' >/dev/null
printf 'flush set ip t s\nadd element ip t s { 1.2.3.4, 1.2.3.08, 1.2.3.6 }\n' | nft -f - >/dev/null 2>&1; rc=$?
assert_eq "a batch with one bad element fails as a whole (exit status)" 1 "$rc"
assert_eq "... and the flush in it is rolled back too: the set still holds 5.5.5.5" "5.5.5.5" "$(elems)"

# argv words are joined and parsed as one string; '#' starts a comment (the DCF_PORT injection)
nft flush ruleset; nft add table ip t; nft add set ip t s '{ type ipv4_addr; }'
nft add chain ip t input '{ type filter hook input priority 0; policy accept; }'
nft add rule ip t input udp dport 7777 accept '#' ip saddr @s accept
rules=$(nft list chain ip t input | grep -E '^\s+udp')
assert_eq "an argv word '#' comments out the rest of the rule: 'udp dport 7777 accept #...' is an unconditional accept" "udp dport 7777 accept" "$(sed 's/^[[:space:]]*//' <<<"$rules")"

t_finish
