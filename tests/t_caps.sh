#!/usr/bin/env bash
# README claim: CAP_NET_ADMIN is enough; CAP_NET_RAW is not needed. Measured by
# running a full cycle (init, both syncs, telemetry) with NET_ADMIN as the ONLY
# capability in the permitted, effective and bounding sets.
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"; t_start "$@"

if ! needs_real_nft "NET_ADMIN-only cycle"; then t_finish; exit; fi
command -v setpriv >/dev/null || { skip "NET_ADMIN-only cycle" "setpriv not installed"; t_finish; exit; }

mkdb "$TMP/id.db" '["alice","8.8.4.4","now",0,0,0]' '["vip","8.8.8.8","now",0,0,1]'
chown 1000:1000 "$TMP/id.db"; chmod 644 "$TMP/id.db"      # written by DCF-ID as another uid
mkdir -m 755 "$TMP/web"
cat > "$TMP/inner.sh" <<'SH'
grep -E '^Cap(Prm|Eff|Bnd)' /proc/self/status | tr '\n\t' '  '; echo
DB_PATH=$1 WEB_ROOT=$2 TELEMETRY_SCRIPT=$3 DCF_WATCHDOG_ONCE=1 LOG_LEVEL=warn bash "$4"
SH
out=$(setpriv --bounding-set=-all,+net_admin --inh-caps=-all bash "$TMP/inner.sh" "$TMP/id.db" "$TMP/web" "$T_ROOT/dcf-telemetry.sh" "$WATCHDOG" 2>&1); rc=$?
assert_has "the process really holds only CAP_NET_ADMIN (0x1000)" "$out" "CapPrm: 0000000000001000 CapEff: 0000000000001000 CapBnd: 0000000000001000"
assert_eq "init + sync + telemetry succeed with NET_ADMIN alone" 0 "$rc"
assert_eq "the whitelist was written" $'8.8.4.4\n8.8.8.8' "$(set_elems whitelist)"
assert_eq "the VIP set was written" "8.8.8.8" "$(set_elems vip_permanent)"
if jq -e . "$TMP/web/status.json" >/dev/null 2>&1; then ok "status.json was written"; else bad "status.json was written" "$out"; fi
t_finish
