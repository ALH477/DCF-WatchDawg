#!/usr/bin/env bash
# dcf-healthcheck.sh -- the container HEALTHCHECK.
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"; t_start "$@"

if ! needs_real_nft "healthcheck"; then t_finish; exit; fi
HC=$T_ROOT/dcf-healthcheck.sh
db=$TMP/id.db; web=$TMP/web
mkdb "$db" '["alice","8.8.4.4","now",0,0,0]'
mkdir -m 755 "$web"
export DB_PATH=$db WEB_ROOT=$web LOG_LEVEL=error

hc() { OUT=$(bash "$HC" 2>&1); RC=$?; }

nft_reset
hc; assert_eq "no firewall installed: unhealthy" 1 "$RC"

nft_reset; wd_once >/dev/null
hc; assert_eq "firewall installed, telemetry not configured: healthy" 0 "$RC"

nft flush chain ip dcf_firewall input
hc; assert_eq "chain flushed: unhealthy" 1 "$RC"
assert_has "... and it says why" "$OUT" "no 'udp dport 7777 drop' rule"

nft_reset; DCF_PORT=7777 wd_once >/dev/null
DCF_PORT=7778 hc; assert_eq "rules are for another port than DCF_PORT: unhealthy" 1 "$RC"
DCF_PORT='7777 accept' hc; assert_eq "a DCF_PORT that is not a port: unhealthy" 1 "$RC"

# DCF_PORT is judged by the same gate as the daemon's (1..65535), not a looser pattern
DCF_PORT=70000 hc; assert_eq "DCF_PORT=70000 is refused" 1 "$RC"
assert_has "... by the gate, with its reason" "$OUT" "refused by dcf-gate"
DCF_PORT=07777 hc; assert_eq "DCF_PORT=07777 (leading zero) is refused" 1 "$RC"
assert_has "... by the gate" "$OUT" "refused by dcf-gate"
DCF_GATE=/nonexistent/dcf-gate hc; assert_eq "an explicit but missing DCF_GATE is unhealthy" 1 "$RC"
assert_has "... and says so" "$OUT" "dcf-gate"

# telemetry configured: status.json freshness
nft_reset; TELEMETRY_SCRIPT=$T_ROOT/dcf-telemetry.sh wd_once >/dev/null
TELEMETRY_SCRIPT=x hc; assert_eq "telemetry configured and status.json fresh: healthy" 0 "$RC"
touch -d '5 minutes ago' "$web/status.json"
TELEMETRY_SCRIPT=x hc; assert_eq "status.json 5 minutes old: unhealthy" 1 "$RC"
assert_has "... and it says how old" "$OUT" "s old (limit 60s)"
touch -d '5 minutes ago' "$web/status.json"
TELEMETRY_SCRIPT=x SYNC_INTERVAL=300 hc; assert_eq "SYNC_INTERVAL=300 allows 900 s: 5 minutes old is healthy" 0 "$RC"
rm -f "$web/status.json"
TELEMETRY_SCRIPT=x hc; assert_eq "status.json missing: unhealthy" 1 "$RC"
hc; assert_eq "status.json missing but telemetry not configured: healthy" 0 "$RC"

t_finish
