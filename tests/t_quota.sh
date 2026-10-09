#!/usr/bin/env bash
# Who is authorized: the quota rule in SQL, one cycle, a row per case. Includes the
# rows a corrupted or hostile database could hold (negative or non-numeric usage,
# non-numeric balance): none of those may whitelist an address.
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"; t_start "$@"
if ! needs_real_nft "quota matrix"; then t_finish; exit; fi

db=$TMP/id.db
export DB_PATH=$db LOG_LEVEL=error
FREE=134217728
OVER=$((FREE + 100 * 1024 * 1024))

# ROWS: "ip|used|balance|vip|seen|expected(yes/no)|why"; used/balance/vip/seen are JSON
rows=(
  '10.0.0.1|0|0.0|1|"now"|yes|vip, fresh'
  '10.0.0.2|104857600|0.0|0|"now"|yes|trial under the free tier'
  "10.0.0.3|$OVER|1000.0|0|\"now\"|yes|paid, ample balance"
  "10.0.0.4|$OVER|0.0|0|\"now\"|no|over quota, zero balance"
  '10.0.0.5|0|0.0|1|"ago:7200"|no|vip but stale'
  '10.0.0.6|0|0.0|1|null|no|vip but last_seen NULL'
  '10.0.0.7|0|0.0|1|"raw:garbage"|no|vip but last_seen garbage'
  '10.0.0.8|9223372036854775807|0.0|0|"now"|no|huge positive usage, no balance'
  '10.0.0.9|-9223372036854775808|0.0|0|"now"|no|NEGATIVE usage (-2^63): read as under the free tier'
  '10.0.0.10|null|0.0|0|"now"|no|usage NULL'
  "10.0.0.11|$OVER|null|0|\"now\"|no|balance NULL, over quota"
  "10.0.0.12|$OVER|0.0|2|\"now\"|no|is_vip 2 is not VIP"
  "10.0.0.13|$OVER|0.0|\"true\"|\"now\"|no|is_vip 'true' is not VIP"
  "10.0.0.14|$OVER|0.0|null|\"now\"|no|is_vip NULL"
  "10.0.0.17|$FREE|0.0|0|\"now\"|yes|exactly the free tier"
  "10.0.0.18|$((FREE + 1))|0.0|0|\"now\"|no|one byte over, no balance"
  '10.0.0.19|-1|0.0|0|"now"|no|usage -1'
  "10.0.0.20|-1|-5.0|0|\"now\"|no|usage -1 and a negative balance"
  '10.0.0.21|-1000000000000|-5.0|0|"now"|no|large negative usage and a negative balance'
  '10.0.0.22|"abc"|0.0|0|"now"|no|usage is text'
  "10.0.0.23|$OVER|\"zzz\"|0|\"now\"|no|balance is text (any number sorts below text), over quota"
  "10.0.0.24|$OVER|-5.0|0|\"now\"|no|negative balance, over quota"
  '10.0.0.25|100|-5.0|0|"now"|yes|negative balance but inside the free tier'
  '10.0.0.26|-1|0.0|1|"now"|yes|VIP is unconditional, whatever the usage'
  "10.0.0.27|$OVER|0.001|0|\"now\"|no|a tenth of a cent does not cover 100 MiB over"
  "10.0.0.28|$((FREE + 1000))|1.0|0|\"now\"|yes|a dollar covers a thousand bytes"
  "10.0.0.29|$OVER|0.01|0|\"now\"|yes|a cent covers 100 MiB over"
)
args=(); i=0
for r in "${rows[@]}"; do
    IFS='|' read -r ip used bal vip seen _ _ <<<"$r"
    # mkdb takes [username, ip, seen, used, balance, vip] as JSON; "seen" may be null or a spec string
    args+=("$(printf '["u%d","%s",%s,%s,%s,%s]' "$i" "$ip" "$seen" "$used" "$bal" "$vip")")
    i=$((i + 1))
done
nft_reset
mkdb "$db" "${args[@]}"
wd_once >/dev/null
got=$(set_elems whitelist)
for r in "${rows[@]}"; do
    IFS='|' read -r ip _ _ _ _ want why <<<"$r"
    in=no; grep -qx "$ip" <<<"$got" && in=yes
    if [[ "$in" == "$want" ]]; then ok "$ip $why: $want"; else bad "$ip $why: wanted $want, got $in"; fi
done
t_finish
