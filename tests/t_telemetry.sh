#!/usr/bin/env bash
# W6 (and the telemetry half of W5) -- dcf-telemetry.sh as root writing into a web volume.
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"; t_start "$@"

command -v jq >/dev/null || { echo "Bail out! jq not found"; exit 2; }

db=$TMP/id.db
web=$TMP/web
export DB_PATH=$db

telemetry() {   # telemetry [VAR=VALUE ...]  -> sets TOUT (stdout+stderr), TRC
    TOUT=$(env WEB_ROOT="$web" "$@" bash "$TELEMETRY" 2>&1); TRC=$?
}
fresh_web() { rm -rf -- "$web"; mkdir -m 755 "$web"; }
status() { jq -c "$1" "$web/status.json" 2>/dev/null; }

mkdb "$db" '["alice","8.8.4.4","now",0,0,0]' '["bob","8.8.8.8","now",0,5.0,0]' '["vip1","9.9.9.9","now",0,0,1]'

# ---- baseline
fresh_web
telemetry
assert_eq "baseline: exits 0" 0 "$TRC"
if jq -e . "$web/status.json" >/dev/null 2>&1; then ok "baseline: status.json is valid JSON"; else bad "baseline: status.json is valid JSON" "$TOUT"; fi
assert_eq "baseline: peers listed by name, VIP first" '["vip1","alice","bob"]' "$(status '[.peers[].username]')"
assert_eq "baseline: mode 644, owned by the running user" "644 $(id -u)" "$(stat -c '%a %u' "$web/status.json")"
left=$(find "$web" -name '.status.json.tmp*' | wc -l)
assert_eq "baseline: no temp file left behind" 0 "$left"

# ---- W6: a predictable temp name written by root follows a pre-created symlink
fresh_web
echo PRECIOUS > "$TMP/victim"
VICTIM=$TMP/victim WEB_ROOT=$web bash -c 'ln -s "$VICTIM" "$WEB_ROOT/.status.json.tmp.$$"; exec bash "$0"' "$TELEMETRY" >/dev/null 2>&1
assert_eq "W6 symlink: a symlink pre-created at the old temp name does not redirect root's write" "PRECIOUS" "$(cat "$TMP/victim")"

# ---- W6: a symlink already sitting at status.json is replaced, not followed
fresh_web
echo PRECIOUS > "$TMP/victim2"
ln -s "$TMP/victim2" "$web/status.json"
telemetry
assert_eq "W6 a pre-existing status.json symlink is replaced, its target untouched" "PRECIOUS" "$(cat "$TMP/victim2")"
if [[ -f "$web/status.json" && ! -L "$web/status.json" ]]; then ok "W6 ... and status.json is now a regular file"; else bad "W6 ... and status.json is now a regular file" "$(ls -la "$web")"; fi

# ---- usernames are untrusted text too: sqlite -json must keep the document valid
mkdb "$TMP/nasty.db" '["a\"quote","8.8.4.4","now",0,0,0]' '["back\\slash","8.8.4.5","now",0,0,0]' '["nl\nname","8.8.4.6","now",0,0,0]' '["ctl\u0001\u001f","8.8.4.7","now",0,0,0]' '["uni\u00e9\u65e5","8.8.4.8","now",0,0,0]'
fresh_web
telemetry DB_PATH="$TMP/nasty.db"
names=$(status '[.peers[].username] | sort' | python3 -c 'import json,sys; print(json.dumps(sorted(json.load(sys.stdin))))' 2>&1)
want=$(python3 -c 'import json; print(json.dumps(sorted(["a\"quote","back\\slash","nl\nname","ctl\u0001\u001f","uni\u00e9\u65e5"])))')
assert_eq "usernames with quotes, backslashes, newlines, control characters and unicode survive as valid JSON" "$want" "$names"

# ---- the gate that vets the numbers runs as root: it must be there, and safe
fresh_web; telemetry DCF_GATE=/nonexistent/dcf-gate
if [[ $TRC -eq 69 && ! -e "$web/status.json" ]]; then ok "gate: a missing DCF_GATE is refused with exit 69, nothing published"
else bad "gate: a missing DCF_GATE is refused with exit 69, nothing published" "rc=$TRC $TOUT"; fi
mkdir -m 777 "$TMP/gate_bad"; cp "$T_ROOT/gate/dcf-gate" "$TMP/gate_bad/dcf-gate"
fresh_web; telemetry DCF_GATE="$TMP/gate_bad/dcf-gate"
if [[ $TRC -eq 69 && ! -e "$web/status.json" ]]; then ok "gate: a gate in a world-writable directory is refused with exit 69"
else bad "gate: a gate in a world-writable directory is refused with exit 69" "rc=$TRC $TOUT"; fi

# ---- no JSON validator on the machine: fail closed, do not publish unchecked text
nov=$TMP/novalidator; mkdir -m 755 "$nov"
for t in cut free awk ip cat nft grep wc sqlite3 date mktemp stat readlink dirname chmod mv rm id; do
    real=$(command -v "$t" 2>/dev/null) && ln -s "$real" "$nov/$t"
done
fresh_web; telemetry DCF_PATH="$nov"
if [[ $TRC -ne 0 && ! -e "$web/status.json" ]]; then ok "no jq and no python3: nothing is published (fail closed)"
else bad "no jq and no python3: nothing is published (fail closed)" "rc=$TRC $(ls -la "$web")"; fi
assert_has "... and the message says why" "$TOUT" "no JSON validator"
ln -s "$(command -v jq)" "$nov/jq"
fresh_web; telemetry DCF_PATH="$nov"
assert_eq "with jq back on the path, status.json is published" "0 yes" "$TRC $([[ -f "$web/status.json" ]] && echo yes || echo no)"

# ---- W6: the directory itself
fresh_web
mkdir "$TMP/real"; rm -rf -- "$web"; ln -s "$TMP/real" "$web"
telemetry
if [[ $TRC -ne 0 && ! -e "$TMP/real/status.json" ]]; then ok "W6 WEB_ROOT that is a symlink is refused"
else bad "W6 WEB_ROOT that is a symlink is refused" "rc=$TRC $(ls -la "$TMP/real")"; fi
rm -f -- "$web"

# a trailing slash must not hide the link
rm -rf -- "$web" "$TMP/real"; mkdir "$TMP/real"; ln -s "$TMP/real" "$web"
TOUT=$(env WEB_ROOT="$web/" bash "$TELEMETRY" 2>&1); TRC=$?
if [[ $TRC -ne 0 && ! -e "$TMP/real/status.json" ]]; then ok "W6 WEB_ROOT that is a symlink is refused even with a trailing slash"
else bad "W6 WEB_ROOT that is a symlink is refused even with a trailing slash" "rc=$TRC $(ls -la "$TMP/real")"; fi
rm -f -- "$web"

fresh_web; chmod 777 "$web"
telemetry
if [[ $TRC -ne 0 && ! -e "$web/status.json" ]]; then ok "W6 world-writable WEB_ROOT is refused"
else bad "W6 world-writable WEB_ROOT is refused" "rc=$TRC"; fi

fresh_web; chmod 775 "$web"
telemetry
if [[ $TRC -ne 0 && ! -e "$web/status.json" ]]; then ok "W6 group-writable WEB_ROOT is refused"
else bad "W6 group-writable WEB_ROOT is refused" "rc=$TRC"; fi

fresh_web; chown 12345:12345 "$web"
telemetry
if [[ $TRC -ne 0 && ! -e "$web/status.json" ]]; then ok "W6 WEB_ROOT owned by another uid is refused"
else bad "W6 WEB_ROOT owned by another uid is refused" "rc=$TRC"; fi

rm -rf -- "$web"
telemetry
assert_eq "W6 missing WEB_ROOT is created (mode 755) and used" "0 755" "$TRC $(stat -c '%a' "$web" 2>/dev/null)"

# ---- W6: numeric fields are validated before they reach the JSON
mkdir -p "$TMP/shim"
cat > "$TMP/shim/cut" <<'SH'
#!/bin/sh
echo '0.42,"injected_load":true'
SH
mkdir -p "$TMP/fakeif/statistics"
echo '1,"injected_rx":true' > "$TMP/fakeif/statistics/rx_bytes"
echo '2' > "$TMP/fakeif/statistics/tx_bytes"
cat > "$TMP/shim/ip" <<SH
#!/bin/sh
echo "default via 10.0.0.1 dev ../../../../../..$TMP/fakeif"
SH
chmod +x "$TMP/shim/"*
fresh_web
telemetry PATH="$TMP/shim:$PATH" DCF_PATH="$TMP/shim:$T_TOOLPATH"
if grep -q 'injected' "$web/status.json" 2>/dev/null; then
    bad "W6 numeric: text read from the system cannot add fields to status.json" "$(cat "$web/status.json")"
else
    ok "W6 numeric: text read from the system cannot add fields to status.json"
fi
if jq -e '(.system.load_avg|type)=="number" and (.system.rx_bytes|type)=="number"' "$web/status.json" >/dev/null 2>&1; then
    ok "W6 numeric: the fields are still numbers (0, with a warning)"
else bad "W6 numeric: the fields are still numbers" "$(cat "$web/status.json" 2>&1)"; fi

# ---- W6: TELEMETRY_PEERS
fresh_web; telemetry
assert_eq "W6 TELEMETRY_PEERS unset = names" '["vip1","alice","bob"]' "$(status '[.peers[].username]')"
fresh_web; telemetry TELEMETRY_PEERS=names
assert_eq "W6 TELEMETRY_PEERS=names" '["vip1","alice","bob"]' "$(status '[.peers[].username]')"
fresh_web; telemetry TELEMETRY_PEERS=count
assert_eq "W6 TELEMETRY_PEERS=count: no peer rows" '[]' "$(status '.peers')"
assert_eq "W6 TELEMETRY_PEERS=count: totals instead" '{"total":3,"online":3}' "$(status '.peer_counts')"
if grep -Eq 'alice|bob|vip1' "$web/status.json"; then bad "W6 TELEMETRY_PEERS=count publishes no usernames" "$(cat "$web/status.json")"; else ok "W6 TELEMETRY_PEERS=count publishes no usernames"; fi
fresh_web; telemetry TELEMETRY_PEERS=off
assert_eq "W6 TELEMETRY_PEERS=off: no peer rows" '[]' "$(status '.peers')"
assert_eq "W6 TELEMETRY_PEERS=off: no counts either" 'null' "$(status '.peer_counts')"
if grep -Eq 'alice|bob|vip1' "$web/status.json"; then bad "W6 TELEMETRY_PEERS=off publishes no usernames" "$(cat "$web/status.json")"; else ok "W6 TELEMETRY_PEERS=off publishes no usernames"; fi
fresh_web; telemetry TELEMETRY_PEERS=all
if [[ $TRC -eq 64 && ! -e "$web/status.json" ]]; then ok "W6 TELEMETRY_PEERS=all (unknown) is refused with exit 64"
else bad "W6 TELEMETRY_PEERS=all (unknown) is refused with exit 64" "rc=$TRC"; fi

# ---- W6: the sqlite3 handle is read-only
cat > "$TMP/shim/sqlite3" <<SH
#!/bin/sh
echo "\$1" >> "$TMP/sqlite3.argv"
exec $(command -v sqlite3) "\$@"
SH
chmod +x "$TMP/shim/sqlite3"
: > "$TMP/sqlite3.argv"
fresh_web; telemetry PATH="$TMP/shim:$PATH" DCF_PATH="$TMP/shim:$T_TOOLPATH"
if [[ -s "$TMP/sqlite3.argv" ]] && ! grep -qvx -e '-readonly' "$TMP/sqlite3.argv"; then ok "W6 every sqlite3 call in telemetry passes -readonly"
else bad "W6 every sqlite3 call in telemetry passes -readonly" "$(cut -c1-120 "$TMP/sqlite3.argv")"; fi
rm -f "$TMP/shim/sqlite3"

# ---- W5 in telemetry: 'online' compares instants, not strings
if python3 "$T_DIR/mkdb.py" "$TMP/probe.db" '["x","1.1.1.1","sameday_stale",0,0,0]'; then
    mkdb "$db" '["fresh","8.8.4.4","now",0,0,0]' '["stale_today","8.8.8.8","sameday_stale",0,0,0]' \
               '["junk","9.9.9.9","raw:garbage",0,0,0]' '["nullseen","9.9.9.8",null,0,0,0]' '["offs","9.9.9.7","offset_now:+05:30",0,0,0]'
    fresh_web; telemetry
    assert_eq "W5 telemetry: only fresh and offset-fresh rows are online" \
        '{"fresh":"online","junk":"offline","nullseen":"offline","offs":"online","stale_today":"offline"}' \
        "$(status '[.peers[] | {(.username): .status}] | add | to_entries | sort_by(.key) | from_entries')"
else
    skip "W5 telemetry: same-date stale row" "UTC clock within an hour of midnight"
fi

t_finish
