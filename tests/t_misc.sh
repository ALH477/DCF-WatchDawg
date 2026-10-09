#!/usr/bin/env bash
# W7 (log lines are valid JSON whatever they carry; TELEMETRY_SCRIPT is executed as
# root only if it is a safe file).
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"; t_start "$@"

db=$TMP/id.db
mkdb "$db" '["alice","8.8.4.4","now",0,0,0]'
export DB_PATH=$db LOG_LEVEL=info

# ---------------------------------------------------------------- log() is JSON
json_check() {   # json_check NAME MESSAGE
    local name=$1 msg=$2 out
    out=$(bash -c 'source "$1"; log_info "$2"' _ "$WATCHDOG" "$msg" 2>&1)
    if python3 - "$msg" "$out" <<'PY'
import json, sys
msg, out = sys.argv[1], sys.argv[2]
lines = out.split("\n")
if len(lines) != 1:
    sys.exit("output is %d lines, not 1" % len(lines))
try:
    d = json.loads(lines[0])
except ValueError as e:
    sys.exit("not JSON: %s" % e)
if d["message"] != msg:
    sys.exit("message came back as %r" % d["message"])
if d["level"] != "info" or d["service"] != "dcf-watchdog":
    sys.exit("envelope changed: %r" % d)
PY
    then ok "$name"; else bad "$name" "$out"; fi
}
json_check "log: double quote"              'say "hi"'
json_check "log: backslash"                 'C:\dir\name'
json_check "log: trailing backslash"        $'ends with \\'
json_check "log: backslash then quote"      'a\"b'
json_check "log: newline stays on one line" $'first\nsecond'
json_check "log: a forged log line in a value" $'x"}\n{"level":"error","message":"forged"}'
json_check "log: CR and TAB"                $'a\rb\tc'
json_check "log: control characters"        $'a\x01b\x1fc\x7fd'
json_check "log: unicode"                   'caf\u00e9 é 日本'
json_check "log: JSON-looking text"         '{"a":[1,2,"\n"]}'

# ---------------------------------------------------------------- TELEMETRY_SCRIPT
tdir=$TMP/tel; mkdir -m 755 "$tdir"
marker=$TMP/ran
mk() { printf '#!/bin/sh\necho ran >> "%s"\n' "$marker" > "$tdir/t.sh"; chmod "$1" "$tdir/t.sh"; chown "${2:-0}:${2:-0}" "$tdir/t.sh"; : > "$marker"; rm -f "$marker"; }
ran() { [[ -e "$marker" ]]; }

if true; then
    nft_reset; mk 755
    out=$(TELEMETRY_SCRIPT=$tdir/t.sh wd_once); rc=$?
    if ran; then ok "TS root-owned 0755 absolute script is run"; else bad "TS root-owned 0755 absolute script is run" "rc=$rc $out"; fi

    nft_reset; mk 777
    out=$(TELEMETRY_SCRIPT=$tdir/t.sh wd_once); rc=$?
    if ran; then bad "TS world-writable script is NOT run as root" "rc=$rc"; else ok "TS world-writable script is NOT run as root"; fi

    nft_reset; mk 775
    out=$(TELEMETRY_SCRIPT=$tdir/t.sh wd_once); rc=$?
    if ran; then bad "TS group-writable script is NOT run as root" "rc=$rc"; else ok "TS group-writable script is NOT run as root"; fi

    nft_reset; mk 755 12345
    out=$(TELEMETRY_SCRIPT=$tdir/t.sh wd_once); rc=$?
    if ran; then bad "TS script owned by another uid is NOT run as root" "rc=$rc"; else ok "TS script owned by another uid is NOT run as root"; fi

    nft_reset; mk 755
    out=$(cd "$tdir" && TELEMETRY_SCRIPT=./t.sh wd_once); rc=$?
    if ran; then bad "TS relative path is NOT run" "rc=$rc"; else ok "TS relative path is NOT run"; fi

    nft_reset; mk 755; chmod 777 "$tdir"
    out=$(TELEMETRY_SCRIPT=$tdir/t.sh wd_once); rc=$?
    chmod 755 "$tdir"
    if ran; then bad "TS script in a world-writable directory is NOT run as root" "rc=$rc"; else ok "TS script in a world-writable directory is NOT run as root"; fi

    nft_reset; mk 755
    nft_reset; mk 777
    out=$(TELEMETRY_SCRIPT=$tdir/t.sh wd_once); rc=$?
    if grep -q '"level":"error"' <<<"$out"; then ok "TS a refused script is logged as an error"; else bad "TS a refused script is logged as an error" "$out"; fi

    # whoever can write ANY directory above the script can rename the one below it
    nft_reset; mk 755
    mkdir -m 777 "$TMP/gp"; mkdir -m 755 "$TMP/gp/inner"; cp "$tdir/t.sh" "$TMP/gp/inner/t.sh"; chmod 755 "$TMP/gp/inner/t.sh"
    out=$(TELEMETRY_SCRIPT=$TMP/gp/inner/t.sh wd_once); rc=$?
    if ran; then bad "TS script under a world-writable GRANDPARENT directory is NOT run as root" "rc=$rc"; else ok "TS script under a world-writable GRANDPARENT directory is NOT run as root"; fi
    chmod 1777 "$TMP/gp"
    out=$(TELEMETRY_SCRIPT=$TMP/gp/inner/t.sh wd_once); rc=$?
    if ran; then ok "TS ... but a sticky root-owned directory above it (like /tmp) is accepted"; else bad "TS ... but a sticky root-owned directory above it (like /tmp) is accepted" "rc=$rc $out"; fi

    # a symlink is judged by what it points to AND by the directory it sits in
    nft_reset; mk 755; rm -f "$marker"
    mkdir -m 755 "$TMP/lnk_ok"; ln -s "$tdir/t.sh" "$TMP/lnk_ok/t.sh"
    out=$(TELEMETRY_SCRIPT=$TMP/lnk_ok/t.sh wd_once); rc=$?
    if ran; then ok "TS a symlink to a safe script in a safe directory is run"; else bad "TS a symlink to a safe script in a safe directory is run" "rc=$rc $out"; fi
    rm -f "$marker"; mkdir -m 777 "$TMP/lnk_bad"; ln -s "$tdir/t.sh" "$TMP/lnk_bad/t.sh"
    out=$(TELEMETRY_SCRIPT=$TMP/lnk_bad/t.sh wd_once); rc=$?
    if ran; then bad "TS a symlink sitting in a world-writable directory is NOT run" "rc=$rc"; else ok "TS a symlink sitting in a world-writable directory is NOT run"; fi

    # a script that fails is reported (as before)
    nft_reset; printf '#!/bin/sh\nexit 3\n' > "$tdir/t.sh"; chmod 755 "$tdir/t.sh"; chown 0:0 "$tdir/t.sh"
    out=$(TELEMETRY_SCRIPT=$tdir/t.sh wd_once)
    assert_has "TS a failing telemetry script is still reported" "$out" "Telemetry script failed"
fi

t_finish
