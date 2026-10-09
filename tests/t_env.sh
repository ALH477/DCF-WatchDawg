#!/usr/bin/env bash
# The scripts run as root. They must not take code from the launcher's environment:
# PATH is pinned (DCF_PATH may replace it, and each entry is checked), BASH_ENV / ENV /
# LD_PRELOAD are not passed on to what they run, and a hostile DCF_PATH is refused.
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"; t_start "$@"

db=$TMP/id.db; web=$TMP/web; marker=$TMP/marker
mkdb "$db" '["alice","8.8.4.4","now",0,0,0]'
mkdir -m 755 "$web"
export DB_PATH=$db LOG_LEVEL=error WEB_ROOT=$web

# ---- a hostile PATH: every tool the scripts call is shadowed by one that leaves a mark
evil=$TMP/evil; mkdir -m 755 "$evil"
for t in nft sqlite3 date stat readlink dirname mktemp cut free awk cat wc grep timeout sleep jq ip chmod mv rm id python3 bash; do
    real=$(command -v "$t" 2>/dev/null) || continue
    printf '#!/bin/sh\necho "%s" >> "%s"\nexec "%s" "$@"\n' "$t" "$marker" "$real" > "$evil/$t"
    chmod 755 "$evil/$t"
done
tel=$TMP/tel.sh; printf '#!/usr/bin/env bash\nexec bash "%s"\n' "$TELEMETRY" > "$tel"; chmod 755 "$tel"

rm -f "$marker"
out=$(PATH="$evil:$PATH" TELEMETRY_SCRIPT="$tel" wd_once); rc=$?
assert_eq "hostile PATH: the daemon still runs a full cycle (exit 0)" 0 "$rc"
if [[ -e "$marker" ]]; then bad "hostile PATH: none of the shadowing tools runs" "ran: $(sort -u "$marker" | tr '\n' ' ')"
else ok "hostile PATH: none of the shadowing tools runs"; fi

rm -f "$marker"
env PATH="$evil:$PATH" "$BASH" "$TELEMETRY" >/dev/null 2>&1; rc=$?
assert_eq "hostile PATH: telemetry run alone still publishes (exit 0)" 0 "$rc"
if [[ -e "$marker" ]]; then bad "hostile PATH: telemetry runs none of the shadowing tools" "ran: $(sort -u "$marker" | tr '\n' ' ')"
else ok "hostile PATH: telemetry runs none of the shadowing tools"; fi

rm -f "$marker"
env PATH="$evil:$PATH" "$BASH" "$T_ROOT/dcf-healthcheck.sh" >/dev/null 2>&1
if [[ -e "$marker" ]]; then bad "hostile PATH: the health check runs none of the shadowing tools" "ran: $(sort -u "$marker" | tr '\n' ' ')"
else ok "hostile PATH: the health check runs none of the shadowing tools"; fi

# ---- DCF_PATH is the one way to name other tool directories, and it is checked
mkdir -m 777 "$TMP/open"
out=$(DCF_PATH="$TMP/open:$T_TOOLPATH" wd_once); rc=$?
assert_eq "DCF_PATH with a world-writable directory is refused (exit 69)" 69 "$rc"
assert_has "... and the message names the directory and the fix" "$out" "$TMP/open"
assert_has "... with the chmod to run" "$out" "chmod g-w,o-w"
out=$(DCF_PATH="relative/bin:$T_TOOLPATH" wd_once); rc=$?
assert_eq "DCF_PATH with a relative entry is refused (exit 69)" 69 "$rc"
out=$(DCF_PATH="$TMP/nonexistent:$T_TOOLPATH" wd_once); rc=$?
assert_eq "DCF_PATH with a missing directory is refused (exit 69)" 69 "$rc"
out=$(DCF_PATH="$TMP/open:$T_TOOLPATH" "$BASH" "$TELEMETRY" 2>&1); rc=$?
assert_eq "telemetry refuses it too (exit 69)" 69 "$rc"

# ---- BASH_ENV, ENV and LD_PRELOAD are not handed on
benv=$TMP/benv.sh; printf 'echo benv >> "%s"\n' "$marker" > "$benv"
rm -f "$marker"
out=$(BASH_ENV=$benv ENV=$benv TELEMETRY_SCRIPT="$tel" wd_once); rc=$?
lines=$(wc -l < "$marker" 2>/dev/null || echo 0)
# bash reads BASH_ENV once, for the daemon's own shell, before the script's first line; the script
# can only keep it from the shells it starts (the telemetry script and its children)
assert_eq "BASH_ENV: read once (by the daemon's own shell), not again by the shells it starts" 1 "$lines"
rm -f "$marker"
out=$(BASH_ENV=$benv ENV=$benv TELEMETRY_SCRIPT="$tel" DCF_WATCHDOG_ONCE=1 "$BASH" -p "$WATCHDOG" 2>&1)
if [[ -e "$marker" ]]; then bad "BASH_ENV: not read at all when the daemon is started with bash -p (the image's ENTRYPOINT)" "$(cat "$marker")"
else ok "BASH_ENV: not read at all when the daemon is started with bash -p (the image's ENTRYPOINT)"; fi

if command -v gcc >/dev/null; then
    printf '#include <stdio.h>\n__attribute__((constructor)) static void m(void){FILE*f=fopen("%s","a");if(f){fputs("preload\\n",f);fclose(f);}}\n' "$marker" > "$TMP/pre.c"
    if gcc -shared -fPIC -o "$TMP/pre.so" "$TMP/pre.c" 2>/dev/null; then
        rm -f "$marker"
        out=$(LD_PRELOAD=$TMP/pre.so wd_once); rc=$?
        lines=$(wc -l < "$marker" 2>/dev/null || echo 0)
        assert_eq "LD_PRELOAD: loaded by the daemon's own shell only, not by nft, sqlite3, dcf-gate and the rest" 1 "$lines"
    else skip "LD_PRELOAD" "cannot build a shared object here"; fi
else skip "LD_PRELOAD" "no gcc"; fi

# ---- hostile IFS in the environment changes nothing
out=$(IFS=$'0123456789. \t\n' wd_once); rc=$?
assert_eq "hostile IFS: the daemon still runs a full cycle" 0 "$rc"

t_finish
