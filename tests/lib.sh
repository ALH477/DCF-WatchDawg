# shellcheck shell=bash
# tests/lib.sh -- shared helpers. Source it from a tests/t_*.sh file:
#
#     . "$(dirname "$0")/lib.sh"; t_start "$@"
#
# MODES. The nftables-side tests need a kernel with nf_tables. tests/run.sh
# probes once (`unshare -n nft add table ...`) and exports DCF_TEST_NFT_MODE:
#   real  every test file re-execs itself inside a fresh network namespace
#         (`unshare -n`), so it talks to a REAL kernel nft and cannot touch the
#         host's ruleset;
#   shim  nft is replaced by a recorder (tests/nft-shim.sh). Only what the
#         scripts SEND can be checked; every claim about what nft accepts or
#         what state results is then skip-ed, never passed.
# A test file prints "mode: real|shim" so the log says which one ran.

T_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
T_DIR=$T_ROOT/tests
WATCHDOG=${WATCHDOG:-$T_ROOT/dcf-watchdog.sh}
TELEMETRY=${TELEMETRY:-$T_ROOT/dcf-telemetry.sh}
T_PASS=0; T_FAIL=0; T_SKIP=0
T_CASES=()

t_detect_mode() {
    if [[ -z "${DCF_TEST_NFT_MODE:-}" ]]; then
        if command -v nft >/dev/null 2>&1 && unshare -n nft add table ip dcf_probe >/dev/null 2>&1; then
            DCF_TEST_NFT_MODE=real
        else
            DCF_TEST_NFT_MODE=shim
        fi
        export DCF_TEST_NFT_MODE
    fi
}

t_start() {
    # The scripts under test call the sqlite3 CLI. If it is missing, borrow it
    # (and shellcheck) from nixpkgs once, here, rather than fail silently.
    if ! command -v sqlite3 >/dev/null 2>&1 && [[ -z "${DCF_TEST_NIX:-}" ]] && command -v nix >/dev/null 2>&1; then
        DCF_TEST_NIX=1 exec nix --extra-experimental-features 'nix-command flakes' \
            shell nixpkgs#sqlite nixpkgs#shellcheck -c bash "$0" "$@"
    fi
    command -v sqlite3 >/dev/null 2>&1 || { echo "Bail out! sqlite3 CLI not found (and no nix to fetch it)"; exit 2; }
    t_detect_mode
    if [[ "$DCF_TEST_NFT_MODE" == real && -z "${DCF_TEST_IN_NETNS:-}" ]]; then
        export DCF_TEST_IN_NETNS=1
        exec unshare -n bash "$0" "$@"
    fi
    TMP=$(mktemp -d)
    trap t_cleanup EXIT
    if [[ "$DCF_TEST_NFT_MODE" == shim ]]; then
        mkdir -p "$TMP/bin"
        cp "$T_DIR/nft-shim.sh" "$TMP/bin/nft"
        chmod +x "$TMP/bin/nft"
        export NFT_SHIM_LOG="$TMP/nft.log"
        : > "$NFT_SHIM_LOG"
        export PATH="$TMP/bin:$PATH"
    fi
    echo "# $(basename "$0") mode: $DCF_TEST_NFT_MODE"
}

t_cleanup() {
    local rc=$?
    if [[ -n "${TMP:-}" && -d "$TMP" ]]; then
        rm -rf -- "$TMP"
    fi
    return $rc
}

ok()   { T_PASS=$((T_PASS + 1)); echo "ok - $1"; }
bad()  { T_FAIL=$((T_FAIL + 1)); echo "not ok - $1"; [[ -n "${2:-}" ]] && printf '%s\n' "$2" | sed 's/^/#   /' | head -${T_DETAIL_LINES:-25}; return 0; }
skip() { T_SKIP=$((T_SKIP + 1)); echo "skip - $1${2:+ ($2)}"; }

# assert_eq NAME EXPECTED ACTUAL
assert_eq() {
    if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "expected: $2"$'\n'"actual:   $3"; fi
}
# assert_has NAME HAYSTACK NEEDLE   (fixed string)
assert_has() {
    if [[ "$2" == *"$3"* ]]; then ok "$1"; else bad "$1" "missing: $3"$'\n'"in: ${2:0:600}"; fi
}
assert_lacks() {
    if [[ "$2" != *"$3"* ]]; then ok "$1"; else bad "$1" "unexpected: $3"$'\n'"in: ${2:0:600}"; fi
}

needs_real_nft() {   # needs_real_nft NAME -> returns 1 (and skips) in shim mode
    if [[ "$DCF_TEST_NFT_MODE" != real ]]; then skip "$1" "needs a real nft; mode is shim"; return 1; fi
}

t_finish() {
    echo "# $(basename "$0"): pass=$T_PASS fail=$T_FAIL skip=$T_SKIP"
    [[ $T_FAIL -eq 0 ]]
}

# ---------------------------------------------------------------- fixtures

mkdb() { python3 "$T_DIR/mkdb.py" "$@"; }

# wd_once: one init+sync cycle of the watchdog, as a child process. Environment
# assignments in front of the call reach it. Output (stdout+stderr) is returned.
wd_once() {
    DCF_WATCHDOG_ONCE=1 bash "$WATCHDOG" 2>&1
}

nft_reset() {   # empty the (netns-private) kernel ruleset
    [[ "$DCF_TEST_NFT_MODE" == real ]] && nft flush ruleset
    return 0
}

set_elems() { python3 "$T_DIR/nftset.py" "$1"; }

# chain_rules: the rules of the input chain, one per line, indentation stripped
chain_rules() {
    nft list chain ip dcf_firewall input 2>/dev/null | sed -e '1,/policy/d' -e '/^[[:space:]]*}/d' -e 's/^[[:space:]]*//'
}
chain_policy() {
    nft list chain ip dcf_firewall input 2>/dev/null | grep -o 'policy [a-z]*' | head -1
}

# fault_path: put tests/nft-fault.sh first on PATH as `nft`; sets NFT_FAULT_DIR.
# (Real mode only.) Call fault_reset between runs to zero the call counter.
fault_path() {
    NFT_REAL=$(command -v nft)
    export NFT_REAL
    NFT_FAULT_DIR=$TMP/fault; mkdir -p "$NFT_FAULT_DIR" "$TMP/fbin"
    export NFT_FAULT_DIR
    cp "$T_DIR/nft-fault.sh" "$TMP/fbin/nft"; chmod +x "$TMP/fbin/nft"
    FAULT_PATH="$TMP/fbin:$PATH"
}
fault_reset() { find "$NFT_FAULT_DIR" -type f -delete; }
fault_calls() { cat "$NFT_FAULT_DIR/calls" 2>/dev/null | wc -l; }
