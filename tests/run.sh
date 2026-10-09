#!/usr/bin/env bash
# tests/run.sh [NAME...] -- run the suite (all tests/t_*, or the named ones).
#
#   tests/run.sh                 everything
#   tests/run.sh t_sync t_vip    just those
#   make test                    same as tests/run.sh
#
# Needs: bash, python3 (sqlite3 module, for fixture databases), the sqlite3 CLI,
# jq, gcc (for the gate CLI), and nft with a kernel that has nf_tables. Without
# the sqlite3 CLI it borrows one from nixpkgs (and shellcheck, for the lint
# step) if nix is present. Without a usable nft the suite runs in SHIM mode and
# says so; shim mode checks what the scripts send, never what nft does.
set -u
cd "$(dirname "$0")/.." || exit 2
root=$PWD

if ! command -v sqlite3 >/dev/null 2>&1 && [[ -z "${DCF_TEST_NIX:-}" ]] && command -v nix >/dev/null 2>&1; then
    echo "# sqlite3 not found; fetching sqlite + shellcheck from nixpkgs"
    DCF_TEST_NIX=1 exec nix --extra-experimental-features 'nix-command flakes' \
        shell nixpkgs#sqlite nixpkgs#shellcheck -c bash "$0" "$@"
fi
command -v sqlite3 >/dev/null 2>&1 || { echo "tests/run.sh: sqlite3 CLI not found" >&2; exit 2; }

# the gate CLI the new scripts call (a no-op while gate/ does not exist)
if [[ -f gate/Makefile ]]; then
    make -s -C gate || { echo "tests/run.sh: gate build failed" >&2; exit 2; }
fi

# shellcheck source=tests/lib.sh
. tests/lib.sh
t_detect_mode
echo "# nft mode: $DCF_TEST_NFT_MODE  ($(nft --version 2>/dev/null || echo 'nft not installed'))"

if [[ $# -gt 0 ]]; then
    names=("$@")
else
    names=()
    for f in tests/t_*.sh tests/t_*.py; do
        [[ -e "$f" ]] && names+=("$(basename "${f%.*}")")
    done
fi

fail=0; total_pass=0; total_fail=0; total_skip=0
summary=()
for n in "${names[@]}"; do
    if [[ -f "tests/$n.sh" ]]; then cmd=(bash "tests/$n.sh")
    elif [[ -f "tests/$n.py" ]]; then cmd=(python3 "tests/$n.py")
    else echo "no such test: $n" >&2; fail=1; continue; fi
    echo "== $n"
    out=$(mktemp)
    "${cmd[@]}" 2>&1 | tee "$out"
    rc=${PIPESTATUS[0]}
    line=$(grep -E '^# .*: pass=[0-9]+ fail=[0-9]+ skip=[0-9]+' "$out" | tail -1)
    p=$(sed -n 's/.*pass=\([0-9]*\).*/\1/p' <<<"$line"); f=$(sed -n 's/.*fail=\([0-9]*\).*/\1/p' <<<"$line"); s=$(sed -n 's/.*skip=\([0-9]*\).*/\1/p' <<<"$line")
    rm -f -- "$out"
    total_pass=$((total_pass + ${p:-0})); total_fail=$((total_fail + ${f:-0})); total_skip=$((total_skip + ${s:-0}))
    if [[ $rc -ne 0 ]]; then fail=1; summary+=("FAIL $n (exit $rc)"); else summary+=("ok   $n"); fi
done

# lint, when shellcheck is around (and the whole suite was asked for)
if command -v shellcheck >/dev/null 2>&1 && [[ $# -eq 0 ]]; then
    echo "== shellcheck"
    files=(dcf-watchdog.sh dcf-telemetry.sh tests/*.sh)
    for f in dcf-healthcheck.sh scripts/*.sh; do [[ -f "$f" ]] && files+=("$f"); done
    if shellcheck -x -s bash "${files[@]}"; then summary+=("ok   shellcheck"); else fail=1; summary+=("FAIL shellcheck"); fi
else
    summary+=("skip shellcheck (not installed, or a subset was requested)")
fi

echo
echo "== summary (nft mode: $DCF_TEST_NFT_MODE)"
printf '%s\n' "${summary[@]}"
echo "total: pass=$total_pass fail=$total_fail skip=$total_skip"
exit $fail
