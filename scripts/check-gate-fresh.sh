#!/usr/bin/env bash
# scripts/check-gate-fresh.sh -- is the vendored C still what exsc emits?
#
# Re-emits each vendored unit's C and header from the Exsecutor source named in
# gate/PROVENANCE.md and compares them, byte for byte, with gate/*.gen.[ch].
# Needs an Exsecutor checkout with build/exsc (EXSECUTOR=/path/to/exsecutor);
# fasmg is NOT needed to emit C. Without one this prints [skip] and exits 0:
# consumers of this repository build gate/ with a C compiler alone.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
exsecutor=${EXSECUTOR:-}
exsc=${EXSC:-${exsecutor:+$exsecutor/build/exsc}}

if [[ -z "$exsc" || ! -x "$exsc" || -z "$exsecutor" ]]; then
    echo "[skip] check-gate-fresh: set EXSECUTOR to an Exsecutor checkout with build/exsc to re-emit and compare"
    exit 0
fi

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
rc=0
for unit in dcf_net_gate watchdawg_gate; do
    src="$exsecutor/examples/$unit/$unit.exsc"
    if [[ ! -f "$src" ]]; then echo "[FAIL] $src not found"; rc=1; continue; fi
    for k in c h; do
        "$exsc" aedifica --hospes x86_64-linux --emitte "$k" "$src" -o "$work/$unit.gen.$k" >/dev/null 2>&1 || {
            echo "[FAIL] exsc --emitte $k $unit failed"; rc=1; continue; }
        if cmp -s "$work/$unit.gen.$k" "$here/gate/$unit.gen.$k"; then
            echo "[ok]   gate/$unit.gen.$k is byte-identical to exsc --emitte $k ($(sha256sum <"$work/$unit.gen.$k" | cut -c1-16)...)"
        else
            echo "[FAIL] gate/$unit.gen.$k differs from what $exsc emits from $src"; rc=1
        fi
    done
done
exit $rc
