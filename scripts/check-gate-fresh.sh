#!/usr/bin/env bash
# scripts/check-gate-fresh.sh -- is the vendored C still what exsc emits?
#
# Re-emits the C unit and its header from the Exsecutor source named in
# gate/PROVENANCE.md and compares them, byte for byte, with gate/*.gen.[ch].
# Needs an Exsecutor checkout with build/exsc (EXSECUTOR=/path/to/exsecutor);
# fasmg is NOT needed to emit C. Without one this prints [skip] and exits 0:
# consumers of this repository build gate/ with a C compiler alone.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
exsecutor=${EXSECUTOR:-}
exsc=${EXSC:-${exsecutor:+$exsecutor/build/exsc}}
src=${exsecutor:+$exsecutor/examples/dcf_net_gate/dcf_net_gate.exsc}

if [[ -z "$exsc" || ! -x "$exsc" || ! -f "${src:-/nonexistent}" ]]; then
    echo "[skip] check-gate-fresh: set EXSECUTOR to an Exsecutor checkout with build/exsc to re-emit and compare"
    exit 0
fi

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
rc=0
for k in c h; do
    "$exsc" aedifica --hospes x86_64-linux --emitte "$k" "$src" -o "$work/dcf_net_gate.gen.$k" >/dev/null 2>&1 || {
        echo "[FAIL] exsc --emitte $k failed"; rc=1; continue; }
    if cmp -s "$work/dcf_net_gate.gen.$k" "$here/gate/dcf_net_gate.gen.$k"; then
        echo "[ok]   gate/dcf_net_gate.gen.$k is byte-identical to exsc --emitte $k ($(sha256sum <"$work/dcf_net_gate.gen.$k" | cut -c1-16)...)"
    else
        echo "[FAIL] gate/dcf_net_gate.gen.$k differs from what $exsc emits from $src"; rc=1
    fi
done
exit $rc
