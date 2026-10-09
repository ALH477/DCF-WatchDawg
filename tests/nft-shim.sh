#!/usr/bin/env bash
# tests/nft-shim.sh -- stands in for nft when the kernel has no nf_tables.
# Records every call (argv, and stdin for `-f -`) in $NFT_SHIM_LOG and pretends
# nothing exists yet: `list ...` fails, everything else succeeds. It cannot
# say what nft would accept; tests that need that skip in shim mode.
{
    printf 'ARGV:'; printf ' [%s]' "$@"; printf '\n'
    if [[ "${1:-}" == "-f" ]]; then
        printf 'STDIN-BEGIN\n'
        cat
        printf '\nSTDIN-END\n'
    fi
} >> "${NFT_SHIM_LOG:?}"
case "${1:-}" in
    list) exit 1 ;;
esac
exit 0
