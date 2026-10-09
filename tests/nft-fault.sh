#!/usr/bin/env bash
# tests/nft-fault.sh -- a fault-injecting front for the real nft. Install it as
# `nft` first on PATH (tests/lib.sh: fault_path). Environment:
#   NFT_REAL         absolute path of the real nft                 (required)
#   NFT_FAULT_DIR    a writable directory for the call counter     (required)
#   NFT_DIE_AT=k     SIGKILL the whole process group when the k-th nft call
#                    is made, BEFORE it runs -- a kill -9 / OOM / power cut
#                    between call k-1 and call k. Run the script under setsid.
#   NFT_FAIL_STDIN_RE=RE / NFT_FAIL_MSG=TEXT
#                    if the call's stdin (`nft -f -`) or argv matches the
#                    extended regex RE, print TEXT on stderr and exit 1
#                    without running nft (a refused transaction).
set -u
dir=${NFT_FAULT_DIR:?}
n=$(( $(cat "$dir/count" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$dir/count"
printf '%s\t' "$n" >> "$dir/calls"
printf '[%s] ' "$@" >> "$dir/calls"
printf '\n' >> "$dir/calls"
if [[ -n "${NFT_DIE_AT:-}" && "$n" -ge "$NFT_DIE_AT" ]]; then
    kill -KILL 0
    sleep 5
fi
if [[ "${1:-}" == "-f" ]]; then
    input=$(cat)
    printf '%s\n' "$input" >> "$dir/stdin.$n"
    if [[ -n "${NFT_FAIL_STDIN_RE:-}" ]] && grep -Eq -- "$NFT_FAIL_STDIN_RE" <<<"$input"; then
        printf '%s\n' "${NFT_FAIL_MSG:-synthetic nft failure}" >&2
        exit 1
    fi
    printf '%s\n' "$input" | exec "${NFT_REAL:?}" "$@"
fi
if [[ -n "${NFT_FAIL_STDIN_RE:-}" ]] && grep -Eq -- "$NFT_FAIL_STDIN_RE" <<<"$*"; then
    printf '%s\n' "${NFT_FAIL_MSG:-synthetic nft failure}" >&2
    exit 1
fi
exec "${NFT_REAL:?}" "$@"
