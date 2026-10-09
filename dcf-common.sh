# shellcheck shell=bash
# shellcheck disable=SC2034  # GATE_BIN, GATE_WHY, SAFE_WHY are for the sourcing script
# ============================================================================
# DeMoD Communications Framework - code shared by the watchdog scripts
# ============================================================================
# Copyright (c) 2024-2025 DeMoD LLC. All Rights Reserved. LICENSE BSD 3
# ============================================================================
# Sourced by dcf-watchdog.sh, dcf-telemetry.sh and dcf-healthcheck.sh from the
# directory they live in; never run. Those scripts run as root, so what they
# trust is decided here, once:
#
#   harden_env   the launcher's environment is not code we run: BASH_ENV, ENV,
#                LD_PRELOAD and friends are dropped, PATH is pinned to the system
#                directories (or to DCF_PATH, each entry checked), IFS is reset;
#   safe_exec_file / dir_chain_safe
#                a file may be run as root only if nobody else can change it or
#                rename a directory above it;
#   find_gate    where dcf-gate is, and that it passes the check above.
#
# The caller sets SCRIPT_DIR (its own directory) before sourcing. Nothing here
# runs an external program until harden_env has pinned PATH, and sourcing does
# not change the sourcing shell.
# ============================================================================

readonly DCF_DEFAULT_PATH=/usr/sbin:/usr/bin:/sbin:/bin

SAFE_WHY=""     # why safe_exec_file / dir_chain_safe / harden_env refused
GATE_BIN=""     # the gate find_gate settled on
GATE_WHY=""     # why find_gate found none

# dir_chain_safe DIR -> 0 if DIR and every directory above it is owned by uid 0
# or the running user and cannot be written by group or others. (Whoever can
# write one of them can rename the directory below it and put their own file
# where ours was.) A world-writable directory is accepted only if it is root's
# and sticky, like /tmp: there nobody can rename entries they do not own.
dir_chain_safe() {
    local d="$1" downer dmode
    while :; do
        read -r downer dmode < <(stat -L -c '%u %a' -- "$d") || { SAFE_WHY="cannot stat $d"; return 1; }
        if (( downer != 0 && downer != EUID )); then
            SAFE_WHY="directory $d is owned by uid $downer; fix: chown root $d"; return 1
        fi
        if (( 8#$dmode & 8#022 )); then
            if ! { (( 8#$dmode & 8#1000 )) && (( downer == 0 )); }; then
                SAFE_WHY="directory $d is writable by group or others (mode $dmode); fix: chmod g-w,o-w $d"; return 1
            fi
        fi
        [[ "$d" == / ]] && return 0
        d=$(dirname -- "$d")
    done
}

# safe_exec_file PATH -> 0 if PATH is an absolute path to an executable regular
# file that only root (or this user) can change: owned by uid 0 or the running
# user, no group/world write bit, and every directory above it (after resolving
# symlinks, and also along the path as given) passes dir_chain_safe.
# On refusal, SAFE_WHY says why and what to run.
safe_exec_file() {
    local p="$1" resolved owner mode pdir
    SAFE_WHY=""
    if [[ "$p" != /* ]]; then SAFE_WHY="not an absolute path"; return 1; fi
    if [[ ! -f "$p" || ! -x "$p" ]]; then SAFE_WHY="not an executable regular file"; return 1; fi
    resolved=$(readlink -f -- "$p") || { SAFE_WHY="cannot resolve the path"; return 1; }
    read -r owner mode < <(stat -L -c '%u %a' -- "$resolved") || { SAFE_WHY="cannot stat it"; return 1; }
    if (( owner != 0 && owner != EUID )); then SAFE_WHY="owned by uid $owner; fix: chown root $resolved"; return 1; fi
    if (( 8#$mode & 8#022 )); then SAFE_WHY="writable by group or others (mode $mode); fix: chmod g-w,o-w $resolved"; return 1; fi
    dir_chain_safe "$(dirname -- "$resolved")" || return 1
    pdir=$(readlink -f -- "$(dirname -- "$p")") || { SAFE_WHY="cannot resolve the directory"; return 1; }
    dir_chain_safe "$pdir" || return 1
    return 0
}

# harden_env -> 0, or 1 with SAFE_WHY set (the caller exits 69).
# bash reads BASH_ENV / ENV before a script's first line, so for the shell that is
# running this script the only defence is to start it as `bash -p` (the image's
# ENTRYPOINT does); what is done here is to keep all of these away from everything
# the script starts.
harden_env() {
    unset BASH_ENV ENV CDPATH GLOBIGNORE LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT
    IFS=$' \t\n'
    PATH=$DCF_DEFAULT_PATH
    export PATH
    [[ -n "${DCF_PATH:-}" ]] || return 0
    # DCF_PATH replaces the system directories (a system that keeps its tools
    # elsewhere, such as NixOS). Every entry must be an absolute directory that
    # only root can change; empty entries (which would mean "here") are refused.
    local -a dirs=()
    local d
    IFS=: read -ra dirs <<<"$DCF_PATH"
    if (( ${#dirs[@]} == 0 )); then SAFE_WHY="DCF_PATH has no directories"; return 1; fi
    for d in "${dirs[@]}"; do
        if [[ "$d" != /* || ! -d "$d" ]]; then
            SAFE_WHY="DCF_PATH entry '$d' is not an absolute directory"; return 1
        fi
        if ! dir_chain_safe "$d"; then
            SAFE_WHY="DCF_PATH entry '$d' refused: $SAFE_WHY"; return 1
        fi
    done
    PATH=$(IFS=:; printf '%s' "${dirs[*]}")
    export PATH
    return 0
}

# find_gate -> 0 with GATE_BIN set, or 1 with GATE_WHY set. DCF_GATE, if set, is
# the only candidate (a wrong path is an error, not a fallback to another gate).
find_gate() {
    local cand cands=()
    GATE_BIN=""; GATE_WHY=""
    if [[ -n "${DCF_GATE:-}" ]]; then
        cands=("$DCF_GATE")
    else
        cands=(/usr/local/bin/dcf-gate "$SCRIPT_DIR/gate/dcf-gate")
    fi
    for cand in "${cands[@]}"; do
        [[ -e "$cand" ]] || continue
        if safe_exec_file "$cand"; then
            GATE_BIN="$cand"
            return 0
        fi
        GATE_WHY="dcf-gate at $cand refused: $SAFE_WHY"
        return 1
    done
    GATE_WHY="dcf-gate not found (set DCF_GATE, or build it: make -C gate)"
    return 1
}
