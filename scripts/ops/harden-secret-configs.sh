#!/usr/bin/env bash
#
# Reconcile ownership and mode on the configs that carry secrets.
#
# install-node.sh sets these correctly — and ONLY at install time. Nothing re-applies them, so a
# node provisioned before a hardening step landed never receives it, and any later drift is
# permanent. That is not hypothetical: on 2026-09-22 four of the eight nodes were found holding
# /etc/ghost/pool-config.toml at 644 ghost:ghost instead of 600 root:root (#916). That file
# carries authority_secret_key, and its only consumer is sri-pool.service, which runs as root.
# The permissive mode bought nothing and handed the unprivileged service account read access to
# key material it never needs.
#
# The exposure was not limited to the live file. Timestamped .bak copies inherit the mode of
# their source, so a permissive source silently produces a growing set of permissive copies —
# several of which held CURRENT, not superseded, key material. The sibling globs below exist for
# that reason; reconciling only the live file leaves the copies behind.
#
# ⚠ Owner is per-file, not one blanket rule. pool-config.toml is read by sri-pool (root), while
# pool.toml and bitcoin.conf are read by ghost-pool/ghostd (ghost). Chowning the whole set to
# root would break ghost-pool at its next restart — a delayed failure, which is the worst kind.
#
# Usage:
#   harden-secret-configs.sh              # apply, print what changed
#   harden-secret-configs.sh --check      # report only; exit 1 if anything needs correcting
#   harden-secret-configs.sh --root DIR   # treat DIR as / (for the self-test)
#
# Exit: 0 = nothing to correct (or corrected), 1 = corrections needed (--check) or apply failed,
#       2 = INCONCLUSIVE: no target file existed, so nothing was examined.
#
# The 2 matters. A reconciler whose glob matches nothing would otherwise print "0 files need
# correcting" and exit 0 — a clean bill of health from a run that looked at nothing. Silence
# must not read as safety.

set -uo pipefail

CHECK=false
ROOT=""
while [ $# -gt 0 ]; do
    case "$1" in
        --check) CHECK=true; shift ;;
        --root)  ROOT="${2:?--root needs a directory}"; shift 2 ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 64 ;;
    esac
done

# want_owner|want_mode|path-glob        ("-" = do not enforce owner)
#
# Globs are matched against the filesystem, so a node that has no /opt/ghost/config simply
# contributes nothing rather than erroring. Siblings (.bak.*, .prev-*) are included because they
# carry the same secrets as the file they were copied from.
#
# ⚠ Owner is enforced on the LIVE files only, and deliberately not on the backups.
#
# A live config must be readable by the service that reads it, so its owner is load-bearing:
# pool-config.toml is read by sri-pool (root), pool.toml and bitcoin.conf by ghost-pool/ghostd
# (ghost). A backup is read by nobody, so its owner carries no such requirement — and enforcing
# one is actively harmful. The fleet proved it: pool.toml backups sit at root:root, and an
# earlier version of this table demanded ghost:ghost for them, which would have LOOSENED every
# one of them — a hardening tool handing the ghost user access it did not previously have.
#
# At mode 600 the owner does not affect exposure either way, so the rule is: tighten the mode
# everywhere, and only ever set an owner where a service depends on it.
SPEC=(
    "root:root|600|/etc/ghost/pool-config.toml"
    "-|600|/etc/ghost/pool-config.toml.*"
    "root:root|600|/opt/ghost/config/pool-config.toml"
    "ghost:ghost|600|/etc/ghost/pool.toml"
    "-|600|/etc/ghost/pool.toml.*"
    "ghost:ghost|600|/etc/bitcoin/bitcoin.conf"
    "-|600|/etc/bitcoin/bitcoin.conf.*"
)

SUDO=""
if [ "$(id -u)" != 0 ] && [ -z "$ROOT" ]; then
    command -v sudo >/dev/null 2>&1 && SUDO="sudo -n"
fi

# Try unprivileged first and escalate only when that fails.
#
# Reaching for sudo unconditionally is wrong in both directions: it fails outright where sudo
# needs a password (which made every file read as UNREADABLE the first time this ran), and it
# escalates for reads that never needed it. On a node this lands correctly either way — root
# succeeds on the first attempt, the ghost user succeeds on the second.
run_priv() {
    if "$@" 2>/dev/null; then return 0; fi
    [ -n "$SUDO" ] || return 1
    $SUDO "$@" 2>/dev/null
}

# Owner enforcement needs root. Say so out loud when it is unavailable rather than quietly
# enforcing mode alone and reporting success — "the check did not run" must not look like a
# verdict. Under --root the harness owns the fixtures, so owner is reported, never applied.
ENFORCE_OWNER=true
if [ -n "$ROOT" ]; then
    ENFORCE_OWNER=false
elif [ "$(id -u)" != 0 ] && [ -z "$SUDO" ]; then
    ENFORCE_OWNER=false
fi

EXAMINED=0
NEED_MODE=0
NEED_OWNER=0
FIXED=0
FAILED=0

for entry in "${SPEC[@]}"; do
    want_owner="${entry%%|*}"
    rest="${entry#*|}"
    want_mode="${rest%%|*}"
    glob="${rest#*|}"

    # Unmatched globs must expand to nothing, not to the literal pattern.
    shopt -s nullglob
    # shellcheck disable=SC2206  # deliberate glob expansion
    matches=( ${ROOT}${glob} )
    shopt -u nullglob

    for f in "${matches[@]}"; do
        [ -f "$f" ] || continue
        EXAMINED=$((EXAMINED + 1))

        cur_mode=$(run_priv stat -c '%a' "$f") || cur_mode=""
        cur_owner=$(run_priv stat -c '%U:%G' "$f") || cur_owner=""

        if [ -z "$cur_mode" ]; then
            echo "  UNREADABLE $f (cannot stat; not counted as clean)"
            FAILED=$((FAILED + 1))
            continue
        fi

        if [ "$cur_mode" != "$want_mode" ]; then
            NEED_MODE=$((NEED_MODE + 1))
            if $CHECK; then
                echo "  MODE  $f  $cur_mode -> $want_mode"
            elif run_priv chmod "$want_mode" "$f"; then
                echo "  MODE  $f  $cur_mode -> $want_mode  (applied)"
                FIXED=$((FIXED + 1))
            else
                echo "  MODE  $f  $cur_mode -> $want_mode  *** FAILED ***"
                FAILED=$((FAILED + 1))
            fi
        fi

        if [ "$want_owner" != "-" ] && [ "$cur_owner" != "$want_owner" ]; then
            if ! $ENFORCE_OWNER; then
                # Reported, not silently dropped, and deliberately NOT counted as a correction
                # that was made.
                echo "  OWNER $f  $cur_owner -> $want_owner  (not enforced here: needs root)"
                continue
            fi
            NEED_OWNER=$((NEED_OWNER + 1))
            if $CHECK; then
                echo "  OWNER $f  $cur_owner -> $want_owner"
            elif run_priv chown "$want_owner" "$f"; then
                echo "  OWNER $f  $cur_owner -> $want_owner  (applied)"
                FIXED=$((FIXED + 1))
            else
                echo "  OWNER $f  $cur_owner -> $want_owner  *** FAILED ***"
                FAILED=$((FAILED + 1))
            fi
        fi
    done
done

if [ "$EXAMINED" -eq 0 ]; then
    echo "  INCONCLUSIVE: no secret-bearing config matched on this host."
    echo "  Nothing was examined, so this proves nothing either way."
    exit 2
fi

NEED=$((NEED_MODE + NEED_OWNER))

if $CHECK; then
    if [ "$NEED" -eq 0 ] && [ "$FAILED" -eq 0 ]; then
        echo "  PASS: $EXAMINED secret-bearing config(s) examined, all at the required owner and mode"
        exit 0
    fi
    echo "  *** FAIL: $NEED of $EXAMINED secret-bearing config(s) need correcting"
    [ "$FAILED" -gt 0 ] && echo "  *** plus $FAILED that could not be read"
    echo "  *** run: scripts/ops/harden-secret-configs.sh"
    exit 1
fi

echo "  examined=$EXAMINED corrected=$FIXED failed=$FAILED"
[ "$FAILED" -gt 0 ] && exit 1
exit 0
