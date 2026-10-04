#!/usr/bin/env bash
#
# Fail if a systemd unit that holds network sockets ships without LimitNOFILE.
#
# ## Why this exists
#
# `sri-pool.service` runs `pool_sv2`, which holds the world-open SV2 miner port (:34255). It was
# the ONLY one of the four installer-written units without `LimitNOFILE`, so it inherited the
# default SOFT limit of 1024 while ghostd, ghost-pool and sri-translator all set 65536.
#
# MEASURED on the live fleet before the fix:
#
#     sri-pool    LimitNOFILE 524288  soft 1024
#     ghost-pool  LimitNOFILE 65536   soft 65536
#
# A process is bounded by its SOFT limit unless it raises it itself, so the miner-facing process
# capped near 1,000 descriptors against a configured ceiling of 1,000 miners — and a miner
# connection costs more than one fd.
#
# ⚠ `capacity.rs` derives its ceiling from `getrlimit` in GHOST-POOL, which holds almost no miner
# sockets. So the capacity model was measuring the wrong process and could never have seen this.
#
# MEASURED on vm5, 2026-10-04: ghost-pool held **197** descriptors, none of them a miner socket,
# and reported `fd=65536 -> fd_max=16384` as a bound on miner capacity.
#
# Rather than have ghost-pool probe other processes, this check makes its self-read SOUND: every
# socket-holding unit must raise `LimitNOFILE` to **at least** ghost-pool's value. Then
# `getrlimit` in ghost-pool can only ever UNDER-state the budget of the units that hold the miner
# sockets, which is the safe direction. Without this the agreement is a coincidence — and it was
# not one: sri-pool sat at a soft 1024 against ghost-pool's 65536 while the node advertised
# capacity for 1,000 miners (measured uniform across all eight nodes, 2026-10-04).
#
# Exit 0 = every socket-holding unit raises it to >= ghost-pool's, 1 = one does not,
# 2 = INCONCLUSIVE.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 2

SRC="scripts/install-node.sh"
[ -r "$SRC" ] || { echo "check-socket-units-raise-nofile: INCONCLUSIVE — cannot read $SRC"; exit 2; }

# The units that accept or hold network connections. Named explicitly: a unit that does NOT serve
# sockets has no reason to raise the limit, and demanding it everywhere would make this noise.
NEED=("Ghost Bitcoin Core" "Ghost Pool node" "SRI Pool" "SRI Translator")

found=0
missing=0
declare -A LIMITS
for want in "${NEED[@]}"; do
    # The unit body: from its Description to the end of its [Install] section.
    body="$(awk -v w="$want" '
        index($0, "Description=") && index($0, w) { on = 1 }
        on { print }
        on && /WantedBy=multi-user.target/ { exit }
    ' "$SRC")"

    if [ -z "$body" ]; then
        echo "check-socket-units-raise-nofile: INCONCLUSIVE — no unit matching '$want' in $SRC."
        echo "  It was renamed or removed; this check now covers less than it claims."
        exit 2
    fi
    found=$((found + 1))

    limit="$(grep -E '^LimitNOFILE=' <<<"$body" | tail -1 | cut -d= -f2 | tr -dc '0-9')"
    if [ -n "$limit" ]; then
        echo "  ✓  $want — LimitNOFILE=$limit"
        LIMITS["$want"]="$limit"
    else
        echo "  *** $want — holds network sockets and sets NO LimitNOFILE (inherits soft 1024)"
        missing=$((missing + 1))
    fi
done

if [ "$found" -lt "${#NEED[@]}" ]; then
    echo "check-socket-units-raise-nofile: INCONCLUSIVE — matched $found of ${#NEED[@]} units"
    exit 2
fi

if [ "$missing" -gt 0 ]; then
    echo
    echo "check-socket-units-raise-nofile: $missing socket-holding unit(s) do not raise LimitNOFILE."
    echo
    echo "  systemd gives a soft limit of 1024 by default, and a process is bounded by the SOFT"
    echo "  limit. A miner-facing service at 1024 fds cannot reach a four-figure miner count, and"
    echo "  the symptom is accept() failures under load rather than anything that names the cause."
    exit 1
fi

# The ordering assertion. `capacity.rs` reads `getrlimit(RLIMIT_NOFILE)` in ghost-pool and divides
# by FD_BUDGET_DIVISOR to bound miner capacity — but miner sockets are held by sri-pool (:34255)
# and sri-translator (:3333/:4444), not by ghost-pool. That self-read is only sound while the
# acceptors' budgets are at least as large as ghost-pool's. Checked numerically, because "both set
# LimitNOFILE" was already true of a tree in which one of them set it to 1024.
POOL_LIMIT="${LIMITS[Ghost Pool node]:-}"
if [ -z "$POOL_LIMIT" ]; then
    echo "check-socket-units-raise-nofile: INCONCLUSIVE — could not read the Ghost Pool node unit's"
    echo "  LimitNOFILE, which is the value capacity.rs measures. Nothing to compare the acceptors to."
    exit 2
fi

acceptor_bad=0
for acceptor in "SRI Pool" "SRI Translator"; do
    got="${LIMITS[$acceptor]:-}"
    [ -n "$got" ] || continue          # already counted as missing above
    if [ "$got" -lt "$POOL_LIMIT" ]; then
        echo "  *** $acceptor — LimitNOFILE=$got is BELOW the Ghost Pool node's $POOL_LIMIT"
        acceptor_bad=$((acceptor_bad + 1))
    fi
done

if [ "$acceptor_bad" -gt 0 ]; then
    echo
    echo "check-socket-units-raise-nofile: $acceptor_bad miner-facing unit(s) have a SMALLER fd"
    echo "budget than ghost-pool, whose budget is the one capacity.rs advertises."
    echo
    echo "  capacity.rs calls getrlimit in ghost-pool — a process that held 197 descriptors and no"
    echo "  miner socket when this was measured. The number it publishes is only a safe bound while"
    echo "  the units that DO hold miner sockets have at least as many descriptors available. Raise"
    echo "  the acceptor to >= $POOL_LIMIT, or lower ghost-pool's to match what the acceptors get."
    exit 1
fi

echo "check-socket-units-raise-nofile: all $found socket-holding unit(s) raise LimitNOFILE,"
echo "  and every miner-facing unit is >= the Ghost Pool node's $POOL_LIMIT (what capacity.rs reads)"
exit 0
