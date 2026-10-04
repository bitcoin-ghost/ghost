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
# Exit 0 = every socket-holding unit raises it, 1 = one does not, 2 = INCONCLUSIVE.
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

    if grep -qE '^LimitNOFILE=' <<<"$body"; then
        echo "  ✓  $want"
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

echo "check-socket-units-raise-nofile: all $found socket-holding unit(s) raise LimitNOFILE"
exit 0
