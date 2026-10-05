#!/usr/bin/env bash
#
# Ask the question nothing else asks: is anything MERGED but NOT DEPLOYED?
#
# ## Why this exists
#
# `check-fleet-uniformity.sh` compares nodes to each other, and the drift sweep asks "is anything
# live but undeclared". Both are the wrong way round for the failure that actually happened: the
# fleet sat **22 commits behind main** for a week with every check green, because the eight nodes
# agreed with each other perfectly — on a build from 2026-09-27 (#993).
#
# Agreement between nodes says nothing about agreement with main. What was undeployed included the
# fix for four `broadcast` receiver loops that exit permanently on `Lagged`, one of which is the
# task that creates the payout proposal for a found block.
#
# ## What it checks
#
#   1. Every node's running `ghost-pool` reports the same build sha (uniformity — still necessary).
#   2. That sha is an ANCESTOR of `origin/main`. A sha that is not means the fleet is running
#      something that was never merged, which is a different and worse problem.
#   3. Nothing is behind: `git log <sha>..origin/main` is empty. When it is not, every commit is
#      listed — with NO name filter, because the point is to see what was forgotten, and a filter
#      can only hide the thing nobody thought to look for.
#   4. Every literal `Key=Value` directive the installer writes into a unit is present in the live
#      unit. This is the half `deploy-node.sh` does not cover: it swaps binaries only, so a unit
#      change (`LimitNOFILE` on sri-pool, #991) can be merged and never reach a node.
#
# Directives containing shell interpolation cannot be compared literally and are skipped — the
# count of skipped lines is REPORTED, so the check states its own coverage instead of quietly
# examining three lines and printing a tick.
#
# Usage:
#   scripts/ops/check-fleet-is-current.sh [<node> ...]        # defaults to all eight
#   scripts/ops/check-fleet-is-current.sh --binary-only       # skip the unit comparison (fast)
#
# Exit 0 = the fleet is current, 1 = something merged is not deployed, 2 = INCONCLUSIVE.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT" || exit 2

BINARY_ONLY=false
if [ "${1:-}" = "--binary-only" ]; then BINARY_ONLY=true; shift; fi

NODES=("$@")
if [ ${#NODES[@]} -eq 0 ]; then
    NODES=(ghost-vm1 ghost-vm2 ghost-vm3 ghost-vm4 ghost-vm5 ghost-vm6 ghost-vm7 ghost-vm8)
fi

# ⛔ FIRST, before any history question. `git log`, `-S`, `--follow` and `blame` all truncate
# silently in a shallow clone — no error, no warning, just fewer commits. A "fleet is current"
# verdict derived from a truncated history is exactly the false green this script exists to stop.
if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" != "false" ]; then
    echo "check-fleet-is-current: INCONCLUSIVE — shallow clone."
    echo "  \`git log <sha>..origin/main\` truncates with no error here, so 'nothing undeployed'"
    echo "  cannot be distinguished from 'history not fetched'. Run \`git fetch --unshallow\`."
    exit 2
fi

if ! git rev-parse --verify --quiet origin/main >/dev/null; then
    echo "check-fleet-is-current: INCONCLUSIVE — no origin/main ref. Nothing to compare against."
    exit 2
fi
git fetch --quiet origin main 2>/dev/null || true
MAIN="$(git rev-parse origin/main)"

# ---------------------------------------------------------------- 1. running build, per node
declare -A BUILD
unreachable=0
for node in "${NODES[@]}"; do
    # `--version` prints: ghost-pool 1.11.43 (95de37cfd built 2026-09-27T20:22:34Z)
    line="$(ssh -o ConnectTimeout=15 -o BatchMode=yes "$node" \
            "/opt/ghost/bin/ghost-pool --version 2>/dev/null" 2>/dev/null)"
    sha="$(printf '%s' "$line" | sed -nE 's/.*\(([0-9a-f]{7,40}) built .*/\1/p')"
    if [ -z "$sha" ]; then
        echo "  ??? $node — could not read a build sha from \`ghost-pool --version\`"
        echo "      got: ${line:-<nothing>}"
        unreachable=$((unreachable + 1))
        continue
    fi
    BUILD["$node"]="$sha"
    printf '  %-10s %s\n' "$node" "$line"
done

if [ "$unreachable" -gt 0 ]; then
    echo
    echo "check-fleet-is-current: INCONCLUSIVE — $unreachable of ${#NODES[@]} node(s) did not report a"
    echo "  build sha. A node that cannot be asked is not a node that is up to date."
    exit 2
fi

# Uniformity. Still necessary — it just is not sufficient, which is the whole point of this script.
SHAS="$(printf '%s\n' "${BUILD[@]}" | sort -u)"
if [ "$(printf '%s\n' "$SHAS" | wc -l | tr -d ' ')" -ne 1 ]; then
    echo
    echo "  *** the fleet is NOT uniform — build shas present:"
    printf '%s\n' "$SHAS" | sed 's/^/        /'
    echo
    echo "check-fleet-is-current: nodes disagree on the running build. Resolve that before asking"
    echo "  whether the fleet is current — 'behind main' is not well defined across two builds."
    exit 1
fi
FLEET_SHA="$SHAS"

# ---------------------------------------------------------------- 2. is it even on main?
if ! git cat-file -e "${FLEET_SHA}^{commit}" 2>/dev/null; then
    echo
    echo "  *** the running build sha $FLEET_SHA is not a commit in this repository."
    echo
    echo "check-fleet-is-current: cannot place the fleet's build in history. It was built from a"
    echo "  tree this checkout does not have — an unpushed branch, or a different repository."
    exit 1
fi

if ! git merge-base --is-ancestor "$FLEET_SHA" "$MAIN" 2>/dev/null; then
    echo
    echo "  *** $FLEET_SHA is NOT an ancestor of origin/main."
    echo
    echo "check-fleet-is-current: the fleet is running a commit that was never merged. That is a"
    echo "  larger problem than being behind: main is supposed to be what is deployed or about to be."
    exit 1
fi

# ---------------------------------------------------------------- 3. what is undeployed
# NO name filter, deliberately. Five units sat undeployed for days behind a filtered sweep.
BEHIND="$(git log --oneline "${FLEET_SHA}..${MAIN}" 2>/dev/null)"
BEHIND_N="$(printf '%s' "$BEHIND" | /usr/bin/grep -c . || true)"

# ---------------------------------------------------------------- 4. unit directives
units_bad=0
units_checked=0
units_skipped=0
if [ "$BINARY_ONLY" = false ]; then
    # Derived from the installer rather than listed here: a hand-maintained list of directives is a
    # list of the ones someone remembered, which is how LimitNOFILE went missing in the first place.
    for pair in "ghostd.service:Ghost Bitcoin Core" \
                "ghost-pool.service:Ghost Pool node" \
                "sri-pool.service:SRI Pool" \
                "sri-translator.service:SRI Translator"; do
        unit="${pair%%:*}"
        desc="${pair#*:}"
        body="$(awk -v w="$desc" '
            index($0, "Description=") && index($0, w) { on = 1 }
            on { print }
            on && /WantedBy=multi-user.target/ { exit }
        ' scripts/install-node.sh)"
        if [ -z "$body" ]; then
            echo
            echo "check-fleet-is-current: INCONCLUSIVE — no unit matching '$desc' in the installer."
            echo "  It was renamed or removed; the unit half of this check now covers nothing."
            exit 2
        fi

        # Literal directives only. `$` means the installer interpolates it and the live value is a
        # legitimately different string.
        want="$(printf '%s\n' "$body" | /usr/bin/grep -E '^[A-Za-z][A-Za-z0-9]*=' | /usr/bin/grep -v '\$' || true)"
        skipped="$(printf '%s\n' "$body" | /usr/bin/grep -E '^[A-Za-z][A-Za-z0-9]*=' | /usr/bin/grep -c '\$' || true)"
        units_skipped=$((units_skipped + ${skipped:-0}))

        for node in "${NODES[@]}"; do
            live="$(ssh -o ConnectTimeout=15 -o BatchMode=yes "$node" \
                    "systemctl cat $unit 2>/dev/null" 2>/dev/null)"
            if [ -z "$live" ]; then
                echo "  ??? $node $unit — \`systemctl cat\` returned nothing"
                units_bad=$((units_bad + 1))
                continue
            fi
            while IFS= read -r directive; do
                [ -n "$directive" ] || continue
                units_checked=$((units_checked + 1))
                if ! printf '%s\n' "$live" | /usr/bin/grep -qxF "$directive"; then
                    echo "  *** $node $unit — merged directive NOT live: $directive"
                    units_bad=$((units_bad + 1))
                fi
            done <<< "$want"
        done
    done
fi

# ---------------------------------------------------------------- verdict
echo
if [ "${BEHIND_N:-0}" -gt 0 ]; then
    echo "  *** the fleet is ${BEHIND_N} commit(s) behind origin/main. All of them:"
    printf '%s\n' "$BEHIND" | sed 's/^/        /'
fi

if [ "${BEHIND_N:-0}" -gt 0 ] || [ "$units_bad" -gt 0 ]; then
    echo
    echo "check-fleet-is-current: ${BEHIND_N:-0} undeployed commit(s), $units_bad unit directive miss(es)."
    echo
    echo "  Main is supposed to be what is deployed or about to be. Release off main and roll one"
    echo "  node at a time, vm1 last, batching the unit changes into the SAME restart as the binary"
    echo "  — \`deploy-node.sh\` swaps binaries only, so a merged unit change never arrives on its own."
    exit 1
fi

if [ "$BINARY_ONLY" = true ]; then
    echo "check-fleet-is-current: all ${#NODES[@]} node(s) run ${FLEET_SHA}, which is origin/main's tip"
    echo "  (unit directives NOT checked — --binary-only was passed)"
else
    echo "check-fleet-is-current: all ${#NODES[@]} node(s) run ${FLEET_SHA}, which is origin/main's tip,"
    echo "  and every literal installer directive is live ($units_checked comparisons = 4 units x"
    echo "  ${#NODES[@]} node(s); $units_skipped interpolated directive(s) per node could not be"
    echo "  compared literally, because the installer substitutes a value into each)"
fi
exit 0
