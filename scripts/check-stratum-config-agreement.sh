#!/usr/bin/env bash
#
# Catch divergence between the two places the stratum config is defined.
#
# install-node.sh is fetched standalone over curl and has no repo to read from, so it
# writes /etc/ghost/translator-config.toml from a heredoc. config/sri/translator-config.toml
# is a second copy of the same values. Nothing has ever checked they agree, and they did not:
#
#   min_individual_miner_hashrate   installer 500_000_000_000.0   repo 10_000_000_000_000.0
#   aggregate_channels              installer false               repo true
#   downstream_extranonce2_size     installer 4                   repo 4     <- both wrong
#
# The vardiff floor was corrected in the repo copy by #426 and not in the installer, so a
# fresh node would have been provisioned with the value that #426 existed to fix. The repo
# copy had aggregate_channels = true, which collapses per-miner channels and would have
# undone the attribution fix in #422 if anyone had applied it. And extranonce2_size was 4
# in both while every live node ran 8 — the value rented-hashrate marketplaces require,
# recorded nowhere.
#
# The duplication cannot be removed while the installer is delivered standalone. This makes
# the divergence loud instead of silent.
#
# Absolute invariants are checked too, because agreement is not correctness: both files
# agreeing on extranonce2_size = 4 is exactly the state that shipped.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

python3 - <<'PY'
import re, sys

INSTALLER = "scripts/install-node.sh"
REFERENCE = "config/sri/translator-config.toml"

# Keys that must be identical in both files.
SHARED = [
    "downstream_extranonce2_size",
    "min_individual_miner_hashrate",
    "aggregate_channels",
    "shares_per_minute",
    "enable_vardiff",
    "downstream_port",
    "max_supported_version",
    "min_supported_version",
]

# Invariants that must hold regardless of whether the two files agree.
def inv_extranonce(v):
    try:
        return (int(v) >= 7, "must be >= 7 or rented-hashrate marketplaces reject the pool")
    except ValueError:
        return (False, "not an integer")

def inv_aggregate(v):
    return (v == "false",
            "true collapses per-miner channels and breaks share attribution")

INVARIANTS = {
    "downstream_extranonce2_size": inv_extranonce,
    "aggregate_channels": inv_aggregate,
}

def values(path):
    out = {}
    with open(path) as fh:
        for line in fh:
            m = re.match(r"^\s*([a-z0-9_]+)\s*=\s*(.+?)\s*$", line)
            if m and m.group(1) in SHARED:
                out.setdefault(m.group(1), m.group(2))
    return out

a, b = values(INSTALLER), values(REFERENCE)

problems = []
for k in SHARED:
    va, vb = a.get(k), b.get(k)
    # A key we cannot find in both files is not "in agreement" — it is unchecked, and
    # silently counting it as passing is how a gate ends up reporting a clean run while
    # testing nothing. The original version of this script could not match a key
    # containing a digit, so `downstream_extranonce2_size` was skipped entirely and it
    # still printed "8 shared keys agree".
    if va is None or vb is None:
        missing = INSTALLER if va is None else REFERENCE
        problems.append(f"{k}: not found in {missing} — cannot verify agreement")
        continue
    if va != vb:
        problems.append(f"{k}: {INSTALLER} = {va!r} but {REFERENCE} = {vb!r}")

for k, check in INVARIANTS.items():
    for path, vals in ((INSTALLER, a), (REFERENCE, b)):
        v = vals.get(k)
        if v is None:
            continue
        ok, why = check(v)
        if not ok:
            problems.append(f"{k} = {v} in {path} — {why}")

if problems:
    print("Stratum config sources disagree, or an invariant is broken:\n", file=sys.stderr)
    for p in problems:
        print(f"  {p}", file=sys.stderr)
    print(f"\nBoth {INSTALLER} and {REFERENCE} define these values. A node is provisioned",
          file=sys.stderr)
    print("from the installer, so a change made only in the reference file never reaches a node.",
          file=sys.stderr)
    sys.exit(1)

checked = [k for k in SHARED if k in a and k in b]
print(f"check-stratum-config-agreement: {len(checked)}/{len(SHARED)} shared keys compared "
      f"and in agreement, invariants hold")
PY
