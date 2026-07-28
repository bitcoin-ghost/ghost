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
import os, re, sys

INSTALLER = "scripts/install-node.sh"
REFERENCE = "config/sri/translator-config.toml"
POOL_REFERENCE = "config/sri/pool-config.toml"

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
    # Extension negotiation. These diverged silently: the installer set
    # required_extensions = [0x0002] on the translator while the reference config said [], so
    # which attribution path a node took depended on which file provisioned it. Nothing
    # reported that, because these keys were not compared (#480).
    "supported_extensions",
    "required_extensions",
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

# The farm tier (#410) repeats `min_individual_miner_hashrate` with a deliberately different
# value, so a naive first-match comparison pairs the hobby floor in one file against the farm
# floor in the other and reports a disagreement that is not one. Keys are therefore collected
# per section, and the two tiers are compared separately.
#
# A TOML section header, but not bash `[[ -n "$x" ]]` — the installer is a shell script and is
# full of those. Anchored and closed to the end of the line, which `[[ -n ... ]]` never is.
SECTION_RE = re.compile(r"^\s*\[\[?[a-z0-9_.]+\]\]?\s*$")

# `install-node.sh` builds the farm block as a shell assignment, so its header is not on a
# line of its own.
FARM_OPENS_RE = re.compile(r"\[farm_tier\]")

FARM_SHARED = [
    "port",
    "min_individual_miner_hashrate",
    "hobby_max_individual_miner_hashrate",
]

def values(path):
    """Return (hobby_keys, farm_keys). Farm-tier keys are kept out of the hobby set."""
    out, farm = {}, {}
    in_farm = False
    with open(path) as fh:
        for line in fh:
            if FARM_OPENS_RE.search(line):
                in_farm = True
                continue
            # The block ends at the next TOML section in the reference file, and at the end of
            # the shell assignment (`fi`, or a blank line) in the installer.
            if in_farm and (SECTION_RE.match(line) or re.match(r"^\s*(fi)?\s*$", line)):
                in_farm = False
            m = re.match(r"^\s*([a-z0-9_]+)\s*=\s*(.+?)\s*$", line)
            if not m:
                continue
            key, val = m.group(1), m.group(2)
            # Strip a trailing TOML comment so `100.0  # ~232,827` compares as `100.0`, and the
            # closing quote of the installer's shell assignment so the last key of the block
            # is not `50_000_000_000_000.0"`.
            val = re.sub(r"\s+#.*$", "", val).rstrip('"')
            if in_farm:
                if key in FARM_SHARED:
                    farm.setdefault(key, val)
            elif key in SHARED:
                out.setdefault(key, val)
    return out, farm

(a, a_farm), (b, b_farm) = values(INSTALLER), values(REFERENCE)

problems = []

# The farm tier is emitted only for public_pool, but both files must describe the SAME tier.
# A mismatch here means a node listens on one port while the firewall opens another, or
# starts farm miners at a floor the reference says is something else.
for k in FARM_SHARED:
    va, vb = a_farm.get(k), b_farm.get(k)
    if va is None or vb is None:
        missing = INSTALLER if va is None else REFERENCE
        problems.append(f"[farm_tier] {k}: not found in {missing} — cannot verify agreement")
        continue
    if va != vb:
        problems.append(f"[farm_tier] {k}: {INSTALLER} = {va!r} but {REFERENCE} = {vb!r}")

# The farm floor must sit above the hobby floor, or the tiers are inverted and a large miner
# routed to 4444 gets an EASIER target than one left on 3333.
try:
    hobby = float(b.get("min_individual_miner_hashrate", "nan").replace("_", ""))
    farm = float(b_farm.get("min_individual_miner_hashrate", "nan").replace("_", ""))
    if farm <= hobby:
        problems.append(
            f"[farm_tier] min_individual_miner_hashrate ({farm:g}) must exceed the hobby "
            f"floor ({hobby:g}) — otherwise the tiers are inverted"
        )
except ValueError:
    pass

# The pool must SUPPORT every extension the translator REQUIRES.
#
# This spans two files, so no amount of per-file agreement catches it. Both directions break
# something, and neither breaks loudly:
#   - translator requires what the pool does not support -> the SV2 handshake fails and the
#     translator falls through to the next upstream.
#   - pool supports what the translator does not require -> the TLV is never negotiated, so
#     per-worker attribution silently stops and shares fall back to the channel identity.
def parse_ext_list(v):
    """`[0x0002, 0x0003]` -> {2, 3}. Returns None if it cannot be parsed."""
    if v is None:
        return None
    inner = v.strip().strip("[]").strip()
    if not inner:
        return set()
    out = set()
    for item in inner.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            out.add(int(item, 16) if item.lower().startswith("0x") else int(item))
        except ValueError:
            return None
    return out

pool_vals, _ = values(POOL_REFERENCE)
tran_required = parse_ext_list(b.get("required_extensions"))
pool_supported = parse_ext_list(pool_vals.get("supported_extensions"))

if tran_required is None or pool_supported is None:
    problems.append(
        "could not parse supported_extensions/required_extensions as a list — "
        "the pool-supports-what-the-translator-requires invariant was NOT checked"
    )
else:
    missing = tran_required - pool_supported
    if missing:
        problems.append(
            f"{REFERENCE} requires extension(s) {sorted(hex(x) for x in missing)} that "
            f"{POOL_REFERENCE} does not list under supported_extensions — the SV2 handshake "
            f"will fail and the translator will fall through to another upstream"
        )

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

# ---------------------------------------------------------------------------
# Cross-file: the farm port ghost-pool GOSSIPS must equal the one the translator LISTENS on.
#
# translator_sv2 owns the listener (`[farm_tier] port`); ghost-pool owns the advertisement
# (`[network] farm_port` in pool.toml), because they are different processes and ghost-pool
# must not read another service's config file. So the value is duplicated, and duplication
# drifts.
#
# Drift here is not cosmetic: a node advertising a farm port it does not listen on turns a
# routing decision into a dropped connection, and the sender reads that as an unreachable peer
# rather than a misconfiguration (#495).
farm_listen = None
in_farm = False
for line in open(REFERENCE, encoding="utf-8"):
    t = line.strip()
    if t.startswith("["):
        in_farm = t == "[farm_tier]"
        continue
    if in_farm and t.startswith("port"):
        m = re.match(r"port\s*=\s*(\d+)", t)
        if m:
            farm_listen = int(m.group(1))
        break

farm_advertise = None
for line in open("config/sri/pool.toml", encoding="utf-8") if os.path.exists("config/sri/pool.toml") else []:
    m = re.match(r"\s*farm_port\s*=\s*(\d+)", line)
    if m:
        farm_advertise = int(m.group(1))
        break

# The installer writes both files, so it is the copy that actually reaches a node.
installer_src = open(INSTALLER, encoding="utf-8").read()
inst_farm_listen = None
m = re.search(r"\[farm_tier\]\s*\nport\s*=\s*(\d+)", installer_src)
if m:
    inst_farm_listen = int(m.group(1))
inst_farm_advertise = None
m = re.search(r"^\s*farm_port\s*=\s*(\d+)", installer_src, re.M)
if m:
    inst_farm_advertise = int(m.group(1))

if inst_farm_listen is not None and inst_farm_advertise is None:
    problems.append(
        f"{INSTALLER} configures a farm listener on {inst_farm_listen} but never sets "
        "[network] farm_port in pool.toml — the node listens and never tells anyone, "
        "so farm routing stays inert (#495)"
    )
elif (
    inst_farm_listen is not None
    and inst_farm_advertise is not None
    and inst_farm_listen != inst_farm_advertise
):
    problems.append(
        f"{INSTALLER} listens for farm traffic on {inst_farm_listen} but advertises "
        f"{inst_farm_advertise} — peers would route farm connections to a closed port"
    )

if (
    farm_listen is not None
    and farm_advertise is not None
    and farm_listen != farm_advertise
):
    problems.append(
        f"{REFERENCE} listens for farm traffic on {farm_listen} but config/sri/pool.toml "
        f"advertises {farm_advertise}"
    )

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
