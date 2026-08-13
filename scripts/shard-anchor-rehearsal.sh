#!/usr/bin/env bash
#
# Share Shard — genesis anchor rehearsal (SHARE_SHARD_BUILD.md Stage 0, used three times).
#
# Reads, read-only, the finalised payout-ledger checkpoint at a given height from every node and
# answers ONE question: do all 8 hold the byte-identical adopted bytes at that height?
#
# That question is the whole ceremony. Stage 5 seeds the shard by CONVERTING this checkpoint, so if
# the eight nodes are not byte-identical here they open with eight different balance sets, each
# internally consistent and therefore undetectable afterwards. Every guard below exists because the
# failure it prevents is silent:
#
#   * EXACT height, never at-or-before. `get_payout_ledger_checkpoint_at_or_before` is the runtime's
#     lookup and is right for the runtime; here it would let a node missing height H answer with
#     H-40 and be scored as agreeing about H. A node that lacks the height must read MISSING.
#   * The blob is hashed as RAW BYTES and its LENGTH is reported. `canonical_payout` is NULL on
#     pre-adopt-on-finalise rows; sha256 of nothing is identical on all eight, which presents as
#     perfect unanimity for a checkpoint carrying no payees at all. Converting that zeroes every
#     miner's accrued balance.
#   * A zero payee count is a hard failure, not a warning, for the same reason.
#   * Lag is checked against each node's own tip at read time, not assumed from the height.
#   * `ledger_root` unanimity is reported but is NOT the gate, because it does not commit to the
#     bytes genesis converts. Since the #606 median gate (h961700) `payout_checkpoint.rs` persists
#     `ledger_root: msg.ledger_root` — the PROPOSER's root over the PROPOSER's list — beside
#     `miner_payouts: medians`, the per-address median of whichever reports THAT node received.
#     Measured 2026-08-13 over the 182 heights all 8 nodes hold since 961,600: roots agree at 180,
#     canonical_payout at 41, and after the gate at only 3. A ceremony gated on the root alone
#     would read as unanimous and seed eight nodes from divergent bytes.
#
# Usage:
#   scripts/shard-anchor-rehearsal.sh --survey [N]     newest N heights whose adopted bytes are
#                                                      byte-identical on every node
#   scripts/shard-anchor-rehearsal.sh --height H       full verdict for one height
#   scripts/shard-anchor-rehearsal.sh --height H --emit-json FILE
#
# Options:
#   --min-lag N   blocks the anchor must sit behind tip (default 30, per Stage 5 step 1)
#   --nodes "..." space-separated ssh aliases (default: the 8-node fleet)
#
# Exit codes: 0 unanimous, 1 usage/precondition, 2 not unanimous, 3 a node could not be read.

set -uo pipefail

NODES_DEFAULT="ghost-vm1 ghost-vm2 ghost-vm3 ghost-vm4 ghost-vm5 ghost-vm6 ghost-vm7 ghost-vm8"
DB="/home/ghost/.ghost/ghost.db"
MIN_LAG=30
MODE=""
HEIGHT=""
SURVEY_N=10
EMIT_JSON=""
NODES="$NODES_DEFAULT"
SSH_TIMEOUT=60

while [[ $# -gt 0 ]]; do
  case "$1" in
    --survey)  MODE="survey"; [[ "${2:-}" =~ ^[0-9]+$ ]] && { SURVEY_N="$2"; shift; }; shift ;;
    --height)  MODE="height"; HEIGHT="${2:?--height needs a block height}"; shift 2 ;;
    --min-lag) MIN_LAG="${2:?--min-lag needs a number}"; shift 2 ;;
    --nodes)   NODES="${2:?--nodes needs a list}"; shift 2 ;;
    --emit-json) EMIT_JSON="${2:?--emit-json needs a path}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

[[ -n "$MODE" ]] || { echo "need --survey or --height; see the header" >&2; exit 1; }

# Numeric arguments are validated rather than interpolated on trust. Both reach a remote shell and
# then SQL, and the realistic bad input is not an attack: every height in SHARE_SHARD_BUILD.md is
# written with thousands separators, so a pasted `962,008` would become a remote sqlite syntax
# error, get swallowed by the stderr redirect, score all 8 nodes MISSING, and print "step back to
# an older finalised height" — the exact misdiagnosis this script exists to prevent.
for pair in "HEIGHT:$HEIGHT" "MIN_LAG:$MIN_LAG" "SURVEY_N:$SURVEY_N"; do
  name="${pair%%:*}" value="${pair#*:}"
  [[ -z "$value" ]] && continue
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be digits only, got '$value' (thousands separators are not accepted)" >&2
    exit 1
  fi
done
[[ "$MODE" == "height" && -z "$HEIGHT" ]] && { echo "--height needs a block height" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------------------------
# Collection. One ssh round trip per node, read-only, no writes and no locks taken on the live DB.
# ---------------------------------------------------------------------------------------------

# Emits the row on stdout; stderr and the exit status are kept so that "I could not read this
# node" stays distinguishable from "this node does not hold the height". Conflating them is worse
# than it sounds: one node down would print MISSING, the operator would be told to step back to an
# older height, and they would walk the whole checkpoint history without ever seeing the cause.
collect_height() {
  local node="$1" h="$2" err_file="$3"
  timeout "$SSH_TIMEOUT" ssh -o BatchMode=yes -o ConnectTimeout=10 "$node" \
    "sudo -u ghost sqlite3 -noheader -separator '|' \"file:${DB}?mode=ro\" \
       \"select c.height, c.cutoff_ts, hex(c.ledger_root), coalesce(length(c.canonical_payout),0),
                coalesce(hex(c.canonical_payout),''), c.proposer_id, c.active_node_count,
                coalesce((select max(block_height) from rounds), -1)
          from payout_ledger_checkpoints c where c.height = ${h};\"" 2>"$err_file"
}

# Heights present on a node, newest first, already lag-filtered against that node's own tip.
collect_candidates() {
  local node="$1"
  timeout "$SSH_TIMEOUT" ssh -o BatchMode=yes -o ConnectTimeout=10 "$node" \
    "sudo -u ghost sqlite3 -noheader \"file:${DB}?mode=ro\" \
       \"select height from payout_ledger_checkpoints
          where canonical_payout is not null
            and height <= (select max(block_height) from rounds) - ${MIN_LAG}
          order by height desc limit 400;\"" 2>/dev/null
}

# ---------------------------------------------------------------------------------------------

if [[ "$MODE" == "survey" ]]; then
  echo "== surveying candidate anchors (min lag ${MIN_LAG} blocks, checkpoint carries payees) =="
  n_nodes=0
  for node in $NODES; do
    collect_candidates "$node" > "$WORK/cand.$node"
    cnt=$(wc -l < "$WORK/cand.$node")
    printf "  %-12s %s heights\n" "$node" "$cnt"
    if [[ "$cnt" -eq 0 ]]; then
      echo "  !! $node returned nothing — cannot survey without it" >&2
      exit 3
    fi
    n_nodes=$((n_nodes + 1))
  done

  # Heights held by EVERY node. sort|uniq -c counting to n_nodes is the intersection.
  #
  # Being held by all 8 is necessary and NOT sufficient — it says nothing about whether the adopted
  # bytes agree, and since #606 they usually do not (measured: 41 of 182 heights, and only 3 after
  # the gate). Reporting this list alone would send an operator to a height `--height` then refuses,
  # almost every time. So the digests are compared here too, over a widened candidate window.
  local_window=$((SURVEY_N * 8))
  common=$(cat "$WORK"/cand.* | sort -n | uniq -c \
    | awk -v n="$n_nodes" '$1 == n {print $2}' | sort -rn | head -"$local_window")
  if [[ -z "$common" ]]; then
    echo "no height is held by all ${n_nodes} nodes at lag >= ${MIN_LAG}" >&2
    exit 2
  fi

  in_list=$(echo "$common" | paste -sd, -)
  echo
  echo "== comparing adopted bytes across $(echo "$common" | wc -l) candidate heights =="
  for node in $NODES; do
    timeout "$SSH_TIMEOUT" ssh -o BatchMode=yes -o ConnectTimeout=10 "$node" \
      "sudo -u ghost sqlite3 -noheader -separator '|' \"file:${DB}?mode=ro\" \
         \"select height, coalesce(hex(canonical_payout),'') from payout_ledger_checkpoints
            where height in (${in_list});\"" 2>/dev/null \
      | sed "s|^|${node}\||" >> "$WORK/blobs"
  done

  REHEARSAL_NODES="$n_nodes" REHEARSAL_TOP="$SURVEY_N" python3 - "$WORK/blobs" <<'PY'
import binascii, hashlib, os, sys, collections

need = int(os.environ["REHEARSAL_NODES"])
top = int(os.environ["REHEARSAL_TOP"])
by_height = collections.defaultdict(dict)
for line in open(sys.argv[1]):
    line = line.rstrip("\n")
    if not line:
        continue
    node, height, blob_hex = line.split("|", 2)
    blob = binascii.unhexlify(blob_hex) if blob_hex else b""
    # An empty blob is recorded as such, never as a digest: sha256 of nothing is identical on every
    # node and would present as unanimity for a checkpoint carrying no payees at all.
    by_height[int(height)][node] = hashlib.sha256(blob).hexdigest() if blob else "EMPTY"

qualifying = []
for height in sorted(by_height, reverse=True):
    seen = by_height[height]
    if len(seen) != need:
        continue
    digests = set(seen.values())
    if len(digests) == 1 and "EMPTY" not in digests:
        qualifying.append(height)

if not qualifying:
    print("\nNo candidate height has byte-identical adopted bytes on all "
          f"{need} nodes. Widen the search (--survey with a larger N) or step further back.")
    sys.exit(2)

print(f"\n== heights with ONE distinct canonical_payout across all {need} nodes ==")
for height in qualifying[:top]:
    print(f"  {height}")
print(f"\n{len(qualifying)} of {len(by_height)} candidates qualified.")
print(f"Now run:  --height {qualifying[0]}   (the newest qualifying height)")
PY
  exit $?
fi

# ---------------------------------------------------------------------------------------------
# Full verdict for one height.
# ---------------------------------------------------------------------------------------------

echo "== anchor rehearsal at height ${HEIGHT} =="
: > "$WORK/rows"
missing=0
unreadable=0
for node in $NODES; do
  line=$(collect_height "$node" "$HEIGHT" "$WORK/err.$node")
  rc=$?
  if [[ "$rc" -ne 0 || -s "$WORK/err.$node" ]]; then
    # ssh/sudo/sqlite failed, or sqlite wrote a diagnostic. Either way we did not read this node,
    # and saying so is the whole point — an unread node is not an absent checkpoint.
    printf "  %-12s UNREADABLE (exit %s) %s\n" \
      "$node" "$rc" "$(head -c 200 "$WORK/err.$node" | tr '\n' ' ')"
    unreadable=$((unreadable + 1))
    continue
  fi
  if [[ -z "$line" ]]; then
    printf "  %-12s MISSING (read cleanly; no checkpoint row at exactly %s)\n" "$node" "$HEIGHT"
    missing=$((missing + 1))
    continue
  fi
  printf '%s|%s\n' "$node" "$line" >> "$WORK/rows"
done

if [[ "$unreadable" -gt 0 ]]; then
  echo
  echo "REFUSE: ${unreadable} node(s) could not be read. Fix access before judging the anchor —" >&2
  echo "an unread node is not evidence about the checkpoint either way." >&2
  exit 3
fi

if [[ "$missing" -gt 0 ]]; then
  echo
  echo "REFUSE: ${missing} node(s) do not hold height ${HEIGHT}. Step back to an older finalised height." >&2
  exit 2
fi

[[ -n "$EMIT_JSON" ]] && export REHEARSAL_JSON="$EMIT_JSON"
export REHEARSAL_MIN_LAG="$MIN_LAG"
export REHEARSAL_HEIGHT="$HEIGHT"

python3 - "$WORK/rows" <<'PY'
import binascii, hashlib, json, os, struct, sys

rows_path = sys.argv[1]
min_lag = int(os.environ["REHEARSAL_MIN_LAG"])
want_height = int(os.environ["REHEARSAL_HEIGHT"])

nodes = []
for raw in open(rows_path):
    raw = raw.rstrip("\n")
    if not raw:
        continue
    node, height, cutoff_ts, root_hex, blob_len, blob_hex, proposer, active, tip = raw.split("|", 8)
    blob = binascii.unhexlify(blob_hex) if blob_hex else b""
    # Parsed here rather than in SQL so that one implementation reads the bytes every node sent,
    # instead of eight sqlite builds each interpreting the blob their own way.
    payees, node_shares = (None, None)
    if blob:
        try:
            decoded = json.loads(blob.decode())
            payees, node_shares = decoded[0], decoded[1]
        except Exception as exc:  # noqa: BLE001 - reported, never swallowed
            print(f"  !! {node}: canonical_payout is not parseable JSON: {exc}")
    nodes.append({
        "node": node,
        "height": int(height),
        "cutoff_ts": int(cutoff_ts),
        "ledger_root": root_hex.upper(),
        "blob_len": int(blob_len),
        "blob_sha256": hashlib.sha256(blob).hexdigest() if blob else None,
        "payees": payees,
        "node_shares": node_shares,
        "proposer_id": proposer,
        "active_node_count": int(active),
        "tip": int(tip),
    })

for n in nodes:
    lag = n["tip"] - n["height"]
    print(f"  {n['node']:<12} root={n['ledger_root'][:16]}… "
          f"blob={n['blob_len']}B sha={(n['blob_sha256'] or 'NULL')[:16]}… "
          f"payees={len(n['payees']) if n['payees'] is not None else '?'} "
          f"nodes={len(n['node_shares']) if n['node_shares'] is not None else '?'} "
          f"cutoff_ts={n['cutoff_ts']} tip={n['tip']} lag={lag}")

fail = []

# --- the hard preconditions, before any agreement is scored ---------------------------------
# An empty blob hashes identically on every node, so unanimity here is not evidence of anything.
empty = [n["node"] for n in nodes if n["blob_len"] == 0]
if empty:
    fail.append(f"canonical_payout is NULL/empty on: {', '.join(empty)} — this checkpoint predates "
                "adopt-on-finalise and carries no payees. Converting it would zero every balance.")

nopayees = [n["node"] for n in nodes if not n["payees"]]
if nopayees:
    fail.append(f"zero miner payees on: {', '.join(nopayees)} — refuse, an anchor with no payees "
                "opens the shard with nothing owed to anyone.")

# The build plan requires qualification state to be pinned alongside balances, not just balances.
nonodes = [n["node"] for n in nodes if not n["node_shares"]]
if nonodes:
    fail.append(f"zero node_shares on: {', '.join(nonodes)} — the genesis snapshot must carry "
                "qualification state (SHARE_SHARD_BUILD.md, open decisions).")

shallow = [f"{n['node']}(lag {n['tip'] - n['height']})" for n in nodes if n["tip"] - n["height"] < min_lag]
if shallow:
    fail.append(f"anchor is under {min_lag} blocks behind tip on: {', '.join(shallow)}")

# --- agreement -------------------------------------------------------------------------------
def distinct(key):
    return sorted({str(n[key]) for n in nodes})

def compute_ledger_root(miners, node_shares, cutoff_ts, height):
    """`bins/ghost-pool/src/payout.rs::compute_ledger_root`, re-spelled.

    Pinned against the 961,642 golden vector in `batch_genesis.rs` (root
    0FE9BAC3…FEC0CAA9), so a drift in this encoding shows up as that vector failing rather than as
    a silently wrong verdict here.
    """
    m = sorted(miners, key=lambda x: (-x[1], x[0]))
    n = sorted(node_shares, key=lambda x: bytes(x[0]))
    h = hashlib.sha256()
    h.update(b"PayoutLedgerRoot/v1")
    h.update(struct.pack("<q", cutoff_ts))
    h.update(struct.pack("<Q", height))
    h.update(struct.pack("<I", len(m)))
    for addr, work in m:
        h.update(struct.pack("<I", len(addr)))
        h.update(addr.encode())
        h.update(int(work).to_bytes(16, "little"))
    h.update(struct.pack("<I", len(n)))
    for nid, shares in n:
        h.update(bytes(nid))
        h.update(struct.pack("<i", shares))
    return h.hexdigest().upper()


# Does the ratified root actually commit to the bytes we are about to convert? Reported, not
# gated: post-#606 the two are written from different objects, so demanding consistency would
# reject every usable anchor. An anchor where they DO agree is strictly stronger — the fleet
# ratified a root over exactly these bytes — and is worth preferring when one is available.
consistent = []
for n in nodes:
    if n["payees"] is None:
        continue
    recomputed = compute_ledger_root(n["payees"], n["node_shares"], n["cutoff_ts"], n["height"])
    consistent.append((n["node"], recomputed == n["ledger_root"]))
agree = [c for c, ok in consistent if ok]
print(f"  root commits to blob on {len(agree)}/{len(consistent)} nodes"
      + ("" if len(agree) == len(consistent)
         else "  <- expected post-#606; the root is the proposer's, the blob is the median"))

# Both are required (Stage 5 step 1). The root is listed first because it is the weaker of the
# two: unanimity here is necessary and NOT sufficient, and gating on it alone is the trap above.
for key, label in (("ledger_root", "ledger_root"),
                   ("blob_sha256", "canonical_payout sha256"),
                   ("blob_len", "canonical_payout length"),
                   ("cutoff_ts", "cutoff_ts")):
    vals = distinct(key)
    if len(vals) != 1:
        by = {}
        for n in nodes:
            by.setdefault(str(n[key]), []).append(n["node"])
        detail = "; ".join(f"{v[:16]}… on {','.join(ns)}" for v, ns in by.items())
        fail.append(f"{len(vals)} distinct {label}: {detail}")

print()
if fail:
    print("REFUSE — this height is not a usable anchor:")
    for f in fail:
        print(f"  * {f}")
    sys.exit(2)

first = nodes[0]
print(f"UNANIMOUS across {len(nodes)} nodes at height {want_height}")
print(f"  ledger_root      {first['ledger_root']}")
print(f"  canonical sha256 {first['blob_sha256']}")
print(f"  canonical bytes  {first['blob_len']}")
print(f"  cutoff_ts        {first['cutoff_ts']}")
print(f"  miner payees     {len(first['payees'])}")
print(f"  node_shares      {len(first['node_shares'])}")
print(f"  proposer_id      {first['proposer_id']}")
print(f"  active_node_count {first['active_node_count']}")

out = os.environ.get("REHEARSAL_JSON")
if out:
    with open(out, "w") as fh:
        json.dump({
            "height": want_height,
            "cutoff_ts": first["cutoff_ts"],
            "ledger_root": first["ledger_root"],
            "canonical_sha256": first["blob_sha256"],
            "canonical_len": first["blob_len"],
            "miner_payouts": first["payees"],
            "node_shares": first["node_shares"],
            "proposer_id": first["proposer_id"],
            "active_node_count": first["active_node_count"],
            "verified_nodes": [n["node"] for n in nodes],
        }, fh, indent=2)
    print(f"\nwrote {out}")
PY
rc=$?
exit $rc
