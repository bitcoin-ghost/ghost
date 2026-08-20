#!/usr/bin/env bash
#
# Share Shard — independent verification of a node's own folded balances.
#
# `SHARE_SHARD_BUILD.md` Stage 4 gate: **balances pinned by value against an independent SQL fold
# on at least one node.** The plan calls it not optional, and gives the reason:
#
#   "Eight nodes agreeing does not mean eight nodes are right — a uniform fold bug agrees with
#    itself. This is the mutation-test lesson from SBC."
#
# Comparing table roots across the fleet cannot catch that. Every node runs the same `fold_shares`,
# so a wrong scale, a double count or a dropped eligibility filter produces the same wrong number
# everywhere and eight nodes agree perfectly on it.
#
# ⚠ **This script therefore re-derives the balances WITHOUT the Rust fold.** It reads the raw
# `shares` rows in SQL and does the arithmetic here, in Python, from the definitions:
#
#     micro_work(d)    = floor(d * 1_000_000 + 0.5)     — half-AWAY-from-zero, as Rust rounds
#     credited value   = the proof's `difficulty`, which is what `fold_shares` credits — NOT
#                        `work`. They are equal today only because both ShareProof construction
#                        sites assign `difficulty: share.work`; if that ever diverges, reading
#                        `work` would silently check a different quantity than the code under test.
#     eligible         = received_by == this node
#                        AND valid = 1
#                        AND proof present
#                        AND tier_log2 >= NETWORK_TIER_LOG2   (absent tier = pre-gate, excluded)
#                        AND creditable_difficulty: finite, > 0, <= 1e12
#     epoch(share)     = rounds.block_height / EPOCH_BLOCKS, and only epochs actually FOLDED
#
# If this file ever imports or shells out to the pool's own fold, it stops being a check and
# becomes a second copy of the thing under test.
#
# ## Why it compares SORTED VALUES rather than address-to-address
#
# `shard_counters.address_enc` is encrypted with a per-call nonce (the `address_key` rule), so the
# ciphertext cannot be matched back to a plaintext address from outside the node. Comparing the
# sorted multiset of per-address values is nearly as strong: it catches a wrong total, a wrong
# split, a missing address and a duplicated one. It would not catch two addresses having their
# balances swapped — stated plainly rather than left as an implied guarantee.
#
# Usage:
#   scripts/shard-verify-fold.sh <node>            # e.g. ghost-vm5
#
# Exit codes: 0 balances agree exactly, 1 usage/precondition (including "the evidence has been
# reaped, so this cannot be checked here" — see the v56 note below), 2 MISMATCH, 3 node unreadable.

set -uo pipefail

NODE="${1:-}"
[[ -n "$NODE" ]] || { echo "usage: shard-verify-fold.sh <node>" >&2; exit 1; }

DB="/home/ghost/.ghost/ghost.db"
EPOCH_BLOCKS=6
NETWORK_TIER_LOG2=10
# Must match ghost_common::share_shard::RETENTION_EPOCHS. Folding epoch M deletes the evidence of
# epoch M - RETENTION_EPOCHS, so raw rows exist only for [M - RETENTION_EPOCHS + 1, M].
RETENTION_EPOCHS=6

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

echo "== independent fold verification on ${NODE} =="

# The node's own column id, and the epochs it has folded.
#
# ⚠ Do NOT read the id from `shard_epochs` — since peers' summaries are retained there (they are
# the evidence the chain check needs), that table holds several node ids and a `group_concat`
# silently returns all of them. That produced an empty persisted set and a false MISMATCH the first
# time this ran, which is the failure mode this script exists to avoid: a verifier whose own bug
# reports the thing under test as broken.
#
# `shares.received_by` is the reliable source: locally received shares carry `hex(own_id[..8])`,
# 16 hex chars, while gossiped rows carry a shorter prefix. Exactly one 16-char value must exist,
# and the script refuses rather than guessing if that is not true.
own_line=$(timeout 90 ssh -o BatchMode=yes -o ConnectTimeout=10 "$NODE" \
  "sudo -u ghost sqlite3 -noheader -separator '|' \"file:${DB}?mode=ro\" \
     \"select received_by, count(*) from shares where length(received_by) = 16
        group by received_by order by count(*) desc limit 2;\"" 2>"$WORK/err")
rc=$?
# Gate on the EXIT STATUS, not on stderr being non-empty. ssh writes benign chatter there
# ("Warning: Permanently added ... to the list of known hosts", sudo lectures, MOTD), and treating
# any byte as failure aborts runs whose data was fine. stderr is reported as context only.
if [[ $rc -ne 0 ]]; then
  echo "  UNREADABLE (exit $rc) $(head -c 200 "$WORK/err")" >&2
  exit 3
fi
if [[ $(echo "$own_line" | grep -c .) -ne 1 ]]; then
  echo "  REFUSE: expected exactly one 16-char received_by, found:" >&2
  echo "$own_line" | sed 's/^/    /' >&2
  exit 1
fi
received_by="${own_line%%|*}"
own_hex=$(echo "$received_by" | tr 'a-f' 'A-F')

epochs=$(timeout 90 ssh -o BatchMode=yes "$NODE" \
  "sudo -u ghost sqlite3 -noheader \"file:${DB}?mode=ro\" \
     \"select group_concat(epoch) from shard_epochs where substr(hex(node_id),1,16) = '${own_hex}';\"" 2>"$WORK/err2")
# ⚠ A FAILED query and a node with nothing folded both yield an empty string. Conflating them
# makes an unreachable node report as a clean pass, so the exit status is checked first.
if [[ $? -ne 0 ]]; then
  echo "  UNREADABLE while listing folded epochs: $(head -c 200 "$WORK/err2")" >&2
  exit 3
fi
[[ -n "$epochs" ]] || { echo "  no folded epochs yet — nothing to verify"; exit 0; }

echo "  own column: ${received_by}  folded epochs: $(echo "$epochs" | tr ',' ' ' | wc -w)"

# Schema v56 is the step-7 cutover, and it is the version at which this check stops being able to
# see the whole story: from there the shard OWNS `shares` and reaps each epoch's evidence
# RETENTION_EPOCHS later. The counters stay CUMULATIVE, so re-deriving them from rows that have
# been deleted under-counts and looks exactly like a fold bug. Read the version now and use it
# below to tell "the fold is wrong" apart from "the evidence is gone by design" — reporting the
# second as the first is the wolf-crying this script's own header warns about.
schema_v=$(timeout 60 ssh -o BatchMode=yes "$NODE" \
  "sudo -u ghost sqlite3 -noheader \"file:${DB}?mode=ro\" 'PRAGMA user_version;'" 2>/dev/null) || schema_v=0
schema_v="${schema_v:-0}"

# Height range covered by the folded epochs.
lo=$(echo "$epochs" | tr ',' '\n' | sort -n | head -1)
hi=$(echo "$epochs" | tr ',' '\n' | sort -n | tail -1)
h_lo=$(( lo * EPOCH_BLOCKS ))
h_hi=$(( hi * EPOCH_BLOCKS + EPOCH_BLOCKS - 1 ))
echo "  height range: ${h_lo}..${h_hi}"

# --- the independent side: raw shares, arithmetic done here -----------------------------------
timeout 300 ssh -o BatchMode=yes "$NODE" \
  "sudo -u ghost sqlite3 -noheader -separator '|' \"file:${DB}?mode=ro\" \
     \"select json_extract(s.proof,'\\\$.payout_address'),
              json_extract(s.proof,'\\\$.difficulty'),
              json_extract(s.proof,'\\\$.tier_log2'),
              r.block_height
         from shares s join rounds r on r.round_id = s.round_id
        where r.block_height between ${h_lo} and ${h_hi}
          and s.received_by = '${received_by}'
          and s.valid = 1
          and s.proof is not null and length(s.proof) > 0;\"" \
  > "$WORK/raw" 2>"$WORK/err3" || { echo "  UNREADABLE while reading shares: $(head -c 200 "$WORK/err3")" >&2; exit 3; }

# --- what the shard actually persisted ---------------------------------------------------------
timeout 90 ssh -o BatchMode=yes "$NODE" \
  "sudo -u ghost sqlite3 -noheader \"file:${DB}?mode=ro\" \
     \"select total_micro from shard_counters where substr(hex(node_id),1,16) = '${own_hex}' order by total_micro;\"" \
  > "$WORK/persisted" 2>"$WORK/err4" || { echo "  UNREADABLE while reading counters: $(head -c 200 "$WORK/err4")" >&2; exit 3; }

# ⚠ Both files empty compares [] == [] and prints EXACT MATCH. A gate that passes when it read
# NOTHING is the "checks that cannot fail" shape this script exists to catch, so refuse outright.
if [[ ! -s "$WORK/raw" ]]; then
  echo "  REFUSE: read zero share rows over ${h_lo}..${h_hi} — the query returned nothing, which" >&2
  echo "          is not the same as the fold being right." >&2
  exit 3
fi

FOLDED_EPOCHS="$epochs" EPOCH_BLOCKS="$EPOCH_BLOCKS" TIER="$NETWORK_TIER_LOG2" \
SCHEMA_V="$schema_v" RETENTION_EPOCHS="$RETENTION_EPOCHS" \
python3 - "$WORK/raw" "$WORK/persisted" <<'PY'
import math, os, sys
from collections import defaultdict

# `creditable_difficulty` (work_fold.rs): the fold REFUSES a difficulty that is not finite, not
# positive, or above the cap that would saturate the accumulator. Omitting this screen makes the
# script count a share the pool deliberately excluded and report a MISMATCH with no bug in the fold.
MAX_CREDIT_DIFFICULTY = 1e12

raw_path, persisted_path = sys.argv[1], sys.argv[2]
epoch_blocks = int(os.environ["EPOCH_BLOCKS"])
tier_floor = int(os.environ["TIER"])
folded = {int(e) for e in os.environ["FOLDED_EPOCHS"].split(",") if e}

by_addr = defaultdict(int)
counted = skipped_tier = skipped_epoch = malformed = skipped_uncreditable = 0

for line in open(raw_path):
    line = line.rstrip("\n")
    if not line:
        continue
    parts = line.split("|")
    if len(parts) != 4:
        malformed += 1
        continue
    addr, difficulty, tier, height = parts
    if not addr or not difficulty:
        malformed += 1
        continue
    # Absent tier = pre-tier-gate share. It committed to no tier, so it cannot be network tier.
    if tier == "" or tier is None:
        skipped_tier += 1
        continue
    if int(tier) < tier_floor:
        skipped_tier += 1
        continue
    # Only epochs this node actually FOLDED. A height inside the range whose epoch was never
    # folded must not be counted, or the check invents work the shard never claimed.
    if (int(height) // epoch_blocks) not in folded:
        skipped_epoch += 1
        continue
    d = float(difficulty)
    if not math.isfinite(d) or d <= 0.0 or d > MAX_CREDIT_DIFFICULTY:
        skipped_uncreditable += 1
        continue
    # micro_work, re-derived: NOT the pool's function.
    #
    # ⚠ Python's round() is round-half-to-EVEN; `micro_work` uses Rust's `f64::round`, which is
    # round-half-AWAY-from-zero. A value landing exactly on .5 would differ by one micro-unit and
    # the script would report a MISMATCH the fold never committed.
    by_addr[addr] += math.floor(d * 1_000_000 + 0.5)
    counted += 1

independent = sorted(v for v in by_addr.values() if v > 0)
persisted = sorted(int(l) for l in open(persisted_path) if l.strip())

print(f"  shares counted: {counted}  (below-tier {skipped_tier}, unfolded-epoch {skipped_epoch}, "
      f"uncreditable {skipped_uncreditable}, malformed {malformed})")
if counted == 0:
    print("\n  REFUSE: zero shares were eligible — an empty comparison is not a match")
    sys.exit(3)
print(f"  independent : {len(independent)} addresses, total {sum(independent):,}")
print(f"  persisted   : {len(persisted)} addresses, total {sum(persisted):,}")

if independent == persisted:
    print("\n  ✅ EXACT MATCH — the shard's own arithmetic is independently confirmed")
    sys.exit(0)

# Before calling a mismatch a fold bug, rule out the one cause that is not one: since v56 the
# shard deletes each epoch's evidence RETENTION_EPOCHS after folding it, while `shard_counters`
# stays cumulative. If the folded range reaches further back than the retained window, the raw
# side is re-deriving from rows that no longer exist and MUST come out short. Say so, and exit 1
# (precondition) rather than 2 (mismatch) — a verifier that reports a designed deletion as a money
# bug is worse than one that admits it cannot see.
schema_v = int(os.environ.get("SCHEMA_V") or 0)
retention = int(os.environ.get("RETENTION_EPOCHS") or 0)
if schema_v >= 56 and folded and min(folded) < max(folded) - retention + 1:
    print("\n  ⚠ UNVERIFIABLE — not a mismatch")
    print(f"     independent: {sum(independent):,}   persisted: {sum(persisted):,}")
    print(f"     schema v{schema_v} means retention is armed (owns_evidence = true). Evidence for")
    print(f"     epochs at or below {max(folded) - retention} has been deleted by design, but")
    print("     `shard_counters` is cumulative, so this re-derivation cannot reach the whole column.")
    print("     Run this against a PRE-CUTOVER database backup (Stage 0 took one per node) — that")
    print("     is where the Stage 4 gate was satisfied and where the full range is still readable.")
    sys.exit(1)

print("\n  ❌ MISMATCH")
print(f"     independent: {independent}")
print(f"     persisted  : {persisted}")
delta = sum(persisted) - sum(independent)
print(f"     persisted - independent = {delta:,}")
if independent and persisted and sum(independent):
    print(f"     ratio persisted/independent = {sum(persisted)/sum(independent):.6f}")
    print("     (a clean ratio points at a SCALE bug; a small delta at eligibility drift)")
sys.exit(2)
PY
rc=$?
exit $rc
