#!/usr/bin/env bash
#
# Fail if the public checkpoint blob omits anything `checkpoint_hash` commits to.
#
# ## Why this exists
#
# `GET /api/v1/pool/mesh-node-list-checkpoint` serves the blob a miner-side shim verifies. The shim
# has to REBUILD `MeshNodeListCheckpointMessage::checkpoint_hash` to check a single signature, so
# every value that hash commits to must be in the blob. Two of them — `advert_root` and
# `coordinator_roster_root` — are deliberately not stored (pure functions of the adopted adverts,
# recomputed on read), so `adverts` must be served too or a consumer can only take those two roots
# on trust, which is the opposite of the point.
#
# ⛔ The hash has been bumped TWICE, both times by ADDING a root — v2 added `advert_root` (#625),
# v3 added `coordinator_roster_root` — and each bump silently created a new must-be-served field.
# Nothing connected the two files.
#
# The v2 bump broke it. From `main.rs`:
#
#   "This served a blob without `adverts` or `advert_root` until now, which no shim could have
#    verified. Nothing noticed because the endpoint 404s below the gate, so the first exercise of
#    it would have been the day it was armed."
#
# Found by reading, not by a test.
#
# ## Why the test written for that regression cannot catch it
#
# `a_served_checkpoint_reconstructs_the_hash_its_proposer_signed` rebuilds the message FROM THE
# STORED RECORD, under the comment "Exactly what the HTTP handler recomputes when it serves this
# record" — an author's claim, not a derived fact. It never reads the handler's JSON. So it proves
# the RECORD holds enough to rebuild the hash; it does not prove the BLOB exposes it. Drop
# `advert_root` from the `json!` block again and that test still passes.
#
# ⚠ The producer is a closure inside `main()`, which is why no test reaches it, and the shim's own
# types are `pub(crate)` in a binary crate, so a cross-crate round-trip test is not available
# either. Hence a source-derived check rather than a test.
#
# ## What it checks
#
# 1. Every field hashed by `checkpoint_hash` is a key in the served blob. DERIVED from the hash
#    body, which is the side that churns.
# 2. `adverts`, `proposer_signature` and `approvals` are present — without the first the unstored
#    roots cannot be independently recomputed, and without the other two there is nothing to check.
# 3. The hash's domain tag equals the blob's `"version"` string. A shim keys off `version`, so a
#    bumped hash carrying a stale version string is its own failure.
#
# Exit 0 = the blob carries everything, 1 = something is missing, 2 = INCONCLUSIVE.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 2

MSG="crates/ghost-consensus/src/message.rs"
SRV="bins/ghost-pool/src/main.rs"

for f in "$MSG" "$SRV"; do
    [ -r "$f" ] || { echo "check-served-checkpoint-carries-the-hash: INCONCLUSIVE — cannot read $f"; exit 2; }
done

# ---- (a) the hash: its domain tag and the fields it commits to -------------------------------
#
# Anchored on the `MeshNodeListCheckpoint/vN` domain tag rather than on "the third fn
# checkpoint_hash in the file" — there are three unrelated ones, and counting them is exactly the
# kind of positional assumption that rots.
HASHBLK="$(awk '
    /fn checkpoint_hash/ { buf = ""; on = 1 }
    on { buf = buf $0 "\n" }
    on && /finalize\(\)/ { if (buf ~ /MeshNodeListCheckpoint\/v/) { printf "%s", buf; exit } on = 0 }
' "$MSG")"

if [ -z "$HASHBLK" ]; then
    echo "check-served-checkpoint-carries-the-hash: INCONCLUSIVE — no \`fn checkpoint_hash\` in"
    echo "  $MSG carries a \`MeshNodeListCheckpoint/v\` domain tag. It was renamed or retagged;"
    echo "  this examined nothing and must not report success."
    exit 2
fi

HASH_TAG="$(printf '%s' "$HASHBLK" | grep -oE 'MeshNodeListCheckpoint/v[0-9]+' | head -1)"
HASHED="$(printf '%s' "$HASHBLK" | grep -oE 'self\.[a-z_]+' | sed 's/self\.//' | sort -u)"

if [ -z "$HASHED" ] || [ "$(grep -c . <<<"$HASHED")" -lt 5 ]; then
    echo "check-served-checkpoint-carries-the-hash: INCONCLUSIVE — found only"
    echo "  $(grep -c . <<<"$HASHED" 2>/dev/null || echo 0) \`self.<field>\` commitment(s) in the hash body."
    echo "  It commits 8; a smaller number means the shape changed and this cannot be trusted."
    exit 2
fi

# ---- (b) the served blob: its top-level keys ------------------------------------------------
#
# Bounded to the `json!` block carrying the `"version": "MeshNodeListCheckpoint/v..."` line, so an
# unrelated json! elsewhere in this very large file cannot stand in for it. Nested keys (the
# signer_set_delta sub-object) are excluded by taking only lines indented to the block's own level.
BLOB="$(awk '
    /serde_json::json!\(\{/ { buf = ""; on = 1 }
    on { buf = buf $0 "\n" }
    on && /^        \}\)\)/ { if (buf ~ /"version": "MeshNodeListCheckpoint\/v/) { printf "%s", buf; exit } on = 0 }
' "$SRV")"

if [ -z "$BLOB" ]; then
    echo "check-served-checkpoint-carries-the-hash: INCONCLUSIVE — could not locate the served"
    echo "  checkpoint \`json!\` block (the one carrying \`\"version\": \"MeshNodeListCheckpoint/v..\"\`)"
    echo "  in $SRV. It moved or was reshaped."
    exit 2
fi

BLOB_TAG="$(printf '%s' "$BLOB" | grep -oE '"version": "MeshNodeListCheckpoint/v[0-9]+"' \
            | grep -oE 'MeshNodeListCheckpoint/v[0-9]+' | head -1)"
# Top-level keys only: 12 spaces of indent inside the json! block.
KEYS="$(printf '%s' "$BLOB" | grep -oE '^            "[a-z_]+":' | tr -d ' ":' | sort -u)"

if [ -z "$KEYS" ] || [ "$(grep -c . <<<"$KEYS")" -lt 8 ]; then
    echo "check-served-checkpoint-carries-the-hash: INCONCLUSIVE — found only"
    echo "  $(grep -c . <<<"$KEYS" 2>/dev/null || echo 0) top-level key(s) in the served blob."
    echo "  The indentation or shape changed, so the comparison would be meaningless."
    exit 2
fi

bad=0

echo "check-served-checkpoint-carries-the-hash: hash commits $(grep -c . <<<"$HASHED") field(s); blob serves $(grep -c . <<<"$KEYS") key(s)"

# (1) Everything the hash commits to must be served.
for f in $HASHED; do
    if grep -qxF "$f" <<<"$KEYS"; then
        echo "  ✓  $f — committed by the hash, served in the blob"
    else
        echo "  *** $f — COMMITTED BY checkpoint_hash BUT NOT IN THE SERVED BLOB"
        bad=$((bad + 1))
    fi
done

# (2) Not hashed, but the blob is useless without them.
#     adverts: the only way to recompute advert_root / coordinator_roster_root, which are
#     committed and deliberately not stored. Without it those two roots are taken on trust.
#     proposer_signature / approvals: there is otherwise nothing to verify.
for f in adverts proposer_signature approvals; do
    if grep -qxF "$f" <<<"$KEYS"; then
        echo "  ✓  $f — present"
    else
        echo "  *** $f — MISSING; without it the blob cannot be independently verified"
        bad=$((bad + 1))
    fi
done

# (3) The tags must agree — a shim dispatches on `version`.
if [ -z "$HASH_TAG" ] || [ -z "$BLOB_TAG" ]; then
    echo "check-served-checkpoint-carries-the-hash: INCONCLUSIVE — could not read both domain tags"
    echo "  (hash='${HASH_TAG:-?}' blob='${BLOB_TAG:-?}')."
    exit 2
fi
if [ "$HASH_TAG" != "$BLOB_TAG" ]; then
    echo "  *** domain tag MISMATCH — hash says '$HASH_TAG', blob's \"version\" says '$BLOB_TAG'"
    echo "      A shim dispatches on \`version\`, so a bumped hash with a stale version string"
    echo "      makes every consumer verify against the wrong preimage."
    bad=$((bad + 1))
else
    echo "  ✓  domain tag — $HASH_TAG (hash and blob agree)"
fi

if [ "$bad" -gt 0 ]; then
    echo
    echo "check-served-checkpoint-carries-the-hash: $bad problem(s)."
    echo
    echo "  A shim rebuilds checkpoint_hash to check any signature at all, so a blob missing one"
    echo "  committed value is a blob nobody can verify. That shipped once already, on the v2 bump,"
    echo "  and went unnoticed because the endpoint 404s below the gate — the first exercise of it"
    echo "  would have been the day someone armed it."
    exit 1
fi

echo "check-served-checkpoint-carries-the-hash: the served blob carries everything the hash commits"
exit 0
