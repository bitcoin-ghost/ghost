//! Where the share shard's balances start — `SHARE_SHARD_BUILD.md` Stage 5, steps 2 and 4.
//!
//! The shard has no history of its own. On the day it is armed it must already owe every miner
//! what the pool owes them, and all eight nodes must agree on that to the byte, because after the
//! flip there is nothing left to reconcile against: each node would be internally consistent with
//! its own wrong opening balances, and the error is undetectable rather than merely undetected.
//!
//! So genesis **converts** a fleet-ratified `PayoutLedgerCheckpoint`; it never recomputes from
//! local shares. Recomputation is what the checkpoint exists to have already settled — eight
//! divergent share ledgers would yield eight divergent opening tables, which is precisely the
//! failure the old design died of. This is the same discipline as [`crate::genesis_balances`], whose
//! `genesis_balances` conversion is reused verbatim rather than re-spelled: two spellings of one
//! conversion drift apart, and the drift is silent.
//!
//! ## The reserved column, and why it is not each node's own
//!
//! `ShardTable::owed` sums **across every column**: `owed[addr] = Σ accrued[·][addr] − settled`.
//! If each node opened by crediting the checkpoint into its OWN column, then the instant those
//! eight tables met over gossip the sum would be **eight times** the balance every miner is
//! actually owed — and it would look perfectly healthy on any single node until the first merge.
//!
//! Every node therefore writes the identical opening balances into ONE reserved column
//! ([`GENESIS_NODE_ID`]). Max-merge of identical values is the identity, so the column survives
//! any number of merges, in any order, contributing exactly once. The write-your-own-column
//! invariant still holds from the first row: no node ever writes another node's column, and the
//! genesis column belongs to no node.
//!
//! ## Why the reserved id cannot be claimed by a peer
//!
//! ⚠ Not because of the key. The first version of this module argued that all-zero bytes are not a
//! valid ed25519 public key and so could never be signed for. That is **false** — dalek accepts
//! `[0u8; 32]` as a low-order point — and the test that asserted it caught the error. Had it stood,
//! a peer could have max-merged an inflated opening balance into a column that is indistinguishable
//! from genesis and, because merging is a max, permanent.
//!
//! The guarantee is structural instead, and lives with the type that holds the invariant:
//! `ShardTable::merge_accrued` skips the reserved column, `EpochSummary::verify_stateless` rejects
//! a summary claiming it before even checking the signature, and the sole writer is
//! `ShardTable::install_genesis`, which no message handler calls.
//!
//! ## Dark code
//!
//! Nothing here is wired into a runtime path. Arming it is Stage 5, and it must land in the same
//! change that renames `shares` (see `owns_evidence` in `bins/ghost-pool/src/shard.rs`).

use std::collections::BTreeMap;

use ghost_common::share_shard::ShardTable;
use sha2::{Digest, Sha256};

use crate::genesis_balances::{genesis_balances, GenesisRounding};

/// The reserved opening-balance column.
///
/// Re-exported rather than redefined: the constant lives beside the table whose `merge_accrued`
/// and `verify_stateless` enforce it, so there is one spelling and the enforcement cannot drift
/// away from the value it protects.
pub use ghost_common::share_shard::GENESIS_NODE_ID;

/// The two adopted lists a `canonical_payout` blob carries, in the order it stores them:
/// `(miner_payouts, node_shares)`, matching `serde_json::to_vec(&(&miner_payouts, &node_shares))`
/// in `queries.rs::upsert_payout_ledger_checkpoint`.
///
/// Named because the pair travels together and that matters: [`GenesisAnchor::canonical_sha256`]
/// covers **both** halves, which is what makes the pin cover the qualified-node set and not only
/// the balances — a requirement Stage 5 states and a balances-only pin would quietly miss.
pub type AdoptedCheckpoint = (Vec<(String, u128)>, Vec<([u8; 32], i32)>);

/// A ceremony pin: the anchor's identity, and what converting it must produce.
///
/// Every field is checked at arming time. They fail in a deliberate order — cheapest and most
/// diagnostic first — so an operator reading the error learns *which* thing went wrong rather than
/// only that the roots differed:
///
/// 1. `canonical_sha256` — "this node's adopted bytes are not the ceremony's bytes". Caught before
///    any conversion runs, and it names the real fault directly.
/// 2. `table_root` — "the bytes were right and the conversion produced something else", i.e. the
///    conversion or the root encoding moved underneath the pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenesisAnchor {
    /// Block height of the ratified checkpoint being converted.
    pub height: u64,
    /// The checkpoint's cutoff timestamp. Chain-derived, carried for provenance.
    pub cutoff_ts: i64,
    /// The `ledger_root` the fleet ratified at `height`.
    ///
    /// ⚠ Provenance only — deliberately NOT the arming check. Since the #606 median gate
    /// (h961700) `payout_checkpoint.rs` persists the proposer's root beside a `miner_payouts`
    /// that is the per-address median of whichever reports that node received, so the root no
    /// longer commits to the bytes genesis converts. Measured across the fleet on 2026-08-13:
    /// over the 182 heights all 8 nodes hold since 961,600 the roots agree at 180 and the adopted
    /// bytes at 41. Gating on this field would pass a height whose bytes differ 5-nodes-to-3.
    pub ledger_root: [u8; 32],
    /// SHA-256 of the checkpoint's adopted `canonical_payout` blob, exactly as stored.
    ///
    /// This is the real fleet-identity check, and it covers the qualified-node set as well as the
    /// balances: the blob is `serde_json::to_vec(&(&miner_payouts, &node_shares))`, so pinning its
    /// digest pins both halves, which Stage 5 requires and a balances-only pin would miss.
    pub canonical_sha256: [u8; 32],
    /// `ShardTable::compute_table_root` of the opening table.
    pub table_root: [u8; 32],
}

/// Height of the pinned genesis anchor.
///
/// Chosen 2026-08-14 by `scripts/shard-anchor-rehearsal.sh` from 163 candidates, of which 3
/// qualified — post-#606 the adopted bytes agree at only ~1.8% of heights, so this is the newest
/// height that COULD be used, not the newest that existed. Re-pin by re-running the survey; the
/// golden vector is the only thing that has to move with it.
///
/// Replaces 962,008, which was 290 blocks staler. Every block between the anchor and arming is
/// work the catch-up has to re-fold, so a fresher anchor is a shorter catch-up — nothing more
/// subtle than that.
pub const ANCHOR_HEIGHT: u64 = 962_298;

/// `cutoff_ts` of the pinned anchor. Chain-derived, carried for provenance.
pub const ANCHOR_CUTOFF_TS: i64 = 1_786_634_458;

/// The `ledger_root` the fleet ratified at [`ANCHOR_HEIGHT`] — provenance only, never the gate.
const ANCHOR_LEDGER_ROOT: &str = "8b7b04e5a77996ef0c585a2c2a492aa8a06d83fbe13ecb9d8e752cc277dbc433";

/// SHA-256 of the adopted `canonical_payout` blob — the real fleet-identity check.
const ANCHOR_CANONICAL_SHA256: &str =
    "7c22a2fdbf36c90de68285a3972d0d2ce4d39f02ce75768b60d29fbc269db7b4";

/// `compute_table_root` of the opening table this anchor converts to.
const ANCHOR_TABLE_ROOT: &str = "a596b397cb12fd2dddfe28a0436b56ac6f2b1ecd36a12348950cc2dd34e1f3c4";

/// The pinned ceremony anchor.
///
/// Panics only if the constants above are not 32 bytes of hex, which
/// `the_pinned_anchor_parses` makes a build-time failure rather than a runtime one.
pub fn pinned_anchor() -> GenesisAnchor {
    fn h(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        let bytes = hex::decode(s).expect("pinned anchor constant is valid hex");
        assert_eq!(bytes.len(), 32, "pinned anchor constant must be 32 bytes");
        out.copy_from_slice(&bytes);
        out
    }
    GenesisAnchor {
        height: ANCHOR_HEIGHT,
        cutoff_ts: ANCHOR_CUTOFF_TS,
        ledger_root: h(ANCHOR_LEDGER_ROOT),
        canonical_sha256: h(ANCHOR_CANONICAL_SHA256),
        table_root: h(ANCHOR_TABLE_ROOT),
    }
}

/// The adopted `canonical_payout` blob the pin was taken over, reconstructed byte-for-byte.
///
/// Feature-gated so it never reaches a production binary, but deliberately NOT inside a `#[cfg(test)]`
/// module: `ghost-pool`'s arming tests need the same bytes, and a second copy over there went stale
/// the first time the anchor was re-pinned — six tests failing for no reason but duplication. One
/// spelling, two crates.
///
/// Byte-identity is what matters, not shape: `node_shares` is in the blob's OWN order rather than
/// sorted, because the digest is over the bytes the fleet actually adopted.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn pinned_canonical_payout_blob() -> Vec<u8> {
    fn hx(s: &str) -> [u8; 32] {
        let mut o = [0u8; 32];
        o.copy_from_slice(&hex::decode(s).expect("valid hex"));
        o
    }
    let miner_payouts: Vec<(String, u128)> = vec![
        (
            "bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492".to_string(),
            62_143_408_528_125_167_927_296,
        ),
        (
            "bc1qhfgc0uj7wv03vmchxe2hn8lhtu6ey9zaf0nre2".to_string(),
            2_827_976_214_437_835_046_912,
        ),
        (
            "bc1q9z23a6yl44nc83dwm996ntl6wphwcwt9k0q0ej".to_string(),
            2_503_874_639_417_892_143_104,
        ),
        (
            "148WRjKfSSo911CYRLzeyYm1QKhy7kCXTN".to_string(),
            532_541_467_700_909_047_808,
        ),
        (
            "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h".to_string(),
            9_741_908_758_669_000_704,
        ),
    ];
    let node_shares: Vec<([u8; 32], i32)> = vec![
        (
            hx("5867b555602257bdffa5d4c3577c464416087f2aa04ac478f3986a17e51d3393"),
            6,
        ),
        (
            hx("e557c97a32335457ed6eceb6f8a9c7ee13f8731ee99dc9f4b7831dcf606d6927"),
            10,
        ),
        (
            hx("fb71fee87bb0516920fdb673f3068be3c0b9b29fc62e309b99594a0008c25622"),
            10,
        ),
        (
            hx("849bceceb22cc7ebbeec252d824940ebb73ee08c7855c5a90b5661dd21aeb18c"),
            10,
        ),
        (
            hx("9fe860bda96ff81820a2e166f48cb3ae59010fc9e42550a3aeafb5bfef4d1b38"),
            10,
        ),
        (
            hx("46141044f80c99ac01476b3c2d6cd2149f31b5f1b06ffd2dfa3d15d588c7a39b"),
            6,
        ),
        (
            hx("f0215f1ffd9a711ffc8e476f37bf3e19a2afc18803d146ecedb5d53d4fe9bd4f"),
            6,
        ),
        (
            hx("4c8c2272ae67d76c6c4108f0e4e6dfde7ff864689d3e9b99a35ab1bd46051132"),
            6,
        ),
    ];
    serde_json::to_vec(&(&miner_payouts, &node_shares)).expect("encodable")
}

/// Why a node refused to open its shard.
///
/// Every variant is a refusal to start, never a warning. A node that opens on the wrong balances
/// is worse than a node that does not open: the first silently misallocates money and cannot be
/// detected afterwards, the second is loud and costs an operator five minutes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GenesisError {
    /// This node's adopted checkpoint bytes are not the ones the ceremony verified.
    #[error(
        "genesis: canonical_payout at height {height} hashes to {found} but the pinned anchor is \
         {expected} — this node did not adopt the bytes the ceremony verified; re-run \
         scripts/shard-anchor-rehearsal.sh before arming"
    )]
    CanonicalMismatch {
        height: u64,
        expected: String,
        found: String,
    },
    /// The bytes were right and the conversion still produced a different table.
    #[error(
        "genesis: opening table root is {found} but the pinned anchor is {expected} — the adopted \
         bytes matched, so the conversion or the table-root encoding has moved"
    )]
    RootMismatch { expected: String, found: String },
    /// The bytes matched the pin but are not decodable as `(miner_payouts, node_shares)`.
    ///
    /// Reachable only if the stored encoding changes shape while its digest is still pinned, which
    /// is to say almost never — but the alternative is a panic on a money path.
    #[error("genesis: canonical_payout at height {height} does not decode: {detail}")]
    Undecodable { height: u64, detail: String },
    /// The checkpoint decodes but carries no payees.
    ///
    /// ⚠ Note what this does NOT catch. The obvious case — a pre-adopt-on-finalise row whose
    /// `canonical_payout` is NULL — never reaches here, because the digest check runs first and a
    /// pinned anchor is always over a non-empty blob, so an empty blob fails as
    /// `CanonicalMismatch`. That is the right verdict and a better message. This variant is the
    /// backstop for the case where the pin *itself* was taken over a payee-less blob, i.e. the
    /// ceremony verified something worthless — which the rehearsal script refuses precisely
    /// because sha256 of nothing is unanimous on all eight nodes.
    #[error("genesis: checkpoint at height {height} carries no miner payouts — refusing to open the shard owing nobody")]
    NoPayees { height: u64 },
    /// A genesis column loaded from disk does not match the pin.
    #[error(
        "genesis: the persisted genesis column for height {height} has root {found}, not the \
         pinned {expected} — the opening balances on disk are not the ones the ceremony \
         installed; restore them rather than starting, because merge can no longer re-learn them"
    )]
    LoadedGenesisMismatch {
        height: u64,
        expected: String,
        found: String,
    },
}

/// Convert a ratified checkpoint's adopted miner set into an opening [`ShardTable`].
///
/// `miner_payouts` must be the checkpoint's own `(payout_address, WORK_SCALE-quantised work)`
/// list, adopted verbatim — passing a locally recomputed list defeats the entire purpose.
///
/// Truncating, never rounding up, inherited from [`genesis_balances`]: under-crediting by less
/// than a millionth of a share is immaterial, whereas crediting work nobody proved is a different
/// kind of thing. `settled` opens empty, which is correct rather than merely convenient — the pool
/// has won no blocks, so nothing has been discharged, and `settled` is chain-derived anyway.
pub fn shard_genesis_table(miner_payouts: &[(String, u128)]) -> (ShardTable, GenesisRounding) {
    let (balances, rounding) = genesis_balances(miner_payouts);
    let mut table = ShardTable::new();
    table.install_genesis(balances);
    (table, rounding)
}

/// The opening balances as a plain column — what `Database::shard_upsert_column` persists.
///
/// Not an intra-doc link: `ghost-accounting` does not depend on `ghost-storage`, and the
/// previous workaround pointed at a docs.rs URL that need not exist for this version.
pub fn genesis_column(table: &ShardTable) -> BTreeMap<String, i64> {
    table
        .accrued()
        .get(&GENESIS_NODE_ID)
        .cloned()
        .unwrap_or_default()
}

/// Open the shard from an adopted checkpoint, refusing unless it matches the pin exactly.
///
/// This is Stage 5 step 4's "loud local self-check, not a fleet negotiation": each node converts
/// its own copy of the byte-identical checkpoint and asserts the result against a compile-time
/// pin. No node asks another node anything, so there is no negotiation to be partitioned, no
/// quorum to stall, and a node holding the wrong bytes discovers it on its own.
///
/// `canonical_payout` is the raw blob exactly as the database holds it, and it is the ONLY input.
///
/// The miner list is decoded from that blob here rather than accepted as a second argument. Taking
/// both would let a caller hash the blob at the anchor height while passing payouts decoded from a
/// different record — which is easy to do by accident, because the runtime's own lookup is
/// `get_payout_ledger_checkpoint_at_or_before`, which happily returns an *older* height when the
/// anchor is absent. The digest would pass, the conversion would run on the wrong list, and the
/// failure would surface as `RootMismatch`, whose message sends the operator to debug the encoder
/// instead of the mismatched inputs. One input cannot disagree with itself.
///
/// Decoding rather than re-encoding is also why the digest is taken over the stored bytes:
/// `serde_json` round-trips are not guaranteed byte-stable, so hashing a re-encoding would be
/// checking a different object from the one the fleet compared.
pub fn open_shard_from_checkpoint(
    canonical_payout: &[u8],
    anchor: &GenesisAnchor,
) -> Result<(ShardTable, GenesisRounding), GenesisError> {
    let found = Sha256::digest(canonical_payout);
    if found.as_slice() != anchor.canonical_sha256 {
        return Err(GenesisError::CanonicalMismatch {
            height: anchor.height,
            expected: hex::encode(anchor.canonical_sha256),
            found: hex::encode(found),
        });
    }

    let (miner_payouts, _node_shares): AdoptedCheckpoint = serde_json::from_slice(canonical_payout)
        .map_err(|e| GenesisError::Undecodable {
            height: anchor.height,
            detail: e.to_string(),
        })?;

    if miner_payouts.is_empty() {
        return Err(GenesisError::NoPayees {
            height: anchor.height,
        });
    }

    let (table, rounding) = shard_genesis_table(&miner_payouts);
    let root = table.compute_table_root();
    if root != anchor.table_root {
        return Err(GenesisError::RootMismatch {
            expected: hex::encode(anchor.table_root),
            found: hex::encode(root),
        });
    }
    Ok((table, rounding))
}

/// Re-assert a genesis column loaded from disk against the pin.
///
/// `merge_accrued` skips the reserved column, so once a node is armed genesis can no longer be
/// re-learned from any peer. That makes the persisted rows a single point of silent failure: if
/// `shard_counters` loses them — truncation, a partial delete, a restored backup taken before the
/// ceremony — the node opens under-owing every miner, stays internally consistent, and nothing
/// ever contradicts it. This is exactly the "internally consistent with its own wrong opening
/// balances" failure the module exists to prevent, arriving through the back door.
///
/// **An absent column is not an error.** Before the ceremony there is legitimately no genesis
/// column, and every dark-mode start is that case, so refusing here would refuse to boot.
/// Present-and-wrong is the only failure.
pub fn verify_loaded_genesis(
    table: &ShardTable,
    anchor: &GenesisAnchor,
) -> Result<(), GenesisError> {
    let Some(loaded) = table.accrued().get(&GENESIS_NODE_ID) else {
        return Ok(());
    };

    // Compared as a table root rather than cell by cell so this check and the arming check speak
    // the same language — one encoding, one pinned value, no second opinion to drift.
    let mut probe = ShardTable::new();
    probe.install_genesis(loaded.clone());
    let root = probe.compute_table_root();
    if root != anchor.table_root {
        return Err(GenesisError::LoadedGenesisMismatch {
            height: anchor.height,
            expected: hex::encode(anchor.table_root),
            found: hex::encode(root),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shares::WORK_SCALE;

    /// Checkpoint units per micro-work — the scale bridge `genesis_balances` applies.
    const UNITS_PER_MICRO: u128 = WORK_SCALE / 1_000_000;

    /// The adopted per-address totals at height **962,008**, read from production 2026-08-13.
    ///
    /// Verified read-only across all 8 nodes by `scripts/shard-anchor-rehearsal.sh`:
    ///   - `ledger_root` `61AE50AB…CD74B93E` — ONE distinct value fleet-wide
    ///   - `canonical_payout` 1,316 bytes, sha256 `a3f7202f…2bebad62`, identical on all 8
    ///   - the ratified root recomputes from those bytes on 8/8 nodes, so at this height the
    ///     median the fleet adopted equals the list the proposer signed
    ///   - 5 miner payees, 8 node entries, lag 311 blocks behind tip at verification
    ///
    /// Chosen over fresher heights because post-#606 blob unanimity is rare: of the 182 heights
    /// all 8 nodes held since 961,600, only 41 had identical adopted bytes, and only 3 of those
    /// were after the gate armed at 961,700.
    /// The adopted per-address totals at height **962,298**, DECODED from the blob rather than
    /// written out again.
    ///
    /// The values used to be duplicated here beside `pinned_canonical_payout_blob`, and re-pinning
    /// the anchor broke six tests in another crate because a third copy had gone stale. Decoding
    /// the one definition means a re-pin touches exactly one place, and the fixture cannot drift
    /// from the bytes whose digest is pinned.
    ///
    /// Verified read-only across all 8 nodes on 2026-08-14 by `scripts/shard-anchor-rehearsal.sh`:
    ///   - `ledger_root` `8B7B04E5…77DBC433` — ONE distinct value fleet-wide
    ///   - `canonical_payout` 1,316 bytes, sha256 `7c22a2fd…269db7b4`, identical on all 8
    ///   - the ratified root recomputes from those bytes on 8/8, so the adopted median equals the
    ///     list the proposer signed
    ///   - 5 miner payees, 8 node entries, lag 103 blocks behind tip at verification
    ///
    /// Chosen from 163 candidates of which 3 qualified: post-#606 the adopted bytes agree at only
    /// ~1.8% of heights, so this is the newest height that COULD be used.
    fn ratified_962298() -> Vec<(String, u128)> {
        let (miners, _nodes): AdoptedCheckpoint =
            serde_json::from_slice(&pinned_canonical_payout_blob()).expect("pinned blob decodes");
        miners
    }

    /// Pinned opening root for the 962,008 anchor.
    ///
    /// A change here means the conversion or `compute_table_root`'s encoding moved, and either
    /// would hand eight nodes eight different opening balances with no way to notice afterwards.
    const GENESIS_TABLE_ROOT_962298: &str =
        "a596b397cb12fd2dddfe28a0436b56ac6f2b1ecd36a12348950cc2dd34e1f3c4";

    /// The whole point of the reserved column, stated as a test.
    ///
    /// Eight nodes each open from the same checkpoint. Their tables then meet over gossip. The
    /// balance a miner is owed must be what the checkpoint said, NOT eight times it.
    #[test]
    fn eight_nodes_opening_together_do_not_multiply_the_opening_balances() {
        let (mut merged, _) = shard_genesis_table(&ratified_962298());
        for _ in 0..7 {
            let (peer, _) = shard_genesis_table(&ratified_962298());
            merged.merge_accrued(peer.accrued());
        }

        let (solo, _) = shard_genesis_table(&ratified_962298());
        assert_eq!(
            merged.owed(),
            solo.owed(),
            "merging eight identical genesis tables must be the identity; a per-node genesis \
             column would make every balance 8x here"
        );
        assert_eq!(
            merged.compute_table_root(),
            solo.compute_table_root(),
            "and the table root must not move either"
        );
    }

    /// Merge order must not matter, since gossip provides no ordering.
    #[test]
    fn genesis_merge_is_order_independent() {
        let forwards = ratified_962298();
        let mut backwards = ratified_962298();
        backwards.reverse();

        let (a, _) = shard_genesis_table(&forwards);
        let (b, _) = shard_genesis_table(&backwards);
        assert_eq!(a.compute_table_root(), b.compute_table_root());
        assert_eq!(a.owed(), b.owed());
    }

    /// Everything lands in the reserved column and nothing lands anywhere else.
    #[test]
    fn genesis_writes_only_the_reserved_column() {
        let (table, _) = shard_genesis_table(&ratified_962298());
        let columns: Vec<&ghost_common::types::NodeId> = table.accrued().keys().collect();
        assert_eq!(columns, vec![&GENESIS_NODE_ID]);
        assert_eq!(genesis_column(&table).len(), 5);
        assert!(
            table.settled().is_empty(),
            "nothing has been discharged at genesis; settled is chain-derived"
        );
    }

    /// The opening balances must account for the ratified total, less only truncation.
    #[test]
    fn the_anchor_converts_without_losing_a_payee_or_unexplained_work() {
        let (table, rounding) = shard_genesis_table(&ratified_962298());
        let column = genesis_column(&table);

        assert_eq!(column.len(), 5, "every payee must survive the conversion");
        assert_eq!(rounding.addresses_dropped, 0);

        let opened: i128 = column.values().map(|v| *v as i128).sum();
        let ratified: u128 = ratified_962298().iter().map(|(_, w)| *w).sum();
        let expected = (ratified - rounding.units_discarded) / UNITS_PER_MICRO;
        assert_eq!(
            opened as u128, expected,
            "opening balances must equal the ratified total minus truncation"
        );

        // Per-address, each payee loses under one micro-work, so the fleet total is bounded by
        // the payee count. (The 961,642 vector asserts a total under ONE micro-work; that held
        // for that data by luck and is not a law.)
        assert!(
            rounding.units_discarded < (column.len() as u128) * UNITS_PER_MICRO,
            "lost {} units across {} payees",
            rounding.units_discarded,
            column.len()
        );

        // The dominant payee holds ~91% of the ledger; a conversion bug there is the one that
        // actually costs someone money.
        assert_eq!(
            column.get("bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492"),
            Some(&62_143_408_528_125_167)
        );
    }

    /// The pinned constants must parse, and must be the anchor the golden vector was taken over.
    ///
    /// `pinned_anchor` panics on malformed hex; this makes that a test failure at build time
    /// rather than a node refusing to start in the middle of a ceremony.
    #[test]
    fn the_pinned_anchor_parses() {
        let anchor = pinned_anchor();
        assert_eq!(anchor.height, 962_298);
        assert_eq!(anchor.cutoff_ts, 1_786_634_458);
        assert_eq!(
            hex::encode(anchor.canonical_sha256),
            "7c22a2fdbf36c90de68285a3972d0d2ce4d39f02ce75768b60d29fbc269db7b4"
        );
        // The pin must agree with the conversion it claims to describe — otherwise the runtime
        // would check itself against a number nothing produced.
        let (table, _) = shard_genesis_table(&ratified_962298());
        assert_eq!(table.compute_table_root(), anchor.table_root);
    }

    /// Golden vector: the opening root for the chosen anchor.
    #[test]
    fn genesis_table_root_for_the_962298_anchor_is_pinned() {
        let (table, _) = shard_genesis_table(&ratified_962298());
        assert_eq!(
            hex::encode(table.compute_table_root()),
            GENESIS_TABLE_ROOT_962298
        );
    }

    /// The arming path accepts the exact adopted bytes.
    #[test]
    fn arming_accepts_the_verified_anchor() {
        let blob = canonical_blob();
        let (table, _) = open_shard_from_checkpoint(&blob, &pinned_anchor())
            .expect("the verified anchor must arm");
        assert_eq!(table.compute_table_root(), pinned_anchor().table_root);
        assert_eq!(genesis_column(&table).len(), 5);
    }

    /// A node holding different adopted bytes must refuse, and must say so as a byte mismatch
    /// rather than as a root mismatch — the operator needs to know which fault it is.
    #[test]
    fn arming_refuses_bytes_the_ceremony_did_not_verify() {
        let mut blob = canonical_blob();
        blob.push(b' '); // JSON-insignificant, byte-significant: still the wrong object
        let err = open_shard_from_checkpoint(&blob, &pinned_anchor())
            .expect_err("different bytes must refuse");
        assert!(
            matches!(err, GenesisError::CanonicalMismatch { .. }),
            "got {err:?}"
        );
    }

    /// The NULL `canonical_payout` case — a pre-adopt-on-finalise row — refuses as a BYTE
    /// mismatch, not as `NoPayees`, because the digest check runs first. Pinned so the error
    /// taxonomy in the docs matches what the code actually returns.
    #[test]
    fn an_empty_blob_refuses_as_a_byte_mismatch_not_as_no_payees() {
        let err = open_shard_from_checkpoint(&[], &pinned_anchor())
            .expect_err("an empty blob must refuse");
        assert!(
            matches!(err, GenesisError::CanonicalMismatch { .. }),
            "got {err:?}"
        );
    }

    /// `NoPayees` is the backstop for a pin taken over a payee-less blob — the ceremony having
    /// verified something worthless. Reachable only by constructing exactly that.
    #[test]
    fn arming_refuses_a_pin_taken_over_a_payee_less_blob() {
        let empty_payouts: Vec<(String, u128)> = Vec::new();
        let empty_nodes: Vec<([u8; 32], i32)> = Vec::new();
        let blob = serde_json::to_vec(&(&empty_payouts, &empty_nodes)).expect("encodable");
        let anchor = GenesisAnchor {
            canonical_sha256: Sha256::digest(&blob).into(),
            ..pinned_anchor()
        };
        let err = open_shard_from_checkpoint(&blob, &anchor)
            .expect_err("a payee-less anchor must refuse");
        assert!(matches!(err, GenesisError::NoPayees { .. }), "got {err:?}");
    }

    /// Right bytes, wrong conversion: the root check is the second line of defence and must be
    /// reachable, not shadowed by the digest check.
    #[test]
    fn arming_refuses_when_the_conversion_moves_under_the_pin() {
        let blob = canonical_blob();
        let anchor = GenesisAnchor {
            table_root: [0xAB; 32],
            ..pinned_anchor()
        };
        let err =
            open_shard_from_checkpoint(&blob, &anchor).expect_err("a moved conversion must refuse");
        assert!(
            matches!(err, GenesisError::RootMismatch { .. }),
            "got {err:?}"
        );
    }

    /// A dark-mode start has no genesis column at all, and must not be refused.
    #[test]
    fn verifying_a_table_with_no_genesis_column_is_not_an_error() {
        assert_eq!(
            verify_loaded_genesis(&ShardTable::new(), &pinned_anchor()),
            Ok(())
        );
    }

    /// The armed, healthy case round-trips.
    #[test]
    fn verifying_an_intact_persisted_genesis_column_passes() {
        let (table, _) =
            open_shard_from_checkpoint(&canonical_blob(), &pinned_anchor()).expect("arms");
        let mut reloaded = ShardTable::new();
        reloaded.install_genesis(genesis_column(&table));
        assert_eq!(verify_loaded_genesis(&reloaded, &pinned_anchor()), Ok(()));
    }

    /// The failure this check exists for: rows lost from `shard_counters`.
    ///
    /// `merge_accrued` skips the reserved column, so a peer can never restore it. Without this
    /// check the node opens under-owing every miner, internally consistent, for ever.
    #[test]
    fn verifying_a_truncated_persisted_genesis_column_refuses() {
        let (table, _) =
            open_shard_from_checkpoint(&canonical_blob(), &pinned_anchor()).expect("arms");
        let mut lossy = genesis_column(&table);
        lossy.remove("bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h");

        let mut reloaded = ShardTable::new();
        reloaded.install_genesis(lossy);
        let err = verify_loaded_genesis(&reloaded, &pinned_anchor())
            .expect_err("a truncated genesis column must refuse to start");
        assert!(
            matches!(err, GenesisError::LoadedGenesisMismatch { .. }),
            "got {err:?}"
        );
    }

    /// And an inflated one — the same check catches tampering, not only loss.
    #[test]
    fn verifying_an_inflated_persisted_genesis_column_refuses() {
        let (table, _) =
            open_shard_from_checkpoint(&canonical_blob(), &pinned_anchor()).expect("arms");
        let mut inflated = genesis_column(&table);
        inflated.insert("bc1qattacker".to_string(), 999_999_999);

        let mut reloaded = ShardTable::new();
        reloaded.install_genesis(inflated);
        assert!(matches!(
            verify_loaded_genesis(&reloaded, &pinned_anchor()),
            Err(GenesisError::LoadedGenesisMismatch { .. })
        ));
    }

    /// ⚠ The reserved id IS a loadable ed25519 key. Pinned as a test because the first version of
    /// this module assumed the opposite and rested the whole "a peer cannot claim the genesis
    /// column" argument on it. If a future dalek starts rejecting low-order points, this fails and
    /// the reader is sent to the enforcement below rather than quietly regaining a false comfort.
    #[test]
    fn the_reserved_id_is_a_loadable_key_so_the_guarantee_cannot_rest_on_the_key() {
        assert_eq!(GENESIS_NODE_ID, [0u8; 32]);
        assert!(
            ed25519_dalek::VerifyingKey::from_bytes(&GENESIS_NODE_ID).is_ok(),
            "all-zero bytes load as a low-order point; the genesis column must be protected \
             structurally, not by unsignability"
        );
    }

    /// The structural guarantee: a peer's table cannot move the opening balances.
    ///
    /// This is the attack the false key assumption would have left open — an inflated genesis
    /// column max-merged in, permanent and indistinguishable from the real thing.
    #[test]
    fn a_peer_cannot_inflate_the_genesis_column() {
        let (mut table, _) = shard_genesis_table(&ratified_962298());
        let before = table.compute_table_root();

        let mut hostile: BTreeMap<String, i64> = BTreeMap::new();
        hostile.insert(
            "bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492".to_string(),
            i64::MAX,
        );
        let mut columns: ghost_common::share_shard::AccruedColumns = BTreeMap::new();
        columns.insert(GENESIS_NODE_ID, hostile);
        table.merge_accrued(&columns);

        assert_eq!(
            table.compute_table_root(),
            before,
            "a peer offering a larger genesis column must not move the table"
        );
        assert_eq!(
            genesis_column(&table).get("bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492"),
            Some(&62_143_408_528_125_167)
        );
    }

    /// A node reloading its own persisted table must keep the opening balances. `merge_accrued`
    /// now skips the reserved column, so any reconstruction routed through it drops genesis
    /// entirely — every miner's opening balance gone on the next restart.
    #[test]
    fn reinstalling_a_persisted_genesis_column_round_trips() {
        let (table, _) = shard_genesis_table(&ratified_962298());
        let persisted = genesis_column(&table);

        let mut reloaded = ShardTable::new();
        reloaded.install_genesis(persisted);
        assert_eq!(reloaded.compute_table_root(), table.compute_table_root());
        assert_eq!(reloaded.owed(), table.owed());
    }

    /// The adopted blob, from the ONE definition — see `pinned_canonical_payout_blob`.
    fn canonical_blob() -> Vec<u8> {
        super::pinned_canonical_payout_blob()
    }

    /// The blob this test module reconstructs must be the blob production actually holds, or the
    /// digest pin is checking a fiction. This is the load-bearing tie between the fixture and the
    /// live fleet.
    #[test]
    fn the_reconstructed_blob_matches_the_bytes_read_from_all_eight_nodes() {
        let blob = canonical_blob();
        assert_eq!(
            blob.len(),
            1316,
            "production stores 1,316 bytes at this height"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&blob)),
            "7c22a2fdbf36c90de68285a3972d0d2ce4d39f02ce75768b60d29fbc269db7b4"
        );
    }
}
