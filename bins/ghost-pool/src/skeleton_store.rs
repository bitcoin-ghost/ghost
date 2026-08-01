//! Keeping per-job coinbase skeletons long enough to prove a share, and no longer.
//!
//! A skeleton is what lets a node verify that a share's proof of work really committed to *its*
//! node tag: rebuild the coinbase from `prefix ‖ extranonce ‖ suffix`, walk the merkle path, and
//! compare against the root inside the header the miner actually hashed. Drop the skeleton and that
//! check becomes impossible — the share is still there, but nothing can say whose it was.
//!
//! So the question is only how long to keep it, and the answer has two halves:
//!
//! - **Until the batch containing the share is finalised.** After that the binding is settled by
//!   67% agreement, and a node syncing later trusts the finalisation rather than re-deriving it.
//! - **But never less than a reorg's worth of chain.** A settlement reversal puts shares back into
//!   the owed set, and if the skeleton is already gone by then the binding cannot be re-established.
//!   An observed reorg *extends* the floor rather than racing it.
//!
//! This is affordable only because of how a skeleton splits. The suffix carries the coinbase
//! outputs — up to ~29 KB at 200 payees — and changes only when the payout set does, so it is
//! content-addressed and shared across every job that reuses it. What changes per template (~30 s)
//! is the merkle path and the prefix, together a few hundred bytes. Storing whole coinbases per job
//! instead would be tens of GB over the same window, and the reorg floor would be unaffordable.
//!
//! Dark code: nothing wires this into a runtime path yet.

use std::collections::HashMap;

use ghost_common::share_binding::CoinbaseSkeleton;

/// Blocks of chain a skeleton must survive regardless of batch progress.
///
/// Matches `ReorgConfig::max_reorg_depth` — the depth beyond which the pool already declares a
/// reorg to need manual intervention. Using the shallower `min_confirmations` (6) would leave a
/// deep-but-handled reorg unable to re-establish bindings, which is the failure this floor exists
/// to prevent.
pub const RETENTION_FLOOR_BLOCKS: u64 = 100;

/// Hard ceiling on how long one skeleton is kept, in blocks.
///
/// Without it, a batch chain that stalls forever grows this store forever. Ten times the floor is
/// far beyond any real stall, so hitting it means something is wrong — and it is reported rather
/// than silently dropped, because a skeleton evicted early turns into an unverifiable share, and
/// that must not be discoverable only as a mystery later.
pub const RETENTION_CEILING_BLOCKS: u64 = RETENTION_FLOOR_BLOCKS * 10;

/// Content address of a skeleton.
///
/// Delegates to [`CoinbaseSkeleton::id`] — `pool_sv2` stamps the same id onto every share, and a
/// second implementation here would be a second chance for a share to name a skeleton this node
/// cannot find.
pub fn skeleton_id(skeleton: &CoinbaseSkeleton) -> [u8; 32] {
    skeleton.id()
}

/// Why a skeleton was let go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eviction {
    /// The normal case: its shares are in a finalised batch and the reorg floor has passed.
    Settled,
    /// The ceiling was hit while it was still needed. Reported loudly — every share still relying
    /// on it has just become unverifiable.
    CeilingHit,
}

#[derive(Debug, Clone)]
struct Entry {
    skeleton: CoinbaseSkeleton,
    /// Height at which this skeleton was first stored.
    stored_at: u64,
    /// Height of the most recent reorg observed while it was held. Pushes the floor forward, so a
    /// reorg extends retention instead of racing it.
    floor_from: u64,
    /// The highest batch sequence that referenced it, once known.
    last_referenced_seq: Option<u64>,
}

/// The live skeletons, with the retention rule applied.
#[derive(Debug, Default)]
pub struct SkeletonStore {
    entries: HashMap<[u8; 32], Entry>,
}

impl SkeletonStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Store a skeleton, or refresh the one already held.
    ///
    /// Re-storing does **not** reset `stored_at`: a job that keeps reusing the same invariant part
    /// would otherwise hold it open indefinitely. It does clear nothing else either — this is
    /// deliberately a no-op on a hit, so the retention clock belongs to the content, not to how
    /// often it happens to be re-announced.
    pub fn insert(&mut self, skeleton: CoinbaseSkeleton, height: u64) -> [u8; 32] {
        let id = skeleton_id(&skeleton);
        self.entries.entry(id).or_insert_with(|| Entry {
            skeleton,
            stored_at: height,
            floor_from: height,
            last_referenced_seq: None,
        });
        id
    }

    pub fn get(&self, id: &[u8; 32]) -> Option<&CoinbaseSkeleton> {
        self.entries.get(id).map(|e| &e.skeleton)
    }

    /// Note that a batch at `seq` contains shares proved by this skeleton.
    ///
    /// Kept as a maximum: a skeleton referenced by several batches is only free once the **last**
    /// of them is final, and taking the latest reference is what expresses that.
    pub fn note_referenced(&mut self, id: &[u8; 32], seq: u64) {
        if let Some(e) = self.entries.get_mut(id) {
            e.last_referenced_seq = Some(e.last_referenced_seq.map_or(seq, |s| s.max(seq)));
        }
    }

    /// A reorg was observed. Every held skeleton's floor moves to here.
    ///
    /// Applied to all of them, not only those near expiry: a reorg means the chain the retention
    /// was measured against has changed underneath every one of them.
    pub fn observed_reorg(&mut self, height: u64) {
        for e in self.entries.values_mut() {
            e.floor_from = e.floor_from.max(height);
        }
    }

    /// Drop what is no longer needed, and report anything dropped while still needed.
    ///
    /// `finalised_seq` is the highest batch sequence finalised so far; `None` means the batch chain
    /// has not finalised anything yet, in which case nothing is releasable on those grounds and
    /// only the ceiling can evict.
    pub fn prune(&mut self, height: u64, finalised_seq: Option<u64>) -> Vec<([u8; 32], Eviction)> {
        let mut evicted = Vec::new();

        self.entries.retain(|id, e| {
            let past_ceiling = height.saturating_sub(e.stored_at) >= RETENTION_CEILING_BLOCKS;
            let past_floor = height.saturating_sub(e.floor_from) >= RETENTION_FLOOR_BLOCKS;
            let batch_final = match (e.last_referenced_seq, finalised_seq) {
                (Some(referenced), Some(final_seq)) => referenced <= final_seq,
                // Never referenced by any batch: no share ever needed it, so the floor alone
                // decides. Holding it forever because nothing claimed it would be backwards.
                (None, _) => true,
                (Some(_), None) => false,
            };

            if batch_final && past_floor {
                evicted.push((*id, Eviction::Settled));
                return false;
            }
            if past_ceiling {
                evicted.push((*id, Eviction::CeilingHit));
                return false;
            }
            true
        });

        evicted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_skeleton(tag: u8) -> CoinbaseSkeleton {
        CoinbaseSkeleton {
            coinbase_prefix: vec![tag, 1, 2, 3],
            coinbase_suffix: vec![tag, 9, 9],
            merkle_path: vec![[tag; 32]],
        }
    }

    /// Content addressing is what lets two jobs sharing an invariant part share one stored copy —
    /// the thing that makes a ~29 KB outputs blob affordable at all.
    #[test]
    fn identical_skeletons_share_one_entry() {
        let mut s = SkeletonStore::new();
        let a = s.insert(a_skeleton(1), 100);
        let b = s.insert(a_skeleton(1), 101);
        assert_eq!(a, b);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn different_skeletons_get_different_ids() {
        let mut s = SkeletonStore::new();
        s.insert(a_skeleton(1), 100);
        s.insert(a_skeleton(2), 100);
        assert_eq!(s.len(), 2);
    }

    /// Re-announcing the same job must not renew the clock, or a long-lived template holds its
    /// skeleton open forever.
    #[test]
    fn re_storing_does_not_renew_the_retention_clock() {
        let mut s = SkeletonStore::new();
        let id = s.insert(a_skeleton(1), 100);
        s.note_referenced(&id, 5);
        s.insert(a_skeleton(1), 100 + RETENTION_FLOOR_BLOCKS);

        let evicted = s.prune(100 + RETENTION_FLOOR_BLOCKS, Some(5));
        assert_eq!(evicted, vec![(id, Eviction::Settled)]);
    }

    /// **The rule.** Finalisation alone is not enough — the reorg floor has to pass too.
    #[test]
    fn a_finalised_batch_still_waits_for_the_reorg_floor() {
        let mut s = SkeletonStore::new();
        let id = s.insert(a_skeleton(1), 100);
        s.note_referenced(&id, 7);

        assert!(
            s.prune(100 + RETENTION_FLOOR_BLOCKS - 1, Some(7))
                .is_empty(),
            "a settlement reversal inside the floor must still be able to re-prove the binding"
        );
        assert_eq!(
            s.prune(100 + RETENTION_FLOOR_BLOCKS, Some(7)),
            vec![(id, Eviction::Settled)]
        );
    }

    /// And the floor alone is not enough either — an unfinalised batch keeps its skeleton.
    #[test]
    fn the_floor_alone_does_not_release_an_unfinalised_batch() {
        let mut s = SkeletonStore::new();
        let id = s.insert(a_skeleton(1), 100);
        s.note_referenced(&id, 9);
        assert!(s.prune(100 + RETENTION_FLOOR_BLOCKS, Some(8)).is_empty());
        assert_eq!(s.len(), 1);
    }

    /// A skeleton referenced by several batches is free only once the last of them is final.
    #[test]
    fn the_latest_reference_is_the_one_that_matters() {
        let mut s = SkeletonStore::new();
        let id = s.insert(a_skeleton(1), 100);
        s.note_referenced(&id, 12);
        s.note_referenced(&id, 4); // an earlier batch, learned later
        assert!(s.prune(100 + RETENTION_FLOOR_BLOCKS, Some(11)).is_empty());
        assert_eq!(s.len(), 1, "seq 12 is not final yet");
    }

    /// **What you asked for.** A reorg extends retention instead of racing it.
    #[test]
    fn an_observed_reorg_pushes_the_floor_forward() {
        let mut s = SkeletonStore::new();
        let id = s.insert(a_skeleton(1), 100);
        s.note_referenced(&id, 3);

        // Almost releasable, then the chain moves under it.
        let nearly = 100 + RETENTION_FLOOR_BLOCKS - 1;
        s.observed_reorg(nearly);

        assert!(
            s.prune(100 + RETENTION_FLOOR_BLOCKS, Some(3)).is_empty(),
            "the floor must restart from the reorg, not from when it was stored"
        );
        assert_eq!(
            s.prune(nearly + RETENTION_FLOOR_BLOCKS, Some(3)),
            vec![(id, Eviction::Settled)]
        );
    }

    /// A stalled chain must not grow this store without bound — but an early eviction is reported,
    /// because every share still relying on it has just become unverifiable.
    #[test]
    fn the_ceiling_evicts_loudly_rather_than_silently() {
        let mut s = SkeletonStore::new();
        let id = s.insert(a_skeleton(1), 100);
        s.note_referenced(&id, 50);

        assert!(s.prune(100 + RETENTION_CEILING_BLOCKS - 1, None).is_empty());
        assert_eq!(
            s.prune(100 + RETENTION_CEILING_BLOCKS, None),
            vec![(id, Eviction::CeilingHit)],
            "a skeleton dropped while still needed must be distinguishable from a normal release"
        );
    }

    /// A skeleton no batch ever referenced is released on the floor alone. Holding it forever
    /// because nothing claimed it would be backwards.
    #[test]
    fn an_unreferenced_skeleton_expires_on_the_floor() {
        let mut s = SkeletonStore::new();
        let id = s.insert(a_skeleton(1), 100);
        assert_eq!(
            s.prune(100 + RETENTION_FLOOR_BLOCKS, None),
            vec![(id, Eviction::Settled)]
        );
    }

    /// Before the chain finalises anything, a referenced skeleton is held — there is nothing to
    /// say its shares are agreed.
    #[test]
    fn nothing_finalised_yet_means_nothing_released() {
        let mut s = SkeletonStore::new();
        let id = s.insert(a_skeleton(1), 100);
        s.note_referenced(&id, 1);
        assert!(s.prune(100 + RETENTION_FLOOR_BLOCKS, None).is_empty());
        assert!(s.get(&id).is_some());
    }
}

/// What the **whole fleet's** coinbase scriptSig actually costs, end to end.
///
/// The bytes are assembled by two programs that never see each other's arithmetic. `ghost-pool`
/// serves `coinbase_prefix` over the template-distribution protocol (BIP34 height, payout tag, node
/// tag); `pool_sv2`'s job factory then appends its own pool tag and the extranonce. Each side checks
/// only its own contribution against the 100-byte consensus limit, and neither one can see the
/// total.
///
/// So the total is measured here, once, against the live configuration. An over-length scriptSig is
/// not a warning — it is a block the network rejects, discovered the one time it matters.
#[cfg(test)]
mod script_sig_budget {
    use ghost_common::coinbase_tags::{
        encode_node_tag, encode_payout_tag, NODE_ID_LEN, PAYOUT_ID_LEN,
    };

    /// `pool_signature` from the live pool-config.toml, read from ghost-vm5 on 2026-08-01.
    const LIVE_POOL_SIGNATURE: &str = "- G H O S T - PublicPool";

    /// `POOL_ALLOCATION_BYTES + CLIENT_SEARCH_SPACE_BYTES` in `pool_sv2`'s channel manager.
    const FULL_EXTRANONCE: usize = 4 + 16;

    /// BIP34 height push at the current tip: `OP_PUSHBYTES_3` plus three bytes.
    const BIP34_AT_960K: usize = 4;

    fn total_script_sig(pool_signature: &str, with_payout_tag: bool) -> usize {
        // ghost-pool's half: what the template provider puts in `coinbase_prefix`.
        let payout = if with_payout_tag {
            encode_payout_tag(&[0u8; PAYOUT_ID_LEN]).len()
        } else {
            0
        };
        let node = encode_node_tag(&[0u8; NODE_ID_LEN]).len();

        // pool_sv2's half: `/pool/miner/` as one push, then the extranonce.
        let sri_tag = 1 + 1 + pool_signature.len() + 1 + 1;

        BIP34_AT_960K + payout + node + sri_tag + 1 + FULL_EXTRANONCE
    }

    /// **The live number.** 99 of 100 — one byte of headroom across the entire fleet.
    ///
    /// Nothing in either program reports this, because neither one computes it. Pinned so that
    /// lengthening `pool_signature` by a single character fails here rather than on a won block.
    #[test]
    fn the_live_configuration_has_one_byte_to_spare() {
        let total = total_script_sig(LIVE_POOL_SIGNATURE, true);
        assert_eq!(total, 99, "live scriptSig total");
        assert!(total <= 100, "over the consensus limit");
    }

    /// One more character and the fleet mines invalid blocks. This is the assertion that makes the
    /// margin real rather than a remark in a document.
    #[test]
    fn two_more_characters_would_break_consensus() {
        assert_eq!(total_script_sig("- G H O S T - PublicPool!", true), 100);
        assert!(
            total_script_sig("- G H O S T - PublicPool!!", true) > 100,
            "the very next character must be over the limit"
        );
    }

    /// The shortened tag the operator asked for (`GHOST PublicPool`) buys back eight bytes.
    #[test]
    fn the_shortened_pool_tag_restores_headroom() {
        assert_eq!(total_script_sig("GHOST PublicPool", true), 91);
    }

    /// A treasury-only coinbase carries no payout tag, so it is 21 bytes cheaper — which is why the
    /// limit has never been hit: nothing has been settleable since 2026-06-02.
    #[test]
    fn a_treasury_only_coinbase_is_far_from_the_limit() {
        assert_eq!(total_script_sig(LIVE_POOL_SIGNATURE, false), 78);
    }
}
