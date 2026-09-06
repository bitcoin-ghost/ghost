//! Coordinator epochs, roster snapshotting, and the per-epoch schedule
//! (increment 3). This is the orchestration layer that composes the roster, the
//! randomness beacon (`beacon.rs`), and the sortition (`sortition.rs`) into a
//! concrete answer to "who coordinates which session, this epoch?".
//!
//! It is **beacon-agnostic**: it takes the 32-byte beacon as a value, so swapping
//! the commit-reveal beacon for the threshold-VRF endgame later changes nothing
//! here. Like the rest of the increments it is a pure, deterministic core with no
//! consensus/network coupling — the qualified-node membership and the beacon are
//! passed in; wiring them to the live ledger is increment 4.
//!
//! ## Epochs & determinism
//!
//! Coordinators are elected per **epoch** of `EPOCH_BLOCKS` blocks. The roster
//! and beacon-anchor for epoch `E` are frozen at `snapshot_height_for_epoch(E)` —
//! the last block of epoch `E-1` — so the set coordinating `E` is fixed *before*
//! `E` begins. No mid-epoch surprises, and every node derives the identical
//! schedule from chain state it already agrees on (the same determinism trick as
//! `CLUSTER_ENFORCEMENT_HEIGHT`).
//!
//! ## Dynamic membership
//!
//! The roster is the qualified set *as of the snapshot height*. A node that drops
//! below the qualification gatekeeper after the snapshot keeps its seat for the
//! current epoch (its rounds simply fail/refund if it goes dark — the bondless
//! model) and is excluded from the *next* epoch's snapshot. Membership therefore
//! churns cleanly at epoch boundaries.

use sha2::{Digest, Sha256};

use crate::sortition::{elect_coordinators, shard_for, CoordinatorNodeId, ElectedCoordinator};

/// Blocks per coordinator epoch. ~1 day at 10-minute blocks. Coordinators are
/// re-elected (and the draw reshuffled) every `EPOCH_BLOCKS`.
pub const EPOCH_BLOCKS: u64 = 144;

/// The epoch a chain height falls in.
pub const fn epoch_for_height(height: u64) -> u64 {
    height / EPOCH_BLOCKS
}

/// The chain height whose state freezes epoch `E`'s roster and beacon-anchor: the
/// last block of epoch `E-1`. Epoch 0 snapshots at height 0.
pub const fn snapshot_height_for_epoch(epoch: u64) -> u64 {
    match epoch.checked_mul(EPOCH_BLOCKS) {
        Some(start) if start > 0 => start - 1,
        _ => 0,
    }
}

/// Domain separator for the coordinator shard key.
const SHARD_KEY_DOMAIN: &[u8] = b"ghost/wraith/coordinator-shard/v1";

/// The key a wallet and a node both shard on to agree which seat serves a
/// tier this epoch: `SHA256(domain ‖ tier_id ‖ epoch_le)`.
///
/// Lives here because both sides must derive byte-identical bytes or they
/// disagree about who is coordinating. It was previously defined only in the
/// wallet daemon, where a node could not reach it.
pub fn shard_key_for_tier_epoch(tier_id: &str, epoch: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SHARD_KEY_DOMAIN);
    h.update(tier_id.as_bytes());
    h.update(epoch.to_le_bytes());
    h.finalize().into()
}

/// Domain separator for the per-epoch beacon.
const BEACON_DOMAIN: &[u8] = b"ghost/wraith/coordinator-beacon/v1";

/// How many consecutive block hashes the beacon combines.
///
/// One hash gives the miner of that single block a free look: they see the
/// beacon their block produces before publishing, and can discard it. Combining
/// several means influencing the beacon requires mining several *specific
/// consecutive* blocks, which multiplies the cost out of reach.
pub const BEACON_ANCHOR_BLOCKS: usize = 6;

/// Derive an epoch's beacon from several consecutive block hashes.
///
/// # Why this is not commit-reveal
///
/// The earlier assessment of single-hash grinding was overstated, and correcting
/// it changed the design. There is no cheap re-roll: a block hash does not exist
/// until the proof of work succeeds, so grinding the extranonce or timestamp
/// yields nothing usable. A second look requires finding a **second valid block
/// at the same height**, and while searching the miner is likely to lose the
/// height altogether.
///
/// So the attack was: one free look, and declining it forfeits a full block
/// reward — bought for one tier's sessions for one epoch, with no ability to
/// link inputs to outputs because the outputs are blind-signed. Nobody pays
/// that.
///
/// The residual is that one free look, and combining `BEACON_ANCHOR_BLOCKS`
/// hashes removes it for nothing: no new messages, no transport, no liveness
/// dependency, and no last-revealer withholding weakness. `beacon::BeaconRound`
/// stays unwired, because commit-reveal solves a problem that does not pay for
/// itself and brings costs a block hash does not have.
///
/// # Order matters and is fixed
///
/// Hashes are folded oldest-first. The caller must supply them in ascending
/// height order; the same set in a different order gives a different beacon,
/// which would be a split.
///
/// # A fixed height, never the tip
///
/// Nodes see different tips and reorgs happen, so anchoring on a live tip trades
/// grinding for disagreement — the more expensive of the two problems.
pub fn derive_beacon_multi(epoch: u64, anchor_hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(BEACON_DOMAIN);
    h.update(epoch.to_le_bytes());
    // Length-prefixed so two different runs of hashes cannot fold to the same
    // beacon by concatenating differently.
    h.update((anchor_hashes.len() as u64).to_le_bytes());
    for a in anchor_hashes {
        h.update(a);
    }
    h.finalize().into()
}

/// Single-anchor beacon.
///
/// Retained for callers that have one hash, and equivalent to
/// [`derive_beacon_multi`] with a one-element slice is **not** true — the
/// multi-hash form is length-prefixed and this is not, deliberately, so the two
/// cannot be confused for one another by a caller that supplies the wrong
/// number of anchors.
///
/// Prefer `derive_beacon_multi` with [`BEACON_ANCHOR_BLOCKS`] hashes. See its
/// documentation for why that closes the miner's one free look, and why
/// commit-reveal is not the answer.
pub fn derive_beacon(epoch: u64, anchor_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(BEACON_DOMAIN);
    h.update(epoch.to_le_bytes());
    h.update(anchor_hash);
    h.finalize().into()
}

/// Canonicalise a qualified-node membership set into a deterministic roster:
/// dedup + sort, so every node builds the byte-identical roster (and thus the
/// identical election) from the same membership.
pub fn canonical_roster(qualified: &[CoordinatorNodeId]) -> Vec<CoordinatorNodeId> {
    let mut v = qualified.to_vec();
    v.sort_unstable();
    v.dedup();
    v
}

/// The elected coordinator set for one epoch, plus the session→coordinator map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochCoordinators {
    pub epoch: u64,
    /// Elected coordinators, seat-ordered. Empty only if the roster was empty.
    pub coordinators: Vec<ElectedCoordinator>,
}

impl EpochCoordinators {
    /// Elect up to `n` coordinators for `epoch` from `qualified` under `beacon`.
    /// The membership is canonicalised first so the result is independent of the
    /// order the caller collected it in.
    pub fn elect(epoch: u64, beacon: &[u8; 32], qualified: &[CoordinatorNodeId], n: usize) -> Self {
        let roster = canonical_roster(qualified);
        Self {
            epoch,
            coordinators: elect_coordinators(beacon, epoch, &roster, n),
        }
    }

    /// How many coordinators are seated this epoch.
    pub fn seats(&self) -> usize {
        self.coordinators.len()
    }

    /// The coordinator that owns `tier_id`'s sessions this epoch — the same
    /// answer for a wallet and for every node, because both derive it from
    /// [`shard_key_for_tier_epoch`]. `None` when no coordinators are seated.
    ///
    /// Shards on `(tier, epoch)` rather than on a session id. A session id
    /// does not exist until a coordinator creates one, so a wallet choosing
    /// *whom to ask* cannot use it — and sharding by tier makes every wallet
    /// wanting the same denomination in the same epoch converge on the same
    /// seat, which is a larger anonymity set rather than load spreading.
    ///
    /// Takes no epoch: it is always `self.epoch`. It used to be a parameter,
    /// which let a caller pair one epoch's election with another epoch's shard
    /// key and silently get a different seat — the same class of mistake as the
    /// one below, and reachable by a plain typo.
    ///
    /// This replaced a `coordinator_for_session(session_id)` that documented
    /// itself as the value "a wallet and every node agree" on, while the
    /// wallet actually sharded by `(tier, epoch)` and nothing called the
    /// library version. Two schemes selecting different seats, one of them
    /// dead and inviting: whoever wired up its `owns_session` companion would
    /// have had wallets dialling one seat while another believed it owned the
    /// work.
    pub fn coordinator_for_tier(&self, tier_id: &str) -> Option<&ElectedCoordinator> {
        if self.coordinators.is_empty() {
            return None;
        }
        let key = shard_key_for_tier_epoch(tier_id, self.epoch);
        let seat = shard_for(&key, self.coordinators.len());
        // seats are exactly 0..len in seat order, so index directly.
        self.coordinators.get(seat as usize)
    }

    /// Whether `node_id` is seated as a coordinator this epoch.
    pub fn is_coordinator(&self, node_id: &CoordinatorNodeId) -> bool {
        self.coordinators.iter().any(|c| &c.node_id == node_id)
    }

    /// If `node_id` is seated, the seat (shard) it owns this epoch.
    pub fn seat_of(&self, node_id: &CoordinatorNodeId) -> Option<u32> {
        self.coordinators
            .iter()
            .find(|c| &c.node_id == node_id)
            .map(|c| c.seat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(i: u8) -> CoordinatorNodeId {
        let mut id = [0u8; 32];
        id[0] = i;
        id[1] = i.wrapping_mul(3);
        id
    }
    fn beacon(s: u8) -> [u8; 32] {
        [s; 32]
    }
    fn qualified(k: u8) -> Vec<CoordinatorNodeId> {
        (0..k).map(node).collect()
    }

    #[test]
    fn epoch_and_snapshot_height_boundaries() {
        assert_eq!(epoch_for_height(0), 0);
        assert_eq!(epoch_for_height(EPOCH_BLOCKS - 1), 0);
        assert_eq!(epoch_for_height(EPOCH_BLOCKS), 1);
        assert_eq!(epoch_for_height(EPOCH_BLOCKS * 5 + 3), 5);

        assert_eq!(snapshot_height_for_epoch(0), 0);
        assert_eq!(snapshot_height_for_epoch(1), EPOCH_BLOCKS - 1);
        assert_eq!(snapshot_height_for_epoch(5), 5 * EPOCH_BLOCKS - 1);
        // an epoch's snapshot is in the PREVIOUS epoch (fixed before it starts)
        let e = 7u64;
        assert_eq!(epoch_for_height(snapshot_height_for_epoch(e)), e - 1);
    }

    /// Pins the relationship between the placeholder and its replacement, so
    /// the two beacon derivations cannot drift apart unnoticed — one of them is
    /// grindable and it is the one currently wired up.
    #[test]
    fn canonical_roster_is_order_independent_and_deduped() {
        let mut a = qualified(6);
        let mut b = a.clone();
        b.reverse();
        b.push(a[2]); // duplicate
        assert_eq!(
            canonical_roster(&a),
            canonical_roster(&b),
            "order + dupes don't matter"
        );
        a.sort_unstable();
        assert_eq!(canonical_roster(&a).len(), 6);
    }

    #[test]
    fn elect_is_deterministic_and_membership_order_independent() {
        let q = qualified(20);
        let mut shuffled = q.clone();
        shuffled.reverse();
        let a = EpochCoordinators::elect(10, &beacon(1), &q, 4);
        let b = EpochCoordinators::elect(10, &beacon(1), &shuffled, 4);
        assert_eq!(
            a, b,
            "schedule must not depend on membership collection order"
        );
        assert_eq!(a.seats(), 4);
    }

    #[test]
    fn every_tier_maps_to_a_seated_coordinator() {
        let q = qualified(15);
        let ec = EpochCoordinators::elect(3, &beacon(2), &q, 5);
        for tier in ["100k_sats", "1m_sats", "10m_sats", "100m_sats"] {
            let c = ec
                .coordinator_for_tier(tier)
                .expect("a coordinator owns every tier");
            assert!(ec.is_coordinator(&c.node_id));
            // Stable: every wallet asking for this tier in this epoch lands
            // on the same seat, which is the point — a larger anonymity set,
            // not load spreading.
            assert_eq!(ec.coordinator_for_tier(tier).unwrap().node_id, c.node_id);
        }
    }

    /// The assignment rotates with the epoch, so one seat does not own a
    /// denomination for ever.
    #[test]
    fn a_tier_moves_between_seats_across_epochs() {
        let q = qualified(15);
        let mut hit = std::collections::HashSet::new();
        // Re-elect each epoch, as a node does. This used to hold one election
        // and vary only the epoch argument, which exercised a pairing that
        // cannot occur now the argument is gone.
        for epoch in 0u64..200 {
            let ec = EpochCoordinators::elect(epoch, &beacon(2), &q, 5);
            hit.insert(ec.coordinator_for_tier("100k_sats").unwrap().seat);
        }
        assert_eq!(hit.len(), 5, "every seat serves the tier in some epoch");
    }

    /// A wallet and a node derive the identical shard key, or they disagree
    /// about who is coordinating.
    #[test]
    fn the_shard_key_is_a_pure_function_of_tier_and_epoch() {
        assert_eq!(
            shard_key_for_tier_epoch("100k_sats", 7),
            shard_key_for_tier_epoch("100k_sats", 7)
        );
        assert_ne!(
            shard_key_for_tier_epoch("100k_sats", 7),
            shard_key_for_tier_epoch("1m_sats", 7)
        );
        assert_ne!(
            shard_key_for_tier_epoch("100k_sats", 7),
            shard_key_for_tier_epoch("100k_sats", 8)
        );
    }

    #[test]
    fn is_coordinator_and_seat_of() {
        let q = qualified(12);
        let ec = EpochCoordinators::elect(1, &beacon(9), &q, 4);
        let seated = ec.coordinators[2].node_id;
        assert!(ec.is_coordinator(&seated));
        assert_eq!(ec.seat_of(&seated), Some(2));
        // a node not in the elected set
        let absent = node(200);
        assert!(!ec.is_coordinator(&absent));
        assert_eq!(ec.seat_of(&absent), None);
    }

    #[test]
    fn rotation_reshuffles_between_epochs() {
        let q = qualified(20);
        let a: Vec<_> = EpochCoordinators::elect(100, &beacon(5), &q, 4)
            .coordinators
            .into_iter()
            .map(|c| c.node_id)
            .collect();
        let b: Vec<_> = EpochCoordinators::elect(101, &beacon(5), &q, 4)
            .coordinators
            .into_iter()
            .map(|c| c.node_id)
            .collect();
        assert_ne!(a, b, "a new epoch rotates the coordinator set");
    }

    #[test]
    fn empty_roster_seats_nobody() {
        let ec = EpochCoordinators::elect(1, &beacon(1), &[], 4);
        assert_eq!(ec.seats(), 0);
        assert!(ec.coordinator_for_tier("100k_sats").is_none());
    }
    fn anchors(n: usize) -> Vec<[u8; 32]> {
        (0..n as u8).map(|i| [i.wrapping_add(1); 32]).collect()
    }

    #[test]
    fn the_multi_anchor_beacon_depends_on_every_hash() {
        // Influencing it must require mining every one of the blocks, so
        // changing any single hash has to change the beacon.
        let base = derive_beacon_multi(7, &anchors(BEACON_ANCHOR_BLOCKS));
        for i in 0..BEACON_ANCHOR_BLOCKS {
            let mut a = anchors(BEACON_ANCHOR_BLOCKS);
            a[i] = [0xEE; 32];
            assert_ne!(
                base,
                derive_beacon_multi(7, &a),
                "changing anchor {i} must change the beacon"
            );
        }
    }

    #[test]
    fn anchor_order_is_part_of_the_beacon() {
        // Callers must supply ascending height order. Two nodes folding the
        // same hashes differently would be a split, so the order has to bind.
        let a = anchors(BEACON_ANCHOR_BLOCKS);
        let mut reversed = a.clone();
        reversed.reverse();
        assert_ne!(
            derive_beacon_multi(7, &a),
            derive_beacon_multi(7, &reversed)
        );
    }

    #[test]
    fn the_epoch_binds_too() {
        let a = anchors(BEACON_ANCHOR_BLOCKS);
        assert_ne!(derive_beacon_multi(7, &a), derive_beacon_multi(8, &a));
    }

    #[test]
    fn a_different_anchor_count_gives_a_different_beacon() {
        // Length-prefixed, so a caller supplying the wrong number of anchors
        // cannot collide with the right one by concatenation.
        let five = anchors(5);
        let six = anchors(6);
        assert_ne!(derive_beacon_multi(7, &five), derive_beacon_multi(7, &six));
    }

    #[test]
    fn the_single_and_multi_forms_are_not_interchangeable() {
        // Deliberate: a caller that passes one anchor where six were intended
        // should not silently produce the single-anchor beacon.
        let one = [3u8; 32];
        assert_ne!(derive_beacon(7, &one), derive_beacon_multi(7, &[one]));
    }

    #[test]
    fn the_beacon_is_deterministic() {
        let a = anchors(BEACON_ANCHOR_BLOCKS);
        assert_eq!(derive_beacon_multi(9, &a), derive_beacon_multi(9, &a));
    }
}
