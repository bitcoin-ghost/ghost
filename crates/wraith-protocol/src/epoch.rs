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

use crate::sortition::{tier_leaders, CoordinatorNodeId, TierLeadership};
use crate::tier::LiteTier;

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

/// Who coordinates each denomination for one epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochCoordinators {
    pub epoch: u64,
    /// The canonical roster the draw was made from. Every node on it runs a
    /// coordinator: it may lead a tier, and it is on every tier's failover path.
    pub roster: Vec<CoordinatorNodeId>,
    /// One entry per tier, in [`LiteTier::all`] order. Empty orders when the
    /// roster is empty.
    pub tiers: Vec<TierLeadership>,
}

impl EpochCoordinators {
    /// Draw every protocol tier's leader for `epoch` from `qualified` under
    /// `beacon`. The membership is canonicalised first so the result is
    /// independent of the order the caller collected it in.
    ///
    /// The tier list is [`LiteTier::all`], not a parameter: a wallet and a node
    /// passing different lists would name different leaders, which is the same
    /// class of split this module exists to prevent.
    pub fn elect(epoch: u64, beacon: &[u8; 32], qualified: &[CoordinatorNodeId]) -> Self {
        let roster = canonical_roster(qualified);
        let tier_ids: Vec<&str> = LiteTier::all().iter().map(|t| t.id()).collect();
        Self {
            epoch,
            tiers: tier_leaders(beacon, epoch, &tier_ids, &roster),
            roster,
        }
    }

    /// The leadership for `tier_id` this epoch, or `None` for a tier the
    /// protocol does not have.
    pub fn for_tier(&self, tier_id: &str) -> Option<&TierLeadership> {
        self.tiers.iter().find(|t| t.tier_id == tier_id)
    }

    /// The node that leads `tier_id` this epoch — the same answer for a wallet
    /// and for every node, because both draw it from the same beacon and
    /// roster. `None` for an empty roster or an unknown tier.
    ///
    /// Takes no epoch: it is always `self.epoch`. An epoch parameter once let a
    /// caller pair one epoch's draw with another epoch's key and silently get a
    /// different answer.
    pub fn coordinator_for_tier(&self, tier_id: &str) -> Option<&CoordinatorNodeId> {
        self.for_tier(tier_id)?.leader()
    }

    /// Whether `node_id` runs a coordinator this epoch. Every roster node does:
    /// the ones not leading a tier are the failover path for the ones that are.
    pub fn is_coordinator(&self, node_id: &CoordinatorNodeId) -> bool {
        self.roster.contains(node_id)
    }

    /// The tiers `node_id` leads this epoch, in [`LiteTier::all`] order.
    pub fn tiers_led_by(&self, node_id: &CoordinatorNodeId) -> Vec<&str> {
        self.tiers
            .iter()
            .filter(|t| t.leader() == Some(node_id))
            .map(|t| t.tier_id.as_str())
            .collect()
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

    const TIER_IDS: [&str; 4] = ["100k_sats", "1m_sats", "10m_sats", "100m_sats"];

    #[test]
    fn elect_is_deterministic_and_membership_order_independent() {
        let q = qualified(20);
        let mut shuffled = q.clone();
        shuffled.reverse();
        let a = EpochCoordinators::elect(10, &beacon(1), &q);
        let b = EpochCoordinators::elect(10, &beacon(1), &shuffled);
        assert_eq!(
            a, b,
            "schedule must not depend on membership collection order"
        );
    }

    #[test]
    fn the_tier_list_is_the_protocols() {
        // Pinned, because a wallet and a node drawing over different lists name
        // different leaders.
        let ec = EpochCoordinators::elect(3, &beacon(2), &qualified(8));
        let ids: Vec<&str> = ec.tiers.iter().map(|t| t.tier_id.as_str()).collect();
        assert_eq!(ids, TIER_IDS);
        assert!(
            ec.coordinator_for_tier("500k_sats").is_none(),
            "no such tier"
        );
    }

    #[test]
    fn every_tier_has_its_own_leader_on_the_roster() {
        let q = qualified(15);
        let ec = EpochCoordinators::elect(3, &beacon(2), &q);
        let mut seen = std::collections::HashSet::new();
        for tier in TIER_IDS {
            let leader = *ec.coordinator_for_tier(tier).expect("every tier is led");
            assert!(ec.is_coordinator(&leader));
            assert!(seen.insert(leader), "{tier} shares a leader");
            assert_eq!(ec.tiers_led_by(&leader), vec![tier]);
        }
    }

    #[test]
    fn every_roster_node_serves_whether_or_not_it_leads() {
        // The failover path is only a path if the nodes on it are listening.
        let q = qualified(12);
        let ec = EpochCoordinators::elect(1, &beacon(9), &q);
        for id in &q {
            assert!(ec.is_coordinator(id));
        }
        let idle = q.iter().filter(|id| ec.tiers_led_by(id).is_empty()).count();
        assert_eq!(idle, q.len() - TIER_IDS.len());
        assert!(
            !ec.is_coordinator(&node(200)),
            "off the roster, never serving"
        );
    }

    /// The lead rotates with the epoch, so no node owns a denomination for ever.
    #[test]
    fn a_tier_moves_between_nodes_across_epochs() {
        let q = qualified(15);
        let hit: std::collections::HashSet<_> = (0u64..200)
            .map(|epoch| {
                *EpochCoordinators::elect(epoch, &beacon(2), &q)
                    .coordinator_for_tier("100m_sats")
                    .unwrap()
            })
            .collect();
        assert_eq!(
            hit.len(),
            q.len(),
            "every node leads the tier in some epoch"
        );
    }

    #[test]
    fn empty_roster_leads_nothing() {
        let ec = EpochCoordinators::elect(1, &beacon(1), &[]);
        assert!(ec.coordinator_for_tier("100k_sats").is_none());
        assert!(!ec.is_coordinator(&node(0)));
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
