//! Per-epoch randomness beacon for coordinator election (increment 2).
//!
//! The sortition core (`sortition.rs`) is correct for *any* 32-byte beacon; this
//! module produces that beacon so that **no single party can bias which nodes get
//! elected**. It is the security-critical half of the design — the place where
//! "random and unriggable" is actually won or lost — so the construction and its
//! residual weaknesses are documented in full.
//!
//! ## Construction: commit-reveal, anchored to the chain
//!
//! For epoch `E`, each participating qualified node:
//!
//! 1. **Commit window.** Picks a secret 32-byte `r_i` and publishes
//!    `c_i = H(DOMAIN_COMMIT ‖ E ‖ node_id ‖ r_i)`. The commitment hides `r_i`
//!    and *binds* the node to it.
//! 2. **Reveal window.** Publishes `r_i`. A reveal counts only if it matches the
//!    earlier commitment (`reveal_is_valid`), so a node cannot change its value
//!    after seeing anyone else's.
//!
//! The beacon is then
//! `B(E) = H(DOMAIN_BEACON ‖ E ‖ anchor ‖ sorted(valid r_i))`, where `anchor`
//! is an independent unpredictable value the network already agrees on — a recent
//! block hash. Reveals are sorted, so submission order does not matter and every
//! node computes the identical `B`.
//!
//! ## What this gives (threat analysis)
//!
//! - **Unbiasable with ≥1 honest contributor.** Because each `r_i` is committed
//!   before any reveal is seen and hashed together, the output is unpredictable
//!   to anyone who does not control *every* contributor. A single honest, secret
//!   `r_i` makes `B` unpredictable and unbiasable by all the others. (Standard
//!   RANDAO property.)
//! - **Binding.** A node cannot grind its `r_i` after the fact — the reveal must
//!   open its commitment.
//! - **Miner-grinding resistance.** A pool miner who could grind a block hash to
//!   bias the draw still has to defeat the commit-reveal honest contributor; and
//!   a commit-reveal manipulator still has to defeat the chain `anchor`. The two
//!   inputs cover each other's weakness, so an attacker must break *both*.
//!
//! ## Residual weakness (do not hand-wave)
//!
//! - **Last-revealer withholding.** A malicious node that reveals last has seen
//!   the others and may choose to reveal or withhold — a 1-bit nudge to `B` per
//!   withholder (`W` withholders ⇒ at most `2^W` candidate beacons it can grind
//!   across by selectively withholding). This is the known RANDAO bias and is
//!   *bounded*, not eliminated. It is mitigated here by (a) the chain `anchor`
//!   (a withholder must also control the block hash) and (b) the caller excluding
//!   "committed-but-did-not-reveal" nodes from the *next* epoch's eligibility
//!   (withholding is publicly detectable). Fully removing it needs a **VDF** over
//!   the reveal output (so the withholder cannot compute the consequence of
//!   withholding before the window closes) — that is the increment-2b upgrade,
//!   deliberately out of scope here.
//!
//! For coordinator election a biased beacon lets an attacker coordinate *more*
//! rounds (a privacy degradation bounded by the attacker's share of the qualified
//! set), not steal funds — so a bounded-bias beacon with a clear VDF upgrade path
//! is an acceptable v1. This module is the pure, tested core; wiring the commit
//! and reveal windows into consensus is a later increment.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::sortition::CoordinatorNodeId;

const DOMAIN_COMMIT: &[u8] = b"ghost/wraith/coordinator-beacon/commit/v1";
const DOMAIN_BEACON: &[u8] = b"ghost/wraith/coordinator-beacon/output/v1";

/// A node's commitment for an epoch: `H(DOMAIN_COMMIT ‖ epoch ‖ node_id ‖ r)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    pub node_id: CoordinatorNodeId,
    pub commit: [u8; 32],
}

/// A node's reveal for an epoch: the secret `r` whose commitment it published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reveal {
    pub node_id: CoordinatorNodeId,
    pub r: [u8; 32],
}

/// Outcome of folding a round's commitments + reveals into a beacon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeaconRound {
    /// The 32-byte beacon for the epoch — feed straight into
    /// [`crate::sortition::elect_coordinators`].
    pub beacon: [u8; 32],
    /// Node ids whose reveal validly opened their commitment and contributed.
    pub contributors: Vec<CoordinatorNodeId>,
    /// Node ids that committed but failed to reveal (or revealed a non-matching
    /// value). The caller should exclude these from the next epoch's eligibility
    /// — withholding is the residual bias vector and is publicly attributable.
    pub withholders: Vec<CoordinatorNodeId>,
}

/// The commitment a node must publish for `(epoch, node_id, r)`.
pub fn commit_for(epoch: u64, node_id: &CoordinatorNodeId, r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_COMMIT);
    h.update(epoch.to_le_bytes());
    h.update(node_id);
    h.update(r);
    h.finalize().into()
}

/// True iff `r` opens `commit` for `(epoch, node_id)`.
pub fn reveal_is_valid(
    epoch: u64,
    node_id: &CoordinatorNodeId,
    r: &[u8; 32],
    commit: &[u8; 32],
) -> bool {
    // Constant-time-ish compare is unnecessary (commitments are public); a plain
    // equality is fine and clearer.
    &commit_for(epoch, node_id, r) == commit
}

/// Compute the beacon directly from a set of *already-validated* reveals plus the
/// chain `anchor`. Reveals are folded in sorted node_id order, so the result is
/// independent of submission order. Used when the caller has its own validation.
pub fn compute_beacon(epoch: u64, anchor: &[u8; 32], valid_reveals: &[Reveal]) -> [u8; 32] {
    // Sort by node_id for a canonical, order-independent fold; dedup defensively.
    let mut sorted: BTreeMap<CoordinatorNodeId, [u8; 32]> = BTreeMap::new();
    for rv in valid_reveals {
        sorted.entry(rv.node_id).or_insert(rv.r);
    }
    let mut h = Sha256::new();
    h.update(DOMAIN_BEACON);
    h.update(epoch.to_le_bytes());
    h.update(anchor);
    for (node_id, r) in &sorted {
        h.update(node_id);
        h.update(r);
    }
    h.finalize().into()
}

/// Validate a round's `reveals` against its `commitments`, then compute the
/// beacon from the openings that check out. A commitment with no valid reveal is
/// recorded as a withholder. Reveals without a matching commitment are ignored
/// (a node cannot contribute without having committed).
pub fn beacon_from_round(
    epoch: u64,
    anchor: &[u8; 32],
    commitments: &[Commitment],
    reveals: &[Reveal],
) -> BeaconRound {
    // First commitment per node wins (a node commits once per epoch).
    let mut commit_by_node: BTreeMap<CoordinatorNodeId, [u8; 32]> = BTreeMap::new();
    for c in commitments {
        commit_by_node.entry(c.node_id).or_insert(c.commit);
    }
    // First valid reveal per node wins.
    let mut reveal_by_node: BTreeMap<CoordinatorNodeId, [u8; 32]> = BTreeMap::new();
    for rv in reveals {
        if let Some(commit) = commit_by_node.get(&rv.node_id) {
            if reveal_is_valid(epoch, &rv.node_id, &rv.r, commit) {
                reveal_by_node.entry(rv.node_id).or_insert(rv.r);
            }
        }
    }

    let valid: Vec<Reveal> = reveal_by_node
        .iter()
        .map(|(node_id, r)| Reveal {
            node_id: *node_id,
            r: *r,
        })
        .collect();
    let contributors: Vec<CoordinatorNodeId> = reveal_by_node.keys().copied().collect();
    let withholders: Vec<CoordinatorNodeId> = commit_by_node
        .keys()
        .filter(|id| !reveal_by_node.contains_key(*id))
        .copied()
        .collect();

    BeaconRound {
        beacon: compute_beacon(epoch, anchor, &valid),
        contributors,
        withholders,
    }
}

/// Stateful accumulator for one epoch's beacon round. A node holds one of these
/// during the commit/reveal windows for the epoch being prepared, ingesting
/// commit and reveal messages as they arrive over the mesh, then finalises the
/// beacon once the reveal window closes. It is the live counterpart to the
/// one-shot [`beacon_from_round`] — same validation rules, fed incrementally.
///
/// Validation is enforced on ingest: a node commits at most once, and a reveal
/// is accepted only if the node committed and the reveal opens that commitment.
/// So `finalize` always reflects a clean round, and "committed but never revealed"
/// nodes surface as `withholders`.
#[derive(Debug, Clone)]
pub struct BeaconRoundState {
    epoch: u64,
    commitments: BTreeMap<CoordinatorNodeId, [u8; 32]>,
    reveals: BTreeMap<CoordinatorNodeId, [u8; 32]>,
}

impl BeaconRoundState {
    /// A fresh round for `epoch`.
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            commitments: BTreeMap::new(),
            reveals: BTreeMap::new(),
        }
    }

    /// The epoch this round is preparing.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Record a node's commitment. First commitment per node wins (a node commits
    /// once per epoch); a second/conflicting commitment from the same node is
    /// rejected. Returns whether it was accepted.
    pub fn add_commitment(&mut self, node_id: CoordinatorNodeId, commit: [u8; 32]) -> bool {
        if self.commitments.contains_key(&node_id) {
            return false;
        }
        self.commitments.insert(node_id, commit);
        true
    }

    /// Record a reveal. Accepted only if the node committed, `r` opens that
    /// commitment, and it hasn't already revealed. Returns whether it was accepted.
    pub fn add_reveal(&mut self, node_id: CoordinatorNodeId, r: [u8; 32]) -> bool {
        if self.reveals.contains_key(&node_id) {
            return false;
        }
        match self.commitments.get(&node_id) {
            Some(commit) if reveal_is_valid(self.epoch, &node_id, &r, commit) => {
                self.reveals.insert(node_id, r);
                true
            }
            _ => false,
        }
    }

    /// How many nodes have committed.
    pub fn committed_count(&self) -> usize {
        self.commitments.len()
    }

    /// How many nodes have validly revealed (these are the beacon's contributors).
    pub fn revealed_count(&self) -> usize {
        self.reveals.len()
    }

    /// True once at least one valid reveal exists — the point past which the
    /// beacon is unbiasable by any party that doesn't control that contributor.
    pub fn has_contributors(&self) -> bool {
        !self.reveals.is_empty()
    }

    /// Finalise the beacon for this epoch with the chain `anchor`, yielding the
    /// beacon plus the contributor and withholder lists.
    pub fn finalize(&self, anchor: &[u8; 32]) -> BeaconRound {
        let valid: Vec<Reveal> = self
            .reveals
            .iter()
            .map(|(node_id, r)| Reveal {
                node_id: *node_id,
                r: *r,
            })
            .collect();
        let contributors: Vec<CoordinatorNodeId> = self.reveals.keys().copied().collect();
        let withholders: Vec<CoordinatorNodeId> = self
            .commitments
            .keys()
            .filter(|id| !self.reveals.contains_key(*id))
            .copied()
            .collect();
        BeaconRound {
            beacon: compute_beacon(self.epoch, anchor, &valid),
            contributors,
            withholders,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(i: u8) -> CoordinatorNodeId {
        let mut id = [0u8; 32];
        id[0] = i;
        id
    }
    fn secret(i: u8) -> [u8; 32] {
        [i.wrapping_mul(13).wrapping_add(1); 32]
    }
    fn anchor(i: u8) -> [u8; 32] {
        [i; 32]
    }

    fn round(epoch: u64, n: u8) -> (Vec<Commitment>, Vec<Reveal>) {
        let commits = (0..n)
            .map(|i| Commitment {
                node_id: node(i),
                commit: commit_for(epoch, &node(i), &secret(i)),
            })
            .collect();
        let reveals = (0..n)
            .map(|i| Reveal {
                node_id: node(i),
                r: secret(i),
            })
            .collect();
        (commits, reveals)
    }

    #[test]
    fn binding_reveal_must_open_commitment() {
        let e = 5u64;
        let c = commit_for(e, &node(1), &secret(1));
        assert!(reveal_is_valid(e, &node(1), &secret(1), &c));
        // wrong secret
        assert!(!reveal_is_valid(e, &node(1), &secret(2), &c));
        // wrong node
        assert!(!reveal_is_valid(e, &node(2), &secret(1), &c));
        // wrong epoch
        assert!(!reveal_is_valid(e + 1, &node(1), &secret(1), &c));
    }

    #[test]
    fn determinism_and_order_independence() {
        let e = 9u64;
        let (commits, mut reveals) = round(e, 6);
        let a = beacon_from_round(e, &anchor(3), &commits, &reveals);
        reveals.reverse(); // submission order changed
        let b = beacon_from_round(e, &anchor(3), &commits, &reveals);
        assert_eq!(a.beacon, b.beacon, "beacon must not depend on reveal order");
        assert_eq!(a.contributors.len(), 6);
        assert!(a.withholders.is_empty());
    }

    #[test]
    fn one_honest_reveal_changes_the_beacon() {
        // Flipping a single contributor's secret yields a different (unpredictable)
        // beacon — i.e. one honest, secret r_i is enough to move the output, so
        // the others cannot fix it without knowing that r_i in advance.
        let e = 11u64;
        let (mut commits, mut reveals) = round(e, 5);
        let base = beacon_from_round(e, &anchor(1), &commits, &reveals).beacon;
        // node 4 chooses a different secret (recommit + reveal accordingly)
        let new_secret = [0xAB; 32];
        commits[4].commit = commit_for(e, &node(4), &new_secret);
        reveals[4].r = new_secret;
        let moved = beacon_from_round(e, &anchor(1), &commits, &reveals).beacon;
        assert_ne!(
            base, moved,
            "a single honest contributor must move the beacon"
        );
    }

    #[test]
    fn anchor_is_folded_in() {
        // Same commit-reveal set, different chain anchor → different beacon, so a
        // commit-reveal-only manipulation still has to beat the anchor.
        let e = 2u64;
        let (commits, reveals) = round(e, 4);
        let a = beacon_from_round(e, &anchor(7), &commits, &reveals).beacon;
        let b = beacon_from_round(e, &anchor(8), &commits, &reveals).beacon;
        assert_ne!(a, b, "anchor must affect the beacon");
    }

    #[test]
    fn withholder_is_detected_and_excluded() {
        let e = 4u64;
        let (commits, mut reveals) = round(e, 5);
        // node 2 commits but withholds its reveal
        reveals.retain(|rv| rv.node_id != node(2));
        let out = beacon_from_round(e, &anchor(0), &commits, &reveals);
        assert!(out.contributors.contains(&node(0)));
        assert!(!out.contributors.contains(&node(2)));
        assert_eq!(out.withholders, vec![node(2)], "withholder attributed");
    }

    #[test]
    fn withholding_influence_is_bounded_to_include_or_exclude() {
        // Documents the residual bias: a last-revealer's only lever is the 1-bit
        // include/exclude choice. Including vs excluding its (valid) reveal gives
        // exactly two possible beacons — bounded, not arbitrary grinding.
        let e = 8u64;
        let (commits, reveals) = round(e, 5);
        let with = beacon_from_round(e, &anchor(2), &commits, &reveals).beacon;
        let without_reveals: Vec<Reveal> = reveals
            .iter()
            .filter(|rv| rv.node_id != node(4))
            .cloned()
            .collect();
        let without = beacon_from_round(e, &anchor(2), &commits, &without_reveals).beacon;
        assert_ne!(with, without, "include/exclude are two distinct outcomes");
        // …but that's the ONLY freedom: re-revealing the same value reproduces `with`.
        let again = beacon_from_round(e, &anchor(2), &commits, &reveals).beacon;
        assert_eq!(
            with, again,
            "a committed node cannot pick among many values"
        );
    }

    #[test]
    fn reveal_without_commitment_is_ignored() {
        let e = 6u64;
        let (mut commits, mut reveals) = round(e, 3);
        // an attacker injects a reveal for a node that never committed
        commits.retain(|c| c.node_id != node(2));
        let out = beacon_from_round(e, &anchor(5), &commits, &reveals);
        assert!(
            !out.contributors.contains(&node(2)),
            "uncommitted reveal ignored"
        );
        // and the beacon equals the one computed from only the committed pair set
        reveals.retain(|rv| rv.node_id != node(2));
        let only_committed = compute_beacon(e, &anchor(5), &reveals);
        assert_eq!(out.beacon, only_committed);
    }

    #[test]
    fn empty_and_single_contributor() {
        let e = 1u64;
        // empty: still a well-defined beacon (anchor-only) — caller decides if an
        // empty contributor set is acceptable for liveness.
        let empty = beacon_from_round(e, &anchor(1), &[], &[]);
        assert!(empty.contributors.is_empty());
        // single contributor: valid, deterministic
        let (c, r) = round(e, 1);
        let one = beacon_from_round(e, &anchor(1), &c, &r);
        assert_eq!(one.contributors, vec![node(0)]);
        assert_ne!(one.beacon, empty.beacon);
    }

    // ── BeaconRoundState (stateful accumulator) ──────────────────────────────

    #[test]
    fn round_state_commit_then_reveal_rules() {
        let e = 5u64;
        let mut st = BeaconRoundState::new(e);
        let (n0, r0) = (node(0), secret(0));
        let c0 = commit_for(e, &n0, &r0);

        // commit accepted once
        assert!(st.add_commitment(n0, c0));
        assert!(
            !st.add_commitment(n0, c0),
            "no second commitment from a node"
        );
        assert_eq!(st.committed_count(), 1);

        // reveal must open the commitment
        assert!(!st.add_reveal(n0, secret(9)), "wrong secret rejected");
        assert!(st.add_reveal(n0, r0), "correct secret accepted");
        assert!(!st.add_reveal(n0, r0), "no double reveal");
        assert_eq!(st.revealed_count(), 1);
        assert!(st.has_contributors());

        // a reveal with no commitment is rejected
        assert!(!st.add_reveal(node(1), secret(1)));
    }

    #[test]
    fn round_state_finalize_matches_one_shot() {
        // The stateful path must produce the byte-identical beacon to the one-shot
        // beacon_from_round for the same valid round.
        let e = 9u64;
        let (commits, reveals) = round(e, 6);
        let anchor = anchor(4);

        let mut st = BeaconRoundState::new(e);
        for c in &commits {
            assert!(st.add_commitment(c.node_id, c.commit));
        }
        for rv in &reveals {
            assert!(st.add_reveal(rv.node_id, rv.r));
        }
        let stateful = st.finalize(&anchor);
        let one_shot = beacon_from_round(e, &anchor, &commits, &reveals);
        assert_eq!(stateful.beacon, one_shot.beacon);
        assert_eq!(stateful.contributors, one_shot.contributors);
        assert_eq!(stateful.withholders, one_shot.withholders);
    }

    #[test]
    fn round_state_ingest_order_independent() {
        let e = 3u64;
        let (commits, reveals) = round(e, 5);
        let anchor = anchor(2);

        let mut a = BeaconRoundState::new(e);
        for c in &commits {
            a.add_commitment(c.node_id, c.commit);
        }
        for rv in &reveals {
            a.add_reveal(rv.node_id, rv.r);
        }

        // feed the second one in reverse order
        let mut b = BeaconRoundState::new(e);
        for c in commits.iter().rev() {
            b.add_commitment(c.node_id, c.commit);
        }
        for rv in reveals.iter().rev() {
            b.add_reveal(rv.node_id, rv.r);
        }
        assert_eq!(a.finalize(&anchor).beacon, b.finalize(&anchor).beacon);
    }

    #[test]
    fn round_state_tracks_withholders() {
        let e = 4u64;
        let mut st = BeaconRoundState::new(e);
        for i in 0u8..5 {
            st.add_commitment(node(i), commit_for(e, &node(i), &secret(i)));
        }
        // everyone reveals except node 2
        for i in [0u8, 1, 3, 4] {
            assert!(st.add_reveal(node(i), secret(i)));
        }
        let out = st.finalize(&anchor(0));
        assert_eq!(out.contributors.len(), 4);
        assert_eq!(out.withholders, vec![node(2)]);
    }
}
