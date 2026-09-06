//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: beacon.rs                                                                                                     |
//|======================================================================================================================|

//! The randomness `elect_coordinators` consumes — and why it cannot be a block hash.
//!
//! `sortition::rank_of` is `H(domain ‖ beacon ‖ epoch ‖ node_id)`. Whoever
//! controls the beacon controls the draw, so the beacon is the entire security
//! of coordinator election. A miner who can choose it picks which sessions they
//! coordinate, which is the position the blind signature and the shuffle are
//! both defending.
//!
//! # Why a block hash alone fails
//!
//! A pool miner grinds the extranonce, sees the resulting rank, and discards
//! blocks that do not elect them. The cost is one block's expected value per
//! attempt and the reward is a coordinator seat — an entirely rational trade
//! for a large enough pool.
//!
//! # Commit-reveal, with an anchor, and the ordering that makes it work
//!
//! Roster members commit `H(tag ‖ node_id ‖ nonce)` first. Only *after* the
//! commit deadline is an anchor block chosen, and the beacon is the hash of
//! every revealed nonce together with that anchor.
//!
//! **The ordering is the security property**, not a detail:
//!
//! - commitments fixed before the anchor exists → a miner grinding the anchor
//!   cannot know what rank it produces for a nonce they already committed to
//! - anchor chosen after commitments → a committer cannot pick a nonce to suit
//!   a block they have already seen
//!
//! [`BeaconError::AnchorPrecedesCommitments`] refuses the combination outright
//! rather than producing a grindable beacon.
//!
//! # What this does NOT solve — read before relying on it
//!
//! **The last revealer can withhold.** Having seen every other nonce, they can
//! compute the beacon their reveal would produce, and stay silent if they
//! dislike it. They cannot *choose* an outcome — withholding forces a re-draw
//! with them excluded, one bit of influence per round, not arbitrary control —
//! but it is real bias and no amount of hashing removes it.
//!
//! The plan of record's endgame is a threshold-VRF beacon, which closes exactly
//! this, and it is **gated on an external crypto audit**. This is the sanctioned
//! interim: bounded, funds-safe, and not to be described as unbiasable.

use std::collections::BTreeMap;

use bitcoin::hashes::{sha256, Hash};

/// Domain tag for commitments. Versioned.
pub const COMMIT_TAG: &str = "wraith/beacon/commit/v1";
/// Domain tag for the beacon itself. Distinct from the commit tag so a
/// commitment can never be replayed as a beacon or vice versa.
pub const BEACON_TAG: &str = "wraith/beacon/v1";

/// Why a beacon could not be produced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BeaconError {
    /// The anchor block was known before commitments closed.
    ///
    /// The whole construction rests on commitments being fixed first. If the
    /// anchor precedes them, a committer chooses a nonce to suit a block they
    /// have already seen and the beacon is theirs.
    #[error("anchor at height {anchor_height} precedes the commit deadline at {commit_deadline} — the beacon would be grindable")]
    AnchorPrecedesCommitments {
        /// Height of the anchor block.
        anchor_height: u32,
        /// Height at which commitments closed.
        commit_deadline: u32,
    },

    /// A reveal did not match its commitment.
    #[error("node {node} revealed a nonce that does not match its commitment")]
    RevealMismatch {
        /// Hex of the offending node id.
        node: String,
    },

    /// Too few reveals to produce a beacon worth using.
    #[error("{revealed} of {committed} nodes revealed; {required} required")]
    TooFewReveals {
        /// How many revealed.
        revealed: usize,
        /// How many committed.
        committed: usize,
        /// Minimum acceptable.
        required: usize,
    },
}

/// A node's commitment to a nonce it has not yet revealed.
pub fn commitment(node_id: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(COMMIT_TAG.len() + 64);
    buf.extend_from_slice(COMMIT_TAG.as_bytes());
    buf.extend_from_slice(node_id);
    buf.extend_from_slice(nonce);
    sha256::Hash::hash(&buf).to_byte_array()
}

/// A commit-reveal round in progress.
#[derive(Debug, Clone, Default)]
pub struct BeaconRound {
    /// Commitments, keyed by node. `BTreeMap` so iteration is canonical and the
    /// beacon does not depend on arrival order.
    committed: BTreeMap<[u8; 32], [u8; 32]>,
    revealed: BTreeMap<[u8; 32], [u8; 32]>,
}

impl BeaconRound {
    /// New round.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a commitment. A node committing twice replaces its first.
    pub fn commit(&mut self, node_id: [u8; 32], commitment: [u8; 32]) {
        self.committed.insert(node_id, commitment);
    }

    /// Record a reveal, checking it against the commitment.
    pub fn reveal(&mut self, node_id: [u8; 32], nonce: [u8; 32]) -> Result<(), BeaconError> {
        match self.committed.get(&node_id) {
            Some(c) if *c == commitment(&node_id, &nonce) => {
                self.revealed.insert(node_id, nonce);
                Ok(())
            }
            _ => Err(BeaconError::RevealMismatch {
                node: hex_short(&node_id),
            }),
        }
    }

    /// How many committed.
    pub fn committed_count(&self) -> usize {
        self.committed.len()
    }

    /// How many revealed.
    pub fn revealed_count(&self) -> usize {
        self.revealed.len()
    }

    /// Nodes that committed and did not reveal.
    ///
    /// Publish this. Withholding is the one bias this construction cannot
    /// remove, so the only remaining defence is that it is visible and
    /// attributable — a node that withholds repeatedly is doing so on purpose.
    pub fn withholders(&self) -> Vec<[u8; 32]> {
        self.committed
            .keys()
            .filter(|k| !self.revealed.contains_key(*k))
            .copied()
            .collect()
    }

    /// Produce the beacon.
    ///
    /// `anchor_height` must be strictly after `commit_deadline`; see the module
    /// docs for why that ordering is the security property.
    pub fn finalise(
        &self,
        anchor_hash: &[u8; 32],
        anchor_height: u32,
        commit_deadline: u32,
        required_reveals: usize,
    ) -> Result<[u8; 32], BeaconError> {
        if anchor_height <= commit_deadline {
            return Err(BeaconError::AnchorPrecedesCommitments {
                anchor_height,
                commit_deadline,
            });
        }
        if self.revealed.len() < required_reveals {
            return Err(BeaconError::TooFewReveals {
                revealed: self.revealed.len(),
                committed: self.committed.len(),
                required: required_reveals,
            });
        }

        let mut buf = Vec::with_capacity(BEACON_TAG.len() + 32 + self.revealed.len() * 64);
        buf.extend_from_slice(BEACON_TAG.as_bytes());
        buf.extend_from_slice(anchor_hash);
        // BTreeMap iteration is ordered, so the beacon is independent of the
        // order reveals arrived in.
        for (node, nonce) in &self.revealed {
            buf.extend_from_slice(node);
            buf.extend_from_slice(nonce);
        }
        Ok(sha256::Hash::hash(&buf).to_byte_array())
    }
}

fn hex_short(b: &[u8; 32]) -> String {
    b[..4].iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(i: u8) -> [u8; 32] {
        [i; 32]
    }
    fn nonce(i: u8) -> [u8; 32] {
        [i.wrapping_add(100); 32]
    }

    fn round_of(n: u8) -> BeaconRound {
        let mut r = BeaconRound::new();
        for i in 1..=n {
            r.commit(node(i), commitment(&node(i), &nonce(i)));
        }
        for i in 1..=n {
            r.reveal(node(i), nonce(i)).expect("matches");
        }
        r
    }

    #[test]
    fn a_complete_round_produces_a_beacon() {
        let r = round_of(5);
        assert!(r.finalise(&[9u8; 32], 1_001, 1_000, 5).is_ok());
    }

    #[test]
    fn an_anchor_older_than_the_commitments_is_refused() {
        // The security property. If the anchor is already known when nodes
        // commit, a committer picks a nonce to suit it and owns the beacon.
        let r = round_of(5);
        assert_eq!(
            r.finalise(&[9u8; 32], 1_000, 1_000, 5),
            Err(BeaconError::AnchorPrecedesCommitments {
                anchor_height: 1_000,
                commit_deadline: 1_000
            })
        );
        assert!(r.finalise(&[9u8; 32], 999, 1_000, 5).is_err());
    }

    #[test]
    fn a_nonce_that_does_not_match_its_commitment_is_refused() {
        let mut r = BeaconRound::new();
        r.commit(node(1), commitment(&node(1), &nonce(1)));
        assert!(matches!(
            r.reveal(node(1), nonce(2)),
            Err(BeaconError::RevealMismatch { .. })
        ));
        assert_eq!(r.revealed_count(), 0);
    }

    #[test]
    fn a_node_cannot_reveal_without_committing() {
        let mut r = BeaconRound::new();
        assert!(r.reveal(node(1), nonce(1)).is_err());
    }

    #[test]
    fn arrival_order_does_not_change_the_beacon() {
        // Otherwise whoever controls network ordering controls the draw.
        let mut a = BeaconRound::new();
        let mut b = BeaconRound::new();
        for i in 1..=5u8 {
            a.commit(node(i), commitment(&node(i), &nonce(i)));
        }
        for i in (1..=5u8).rev() {
            b.commit(node(i), commitment(&node(i), &nonce(i)));
        }
        for i in 1..=5u8 {
            a.reveal(node(i), nonce(i)).unwrap();
        }
        for i in (1..=5u8).rev() {
            b.reveal(node(i), nonce(i)).unwrap();
        }
        assert_eq!(
            a.finalise(&[9u8; 32], 1_001, 1_000, 5).unwrap(),
            b.finalise(&[9u8; 32], 1_001, 1_000, 5).unwrap()
        );
    }

    #[test]
    fn changing_the_anchor_changes_the_beacon() {
        // The anchor has to contribute, or it is decoration.
        let r = round_of(5);
        assert_ne!(
            r.finalise(&[9u8; 32], 1_001, 1_000, 5).unwrap(),
            r.finalise(&[8u8; 32], 1_001, 1_000, 5).unwrap()
        );
    }

    #[test]
    fn one_nonce_changing_changes_the_beacon() {
        // Every contribution must matter, or a subset of the roster owns it.
        let a = round_of(5);
        let mut b = BeaconRound::new();
        for i in 1..=5u8 {
            let n = if i == 3 { [7u8; 32] } else { nonce(i) };
            b.commit(node(i), commitment(&node(i), &n));
            b.reveal(node(i), n).unwrap();
        }
        assert_ne!(
            a.finalise(&[9u8; 32], 1_001, 1_000, 5).unwrap(),
            b.finalise(&[9u8; 32], 1_001, 1_000, 5).unwrap()
        );
    }

    #[test]
    fn withholders_are_named_rather_than_silently_dropped() {
        // The bias this construction cannot remove is last-revealer withholding.
        // The only remaining defence is that it is visible and attributable.
        let mut r = BeaconRound::new();
        for i in 1..=5u8 {
            r.commit(node(i), commitment(&node(i), &nonce(i)));
        }
        for i in 1..=4u8 {
            r.reveal(node(i), nonce(i)).unwrap();
        }
        assert_eq!(r.withholders(), vec![node(5)]);
        assert_eq!(r.committed_count(), 5);
        assert_eq!(r.revealed_count(), 4);
    }

    #[test]
    fn too_few_reveals_refuses_rather_than_producing_a_thin_beacon() {
        let mut r = BeaconRound::new();
        for i in 1..=5u8 {
            r.commit(node(i), commitment(&node(i), &nonce(i)));
        }
        r.reveal(node(1), nonce(1)).unwrap();
        assert!(matches!(
            r.finalise(&[9u8; 32], 1_001, 1_000, 4),
            Err(BeaconError::TooFewReveals {
                revealed: 1,
                committed: 5,
                required: 4
            })
        ));
    }

    #[test]
    fn the_commit_tag_cannot_be_replayed_as_a_beacon() {
        // Distinct domains, so a commitment is never a valid beacon value and a
        // beacon is never a valid commitment.
        assert_ne!(COMMIT_TAG, BEACON_TAG);
        let c = commitment(&node(1), &nonce(1));
        let b = round_of(1).finalise(&[9u8; 32], 1_001, 1_000, 1).unwrap();
        assert_ne!(c, b);
    }

    #[test]
    fn the_beacon_actually_moves_the_election() {
        // End to end: this exists to feed `elect_coordinators`, and a different
        // beacon must produce a different draw or none of the above matters.
        use crate::sortition::{elect_coordinators, CoordinatorNodeId};
        let roster: Vec<CoordinatorNodeId> = (1..=20u8).map(|i| [i; 32]).collect();

        let a = round_of(5).finalise(&[9u8; 32], 1_001, 1_000, 5).unwrap();
        let b = round_of(5).finalise(&[8u8; 32], 1_001, 1_000, 5).unwrap();

        let ea = elect_coordinators(&a, 7, &roster, 4);
        let eb = elect_coordinators(&b, 7, &roster, 4);
        assert_ne!(
            ea.iter().map(|c| c.node_id).collect::<Vec<_>>(),
            eb.iter().map(|c| c.node_id).collect::<Vec<_>>(),
            "a different beacon must draw a different set"
        );
    }
}
