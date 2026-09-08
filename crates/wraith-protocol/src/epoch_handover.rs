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
//| FILE: epoch_handover.rs                                                                                               |
//|======================================================================================================================|

//! What happens to a session that is still signing when the epoch rotates.
//!
//! `shard_key_for_tier_epoch` mixes the epoch in, so at every rotation a tier's
//! sessions map to a *different* seat. Meanwhile `service::owns_tier` asks "is
//! this tier mine **this epoch**". Put those together and a coordinator holding
//! a `Locked` session — participants committed, partial signatures collected —
//! answers `false` the instant the epoch turns, while wallets computing the new
//! epoch's shard dial somebody else.
//!
//! Nobody is wrong. Each side follows the rule it was given. The session simply
//! stops having an owner, with participants' inputs already committed to it.
//!
//! # A session belongs to the epoch it opened in
//!
//! [`SessionEpoch`] carries the opening epoch, and [`owns_session`] answers from
//! *that* rather than from the current one. Ownership then never moves under a
//! live session, and rotation becomes uneventful for work already in flight.
//!
//! This needs no timing assumption, which is the point — see below.
//!
//! # The cutoff is a heuristic and cannot be otherwise
//!
//! [`OPEN_CUTOFF_BLOCKS`] additionally stops a coordinator opening a session it
//! probably cannot finish before rotating. It is defence in depth, and it is
//! **not** a guarantee: Bitcoin block times are a Poisson process, so the wall
//! time in any given block count is unpredictable — two blocks can arrive in
//! twenty seconds. No block count makes the deadline safe.
//!
//! So the cutoff reduces how often a session straddles a boundary, and
//! [`owns_session`] is what makes straddling harmless when it happens anyway.
//! Correctness rests on the binding; the cutoff only buys tidiness.

use crate::epoch::{epoch_for_height, EpochCoordinators, EPOCH_BLOCKS};
use crate::sortition::CoordinatorNodeId;

/// How close to a rotation a coordinator will still open a new session.
///
/// Two blocks is roughly twenty expected minutes against a 300-second fill
/// window, leaving room to fill, sign and broadcast. "Expected" is doing real
/// work in that sentence — see the module note. Correctness does not depend on
/// this number being right.
pub const OPEN_CUTOFF_BLOCKS: u64 = 2;

/// A session, bound to the epoch it opened in.
///
/// Constructed from the height at open time so the binding cannot be set to
/// something other than where the session actually started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionEpoch {
    /// The epoch the session opened in. Ownership is answered from this.
    pub opened_in: u64,
    /// The height it opened at, retained for diagnosis.
    pub opened_at_height: u64,
}

impl SessionEpoch {
    /// Bind a session opening at `height`.
    pub fn at_height(height: u64) -> Self {
        Self {
            opened_in: epoch_for_height(height),
            opened_at_height: height,
        }
    }

    /// Blocks remaining until this session's epoch rotates.
    pub fn blocks_until_rotation(&self, current_height: u64) -> u64 {
        let end = (self.opened_in + 1) * EPOCH_BLOCKS;
        end.saturating_sub(current_height)
    }

    /// Whether the epoch this session opened in has since rotated.
    pub fn has_rotated(&self, current_height: u64) -> bool {
        epoch_for_height(current_height) > self.opened_in
    }
}

/// Why a session should not be opened now.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OpenRefusal {
    /// Too close to rotation to expect to finish.
    #[error("only {remaining} blocks until epoch {epoch} rotates; {required} required to open")]
    TooCloseToRotation {
        /// The epoch about to end.
        epoch: u64,
        /// Blocks left in it.
        remaining: u64,
        /// The cutoff.
        required: u64,
    },
    /// This node does not own the tier in the epoch the session would open in.
    #[error("node does not own tier '{tier_id}' in epoch {epoch}")]
    NotOurTier {
        /// The tier asked for.
        tier_id: String,
        /// The epoch it would open in.
        epoch: u64,
    },
}

/// Whether `self_id` owns `session` — answered from the session's **opening**
/// epoch, not the current one.
///
/// `coords` must be the election for `session.opened_in`; a caller holding only
/// the current epoch's election cannot answer this, which is deliberate. The
/// mismatch is reported rather than guessed at, because silently answering from
/// the wrong epoch is exactly the bug this module exists to prevent.
pub fn owns_session(
    coords: &EpochCoordinators,
    self_id: &CoordinatorNodeId,
    tier_id: &str,
    session: &SessionEpoch,
) -> Option<bool> {
    if coords.epoch != session.opened_in {
        return None;
    }
    Some(coords.coordinator_for_tier(tier_id).map(|c| c.node_id) == Some(*self_id))
}

/// Whether to open a new session for `tier_id` at `current_height`.
pub fn check_open(
    coords: &EpochCoordinators,
    self_id: &CoordinatorNodeId,
    tier_id: &str,
    current_height: u64,
) -> Result<SessionEpoch, OpenRefusal> {
    let binding = SessionEpoch::at_height(current_height);

    if owns_session(coords, self_id, tier_id, &binding) != Some(true) {
        return Err(OpenRefusal::NotOurTier {
            tier_id: tier_id.to_string(),
            epoch: binding.opened_in,
        });
    }

    let remaining = binding.blocks_until_rotation(current_height);
    if remaining < OPEN_CUTOFF_BLOCKS {
        return Err(OpenRefusal::TooCloseToRotation {
            epoch: binding.opened_in,
            remaining,
            required: OPEN_CUTOFF_BLOCKS,
        });
    }
    Ok(binding)
}

/// What a coordinator does with a tier after rotating out of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Still ours: open new sessions and finish existing ones.
    Active,
    /// No longer ours, but sessions opened under our ownership are still ours
    /// to finish. Accept nothing new.
    ///
    /// The distinction matters: a coordinator that treats losing a tier as
    /// "drop everything" abandons committed participants, and one that treats
    /// it as "carry on" competes with the new owner for new sessions.
    Draining,
    /// Not ours, nothing outstanding.
    Idle,
}

/// How a node should treat `tier_id` now.
pub fn disposition(
    current: &EpochCoordinators,
    self_id: &CoordinatorNodeId,
    tier_id: &str,
    outstanding: usize,
) -> Disposition {
    let ours = current.coordinator_for_tier(tier_id).map(|c| c.node_id) == Some(*self_id);
    match (ours, outstanding) {
        (true, _) => Disposition::Active,
        (false, 0) => Disposition::Idle,
        (false, _) => Disposition::Draining,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(i: u8) -> CoordinatorNodeId {
        [i; 32]
    }
    fn roster() -> Vec<CoordinatorNodeId> {
        (1..=8u8).map(node).collect()
    }
    fn elect(epoch: u64) -> EpochCoordinators {
        EpochCoordinators::elect(epoch, &[9u8; 32], &roster(), 4)
    }

    /// Find a tier whose owning seat differs between two epochs. That is the
    /// rotation case; if no tier moved, the fixture proves nothing.
    fn tier_that_moves(a: &EpochCoordinators, b: &EpochCoordinators) -> String {
        for t in ["100k_sats", "1m_sats", "10k_sats", "500k_sats", "5m_sats"] {
            if a.coordinator_for_tier(t).map(|c| c.node_id)
                != b.coordinator_for_tier(t).map(|c| c.node_id)
            {
                return t.to_string();
            }
        }
        panic!("no tier changed owner across the rotation; fixture cannot test handover");
    }

    #[test]
    fn a_session_is_bound_to_the_epoch_it_opened_in() {
        let s = SessionEpoch::at_height(3 * EPOCH_BLOCKS + 10);
        assert_eq!(s.opened_in, 3);
        assert!(!s.has_rotated(3 * EPOCH_BLOCKS + 11));
        assert!(s.has_rotated(4 * EPOCH_BLOCKS));
    }

    #[test]
    fn ownership_does_not_move_under_a_live_session() {
        // The bug: `owns_tier` asks about the CURRENT epoch, so a coordinator
        // holding partial signatures stops owning its own session at rotation.
        let (a, b) = (elect(3), elect(4));
        let tier = tier_that_moves(&a, &b);
        let owner = a.coordinator_for_tier(&tier).unwrap().node_id;

        let session = SessionEpoch::at_height(3 * EPOCH_BLOCKS + 100);

        // Under the old scheme the new epoch's election answers, and it says no.
        assert_ne!(b.coordinator_for_tier(&tier).unwrap().node_id, owner);

        // Bound to its opening epoch, it is still ours.
        assert_eq!(owns_session(&a, &owner, &tier, &session), Some(true));
    }

    #[test]
    fn answering_from_the_wrong_epoch_is_refused_rather_than_guessed() {
        // Silently answering from whichever election is to hand IS the bug.
        let (a, b) = (elect(3), elect(4));
        let tier = tier_that_moves(&a, &b);
        let owner = a.coordinator_for_tier(&tier).unwrap().node_id;
        let session = SessionEpoch::at_height(3 * EPOCH_BLOCKS + 100);
        assert_eq!(owns_session(&b, &owner, &tier, &session), None);
    }

    #[test]
    fn a_session_is_not_opened_on_the_edge_of_a_rotation() {
        let coords = elect(3);
        let tier = "100k_sats";
        let owner = coords.coordinator_for_tier(tier).unwrap().node_id;
        let last = (3 + 1) * EPOCH_BLOCKS - 1;
        assert!(matches!(
            check_open(&coords, &owner, tier, last),
            Err(OpenRefusal::TooCloseToRotation { remaining: 1, .. })
        ));
        // With headroom it opens, bound to epoch 3.
        let ok = check_open(&coords, &owner, tier, last - OPEN_CUTOFF_BLOCKS).unwrap();
        assert_eq!(ok.opened_in, 3);
    }

    #[test]
    fn a_node_does_not_open_sessions_for_a_tier_it_does_not_own() {
        let coords = elect(3);
        let tier = "100k_sats";
        let owner = coords.coordinator_for_tier(tier).unwrap().node_id;
        let other = roster().into_iter().find(|n| *n != owner).unwrap();
        assert!(matches!(
            check_open(&coords, &other, tier, 3 * EPOCH_BLOCKS + 10),
            Err(OpenRefusal::NotOurTier { .. })
        ));
    }

    #[test]
    fn losing_a_tier_with_work_outstanding_drains_rather_than_abandons() {
        // Dropping the sessions abandons committed participants; carrying on
        // competes with the new owner. Draining is neither.
        let (a, b) = (elect(3), elect(4));
        let tier = tier_that_moves(&a, &b);
        let old = a.coordinator_for_tier(&tier).unwrap().node_id;

        assert_eq!(disposition(&a, &old, &tier, 2), Disposition::Active);
        assert_eq!(disposition(&b, &old, &tier, 2), Disposition::Draining);
        assert_eq!(disposition(&b, &old, &tier, 0), Disposition::Idle);
    }

    #[test]
    fn the_new_owner_is_active_immediately() {
        let (a, b) = (elect(3), elect(4));
        let tier = tier_that_moves(&a, &b);
        let new = b.coordinator_for_tier(&tier).unwrap().node_id;
        assert_eq!(disposition(&b, &new, &tier, 0), Disposition::Active);
    }
}
