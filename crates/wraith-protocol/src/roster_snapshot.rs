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
//| FILE: roster_snapshot.rs                                                                                               |
//|======================================================================================================================|

//! Agreeing on who was qualified — and why the epoch boundary is the wrong place to ask.
//!
//! Sortition is deterministic given a beacon and a roster. Two nodes with the
//! same beacon and *different rosters* elect different coordinators, and then
//! disagree about who owns a session. That is a split in the coordinator layer,
//! and nothing currently detects it.
//!
//! # The snapshot height is too tight
//!
//! `epoch::snapshot_height_for_epoch` returns `epoch * EPOCH_BLOCKS - 1` — the
//! block immediately before the epoch begins. Qualification is not a property of
//! a block, though: it is 95% uptime over a seven-day window plus at least ten
//! peer challenges, assembled from a verification ledger that reconciles over
//! time.
//!
//! So at the boundary instant, honest nodes may hold different views. A peer
//! that just crossed the uptime threshold, a ban that has not propagated, a
//! challenge result still in flight — each flips one node's roster and not
//! another's. Asking at `boundary - 1` asks while the answer is still moving.
//!
//! [`SNAPSHOT_LAG_BLOCKS`] is the distance back the question should be asked
//! from, and [`lagged_snapshot_height`] applies it.
//!
//! # This is a detection, not a fix
//!
//! A lag makes divergence less likely; it cannot make it impossible, because
//! nothing here is consensus. [`roster_commitment`] gives nodes a value to
//! compare so a disagreement is *seen* rather than silently producing two
//! elections — which is the difference between a bug that is diagnosed in an
//! hour and one that is diagnosed from payout discrepancies a week later.

use bitcoin::hashes::{sha256, Hash};

use crate::epoch::{snapshot_height_for_epoch, EPOCH_BLOCKS};
use crate::sortition::CoordinatorNodeId;

/// Domain tag. Versioned.
pub const ROSTER_TAG: &str = "wraith/roster/v1";

/// How far behind the epoch boundary to read qualification from.
///
/// One epoch. Qualification data reconciles over days, so a lag of a few blocks
/// would be cosmetic; a lag of a full epoch means every node is answering a
/// question whose inputs stopped moving before the previous epoch ended.
///
/// This is a parameter, not a proof. It trades freshness — a node qualifying
/// today waits until the epoch after next — for agreement, and the trade is the
/// right way round: a coordinator elected from a stale roster is merely
/// out of date, while coordinators elected from *divergent* rosters is a split.
pub const SNAPSHOT_LAG_BLOCKS: u64 = EPOCH_BLOCKS;

/// Why a roster could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RosterError {
    /// The snapshot was taken too close to the epoch it elects for.
    #[error("snapshot at {taken_at} is only {lag} blocks behind epoch {epoch}'s boundary; {required} required for qualification data to settle")]
    SnapshotTooFresh {
        /// Epoch being elected for.
        epoch: u64,
        /// Height the roster was read at.
        taken_at: u64,
        /// Actual lag.
        lag: u64,
        /// Minimum acceptable.
        required: u64,
    },
}

/// The height to read qualification from when electing for `epoch`.
pub fn lagged_snapshot_height(epoch: u64) -> u64 {
    snapshot_height_for_epoch(epoch).saturating_sub(SNAPSHOT_LAG_BLOCKS)
}

/// A value two nodes can compare to see whether they agree.
///
/// Binds the epoch and the height as well as the members, so a roster that is
/// correct for a different epoch does not compare equal — that mistake would
/// otherwise look like agreement.
pub fn roster_commitment(
    epoch: u64,
    snapshot_height: u64,
    roster: &[CoordinatorNodeId],
) -> [u8; 32] {
    let mut sorted: Vec<&CoordinatorNodeId> = roster.iter().collect();
    sorted.sort_unstable();
    sorted.dedup();

    let mut buf = Vec::with_capacity(ROSTER_TAG.len() + 16 + sorted.len() * 32);
    buf.extend_from_slice(ROSTER_TAG.as_bytes());
    buf.extend_from_slice(&epoch.to_be_bytes());
    buf.extend_from_slice(&snapshot_height.to_be_bytes());
    for m in sorted {
        buf.extend_from_slice(m);
    }
    sha256::Hash::hash(&buf).to_byte_array()
}

/// Check a snapshot was taken far enough back to be worth comparing.
pub fn check_snapshot_lag(epoch: u64, taken_at: u64) -> Result<(), RosterError> {
    let boundary = snapshot_height_for_epoch(epoch);
    let lag = boundary.saturating_sub(taken_at);
    if lag < SNAPSHOT_LAG_BLOCKS {
        return Err(RosterError::SnapshotTooFresh {
            epoch,
            taken_at,
            lag,
            required: SNAPSHOT_LAG_BLOCKS,
        });
    }
    Ok(())
}

/// What a comparison with a peer found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Agreement {
    /// Same roster.
    Agreed,
    /// Different rosters for the same epoch. **This is a split.**
    ///
    /// Carries the symmetric difference so the disagreement can be diagnosed
    /// rather than merely counted — which nodes one side has and the other does
    /// not is the whole diagnosis.
    Diverged {
        /// Members we have and the peer does not.
        only_ours: Vec<CoordinatorNodeId>,
        /// Members the peer has and we do not.
        only_theirs: Vec<CoordinatorNodeId>,
    },
}

/// Compare our roster with a peer's.
pub fn compare(ours: &[CoordinatorNodeId], theirs: &[CoordinatorNodeId]) -> Agreement {
    use std::collections::BTreeSet;
    let a: BTreeSet<&CoordinatorNodeId> = ours.iter().collect();
    let b: BTreeSet<&CoordinatorNodeId> = theirs.iter().collect();
    if a == b {
        return Agreement::Agreed;
    }
    Agreement::Diverged {
        only_ours: a.difference(&b).map(|x| **x).collect(),
        only_theirs: b.difference(&a).map(|x| **x).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(i: u8) -> CoordinatorNodeId {
        [i; 32]
    }
    fn roster(ids: &[u8]) -> Vec<CoordinatorNodeId> {
        ids.iter().map(|i| node(*i)).collect()
    }

    #[test]
    fn the_lagged_height_is_a_full_epoch_behind_the_boundary() {
        let epoch = 100;
        let boundary = snapshot_height_for_epoch(epoch);
        assert_eq!(lagged_snapshot_height(epoch), boundary - EPOCH_BLOCKS);
        assert!(check_snapshot_lag(epoch, lagged_snapshot_height(epoch)).is_ok());
    }

    #[test]
    fn the_epoch_boundary_itself_is_refused() {
        // The existing `snapshot_height_for_epoch` returns boundary - 1, which
        // reads qualification while it is still reconciling. That is where
        // honest nodes disagree.
        let epoch = 100;
        let boundary = snapshot_height_for_epoch(epoch);
        assert!(matches!(
            check_snapshot_lag(epoch, boundary),
            Err(RosterError::SnapshotTooFresh { .. })
        ));
        assert!(check_snapshot_lag(epoch, boundary - 1).is_err());
        assert!(check_snapshot_lag(epoch, boundary - EPOCH_BLOCKS + 1).is_err());
    }

    #[test]
    fn the_commitment_ignores_order_and_duplicates() {
        // Otherwise two nodes with the same roster in a different order would
        // report a split that does not exist.
        let h = 1_000;
        assert_eq!(
            roster_commitment(5, h, &roster(&[3, 1, 2])),
            roster_commitment(5, h, &roster(&[1, 2, 3]))
        );
        assert_eq!(
            roster_commitment(5, h, &roster(&[1, 2, 2, 3])),
            roster_commitment(5, h, &roster(&[1, 2, 3]))
        );
    }

    #[test]
    fn the_commitment_binds_the_epoch_and_the_height() {
        // A roster that is correct for a different epoch must not compare equal;
        // that mistake would look exactly like agreement.
        let r = roster(&[1, 2, 3]);
        assert_ne!(
            roster_commitment(5, 1_000, &r),
            roster_commitment(6, 1_000, &r)
        );
        assert_ne!(
            roster_commitment(5, 1_000, &r),
            roster_commitment(5, 1_001, &r)
        );
    }

    #[test]
    fn identical_rosters_agree_regardless_of_order() {
        assert_eq!(
            compare(&roster(&[1, 2, 3]), &roster(&[3, 2, 1])),
            Agreement::Agreed
        );
    }

    #[test]
    fn divergence_names_both_sides_rather_than_counting_them() {
        // Which nodes one side has and the other does not IS the diagnosis.
        // A boolean would say a split happened and nothing about why.
        let d = compare(&roster(&[1, 2, 3, 4]), &roster(&[2, 3, 4, 5]));
        assert_eq!(
            d,
            Agreement::Diverged {
                only_ours: vec![node(1)],
                only_theirs: vec![node(5)],
            }
        );
    }

    #[test]
    fn one_extra_member_is_a_divergence_not_a_rounding_error() {
        // A single node's qualification flipping is exactly the boundary case
        // the lag exists to avoid, and it must not be tolerated as close enough.
        let d = compare(&roster(&[1, 2, 3]), &roster(&[1, 2, 3, 4]));
        assert!(matches!(d, Agreement::Diverged { .. }));
    }

    #[test]
    fn a_divergent_roster_elects_a_different_set() {
        // Why any of this matters: the two rosters produce different
        // coordinators from the same beacon, so the two nodes disagree about
        // who owns a session.
        use crate::sortition::elect_coordinators;
        let beacon = [7u8; 32];
        let ours = roster(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let theirs = roster(&[1, 2, 3, 4, 5, 6, 7, 9]);
        assert!(matches!(
            compare(&ours, &theirs),
            Agreement::Diverged { .. }
        ));

        let a = elect_coordinators(&beacon, 3, &ours, 4);
        let b = elect_coordinators(&beacon, 3, &theirs, 4);
        assert_ne!(
            a.iter().map(|c| c.node_id).collect::<Vec<_>>(),
            b.iter().map(|c| c.node_id).collect::<Vec<_>>()
        );
    }
}
