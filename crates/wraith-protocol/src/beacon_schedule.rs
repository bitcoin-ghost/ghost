//! When, in chain-height terms, nodes commit, reveal, and finalise the beacon
//! for each coordinator epoch (increment 4a). Pure, height-driven, deterministic
//! — no consensus/network coupling. It answers "given the current block height,
//! what should a qualified node be doing about the beacon right now, and for which
//! upcoming epoch?".
//!
//! ## The timeline
//!
//! Epoch `E`'s coordinators must be known *before* `E` begins, so its beacon is
//! built during the **previous** epoch `E-1`, in two windows:
//!
//! ```text
//! epoch E-1: |<-- COMMIT_BLOCKS -->|<-- REVEAL_BLOCKS -->|<-- settled -->|  epoch E: coordinators serve
//!            commit r_i             reveal r_i            beacon(E) known
//! ```
//!
//! - **Commit window** — the first `COMMIT_BLOCKS` of `E-1`: each qualified node
//!   publishes `commit_for(E, node_id, r)`.
//! - **Reveal window** — the next `REVEAL_BLOCKS`: each publishes its `r`.
//! - **Settled** — the remainder of `E-1`: `beacon(E)` is final (everyone can run
//!   `beacon_from_round`), the roster is frozen at `snapshot_height_for_epoch(E)`,
//!   and the election for `E` is computable by every node and wallet.
//!
//! Anchoring uses the block hash at `anchor_height_for_epoch(E)` (the epoch
//! boundary), folded into the beacon by `beacon::compute_beacon`.
//!
//! `COMMIT_BLOCKS + REVEAL_BLOCKS` is well under `EPOCH_BLOCKS`, leaving a settled
//! margin so a late block or brief reorg near a window edge cannot leave `E`
//! without a finalised beacon.

use crate::epoch::{epoch_for_height, snapshot_height_for_epoch, EPOCH_BLOCKS};

/// Blocks of the commit window at the start of each epoch.
pub const COMMIT_BLOCKS: u64 = 24;
/// Blocks of the reveal window, immediately after the commit window.
pub const REVEAL_BLOCKS: u64 = 24;

const _: () = assert!(
    COMMIT_BLOCKS + REVEAL_BLOCKS < EPOCH_BLOCKS,
    "commit+reveal windows must fit inside an epoch with settled margin"
);

/// What a node should be doing about the beacon at a given height, and the epoch
/// the work is *for* (always the next epoch — the one being prepared).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeaconPhase {
    /// Publish `commit_for(for_epoch, node_id, r)`.
    Commit { for_epoch: u64 },
    /// Publish the secret `r` committed earlier.
    Reveal { for_epoch: u64 },
    /// Beacon for `for_epoch` is final; election is computable.
    Settled { for_epoch: u64 },
}

impl BeaconPhase {
    /// The epoch this phase is preparing.
    pub const fn for_epoch(self) -> u64 {
        match self {
            BeaconPhase::Commit { for_epoch }
            | BeaconPhase::Reveal { for_epoch }
            | BeaconPhase::Settled { for_epoch } => for_epoch,
        }
    }
}

/// The beacon phase at `height`. The work always targets the *next* epoch, since
/// each epoch's beacon is built during the preceding one.
pub fn phase_for_height(height: u64) -> BeaconPhase {
    let for_epoch = epoch_for_height(height) + 1;
    let offset = height % EPOCH_BLOCKS;
    if offset < COMMIT_BLOCKS {
        BeaconPhase::Commit { for_epoch }
    } else if offset < COMMIT_BLOCKS + REVEAL_BLOCKS {
        BeaconPhase::Reveal { for_epoch }
    } else {
        BeaconPhase::Settled { for_epoch }
    }
}

/// The block height whose hash anchors `epoch`'s beacon — the epoch's snapshot
/// height (last block of the previous epoch), the same height that freezes the
/// roster, so anchor and roster are taken from one agreed point.
pub fn anchor_height_for_epoch(epoch: u64) -> u64 {
    snapshot_height_for_epoch(epoch)
}

/// True at heights where a node should broadcast its commitment for the next epoch.
pub fn is_commit_height(height: u64) -> bool {
    matches!(phase_for_height(height), BeaconPhase::Commit { .. })
}

/// True at heights where a node should broadcast its reveal for the next epoch.
pub fn is_reveal_height(height: u64) -> bool {
    matches!(phase_for_height(height), BeaconPhase::Reveal { .. })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_partition_each_epoch() {
        // Walk a full epoch (epoch 3) block by block and confirm the phases line up.
        let base = 3 * EPOCH_BLOCKS;
        for off in 0..EPOCH_BLOCKS {
            let h = base + off;
            let p = phase_for_height(h);
            assert_eq!(p.for_epoch(), 4, "work at epoch 3 prepares epoch 4");
            if off < COMMIT_BLOCKS {
                assert!(matches!(p, BeaconPhase::Commit { .. }), "off {off} commit");
            } else if off < COMMIT_BLOCKS + REVEAL_BLOCKS {
                assert!(matches!(p, BeaconPhase::Reveal { .. }), "off {off} reveal");
            } else {
                assert!(
                    matches!(p, BeaconPhase::Settled { .. }),
                    "off {off} settled"
                );
            }
        }
    }

    #[test]
    fn boundaries_are_exact() {
        let base = 10 * EPOCH_BLOCKS;
        assert!(is_commit_height(base)); // first block of epoch
        assert!(is_commit_height(base + COMMIT_BLOCKS - 1));
        assert!(!is_commit_height(base + COMMIT_BLOCKS));
        assert!(is_reveal_height(base + COMMIT_BLOCKS));
        assert!(is_reveal_height(base + COMMIT_BLOCKS + REVEAL_BLOCKS - 1));
        assert!(!is_reveal_height(base + COMMIT_BLOCKS + REVEAL_BLOCKS));
        // settled for the rest
        assert!(matches!(
            phase_for_height(base + COMMIT_BLOCKS + REVEAL_BLOCKS),
            BeaconPhase::Settled { .. }
        ));
        assert!(matches!(
            phase_for_height(base + EPOCH_BLOCKS - 1),
            BeaconPhase::Settled { .. }
        ));
    }

    #[test]
    fn always_prepares_the_next_epoch() {
        assert_eq!(phase_for_height(0).for_epoch(), 1);
        assert_eq!(phase_for_height(EPOCH_BLOCKS).for_epoch(), 2);
        assert_eq!(phase_for_height(EPOCH_BLOCKS * 9 + 100).for_epoch(), 10);
    }

    #[test]
    fn settled_before_the_epoch_it_serves() {
        // By the last block of epoch E-1, epoch E's beacon is Settled — i.e. known
        // before E starts. Check the block right before an epoch boundary.
        let e = 6u64;
        let last_block_of_prev = e * EPOCH_BLOCKS - 1;
        let p = phase_for_height(last_block_of_prev);
        assert_eq!(p.for_epoch(), e);
        assert!(
            matches!(p, BeaconPhase::Settled { .. }),
            "E's beacon final before E begins"
        );
    }

    #[test]
    fn anchor_height_matches_roster_snapshot() {
        for e in [1u64, 2, 7, 50] {
            assert_eq!(anchor_height_for_epoch(e), snapshot_height_for_epoch(e));
        }
    }
}
