//! In-memory chain-health state: recent reorgs + the current tip-lag signal.
//!
//! The node already *detects* reorgs (the ZMQ-driven reorg handler in
//! `bins/ghost-pool`) and *evaluates* tip-lag (the behind-tip monitor), but
//! historically both only fired an operator alert — nothing was persisted, so
//! an operator could never look back and SEE a reorg or the current tip status.
//!
//! This module keeps a bounded, process-local record of recent reorg events
//! plus the latest tip-status snapshot, shared (behind `Arc`) between the
//! writer tasks (reorg handler, behind-tip monitor) and the
//! `GET /api/v1/chain/health` route handler. It mirrors the bounded-`VecDeque`
//! shape of [`crate::pool_series`], but also carries a single latest-value cell
//! for the tip status.
//!
//! In-memory only — resets on restart, like the other operator-facing rings.

use parking_lot::RwLock;
use serde::Serialize;
use std::collections::VecDeque;

/// Default number of recent reorg events retained. Reorgs are rare; a few dozen
/// is plenty of scrollback for an operator, and each entry is tiny.
pub const DEFAULT_REORG_CAPACITY: usize = 50;

/// One detected reorg (block disconnected from the main chain).
///
/// The ZMQ sequence event that drives detection carries only the disconnected
/// block hash and the consecutive-disconnect depth, so those are always
/// present; `new_tip_height` is filled from the node's own height source when
/// one is wired (the ZMQ event itself does not carry a new tip), and the new
/// tip hash is not available from the event so it is not recorded.
#[derive(Debug, Clone, Serialize)]
pub struct ReorgEvent {
    /// Unix timestamp (seconds) the reorg was recorded.
    pub unix_time: i64,
    /// Consecutive-disconnect depth at the time this block was orphaned.
    pub depth: u32,
    /// Hash of the disconnected (orphaned) block — the old tip.
    pub old_tip_hash: String,
    /// The node's local chain height right after the disconnect, when a height
    /// source is wired; `None` when unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_tip_height: Option<u64>,
}

/// Tip-lag status label. `at_tip` is the normal, healthy state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TipStatusKind {
    /// Caught up with the network (or ahead) — healthy.
    AtTip,
    /// Behind the best known peer by more than the lag threshold.
    Behind,
    /// No new block for longer than the stale threshold while a peer is ahead.
    Stale,
}

/// Snapshot of the current tip-lag signal, derived from the same inputs the
/// behind-tip monitor uses (local height, best-peer height, tip age).
#[derive(Debug, Clone, Serialize)]
pub struct TipStatus {
    /// This node's current local L1 height.
    pub local_height: u64,
    /// Highest L1 height reported by a fresh connected mesh peer (0 = unknown).
    pub best_peer_height: u64,
    /// How many blocks behind the best peer (0 when caught up or peer unknown).
    pub behind_by: u64,
    /// Seconds since the local height last advanced (tip age).
    pub tip_age_secs: u64,
    /// Derived status label.
    pub status: TipStatusKind,
}

/// Derive a [`TipStatus`] from the raw signals. Pure — no I/O or clock access —
/// so the classification is unit-testable independently of the monitor.
///
/// Mirrors the behind-tip alert thresholds so the displayed status and the
/// fired alert agree:
/// * `best_peer_height == 0` (unknown / isolated) → `AtTip` (never false-alarm).
/// * lagging: `best_peer - local > lag_blocks_k` → `Behind`.
/// * stalled: `tip_age > max_tip_age` AND a peer is strictly ahead → `Stale`.
/// * otherwise → `AtTip`.
///
/// `behind_by` is the raw `best_peer - local` gap (saturating, 0 when peer
/// unknown), reported regardless of whether it crosses the alert threshold.
pub fn derive_tip_status(
    local_height: u64,
    best_peer_height: u64,
    tip_age_secs: u64,
    lag_blocks_k: u64,
    max_tip_age_secs: u64,
) -> TipStatus {
    let behind_by = if best_peer_height == 0 {
        0
    } else {
        best_peer_height.saturating_sub(local_height)
    };
    let status = if best_peer_height == 0 {
        TipStatusKind::AtTip
    } else if behind_by > lag_blocks_k {
        TipStatusKind::Behind
    } else if tip_age_secs > max_tip_age_secs && best_peer_height > local_height {
        TipStatusKind::Stale
    } else {
        TipStatusKind::AtTip
    };
    TipStatus {
        local_height,
        best_peer_height,
        behind_by,
        tip_age_secs,
        status,
    }
}

/// Shared chain-health state: a bounded ring of recent reorgs plus the latest
/// tip-status snapshot. Cheap reads/writes behind independent `RwLock`s.
pub struct ChainHealth {
    reorgs: RwLock<VecDeque<ReorgEvent>>,
    reorg_capacity: usize,
    tip: RwLock<Option<TipStatus>>,
}

impl ChainHealth {
    /// Create a holder retaining at most `reorg_capacity` reorg events.
    pub fn new(reorg_capacity: usize) -> Self {
        let reorg_capacity = reorg_capacity.max(1);
        Self {
            reorgs: RwLock::new(VecDeque::with_capacity(reorg_capacity.min(64))),
            reorg_capacity,
            tip: RwLock::new(None),
        }
    }

    /// Record a detected reorg, evicting the oldest when at capacity (FIFO).
    /// `unix_time` is the current wall-clock second.
    pub fn record_reorg(
        &self,
        unix_time: i64,
        depth: u32,
        old_tip_hash: impl Into<String>,
        new_tip_height: Option<u64>,
    ) {
        let mut buf = self.reorgs.write();
        while buf.len() >= self.reorg_capacity {
            buf.pop_front();
        }
        buf.push_back(ReorgEvent {
            unix_time,
            depth,
            old_tip_hash: old_tip_hash.into(),
            new_tip_height,
        });
    }

    /// All retained reorg events, newest first.
    pub fn recent_reorgs(&self) -> Vec<ReorgEvent> {
        self.reorgs.read().iter().rev().cloned().collect()
    }

    /// Count of reorg events recorded at or after `cutoff` (unix seconds).
    pub fn reorg_count_since(&self, cutoff: i64) -> usize {
        self.reorgs
            .read()
            .iter()
            .filter(|e| e.unix_time >= cutoff)
            .count()
    }

    /// Number of reorg events currently retained.
    pub fn reorg_len(&self) -> usize {
        self.reorgs.read().len()
    }

    /// Replace the current tip-status snapshot.
    pub fn set_tip(&self, tip: TipStatus) {
        *self.tip.write() = Some(tip);
    }

    /// The latest tip-status snapshot, if the monitor has run at least once.
    pub fn tip(&self) -> Option<TipStatus> {
        self.tip.read().clone()
    }
}

impl Default for ChainHealth {
    fn default() -> Self {
        Self::new(DEFAULT_REORG_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reorg_ring_evicts_oldest_at_capacity() {
        let ch = ChainHealth::new(3);
        for i in 0..5 {
            ch.record_reorg(i, i as u32 + 1, format!("hash{i}"), Some(1000 + i as u64));
        }
        assert_eq!(ch.reorg_len(), 3);
        // Newest first; oldest two (t=0,1) evicted, so t=4,3,2 remain.
        let recent = ch.recent_reorgs();
        assert_eq!(
            recent.iter().map(|e| e.unix_time).collect::<Vec<_>>(),
            vec![4, 3, 2]
        );
        assert_eq!(recent[0].old_tip_hash, "hash4");
        assert_eq!(recent[0].new_tip_height, Some(1004));
    }

    #[test]
    fn reorg_count_since_filters_by_cutoff() {
        let ch = ChainHealth::new(50);
        for t in 0..10 {
            ch.record_reorg(t, 1, "h", None);
        }
        assert_eq!(ch.reorg_count_since(7), 3); // t = 7,8,9
        assert_eq!(ch.reorg_count_since(i64::MIN), 10);
        assert_eq!(ch.reorg_count_since(100), 0);
    }

    #[test]
    fn capacity_is_at_least_one() {
        let ch = ChainHealth::new(0);
        ch.record_reorg(1, 1, "h", None);
        assert_eq!(ch.reorg_len(), 1);
    }

    #[test]
    fn tip_is_none_until_set() {
        let ch = ChainHealth::new(4);
        assert!(ch.tip().is_none());
        ch.set_tip(derive_tip_status(100, 100, 5, 3, 1800));
        assert_eq!(ch.tip().unwrap().status, TipStatusKind::AtTip);
    }

    #[test]
    fn derive_at_tip_when_peer_unknown() {
        // best_peer == 0 → unknown, never Behind/Stale even if local is 0.
        let t = derive_tip_status(0, 0, 999_999, 3, 1800);
        assert_eq!(t.status, TipStatusKind::AtTip);
        assert_eq!(t.behind_by, 0);
    }

    #[test]
    fn derive_at_tip_when_caught_up_or_ahead() {
        assert_eq!(derive_tip_status(100, 100, 5, 3, 1800).status, TipStatusKind::AtTip);
        assert_eq!(derive_tip_status(105, 100, 5, 3, 1800).status, TipStatusKind::AtTip);
        // lag exactly K is not "more than K".
        assert_eq!(derive_tip_status(100, 103, 5, 3, 1800).status, TipStatusKind::AtTip);
    }

    #[test]
    fn derive_behind_when_lag_exceeds_k() {
        let t = derive_tip_status(100, 105, 5, 3, 1800);
        assert_eq!(t.status, TipStatusKind::Behind);
        assert_eq!(t.behind_by, 5);
    }

    #[test]
    fn derive_stale_when_tip_old_and_peer_ahead() {
        // Only 1 behind (within K) but tip older than max age and peer ahead.
        let t = derive_tip_status(100, 101, 1801, 3, 1800);
        assert_eq!(t.status, TipStatusKind::Stale);
        assert_eq!(t.behind_by, 1);
    }

    #[test]
    fn derive_not_stale_when_old_but_caught_up() {
        // Tip old but we are at/above best peer → healthy.
        let t = derive_tip_status(101, 101, 5000, 3, 1800);
        assert_eq!(t.status, TipStatusKind::AtTip);
    }
}
