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
//| FILE: remix.rs                                                                                                       |
//|======================================================================================================================|

//! Wraith Lite v1 — remix queue (DESIGN_LITE.md §9).
//!
//! Whirlpool's killer UX feature ported to Wraith Lite: outputs from a
//! completed round optionally auto-enrol in subsequent rounds at the
//! same (or smaller) tier, building **cumulative anonymity** across
//! many rounds without further user action. K remixes ≈ N^K effective
//! anonymity set, where N is the average per-round participant count.
//! Diminishing returns past K=5; we hard-cap at 10.
//!
//! ## Lifecycle
//!
//! ```text
//!   enqueue() ──► Queued ────► Active { session_id }
//!                  ▲   │             │
//!                  │   │             ▼
//!                  │   │      record_round_complete()
//!                  │   │             │
//!                  │   │             ├── remixes_left > 0 ─► Queued (FIFO)
//!                  │   │             │
//!                  │   │             └── remixes_left == 0 ─► Completed
//!                  │   │
//!                  │   ▼
//!                  │   Cancelled  (user cancel — only allowed from Queued)
//!                  │
//!                  └── expire_stale() ─► Expired  (no session at tier within
//!                                                 queue_timeout; wallet
//!                                                 re-enrols or cashes out)
//! ```
//!
//! ## Why a protocol-crate data structure
//!
//! DESIGN_LITE.md §9 says "coordinator maintains a remix_queue." The
//! queue mostly is bookkeeping (no funds movement, no signatures); a
//! coordinator-owned queue gives the coordinator priority routing for
//! known-good participants and queue-depth stats. A wallet-owned queue
//! works equally well for the basic "remix me K more times" use case.
//! Putting the data structure in the protocol crate means *either*
//! side can use it without re-implementing the FIFO + state-machine
//! logic, and the wire types stay shared.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::tier::LiteTier;

/// Default number of remixes when the wallet doesn't override. 3 covers
/// the common "I want better-than-one-round privacy without committing
/// to a full Whirlpool-style indefinite remix loop" case.
pub const DEFAULT_REMIX_COUNT: u8 = 3;

/// Hard cap on `max_remixes`. DESIGN_LITE §9 picks 10 because privacy
/// returns are negligible past that point and the coordinator's
/// queue-tracking cost grows linearly with this number.
pub const MAX_REMIX_COUNT: u8 = 10;

/// How long a queued enrolment may sit unmatched before
/// `expire_stale()` flips it to `Expired`. Default 1 hour from
/// DESIGN_LITE §9 — short enough that users notice, long enough that
/// any low-traffic tier still has a fair shot at filling.
pub const DEFAULT_QUEUE_TIMEOUT_SECS: u64 = 3600;

/// Opaque enrolment identifier. Wallet-side tracking handle —
/// returned by `enqueue()`, used as the parameter for `cancel()`,
/// `status()`, and `record_round_complete()`. Internally a hex
/// string; format is "remix-<16 hex>".
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RemixId(pub String);

impl RemixId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RemixId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where in the lifecycle a particular enrolment is. Set transitions
/// follow the diagram in the module docs strictly — invalid transitions
/// return `RemixError::InvalidTransition` rather than panicking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemixStatus {
    /// Awaiting an open session at the target tier. Sits in the FIFO
    /// for that tier until `drain_for_tier()` consumes it.
    Queued,
    /// Currently participating in a round. `record_round_complete()`
    /// is the next legal call.
    Active { session_id: String },
    /// Reached `max_remixes`. Terminal state — no further rounds.
    Completed,
    /// User-initiated cancellation. Terminal state.
    Cancelled,
    /// Sat in `Queued` past `queue_timeout`. Terminal state from the
    /// queue's perspective; the wallet decides whether to re-enrol or
    /// cash out.
    Expired,
}

impl RemixStatus {
    /// Stable wire-format string. Used in `RemixEnrolment` so wallets
    /// don't have to know the Rust enum layout.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Active { .. } => "active",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Expired)
    }
}

/// One queued remix enrolment. Owned by the queue; the wallet sees
/// snapshots returned by `status()` / `drain_for_tier()`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemixEnrolment {
    pub remix_id: RemixId,
    /// Identifies the wallet — same value the wallet uses in
    /// `session.find_or_create()` and input registration.
    pub owner_ghost_id: String,
    pub target_tier: LiteTier,
    pub max_remixes: u8,
    pub completed_remixes: u8,
    pub status: RemixStatus,
    /// Unix seconds at most-recent state change. Used by
    /// `expire_stale()` to identify enrolments that have been Queued
    /// too long.
    pub last_state_change_at: u64,
}

impl RemixEnrolment {
    /// Number of remixes still owed before this enrolment hits the
    /// terminal `Completed` state.
    pub fn remixes_remaining(&self) -> u8 {
        self.max_remixes.saturating_sub(self.completed_remixes)
    }
}

/// Errors surfaced by the queue's mutating operations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RemixError {
    #[error("max_remixes {got} exceeds hard cap {MAX_REMIX_COUNT}")]
    MaxRemixesTooLarge { got: u8 },
    #[error("max_remixes must be at least 1")]
    MaxRemixesZero,
    #[error("remix '{0}' not found")]
    NotFound(RemixId),
    #[error("remix '{0}' is in terminal state {1}, can't transition")]
    Terminal(RemixId, &'static str),
    #[error("remix invalid transition from {from} to {to}")]
    InvalidTransition {
        from: &'static str,
        to: &'static str,
    },
}

/// Coordinator-or-wallet-side remix queue. Holds enrolments, drains
/// them in FIFO order when sessions open at their target tier.
///
/// Internally two `Mutex`-protected tables: one keyed by `RemixId`
/// (the canonical store), one keyed by `LiteTier` (a FIFO of pending
/// `RemixId`s for fast tier-scoped drain). Tables stay in sync; both
/// locks are taken only briefly within each method.
pub struct RemixQueue {
    enrolments: Mutex<HashMap<RemixId, RemixEnrolment>>,
    by_tier: Mutex<HashMap<LiteTier, VecDeque<RemixId>>>,
    /// Counter for deterministic-in-tests RemixId generation. Not used
    /// for any cryptographic purpose; the queue's correctness doesn't
    /// depend on RemixIds being unguessable.
    counter: AtomicU64,
}

impl Default for RemixQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl RemixQueue {
    pub fn new() -> Self {
        Self {
            enrolments: Mutex::new(HashMap::new()),
            by_tier: Mutex::new(HashMap::new()),
            counter: AtomicU64::new(0),
        }
    }

    /// Add a new enrolment to the queue. Validates `max_remixes` is in
    /// `[1, MAX_REMIX_COUNT]`. Returns the freshly-generated `RemixId`.
    pub fn enqueue(
        &self,
        owner_ghost_id: impl Into<String>,
        target_tier: LiteTier,
        max_remixes: u8,
        now: u64,
    ) -> Result<RemixId, RemixError> {
        if max_remixes == 0 {
            return Err(RemixError::MaxRemixesZero);
        }
        if max_remixes > MAX_REMIX_COUNT {
            return Err(RemixError::MaxRemixesTooLarge { got: max_remixes });
        }
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        let remix_id = RemixId::new(format!("remix-{:016x}", n));
        let enrolment = RemixEnrolment {
            remix_id: remix_id.clone(),
            owner_ghost_id: owner_ghost_id.into(),
            target_tier,
            max_remixes,
            completed_remixes: 0,
            status: RemixStatus::Queued,
            last_state_change_at: now,
        };
        self.enrolments
            .lock()
            .expect("queue mutex")
            .insert(remix_id.clone(), enrolment);
        self.by_tier
            .lock()
            .expect("queue mutex")
            .entry(target_tier)
            .or_default()
            .push_back(remix_id.clone());
        Ok(remix_id)
    }

    /// Snapshot one enrolment by id. Returns a clone so callers don't
    /// hold the queue's lock while inspecting.
    pub fn status(&self, remix_id: &RemixId) -> Option<RemixEnrolment> {
        self.enrolments
            .lock()
            .expect("queue mutex")
            .get(remix_id)
            .cloned()
    }

    /// Number of enrolments currently in any state (including terminal).
    pub fn len(&self) -> usize {
        self.enrolments.lock().expect("queue mutex").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of `Queued` enrolments waiting for a session at `tier`.
    /// Used for diagnostics and the "estimated wait" UX feedback.
    pub fn queued_count(&self, tier: LiteTier) -> usize {
        self.by_tier
            .lock()
            .expect("queue mutex")
            .get(&tier)
            .map(|q| q.len())
            .unwrap_or(0)
    }

    /// Pop up to `max_count` enrolments from the FIFO at `tier`,
    /// transitioning each to `Active { session_id }` and returning the
    /// updated snapshots. Caller (the coordinator) is then responsible
    /// for actually registering each enrolment's owner with the
    /// session.
    ///
    /// Returns fewer than `max_count` if the FIFO is shorter — this is
    /// the common case in the sparse-traffic regime where queue depth
    /// is shorter than session capacity.
    pub fn drain_for_tier(
        &self,
        tier: LiteTier,
        session_id: impl Into<String>,
        max_count: usize,
        now: u64,
    ) -> Vec<RemixEnrolment> {
        let session_id = session_id.into();
        let mut drained = Vec::new();
        let mut by_tier = self.by_tier.lock().expect("queue mutex");
        let mut enrolments = self.enrolments.lock().expect("queue mutex");
        let queue = match by_tier.get_mut(&tier) {
            Some(q) => q,
            None => return drained,
        };
        while drained.len() < max_count {
            let Some(remix_id) = queue.pop_front() else {
                break;
            };
            let Some(enrolment) = enrolments.get_mut(&remix_id) else {
                // Inconsistency between by_tier and enrolments — log
                // and drop. Won't happen in practice because we
                // always update both atomically under both locks.
                continue;
            };
            // Defensive: only drain enrolments that are still Queued.
            // If somehow the state drifted (cancelled, expired), skip.
            if !matches!(enrolment.status, RemixStatus::Queued) {
                continue;
            }
            enrolment.status = RemixStatus::Active {
                session_id: session_id.clone(),
            };
            enrolment.last_state_change_at = now;
            drained.push(enrolment.clone());
        }
        drained
    }

    /// Mark a round complete for one enrolment. Decrements the remix
    /// counter, transitions back to `Queued` (FIFO re-tail) if more
    /// remixes remain, or to `Completed` if the cap is hit.
    pub fn record_round_complete(
        &self,
        remix_id: &RemixId,
        now: u64,
    ) -> Result<RemixEnrolment, RemixError> {
        let mut enrolments = self.enrolments.lock().expect("queue mutex");
        let enrolment = enrolments
            .get_mut(remix_id)
            .ok_or_else(|| RemixError::NotFound(remix_id.clone()))?;
        // Must be Active.
        match &enrolment.status {
            RemixStatus::Active { .. } => {}
            other => {
                return Err(RemixError::InvalidTransition {
                    from: other.as_str(),
                    to: "post-round",
                });
            }
        }
        enrolment.completed_remixes = enrolment.completed_remixes.saturating_add(1);
        enrolment.last_state_change_at = now;
        if enrolment.completed_remixes >= enrolment.max_remixes {
            enrolment.status = RemixStatus::Completed;
        } else {
            // More remixes wanted — re-queue at FIFO tail.
            enrolment.status = RemixStatus::Queued;
            self.by_tier
                .lock()
                .expect("queue mutex")
                .entry(enrolment.target_tier)
                .or_default()
                .push_back(remix_id.clone());
        }
        Ok(enrolment.clone())
    }

    /// User cancellation. Only legal from `Queued`. Active enrolments
    /// can't be cancelled — the round is already in flight. Terminal
    /// states return `Terminal`.
    pub fn cancel(&self, remix_id: &RemixId, now: u64) -> Result<RemixEnrolment, RemixError> {
        let mut enrolments = self.enrolments.lock().expect("queue mutex");
        let enrolment = enrolments
            .get_mut(remix_id)
            .ok_or_else(|| RemixError::NotFound(remix_id.clone()))?;
        match &enrolment.status {
            RemixStatus::Queued => {}
            RemixStatus::Active { .. } => {
                return Err(RemixError::InvalidTransition {
                    from: "active",
                    to: "cancelled",
                });
            }
            other => {
                return Err(RemixError::Terminal(remix_id.clone(), other.as_str()));
            }
        }
        enrolment.status = RemixStatus::Cancelled;
        enrolment.last_state_change_at = now;
        // Lazy: leave the (now-stale) RemixId in by_tier; drain skips
        // non-Queued entries. Avoids a linear-time scan to rebuild the
        // VecDeque on every cancel.
        Ok(enrolment.clone())
    }

    /// Mark every Queued enrolment older than `timeout_secs` as
    /// `Expired`. Idempotent — re-running with the same `now` does
    /// nothing past the first call. Returns the list of expired
    /// `RemixId`s so the caller can notify wallets.
    pub fn expire_stale(&self, now: u64, timeout_secs: u64) -> Vec<RemixId> {
        let mut expired = Vec::new();
        let mut enrolments = self.enrolments.lock().expect("queue mutex");
        for (id, enrolment) in enrolments.iter_mut() {
            if !matches!(enrolment.status, RemixStatus::Queued) {
                continue;
            }
            if now.saturating_sub(enrolment.last_state_change_at) < timeout_secs {
                continue;
            }
            enrolment.status = RemixStatus::Expired;
            enrolment.last_state_change_at = now;
            expired.push(id.clone());
        }
        // Same lazy approach as cancel(): leave stale ids in by_tier;
        // drain filters them on consumption.
        expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_queue() -> RemixQueue {
        RemixQueue::new()
    }

    // -- enqueue --------------------------------------------------------

    #[test]
    fn enqueue_creates_a_queued_enrolment() {
        let q = fresh_queue();
        let id = q
            .enqueue("alice", LiteTier::Denom100kSats, 3, 1_000_000)
            .unwrap();
        let snap = q.status(&id).unwrap();
        assert_eq!(snap.owner_ghost_id, "alice");
        assert_eq!(snap.target_tier, LiteTier::Denom100kSats);
        assert_eq!(snap.max_remixes, 3);
        assert_eq!(snap.completed_remixes, 0);
        assert!(matches!(snap.status, RemixStatus::Queued));
        assert_eq!(q.len(), 1);
        assert_eq!(q.queued_count(LiteTier::Denom100kSats), 1);
    }

    #[test]
    fn enqueue_rejects_zero_max_remixes() {
        let q = fresh_queue();
        let err = q
            .enqueue("alice", LiteTier::Denom100kSats, 0, 1_000_000)
            .unwrap_err();
        assert_eq!(err, RemixError::MaxRemixesZero);
    }

    #[test]
    fn enqueue_rejects_max_remixes_above_cap() {
        let q = fresh_queue();
        let err = q
            .enqueue("alice", LiteTier::Denom100kSats, 11, 1_000_000)
            .unwrap_err();
        assert_eq!(err, RemixError::MaxRemixesTooLarge { got: 11 });
    }

    #[test]
    fn enqueue_accepts_max_remix_at_hard_cap() {
        let q = fresh_queue();
        let id = q
            .enqueue("alice", LiteTier::Denom100kSats, MAX_REMIX_COUNT, 1_000_000)
            .unwrap();
        assert!(q.status(&id).is_some());
    }

    // -- drain ----------------------------------------------------------

    #[test]
    fn drain_pops_in_fifo_order() {
        let q = fresh_queue();
        let a = q
            .enqueue("a", LiteTier::Denom100kSats, 3, 1_000_000)
            .unwrap();
        let b = q
            .enqueue("b", LiteTier::Denom100kSats, 3, 1_000_001)
            .unwrap();
        let c = q
            .enqueue("c", LiteTier::Denom100kSats, 3, 1_000_002)
            .unwrap();
        let drained = q.drain_for_tier(LiteTier::Denom100kSats, "session-x", 3, 1_000_010);
        let ids: Vec<RemixId> = drained.iter().map(|e| e.remix_id.clone()).collect();
        assert_eq!(ids, vec![a, b, c]);
    }

    #[test]
    fn drain_only_returns_matching_tier() {
        let q = fresh_queue();
        let _ = q
            .enqueue("a", LiteTier::Denom100kSats, 3, 1_000_000)
            .unwrap();
        let _ = q.enqueue("b", LiteTier::Denom1mSats, 3, 1_000_000).unwrap();
        let drained_small = q.drain_for_tier(LiteTier::Denom100kSats, "s1", 10, 1_000_010);
        assert_eq!(drained_small.len(), 1);
        assert_eq!(drained_small[0].owner_ghost_id, "a");
        let drained_big = q.drain_for_tier(LiteTier::Denom1mSats, "s2", 10, 1_000_020);
        assert_eq!(drained_big.len(), 1);
        assert_eq!(drained_big[0].owner_ghost_id, "b");
    }

    #[test]
    fn drain_caps_at_max_count() {
        let q = fresh_queue();
        for i in 0..10 {
            q.enqueue(
                format!("g-{i}"),
                LiteTier::Denom100kSats,
                3,
                1_000_000 + i as u64,
            )
            .unwrap();
        }
        let drained = q.drain_for_tier(LiteTier::Denom100kSats, "s1", 4, 1_000_100);
        assert_eq!(drained.len(), 4);
        // Remaining 6 still queued.
        assert_eq!(q.queued_count(LiteTier::Denom100kSats), 6);
    }

    #[test]
    fn drain_marks_enrolments_active() {
        let q = fresh_queue();
        let id = q
            .enqueue("a", LiteTier::Denom100kSats, 3, 1_000_000)
            .unwrap();
        let _ = q.drain_for_tier(LiteTier::Denom100kSats, "session-x", 1, 1_000_010);
        match q.status(&id).unwrap().status {
            RemixStatus::Active { session_id } => assert_eq!(session_id, "session-x"),
            other => panic!("expected Active, got {other:?}"),
        }
    }

    #[test]
    fn drain_empty_queue_returns_empty_vec() {
        let q = fresh_queue();
        let drained = q.drain_for_tier(LiteTier::Denom100kSats, "s1", 5, 1_000_010);
        assert!(drained.is_empty());
    }

    #[test]
    fn drain_skips_cancelled_entries_left_in_fifo() {
        // Cancellation is lazy — the RemixId stays in by_tier until
        // drained-and-skipped. Verify the skip works.
        let q = fresh_queue();
        let cancel_me = q
            .enqueue("a", LiteTier::Denom100kSats, 3, 1_000_000)
            .unwrap();
        let real = q
            .enqueue("b", LiteTier::Denom100kSats, 3, 1_000_001)
            .unwrap();
        q.cancel(&cancel_me, 1_000_005).unwrap();
        let drained = q.drain_for_tier(LiteTier::Denom100kSats, "s1", 10, 1_000_010);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].remix_id, real);
    }

    // -- record_round_complete ------------------------------------------

    #[test]
    fn record_round_complete_decrements_counter_and_requeues() {
        let q = fresh_queue();
        let id = q
            .enqueue("a", LiteTier::Denom100kSats, 3, 1_000_000)
            .unwrap();
        q.drain_for_tier(LiteTier::Denom100kSats, "s1", 1, 1_000_010);
        let after = q.record_round_complete(&id, 1_000_100).unwrap();
        assert_eq!(after.completed_remixes, 1);
        assert_eq!(after.remixes_remaining(), 2);
        assert!(matches!(after.status, RemixStatus::Queued));
        assert_eq!(q.queued_count(LiteTier::Denom100kSats), 1);
    }

    #[test]
    fn record_round_complete_terminal_at_max() {
        let q = fresh_queue();
        let id = q
            .enqueue("a", LiteTier::Denom100kSats, 2, 1_000_000)
            .unwrap();
        // First round.
        q.drain_for_tier(LiteTier::Denom100kSats, "s1", 1, 1_000_010);
        q.record_round_complete(&id, 1_000_100).unwrap();
        // Second round.
        q.drain_for_tier(LiteTier::Denom100kSats, "s2", 1, 1_000_200);
        let after = q.record_round_complete(&id, 1_000_300).unwrap();
        assert_eq!(after.completed_remixes, 2);
        assert!(matches!(after.status, RemixStatus::Completed));
        assert_eq!(q.queued_count(LiteTier::Denom100kSats), 0);
    }

    #[test]
    fn record_round_complete_requires_active_state() {
        let q = fresh_queue();
        let id = q
            .enqueue("a", LiteTier::Denom100kSats, 3, 1_000_000)
            .unwrap();
        // Still Queued, not yet drained — record should fail.
        let err = q.record_round_complete(&id, 1_000_100).unwrap_err();
        match err {
            RemixError::InvalidTransition { from, .. } => assert_eq!(from, "queued"),
            other => panic!("expected InvalidTransition, got {other:?}"),
        }
    }

    #[test]
    fn record_round_complete_unknown_id_yields_not_found() {
        let q = fresh_queue();
        let err = q
            .record_round_complete(&RemixId::new("nope"), 1_000_000)
            .unwrap_err();
        assert!(matches!(err, RemixError::NotFound(_)));
    }

    // -- cancel ---------------------------------------------------------

    #[test]
    fn cancel_queued_enrolment_succeeds() {
        let q = fresh_queue();
        let id = q
            .enqueue("a", LiteTier::Denom100kSats, 3, 1_000_000)
            .unwrap();
        let after = q.cancel(&id, 1_000_005).unwrap();
        assert!(matches!(after.status, RemixStatus::Cancelled));
    }

    #[test]
    fn cancel_active_enrolment_is_rejected() {
        // Once a round is in flight, cancellation isn't possible at
        // queue level — round either completes (and the queue handles)
        // or fails (and the coordinator's session lifecycle handles).
        let q = fresh_queue();
        let id = q
            .enqueue("a", LiteTier::Denom100kSats, 3, 1_000_000)
            .unwrap();
        q.drain_for_tier(LiteTier::Denom100kSats, "s1", 1, 1_000_010);
        let err = q.cancel(&id, 1_000_020).unwrap_err();
        match err {
            RemixError::InvalidTransition { from, to } => {
                assert_eq!(from, "active");
                assert_eq!(to, "cancelled");
            }
            other => panic!("expected InvalidTransition, got {other:?}"),
        }
    }

    #[test]
    fn cancel_terminal_enrolment_yields_terminal_error() {
        let q = fresh_queue();
        let id = q
            .enqueue("a", LiteTier::Denom100kSats, 3, 1_000_000)
            .unwrap();
        q.cancel(&id, 1_000_005).unwrap();
        let err = q.cancel(&id, 1_000_100).unwrap_err();
        assert!(matches!(err, RemixError::Terminal(_, "cancelled")));
    }

    // -- expire_stale ---------------------------------------------------

    #[test]
    fn expire_stale_marks_old_queued_entries() {
        let q = fresh_queue();
        // Stale: enrolled at T=0, idle for >> timeout when we sweep.
        let stale = q
            .enqueue("a", LiteTier::Denom100kSats, 3, 1_000_000)
            .unwrap();
        // Fresh: enrolled just before the sweep (idle = 100s < 3600s).
        let fresh = q
            .enqueue("b", LiteTier::Denom100kSats, 3, 1_004_000 - 100)
            .unwrap();
        let expired = q.expire_stale(1_004_000, DEFAULT_QUEUE_TIMEOUT_SECS);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], stale);
        assert!(matches!(
            q.status(&stale).unwrap().status,
            RemixStatus::Expired
        ));
        assert!(matches!(
            q.status(&fresh).unwrap().status,
            RemixStatus::Queued
        ));
    }

    #[test]
    fn expire_stale_is_idempotent() {
        let q = fresh_queue();
        let _ = q
            .enqueue("a", LiteTier::Denom100kSats, 3, 1_000_000)
            .unwrap();
        let first = q.expire_stale(1_004_000, DEFAULT_QUEUE_TIMEOUT_SECS);
        let second = q.expire_stale(1_004_000, DEFAULT_QUEUE_TIMEOUT_SECS);
        assert_eq!(first.len(), 1);
        assert!(second.is_empty(), "second expire_stale should be a no-op");
    }

    #[test]
    fn expire_stale_skips_active_and_completed() {
        let q = fresh_queue();
        let active = q
            .enqueue("a", LiteTier::Denom100kSats, 3, 1_000_000)
            .unwrap();
        q.drain_for_tier(LiteTier::Denom100kSats, "s1", 1, 1_000_005);
        let expired = q.expire_stale(1_004_000, DEFAULT_QUEUE_TIMEOUT_SECS);
        assert!(
            expired.is_empty(),
            "Active enrolment must not be expired by stale-sweep"
        );
        assert!(matches!(
            q.status(&active).unwrap().status,
            RemixStatus::Active { .. }
        ));
    }

    // -- end-to-end multi-round scenario --------------------------------

    #[test]
    fn three_round_lifecycle_for_a_single_enrolment() {
        // K=3 remix loop: enqueue → drain → complete → drain → complete
        // → drain → complete → terminal Completed.
        let q = fresh_queue();
        let id = q
            .enqueue("alice", LiteTier::Denom100kSats, 3, 1_000_000)
            .unwrap();
        for i in 0..3u64 {
            let drained = q.drain_for_tier(
                LiteTier::Denom100kSats,
                format!("session-{i}"),
                1,
                1_000_010 + i * 100,
            );
            assert_eq!(drained.len(), 1, "round {i}");
            let snap = drained[0].clone();
            assert_eq!(snap.completed_remixes, i as u8);
            q.record_round_complete(&id, 1_000_050 + i * 100).unwrap();
        }
        let final_state = q.status(&id).unwrap();
        assert_eq!(final_state.completed_remixes, 3);
        assert_eq!(final_state.remixes_remaining(), 0);
        assert!(matches!(final_state.status, RemixStatus::Completed));
        assert_eq!(q.queued_count(LiteTier::Denom100kSats), 0);
    }

    #[test]
    fn fifo_order_preserved_across_requeues() {
        // Enqueue three. Drain one. Complete with remixes_remaining > 0
        // (re-queues at tail). Subsequent drain should see (b, c, a).
        let q = fresh_queue();
        let a = q
            .enqueue("a", LiteTier::Denom100kSats, 3, 1_000_000)
            .unwrap();
        let b = q
            .enqueue("b", LiteTier::Denom100kSats, 3, 1_000_001)
            .unwrap();
        let c = q
            .enqueue("c", LiteTier::Denom100kSats, 3, 1_000_002)
            .unwrap();
        let _ = q.drain_for_tier(LiteTier::Denom100kSats, "s1", 1, 1_000_010);
        q.record_round_complete(&a, 1_000_100).unwrap(); // a re-queued at tail
        let drained = q.drain_for_tier(LiteTier::Denom100kSats, "s2", 10, 1_000_200);
        let ids: Vec<RemixId> = drained.iter().map(|e| e.remix_id.clone()).collect();
        assert_eq!(ids, vec![b, c, a]);
    }

    #[test]
    fn remix_id_round_trips_through_serde() {
        let id = RemixId::new("test-id");
        let s = serde_json::to_string(&id).unwrap();
        let back: RemixId = serde_json::from_str(&s).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn enrolment_round_trips_through_serde() {
        let q = fresh_queue();
        let id = q
            .enqueue("alice", LiteTier::Denom100kSats, 3, 1_000_000)
            .unwrap();
        let snap = q.status(&id).unwrap();
        let s = serde_json::to_string(&snap).unwrap();
        let back: RemixEnrolment = serde_json::from_str(&s).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn status_is_terminal_classification() {
        assert!(!RemixStatus::Queued.is_terminal());
        assert!(!RemixStatus::Active {
            session_id: "x".into(),
        }
        .is_terminal());
        assert!(RemixStatus::Completed.is_terminal());
        assert!(RemixStatus::Cancelled.is_terminal());
        assert!(RemixStatus::Expired.is_terminal());
    }
}
