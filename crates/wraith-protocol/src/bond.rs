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
//| FILE: bond.rs                                                                                                        |
//|======================================================================================================================|

//! Wraith Lite v1 — bond types + L2 escrow trait.
//!
//! See `DESIGN_LITE.md` §12 for the bond mechanism. Summary: each
//! participant escrows `tier.bond_sats()` (0.5% of denomination) into
//! ghost-pay's L2 ledger at `session.bond()` time. Bond is refunded on
//! round completion or no-show during Filling, slashed on no-sign during
//! Signing.
//!
//! ## Why a trait, not a direct ghost-pay dependency
//!
//! The coordinator code that consumes bonds doesn't care *how* the bond
//! is held — only that the bond is verifiable, refundable, and slashable
//! against an authoritative ledger. By depending on the [`BondLedger`]
//! trait rather than the ghost-pay L2 client directly:
//!
//!   * The protocol crate doesn't need ghost-pay as a dependency (would
//!     be circular: ghost-pay depends on wraith-protocol's types).
//!   * Tests can swap in [`MockBondLedger`] with no real L2 plumbing.
//!   * A future v2 backing (e.g. L1-bonded tx0, threshold-secured ledger)
//!     drops in by implementing the same trait.
//!
//! The production binding lives in `crates/ghost-pay/` and is wired at
//! coordinator-startup time.
//!
//! ## What's intentionally absent from v1
//!
//! - **Threshold-signed bond proofs.** A `BondProof` in v1 is the
//!   ledger's word, presented by the coordinator on demand. Standby
//!   coordinators trust the ledger. v2 adds cryptographic
//!   non-repudiation (multi-coordinator co-signing of bond resolutions).
//! - **On-chain bond receipts.** v1 bonds are L2-only. A future variant
//!   could anchor BondId hashes to on-chain commitments for stronger
//!   verifiability against an L2 outage.
//! - **Slashing distribution.** Splitting a slashed bond between the
//!   round's other participants and the protocol fund is the
//!   coordinator's job, not the ledger's. The ledger just credits/debits
//!   per [`BondResolution`].

use serde::{Deserialize, Serialize};

/// Opaque identifier for a bond escrowed in the [`BondLedger`].
///
/// Returned by `BondLedger::escrow()` (or its real-world equivalent on
/// the wallet side at `session.bond()` time), passed back to
/// `BondLedger::resolve()` when the round closes. Internally it's a
/// 32-byte hex string — long enough to be globally unique across the
/// network's lifetime, short enough to round-trip in JSON-RPC envelopes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BondId(pub String);

impl BondId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for BondId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What happens to a bond when its session closes. Either the bond is
/// returned to the participant (the common case) or it's slashed (the
/// griefing case).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BondResolution {
    Refund(RefundReason),
    Slash(SlashReason),
}

/// Why a bond is being refunded. All paths return the participant's
/// principal in full — the participant did nothing wrong (or the round
/// never reached the slashing condition).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefundReason {
    /// Round completed all phases including Signing. Standard happy path.
    RoundCompleted,
    /// Participant withdrew during the open Filling window. Legitimate —
    /// changing your mind before commitment isn't griefing.
    WithdrewDuringFilling,
    /// Round-wide failure: ≥80% of participants missed Signing, so the
    /// coordinator voided the round entirely. Slashing one participant
    /// out of a wholesale failure would be a coordinator-controlled
    /// windfall.
    RoundVoided,
    /// Coordinator aborted the round (e.g. malformed transaction state,
    /// failover state lost). Always full refund — the abort isn't the
    /// participant's fault.
    CoordinatorAborted,
}

/// Why a bond is being slashed. Each variant identifies a specific
/// participant-attributable failure mode. v1 has only one reason
/// (no-sign during Signing); v2 may add more (e.g. submitting a known-
/// invalid signature).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashReason {
    /// Participant joined a Locked round (passed Filling) but failed to
    /// produce their signature within `PHASE_EXECUTION_TIMEOUT_SECS`.
    /// This is the actual griefing case — round filled, others wasted
    /// their time, this participant disappeared.
    NoSignDuringSigning,
}

/// Snapshot of a bond's current state in the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondRecord {
    pub bond_id: BondId,
    pub ghost_id: String,
    pub session_id: String,
    pub amount_sats: u64,
    pub status: BondStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BondStatus {
    /// Bond is held; round is in progress.
    Escrowed,
    /// Bond has been resolved — see `final_resolution` for how.
    Resolved(BondResolution),
}

/// Errors any [`BondLedger`] implementation may surface to the coordinator.
#[derive(Debug, thiserror::Error)]
pub enum BondError {
    /// The participant has no escrowed bond for this session. Coordinator
    /// surfaces this to the wallet at registration time so the wallet
    /// knows to call `session.bond()` first.
    #[error("no bond escrowed for participant '{ghost_id}' in session '{session_id}'")]
    NotBonded {
        ghost_id: String,
        session_id: String,
    },
    /// The bond exists but is the wrong size. Likely a wallet-coordinator
    /// disagreement on the tier — bond was posted at one tier, round
    /// is at another.
    #[error(
        "bond {bond_id} has {actual_sats} sats, expected {expected_sats} \
         (tier mismatch?)"
    )]
    AmountMismatch {
        bond_id: BondId,
        expected_sats: u64,
        actual_sats: u64,
    },
    /// `resolve()` was called on a bond that's already been resolved.
    /// Almost always a coordinator bug (double-resolution); ledger
    /// refuses idempotently to keep accounting clean.
    #[error("bond {bond_id} already resolved")]
    AlreadyResolved { bond_id: BondId },
    /// The L2 ledger backend is unavailable (network partition, ghost-pay
    /// down, etc.). DESIGN_LITE §15.6: assumed never to happen in
    /// production. When it does, coordinator queues the operation and
    /// retries on next heartbeat.
    #[error("bond ledger unreachable: {0}")]
    LedgerUnreachable(String),
    /// Catch-all for unexpected ledger responses — surfaced as an error
    /// instead of a panic so the coordinator's session-state machine
    /// can fail the round gracefully.
    #[error("ledger error: {0}")]
    Other(String),
}

/// Abstraction over the L2 escrow store. Production binding lives in
/// `crates/ghost-pay/`; tests use [`MockBondLedger`].
///
/// All methods are sync — async I/O happens at the ghost-pay client
/// layer (which adapts to this trait). Keeping the trait sync means
/// coordinator state-machine code doesn't have to thread `Future`s
/// through every bond check; the ledger calls are I/O-bounded but
/// short.
///
/// `Send + Sync` so the coordinator can hold an `Arc<dyn BondLedger>`
/// across tokio tasks.
pub trait BondLedger: Send + Sync {
    /// Verify that `ghost_id` has escrowed exactly `expected_sats` for
    /// `session_id` and return the [`BondId`]. Used by the coordinator
    /// at participant registration: "show me your bond before I let
    /// you into the round."
    ///
    /// Returns:
    /// - `Ok(BondId)` if the bond exists and matches.
    /// - `Err(BondError::NotBonded)` if no bond is escrowed.
    /// - `Err(BondError::AmountMismatch)` if the bond's value differs.
    fn verify_bond(
        &self,
        ghost_id: &str,
        session_id: &str,
        expected_sats: u64,
    ) -> Result<BondId, BondError>;

    /// Resolve a bond — either refund the participant or slash it. The
    /// ledger updates its state and returns the resulting [`BondRecord`]
    /// for coordinator audit. Idempotent: re-calling `resolve()` on an
    /// already-resolved bond returns `AlreadyResolved`, never silently
    /// double-credits.
    fn resolve_bond(
        &self,
        bond_id: &BondId,
        resolution: BondResolution,
    ) -> Result<BondRecord, BondError>;

    /// Read a bond's current state without mutating it. Used by standby
    /// coordinators during failover (DESIGN_LITE §7) so the new Active
    /// can rebuild its in-flight session view.
    fn snapshot_bond(&self, bond_id: &BondId) -> Result<BondRecord, BondError>;
}

// ---------------------------------------------------------------------------
// In-memory mock ledger — tests + integration scaffolding only.
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::sync::Mutex;

/// In-memory `BondLedger` for tests + the integration test scaffolding
/// that doesn't have a real ghost-pay running. NOT for production.
///
/// Internally a `HashMap<BondId, BondRecord>` behind a `Mutex` so
/// multi-threaded tests don't deadlock on concurrent reads. Bonds must
/// be pre-loaded via [`MockBondLedger::escrow`] before
/// [`BondLedger::verify_bond`] can succeed — the mock doesn't auto-create
/// bonds because the production ghost-pay client doesn't either.
pub struct MockBondLedger {
    bonds: Mutex<HashMap<BondId, BondRecord>>,
    /// Counter used to generate stable, ascending BondIds in tests so
    /// assertions can check exact IDs without fishing them out of
    /// non-deterministic structures.
    counter: Mutex<u64>,
    /// Auto-escrow mode: when true, `verify_bond` auto-creates a
    /// matching bond record on first call instead of returning
    /// `NotBonded`. Lets dev/regtest demo flows skip the wallet-side
    /// L2 escrow plumbing entirely. Production / mainnet must NOT
    /// use this — there's no real money behind the bond, so a Sybil
    /// attacker can fill any round for free. Coordinator binary
    /// gates this behind `--mock-bond-ledger-auto-escrow`.
    auto_escrow: bool,
}

impl Default for MockBondLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl MockBondLedger {
    pub fn new() -> Self {
        Self {
            bonds: Mutex::new(HashMap::new()),
            counter: Mutex::new(0),
            auto_escrow: false,
        }
    }

    /// Construct a mock ledger that auto-escrows on first
    /// `verify_bond` call. See `auto_escrow` field docs for why
    /// this is dev/regtest-only and what attack surface it opens.
    pub fn with_auto_escrow() -> Self {
        Self {
            bonds: Mutex::new(HashMap::new()),
            counter: Mutex::new(0),
            auto_escrow: true,
        }
    }

    /// Escrow a fresh bond. Stand-in for the real L2 escrow flow that
    /// the wallet hits at `session.bond()` time.
    pub fn escrow(
        &self,
        ghost_id: impl Into<String>,
        session_id: impl Into<String>,
        amount_sats: u64,
    ) -> BondId {
        let mut counter = self.counter.lock().expect("mock ledger poisoned");
        *counter += 1;
        let id = BondId::new(format!("mock-bond-{:016x}", *counter));
        let record = BondRecord {
            bond_id: id.clone(),
            ghost_id: ghost_id.into(),
            session_id: session_id.into(),
            amount_sats,
            status: BondStatus::Escrowed,
        };
        self.bonds
            .lock()
            .expect("mock ledger poisoned")
            .insert(id.clone(), record);
        id
    }

    /// Total number of bonds currently tracked, regardless of status.
    /// Used by tests that want to assert ledger size without iterating.
    pub fn len(&self) -> usize {
        self.bonds.lock().expect("mock ledger poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot every bond record. Test-only convenience so callers
    /// don't have to track every BondId returned from `escrow` to
    /// inspect resolution status later.
    pub fn snapshot_all(&self) -> Vec<BondRecord> {
        self.bonds
            .lock()
            .expect("mock ledger poisoned")
            .values()
            .cloned()
            .collect()
    }
}

impl BondLedger for MockBondLedger {
    fn verify_bond(
        &self,
        ghost_id: &str,
        session_id: &str,
        expected_sats: u64,
    ) -> Result<BondId, BondError> {
        // Auto-escrow path: if no bond exists for this
        // (ghost_id, session_id) and auto_escrow is on, create one
        // implicitly so verify succeeds. Drops to the normal path
        // for already-recorded bonds (so amount-mismatch detection
        // still works). Locked outside the inner block so we don't
        // hold the lock across self.escrow() (which re-locks).
        if self.auto_escrow {
            let needs_escrow = {
                let bonds = self.bonds.lock().expect("mock ledger poisoned");
                !bonds
                    .values()
                    .any(|r| r.ghost_id == ghost_id && r.session_id == session_id)
            };
            if needs_escrow {
                self.escrow(ghost_id, session_id, expected_sats);
            }
        }
        let bonds = self.bonds.lock().expect("mock ledger poisoned");
        let found = bonds
            .values()
            .find(|r| r.ghost_id == ghost_id && r.session_id == session_id)
            .ok_or_else(|| BondError::NotBonded {
                ghost_id: ghost_id.into(),
                session_id: session_id.into(),
            })?;
        if found.amount_sats != expected_sats {
            return Err(BondError::AmountMismatch {
                bond_id: found.bond_id.clone(),
                expected_sats,
                actual_sats: found.amount_sats,
            });
        }
        // Don't surface already-resolved bonds as "verified" — they can't
        // back a fresh registration.
        match &found.status {
            BondStatus::Escrowed => Ok(found.bond_id.clone()),
            BondStatus::Resolved(_) => Err(BondError::AlreadyResolved {
                bond_id: found.bond_id.clone(),
            }),
        }
    }

    fn resolve_bond(
        &self,
        bond_id: &BondId,
        resolution: BondResolution,
    ) -> Result<BondRecord, BondError> {
        let mut bonds = self.bonds.lock().expect("mock ledger poisoned");
        let record = bonds
            .get_mut(bond_id)
            .ok_or_else(|| BondError::Other(format!("bond {bond_id} unknown to ledger")))?;
        match &record.status {
            BondStatus::Escrowed => {
                record.status = BondStatus::Resolved(resolution);
                Ok(record.clone())
            }
            BondStatus::Resolved(_) => Err(BondError::AlreadyResolved {
                bond_id: bond_id.clone(),
            }),
        }
    }

    fn snapshot_bond(&self, bond_id: &BondId) -> Result<BondRecord, BondError> {
        let bonds = self.bonds.lock().expect("mock ledger poisoned");
        bonds
            .get(bond_id)
            .cloned()
            .ok_or_else(|| BondError::Other(format!("bond {bond_id} unknown to ledger")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tier::LiteTier;

    // -- BondId / Display ------------------------------------------------

    #[test]
    fn bond_id_round_trips_through_serde() {
        let id = BondId::new("test-1234");
        let serialised = serde_json::to_string(&id).unwrap();
        let back: BondId = serde_json::from_str(&serialised).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn bond_id_displays_as_inner_string() {
        let id = BondId::new("readable-id");
        assert_eq!(format!("{id}"), "readable-id");
    }

    // -- MockBondLedger lifecycle ---------------------------------------

    #[test]
    fn escrow_then_verify_returns_same_id() {
        let ledger = MockBondLedger::new();
        let id = ledger.escrow("alice", "session-1", 500);
        let verified = ledger
            .verify_bond("alice", "session-1", 500)
            .expect("verify should succeed for fresh bond");
        assert_eq!(verified, id);
    }

    #[test]
    fn verify_unknown_bond_yields_not_bonded() {
        let ledger = MockBondLedger::new();
        // Different participant, never escrowed.
        let err = ledger
            .verify_bond("eve", "session-1", 500)
            .expect_err("unknown bond should fail");
        match err {
            BondError::NotBonded {
                ghost_id,
                session_id,
            } => {
                assert_eq!(ghost_id, "eve");
                assert_eq!(session_id, "session-1");
            }
            other => panic!("expected NotBonded, got {other:?}"),
        }
    }

    #[test]
    fn verify_with_wrong_amount_yields_amount_mismatch() {
        let ledger = MockBondLedger::new();
        let _ = ledger.escrow("alice", "session-1", 500);
        let err = ledger
            .verify_bond("alice", "session-1", 1000)
            .expect_err("amount mismatch should fail");
        match err {
            BondError::AmountMismatch {
                expected_sats,
                actual_sats,
                ..
            } => {
                assert_eq!(expected_sats, 1000);
                assert_eq!(actual_sats, 500);
            }
            other => panic!("expected AmountMismatch, got {other:?}"),
        }
    }

    #[test]
    fn resolve_refund_changes_status() {
        let ledger = MockBondLedger::new();
        let id = ledger.escrow("alice", "session-1", 500);
        let record = ledger
            .resolve_bond(&id, BondResolution::Refund(RefundReason::RoundCompleted))
            .expect("resolve should succeed");
        assert!(matches!(
            record.status,
            BondStatus::Resolved(BondResolution::Refund(RefundReason::RoundCompleted))
        ));
    }

    #[test]
    fn resolve_slash_changes_status() {
        let ledger = MockBondLedger::new();
        let id = ledger.escrow("alice", "session-1", 500);
        let record = ledger
            .resolve_bond(&id, BondResolution::Slash(SlashReason::NoSignDuringSigning))
            .expect("resolve should succeed");
        assert!(matches!(
            record.status,
            BondStatus::Resolved(BondResolution::Slash(SlashReason::NoSignDuringSigning))
        ));
    }

    #[test]
    fn double_resolve_is_rejected() {
        let ledger = MockBondLedger::new();
        let id = ledger.escrow("alice", "session-1", 500);
        ledger
            .resolve_bond(&id, BondResolution::Refund(RefundReason::RoundCompleted))
            .unwrap();
        let err = ledger
            .resolve_bond(&id, BondResolution::Refund(RefundReason::RoundCompleted))
            .expect_err("second resolve should fail");
        match err {
            BondError::AlreadyResolved { bond_id } => assert_eq!(bond_id, id),
            other => panic!("expected AlreadyResolved, got {other:?}"),
        }
    }

    #[test]
    fn verify_resolved_bond_is_rejected() {
        let ledger = MockBondLedger::new();
        let id = ledger.escrow("alice", "session-1", 500);
        ledger
            .resolve_bond(&id, BondResolution::Refund(RefundReason::RoundCompleted))
            .unwrap();
        // After resolution, verifying must fail — a resolved bond can't
        // back a fresh registration.
        let err = ledger
            .verify_bond("alice", "session-1", 500)
            .expect_err("resolved bond can't reverify");
        assert!(matches!(err, BondError::AlreadyResolved { .. }));
    }

    #[test]
    fn snapshot_returns_full_record() {
        let ledger = MockBondLedger::new();
        let id = ledger.escrow("alice", "session-1", 500);
        let snap = ledger.snapshot_bond(&id).unwrap();
        assert_eq!(snap.bond_id, id);
        assert_eq!(snap.ghost_id, "alice");
        assert_eq!(snap.session_id, "session-1");
        assert_eq!(snap.amount_sats, 500);
        assert!(matches!(snap.status, BondStatus::Escrowed));
    }

    // -- Bond size derives from tier (cross-module sanity) --------------

    #[test]
    fn tier_bond_amounts_match_design_doc() {
        // From DESIGN_LITE.md §11/§12: 0.5% of denom.
        // Pinning here so that any change to tier or LITE_BOND_BPS shows
        // up here and not just as silently-broken bonds.
        assert_eq!(LiteTier::Denom100kSats.bond_sats(), 500);
        assert_eq!(LiteTier::Denom1mSats.bond_sats(), 5_000);
        assert_eq!(LiteTier::Denom10mSats.bond_sats(), 50_000);
        assert_eq!(LiteTier::Denom100mSats.bond_sats(), 500_000);
    }

    #[test]
    fn ledger_can_hold_bonds_for_multiple_participants_in_one_session() {
        let ledger = MockBondLedger::new();
        let id_a = ledger.escrow("alice", "session-1", 500);
        let id_b = ledger.escrow("bob", "session-1", 500);
        assert_ne!(id_a, id_b);
        assert_eq!(ledger.len(), 2);
        assert_eq!(ledger.verify_bond("alice", "session-1", 500).unwrap(), id_a);
        assert_eq!(ledger.verify_bond("bob", "session-1", 500).unwrap(), id_b);
    }

    #[test]
    fn one_participant_multiple_sessions_get_distinct_bonds() {
        // A real wallet may have rounds in flight at multiple tiers
        // simultaneously — distinct bonds must be tracked separately.
        let ledger = MockBondLedger::new();
        let id_1 = ledger.escrow("alice", "session-1", 500);
        let id_2 = ledger.escrow("alice", "session-2", 500);
        assert_ne!(id_1, id_2);
        assert_eq!(ledger.verify_bond("alice", "session-1", 500).unwrap(), id_1);
        assert_eq!(ledger.verify_bond("alice", "session-2", 500).unwrap(), id_2);
    }

    #[test]
    fn refund_reasons_are_serde_round_trippable() {
        // The wire format for bond resolutions has to be stable across
        // coordinator pool updates — pin every variant.
        for reason in [
            RefundReason::RoundCompleted,
            RefundReason::WithdrewDuringFilling,
            RefundReason::RoundVoided,
            RefundReason::CoordinatorAborted,
        ] {
            let serialised = serde_json::to_string(&reason).unwrap();
            let back: RefundReason = serde_json::from_str(&serialised).unwrap();
            assert_eq!(reason, back);
        }
        {
            let reason = SlashReason::NoSignDuringSigning;
            let serialised = serde_json::to_string(&reason).unwrap();
            let back: SlashReason = serde_json::from_str(&serialised).unwrap();
            assert_eq!(reason, back);
        }
    }

    // -- auto-escrow mode -----------------------------------------------

    #[test]
    fn auto_escrow_creates_record_on_first_verify() {
        let ledger = MockBondLedger::with_auto_escrow();
        // No escrow() call — verify_bond should lazily create a record.
        let id = ledger
            .verify_bond("alice", "session-1", 500)
            .expect("auto-escrow must succeed without a prior escrow");
        // Record persists — second call returns the same id.
        let again = ledger
            .verify_bond("alice", "session-1", 500)
            .expect("verify_bond on the auto-created record must succeed");
        assert_eq!(id, again);
        assert_eq!(ledger.len(), 1, "auto-escrow created exactly one record");
    }

    #[test]
    fn auto_escrow_still_enforces_amount_match() {
        // Auto-escrow lazily creates with whatever amount was first
        // requested. Subsequent verifies with a DIFFERENT amount
        // must still fail with AmountMismatch — auto-escrow doesn't
        // bypass amount checking, only the existence check.
        let ledger = MockBondLedger::with_auto_escrow();
        ledger
            .verify_bond("alice", "session-1", 500)
            .expect("first verify creates record at amount 500");
        let result = ledger.verify_bond("alice", "session-1", 1000);
        assert!(matches!(result, Err(BondError::AmountMismatch { .. })));
    }

    #[test]
    fn default_ledger_does_not_auto_escrow() {
        // The plain new() ledger preserves existing behaviour:
        // verify_bond without a prior escrow returns NotBonded.
        let ledger = MockBondLedger::new();
        let result = ledger.verify_bond("alice", "session-1", 500);
        assert!(matches!(result, Err(BondError::NotBonded { .. })));
    }
}
