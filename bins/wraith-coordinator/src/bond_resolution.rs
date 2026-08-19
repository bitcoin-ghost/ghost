//! Bond resolution at round terminal transitions.
//!
//! When a round reaches `Complete` (successful broadcast) or `Failed`
//! (assembly / broadcast rejection), every participant's L2 bond must
//! be settled with the `BondLedger`. This module handles that walk.
//!
//! Bond IDs come from `inputs_store`: at /inputs time the coordinator
//! calls `BondLedger::verify_bond(ghost_id, session_id, expected_sats)`
//! and stores the returned `BondId` on the participant's
//! `AcceptedInputs` record. By round terminal time we already have a
//! confirmed-correct mapping from ghost_id to BondId for everyone who
//! made it past /inputs.
//!
//! What this module does NOT cover (intentionally):
//!
//!   - Filling → Failed (no-quorum) bond cleanup. Those participants
//!     never hit /inputs so the coordinator has no verified BondIds
//!     for them. The wallet's bond ledger client (phase C) will need
//!     to scan for orphaned escrows by (ghost_id, session_id) and
//!     refund directly. Out of scope until phase C.
//!
//!   - No-sign deadline + slashing. Today every enrolled participant
//!     must submit a /witness for the round to advance. The deadline
//!     path (B/5e) will mark non-signers' bonds as
//!     `Slash(NoSignDuringSigning)` and signers' bonds as
//!     `Refund(RoundVoided)` if the round fails to broadcast as a
//!     result of those non-signs. Adding a background timer touches
//!     enough of the runtime to deserve its own commit.
//!
//! Errors during resolution are logged but do not fail the round —
//! the on-chain transaction is already broadcast (or the round is
//! already failed) by the time we get here, so a flaky ledger
//! shouldn't undo that. Operators reconcile from logs + ghost-pay
//! audit records.

use std::sync::Arc;

use tracing::{info, warn};

use wraith_protocol::{
    BondLedger, BondResolution, LiteSessionState, RefundReason, SessionGossipEvent, SlashReason,
};

use crate::inputs::AcceptedInputs;
use crate::state::CoordinatorState;

/// Outcome of a bond-resolution pass. Surfaced in logs and (in
/// future) in the round-status endpoint so operators can confirm
/// every participant got their bond returned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolutionSummary {
    /// Number of bonds successfully resolved.
    pub resolved: u32,
    /// Number of bonds that failed to resolve. Each failure is logged
    /// at warn-level with the offending ghost_id and the underlying
    /// error from the ledger.
    pub failed: u32,
    /// Number of inputs that had no bond_id stored (the
    /// "should-not-happen but defensive" case — every entry written
    /// by /inputs has a verified BondId, so this should always be 0).
    pub skipped: u32,
}

/// Walk the per-session input set and resolve each participant's
/// bond with the supplied resolution.
///
/// Idempotent at the ledger layer: re-calling against an already-
/// resolved bond returns `BondError::AlreadyResolved`, which we log
/// and count as `failed`. The function never panics, never returns
/// an error type — it always returns a summary so the caller can
/// proceed with the terminal transition unconditionally.
pub fn resolve_round_bonds(
    ledger: &Arc<dyn BondLedger>,
    session_id: &str,
    inputs: &[AcceptedInputs],
    resolution: BondResolution,
) -> ResolutionSummary {
    // A failed resolve leaves the bond stranded as `escrowed` (the participant's
    // sats stay withheld) with no recovery, so retry transient failures (a brief
    // ghost-pay blip/restart, a rate-limit on the path) with backoff before
    // giving up. resolve_bond is idempotent — re-resolving an already-resolved
    // bond returns AlreadyResolved and never double-credits — so retrying after a
    // lost-response success is safe.
    const MAX_ATTEMPTS: u32 = 4;
    let mut summary = ResolutionSummary::default();
    for input in inputs {
        let mut last_err = None;
        for attempt in 1..=MAX_ATTEMPTS {
            match ledger.resolve_bond(&input.bond_id, resolution.clone()) {
                Ok(_record) => {
                    info!(
                        %session_id,
                        ghost_id = %input.ghost_id,
                        bond_id = %input.bond_id,
                        ?resolution,
                        attempt,
                        "bond resolved",
                    );
                    summary.resolved += 1;
                    last_err = None;
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                    if attempt < MAX_ATTEMPTS {
                        // 200ms, 400ms, 800ms backoff (resolve_bond is blocking).
                        std::thread::sleep(std::time::Duration::from_millis(
                            200u64 * (1 << (attempt - 1)),
                        ));
                    }
                }
            }
        }
        if let Some(e) = last_err {
            warn!(
                %session_id,
                ghost_id = %input.ghost_id,
                bond_id = %input.bond_id,
                ?resolution,
                attempts = MAX_ATTEMPTS,
                error = %e,
                "bond resolution failed after retries — bond may remain escrowed",
            );
            summary.failed += 1;
        }
    }
    summary
}

/// Outcome of a no-sign deadline sweep — partition + counts.
#[derive(Debug, Clone, Default)]
pub struct NoSignSweepSummary {
    /// Non-signers slashed with `Slash(NoSignDuringSigning)`.
    pub slashed: u32,
    /// In-window signers refunded with `Refund(RoundVoided)`.
    pub refunded: u32,
    /// True if no bond ledger was configured. The session still
    /// transitions to Failed; bonds are reconciled out of band.
    pub ledger_missing: bool,
}

/// Run the no-sign-deadline sweep on a session. Walks inputs_store,
/// partitions into signers (their ghost_id appears in
/// witnesses_store) and non-signers; slashes non-signers, refunds
/// signers as RoundVoided, and emits a Failed StateChanged event
/// for the session.
///
/// Pure side-effects on the supplied state — no HTTP response, no
/// channel notifications. Caller (background tick OR /witness
/// handler) decides what to do with the summary.
pub fn execute_no_sign_sweep(state: &CoordinatorState, session_id: &str) -> NoSignSweepSummary {
    let inputs = state
        .inputs_store
        .lock()
        .expect("inputs_store poisoned")
        .get(session_id)
        .cloned()
        .unwrap_or_default();
    let witnesses = state
        .witnesses_store
        .lock()
        .expect("witnesses_store poisoned")
        .get(session_id)
        .cloned()
        .unwrap_or_default();

    let signers: std::collections::HashSet<String> =
        witnesses.into_iter().map(|w| w.ghost_id).collect();
    let (present, absent): (Vec<AcceptedInputs>, Vec<AcceptedInputs>) = inputs
        .into_iter()
        .partition(|i| signers.contains(&i.ghost_id));

    // Ban the coins that killed the round, before anything that depends
    // on a backend being configured. This is what replaces the bond
    // (#699): a disruptor must buy a fresh coin on-chain to try again,
    // and that holds whether or not any ledger is wired.
    let now = state.now();
    for entry in &absent {
        match crate::utxo_source::parse_outpoint(&entry.input.txid, entry.input.vout) {
            Ok(outpoint) => {
                state.bans.ban(outpoint, now);
            }
            // Unreachable in practice: /inputs parses the outpoint before
            // accepting the record. Log rather than panic — a stored
            // record we cannot parse must not stop the sweep resolving
            // everyone else.
            Err(detail) => warn!(
                %session_id,
                ghost_id = %entry.ghost_id,
                %detail,
                "could not ban a non-signer's outpoint",
            ),
        }
    }

    let summary = match state.bond_ledger.as_ref() {
        Some(ledger) => {
            let slashed = resolve_round_bonds(
                ledger,
                session_id,
                &absent,
                BondResolution::Slash(SlashReason::NoSignDuringSigning),
            );
            let refunded = resolve_round_bonds(
                ledger,
                session_id,
                &present,
                BondResolution::Refund(RefundReason::RoundVoided),
            );
            info!(
                %session_id,
                slashed = slashed.resolved,
                refunded = refunded.resolved,
                "no-sign deadline sweep complete",
            );
            NoSignSweepSummary {
                slashed: slashed.resolved,
                refunded: refunded.resolved,
                ledger_missing: false,
            }
        }
        None => {
            warn!(%session_id, "no bond ledger; can't sweep no-sign deadline");
            NoSignSweepSummary {
                slashed: 0,
                refunded: 0,
                ledger_missing: true,
            }
        }
    };

    let reason = if summary.ledger_missing {
        "witness:no_sign_deadline_no_ledger"
    } else {
        "witness:no_sign_deadline"
    };
    let _ = state
        .sessions
        .apply_event(SessionGossipEvent::StateChanged {
            session_id: session_id.to_string(),
            new_state: LiteSessionState::Failed {
                reason: reason.into(),
            },
        });

    // Drop the deadline entry so a subsequent tick doesn't re-sweep.
    state
        .signing_deadlines
        .lock()
        .expect("signing_deadlines poisoned")
        .remove(session_id);

    summary
}
