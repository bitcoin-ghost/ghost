//! No-sign deadline sweep.
//!
//! Every enrolled participant must submit a `/witness` for the round to
//! advance. Past the deadline the round cannot complete, so the
//! coordinator fails it and puts the coins that never signed into
//! cooldown (#699).
//!
//! This used to settle L2 bonds instead — slashing non-signers, refunding
//! signers. Bonds are gone: they required an escrow in ghost-pay that was
//! never built, they charged honest participants for the privilege of
//! joining, and their whole purpose was to make disruption expensive,
//! which an outpoint cooldown does without holding anyone's money.
//!
//! Only the coins that failed to sign are banned. A participant who signed
//! and lost the round anyway did nothing wrong and pays nothing.
//!
//! Side-effects on the supplied state only — no HTTP response, no channel
//! notifications. The caller (the background tick, or the `/witness`
//! handler when someone pings past the deadline) decides what to do with
//! the summary.

use tracing::{info, warn};

use wraith_protocol::{LiteSessionState, SessionGossipEvent};

use crate::inputs::AcceptedInputs;
use crate::state::CoordinatorState;

/// Outcome of a no-sign deadline sweep.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NoSignSweepSummary {
    /// Participants who never signed. Their outpoints are now in
    /// cooldown.
    pub banned: u32,
    /// Participants who did sign before the deadline. Recorded so an
    /// operator reading the logs can tell a round that nobody joined
    /// from one that a minority killed.
    pub signed: u32,
    /// Non-signers whose stored outpoint could not be parsed, so no ban
    /// could be applied. Should always be 0 — `/inputs` parses the
    /// outpoint before accepting the record.
    pub unbannable: u32,
}

/// Fail a session whose signing deadline has passed, and ban the coins
/// that did not sign.
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

    let now = state.now();
    let mut summary = NoSignSweepSummary {
        signed: present.len() as u32,
        ..Default::default()
    };
    // Every rung a non-signer brought is banned, not just the first. Banning
    // one of a ladder participant's coins leaves the others free to disrupt the
    // next round at no cost, which is the cooldown doing nothing.
    for entry in &absent {
        for rung in &entry.inputs {
            match crate::utxo_source::parse_outpoint(&rung.txid, rung.vout) {
                Ok(outpoint) => {
                    state.bans.ban(outpoint, now);
                    summary.banned += 1;
                }
                // Unreachable in practice: `/inputs` parses the outpoint
                // before accepting the record. Logged rather than fatal — one
                // unparseable record must not stop the rest of the sweep.
                Err(detail) => {
                    warn!(
                        %session_id,
                        ghost_id = %entry.ghost_id,
                        %detail,
                        "could not ban a non-signer's outpoint",
                    );
                    summary.unbannable += 1;
                }
            }
        }
    }

    info!(
        %session_id,
        banned = summary.banned,
        signed = summary.signed,
        "no-sign deadline sweep complete",
    );

    let _ = state
        .sessions
        .apply_event(SessionGossipEvent::StateChanged {
            session_id: session_id.to_string(),
            new_state: LiteSessionState::Failed {
                reason: "witness:no_sign_deadline".into(),
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
