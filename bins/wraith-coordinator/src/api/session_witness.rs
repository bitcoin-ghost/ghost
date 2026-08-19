//! `POST /api/v1/session/:session_id/witness` — wallet submits the
//! signed witness for its input.
//!
//! After tx assembly (B/5b), each enrolled participant fetches the
//! unsigned tx via `/round-tx`, computes the sighash for its own input
//! against the canonical tx, signs it, and posts the resulting
//! `bitcoin::Witness` (consensus-encoded hex) here. Once the coordinator
//! has all N witnesses it merges them into the assembled transaction
//! and asks the configured `Broadcaster` to push it to the network.
//!
//! State transitions:
//!   - `Signing` (after B/5b assembly) — handler accepts witnesses.
//!   - On the final submission: merge → broadcast → advance to
//!     `Broadcasting`, and (for v1) immediately to `Complete`. A
//!     future iteration may keep `Broadcasting` distinct so a
//!     confirmation poller can flip to Complete only after N
//!     confirmations; v1 trusts the broadcaster's success response.
//!
//! Out of scope (deferred to follow-on tasks):
//!   - Witness validation (signed-message correctness vs the
//!     prevout's scriptpubkey). Bitcoind / mempool acceptance rejects
//!     bogus witnesses anyway, so we surface those failures via
//!     `BroadcastError::Rejected`.
//!   - Nothing: the no-sign deadline is handled, here and by the
//!     background tick, via `no_sign_sweep` — it fails the round and
//!     puts the coins that never signed into cooldown (#699).

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use bitcoin::consensus::encode::deserialize;
use bitcoin::Witness;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use wraith_protocol::{LiteSessionState, SessionGossipEvent};

use crate::broadcaster::BroadcastError;
use crate::no_sign_sweep::execute_no_sign_sweep;
use crate::state::CoordinatorState;
use crate::witnesses::AcceptedWitness;

#[derive(Debug, Deserialize)]
pub struct Request {
    pub ghost_id: String,
    /// Index into `LiteRound::tx.input` this witness is for. Wallets
    /// scan the assembled tx for their own (txid, vout) and supply
    /// the matching index. Coordinator cross-checks against its own
    /// inputs_store.
    pub input_index: u32,
    /// Hex-encoded `bitcoin::Witness` (consensus-encoded
    /// length-prefixed witness stack).
    pub witness_hex: String,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    detail: String,
}

#[derive(Debug, Serialize)]
pub struct ResponseBody {
    pub session_id: String,
    pub state: String,
    pub witnesses_collected: u32,
    pub enrolled_count: u32,
    /// Set on the round-completing submission (the broadcaster's
    /// reported txid). Otherwise None.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broadcast_txid: Option<String>,
}

pub async fn post(
    State(state): State<Arc<CoordinatorState>>,
    Path(session_id): Path<String>,
    Json(req): Json<Request>,
) -> Response {
    let now = state.now();
    let _changed = state.sessions.tick(now);
    let session = match state.sessions.get(&session_id) {
        Some(s) => s,
        None => {
            return error(
                StatusCode::NOT_FOUND,
                "session_not_found",
                format!("no session with id '{session_id}'"),
            );
        }
    };

    match &session.state {
        LiteSessionState::Signing => {}
        other => {
            return error(
                StatusCode::CONFLICT,
                "wrong_session_state",
                format!(
                    "session '{session_id}' is in state '{}', expected 'signing'",
                    other.as_str()
                ),
            );
        }
    }

    // No-sign deadline check. If the deadline has expired, this
    // request kicks off the failure sweep — slashing non-signers,
    // refunding signers as RoundVoided, transitioning to Failed.
    // The current submission is rejected with 410 Gone so the
    // wallet learns its slot is no longer fillable.
    //
    // KNOWN LIMITATION: deadline only fires when SOMEONE pings the
    // coordinator. A round where every wallet drops gets stuck in
    // Signing forever. Production-readiness adds a background scan;
    // see B/5e task notes.
    let deadline = state
        .signing_deadlines
        .lock()
        .expect("signing_deadlines poisoned")
        .get(&session_id)
        .copied();
    if let Some(deadline) = deadline {
        if now >= deadline {
            warn!(%session_id, %deadline, %now, "no-sign deadline reached");
            let resp = sweep_no_sign(&state, &session_id);
            return resp;
        }
    }

    if !session
        .participants
        .iter()
        .any(|p| p.ghost_id == req.ghost_id)
    {
        return error(
            StatusCode::FORBIDDEN,
            "not_enrolled",
            format!("ghost_id '{}' not enrolled", req.ghost_id),
        );
    }

    // Witness hex must parse as a `bitcoin::Witness`. We don't
    // validate signature correctness here — that's broadcaster's job.
    let witness_bytes = match hex::decode(req.witness_hex.trim()) {
        Ok(b) => b,
        Err(e) => {
            return error(
                StatusCode::BAD_REQUEST,
                "bad_witness_hex",
                format!("witness is not valid hex: {e}"),
            );
        }
    };
    let witness: Witness = match deserialize(&witness_bytes) {
        Ok(w) => w,
        Err(e) => {
            return error(
                StatusCode::BAD_REQUEST,
                "bad_witness_encoding",
                format!("witness does not consensus-decode: {e}"),
            );
        }
    };

    // The assembled round must exist (Signing state implies B/5b's
    // /outputs path advanced through assembly). If the assembled
    // store is empty here it's a coordinator bug — the round
    // shouldn't be in Signing without an assembled tx.
    let assembled = match state
        .assembled_rounds
        .lock()
        .expect("assembled_rounds poisoned")
        .get(&session_id)
        .cloned()
    {
        Some(a) => a,
        None => {
            warn!(%session_id, "session in Signing without assembled tx — bug");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "no_assembled_round",
                "session is signing but no assembled tx exists".into(),
            );
        }
    };

    // Cross-check: the input_index the wallet supplied must match the
    // index of an input whose (txid, vout) appears in inputs_store
    // for this ghost_id. Defends against a wallet pinning a
    // wrong-index witness onto the wrong input.
    {
        let inputs_guard = state.inputs_store.lock().expect("inputs_store poisoned");
        let inputs = inputs_guard.get(&session_id).cloned().unwrap_or_default();
        let mine = inputs.iter().find(|i| i.ghost_id == req.ghost_id).cloned();
        drop(inputs_guard);

        let mine = match mine {
            Some(m) => m,
            None => {
                return error(
                    StatusCode::FORBIDDEN,
                    "no_input_for_ghost_id",
                    "no input record for this ghost_id".into(),
                );
            }
        };

        let claimed = match assembled.round.tx.input.get(req.input_index as usize) {
            Some(t) => t,
            None => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "input_index_out_of_range",
                    format!(
                        "input_index {} >= tx input count {}",
                        req.input_index,
                        assembled.round.tx.input.len()
                    ),
                );
            }
        };
        if claimed.previous_output.txid.to_string() != mine.input.txid
            || claimed.previous_output.vout != mine.input.vout
        {
            return error(
                StatusCode::BAD_REQUEST,
                "input_index_mismatch",
                "input_index does not point at this ghost_id's UTXO".into(),
            );
        }
    }

    let enrolled_count = session.participants.len() as u32;
    let witnesses_collected = {
        let mut store = state
            .witnesses_store
            .lock()
            .expect("witnesses_store poisoned");
        let entry = store.entry(session_id.clone()).or_default();
        // Idempotent: re-submitting replaces previous witness. Same
        // pattern as /inputs.
        if let Some(existing) = entry.iter_mut().find(|w| w.ghost_id == req.ghost_id) {
            *existing = AcceptedWitness {
                ghost_id: req.ghost_id.clone(),
                input_index: req.input_index,
                witness_hex: req.witness_hex.clone(),
                accepted_at: now,
            };
        } else {
            entry.push(AcceptedWitness {
                ghost_id: req.ghost_id.clone(),
                input_index: req.input_index,
                witness_hex: req.witness_hex.clone(),
                accepted_at: now,
            });
        }
        entry.len() as u32
    };

    // Drop reference to `witness` here (we keep the hex form).
    let _ = witness;

    // Final submission triggers merge + broadcast.
    if witnesses_collected < enrolled_count {
        return (
            StatusCode::OK,
            Json(ResponseBody {
                session_id,
                state: session.state.as_str().to_string(),
                witnesses_collected,
                enrolled_count,
                broadcast_txid: None,
            }),
        )
            .into_response();
    }

    // Merge witnesses into a fresh copy of the assembled tx.
    let witnesses_snapshot = state
        .witnesses_store
        .lock()
        .expect("witnesses_store poisoned")
        .get(&session_id)
        .cloned()
        .unwrap_or_default();
    let mut signed_tx = assembled.round.tx.clone();
    for w in &witnesses_snapshot {
        let raw = match hex::decode(&w.witness_hex) {
            Ok(r) => r,
            Err(e) => {
                return fail_round(
                    &state,
                    &session_id,
                    "bad_stored_witness",
                    format!("stored witness for {} did not re-decode: {e}", w.ghost_id),
                );
            }
        };
        let parsed: Witness = match deserialize(&raw) {
            Ok(w) => w,
            Err(e) => {
                return fail_round(
                    &state,
                    &session_id,
                    "bad_stored_witness",
                    format!("stored witness for {} did not re-decode: {e}", w.ghost_id),
                );
            }
        };
        let idx = w.input_index as usize;
        if idx >= signed_tx.input.len() {
            return fail_round(
                &state,
                &session_id,
                "stored_input_index_out_of_range",
                format!(
                    "stored witness for {} index {} ≥ tx input count {}",
                    w.ghost_id,
                    idx,
                    signed_tx.input.len()
                ),
            );
        }
        signed_tx.input[idx].witness = parsed;
    }

    // Broadcast.
    let broadcaster = match state.broadcaster.as_ref() {
        Some(b) => b.clone(),
        None => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "broadcaster_not_configured",
                "broadcast backend not yet wired (phase D)".into(),
            );
        }
    };

    match broadcaster.broadcast(&signed_tx) {
        Ok(network_txid) => {
            let assembled_txid = assembled.round.txid();
            if network_txid != assembled_txid {
                warn!(
                    %session_id,
                    %network_txid,
                    %assembled_txid,
                    "broadcaster reported a different txid than the one we computed",
                );
            }
            // Advance Signing → Complete in one step. (Broadcasting
            // is a future-iteration distinction for confirmation
            // tracking; v1 collapses it.)
            let _ = state
                .sessions
                .apply_event(SessionGossipEvent::StateChanged {
                    session_id: session_id.clone(),
                    new_state: LiteSessionState::Complete,
                });
            info!(%session_id, %network_txid, "round broadcast complete");
            (
                StatusCode::OK,
                Json(ResponseBody {
                    session_id,
                    state: "complete".into(),
                    witnesses_collected,
                    enrolled_count,
                    broadcast_txid: Some(network_txid.to_string()),
                }),
            )
                .into_response()
        }
        Err(BroadcastError::NotConfigured) => error(
            StatusCode::SERVICE_UNAVAILABLE,
            "broadcaster_not_configured",
            "broadcast backend not yet wired (phase D)".into(),
        ),
        Err(BroadcastError::Rejected(detail)) => fail_round(
            &state,
            &session_id,
            "broadcast_rejected",
            format!("backend rejected the round transaction: {detail}"),
        ),
        Err(BroadcastError::Unreachable(detail)) => fail_round(
            &state,
            &session_id,
            "broadcast_unreachable",
            format!("backend unreachable: {detail}"),
        ),
    }
}

/// No-sign deadline fired during a /witness submission. Delegates
/// to the shared sweep helper (also used by the background tick) and
/// wraps its summary into a 410 Gone HTTP response so the wallet
/// learns its slot is no longer fillable.
fn sweep_no_sign(state: &CoordinatorState, session_id: &str) -> Response {
    let summary = execute_no_sign_sweep(state, session_id);
    error(
        StatusCode::GONE,
        "no_sign_deadline",
        format!(
            "signing deadline expired; {} coin(s) that never signed are now in cooldown, \
             {} participant(s) signed in time and are unaffected",
            summary.banned, summary.signed
        ),
    )
}

fn fail_round(
    state: &CoordinatorState,
    session_id: &str,
    code: &'static str,
    detail: String,
) -> Response {
    let reason = format!("witness:{code}");
    warn!(%session_id, %code, %detail, "failing round during witness merge");
    // Nobody is put in cooldown: none of them caused this failure — it
    // was either a coordinator-side merge issue or a node-side
    // rejection. Cooldowns come only from the no-sign deadline sweep,
    // which actually identifies a guilty party.
    let _ = state
        .sessions
        .apply_event(SessionGossipEvent::StateChanged {
            session_id: session_id.to_string(),
            new_state: LiteSessionState::Failed { reason },
        });
    error(StatusCode::INTERNAL_SERVER_ERROR, code, detail)
}

fn error(status: StatusCode, code: &'static str, detail: String) -> Response {
    (
        status,
        Json(ErrorBody {
            error: code,
            detail,
        }),
    )
        .into_response()
}
