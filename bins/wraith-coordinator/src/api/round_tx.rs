//! `GET /api/v1/session/:session_id/round-tx` — fetch the assembled
//! unsigned round transaction.
//!
//! Available once `/outputs` has collected its Nth submission and
//! tx assembly succeeded. Wallets poll this between `/outputs` and
//! the upcoming `/witness` (B/5c) so they can sign their own input
//! against the canonical round transaction.
//!
//! The response carries the unsigned tx as hex plus per-output structure
//! (index, kind, value) so a participant can verify their mixed output is
//! present at the right denomination before signing.
//!
//! # It must never carry participant attribution
//!
//! A participant finds their own output by matching their own
//! `mixed_output_address` against the transaction. They do not need, and must
//! not be told, which output belongs to anybody else.
//!
//! The outputs are shuffled with ChaCha20 precisely so that no one — not even
//! the coordinator — can recover the input-to-output mapping. Publishing a
//! per-output `participant_id` hands that mapping straight back: inputs are in
//! registration order, so index *i* of `prevouts` plus attribution on the
//! outputs is the complete answer key. This endpoint is unauthenticated, so
//! anyone who can reach the coordinator could read it.
//!
//! `no_participant_attribution_is_ever_serialised` is a permanent regression
//! test. Do not add a field that identifies whose output an output is, however
//! useful it looks for debugging.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use wraith_protocol::{LiteOutputKind, LiteSessionState};

use crate::state::CoordinatorState;

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    detail: String,
}

#[derive(Debug, Serialize)]
pub struct OutputProvenanceWire {
    pub tx_output_index: usize,
    /// `mixed` / `change` / `service_fee` — stable lowercase strings.
    pub kind: &'static str,
    pub amount_sats: u64,
}

#[derive(Debug, Serialize)]
pub struct ResponseBody {
    pub session_id: String,
    /// Hex-encoded unsigned bitcoin transaction (consensus serialised).
    pub unsigned_tx_hex: String,
    /// Hex-encoded txid the eventual signed tx will commit to.
    pub txid: String,
    pub mining_fee_sats: u64,
    pub output_provenance: Vec<OutputProvenanceWire>,
    /// Per-input prevouts, in `unsigned_tx.input` order. Required for
    /// BIP-341 (Taproot) sighash computation — the wallet needs the
    /// scriptPubKey + amount of EVERY input, not just its own. For
    /// BIP-143 (P2WPKH) sighash only the wallet's own prevout is
    /// strictly needed, but exposing all of them uniformly keeps
    /// the wire format simple.
    pub prevouts: Vec<PrevOutWire>,
    /// Unix-seconds the round was assembled (per the coordinator's
    /// clock).
    pub assembled_at: u64,
}

#[derive(Debug, Serialize)]
pub struct PrevOutWire {
    pub scriptpubkey_hex: String,
    pub value_sats: u64,
}

pub async fn get(
    State(state): State<Arc<CoordinatorState>>,
    Path(session_id): Path<String>,
) -> Response {
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

    // Assembled tx is only meaningful in Signing or Broadcasting state.
    // In Failed it tells us nothing useful (the tx was never built or
    // was built and then thrown out); in Filling/Locked it doesn't
    // exist yet.
    match &session.state {
        LiteSessionState::Signing | LiteSessionState::Broadcasting | LiteSessionState::Complete => {
        }
        other => {
            return error(
                StatusCode::CONFLICT,
                "wrong_session_state",
                format!(
                    "round-tx is only available in signing/broadcasting/complete; \
                     session is currently '{}'",
                    other.as_str()
                ),
            );
        }
    }

    let assembled = match state
        .assembled_rounds
        .lock()
        .expect("assembled_rounds poisoned")
        .get(&session_id)
        .cloned()
    {
        Some(a) => a,
        None => {
            return error(
                StatusCode::NOT_FOUND,
                "round_not_assembled",
                "round transaction has not been assembled yet — \
                 wait for /outputs to collect all submissions"
                    .into(),
            );
        }
    };

    let provenance = assembled
        .round
        .output_provenance
        .iter()
        .map(|p| OutputProvenanceWire {
            tx_output_index: p.tx_output_index,
            kind: kind_str(p.kind),
            amount_sats: p.amount_sats,
        })
        .collect();

    // Walk inputs_store in tx-input order to build the prevouts
    // wire array. The assembly path adds participants in
    // arrival/registration order and the LiteRoundBuilder preserves
    // that order for inputs (only outputs get shuffled), so
    // inputs_store[i] aligns with assembled.tx.input[i].
    let inputs_snapshot = state
        .inputs_store
        .lock()
        .expect("inputs_store poisoned")
        .get(&session_id)
        .cloned()
        .unwrap_or_default();
    let mut prevouts = Vec::with_capacity(inputs_snapshot.len());
    for inp in &inputs_snapshot {
        prevouts.push(PrevOutWire {
            scriptpubkey_hex: inp.input.scriptpubkey_hex.clone(),
            value_sats: inp.input.value_sats,
        });
    }

    let body = ResponseBody {
        session_id,
        unsigned_tx_hex: assembled.unsigned_tx_hex.clone(),
        txid: assembled.round.txid().to_string(),
        mining_fee_sats: assembled.round.mining_fee_sats,
        output_provenance: provenance,
        prevouts,
        assembled_at: assembled.assembled_at,
    };
    (StatusCode::OK, Json(body)).into_response()
}

fn kind_str(k: LiteOutputKind) -> &'static str {
    match k {
        LiteOutputKind::Mixed => "mixed",
        LiteOutputKind::ServiceFee => "service_fee",
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// **Permanent regression test.** v1 published a per-output `participant_id`
    /// over this unauthenticated endpoint, which is the complete input-to-output
    /// mapping the ChaCha20 output shuffle exists to destroy: inputs are served
    /// in registration order, so attribution on the outputs is the answer key.
    ///
    /// If this fails, someone re-added participant attribution. A participant
    /// locates their own output by matching their own address, and never needs
    /// to be told whose any other output is.
    #[test]
    fn no_participant_attribution_is_ever_serialised() {
        let body = ResponseBody {
            session_id: "s-1".into(),
            unsigned_tx_hex: "00".into(),
            txid: "ab".repeat(32),
            mining_fee_sats: 1_234,
            output_provenance: vec![
                OutputProvenanceWire {
                    tx_output_index: 0,
                    kind: "mixed",
                    amount_sats: 100_000,
                },
                OutputProvenanceWire {
                    tx_output_index: 1,
                    kind: "mixed",
                    amount_sats: 100_000,
                },
                OutputProvenanceWire {
                    tx_output_index: 2,
                    kind: "service_fee",
                    amount_sats: 1_000,
                },
            ],
            prevouts: vec![],
            assembled_at: 0,
        };

        let json = serde_json::to_string(&body).expect("serialises");

        for banned in ["participant_id", "participant", "owner", "ghost_id"] {
            assert!(
                !json.contains(banned),
                "round-tx response leaks participant attribution via `{banned}`: {json}"
            );
        }
    }

    /// Structure a participant legitimately needs is still there — this is not
    /// a licence to strip the endpoint of everything useful.
    #[test]
    fn structural_verification_data_is_retained() {
        let body = ResponseBody {
            session_id: "s-1".into(),
            unsigned_tx_hex: "00".into(),
            txid: "ab".repeat(32),
            mining_fee_sats: 1_234,
            output_provenance: vec![OutputProvenanceWire {
                tx_output_index: 0,
                kind: "mixed",
                amount_sats: 100_000,
            }],
            prevouts: vec![],
            assembled_at: 0,
        };
        let json = serde_json::to_string(&body).expect("serialises");
        for needed in [
            "tx_output_index",
            "kind",
            "amount_sats",
            "mining_fee_sats",
            "txid",
        ] {
            assert!(
                json.contains(needed),
                "dropped data a participant needs: {needed}"
            );
        }
    }
}
