//! `POST /api/v1/session/:session_id/outputs` — anonymous output
//! submission.
//!
//! Each wallet submits its unblinded mix-output address here over a
//! fresh anonymous connection (Tor circuit / separate IP / new auth
//! token — the wire-level anonymity layer is the wallet's job, the
//! coordinator just enforces *not* knowing which participant the
//! submission belongs to). The Schnorr signature attached to the
//! submission is the one the coordinator blind-signed in B/4b; here
//! we verify it with the per-round signing key.
//!
//! Critically, the request body has **no ghost_id**. That's
//! deliberate. If the request carried any participant identifier the
//! coordinator could correlate input UTXO ↔ output address and the
//! whole privacy story is gone.
//!
//! Verification path:
//!   - Session exists and is in `Signing` state.
//!   - The per-round signer was created (ie. someone called /nonce —
//!     a session in Signing always has a signer because the wallet
//!     flow is /inputs → /nonce → /blind-sign → /outputs).
//!   - Reconstruct an `UnblindedToken` from the body + the
//!     coordinator's own `signer.key_id()`, run it through
//!     `TokenVerifier::verify`. Pass → accept; fail → 403.
//!   - Reject duplicate addresses (a single submission per output;
//!     the same address from two different blind sigs is suspicious).
//!
//! Out of scope here:
//!   - Address parsing against the coordinator's `Network`. We do that
//!     check (it's cheap and catches misconfigured wallets early)
//!     before the crypto check, so a typo isn't accepted as a "valid
//!     signed garbage address".
//!   - Tx assembly. Once `outputs.len() == enrolled_count` the round
//!     is ready to be built; that's B/5b.

use std::str::FromStr;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use bitcoin::Address;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use wraith_protocol::{
    BondResolution, LiteSessionState, RefundReason, SessionGossipEvent, TokenVerifier,
    UnblindedToken,
};

use crate::assembly::try_assemble_if_ready;
use crate::bond_resolution::resolve_round_bonds;
use crate::outputs::AcceptedOutput;
use crate::state::CoordinatorState;

#[derive(Debug, Deserialize)]
pub struct Request {
    /// The unblinded mix-output destination address. Must parse
    /// against the coordinator's network.
    pub address: String,
    /// Hex-encoded blinded nonce R' (33-byte SEC1 compressed point).
    /// Wallet supplies this from `BlindingContext::blinded_nonce()`.
    pub blinded_nonce_point: String,
    /// Hex-encoded unblinded signature scalar s' (32 bytes). Wallet
    /// supplies this from the `UnblindedToken::signature_scalar`
    /// field returned by `BlindingContext::unblind`.
    pub unblinded_signature_scalar: String,
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
    pub outputs_collected: u32,
    pub enrolled_count: u32,
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

    // Address must parse against the coordinator's network. Caught
    // before the crypto check so a misconfigured wallet learns
    // immediately rather than getting a generic "verification failed".
    let parsed = match Address::from_str(req.address.trim()) {
        Ok(a) => a,
        Err(e) => {
            return error(
                StatusCode::BAD_REQUEST,
                "bad_address",
                format!("could not parse '{}': {e}", req.address),
            );
        }
    };
    if parsed.is_valid_for_network(state.network) {
        // ok — proceed
    } else {
        return error(
            StatusCode::BAD_REQUEST,
            "wrong_network",
            format!(
                "address is not valid for network '{}'",
                state.network_name()
            ),
        );
    }

    let blinded_nonce_bytes = match decode_33(&req.blinded_nonce_point) {
        Ok(b) => b,
        Err(detail) => return error(StatusCode::BAD_REQUEST, "bad_blinded_nonce_point", detail),
    };
    let signature_bytes = match decode_32(&req.unblinded_signature_scalar) {
        Ok(b) => b,
        Err(detail) => {
            return error(
                StatusCode::BAD_REQUEST,
                "bad_unblinded_signature_scalar",
                detail,
            );
        }
    };

    // Per-round signer must already exist (ie. /nonce was called by
    // *some* participant on this round). If absent, /outputs has
    // nothing to verify against.
    let signer = {
        let signers = state.signers.lock().expect("signers poisoned");
        match signers.get(&session_id) {
            Some(s) => s.clone(),
            None => {
                return error(
                    StatusCode::CONFLICT,
                    "no_active_signer",
                    "round signer is not initialised; participants must run /nonce first".into(),
                );
            }
        }
    };

    // Snapshot the verifier inputs while we hold the signer lock,
    // then drop the lock before doing the (bounded but non-trivial)
    // crypto check. Keeps the lock window short.
    let (signer_pubkey, signer_session_id, signer_key_id) = {
        let guard = signer.lock().expect("signer poisoned");
        (*guard.public_key(), *guard.session_id(), *guard.key_id())
    };

    let token = UnblindedToken {
        message: req.address.as_bytes().to_vec(),
        nonce_point: blinded_nonce_bytes,
        signature_scalar: signature_bytes,
        session_key_id: signer_key_id,
    };
    let verifier = TokenVerifier::new(signer_pubkey, &signer_session_id);
    let valid = match verifier.verify(&token) {
        Ok(v) => v,
        Err(e) => {
            warn!(%session_id, ?e, "TokenVerifier returned error during /outputs");
            return error(
                StatusCode::FORBIDDEN,
                "verification_failed",
                "signature verification failed".into(),
            );
        }
    };
    if !valid {
        return error(
            StatusCode::FORBIDDEN,
            "verification_failed",
            "signature verification failed".into(),
        );
    }

    // Reject duplicate addresses for this session. Any single
    // participant should submit only one output; if the same address
    // arrives twice, it's either a wallet retry on a transient network
    // failure (still bad — the second submission is redundant work and
    // a second consumed crypto budget) or an attacker trying to flood.
    let enrolled_count = session.participants.len() as u32;
    let outputs_collected = {
        let mut store = state.outputs_store.lock().expect("outputs_store poisoned");
        let entry = store.entry(session_id.clone()).or_default();
        if entry.iter().any(|o| o.address == req.address) {
            return error(
                StatusCode::CONFLICT,
                "duplicate_output",
                "this output address has already been accepted for this round".into(),
            );
        }
        if entry.len() as u32 >= enrolled_count {
            // Over-submission. The output set is already full — a
            // valid sig on an extra address means either the wallet
            // double-signed or there's a protocol bug. Either way,
            // reject so the round set stays exactly N.
            return error(
                StatusCode::CONFLICT,
                "outputs_full",
                format!("round already has {enrolled_count} outputs; further submissions rejected"),
            );
        }
        entry.push(AcceptedOutput {
            address: req.address.clone(),
            accepted_at: now,
        });
        entry.len() as u32
    };

    debug!(
        %session_id,
        outputs_collected,
        enrolled_count,
        "/outputs accepted unblinded address",
    );

    // If this is the Nth (final) submission, assemble the round
    // transaction synchronously. We hold no locks across the build
    // step — snapshot inputs + outputs first, then build, then store.
    let mut final_state = session.state.clone();
    if outputs_collected == enrolled_count {
        let inputs_snapshot = state
            .inputs_store
            .lock()
            .expect("inputs_store poisoned")
            .get(&session_id)
            .cloned()
            .unwrap_or_default();
        let outputs_snapshot = state
            .outputs_store
            .lock()
            .expect("outputs_store poisoned")
            .get(&session_id)
            .cloned()
            .unwrap_or_default();
        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy).expect("OS CSPRNG failed during round assembly");
        let round_ctx = crate::assembly::RoundContext {
            session_id: &session_id,
            tier: session.tier,
            session_type: session.session_type,
            network: state.network,
            coordinator_fee_address: state.coordinator_fee_address.as_deref(),
            inputs: &inputs_snapshot,
            outputs: &outputs_snapshot,
            entropy: &entropy,
        };
        match try_assemble_if_ready(
            round_ctx,
            session.state.clone(),
            enrolled_count as usize,
            now,
        ) {
            Some(Ok(assembled)) => {
                state
                    .assembled_rounds
                    .lock()
                    .expect("assembled_rounds poisoned")
                    .insert(session_id.clone(), assembled);
            }
            Some(Err(e)) => {
                // Transition to Failed and refund bonds (assembly
                // failure isn't any single participant's fault — it's
                // a coordinator-side data problem). Slashing only
                // happens via the no-sign deadline path (B/5e).
                let reason = format!("tx_assembly:{}", e.code());
                warn!(%session_id, ?e, "assembly failed; transitioning session to Failed");
                if let Some(ledger) = state.bond_ledger.as_ref() {
                    let inputs = state
                        .inputs_store
                        .lock()
                        .expect("inputs_store poisoned")
                        .get(&session_id)
                        .cloned()
                        .unwrap_or_default();
                    let _ = resolve_round_bonds(
                        ledger,
                        &session_id,
                        &inputs,
                        BondResolution::Refund(RefundReason::CoordinatorAborted),
                    );
                }
                let _ = state
                    .sessions
                    .apply_event(SessionGossipEvent::StateChanged {
                        session_id: session_id.clone(),
                        new_state: LiteSessionState::Failed {
                            reason: reason.clone(),
                        },
                    });
                final_state = LiteSessionState::Failed { reason };
            }
            None => {
                // try_assemble_if_ready returns None when the
                // session isn't actually ready — should be unreachable
                // here because we just confirmed counts match.
                warn!(%session_id, "try_assemble_if_ready returned None despite count match");
            }
        }
    }

    (
        StatusCode::OK,
        Json(ResponseBody {
            session_id,
            state: final_state.as_str().to_string(),
            outputs_collected,
            enrolled_count,
        }),
    )
        .into_response()
}

fn decode_32(s: &str) -> Result<[u8; 32], String> {
    let raw = hex::decode(s).map_err(|e| format!("not valid hex: {e}"))?;
    if raw.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", raw.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn decode_33(s: &str) -> Result<[u8; 33], String> {
    let raw = hex::decode(s).map_err(|e| format!("not valid hex: {e}"))?;
    if raw.len() != 33 {
        return Err(format!("expected 33 bytes, got {}", raw.len()));
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(&raw);
    Ok(out)
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
