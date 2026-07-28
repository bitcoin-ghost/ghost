//! Schnorr blind-signature endpoints.
//!
//! Two endpoints serve the wallet's two-step blind-signing protocol:
//!
//!   1. `POST /api/v1/session/:session_id/nonce`
//!      Returns a fresh `PublicNonce R = k*G` plus the per-round signing
//!      pubkey + key id so the wallet can build a `BlindingContext`. The
//!      coordinator keeps `(k, R, ghost_id)` and consumes the nonce on
//!      the first matching `/blind-sign` call.
//!
//!   2. `POST /api/v1/session/:session_id/blind-sign`
//!      Wallet sends `BlindedChallenge { c', blind_session_id }`,
//!      coordinator returns `BlindSignatureResponse { s, … }`. Wallet
//!      then unblinds locally with `BlindingContext::unblind` to obtain a
//!      valid Schnorr signature `(R', s')` over its own message — the
//!      coordinator never learns either the message or the unblinded
//!      signature. (This is the unlinkability property — see
//!      `crates/wraith-protocol/src/blind.rs` module docstring.)
//!
//! Both endpoints require the session to be `Locked` and the
//! `ghost_id` to be enrolled. The signer is created lazily on the
//! first `/nonce` per round and reused thereafter.
//!
//! Out of scope here (B/4b is just the issuance path):
//! - `BlindLite`-style aggregation (one nonce per round, batched).
//! - Re-blinding-on-failover (DESIGN_LITE §7) — the per-round signer
//!   doesn't survive a coordinator restart yet; B/6 handles that.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use wraith_protocol::{BlindedChallenge, LiteSessionState};

use crate::state::CoordinatorState;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    detail: String,
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

/// Validate the common preconditions for both endpoints — session
/// exists, in `Locked` state, ghost_id enrolled — and return the
/// caller-friendly error response when any precondition fails.
// `Err = axum::http::Response` is the idiomatic axum early-return: the helper hands back the
// exact response the caller should send. Boxing it to satisfy result_large_err would make
// every call site unwrap a Box to return a Response, which is worse code for 128 bytes on a
// path that is already building an HTTP response.
#[allow(clippy::result_large_err)]
fn check_session(
    state: &CoordinatorState,
    session_id: &str,
    ghost_id: &str,
) -> Result<(), Response> {
    let now = state.now();
    let _changed = state.sessions.tick(now);
    let session = match state.sessions.get(session_id) {
        Some(s) => s,
        None => {
            return Err(error(
                StatusCode::NOT_FOUND,
                "session_not_found",
                format!("no session with id '{session_id}'"),
            ));
        }
    };
    // /nonce + /blind-sign run in Signing state — the wallet first
    // commits its UTXO via /inputs (which auto-advances Locked →
    // Signing once all enrolled participants have submitted), then
    // requests blind sigs over its mix-output address. Allowing /nonce
    // before /inputs would let a non-paying participant burn the
    // coordinator's crypto budget without ever escrowing a bond.
    match &session.state {
        LiteSessionState::Signing => {}
        other => {
            return Err(error(
                StatusCode::CONFLICT,
                "wrong_session_state",
                format!(
                    "session '{session_id}' is in state '{}', expected 'signing'",
                    other.as_str()
                ),
            ));
        }
    }
    if !session.participants.iter().any(|p| p.ghost_id == ghost_id) {
        return Err(error(
            StatusCode::FORBIDDEN,
            "not_enrolled",
            format!("ghost_id '{ghost_id}' is not enrolled in session '{session_id}'"),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// POST /api/v1/session/:session_id/nonce
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct NonceRequest {
    pub ghost_id: String,
}

#[derive(Debug, Serialize)]
pub struct NonceResponse {
    /// Coordinator's per-round signing pubkey, hex-encoded
    /// SEC1-compressed (33 bytes). Wallet feeds this into
    /// `BlindingContext::new` as `coordinator_pubkey` and into
    /// `TokenVerifier::new` so it can verify the unblinded signature.
    pub signing_pubkey: String,
    /// Per-round signer session id, hex-encoded (32 bytes). Stable per
    /// round. Wallet supplies this to `TokenVerifier::new(pubkey, &sid)`
    /// — the verifier derives the matching `key_id` internally so the
    /// wallet doesn't have to.
    pub signer_session_id: String,
    /// Per-round signing key id, hex-encoded (32 bytes). Wallet
    /// supplies this to `BlindingContext::unblind(response, key_id)`
    /// so the resulting `UnblindedToken` carries the right
    /// `session_key_id`.
    pub signing_key_id: String,
    /// Public nonce `R = k*G`, hex-encoded SEC1-compressed (33 bytes).
    pub nonce_point: String,
    /// Signer-internal blind-session id, hex-encoded (32 bytes). Wallet
    /// echoes this back on `/blind-sign` so the coordinator can find
    /// the matching secret nonce. This is **not** the round session id
    /// (the URL path) — it's the per-nonce id the signer uses to
    /// match secret + public halves.
    pub blind_session_id: String,
}

pub async fn post_nonce(
    State(state): State<Arc<CoordinatorState>>,
    Path(session_id): Path<String>,
    Json(req): Json<NonceRequest>,
) -> Response {
    if let Err(resp) = check_session(&state, &session_id, &req.ghost_id) {
        return resp;
    }

    let signer = match state.signer_for(&session_id) {
        Ok(s) => s,
        Err(e) => {
            warn!(?e, %session_id, "failed to instantiate per-round signer");
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "signer_init_failed",
                e.to_string(),
            );
        }
    };

    let (signing_pubkey_bytes, signing_key_id, signer_session_id, nonce) = {
        let mut guard = signer.lock().expect("signer poisoned");
        let pubkey = guard.public_key().serialize();
        let key_id = *guard.key_id();
        let signer_sid = *guard.session_id();
        match guard.create_nonce_for_participant(&req.ghost_id) {
            Ok(n) => (pubkey, key_id, signer_sid, n),
            Err(e) => {
                warn!(%session_id, ghost_id = %req.ghost_id, ?e, "create_nonce failed");
                return error(
                    StatusCode::TOO_MANY_REQUESTS,
                    "nonce_rate_limited",
                    e.to_string(),
                );
            }
        }
    };

    debug!(%session_id, ghost_id = %req.ghost_id, "issued blind-sig nonce");
    (
        StatusCode::OK,
        Json(NonceResponse {
            signing_pubkey: hex::encode(signing_pubkey_bytes),
            signer_session_id: hex::encode(signer_session_id),
            signing_key_id: hex::encode(signing_key_id),
            nonce_point: hex::encode(nonce.nonce_point),
            blind_session_id: hex::encode(nonce.session_id),
        }),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// POST /api/v1/session/:session_id/blind-sign
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct BlindSignRequest {
    pub ghost_id: String,
    /// Hex-encoded blinded challenge `c'` (32 bytes).
    pub blinded_challenge: String,
    /// Hex-encoded blind-session id from the matching `/nonce` response
    /// (32 bytes).
    pub blind_session_id: String,
}

#[derive(Debug, Serialize)]
pub struct BlindSignResponse {
    /// Hex-encoded signature scalar `s = k + c'*x` (32 bytes). Wallet
    /// computes `s' = s + α` locally to obtain the unblinded signature.
    pub signature_scalar: String,
    /// Echoed blind-session id (32 bytes hex).
    pub blind_session_id: String,
}

pub async fn post_blind_sign(
    State(state): State<Arc<CoordinatorState>>,
    Path(session_id): Path<String>,
    Json(req): Json<BlindSignRequest>,
) -> Response {
    if let Err(resp) = check_session(&state, &session_id, &req.ghost_id) {
        return resp;
    }

    let challenge_bytes = match decode_32(&req.blinded_challenge) {
        Ok(b) => b,
        Err(detail) => return error(StatusCode::BAD_REQUEST, "bad_blinded_challenge", detail),
    };
    let blind_session_id = match decode_32(&req.blind_session_id) {
        Ok(b) => b,
        Err(detail) => return error(StatusCode::BAD_REQUEST, "bad_blind_session_id", detail),
    };
    let challenge = BlindedChallenge {
        challenge: challenge_bytes,
        session_id: blind_session_id,
    };

    // Signer must already exist — wallets are required to call /nonce
    // first. We do NOT lazily create here, because doing so would make
    // a stray /blind-sign with a random blind_session_id silently
    // create a useless signer.
    let signer = {
        let signers = state.signers.lock().expect("signers poisoned");
        match signers.get(&session_id) {
            Some(s) => s.clone(),
            None => {
                return error(
                    StatusCode::BAD_REQUEST,
                    "no_active_signer",
                    "call /nonce first to instantiate a signer for this round".into(),
                );
            }
        }
    };

    let response = {
        let mut guard = signer.lock().expect("signer poisoned");
        match guard.sign_blinded_challenge_for_participant(&challenge, &req.ghost_id) {
            Ok(r) => r,
            Err(e) => {
                // The blind module deliberately returns a generic
                // "Signature verification failed" error so cross-
                // participant nonce-hijack attempts can't be
                // distinguished by timing or message. We map it to a
                // single forbidden/error code at the HTTP layer for
                // the same reason.
                warn!(%session_id, ghost_id = %req.ghost_id, ?e, "blind-sign failed");
                return error(
                    StatusCode::FORBIDDEN,
                    "blind_sign_rejected",
                    "signature request rejected".into(),
                );
            }
        }
    };

    debug!(%session_id, ghost_id = %req.ghost_id, "blind-sign issued");
    (
        StatusCode::OK,
        Json(BlindSignResponse {
            signature_scalar: hex::encode(response.signature_scalar),
            blind_session_id: hex::encode(response.session_id),
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
