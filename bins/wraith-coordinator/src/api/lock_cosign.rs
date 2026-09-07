//! The quorum's half of a Ghost Lock Spending spend, over HTTP.
//!
//! Two rounds, because MuSig2 needs two: `/nonce` commits to the spend and
//! returns this quorum's public nonce, `/partial` completes it.
//!
//! # What this endpoint is allowed to refuse
//!
//! Most of it. A quorum that co-signs whatever it is asked adds nothing
//! against somebody holding a stolen owner key, so the refusals are the
//! feature — see [`wraith_protocol::lock_cosign`]. The route's job is to carry
//! them faithfully, including saying *which* rule said no, because "refused"
//! with no reason is indistinguishable from an outage and sends an owner
//! looking in the wrong place.
//!
//! # Not configured is not the same as refusing
//!
//! A coordinator with no quorum seed answers 501 rather than 403: it is not
//! declining this spend, it does not do this at all, and an owner should go to
//! a different coordinator rather than change their transaction.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use ghost_lock::airgap::SigningRequest;
use wraith_protocol::lock_cosign::{begin_cosign, CosignRefusal};

use crate::state::CoordinatorState;

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    detail: String,
}

fn err(status: StatusCode, error: &'static str, detail: String) -> axum::response::Response {
    (status, Json(ErrorBody { error, detail })).into_response()
}

/// Round 1 request: the Lock and the spend.
#[derive(Deserialize)]
pub struct NonceRequest {
    /// Which Lock, so the quorum derives the right key for it.
    pub lock_id: String,
    /// The spend, as the owner's wallet built it.
    pub request: SigningRequest,
}

#[derive(Serialize)]
pub struct NonceResponseBody {
    /// Identifies this co-signing, for the second call.
    pub session: String,
    /// This quorum's public nonce, hex.
    pub public_nonce: String,
    /// What the quorum understood the spend to do. Echoed so the owner can
    /// see the two sides agree before committing anything further.
    pub input_sats: u64,
    pub fee_sats: u64,
}

/// Round 2 request.
#[derive(Deserialize)]
pub struct PartialRequestBody {
    pub session: String,
    /// Every party's public nonce, hex.
    pub public_nonces: Vec<String>,
}

#[derive(Serialize)]
pub struct PartialResponseBody {
    pub session: String,
    /// This quorum's partial signature, hex.
    pub partial: String,
}

/// Map a refusal to a status that says what kind of "no" it is.
fn refusal_status(r: &CosignRefusal) -> StatusCode {
    match r {
        // The owner can act on these: change the spend, or wait.
        CosignRefusal::AboveCeiling { .. } | CosignRefusal::AboveWindow { .. } => {
            StatusCode::FORBIDDEN
        }
        // Asking a standby is a routing mistake, not a policy decision.
        CosignRefusal::NotActive => StatusCode::SERVICE_UNAVAILABLE,
        // The quorum will not sign this coin again, and never will.
        CosignRefusal::WouldEquivocate(_) => StatusCode::CONFLICT,
        // The quorum's problem, not the owner's: retrying may work.
        CosignRefusal::LogUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        CosignRefusal::Unreadable(_) => StatusCode::BAD_REQUEST,
    }
}

/// `POST /api/v1/lock/cosign/nonce`
pub async fn post_nonce(
    State(state): State<Arc<CoordinatorState>>,
    Json(body): Json<NonceRequest>,
) -> axum::response::Response {
    let Some(cfg) = state.lock_cosign.as_ref() else {
        return err(
            StatusCode::NOT_IMPLEMENTED,
            "lock_cosign_not_configured",
            "this coordinator has no quorum seed and does not co-sign Ghost Locks".into(),
        );
    };

    let quorum_key = match ghost_lock::backup_key::quorum_secret_key(
        &cfg.seed_phrase,
        &cfg.seed_passphrase,
        &body.lock_id,
    ) {
        Ok(k) => k,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "quorum_key",
                format!("could not derive this Lock's quorum key: {e}"),
            )
        }
    };

    let keys = match ghost_lock::airgap::keys(&body.request) {
        Ok(k) => k,
        Err(e) => return err(StatusCode::BAD_REQUEST, "keys", e.to_string()),
    };
    let root = match ghost_lock::airgap::merkle_root(&body.request) {
        Ok(r) => r,
        Err(e) => return err(StatusCode::BAD_REQUEST, "merkle_root", e.to_string()),
    };

    // The derived key must be one of the co-signers the request names. If it
    // is not, this is a Lock this quorum does not guard, and co-signing would
    // burn a nonce producing a share nobody can use.
    let ours = quorum_key
        .x_only_public_key(&bitcoin::secp256k1::Secp256k1::new())
        .0;
    if !keys.contains(&ours) {
        return err(
            StatusCode::BAD_REQUEST,
            "not_our_lock",
            "this quorum's key for that lock_id is not among the request's co-signers; \
             either the lock_id is wrong or this Lock names a different quorum"
                .into(),
        );
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let outcome = {
        let mut coins = cfg.coins.lock().expect("coins ledger");
        let mut spends = cfg.spends.lock().expect("spend log");
        begin_cosign(
            &body.request,
            state.network,
            cfg.policy,
            cfg.role,
            &mut *coins,
            &mut *spends,
            now,
            &quorum_key,
            &keys,
            root,
        )
    };

    let session = match outcome {
        Ok(s) => s,
        Err(e) => return err(refusal_status(&e), "refused", e.to_string()),
    };

    let summary = session.summary().clone();
    let session_id = hex::encode(bitcoin::hashes::Hash::to_byte_array(
        bitcoin::hashes::sha256::Hash::hash(session.public_nonce().as_slice()),
    ));
    let public_nonce = hex::encode(session.public_nonce());
    cfg.pending
        .lock()
        .expect("pending")
        .insert(session_id.clone(), session);

    Json(NonceResponseBody {
        session: session_id,
        public_nonce,
        input_sats: summary.input_sats,
        fee_sats: summary.fee_sats,
    })
    .into_response()
}

/// `POST /api/v1/lock/cosign/partial`
pub async fn post_partial(
    State(state): State<Arc<CoordinatorState>>,
    Json(body): Json<PartialRequestBody>,
) -> axum::response::Response {
    let Some(cfg) = state.lock_cosign.as_ref() else {
        return err(
            StatusCode::NOT_IMPLEMENTED,
            "lock_cosign_not_configured",
            "this coordinator does not co-sign Ghost Locks".into(),
        );
    };

    let mut nonces = Vec::with_capacity(body.public_nonces.len());
    for (i, n) in body.public_nonces.iter().enumerate() {
        let raw = match hex::decode(n.trim()) {
            Ok(r) => r,
            Err(e) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    "public_nonce",
                    format!("public_nonces[{i}] is not hex: {e}"),
                )
            }
        };
        match <[u8; 66]>::try_from(raw) {
            Ok(a) => nonces.push(a),
            Err(_) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    "public_nonce",
                    format!("public_nonces[{i}] must be 66 bytes"),
                )
            }
        }
    }

    // Taken out of the map, not borrowed: signing consumes the session, so a
    // second attempt on one session must find nothing rather than a nonce it
    // could reuse.
    let session = cfg.pending.lock().expect("pending").remove(&body.session);
    let Some(session) = session else {
        return err(
            StatusCode::NOT_FOUND,
            "unknown_session",
            "no co-signing in progress with that session; a coordinator restart drops \
             them, which is safe — start again from /nonce"
                .into(),
        );
    };

    let mut ledger = ghost_lock::signing::VolatileNonceLedger::default();
    match session.sign(&mut ledger, &nonces) {
        Ok(partial) => Json(PartialResponseBody {
            session: body.session,
            partial: hex::encode(partial),
        })
        .into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, "sign", e),
    }
}

use bitcoin::hashes::Hash as _;
