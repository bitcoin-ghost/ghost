//! Asking the Wraith quorum to co-sign a Ghost Lock Spending spend.
//!
//! # Why this is one call and the device flow is three
//!
//! Both are MuSig2, so both are two rounds. The difference is who carries the
//! bytes: an air-gapped device needs a person walking between two machines, so
//! the wallet has to stop and hand them something. The quorum is reachable
//! over HTTP, so the wallet does both rounds itself and the user sees one
//! action.
//!
//! # A refusal is not a failure
//!
//! The quorum is entitled to say no — that is the entire security value of it
//! being a second factor rather than a rubber stamp. So a 403 is reported as
//! what it is, with the reason the coordinator gave, rather than flattened
//! into "request failed". An owner told only that something went wrong will
//! retry; an owner told the spend exceeds the window will wait.

use bitcoin::TapNodeHash;
use ghost_lock::airgap::SigningRequest;
use ghost_lock::signing::{combine, NonceLedger, SigningSession};
use serde::{Deserialize, Serialize};

/// Why the wallet could not get a co-signature.
#[derive(Debug, thiserror::Error)]
pub enum CosignError {
    /// The quorum declined, and said why.
    #[error("the quorum refused: {detail}")]
    Refused {
        /// The coordinator's machine-readable reason.
        code: String,
        /// Its human-readable one.
        detail: String,
    },
    /// This coordinator does not co-sign Locks at all.
    #[error(
        "this coordinator does not co-sign Ghost Locks ({detail}); try another one rather \
         than changing the spend"
    )]
    NotOffered {
        /// What it said.
        detail: String,
    },
    /// The request never got there, or the reply made no sense.
    #[error("could not reach the quorum: {0}")]
    Transport(String),
    /// Local signing failed.
    #[error("{0}")]
    Local(String),
}

#[derive(Serialize)]
struct NonceBody<'a> {
    binding_id: &'a str,
    request: &'a SigningRequest,
}

#[derive(Deserialize)]
struct NonceReply {
    session: String,
    public_nonce: String,
    input_sats: u64,
    fee_sats: u64,
}

#[derive(Serialize)]
struct PartialBody<'a> {
    session: &'a str,
    public_nonces: Vec<String>,
}

#[derive(Deserialize)]
struct PartialReply {
    partial: String,
}

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
    detail: String,
}

/// What the quorum understood the spend to be.
///
/// Returned so the wallet can check the two sides agree before the signature
/// is used. They are derived from the same PSBT, so a mismatch means one of
/// them read a different transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuorumView {
    /// What leaves the lane.
    pub input_sats: u64,
    /// What the miners take.
    pub fee_sats: u64,
}

/// Run both rounds against a coordinator and return the finished signature.
///
/// The wallet's own nonce is burned in its ledger before its partial signature
/// exists, exactly as in the device flow — the counterparty being a service
/// rather than a person changes nothing about nonce safety.
#[allow(clippy::too_many_arguments)]
pub async fn cosign_with_quorum<L: NonceLedger>(
    http: &reqwest::Client,
    coordinator_url: &str,
    binding_id: &str,
    request: &SigningRequest,
    owner_key: &bitcoin::secp256k1::SecretKey,
    keys: &[bitcoin::XOnlyPublicKey],
    merkle_root: Option<TapNodeHash>,
    message: &[u8; 32],
    nonces_ledger: &mut L,
) -> Result<(bitcoin::secp256k1::schnorr::Signature, QuorumView), CosignError> {
    let base = coordinator_url.trim_end_matches('/');

    // Round 1, quorum side.
    let resp = http
        .post(format!("{base}/api/v1/lock/cosign/nonce"))
        .json(&NonceBody {
            binding_id,
            request,
        })
        .send()
        .await
        .map_err(|e| CosignError::Transport(e.to_string()))?;
    let quorum_nonce = read_nonce(resp).await?;

    // Round 1, our side. After the quorum's, so a refusal costs us no nonce.
    let (session, commitment) = SigningSession::begin(keys, owner_key, merkle_root, message)
        .map_err(|e| CosignError::Local(format!("round 1: {e}")))?;

    let their_nonce: [u8; 66] = hex::decode(quorum_nonce.public_nonce.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| {
            CosignError::Transport("the quorum's public nonce is not 66 bytes of hex".into())
        })?;

    // Sorted, so both sides aggregate the same set without agreeing an order.
    let mut nonces = vec![commitment.public_nonce, their_nonce];
    nonces.sort_unstable();

    // Round 2, quorum side.
    let resp = http
        .post(format!("{base}/api/v1/lock/cosign/partial"))
        .json(&PartialBody {
            session: &quorum_nonce.session,
            public_nonces: nonces.iter().map(hex::encode).collect(),
        })
        .send()
        .await
        .map_err(|e| CosignError::Transport(e.to_string()))?;
    let their_partial = read_partial(resp).await?;

    // Round 2, our side.
    let ours = session
        .sign(nonces_ledger, &nonces)
        .map_err(|e| CosignError::Local(format!("round 2: {e}")))?;

    let sig = combine(keys, merkle_root, &nonces, &[ours, their_partial], message)
        .map_err(|e| CosignError::Local(format!("combine: {e}")))?;

    Ok((
        sig,
        QuorumView {
            input_sats: quorum_nonce.input_sats,
            fee_sats: quorum_nonce.fee_sats,
        },
    ))
}

async fn read_nonce(resp: reqwest::Response) -> Result<NonceReply, CosignError> {
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| CosignError::Transport(e.to_string()))?;
    if status.is_success() {
        return serde_json::from_str(&body)
            .map_err(|e| CosignError::Transport(format!("unreadable reply: {e}")));
    }
    Err(classify(status, &body))
}

async fn read_partial(resp: reqwest::Response) -> Result<[u8; 32], CosignError> {
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| CosignError::Transport(e.to_string()))?;
    if !status.is_success() {
        return Err(classify(status, &body));
    }
    let parsed: PartialReply = serde_json::from_str(&body)
        .map_err(|e| CosignError::Transport(format!("unreadable reply: {e}")))?;
    hex::decode(parsed.partial.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| {
            CosignError::Transport("the quorum's partial signature is not 32 bytes of hex".into())
        })
}

/// Turn a failing reply into an error that says what kind of "no" it was.
///
/// 501 is kept distinct from 403 because they send an owner to opposite
/// places: one to a different coordinator, the other to a different spend.
fn classify(status: reqwest::StatusCode, body: &str) -> CosignError {
    let parsed: Option<ErrorBody> = serde_json::from_str(body).ok();
    let (code, detail) = match parsed {
        Some(e) => (e.error, e.detail),
        None => (status.as_u16().to_string(), body.trim().to_string()),
    };
    if status == reqwest::StatusCode::NOT_IMPLEMENTED {
        return CosignError::NotOffered { detail };
    }
    CosignError::Refused { code, detail }
}
