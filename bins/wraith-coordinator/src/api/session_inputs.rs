//! `POST /api/v1/session/:session_id/inputs` — commit-phase submission.
//!
//! Once a session is `Locked` (fill window closed and quorum hit), each
//! enrolled participant submits their input UTXO + change address here.
//! The coordinator validates and stashes the submission, and once every
//! enrolled participant has submitted, advances the session to
//! `Signing`.
//!
//! ## What this commit (B/4a) covers
//!
//! - Pluggable `BondLedger` verification — the bond is checked against
//!   `(ghost_id, session_id, expected_sats = tier.bond_sats)`. Without a
//!   ledger configured, the endpoint returns 503 — see
//!   `CoordinatorState::bond_ledger`.
//! - Identity check: `ghost_id` must already be enrolled on the session.
//! - **Chain check** (#699): the outpoint must be an unspent, confirmed,
//!   mature output whose value and scriptPubKey match what the
//!   submission claims. Everything in `TxInputRef` is wallet-asserted,
//!   so without this the round's arithmetic is computed from a number
//!   the participant chose, and any later ownership proof is worthless —
//!   a signature over a wallet-supplied script says nothing about the
//!   real outpoint. Without a source configured, the endpoint returns
//!   503 rather than falling back to trust.
//! - Input arithmetic: chain value ≥ denom + per-participant
//!   service share + per-participant mining share. Surplus over that
//!   total goes to the change output; if the surplus is ≥ dust, a
//!   change address is required.
//! - Idempotent acceptance: submitting again with the same `ghost_id`
//!   replaces the previous record (covers wallet retries).
//! - Locked → Signing transition once all enrolled have submitted.
//!
//! ## Blind-sig protocol (B/4b, separate endpoints)
//!
//! Schnorr blind-signature issuance lives on its own endpoints
//! (`/nonce` + `/blind-sign`, see `api::blind_sig`) so the input-set
//! validation here stays bounded and the crypto path is exercised
//! independently. Wallets call /inputs once to commit their UTXO set,
//! then /nonce + /blind-sign to obtain a signature over their (still
//! unrevealed) mix-output.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use bitcoin::constants::COINBASE_MATURITY;

use wraith_protocol::{
    per_participant_mining_share, BondError, LiteSession, LiteSessionState, SessionType,
    CHANGE_DUST_THRESHOLD_SATS, DEFAULT_FEE_RATE_SATS_PER_VB,
};

/// No-sign deadline for the Signing phase, in seconds. From the moment
/// the round transitions Locked → Signing, every enrolled participant
/// has this long to submit their /witness; past the deadline, the
/// round fails and non-signers' bonds get slashed.
///
/// Picked at 600s (10 min) to be generous: signing requires the wallet
/// to derive a sighash, sign with a hardware wallet maybe, and post.
/// Real-world Whirlpool clients allow ~5 min on the equivalent step.
pub const WITNESS_DEADLINE_SECS: u64 = 600;

use crate::inputs::{AcceptedInputs, TxInputRef};
use crate::state::CoordinatorState;
use crate::utxo_source::parse_outpoint;

#[derive(Debug, Deserialize)]
pub struct Request {
    pub ghost_id: String,
    pub input: TxInputRef,
    /// Optional change address. Required when input value exceeds
    /// (denom + fee shares) by ≥ dust threshold.
    #[serde(default)]
    pub change_address: Option<String>,
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
    pub submitted_count: u32,
    pub enrolled_count: u32,
}

pub async fn post(
    State(state): State<Arc<CoordinatorState>>,
    Path(session_id): Path<String>,
    Json(req): Json<Request>,
) -> Response {
    // 1. Bond ledger must be configured. Phase C wires the real one;
    //    until then production binaries refuse commit-phase submissions.
    let ledger = match state.bond_ledger.as_ref() {
        Some(l) => l.clone(),
        None => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ledger_not_configured",
                "bond ledger backend is not yet wired (phase C)".into(),
            );
        }
    };

    // 1b. A UTXO source is equally non-optional. Without one the
    //     coordinator would have to take the participant's word for
    //     what its own input is, which is what #699 exists to stop.
    let utxo_source = match state.utxo_source.as_ref() {
        Some(u) => u.clone(),
        None => {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "utxo_source_not_configured",
                "no UTXO source is configured; registration cannot verify inputs".into(),
            );
        }
    };

    // 2. Refresh time-driven transitions and snapshot the session.
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

    // 3. Session must be Locked. Filling sessions still accept
    //    /find_or_create joins; Signing/Broadcasting/Complete/Failed
    //    sessions are past the commit phase.
    match &session.state {
        LiteSessionState::Locked => {}
        other => {
            return error(
                StatusCode::CONFLICT,
                "wrong_session_state",
                format!(
                    "session '{session_id}' is in state '{}', expected 'locked'",
                    other.as_str()
                ),
            );
        }
    }

    // 4. Participant must be enrolled. The coordinator's view of who's
    //    in the round is authoritative; an unenrolled ghost_id is
    //    either a bug or a probe.
    if !session
        .participants
        .iter()
        .any(|p| p.ghost_id == req.ghost_id)
    {
        return error(
            StatusCode::FORBIDDEN,
            "not_enrolled",
            format!(
                "ghost_id '{}' is not enrolled in session '{}'",
                req.ghost_id, session_id
            ),
        );
    }

    // 5. Verify the bond against the ledger. Bond amount comes from
    //    the tier — the wallet doesn't get to negotiate this.
    let expected_bond = session.tier.bond_sats();
    let verified_bond_id = match ledger.verify_bond(&req.ghost_id, &session_id, expected_bond) {
        Ok(id) => id,
        Err(BondError::NotBonded { .. }) => {
            return error(
                StatusCode::PAYMENT_REQUIRED,
                "bond_not_found",
                format!(
                    "no escrowed bond for ghost_id '{}' in session '{}'",
                    req.ghost_id, session_id
                ),
            );
        }
        Err(BondError::AmountMismatch {
            expected_sats,
            actual_sats,
            ..
        }) => {
            return error(
                StatusCode::PAYMENT_REQUIRED,
                "bond_amount_mismatch",
                format!("bond is {actual_sats} sats; expected {expected_sats}"),
            );
        }
        Err(BondError::AlreadyResolved { .. }) => {
            return error(
                StatusCode::CONFLICT,
                "bond_already_resolved",
                "this bond has already been resolved against another round".into(),
            );
        }
        Err(BondError::LedgerUnreachable(detail)) => {
            warn!(?detail, "bond ledger unreachable during /inputs");
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ledger_unreachable",
                detail,
            );
        }
        Err(other) => {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ledger_error",
                other.to_string(),
            );
        }
    };

    // The ledger is authoritative for bond existence at /inputs time.
    // The bond_id stored on `LiteSessionParticipant` at find_or_create
    // time is an informational placeholder — wallets typically don't
    // know the eventual session_id when first calling find_or_create,
    // so they post the real bond against (ghost_id, session_id) AFTER
    // the session exists, and `verify_bond` is what locks identity to
    // the L2 escrow. No cross-check on the participant record's
    // bond_id is meaningful here.

    // 6. Check the input against the chain.
    //
    //    Everything in `req.input` is wallet-asserted. Until this
    //    existed the coordinator believed all of it, so the round
    //    arithmetic was computed from a number the participant chose and
    //    the input might have been spent, or never have existed. One
    //    `gettxout` settles existence, value, scriptPubKey and
    //    unspent-ness together (#699).
    let outpoint = match parse_outpoint(&req.input.txid, req.input.vout) {
        Ok(o) => o,
        Err(detail) => return error(StatusCode::BAD_REQUEST, "bad_outpoint", detail),
    };
    let chain_utxo = match utxo_source.get_utxo(&outpoint) {
        Ok(Some(u)) => u,
        // Absent or spent. Deliberately one error for both: saying
        // which would answer a question about the chain that the
        // submitter did not ask.
        Ok(None) => {
            return error(
                StatusCode::BAD_REQUEST,
                "utxo_not_found",
                format!("{outpoint} is not an unspent output"),
            );
        }
        Err(e) => {
            warn!(%outpoint, error = %e, "utxo lookup failed");
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "utxo_source_unreachable",
                e.to_string(),
            );
        }
    };

    // An unconfirmed input can still be replaced out from under the
    // round by its own parent, which would invalidate the whole
    // transaction after everyone has signed.
    if chain_utxo.confirmations == 0 {
        return error(
            StatusCode::BAD_REQUEST,
            "input_unconfirmed",
            format!("{outpoint} is unconfirmed; a round input must be confirmed"),
        );
    }
    if chain_utxo.coinbase && chain_utxo.confirmations < COINBASE_MATURITY {
        return error(
            StatusCode::BAD_REQUEST,
            "immature_coinbase",
            format!(
                "{outpoint} is a coinbase output with {} of {} confirmations",
                chain_utxo.confirmations, COINBASE_MATURITY
            ),
        );
    }

    // The chain is authoritative. A mismatch is refused rather than
    // silently corrected, so a wallet working from a stale view learns
    // that it is stale instead of having its arithmetic quietly changed.
    if chain_utxo.value_sats != req.input.value_sats {
        return error(
            StatusCode::BAD_REQUEST,
            "value_mismatch",
            format!(
                "{outpoint} is worth {} sats on-chain; submission claims {}",
                chain_utxo.value_sats, req.input.value_sats
            ),
        );
    }
    let claimed_spk = req.input.scriptpubkey_hex.trim();
    if !claimed_spk.eq_ignore_ascii_case(&chain_utxo.script_pubkey.to_hex_string()) {
        return error(
            StatusCode::BAD_REQUEST,
            "scriptpubkey_mismatch",
            format!(
                "{outpoint} has scriptPubKey {}; submission claims {claimed_spk}",
                chain_utxo.script_pubkey.to_hex_string()
            ),
        );
    }

    // 7. Validate input arithmetic. Compute per-participant fee shares
    //    against the tier; reject inputs below the minimum or with
    //    surplus-over-dust missing a change address.
    let min_input = match minimum_participant_input(&session, &state) {
        Ok(m) => m,
        Err(resp) => return resp,
    };

    if chain_utxo.value_sats < min_input {
        return error(
            StatusCode::BAD_REQUEST,
            "insufficient_input",
            format!(
                "input {} sats < required {} sats (denom + fee shares)",
                chain_utxo.value_sats, min_input
            ),
        );
    }

    let surplus = chain_utxo.value_sats - min_input;
    if surplus >= CHANGE_DUST_THRESHOLD_SATS && req.change_address.is_none() {
        return error(
            StatusCode::BAD_REQUEST,
            "missing_change_address",
            format!(
                "input has {} sats surplus over minimum; change_address required",
                surplus
            ),
        );
    }

    // 8. Stash the accepted submission. Idempotent: if this ghost_id
    //    already submitted, the entry is replaced (wallet retry path).
    let accepted = AcceptedInputs {
        ghost_id: req.ghost_id.clone(),
        bond_id: verified_bond_id,
        input: req.input.clone(),
        change_address: req.change_address.clone(),
        accepted_at: now,
    };
    let (submitted_count, enrolled_count) = {
        let mut store = state.inputs_store.lock().expect("inputs_store poisoned");
        let entry = store.entry(session_id.clone()).or_default();
        if let Some(existing) = entry.iter_mut().find(|a| a.ghost_id == req.ghost_id) {
            *existing = accepted;
        } else {
            entry.push(accepted);
        }
        (entry.len() as u32, session.participants.len() as u32)
    };

    debug!(
        session_id = %session_id,
        ghost_id = %req.ghost_id,
        submitted = submitted_count,
        enrolled = enrolled_count,
        "/inputs accepted submission",
    );

    // 8. Advance Locked → Signing once every enrolled participant has
    //    submitted. The protocol crate's registry only exposes
    //    apply_event() and add_participant for state mutation — for
    //    Locked → Signing we use apply_event with StateChanged so
    //    standby coordinators learn about the transition through the
    //    same gossip path as natural transitions.
    //
    //    Record the no-sign deadline at the same time. /witness
    //    checks this deadline and fails the round (slashing
    //    non-signers) if it expires before all witnesses arrive.
    let mut next_state = session.state.clone();
    if submitted_count == enrolled_count {
        next_state = LiteSessionState::Signing;
        let _ = state
            .sessions
            .apply_event(wraith_protocol::SessionGossipEvent::StateChanged {
                session_id: session_id.clone(),
                new_state: next_state.clone(),
            });
        state
            .signing_deadlines
            .lock()
            .expect("signing_deadlines poisoned")
            .insert(session_id.clone(), now + WITNESS_DEADLINE_SECS);
    }

    let body = ResponseBody {
        session_id,
        state: next_state.as_str().to_string(),
        submitted_count,
        enrolled_count,
    };
    (StatusCode::OK, Json(body)).into_response()
}

/// Compute the minimum acceptable per-participant input for the round
/// described by `session`. Mirrors `LiteRoundBuilder::min_participant_input`
/// without instantiating a builder — keeps the validation path
/// allocation-free and avoids needing the coordinator_fee_address for
/// Mix rounds at /inputs time.
///
/// Returns either the minimum sat value or a pre-built error response
/// for the conditions the caller can't recover from (Mix round with no
/// fee address configured — the round can't be built later, so we fail
/// the input now).
// `Err = axum::http::Response` is the idiomatic axum early-return: the helper hands back the
// exact response the caller should send. Boxing it to satisfy result_large_err would make
// every call site unwrap a Box to return a Response, which is worse code for 128 bytes on a
// path that is already building an HTTP response.
#[allow(clippy::result_large_err)]
fn minimum_participant_input(
    session: &LiteSession,
    state: &CoordinatorState,
) -> Result<u64, Response> {
    if session.session_type == SessionType::Mix && state.coordinator_fee_address.is_none() {
        return Err(error(
            StatusCode::SERVICE_UNAVAILABLE,
            "fee_address_not_configured",
            "operator has not configured a coordinator fee address; \
             Mix rounds cannot accept inputs without one"
                .into(),
        ));
    }
    let tier = session.tier;
    let mining_share =
        per_participant_mining_share(tier, session.session_type, DEFAULT_FEE_RATE_SATS_PER_VB);
    let service_share = match session.session_type {
        SessionType::Mix => tier.service_fee_sats(),
        SessionType::Jump => 0,
    };
    Ok(tier.denomination_sats() + mining_share + service_share)
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
