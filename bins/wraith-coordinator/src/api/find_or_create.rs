//! `POST /api/v1/session/find_or_create` — wallet's session entry point.
//!
//! The wallet calls this when it wants to mix at a
//! specific tier. The coordinator either:
//!   - returns an existing open session at that tier (fast path: the
//!     wallet joins a partially-filled round), or
//!   - creates a fresh session with this wallet as the first participant.
//!
//! Either way the response is a `SessionDescriptor` carrying the
//! session_id the wallet then uses for the rest of the round
//! (`/status`, `/inputs`, `/sign`).
//!
//! There's an unavoidable TOCTOU window between `find_or_create_session`
//! and `add_participant`: another wallet could fill the chosen session
//! between our discover and our claim. When that happens, the inner
//! `add_participant` returns `Full` or `NotAcceptingParticipants` and we
//! retry once with a fresh `find_or_create_session` call — the second
//! attempt will spin up a brand-new session if no other open one exists.
//! One retry is enough: under contention the registry will keep
//! returning fresh ids, and a participant who races repeatedly is
//! exhibiting the Sybil behaviour the ownership proof and outpoint
//! cooldown are there to handle (#699).

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use wraith_protocol::anonymity_set::Role;
use wraith_protocol::composition::CompositionPolicy;
use wraith_protocol::{
    find_or_create_session, LiteSessionError, LiteTier, SessionDescriptor, SessionType,
};

use crate::state::CoordinatorState;

#[derive(Debug, Deserialize)]
pub struct Request {
    /// Tier id from the discover endpoint, e.g. `100k_sats`.
    pub tier_id: String,
    /// `mix` (default) or `jump`. The two cost differently and are
    /// tracked as separate session types so the registry doesn't merge
    /// them when looking for open sessions.
    #[serde(default)]
    pub session_type: Option<String>,
    /// Wallet's coordinator-facing identity. NOT the on-chain pubkey;
    /// this is a per-round identifier the wallet keeps to itself across
    /// `/inputs` and `/sign` so the coordinator can correlate. Must be
    /// non-empty.
    pub ghost_id: String,
    /// What this participant is doing: `payer` (default), `mixer`, or
    /// `{"liquidity_provider": <id>}`.
    ///
    /// Declared at join because `composition` enforces mixing scarcity and the
    /// provider allowance before a seat is given away — a rule applied after
    /// the seat is taken has nothing left to refuse.
    ///
    /// Defaults to `payer`, which is the conservative choice: payers are the
    /// uncapped role, so a client that does not send one is never handed a
    /// scarce mixing slot by accident.
    #[serde(default = "default_role")]
    pub role: Role,
}

fn default_role() -> Role {
    Role::Payer
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    detail: String,
}

/// What the wallet actually gets back: the descriptor plus a couple of
/// echo fields that make request/response correlation cheap on the
/// client side.
#[derive(Debug, Serialize)]
pub struct ResponseBody {
    pub session: SessionDescriptor,
    pub joined: bool,
}

pub async fn post(
    State(state): State<Arc<CoordinatorState>>,
    Json(req): Json<Request>,
) -> Response {
    let tier = match LiteTier::from_id(&req.tier_id) {
        Some(t) => t,
        None => {
            return error(
                StatusCode::BAD_REQUEST,
                "unknown_tier",
                format!("tier_id '{}' is not a Wraith Lite v1 tier", req.tier_id),
            );
        }
    };

    let session_type = match parse_session_type(req.session_type.as_deref()) {
        Ok(t) => t,
        Err(detail) => return error(StatusCode::BAD_REQUEST, "unknown_session_type", detail),
    };

    if req.ghost_id.trim().is_empty() {
        return error(
            StatusCode::BAD_REQUEST,
            "missing_ghost_id",
            "ghost_id must be non-empty".into(),
        );
    }

    // Try once, retry once if the session we picked got filled out from
    // under us between discover and claim. See module docstring.
    for attempt in 0..2 {
        let descriptor = find_or_create_session(
            tier,
            session_type,
            &state.sessions,
            state.clock.as_ref(),
            state.id_gen.as_ref(),
            state.fill_window_secs,
        );
        let pre_count = descriptor.slots_filled;
        let now = state.now();
        match state.sessions.add_participant(
            &descriptor.session_id,
            &req.ghost_id,
            req.role,
            CompositionPolicy::default(),
            now,
        ) {
            Ok(updated) => {
                debug!(
                    session_id = %updated.session_id,
                    tier = %updated.tier_id,
                    slots = updated.slots_filled,
                    attempt,
                    "find_or_create accepted participant",
                );
                let body = ResponseBody {
                    session: updated,
                    // We "joined" if the session existed with at least
                    // one participant before us; otherwise this call
                    // also created the session.
                    joined: pre_count > 0,
                };
                return (StatusCode::OK, Json(body)).into_response();
            }
            Err(LiteSessionError::AlreadyRegistered(_, _)) => {
                return error(
                    StatusCode::CONFLICT,
                    "already_registered",
                    format!(
                        "ghost_id '{}' already registered for session '{}'",
                        req.ghost_id, descriptor.session_id
                    ),
                );
            }
            Err(LiteSessionError::Full(_, _))
            | Err(LiteSessionError::NotAcceptingParticipants(_, _))
                if attempt == 0 =>
            {
                warn!(
                    session_id = %descriptor.session_id,
                    "session unavailable mid-claim, retrying with fresh find_or_create",
                );
                continue;
            }
            // Terminal, and deliberately NOT retried.
            //
            // `Full` and `NotAcceptingParticipants` retry, which can create a
            // fresh session. A composition refusal must never reach that path:
            // a new session carries a new set of mixing slots, so retrying on
            // `MixingSlotsFull` would hand the refused participant the very
            // seats the cap just denied. Scarcity per round means nothing if
            // being turned away spawns another round.
            //
            // The honest answer is to wait for the next round, and the message
            // says so.
            Err(LiteSessionError::Composition(detail)) => {
                return error(StatusCode::CONFLICT, "composition_refused", detail);
            }
            Err(other) => {
                return error(
                    StatusCode::CONFLICT,
                    "session_unavailable",
                    other.to_string(),
                );
            }
        }
    }

    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "no_session_available",
        "could not place participant after retry — try again shortly".into(),
    )
}

fn parse_session_type(s: Option<&str>) -> Result<SessionType, String> {
    match s.map(str::trim).filter(|t| !t.is_empty()) {
        None => Ok(SessionType::Mix),
        Some(t) => match t.to_ascii_lowercase().as_str() {
            "mix" => Ok(SessionType::Mix),
            "jump" => Ok(SessionType::Jump),
            other => Err(format!("session_type '{other}' is not 'mix' or 'jump'")),
        },
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
