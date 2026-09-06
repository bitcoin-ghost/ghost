//! `GET /api/v1/session/{session_id}` — wallet polling endpoint.
//!
//! Wallets poll this between calls to `/find_or_create` and `/inputs` to
//! watch for `Filling → Locked` (other participants showed up, round
//! is full) or `Filling → Failed` (fill window expired without
//! quorum). Read-only from the wallet's perspective; the coordinator
//! itself ticks the registry on every call so time-driven transitions
//! show up without needing a separate background loop.
//!
//! Idempotent: repeated calls at the same `now` produce the same
//! response. The registry's `tick(now)` is a no-op past the first
//! call for any given timestamp.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use wraith_protocol::SessionDescriptor;

use crate::state::CoordinatorState;

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    detail: String,
}

#[derive(Serialize)]
pub struct ResponseBody {
    pub session: SessionDescriptor,
    /// The round's anonymity figure, counted in **entities**.
    ///
    /// Served so a wallet has something to check its own arithmetic against,
    /// never so it can skip doing that arithmetic. Every input is public chain
    /// data, so the two computations should agree exactly — a coordinator that
    /// lies here disagrees with the wallet, which is a far louder failure than
    /// serving nothing.
    pub anonymity: AnonymityBody,
}

/// Wire form of `SetReport`. Flattened deliberately: a wallet comparing figures
/// should not have to guess which field is the one that matters.
#[derive(Debug, Serialize)]
pub struct AnonymityBody {
    /// Seats in the round — what a naive mixer would report as the set.
    pub seats: usize,
    /// **This is the anonymity set.** Distinct entities behind those seats.
    pub entities: usize,
    /// Seats that collapsed into another entity.
    pub discounted: usize,
    /// Entities whose distinctness rests on no linkage being found, rather than
    /// on evidence of independence.
    pub unverified: usize,
    /// Real payers among the entities — cover that behaves like the user,
    /// because it is doing the same thing the user is doing.
    pub payers: usize,
}

pub async fn get(
    State(state): State<Arc<CoordinatorState>>,
    Path(session_id): Path<String>,
) -> Response {
    let now = state.now();
    // Advance any time-driven transitions before snapshotting. Cheap +
    // idempotent — re-running tick(now) at the same `now` is a no-op.
    let _changed = state.sessions.tick(now);

    match state.sessions.get(&session_id) {
        Some(session) => {
            let descriptor = SessionDescriptor::from_session(&session);
            let report = crate::set_report::session_set_report(&state, &session_id)
                .unwrap_or_else(|| wraith_protocol::anonymity_set::assess(&[]));
            (
                StatusCode::OK,
                Json(ResponseBody {
                    session: descriptor,
                    anonymity: AnonymityBody {
                        seats: report.seats,
                        entities: report.entities,
                        discounted: report.discounted(),
                        unverified: report.unverified,
                        payers: report.payers,
                    },
                }),
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "session_not_found",
                detail: format!("no session with id '{session_id}'"),
            }),
        )
            .into_response(),
    }
}
