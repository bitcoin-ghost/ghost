//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: bins/ghost-stats/src/api.rs                                                                                    |

//! The read side: one endpoint, served from memory.
//!
//! Every request is answered from the in-memory snapshot with no upstream call, so response time is
//! independent of how slow the nodes are. This is the property the page needs: the browser makes one
//! request per minute for everything, instead of ~145 requests per minute per viewer, and the cost
//! stops scaling with the number of people watching.
//!
//! Each section carries `updated_at`, `age_secs` and `ok_nodes`/`total_nodes` so the page can render
//! honest provenance ("as of 40s ago, 7 of 8 nodes") rather than either implying the data is live or
//! hiding that a node is missing.

use crate::snapshot::{now_secs, SharedSnapshot};
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};

pub fn router(snap: SharedSnapshot) -> Router {
    Router::new()
        .route("/api/v1/pool/summary", get(summary))
        .route("/health", get(health))
        .with_state(snap)
}

/// Attach a request-time age to a section so the client does not have to trust its own clock
/// against the server's.
fn with_age(value: &mut serde_json::Value, now: u64) {
    let Some(obj) = value.as_object_mut() else {
        return;
    };
    let updated = obj.get("updated_at").and_then(|u| u.as_u64()).unwrap_or(0);
    obj.insert(
        "age_secs".into(),
        serde_json::json!(now.saturating_sub(updated)),
    );
}

async fn summary(State(snap): State<SharedSnapshot>) -> impl IntoResponse {
    let snapshot = snap.read().await;
    let now = now_secs();
    let ready = snapshot.ready();

    let mut body = match serde_json::to_value(&snapshot) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "could not serialise snapshot");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "snapshot serialisation failed",
            )
                .into_response();
        }
    };

    if let Some(obj) = body.as_object_mut() {
        for key in ["status", "payout"] {
            if let Some(section) = obj.get_mut(key) {
                with_age(section, now);
            }
        }
        if let Some(lbs) = obj.get_mut("leaderboards").and_then(|l| l.as_object_mut()) {
            for section in lbs.values_mut() {
                with_age(section, now);
            }
        }
        obj.insert("ready".into(), serde_json::json!(ready));
        obj.insert("server_time".into(), serde_json::json!(now));
    }

    // A short shared cache lets nginx collapse a burst of viewers onto one copy without ever
    // holding a response longer than the fastest refresh cadence.
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "public, max-age=15"),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"),
        ],
        Json(body),
    )
        .into_response()
}

async fn health(State(snap): State<SharedSnapshot>) -> impl IntoResponse {
    let snapshot = snap.read().await;
    let now = now_secs();
    // Deliberately still 200 when not ready: the process is healthy, it just has not finished its
    // first cycle. A restart loop caused by a health check that fails during warm-up would be a
    // self-inflicted outage.
    Json(serde_json::json!({
        "ok": true,
        "ready": snapshot.ready(),
        "generated_at": snapshot.generated_at,
        "age_secs": now.saturating_sub(snapshot.generated_at),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn age_is_derived_from_updated_at() {
        let mut v = serde_json::json!({"updated_at": 100, "data": {}});
        with_age(&mut v, 160);
        assert_eq!(v["age_secs"], 60);
    }

    #[test]
    fn age_of_a_never_updated_section_does_not_underflow() {
        // Saturating arithmetic matters: a clock that steps backwards must not produce a
        // nonsensical age near u64::MAX on a public page.
        let mut v = serde_json::json!({"updated_at": 500, "data": {}});
        with_age(&mut v, 100);
        assert_eq!(v["age_secs"], 0);
    }
}
