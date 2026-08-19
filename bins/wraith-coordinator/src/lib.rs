//! Wraith Lite v1 — coordinator library surface.
//!
//! Most of the coordinator runs as a binary (`bins/wraith-coordinator/
//! src/main.rs`). This lib target exists so integration tests under
//! `tests/` can reach `build_router` + `CoordinatorState` without
//! shelling out to a real process. Production code uses the binary;
//! tests use this lib.

use std::sync::Arc;

use axum::Router;

pub mod api;
pub mod assembly;
pub mod bans;
pub mod bond_ledger_http;
pub mod bond_resolution;
pub mod broadcaster;
pub mod gossip_auth;
pub mod gossip_http;
pub mod inputs;
pub mod outputs;
pub mod rpc;
pub mod state;
pub mod tick;
pub mod utxo_source;
pub mod witnesses;

pub use state::CoordinatorState;

/// Construct the Axum router for a given coordinator state. Pure
/// function so tests can build it deterministically.
pub fn build_router(state: Arc<CoordinatorState>) -> Router {
    Router::new()
        .route("/health", axum::routing::get(api::health::get))
        .route(
            "/api/v1/pool/discover",
            axum::routing::get(api::discover::get),
        )
        .route(
            "/api/v1/session/find_or_create",
            axum::routing::post(api::find_or_create::post),
        )
        .route(
            "/api/v1/session/:session_id",
            axum::routing::get(api::session_status::get),
        )
        .route(
            "/api/v1/session/:session_id/inputs",
            axum::routing::post(api::session_inputs::post),
        )
        .route(
            "/api/v1/session/:session_id/nonce",
            axum::routing::post(api::blind_sig::post_nonce),
        )
        .route(
            "/api/v1/session/:session_id/blind-sign",
            axum::routing::post(api::blind_sig::post_blind_sign),
        )
        .route(
            "/api/v1/session/:session_id/outputs",
            axum::routing::post(api::session_outputs::post),
        )
        .route(
            "/api/v1/session/:session_id/round-tx",
            axum::routing::get(api::round_tx::get),
        )
        .route(
            "/api/v1/session/:session_id/witness",
            axum::routing::post(api::session_witness::post),
        )
        // Internal coordinator-to-coordinator state replication.
        // Operator firewalls this prefix to the pool's address range
        // until the auth header lands; v1 trusts peers on a private
        // network. See `gossip_http.rs`.
        .route(
            "/api/v1/internal/gossip",
            axum::routing::post(api::gossip::post),
        )
        .with_state(state)
}
