//! `GET /api/v1/pool/discover` — first call any wallet makes.
//!
//! Returns the coordinator's identity (network, supported tiers, fee
//! schedule, fee rates) so the wallet can verify it's talking to a
//! coordinator that matches its expectations. From DESIGN_LITE.md §5
//! step 1: `pool.discover()` → `{ active_url, standby_urls[],
//! supported_tiers[] }`.
//!
//! v1 returns just the local coordinator's info — `active_url` is "this
//! one" and `standby_urls` is empty. Future commits add coordinator-
//! pool awareness via `coordinator_redundancy.rs`'s pool registry.

use std::sync::Arc;

use axum::{extract::State, Json};
use serde::Serialize;

use wraith_protocol::{
    per_participant_mining_share, LiteTier, SessionType, DEFAULT_FEE_RATE_SATS_PER_VB,
    LITE_FILL_WINDOW_SECS, LITE_SERVICE_FEE_BPS,
};

use crate::state::CoordinatorState;

#[derive(Serialize)]
pub struct DiscoverResponse {
    /// Network the coordinator serves (`mainnet` / `signet` / etc.).
    /// Wallet refuses to register if this disagrees with its own
    /// configured network.
    pub network: &'static str,
    /// Stable identifier for this coordinator pool. Lets wallets
    /// remember "I was registered with pool X" across reconnections
    /// and detect if a load balancer accidentally swapped them to a
    /// different pool. v1 just returns the network — multi-pool
    /// support comes when `coordinator_redundancy.rs` is wired in.
    pub pool_id: String,
    /// Service fee rate (basis points). Pinned in `DESIGN_LITE.md` §11.
    pub service_fee_bps: u32,
    /// Fill window (seconds) — how long a session stays open accepting
    /// new participants after `min_participants` is reached.
    pub fill_window_secs: u64,
    /// Tier descriptors for every tier this coordinator supports.
    pub tiers: Vec<TierDescriptor>,
}

#[derive(Serialize)]
pub struct TierDescriptor {
    /// Stable string id (`100k_sats` / `1m_sats` / `10m_sats` /
    /// `100m_sats`). Wallets reference tiers by this string in
    /// subsequent requests so the wire format doesn't break under
    /// future enum reordering.
    pub id: String,
    pub denomination_sats: u64,
    pub min_participants: u32,
    pub max_participants: u32,
    pub service_fee_sats: u64,
    /// What a seat in a **Mix** round costs, to the satoshi: denomination
    /// + mining-fee share + service-fee share.
    ///
    /// Published rather than left for the wallet to derive, because a
    /// round has no change output (#698) and so registration demands this
    /// exact value — and a wallet computing it independently is a fourth
    /// copy of a calculation that has already disagreed with itself once.
    /// The wallet splits its coin to match this number.
    pub mix_seat_price_sats: u64,
    /// The same for a **Jump** round, which builds no fee output and so
    /// costs the service fee less.
    pub jump_seat_price_sats: u64,
}

/// The exact input a seat costs. Derived from the same function the
/// coordinator enforces with and the round builder builds with, so the
/// three cannot drift apart.
fn seat_price(tier: LiteTier, session_type: SessionType) -> u64 {
    tier.denomination_sats()
        + per_participant_mining_share(tier, session_type, DEFAULT_FEE_RATE_SATS_PER_VB)
        + match session_type {
            SessionType::Mix => tier.service_fee_sats(),
            SessionType::Jump => 0,
        }
}

pub async fn get(State(state): State<Arc<CoordinatorState>>) -> Json<DiscoverResponse> {
    let tiers = state
        .supported_tiers()
        .into_iter()
        .map(|t| TierDescriptor {
            id: t.id().to_string(),
            denomination_sats: t.denomination_sats(),
            min_participants: t.min_participants() as u32,
            max_participants: t.max_participants() as u32,
            service_fee_sats: t.service_fee_sats(),
            mix_seat_price_sats: seat_price(t, SessionType::Mix),
            jump_seat_price_sats: seat_price(t, SessionType::Jump),
        })
        .collect();
    Json(DiscoverResponse {
        network: state.network_name(),
        pool_id: format!("wraith-pool-{}", state.network_name()),
        service_fee_bps: LITE_SERVICE_FEE_BPS,
        fill_window_secs: LITE_FILL_WINDOW_SECS,
        tiers,
    })
}
