//! Active → Standby gossip end-to-end test.
//!
//! Spins up two coordinators on real ephemeral ports, points Active's
//! `HttpGossipSink` at Standby, drives a `find_or_create` session
//! against Active, and asserts the Standby's `LiteSessionRegistry`
//! mirrors the new session.
//!
//! Real HTTP — `reqwest` inside the sink talks to `axum::serve` on
//! the Standby. This is the only path that exercises both halves of
//! the wire format end-to-end; the unit tests in `wraith-protocol`
//! cover `apply_event` semantics, and this test pins the JSON shape
//! and the receive endpoint.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::Network;
use wraith_coordinator::gossip_http::HttpGossipSink;
use wraith_coordinator::{build_router, CoordinatorState};
use wraith_protocol::{DeterministicSessionIdGenerator, MockClock};

const TEST_FEE_ADDRESS: &str = "tb1q0xcqpzrky6eff2g52qdye53xkk9jxkvraulyla";

/// Build an Active coordinator that publishes via HTTP to `peer_url`.
async fn spawn_active_with_peer(peer_url: String) -> (String, Arc<CoordinatorState>) {
    spawn_active_with_peer_secret(peer_url, None).await
}

async fn spawn_active_with_peer_secret(
    peer_url: String,
    peer_secret: Option<String>,
) -> (String, Arc<CoordinatorState>) {
    let mut state = CoordinatorState::with_components(
        Network::Signet,
        Arc::new(MockClock::new(1_700_000_000)),
        Arc::new(DeterministicSessionIdGenerator::new()),
        Some(TEST_FEE_ADDRESS.to_string()),
        None,
    );
    state.gossip_peer_secret = peer_secret.clone();
    let sink = HttpGossipSink::spawn(
        vec![peer_url],
        peer_secret,
        &tokio::runtime::Handle::current(),
    );
    state.sessions.set_gossip_sink(Box::new(sink));
    let state = Arc::new(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_router(state.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{}", addr), state)
}

/// Build a Standby coordinator (no outbound sink — pure receiver).
async fn spawn_standby() -> (String, Arc<CoordinatorState>) {
    spawn_standby_with_secret(None).await
}

async fn spawn_standby_with_secret(secret: Option<String>) -> (String, Arc<CoordinatorState>) {
    let mut state = CoordinatorState::with_components(
        Network::Signet,
        Arc::new(MockClock::new(1_700_000_000)),
        Arc::new(DeterministicSessionIdGenerator::new()),
        Some(TEST_FEE_ADDRESS.to_string()),
        None,
    );
    state.gossip_peer_secret = secret;
    let state = Arc::new(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_router(state.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{}", addr), state)
}

/// Wait until `pred` returns true, polling every 25ms up to ~2s.
/// Async tasks need a moment to drain the gossip queue and complete
/// their reqwest call to the standby.
async fn poll_until<F: FnMut() -> bool>(mut pred: F) -> bool {
    for _ in 0..80 {
        if pred() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    pred()
}

#[tokio::test]
async fn active_session_creation_replicates_to_standby() {
    let (standby_url, standby_state) = spawn_standby().await;
    let (active_url, _active_state) = spawn_active_with_peer(standby_url).await;

    // Sanity: Standby starts empty.
    assert_eq!(standby_state.sessions.len(), 0);

    // Drive a session creation on the Active via its real HTTP API.
    // `find_or_create` publishes a `SessionCreated` gossip event; the
    // sink POSTs it to Standby's `/api/v1/internal/gossip` route.
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/session/find_or_create", active_url))
        .json(&serde_json::json!({
            "tier_id": "100k_sats",
            "session_type": "mix",
            "ghost_id": "test_wallet_a",
            "bond_id": "bond_a",
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "find_or_create failed: {} body={}",
        status,
        body
    );

    // Standby should have mirrored the new session within a moment.
    let mirrored = poll_until(|| standby_state.sessions.len() == 1).await;
    assert!(mirrored, "standby never observed the session");
}

#[tokio::test]
async fn second_participant_replicates_to_standby() {
    let (standby_url, standby_state) = spawn_standby().await;
    let (active_url, _active_state) = spawn_active_with_peer(standby_url).await;
    let client = reqwest::Client::new();

    // First wallet creates the session.
    let resp1 = client
        .post(format!("{}/api/v1/session/find_or_create", active_url))
        .json(&serde_json::json!({
            "tier_id": "100k_sats",
            "session_type": "mix",
            "ghost_id": "wallet_a",
            "bond_id": "bond_a",
        }))
        .send()
        .await
        .unwrap();
    assert!(resp1.status().is_success());
    let body1: serde_json::Value = resp1.json().await.unwrap();
    let session_id = body1["session"]["session_id"].as_str().unwrap().to_string();

    // Wait for SessionCreated + first ParticipantAdded to land.
    let one_ok = poll_until(|| {
        standby_state
            .sessions
            .get(&session_id)
            .map(|s| s.participants.len() == 1)
            .unwrap_or(false)
    })
    .await;
    assert!(one_ok, "standby never observed the first participant");

    // Second wallet joins the same session via the same find_or_create
    // path — same tier, different ghost_id + bond_id. The handler
    // reuses the existing session (Filling state) and publishes a
    // second ParticipantAdded gossip event.
    let resp2 = client
        .post(format!("{}/api/v1/session/find_or_create", active_url))
        .json(&serde_json::json!({
            "tier_id": "100k_sats",
            "session_type": "mix",
            "ghost_id": "wallet_b",
            "bond_id": "bond_b",
        }))
        .send()
        .await
        .unwrap();
    assert!(resp2.status().is_success());

    // Standby should now mirror two participants on the same session.
    let two_ok = poll_until(|| {
        standby_state
            .sessions
            .get(&session_id)
            .map(|s| s.participants.len() == 2)
            .unwrap_or(false)
    })
    .await;
    assert!(two_ok, "standby never observed the second participant");

    // And both ghost_ids should be present (idempotent re-apply
    // wouldn't drop the second one — see lite_session.apply_event).
    let mirrored = standby_state.sessions.get(&session_id).unwrap();
    let ghost_ids: Vec<&str> = mirrored
        .participants
        .iter()
        .map(|p| p.ghost_id.as_str())
        .collect();
    assert!(ghost_ids.contains(&"wallet_a"));
    assert!(ghost_ids.contains(&"wallet_b"));
}

#[tokio::test]
async fn state_change_replicates_to_standby() {
    use wraith_protocol::LiteSessionState;

    let (standby_url, standby_state) = spawn_standby().await;
    let (active_url, active_state) = spawn_active_with_peer(standby_url).await;
    let client = reqwest::Client::new();

    // Create the session via the Active's HTTP route so SessionCreated
    // + ParticipantAdded both fire and Standby has the session.
    let resp = client
        .post(format!("{}/api/v1/session/find_or_create", active_url))
        .json(&serde_json::json!({
            "tier_id": "100k_sats",
            "session_type": "mix",
            "ghost_id": "wallet_a",
            "bond_id": "bond_a",
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    let session_id = body["session"]["session_id"].as_str().unwrap().to_string();

    // Wait for Standby to mirror the initial Filling state.
    let mirrored = poll_until(|| {
        standby_state
            .sessions
            .get(&session_id)
            .map(|s| matches!(s.state, LiteSessionState::Filling { .. }))
            .unwrap_or(false)
    })
    .await;
    assert!(mirrored, "standby never observed initial Filling state");

    // Force a Filling → Failed transition on the Active. This goes
    // straight through the registry's `fail_session` path which
    // publishes a StateChanged gossip event.
    active_state
        .sessions
        .fail_session(&session_id, "test-injected-failure")
        .expect("fail_session on Active");

    // Standby should reflect the new Failed state with the same reason.
    let failed_ok = poll_until(|| {
        standby_state
            .sessions
            .get(&session_id)
            .map(|s| {
                matches!(
                    &s.state,
                    LiteSessionState::Failed { reason } if reason == "test-injected-failure"
                )
            })
            .unwrap_or(false)
    })
    .await;
    assert!(failed_ok, "standby never observed StateChanged → Failed");
}

#[tokio::test]
async fn signed_gossip_round_trips_when_secrets_match() {
    let secret = "shared-pool-secret".to_string();
    let (standby_url, standby_state) = spawn_standby_with_secret(Some(secret.clone())).await;
    let (active_url, _active_state) =
        spawn_active_with_peer_secret(standby_url, Some(secret)).await;

    // Same secret on both sides — same-shape scenario as the
    // unauthenticated round-trip test, but every event carries
    // X-Ghost-Signature.
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/session/find_or_create", active_url))
        .json(&serde_json::json!({
            "tier_id": "100k_sats",
            "session_type": "mix",
            "ghost_id": "wallet_a",
            "bond_id": "bond_a",
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let mirrored = poll_until(|| standby_state.sessions.len() == 1).await;
    assert!(mirrored, "standby never observed signed gossip");
}

#[tokio::test]
async fn standby_rejects_gossip_with_wrong_secret() {
    let (standby_url, standby_state) =
        spawn_standby_with_secret(Some("standby-secret".to_string())).await;
    // Active signs with a DIFFERENT secret than the Standby expects.
    let (active_url, _active_state) =
        spawn_active_with_peer_secret(standby_url, Some("active-secret".to_string())).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/session/find_or_create", active_url))
        .json(&serde_json::json!({
            "tier_id": "100k_sats",
            "session_type": "mix",
            "ghost_id": "wallet_a",
            "bond_id": "bond_a",
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "Active still serves clients fine"
    );

    // Give the gossip task plenty of time to fan out + get rejected
    // (so the test fails fast if replication is somehow happening).
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(
        standby_state.sessions.len(),
        0,
        "standby must drop gossip events with mismatched HMAC"
    );
}

#[tokio::test]
async fn standby_rejects_unsigned_gossip_when_secret_is_set() {
    let (standby_url, standby_state) =
        spawn_standby_with_secret(Some("standby-secret".to_string())).await;
    // Active doesn't sign at all (peer_secret = None) — should be
    // identical in effect to a fresh-from-the-internet attacker.
    let (active_url, _active_state) = spawn_active_with_peer_secret(standby_url, None).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v1/session/find_or_create", active_url))
        .json(&serde_json::json!({
            "tier_id": "100k_sats",
            "session_type": "mix",
            "ghost_id": "wallet_a",
            "bond_id": "bond_a",
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        standby_state.sessions.len(),
        0,
        "standby must reject unsigned gossip when configured for auth"
    );
}

#[tokio::test]
async fn solo_coordinator_with_no_peers_runs_fine() {
    // Regression guard: gossip is optional. With an empty peer list
    // the binary still boots and serves traffic.
    let state = Arc::new(CoordinatorState::with_components(
        Network::Signet,
        Arc::new(MockClock::new(1_700_000_000)),
        Arc::new(DeterministicSessionIdGenerator::new()),
        Some(TEST_FEE_ADDRESS.to_string()),
        None,
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_router(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // /health should still respond.
    let resp = reqwest::get(format!("http://{}/health", addr))
        .await
        .unwrap();
    assert!(resp.status().is_success());
}
