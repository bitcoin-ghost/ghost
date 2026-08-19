//! Tests that `WraithSessionClient::with_peers` rotates to a fallback
//! coordinator when the primary URL is unreachable.
//!
//! This is the wire-level half of task #77 (signer handover): if the
//! Active coordinator goes dark, the wallet must transparently route
//! to a Standby without operator intervention. The test proves the
//! rotation path triggers on connection-level errors but does NOT
//! trigger on HTTP error responses (which mean a coordinator answered).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use axum::{routing::post, Json, Router};
use bitcoin::Network;
use serde_json::{json, Value};
use wraith_wallet_core::wraith::{
    MixRequest, ParticipantUtxo, WraithClientError, WraithSessionClient,
};

/// Stub `/api/v1/session/find_or_create` that increments a counter on
/// each hit and returns a Filling-state session reply. We don't care
/// what happens after find_or_create — the test asserts on whether
/// THIS endpoint was reached, not whether the full mix succeeds.
async fn spawn_stub() -> (std::net::SocketAddr, Arc<AtomicU32>) {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();
    let app = Router::new().route(
        "/api/v1/session/find_or_create",
        post(move |Json(_body): Json<Value>| {
            let counter = counter_clone.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Json(json!({
                    "session": {
                        "session_id": "stub-session",
                        "tier_id": "100k_sats",
                        "denom_sats": 100_000,
                        "bond_amount_sats": 500,
                        "min_participants": 5,
                        "max_participants": 20,
                        "fill_window_secs": 300,
                        "current_state": "Filling",
                        "participant_count": 1,
                        "fees": {
                            "coord_fee_sats": 0,
                            "miner_fee_sats": 0,
                        },
                    }
                }))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    (addr, counter)
}

fn signet_addr_for(i: u8) -> String {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::{Address, CompressedPublicKey};
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[i; 32]).unwrap();
    let cpk = CompressedPublicKey(sk.public_key(&secp));
    Address::p2wpkh(&cpk, Network::Signet).to_string()
}

fn fixture_request() -> MixRequest {
    MixRequest {
        tier_id: "100k_sats".into(),
        ghost_id: "rotation-test".into(),
        bond_id_placeholder: "placeholder".into(),
        utxo: ParticipantUtxo {
            txid: "11".repeat(32),
            vout: 0,
            value_sats: 200_000,
            scriptpubkey_hex: "deadbeef".into(),
        },
        change_address: Some(signet_addr_for(50)),
        mix_output_address: signet_addr_for(1),
    }
}

/// `bond_setup` shouldn't run — `prepare_mix` returns a coordinator
/// error before reaching it because our stub only handles
/// `/find_or_create`. Returns Ok regardless to avoid masking the
/// rotation behaviour we actually care about.
fn bond_setup_noop(
    _: &str,
    _: u64,
) -> impl std::future::Future<Output = Result<(), WraithClientError>> {
    async { Ok(()) }
}

/// Likewise unreached: the stub never gets far enough to ask for an
/// ownership proof.
fn prove_ownership_noop(
    _: &str,
) -> impl std::future::Future<Output = Result<String, WraithClientError>> {
    async { Ok(String::new()) }
}

#[tokio::test]
async fn rotates_to_peer_when_primary_unreachable() {
    let (addr, counter) = spawn_stub().await;
    let live_url = format!("http://{addr}");
    // Port 1 is well-known to refuse — connect-error path.
    let dead_url = "http://127.0.0.1:1".to_string();

    let client = WraithSessionClient::with_peers(dead_url, vec![live_url], Network::Signet);

    // We expect this to FAIL — the stub only answers find_or_create —
    // but it must reach find_or_create on the peer at least once.
    let _ = client
        .prepare_mix(fixture_request(), bond_setup_noop, prove_ownership_noop)
        .await;

    assert!(
        counter.load(Ordering::SeqCst) >= 1,
        "rotation must reach the live peer at least once"
    );
}

#[tokio::test]
async fn does_not_rotate_on_http_error() {
    // A coordinator that answers but rejects with 500 must NOT cause
    // failover — that means a coordinator IS reachable, and silently
    // moving to a different one would mask real bugs.
    let app = Router::new().route(
        "/api/v1/session/find_or_create",
        post(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom") }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let primary = format!("http://{addr}");

    let (peer_addr, peer_counter) = spawn_stub().await;
    let peer_url = format!("http://{peer_addr}");

    let client = WraithSessionClient::with_peers(primary, vec![peer_url], Network::Signet);

    let result = client
        .prepare_mix(fixture_request(), bond_setup_noop, prove_ownership_noop)
        .await;

    assert!(
        matches!(
            result,
            Err(WraithClientError::Coordinator { status: 500, .. })
        ),
        "expected 500 from primary, got {result:?}"
    );
    assert_eq!(
        peer_counter.load(Ordering::SeqCst),
        0,
        "peer must NOT be hit when primary returns an HTTP error"
    );
}

// ---------------------------------------------------------------------------
// discover() — same connect-error rotation as the mix calls
// ---------------------------------------------------------------------------

async fn spawn_discover_stub(
    response_body: serde_json::Value,
) -> (std::net::SocketAddr, Arc<AtomicU32>) {
    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();
    let app = Router::new().route(
        "/api/v1/pool/discover",
        axum::routing::get(move || {
            let counter = counter_clone.clone();
            let body = response_body.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Json(body)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    (addr, counter)
}

fn canonical_discover_body() -> serde_json::Value {
    json!({
        "network": "regtest",
        "pool_id": "wraith-pool-regtest",
        "service_fee_bps": 25,
        "bond_bps": 50,
        "fill_window_secs": 300,
        "tiers": [
            {
                "id": "100k_sats",
                "denomination_sats": 100000,
                "min_participants": 5,
                "max_participants": 20,
                "bond_sats": 500,
                "service_fee_sats": 250
            }
        ]
    })
}

#[tokio::test]
async fn discover_rotates_to_peer_when_primary_unreachable() {
    let (addr, counter) = spawn_discover_stub(canonical_discover_body()).await;
    let live_url = format!("http://{addr}");
    let dead_url = "http://127.0.0.1:1".to_string();

    let client = WraithSessionClient::with_peers(dead_url, vec![live_url.clone()], Network::Signet);

    let (answered_by, parsed) = client
        .discover()
        .await
        .expect("discover must rotate to live peer");

    assert_eq!(
        answered_by, live_url,
        "answered_by must report the URL that actually served the response"
    );
    assert_eq!(parsed.network, "regtest");
    assert_eq!(parsed.tiers.len(), 1);
    assert_eq!(parsed.tiers[0].id, "100k_sats");
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "live peer must have been hit exactly once"
    );
}

#[tokio::test]
async fn discover_does_not_rotate_on_http_error() {
    // Primary answers but with 500 — must NOT trigger failover.
    // Same invariant as the mix-prepare path: a coordinator answered,
    // routing past it would mask real bugs.
    let primary_app = Router::new().route(
        "/api/v1/pool/discover",
        axum::routing::get(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom") }),
    );
    let primary_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let primary_addr = primary_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(primary_listener, primary_app).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let (peer_addr, peer_counter) = spawn_discover_stub(canonical_discover_body()).await;

    let client = WraithSessionClient::with_peers(
        format!("http://{primary_addr}"),
        vec![format!("http://{peer_addr}")],
        Network::Signet,
    );

    let result = client.discover().await;
    assert!(
        matches!(
            result,
            Err(WraithClientError::Coordinator { status: 500, .. })
        ),
        "expected 500 from primary, got {result:?}"
    );
    assert_eq!(
        peer_counter.load(Ordering::SeqCst),
        0,
        "peer must NOT be hit on HTTP error from primary"
    );
}

#[tokio::test]
async fn discover_returns_primary_url_on_success() {
    // Both endpoints are live; the primary must answer first.
    let (primary_addr, primary_counter) = spawn_discover_stub(canonical_discover_body()).await;
    let (peer_addr, peer_counter) = spawn_discover_stub(canonical_discover_body()).await;

    let primary_url = format!("http://{primary_addr}");
    let client = WraithSessionClient::with_peers(
        primary_url.clone(),
        vec![format!("http://{peer_addr}")],
        Network::Signet,
    );

    let (answered_by, _parsed) = client
        .discover()
        .await
        .expect("discover must succeed against live primary");

    assert_eq!(answered_by, primary_url);
    assert_eq!(primary_counter.load(Ordering::SeqCst), 1);
    assert_eq!(
        peer_counter.load(Ordering::SeqCst),
        0,
        "peer must not be touched when primary is healthy"
    );
}
