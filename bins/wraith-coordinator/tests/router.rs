//! End-to-end router tests. Builds the same Axum router `main()` builds
//! and exercises it via tower's `oneshot` plumbing — no port binding,
//! no flaky timing, just the request → handler → response path.

use std::str::FromStr;
use std::sync::Arc;

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use bitcoin::Network;
use tower::ServiceExt;
use wraith_coordinator::broadcaster::{Broadcaster, StubBroadcaster};
use wraith_coordinator::utxo_source::MockUtxoSource;
use wraith_coordinator::{build_router, CoordinatorState};
use wraith_protocol::{DeterministicSessionIdGenerator, MockClock};

/// Signet P2WPKH address used as the placeholder coordinator fee
/// destination + change destination in tests. Real bech32 with a
/// valid checksum so /outputs's address parser accepts it.
///
/// Deliberately **not** P2TR: neither the fee output nor a change
/// output is a mixed output, so neither is subject to the P2TR-only
/// rule (#696). It doubles as the wrong-type fixture for
/// `outputs_rejects_a_non_p2tr_address`.
const TEST_FEE_ADDRESS: &str = "tb1q0xcqpzrky6eff2g52qdye53xkk9jxkvraulyla";

/// Five distinct valid signet **P2TR** addresses for the
/// outputs-over-submission test. BIP86 key-path outputs derived from
/// `[i; 32]` secret keys 1..=5 — deterministic so the strings are
/// stable.
///
/// Mixed outputs are P2TR and nothing else (#696), so these are what a
/// wallet may register at /outputs.
const FIVE_SIGNET_ADDRS: [&str; 5] = [
    "tb1p33wm0auhr9kkahzd6l0kqj85af4cswn276hsxg6zpz85xe2r0y8snwrkwy",
    "tb1p5e6v9v2j5wp3y6c79gaqdqltq7jdv45fswnnm7exmmp2020mqepsvssqqw",
    "tb1p6wsds2al4cnjx209fcangy80exryd6hsddakha72mnhwqkapg3lqfsl44e",
    "tb1p770cds92gkjrjfu7cr76fyj82snvp6jadyre7xen6mrx2y52vphsp5shce",
    "tb1pngylwuvf9ud79em6cvp0lzx48t7ujn36670kdfsxt08ngvmc59xsuh0yev",
];

/// A sixth distinct valid signet P2TR address for the outputs-full
/// over-submission test (key = [6; 32]).
const SIXTH_SIGNET_ADDR: &str = "tb1pweq8jyw0sgtx6jure6mqpalmx5wsupexu5vtwz69gjnz99mt8a2qwxedl7";

/// The address single-submission tests register at /outputs. Must be
/// P2TR like any other mixed output.
const TEST_OUTPUT_ADDRESS: &str = FIVE_SIGNET_ADDRS[0];

fn router() -> axum::Router {
    build_router(Arc::new(CoordinatorState::new(Network::Signet)))
}

/// Router backed by deterministic clock + session-id generator,
/// a placeholder fee address, and `StubBroadcaster`.
/// Returns:
///   - the router
///   - the shared `Arc<CoordinatorState>` for direct inspection
///   - the `StubBroadcaster` so tests can assert that broadcast was
///     called once /witness collected the final submission.
fn deterministic_router(
    initial_unix: u64,
) -> (axum::Router, Arc<CoordinatorState>, StubBroadcaster) {
    let (router, state, stub, _utxos) = deterministic_router_full(initial_unix, true, true);
    (router, state, stub)
}

/// Variant that lets tests opt out of the fee address
/// (Mix-needs-fee-address path) or the broadcaster
/// (broadcaster_not_configured path).
fn deterministic_router_full(
    initial_unix: u64,
    install_fee_address: bool,
    install_broadcaster: bool,
) -> (
    axum::Router,
    Arc<CoordinatorState>,
    StubBroadcaster,
    MockUtxoSource,
) {
    let stub = StubBroadcaster::new();
    let broadcaster = if install_broadcaster {
        Some(Arc::new(stub.clone()) as Arc<dyn Broadcaster>)
    } else {
        None
    };
    // Registration reads the input from the chain, not from the
    // request (#699), so every router needs a UTXO source. This one is
    // preloaded with exactly the outpoints the `make_*` helpers
    // register; a test that claims some other value must add its own
    // entry via `deterministic_router_with_utxos`.
    let utxos = fixture_utxo_source();

    let state = Arc::new(
        CoordinatorState::with_components(
            Network::Signet,
            Arc::new(MockClock::new(initial_unix)),
            Arc::new(DeterministicSessionIdGenerator::new()),
            install_fee_address.then(|| TEST_FEE_ADDRESS.to_string()),
            broadcaster,
        )
        .with_utxo_source(Arc::new(utxos.clone())),
    );
    (build_router(state.clone()), state, stub, utxos)
}

/// A UTXO source holding exactly the outpoints the `make_*` helpers
/// register. Any test that claims a different value must add its own
/// entry.
///
/// `11…:i` is participant `i`'s coin — that is the shape
/// `make_signing_session` submits. `00…:0` is wallet-0's coin, used by
/// the single-participant tests.
fn fixture_utxo_source() -> MockUtxoSource {
    let utxos = MockUtxoSource::new();
    for i in 0..MIN_5 as u32 {
        utxos.insert(fixture_outpoint(0x11, i), 200_000, fixture_spk(i as u8));
    }
    utxos.insert(
        fixture_outpoint(0x00, 0),
        MIN_INPUT_100K_MIX,
        fixture_spk(0),
    );
    utxos
}

/// Fixture participant `i`'s key. Deterministic (`[i + 1; 32]`, since
/// zero is not a valid secret key) so every derived address and every
/// signature is stable across runs.
fn fixture_key(i: u8) -> bitcoin::PrivateKey {
    let inner = secp256k1::SecretKey::from_slice(&[i + 1; 32]).expect("valid fixture secret key");
    bitcoin::PrivateKey::new(inner, Network::Signet)
}

/// Fixture participant `i`'s BIP86 key-path P2TR address — what its coin
/// pays to, and what its ownership proof is checked against.
fn fixture_address(i: u8) -> bitcoin::Address {
    let secp = secp256k1::Secp256k1::new();
    let (xonly, _) = fixture_key(i).public_key(&secp).inner.x_only_public_key();
    bitcoin::Address::p2tr(&secp, xonly, None, Network::Signet)
}

/// The scriptPubKey of participant `i`'s coin. Registration compares the
/// claim against the chain, so the two must agree — this is the single
/// place that decides what both say.
fn fixture_spk(i: u8) -> bitcoin::ScriptBuf {
    fixture_address(i).script_pubkey()
}

/// A complete `/inputs` body for fixture participant `i`, carrying a real
/// BIP-322 proof over this session's ownership challenge.
///
/// Real rather than canned: the coordinator checks the proof against the
/// scriptPubKey the *chain* reports, so a canned blob would only ever
/// prove that the check ran, not that it verifies what it claims to.
fn signed_inputs_body(
    session_id: &str,
    ghost_id: &str,
    i: u8,
    txid_byte: u8,
    vout: u32,
    value_sats: u64,
    change_address: Option<&str>,
) -> serde_json::Value {
    let txid = format!("{txid_byte:02x}").repeat(32);
    let mut body = serde_json::json!({
        "ghost_id": ghost_id,
        "input": {
            "txid": txid,
            "vout": vout,
            "value_sats": value_sats,
            "scriptpubkey_hex": fixture_spk(i).to_hex_string(),
        },
        "ownership_proof": fixture_ownership_proof(session_id, i, &txid, vout),
    });
    if let Some(addr) = change_address {
        body["change_address"] = serde_json::Value::String(addr.into());
    }
    body
}

/// Sign the session's ownership challenge with participant `i`'s key and
/// encode it the way the BIP specifies: base64 of the witness.
fn fixture_ownership_proof(session_id: &str, i: u8, txid: &str, vout: u32) -> String {
    use base64::Engine;
    use bitcoin::consensus::Encodable;

    let challenge = wraith_protocol::ownership_challenge(session_id, txid, vout);
    let witness = bip322::sign_simple(
        &fixture_address(i),
        challenge.as_bytes(),
        &[fixture_key(i)],
        None,
    )
    .expect("sign fixture ownership proof");

    let mut encoded = Vec::new();
    witness
        .consensus_encode(&mut encoded)
        .expect("encode witness");
    base64::engine::general_purpose::STANDARD.encode(encoded)
}

/// `<byte repeated 32 times>:vout` — the shape every input fixture uses.
fn fixture_outpoint(txid_byte: u8, vout: u32) -> bitcoin::OutPoint {
    use std::str::FromStr;
    bitcoin::OutPoint {
        txid: bitcoin::Txid::from_str(&format!("{txid_byte:02x}").repeat(32))
            .expect("valid fixture txid"),
        vout,
    }
}

/// Router plus its UTXO source, for tests that register an input the
/// preloaded set doesn't cover.
fn deterministic_router_with_utxos(
    initial_unix: u64,
) -> (
    axum::Router,
    Arc<CoordinatorState>,
    StubBroadcaster,
    MockUtxoSource,
) {
    deterministic_router_full(initial_unix, true, true)
}

/// Build a JSON POST request — small ergonomics helper for the
/// find_or_create tests below.
fn post_json(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn health_endpoint_returns_200_with_expected_shape() {
    let response = router()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["service"], "wraith-coordinator");
    assert_eq!(json["network"], "signet");
    // version + uptime_secs present
    assert!(json["version"].is_string());
    assert!(json["uptime_secs"].is_number());
}

#[tokio::test]
async fn discover_endpoint_returns_full_tier_table() {
    let response = router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/pool/discover")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["network"], "signet");
    assert_eq!(json["pool_id"], "wraith-pool-signet");
    assert_eq!(json["service_fee_bps"], 50);
    assert_eq!(json["fill_window_secs"], 300);

    let tiers = json["tiers"].as_array().expect("tiers must be an array");
    assert_eq!(tiers.len(), 4, "all four Lite tiers advertised");

    // Verify the smallest tier specifically — lock the wire shape so any
    // change to LiteTier's exposed values surfaces here.
    let smallest = tiers
        .iter()
        .find(|t| t["id"] == "100k_sats")
        .expect("100k_sats tier present");
    assert_eq!(smallest["denomination_sats"], 100_000);
    assert_eq!(smallest["min_participants"], 5);
    assert_eq!(smallest["max_participants"], 20);
    assert_eq!(smallest["service_fee_sats"], 500);
}

#[tokio::test]
async fn discover_response_carries_network_in_pool_id() {
    let mainnet = build_router(Arc::new(CoordinatorState::new(Network::Bitcoin)));
    let response = mainnet
        .oneshot(
            Request::builder()
                .uri("/api/v1/pool/discover")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["network"], "mainnet");
    assert_eq!(json["pool_id"], "wraith-pool-mainnet");
}

#[tokio::test]
async fn unknown_path_returns_404() {
    let response = router()
        .oneshot(
            Request::builder()
                .uri("/this/does/not/exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// POST /api/v1/session/find_or_create
// ---------------------------------------------------------------------------

#[tokio::test]
async fn find_or_create_creates_a_new_session_when_registry_is_empty() {
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let response = router
        .oneshot(post_json(
            "/api/v1/session/find_or_create",
            serde_json::json!({
                "tier_id": "100k_sats",
                "ghost_id": "wallet-alice",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["session"]["session_id"], "test-session-0000");
    assert_eq!(json["session"]["tier_id"], "100k_sats");
    assert_eq!(json["session"]["state"], "filling");
    assert_eq!(json["session"]["slots_filled"], 1);
    assert_eq!(json["session"]["slots_total"], 20);
    assert_eq!(json["session"]["fill_window_expires_at"], 1_000_000 + 300);
    assert_eq!(json["joined"], false, "creating, not joining");

    // Registry should now hold exactly one session.
    assert_eq!(state.sessions.len(), 1);
}

#[tokio::test]
async fn find_or_create_joins_an_existing_open_session() {
    let (router, _state, _broadcaster) = deterministic_router(1_000_000);

    let body_for = |ghost: &str| {
        serde_json::json!({
            "tier_id": "100k_sats",
            "ghost_id": ghost,
        })
    };

    let alice = router
        .clone()
        .oneshot(post_json(
            "/api/v1/session/find_or_create",
            body_for("wallet-alice"),
        ))
        .await
        .unwrap();
    assert_eq!(alice.status(), StatusCode::OK);
    let alice_body = to_bytes(alice.into_body(), 4096).await.unwrap();
    let alice_json: serde_json::Value = serde_json::from_slice(&alice_body).unwrap();
    let alice_session = alice_json["session"]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();

    let bob = router
        .oneshot(post_json(
            "/api/v1/session/find_or_create",
            body_for("wallet-bob"),
        ))
        .await
        .unwrap();
    assert_eq!(bob.status(), StatusCode::OK);
    let bob_body = to_bytes(bob.into_body(), 4096).await.unwrap();
    let bob_json: serde_json::Value = serde_json::from_slice(&bob_body).unwrap();

    // Both wallets land in the same session — slots are now 2.
    assert_eq!(bob_json["session"]["session_id"], alice_session);
    assert_eq!(bob_json["session"]["slots_filled"], 2);
    assert_eq!(
        bob_json["joined"], true,
        "second wallet joined, didn't create"
    );
}

#[tokio::test]
async fn find_or_create_separates_distinct_tiers_into_distinct_sessions() {
    let (router, _state, _broadcaster) = deterministic_router(1_000_000);

    let small = router
        .clone()
        .oneshot(post_json(
            "/api/v1/session/find_or_create",
            serde_json::json!({
                "tier_id": "100k_sats",
                "ghost_id": "wallet-small",
            }),
        ))
        .await
        .unwrap();
    let small_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(small.into_body(), 4096).await.unwrap()).unwrap();

    let big = router
        .oneshot(post_json(
            "/api/v1/session/find_or_create",
            serde_json::json!({
                "tier_id": "1m_sats",
                "ghost_id": "wallet-big",
            }),
        ))
        .await
        .unwrap();
    let big_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(big.into_body(), 4096).await.unwrap()).unwrap();

    assert_ne!(
        small_json["session"]["session_id"], big_json["session"]["session_id"],
        "distinct tiers must yield distinct sessions",
    );
    assert_eq!(small_json["session"]["tier_id"], "100k_sats");
    assert_eq!(big_json["session"]["tier_id"], "1m_sats");
}

#[tokio::test]
async fn find_or_create_rejects_unknown_tier_id_with_400() {
    let (router, _state, _broadcaster) = deterministic_router(1_000_000);
    let response = router
        .oneshot(post_json(
            "/api/v1/session/find_or_create",
            serde_json::json!({
                "tier_id": "not_a_tier",
                "ghost_id": "wallet-alice",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "unknown_tier");
}

#[tokio::test]
async fn find_or_create_rejects_unknown_session_type_with_400() {
    let (router, _state, _broadcaster) = deterministic_router(1_000_000);
    let response = router
        .oneshot(post_json(
            "/api/v1/session/find_or_create",
            serde_json::json!({
                "tier_id": "100k_sats",
                "session_type": "blender",
                "ghost_id": "wallet-alice",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "unknown_session_type");
}

#[tokio::test]
async fn find_or_create_rejects_duplicate_ghost_id_with_409() {
    let (router, _state, _broadcaster) = deterministic_router(1_000_000);

    let body = serde_json::json!({
        "tier_id": "100k_sats",
        "ghost_id": "wallet-alice",
    });
    let first = router
        .clone()
        .oneshot(post_json("/api/v1/session/find_or_create", body.clone()))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    // Same ghost_id, second call — coordinator joins the same session
    // and rejects the duplicate registration.
    let dup = router
        .oneshot(post_json("/api/v1/session/find_or_create", body))
        .await
        .unwrap();
    assert_eq!(dup.status(), StatusCode::CONFLICT);
    let dup_body = to_bytes(dup.into_body(), 4096).await.unwrap();
    let dup_json: serde_json::Value = serde_json::from_slice(&dup_body).unwrap();
    assert_eq!(dup_json["error"], "already_registered");
}

#[tokio::test]
async fn find_or_create_rejects_blank_ghost_id_with_400() {
    let (router, _state, _broadcaster) = deterministic_router(1_000_000);
    let response = router
        .oneshot(post_json(
            "/api/v1/session/find_or_create",
            serde_json::json!({
                "tier_id": "100k_sats",
                "ghost_id": "   ",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "missing_ghost_id");
}

// ---------------------------------------------------------------------------
// GET /api/v1/session/{id} — status polling
// ---------------------------------------------------------------------------

/// Helper — runs find_or_create on the given router and returns the
/// session_id from the response.
async fn create_session_via_router(router: axum::Router, ghost: &str) -> String {
    let response = router
        .oneshot(post_json(
            "/api/v1/session/find_or_create",
            serde_json::json!({
                "tier_id": "100k_sats",
                "ghost_id": ghost,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    json["session"]["session_id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn session_status_returns_200_with_descriptor_for_known_session() {
    let (router, _state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = create_session_via_router(router.clone(), "wallet-a").await;

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/session/{session_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["session"]["session_id"], session_id);
    assert_eq!(json["session"]["tier_id"], "100k_sats");
    assert_eq!(json["session"]["state"], "filling");
    assert_eq!(json["session"]["slots_filled"], 1);
    assert_eq!(json["session"]["fill_window_expires_at"], 1_000_000 + 300);
}

#[tokio::test]
async fn session_status_returns_404_for_unknown_session() {
    let (router, _state, _broadcaster) = deterministic_router(1_000_000);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/session/no-such-session")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "session_not_found");
}

#[tokio::test]
async fn session_status_reflects_fill_window_expiry_after_clock_advance() {
    // 100k_sats tier needs 5 to lock; we'll add 1 then advance past
    // the fill window so the registry's tick rolls Filling → Failed
    // (FillWindowExpired). Status should report "failed".
    let mock_clock = Arc::new(MockClock::new(1_000_000));
    let state = Arc::new(CoordinatorState::with_components(
        Network::Signet,
        mock_clock.clone(),
        Arc::new(DeterministicSessionIdGenerator::new()),
        Some(TEST_FEE_ADDRESS.to_string()),
        Some(Arc::new(StubBroadcaster::new())),
    ));
    let router = build_router(state.clone());

    let session_id = create_session_via_router(router.clone(), "lonely-wallet").await;
    // Clock advances past the fill window (300s) without enough joiners.
    mock_clock.advance(301);

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/session/{session_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["session"]["state"], "failed",
        "fill window expired without quorum should surface as failed",
    );
    assert!(
        json["session"]["fill_window_expires_at"].is_null(),
        "fill_window_expires_at should be cleared once not in Filling",
    );
}

// ---------------------------------------------------------------------------
// POST /api/v1/session/:id/inputs — commit phase (B/4a, validation only)
// ---------------------------------------------------------------------------

/// Min-N for 100k_sats — 5. Anything below this won't reach Locked.
const MIN_5: usize = 5;

/// Per-participant minimum input for 100k_sats Mix at the default fee rate.
/// Computed from: denom 100_000 + service_fee 500 + ceil((5*58 + 12*43)*10/5)
/// = 100_000 + 500 + 1612 = 102_112. Same number the handler computes.
const MIN_INPUT_100K_MIX: u64 = 102_112;

/// A scriptPubKey with no address form at all. Registration has to
/// refuse it rather than panic deriving an address to check a proof
/// against.
const NONSTANDARD_SPK_HEX: &str = "deadbeef";

/// Drive 5 wallets through /find_or_create,
/// then advance the clock past the fill window so the registry's tick
/// transitions Filling → Locked. Returns the session_id.
async fn make_locked_session(router: axum::Router, state: &Arc<CoordinatorState>) -> String {
    // Enrol 5 distinct wallets.
    let mut session_id: Option<String> = None;
    for i in 0..MIN_5 {
        let resp = router
            .clone()
            .oneshot(post_json(
                "/api/v1/session/find_or_create",
                serde_json::json!({
                    "tier_id": "100k_sats",
                    "ghost_id": format!("wallet-{i}"),
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "find_or_create #{i}");
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let sid = json["session"]["session_id"].as_str().unwrap().to_owned();
        if session_id.is_none() {
            session_id = Some(sid.clone());
        } else {
            assert_eq!(session_id.as_deref(), Some(sid.as_str()));
        }
    }
    let session_id = session_id.expect("at least one find_or_create succeeded");

    // 100k_sats has min=5 but max=20, so 5 joiners doesn't auto-lock —
    // the registry would normally wait for the fill window to expire
    // and then run tick(). We can't reach through `Arc<dyn Clock>` to
    // advance the underlying MockClock, so we drive the same end state
    // via the gossip path that production tick + standby failover both
    // use.
    state
        .sessions
        .apply_event(wraith_protocol::SessionGossipEvent::StateChanged {
            session_id: session_id.clone(),
            new_state: wraith_protocol::LiteSessionState::Locked,
        })
        .expect("apply Locked");

    session_id
}

#[tokio::test]
async fn inputs_returns_404_for_unknown_session() {
    let (router, _state, _broadcaster) = deterministic_router(1_000_000);
    let response = router
        .oneshot(post_json(
            "/api/v1/session/no-such-session/inputs",
            serde_json::json!({
                "ghost_id": "wallet-x",
                "input": {
                    "txid": "00".repeat(32),
                    "vout": 0,
                    "value_sats": MIN_INPUT_100K_MIX,
                    "scriptpubkey_hex": "deadbeef",
                },
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "session_not_found");
}

#[tokio::test]
async fn inputs_returns_409_when_session_still_filling() {
    let (router, _state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = create_session_via_router(router.clone(), "wallet-a").await;
    // Session is in Filling. /inputs should reject.
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            serde_json::json!({
                "ghost_id": "wallet-a",
                "input": {
                    "txid": "00".repeat(32),
                    "vout": 0,
                    "value_sats": MIN_INPUT_100K_MIX,
                    "scriptpubkey_hex": "deadbeef",
                },
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "wrong_session_state");
}

#[tokio::test]
async fn inputs_returns_403_for_unenrolled_ghost_id() {
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;
    // wallet-99 is not on the participant list.
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            serde_json::json!({
                "ghost_id": "wallet-99",
                "input": {
                    "txid": "00".repeat(32),
                    "vout": 0,
                    "value_sats": MIN_INPUT_100K_MIX,
                    "scriptpubkey_hex": "deadbeef",
                },
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "not_enrolled");
}

/// Ownership proofs are not optional. Without one, registering someone
/// else's coin is free (#699).
#[tokio::test]
async fn inputs_rejects_a_missing_ownership_proof() {
    let (router, state, _broadcaster, _utxos) = deterministic_router_with_utxos(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;

    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "input": {
                    "txid": "00".repeat(32),
                    "vout": 0,
                    "value_sats": MIN_INPUT_100K_MIX,
                    "scriptpubkey_hex": fixture_spk(0).to_hex_string(),
                },
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "missing_ownership_proof");
}

/// A proof that is not a base64 witness is a wallet bug, and says so,
/// rather than being reported as a failed proof.
#[tokio::test]
async fn inputs_rejects_a_malformed_ownership_proof() {
    let (router, state, _broadcaster, _utxos) = deterministic_router_with_utxos(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;

    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "input": {
                    "txid": "00".repeat(32),
                    "vout": 0,
                    "value_sats": MIN_INPUT_100K_MIX,
                    "scriptpubkey_hex": fixture_spk(0).to_hex_string(),
                },
                "ownership_proof": "not base64 at all!!",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "bad_ownership_proof");
}

/// **The attack this is all for.** Register a coin belonging to someone
/// else, and prove ownership with a key of your own.
///
/// It fails because the proof is checked against the scriptPubKey the
/// chain reports for that outpoint, not the one the submission names.
/// Without the chain lookup underneath, this test would pass.
#[tokio::test]
async fn inputs_rejects_a_proof_made_with_the_wrong_key() {
    let (router, state, _broadcaster, utxos) = deterministic_router_with_utxos(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;
    // The coin at 00…:0 belongs to participant 1.
    utxos.insert(fixture_outpoint(0x00, 0), 200_000, fixture_spk(1));

    let txid = "00".repeat(32);
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "input": {
                    "txid": txid,
                    "vout": 0,
                    "value_sats": 200_000,
                    // Names the true script, as it must to get this far.
                    "scriptpubkey_hex": fixture_spk(1).to_hex_string(),
                },
                // ...but signs with participant 0's key.
                "ownership_proof": fixture_ownership_proof(&session_id, 0, &txid, 0),
                "change_address": TEST_FEE_ADDRESS,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "ownership_proof_failed");
}

/// A proof is bound to its session, so one captured from an earlier
/// round cannot be replayed into a round its owner never joined.
#[tokio::test]
async fn inputs_rejects_a_proof_bound_to_another_session() {
    let (router, state, _broadcaster, utxos) = deterministic_router_with_utxos(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;
    utxos.insert(fixture_outpoint(0x00, 0), 200_000, fixture_spk(0));

    let txid = "00".repeat(32);
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "input": {
                    "txid": txid,
                    "vout": 0,
                    "value_sats": 200_000,
                    "scriptpubkey_hex": fixture_spk(0).to_hex_string(),
                },
                // Right key, right coin, wrong round.
                "ownership_proof": fixture_ownership_proof("some-other-session", 0, &txid, 0),
                "change_address": TEST_FEE_ADDRESS,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "ownership_proof_failed");
}

/// A proof is bound to its outpoint, so proving you own one coin does
/// not authorise registering another.
#[tokio::test]
async fn inputs_rejects_a_proof_bound_to_another_outpoint() {
    let (router, state, _broadcaster, utxos) = deterministic_router_with_utxos(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;
    utxos.insert(fixture_outpoint(0x00, 0), 200_000, fixture_spk(0));

    let txid = "00".repeat(32);
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "input": {
                    "txid": txid,
                    "vout": 0,
                    "value_sats": 200_000,
                    "scriptpubkey_hex": fixture_spk(0).to_hex_string(),
                },
                // Same key and session, but a proof over vout 1.
                "ownership_proof": fixture_ownership_proof(&session_id, 0, &txid, 1),
                "change_address": TEST_FEE_ADDRESS,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "ownership_proof_failed");
}

/// A scriptPubKey with no address form has nothing to check a proof
/// against, so registration refuses it rather than failing obscurely.
#[tokio::test]
async fn inputs_rejects_an_input_with_no_address_form() {
    let (router, state, _broadcaster, utxos) = deterministic_router_with_utxos(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;
    utxos.insert(
        fixture_outpoint(0x00, 0),
        200_000,
        bitcoin::ScriptBuf::from_hex(NONSTANDARD_SPK_HEX).unwrap(),
    );

    let txid = "00".repeat(32);
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "input": {
                    "txid": txid,
                    "vout": 0,
                    "value_sats": 200_000,
                    "scriptpubkey_hex": NONSTANDARD_SPK_HEX,
                },
                "ownership_proof": fixture_ownership_proof(&session_id, 0, &txid, 0),
                "change_address": TEST_FEE_ADDRESS,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "unsupported_input_script");
}

/// One outpoint, one participant (#701).
///
/// Two participants registering the same coin builds a transaction with
/// duplicate inputs, which cannot broadcast — so the round dies for
/// everyone at a cost of one enrolment, and it dies at broadcast rather
/// than at signing, where the no-sign deadline would have caught it.
#[tokio::test]
async fn inputs_rejects_an_outpoint_another_participant_already_registered() {
    let (router, state, _broadcaster, utxos) = deterministic_router_with_utxos(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;
    utxos.insert(fixture_outpoint(0x00, 0), 200_000, fixture_spk(0));

    // One person, two enrolments, one coin — which is what the attack
    // reduces to once ownership is proved: you can no longer register a
    // coin you do not control, but you can still register your own twice
    // and kill the round.
    let body = |ghost_id: &str| {
        signed_inputs_body(
            &session_id,
            ghost_id,
            0,
            0x00,
            0,
            200_000,
            Some(TEST_FEE_ADDRESS),
        )
    };

    let first = router
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            body("wallet-0"),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let second = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            body("wallet-1"),
        ))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
    let body = to_bytes(second.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "duplicate_outpoint");
}

/// The duplicate rule must not break the retry path: a participant
/// resubmitting its *own* outpoint is a wallet retry, not a collision.
#[tokio::test]
async fn inputs_still_accepts_a_participant_resubmitting_its_own_outpoint() {
    let (router, state, _broadcaster, utxos) = deterministic_router_with_utxos(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;
    utxos.insert(fixture_outpoint(0x00, 0), 200_000, fixture_spk(0));

    let body = signed_inputs_body(
        &session_id,
        "wallet-0",
        0,
        0x00,
        0,
        200_000,
        Some(TEST_FEE_ADDRESS),
    );

    for attempt in 0..2 {
        let resp = router
            .clone()
            .oneshot(post_json(
                &format!("/api/v1/session/{session_id}/inputs"),
                body.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "attempt {attempt}");
        let json: serde_json::Value =
            serde_json::from_slice(&to_bytes(resp.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(json["submitted_count"], 1, "attempt {attempt}");
    }
}

/// Registration must refuse rather than fall back to trusting the
/// wallet's own account of its input (#699).
#[tokio::test]
async fn inputs_returns_503_when_no_utxo_source_is_configured() {
    let state = Arc::new(CoordinatorState::with_components(
        Network::Signet,
        Arc::new(MockClock::new(1_000_000)),
        Arc::new(DeterministicSessionIdGenerator::new()),
        Some(TEST_FEE_ADDRESS.to_string()),
        Some(Arc::new(StubBroadcaster::new())),
    ));
    let router = build_router(state.clone());
    let session_id = make_locked_session(router.clone(), &state).await;

    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "input": {
                    "txid": "00".repeat(32),
                    "vout": 0,
                    "value_sats": MIN_INPUT_100K_MIX,
                    "scriptpubkey_hex": fixture_spk(0).to_hex_string(),
                },
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "utxo_source_not_configured");
}

/// An outpoint that is not in the UTXO set — never existed, or already
/// spent. Both answer the same way on purpose: distinguishing them
/// would answer a question about the chain the submitter did not ask.
#[tokio::test]
async fn inputs_rejects_an_outpoint_that_is_not_unspent() {
    let (router, state, _broadcaster, utxos) = deterministic_router_with_utxos(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;
    utxos.remove(&fixture_outpoint(0x00, 0));

    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "input": {
                    "txid": "00".repeat(32),
                    "vout": 0,
                    "value_sats": MIN_INPUT_100K_MIX,
                    "scriptpubkey_hex": fixture_spk(0).to_hex_string(),
                },
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "utxo_not_found");
}

/// The chain decides what an input is worth. A wallet claiming
/// otherwise is refused rather than silently corrected, so a stale
/// wallet learns it is stale instead of having its arithmetic changed
/// underneath it.
#[tokio::test]
async fn inputs_rejects_a_value_the_chain_disagrees_with() {
    let (router, state, _broadcaster, utxos) = deterministic_router_with_utxos(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;
    utxos.insert(fixture_outpoint(0x00, 0), 150_000, fixture_spk(0));

    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "input": {
                    "txid": "00".repeat(32),
                    "vout": 0,
                    // Claims nearly seven times what the chain holds.
                    "value_sats": 1_000_000,
                    "scriptpubkey_hex": fixture_spk(0).to_hex_string(),
                },
                "change_address": TEST_FEE_ADDRESS,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "value_mismatch");
}

/// The scriptPubKey matters more than the value: it is what an
/// ownership proof will be checked against, so a submitter must not be
/// able to name a script it chose for a coin it does not control.
#[tokio::test]
async fn inputs_rejects_a_scriptpubkey_the_chain_disagrees_with() {
    let (router, state, _broadcaster, utxos) = deterministic_router_with_utxos(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;
    utxos.insert(
        fixture_outpoint(0x00, 0),
        MIN_INPUT_100K_MIX,
        bitcoin::ScriptBuf::from_hex("0014aabbccddeeff00112233445566778899aabbccdd").unwrap(),
    );

    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "input": {
                    "txid": "00".repeat(32),
                    "vout": 0,
                    "value_sats": MIN_INPUT_100K_MIX,
                    // A script the submitter controls, for a coin it does not.
                    "scriptpubkey_hex": fixture_spk(0).to_hex_string(),
                },
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "scriptpubkey_mismatch");
}

/// An unconfirmed input can be replaced out from under the round by its
/// own parent, invalidating the transaction after everyone has signed.
#[tokio::test]
async fn inputs_rejects_an_unconfirmed_input() {
    use wraith_coordinator::utxo_source::Utxo;
    let (router, state, _broadcaster, utxos) = deterministic_router_with_utxos(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;
    utxos.insert_utxo(
        fixture_outpoint(0x00, 0),
        Utxo {
            value_sats: MIN_INPUT_100K_MIX,
            script_pubkey: fixture_spk(0),
            confirmations: 0,
            coinbase: false,
        },
    );

    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "input": {
                    "txid": "00".repeat(32),
                    "vout": 0,
                    "value_sats": MIN_INPUT_100K_MIX,
                    "scriptpubkey_hex": fixture_spk(0).to_hex_string(),
                },
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "input_unconfirmed");
}

/// A coinbase output is unspendable until 100 confirmations, so a round
/// built on an immature one cannot broadcast.
#[tokio::test]
async fn inputs_rejects_an_immature_coinbase() {
    use wraith_coordinator::utxo_source::Utxo;
    let (router, state, _broadcaster, utxos) = deterministic_router_with_utxos(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;
    utxos.insert_utxo(
        fixture_outpoint(0x00, 0),
        Utxo {
            value_sats: MIN_INPUT_100K_MIX,
            script_pubkey: fixture_spk(0),
            confirmations: 99,
            coinbase: true,
        },
    );

    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "input": {
                    "txid": "00".repeat(32),
                    "vout": 0,
                    "value_sats": MIN_INPUT_100K_MIX,
                    "scriptpubkey_hex": fixture_spk(0).to_hex_string(),
                },
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "immature_coinbase");
}

#[tokio::test]
async fn inputs_rejects_input_below_minimum_with_400() {
    let (router, state, _broadcaster, utxos) = deterministic_router_with_utxos(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;
    // The chain says this outpoint really is worth 1,000 sats, so the
    // refusal is about the tier minimum and not about a stale claim.
    utxos.insert(fixture_outpoint(0x00, 0), 1_000, fixture_spk(0));
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            // 1000 sats well below the minimum 102_112.
            signed_inputs_body(&session_id, "wallet-0", 0, 0x00, 0, 1_000, None),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "insufficient_input");
}

#[tokio::test]
async fn inputs_rejects_surplus_above_dust_without_change_address() {
    let (router, state, _broadcaster, utxos) = deterministic_router_with_utxos(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;
    utxos.insert(fixture_outpoint(0x00, 0), 200_000, fixture_spk(0));
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            // Big surplus (~98k sats over min) but no change address.
            signed_inputs_body(&session_id, "wallet-0", 0, 0x00, 0, 200_000, None),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "missing_change_address");
}

#[tokio::test]
async fn inputs_accepts_exact_minimum_without_change_address() {
    // Exact-minimum input (no surplus) is fine without a change address.
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            signed_inputs_body(
                &session_id,
                "wallet-0",
                0,
                0x00,
                0,
                MIN_INPUT_100K_MIX,
                None,
            ),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["session_id"], session_id);
    assert_eq!(json["state"], "locked", "1/5 submitted; not yet Signing");
    assert_eq!(json["submitted_count"], 1);
    assert_eq!(json["enrolled_count"], 5);
}

#[tokio::test]
async fn inputs_advances_session_to_signing_when_all_submit() {
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;
    for i in 0..MIN_5 {
        let response = router
            .clone()
            .oneshot(post_json(
                &format!("/api/v1/session/{session_id}/inputs"),
                signed_inputs_body(
                    &session_id,
                    &format!("wallet-{i}"),
                    i as u8,
                    0x11,
                    i as u32,
                    200_000,
                    Some(TEST_FEE_ADDRESS),
                ),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "submission #{i}");
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let expected_state = if i + 1 == MIN_5 { "signing" } else { "locked" };
        assert_eq!(json["state"], expected_state, "after submission {i}");
        assert_eq!(json["submitted_count"], (i as u32) + 1);
    }
    // Final session state in the registry confirms the transition.
    let final_session = state.sessions.get(&session_id).expect("session present");
    assert!(matches!(
        final_session.state,
        wraith_protocol::LiteSessionState::Signing
    ));
}

#[tokio::test]
async fn inputs_idempotent_on_resubmission() {
    // Wallet retries with a different input; the latest submission
    // wins and the count doesn't double-up.
    //
    // The retry names a *different coin* rather than a different value
    // for the same one: value comes from the chain now, so re-pricing
    // one outpoint is a stale claim, not a retry.
    let (router, state, _broadcaster, utxos) = deterministic_router_with_utxos(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;
    utxos.insert(fixture_outpoint(0x00, 0), 200_000, fixture_spk(0));
    utxos.insert(fixture_outpoint(0x22, 0), 300_000, fixture_spk(0));
    let body = |txid_byte: u8, sats: u64| {
        signed_inputs_body(
            &session_id,
            "wallet-0",
            0,
            txid_byte,
            0,
            sats,
            Some(TEST_FEE_ADDRESS),
        )
    };
    let first = router
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            body(0x00, 200_000),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(first.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(first_json["submitted_count"], 1);

    let second = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            body(0x22, 300_000),
        ))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    let second_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(second.into_body(), 4096).await.unwrap()).unwrap();
    // Still one submission, not two — the duplicate replaced the first.
    assert_eq!(second_json["submitted_count"], 1);
}

// ---------------------------------------------------------------------------
// POST /api/v1/session/:id/nonce + /blind-sign — Schnorr blind signature (B/4b)
// ---------------------------------------------------------------------------

/// /nonce on a properly-locked session with an enrolled wallet returns
/// 200 with hex-encoded crypto material that's the right length.
#[tokio::test]
async fn nonce_returns_200_with_valid_shape() {
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state).await;
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/nonce"),
            serde_json::json!({ "ghost_id": "wallet-0" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let pubkey_hex = json["signing_pubkey"].as_str().unwrap();
    let key_id_hex = json["signing_key_id"].as_str().unwrap();
    let nonce_hex = json["nonce_point"].as_str().unwrap();
    let blind_sid_hex = json["blind_session_id"].as_str().unwrap();
    assert_eq!(pubkey_hex.len(), 66, "33-byte SEC1 compressed");
    assert_eq!(key_id_hex.len(), 64, "32-byte sha256");
    assert_eq!(nonce_hex.len(), 66, "33-byte SEC1 compressed");
    assert_eq!(blind_sid_hex.len(), 64, "32-byte session id");
}

#[tokio::test]
async fn nonce_returns_403_for_unenrolled_ghost_id() {
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state).await;
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/nonce"),
            serde_json::json!({ "ghost_id": "wallet-99" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "not_enrolled");
}

#[tokio::test]
async fn nonce_returns_409_for_filling_session() {
    let (router, _state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = create_session_via_router(router.clone(), "wallet-a").await;
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/nonce"),
            serde_json::json!({ "ghost_id": "wallet-a" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "wrong_session_state");
}

#[tokio::test]
async fn nonce_returns_404_for_unknown_session() {
    let (router, _state, _broadcaster) = deterministic_router(1_000_000);
    let response = router
        .oneshot(post_json(
            "/api/v1/session/no-such-session/nonce",
            serde_json::json!({ "ghost_id": "x" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "session_not_found");
}

#[tokio::test]
async fn blind_sign_returns_400_when_no_signer_for_round() {
    // /blind-sign before any /nonce on this round → 400 no_active_signer.
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state).await;
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/blind-sign"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "blinded_challenge": "00".repeat(32),
                "blind_session_id": "00".repeat(32),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "no_active_signer");
}

#[tokio::test]
async fn blind_sign_returns_400_for_bad_hex() {
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state).await;
    // Prime a signer so we get past the no_active_signer gate.
    let _ = router
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/nonce"),
            serde_json::json!({ "ghost_id": "wallet-0" }),
        ))
        .await
        .unwrap();
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/blind-sign"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "blinded_challenge": "not-hex",
                "blind_session_id": "00".repeat(32),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "bad_blinded_challenge");
}

#[tokio::test]
async fn blind_sign_rejects_cross_participant_nonce_hijack() {
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state).await;

    // wallet-0 requests a nonce.
    let nonce_resp = router
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/nonce"),
            serde_json::json!({ "ghost_id": "wallet-0" }),
        ))
        .await
        .unwrap();
    assert_eq!(nonce_resp.status(), StatusCode::OK);
    let nonce_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(nonce_resp.into_body(), 4096).await.unwrap()).unwrap();
    let blind_sid = nonce_json["blind_session_id"].as_str().unwrap().to_string();

    // wallet-1 attempts to use wallet-0's nonce. Coordinator rejects.
    let bad_resp = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/blind-sign"),
            serde_json::json!({
                "ghost_id": "wallet-1",
                "blinded_challenge": "11".repeat(32),
                "blind_session_id": blind_sid,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(bad_resp.status(), StatusCode::FORBIDDEN);
    let bad_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(bad_resp.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(bad_json["error"], "blind_sign_rejected");
}

/// End-to-end happy path: wallet runs the full blind-sig protocol
/// against the coordinator and verifies the resulting unblinded
/// signature with `TokenVerifier`. Demonstrates that the two endpoints
/// implement the protocol correctly — the coordinator's signature is
/// a valid Schnorr sig on the wallet's chosen message and the
/// coordinator never saw the message.
#[tokio::test]
async fn blind_sign_full_round_trip_produces_valid_signature() {
    use secp256k1::PublicKey;
    use wraith_protocol::{BlindSignatureResponse, BlindingContext, PublicNonce, TokenVerifier};

    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state).await;

    // Step 1 — wallet asks coordinator for a fresh nonce.
    let nonce_resp = router
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/nonce"),
            serde_json::json!({ "ghost_id": "wallet-0" }),
        ))
        .await
        .unwrap();
    assert_eq!(nonce_resp.status(), StatusCode::OK);
    let nonce_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(nonce_resp.into_body(), 4096).await.unwrap()).unwrap();

    let signing_pubkey_bytes = hex::decode(nonce_json["signing_pubkey"].as_str().unwrap()).unwrap();
    let signer_session_id_bytes =
        hex::decode(nonce_json["signer_session_id"].as_str().unwrap()).unwrap();
    let signing_key_id_bytes = hex::decode(nonce_json["signing_key_id"].as_str().unwrap()).unwrap();
    let nonce_point_bytes = hex::decode(nonce_json["nonce_point"].as_str().unwrap()).unwrap();
    let blind_sid_bytes = hex::decode(nonce_json["blind_session_id"].as_str().unwrap()).unwrap();

    let coordinator_pubkey = PublicKey::from_slice(&signing_pubkey_bytes).expect("valid pubkey");
    let mut nonce_point_arr = [0u8; 33];
    nonce_point_arr.copy_from_slice(&nonce_point_bytes);
    let mut blind_sid_arr = [0u8; 32];
    blind_sid_arr.copy_from_slice(&blind_sid_bytes);
    let mut signing_key_id_arr = [0u8; 32];
    signing_key_id_arr.copy_from_slice(&signing_key_id_bytes);
    let mut signer_session_id_arr = [0u8; 32];
    signer_session_id_arr.copy_from_slice(&signer_session_id_bytes);

    let public_nonce = PublicNonce {
        nonce_point: nonce_point_arr,
        session_id: blind_sid_arr,
    };

    // Step 2 — wallet builds a blinding context over its own message
    // (the unblinded mix-output address it wants signed) and computes
    // the blinded challenge.
    let message = b"wallet-0 chose this output address".to_vec();
    let blinding = BlindingContext::new(message.clone(), &coordinator_pubkey, &public_nonce)
        .expect("blinding context");
    let blinded_challenge = blinding
        .create_blinded_challenge()
        .expect("blinded challenge");

    // Step 3 — wallet posts the blinded challenge to /blind-sign.
    let sign_resp = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/blind-sign"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "blinded_challenge": hex::encode(blinded_challenge.challenge),
                "blind_session_id": hex::encode(blinded_challenge.session_id),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(sign_resp.status(), StatusCode::OK);
    let sign_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(sign_resp.into_body(), 4096).await.unwrap()).unwrap();
    let s_bytes_vec = hex::decode(sign_json["signature_scalar"].as_str().unwrap()).unwrap();
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&s_bytes_vec);

    let response = BlindSignatureResponse {
        signature_scalar: s_bytes,
        session_id: blind_sid_arr,
    };

    // Step 4 — wallet unblinds locally, then verifies. The verifier
    // sees only the unblinded signature on the wallet's chosen message,
    // and the verification ought to pass — proving the coordinator
    // signed something it never saw.
    let token = blinding
        .unblind(&response, signing_key_id_arr)
        .expect("unblind");
    assert_eq!(token.message, message, "message preserved through unblind");

    // The verifier takes the SIGNER's session_id (not the key_id) and
    // re-derives the key_id internally to match `token.session_key_id`.
    let verifier = TokenVerifier::new(coordinator_pubkey, &signer_session_id_arr);
    let valid = verifier.verify(&token).expect("verify");
    assert!(
        valid,
        "unblinded signature must be a valid Schnorr sig on the wallet's message"
    );

    // Crucially: the coordinator never saw `message`. The blinded
    // challenge is c' = c + β where c = H(X || R' || message). The
    // coordinator returns s = k + c'*x without learning c (β was
    // generated locally and never transmitted). Unlinkability holds.
}

// ---------------------------------------------------------------------------
// POST /api/v1/session/:id/outputs — anonymous output submission (B/5a)
// ---------------------------------------------------------------------------

/// Drive a session all the way through to Signing state with all 5
/// participants having submitted /inputs. Returns the session_id; the
/// session is ready for /nonce + /blind-sign + /outputs.
async fn make_signing_session(router: axum::Router, state: &Arc<CoordinatorState>) -> String {
    let session_id = make_locked_session(router.clone(), state).await;
    // 5 participants submit /inputs → session advances to Signing.
    for i in 0..MIN_5 {
        let resp = router
            .clone()
            .oneshot(post_json(
                &format!("/api/v1/session/{session_id}/inputs"),
                signed_inputs_body(
                    &session_id,
                    &format!("wallet-{i}"),
                    i as u8,
                    0x11,
                    i as u32,
                    200_000,
                    Some(TEST_FEE_ADDRESS),
                ),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "inputs #{i}");
    }
    // Confirm we're now in Signing.
    let snapshot = state.sessions.get(&session_id).expect("present");
    assert!(matches!(
        snapshot.state,
        wraith_protocol::LiteSessionState::Signing
    ));
    session_id
}

/// One pass of the wallet-side blind-sig protocol: call /nonce, build
/// a `BlindingContext` over `message`, post the blinded challenge to
/// /blind-sign, return everything needed for an /outputs submission.
async fn run_blind_sig_for(
    router: axum::Router,
    session_id: &str,
    ghost_id: &str,
    message: Vec<u8>,
) -> (String, String) {
    use secp256k1::PublicKey;
    use wraith_protocol::{BlindSignatureResponse, BlindingContext, PublicNonce};

    let nonce_resp = router
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/nonce"),
            serde_json::json!({ "ghost_id": ghost_id }),
        ))
        .await
        .unwrap();
    assert_eq!(nonce_resp.status(), StatusCode::OK);
    let nj: serde_json::Value =
        serde_json::from_slice(&to_bytes(nonce_resp.into_body(), 4096).await.unwrap()).unwrap();

    let pubkey =
        PublicKey::from_slice(&hex::decode(nj["signing_pubkey"].as_str().unwrap()).unwrap())
            .unwrap();
    let mut nonce_point = [0u8; 33];
    nonce_point.copy_from_slice(&hex::decode(nj["nonce_point"].as_str().unwrap()).unwrap());
    let mut blind_sid = [0u8; 32];
    blind_sid.copy_from_slice(&hex::decode(nj["blind_session_id"].as_str().unwrap()).unwrap());
    let mut key_id = [0u8; 32];
    key_id.copy_from_slice(&hex::decode(nj["signing_key_id"].as_str().unwrap()).unwrap());

    let public_nonce = PublicNonce {
        nonce_point,
        session_id: blind_sid,
    };
    let ctx = BlindingContext::new(message, &pubkey, &public_nonce).unwrap();
    let blinded = ctx.create_blinded_challenge().unwrap();
    let blinded_nonce = ctx.blinded_nonce().serialize();

    let sign_resp = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/blind-sign"),
            serde_json::json!({
                "ghost_id": ghost_id,
                "blinded_challenge": hex::encode(blinded.challenge),
                "blind_session_id": hex::encode(blinded.session_id),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(sign_resp.status(), StatusCode::OK);
    let sj: serde_json::Value =
        serde_json::from_slice(&to_bytes(sign_resp.into_body(), 4096).await.unwrap()).unwrap();
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&hex::decode(sj["signature_scalar"].as_str().unwrap()).unwrap());

    let response = BlindSignatureResponse {
        signature_scalar: s_bytes,
        session_id: blind_sid,
    };
    let token = ctx.unblind(&response, key_id).unwrap();

    (
        hex::encode(blinded_nonce),
        hex::encode(token.signature_scalar),
    )
}

#[tokio::test]
async fn outputs_returns_404_for_unknown_session() {
    let (router, _state, _broadcaster) = deterministic_router(1_000_000);
    let response = router
        .oneshot(post_json(
            "/api/v1/session/no-such-session/outputs",
            serde_json::json!({
                "address": TEST_OUTPUT_ADDRESS,
                "blinded_nonce_point": "00".repeat(33),
                "unblinded_signature_scalar": "00".repeat(32),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "session_not_found");
}

#[tokio::test]
async fn outputs_returns_409_when_session_still_locked() {
    // /outputs only accepts in Signing state. A session in Locked
    // (post-/nonce, pre-all-/inputs) is not yet accepting outputs.
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/outputs"),
            serde_json::json!({
                "address": TEST_OUTPUT_ADDRESS,
                "blinded_nonce_point": "00".repeat(33),
                "unblinded_signature_scalar": "00".repeat(32),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "wrong_session_state");
}

#[tokio::test]
async fn outputs_rejects_address_for_wrong_network() {
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state).await;
    // Need a signer to exist before signature checks would matter,
    // but address parsing happens first — exercise that path with
    // a mainnet-format address against this signet coordinator.
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/outputs"),
            serde_json::json!({
                // Mainnet bech32 prefix (`bc1`) not valid for signet.
                "address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                "blinded_nonce_point": "00".repeat(33),
                "unblinded_signature_scalar": "00".repeat(32),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "wrong_network");
}

/// Every mixed output in a round is P2TR (#696).
///
/// Equal values buy the anonymity set; equal values across *mixed*
/// script types do not — a lone P2WPKH output among P2TR ones is
/// trivially separable inside the round, and its owner gains nothing
/// while believing they did. Registration is the only place this can be
/// caught: by round-build time the outputs are committed, and the blind
/// signature means the coordinator cannot tell whose they are.
///
/// The refusal must land *before* the signature check, so a wallet
/// learns the type is wrong rather than getting a generic verification
/// failure.
#[tokio::test]
async fn outputs_rejects_a_non_p2tr_address() {
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state).await;

    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/outputs"),
            serde_json::json!({
                // Valid signet address, right network, wrong type.
                "address": TEST_FEE_ADDRESS,
                "blinded_nonce_point": "00".repeat(33),
                "unblinded_signature_scalar": "00".repeat(32),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "not_p2tr");
}

#[tokio::test]
async fn outputs_rejects_when_no_signer_initialised() {
    // Session in Signing but nobody ever called /nonce, so no signer
    // exists. /outputs has nothing to verify against.
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state).await;
    // Sanity: signers map is empty.
    assert!(state.signers.lock().unwrap().get(&session_id).is_none());

    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/outputs"),
            serde_json::json!({
                "address": TEST_OUTPUT_ADDRESS,
                "blinded_nonce_point": "00".repeat(33),
                "unblinded_signature_scalar": "00".repeat(32),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "no_active_signer");
}

#[tokio::test]
async fn outputs_rejects_invalid_signature_with_403() {
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state).await;
    // Prime the signer so the no_active_signer gate doesn't fire.
    let _ = router
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/nonce"),
            serde_json::json!({ "ghost_id": "wallet-0" }),
        ))
        .await
        .unwrap();
    // Submit a syntactically-valid but cryptographically-junk sig.
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/outputs"),
            serde_json::json!({
                "address": TEST_OUTPUT_ADDRESS,
                // 33-byte point that's actually a valid SEC1 generator-G
                // serialisation (not zero, which from_slice rejects).
                "blinded_nonce_point": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "unblinded_signature_scalar": "01".repeat(32),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "verification_failed");
}

#[tokio::test]
async fn outputs_full_round_trip_accepts_valid_signature() {
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state).await;

    let address = TEST_OUTPUT_ADDRESS.to_string();
    let (blinded_nonce_hex, unblinded_sig_hex) = run_blind_sig_for(
        router.clone(),
        &session_id,
        "wallet-0",
        address.as_bytes().to_vec(),
    )
    .await;

    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/outputs"),
            serde_json::json!({
                "address": address,
                "blinded_nonce_point": blinded_nonce_hex,
                "unblinded_signature_scalar": unblinded_sig_hex,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["session_id"], session_id);
    assert_eq!(json["state"], "signing");
    assert_eq!(json["outputs_collected"], 1);
    assert_eq!(json["enrolled_count"], 5);
}

#[tokio::test]
async fn outputs_rejects_duplicate_address_with_409() {
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state).await;

    let address = TEST_OUTPUT_ADDRESS.to_string();
    let (n1, s1) = run_blind_sig_for(
        router.clone(),
        &session_id,
        "wallet-0",
        address.as_bytes().to_vec(),
    )
    .await;

    let body = |bn: &str, us: &str| {
        serde_json::json!({
            "address": &address,
            "blinded_nonce_point": bn,
            "unblinded_signature_scalar": us,
        })
    };

    let first = router
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/outputs"),
            body(&n1, &s1),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    // Second wallet runs a fresh blind-sig over the SAME address.
    // Both signatures verify, but the coordinator refuses to record
    // the duplicate.
    let (n2, s2) = run_blind_sig_for(
        router.clone(),
        &session_id,
        "wallet-1",
        address.as_bytes().to_vec(),
    )
    .await;
    let second = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/outputs"),
            body(&n2, &s2),
        ))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
    let json: serde_json::Value =
        serde_json::from_slice(&to_bytes(second.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(json["error"], "duplicate_output");
}

#[tokio::test]
async fn outputs_rejects_over_submission_with_409() {
    // 5 distinct outputs accepted, then a sixth with a fresh address
    // fails because the round set is full.
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state).await;

    // Five distinct signet P2WPKH addresses to accept.
    let addrs = FIVE_SIGNET_ADDRS;
    for (i, a) in addrs.iter().enumerate() {
        let (bn, sg) = run_blind_sig_for(
            router.clone(),
            &session_id,
            &format!("wallet-{i}"),
            a.as_bytes().to_vec(),
        )
        .await;
        let resp = router
            .clone()
            .oneshot(post_json(
                &format!("/api/v1/session/{session_id}/outputs"),
                serde_json::json!({
                    "address": a,
                    "blinded_nonce_point": bn,
                    "unblinded_signature_scalar": sg,
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "address {i}");
    }

    // Sixth submission (fresh address, fresh blind sig from wallet-0
    // again — they could theoretically request multiple nonces, the
    // rate limit allows it). Should be rejected because outputs is full.
    let extra_addr = SIXTH_SIGNET_ADDR;
    let (bn, sg) = run_blind_sig_for(
        router.clone(),
        &session_id,
        "wallet-0",
        extra_addr.as_bytes().to_vec(),
    )
    .await;
    let resp = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/outputs"),
            serde_json::json!({
                "address": extra_addr,
                "blinded_nonce_point": bn,
                "unblinded_signature_scalar": sg,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let json: serde_json::Value =
        serde_json::from_slice(&to_bytes(resp.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(json["error"], "outputs_full");
}

// ---------------------------------------------------------------------------
// GET /api/v1/session/:id/round-tx — assembled tx fetch (B/5b)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn round_tx_returns_404_for_unknown_session() {
    let (router, _state, _broadcaster) = deterministic_router(1_000_000);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/v1/session/no-such-session/round-tx")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "session_not_found");
}

#[tokio::test]
async fn round_tx_returns_409_when_session_still_filling() {
    let (router, _state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = create_session_via_router(router.clone(), "wallet-a").await;
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/session/{session_id}/round-tx"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "wrong_session_state");
}

#[tokio::test]
async fn round_tx_returns_404_when_session_signing_but_no_outputs() {
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state).await;
    // No /outputs called yet — assembly hasn't fired.
    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/session/{session_id}/round-tx"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "round_not_assembled");
}

#[tokio::test]
async fn round_tx_full_pipeline_assembles_a_valid_transaction() {
    // Drive a complete Wraith Lite session end-to-end:
    //   find_or_create × 5 → lock → inputs × 5 (Signing) →
    //   nonce + blind-sign + outputs × 5 → assembly fires →
    //   GET /round-tx returns a sane unsigned tx.
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state).await;

    for (i, addr) in FIVE_SIGNET_ADDRS.iter().enumerate() {
        let (bn, sg) = run_blind_sig_for(
            router.clone(),
            &session_id,
            &format!("wallet-{i}"),
            addr.as_bytes().to_vec(),
        )
        .await;
        let resp = router
            .clone()
            .oneshot(post_json(
                &format!("/api/v1/session/{session_id}/outputs"),
                serde_json::json!({
                    "address": addr,
                    "blinded_nonce_point": bn,
                    "unblinded_signature_scalar": sg,
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "outputs #{i}");
    }

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/session/{session_id}/round-tx"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["session_id"], session_id);
    assert!(json["unsigned_tx_hex"].as_str().unwrap().len() > 100);
    assert_eq!(json["txid"].as_str().unwrap().len(), 64);
    assert!(json["mining_fee_sats"].as_u64().unwrap() > 0);

    // Output provenance: must include 5 Mixed outputs (one per
    // participant), 5 Change outputs, and 1 ServiceFee output.
    let prov = json["output_provenance"].as_array().expect("array");
    let mixed = prov.iter().filter(|p| p["kind"] == "mixed").count();
    let change = prov.iter().filter(|p| p["kind"] == "change").count();
    let service = prov.iter().filter(|p| p["kind"] == "service_fee").count();
    assert_eq!(mixed, 5, "5 mixed outputs");
    assert_eq!(change, 5, "5 change outputs");
    assert_eq!(service, 1, "1 service-fee output");

    // Mixed outputs must all be at the tier denomination (100k_sats).
    for p in prov.iter().filter(|p| p["kind"] == "mixed") {
        assert_eq!(p["amount_sats"].as_u64().unwrap(), 100_000);
    }

    // The session is still in Signing — assembly didn't advance it.
    let snapshot = state.sessions.get(&session_id).expect("present");
    assert!(matches!(
        snapshot.state,
        wraith_protocol::LiteSessionState::Signing
    ));
}

#[tokio::test]
async fn round_tx_decodes_to_a_valid_bitcoin_transaction() {
    use bitcoin::consensus::encode::deserialize_hex;

    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = make_signing_session(router.clone(), &state).await;
    for (i, addr) in FIVE_SIGNET_ADDRS.iter().enumerate() {
        let (bn, sg) = run_blind_sig_for(
            router.clone(),
            &session_id,
            &format!("wallet-{i}"),
            addr.as_bytes().to_vec(),
        )
        .await;
        let _ = router
            .clone()
            .oneshot(post_json(
                &format!("/api/v1/session/{session_id}/outputs"),
                serde_json::json!({
                    "address": addr,
                    "blinded_nonce_point": bn,
                    "unblinded_signature_scalar": sg,
                }),
            ))
            .await
            .unwrap();
    }

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/session/{session_id}/round-tx"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 16 * 1024).await.unwrap()).unwrap();
    let tx_hex = json["unsigned_tx_hex"].as_str().unwrap();

    // Round-trip the hex through bitcoin's deserializer. If it
    // parses, the consensus encoding is sound.
    let tx: bitcoin::Transaction = deserialize_hex(tx_hex).expect("valid consensus encoding");
    // 5 inputs, 5 mixed + 5 change + 1 service-fee = 11 outputs.
    // No marker output: the `WL01` OP_RETURN was removed in #695.
    assert_eq!(tx.input.len(), 5);
    assert_eq!(tx.output.len(), 11);
    assert!(
        !tx.output.iter().any(|o| o.script_pubkey.is_op_return()),
        "round tx must carry no OP_RETURN marker (#695)"
    );

    // Reported txid in the response must match the deserialised tx.
    let computed_txid = tx.compute_txid().to_string();
    assert_eq!(json["txid"].as_str().unwrap(), computed_txid);
}

// ---------------------------------------------------------------------------
// POST /api/v1/session/:id/witness — witness collection + broadcast (B/5c)
// ---------------------------------------------------------------------------

/// Encode a placeholder `bitcoin::Witness` with a single 4-byte stack
/// item. The coordinator doesn't validate witness signature
/// correctness in B/5c (stubbed broadcaster doesn't either) — it just
/// requires the bytes parse as a `bitcoin::Witness`.
fn placeholder_witness_hex() -> String {
    use bitcoin::consensus::encode::serialize_hex;
    let mut w = bitcoin::Witness::new();
    w.push([0xde, 0xad, 0xbe, 0xef]);
    serialize_hex(&w)
}

/// Drive a session through the full B/1..B/5b pipeline, returning
/// the session_id and the round-tx response (for input_index lookup
/// in B/5c tests).
async fn make_assembled_session(
    router: axum::Router,
    state: &Arc<CoordinatorState>,
) -> (String, serde_json::Value) {
    let session_id = make_signing_session(router.clone(), state).await;
    for (i, addr) in FIVE_SIGNET_ADDRS.iter().enumerate() {
        let (bn, sg) = run_blind_sig_for(
            router.clone(),
            &session_id,
            &format!("wallet-{i}"),
            addr.as_bytes().to_vec(),
        )
        .await;
        let resp = router
            .clone()
            .oneshot(post_json(
                &format!("/api/v1/session/{session_id}/outputs"),
                serde_json::json!({
                    "address": addr,
                    "blinded_nonce_point": bn,
                    "unblinded_signature_scalar": sg,
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "outputs #{i}");
    }
    let rt_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/session/{session_id}/round-tx"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rt_resp.status(), StatusCode::OK);
    let rt_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(rt_resp.into_body(), 16 * 1024).await.unwrap()).unwrap();
    (session_id, rt_json)
}

/// Find the input index in the assembled tx whose previous_output
/// matches the inputs_store record for `ghost_id`.
fn find_input_index(state: &CoordinatorState, session_id: &str, ghost_id: &str) -> u32 {
    use bitcoin::consensus::encode::deserialize_hex;
    let assembled = state
        .assembled_rounds
        .lock()
        .unwrap()
        .get(session_id)
        .cloned()
        .expect("assembled");
    let tx: bitcoin::Transaction = deserialize_hex(&assembled.unsigned_tx_hex).unwrap();
    let inputs = state
        .inputs_store
        .lock()
        .unwrap()
        .get(session_id)
        .cloned()
        .unwrap_or_default();
    let mine = inputs
        .iter()
        .find(|i| i.ghost_id == ghost_id)
        .expect("mine");
    let target_txid = bitcoin::Txid::from_str(&mine.input.txid).unwrap();
    tx.input
        .iter()
        .position(|t| {
            t.previous_output.txid == target_txid && t.previous_output.vout == mine.input.vout
        })
        .expect("input present") as u32
}

#[tokio::test]
async fn witness_returns_404_for_unknown_session() {
    let (router, _state, _broadcaster) = deterministic_router(1_000_000);
    let response = router
        .oneshot(post_json(
            "/api/v1/session/no-such-session/witness",
            serde_json::json!({
                "ghost_id": "wallet-0",
                "input_index": 0,
                "witness_hex": placeholder_witness_hex(),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn witness_returns_409_when_session_still_locked() {
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/witness"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "input_index": 0,
                "witness_hex": placeholder_witness_hex(),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "wrong_session_state");
}

#[tokio::test]
async fn witness_returns_403_for_unenrolled_ghost_id() {
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let (session_id, _rt) = make_assembled_session(router.clone(), &state).await;
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/witness"),
            serde_json::json!({
                "ghost_id": "wallet-99",
                "input_index": 0,
                "witness_hex": placeholder_witness_hex(),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn witness_returns_400_for_bad_hex() {
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let (session_id, _rt) = make_assembled_session(router.clone(), &state).await;
    let idx = find_input_index(&state, &session_id, "wallet-0");
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/witness"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "input_index": idx,
                "witness_hex": "not-hex",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "bad_witness_hex");
}

#[tokio::test]
async fn witness_returns_400_when_input_index_does_not_match_ghost_id() {
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let (session_id, _rt) = make_assembled_session(router.clone(), &state).await;
    let mine = find_input_index(&state, &session_id, "wallet-0");
    // Pick the index of a DIFFERENT participant.
    let theirs = find_input_index(&state, &session_id, "wallet-1");
    assert_ne!(mine, theirs);
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/witness"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "input_index": theirs,
                "witness_hex": placeholder_witness_hex(),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "input_index_mismatch");
}

#[tokio::test]
async fn witness_returns_503_on_final_submission_when_broadcaster_missing() {
    // Ledger + fee address installed; broadcaster NOT installed.
    // The final witness submission tries to broadcast and fails.
    let (router, state, _stub, _utxos) = deterministic_router_full(1_000_000, true, false);
    let (session_id, _rt) = make_assembled_session(router.clone(), &state).await;
    for i in 0..MIN_5 {
        let idx = find_input_index(&state, &session_id, &format!("wallet-{i}"));
        let resp = router
            .clone()
            .oneshot(post_json(
                &format!("/api/v1/session/{session_id}/witness"),
                serde_json::json!({
                    "ghost_id": format!("wallet-{i}"),
                    "input_index": idx,
                    "witness_hex": placeholder_witness_hex(),
                }),
            ))
            .await
            .unwrap();
        if i + 1 < MIN_5 {
            assert_eq!(resp.status(), StatusCode::OK, "non-final submission #{i}");
        } else {
            assert_eq!(
                resp.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "final submission"
            );
            let body = to_bytes(resp.into_body(), 4096).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["error"], "broadcaster_not_configured");
        }
    }
}

#[tokio::test]
async fn witness_full_pipeline_advances_to_complete_and_broadcasts() {
    let (router, state, broadcaster) = deterministic_router(1_000_000);
    let (session_id, _rt) = make_assembled_session(router.clone(), &state).await;

    let mut last_resp: Option<serde_json::Value> = None;
    for i in 0..MIN_5 {
        let idx = find_input_index(&state, &session_id, &format!("wallet-{i}"));
        let resp = router
            .clone()
            .oneshot(post_json(
                &format!("/api/v1/session/{session_id}/witness"),
                serde_json::json!({
                    "ghost_id": format!("wallet-{i}"),
                    "input_index": idx,
                    "witness_hex": placeholder_witness_hex(),
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "witness #{i}");
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        last_resp = Some(json);
    }

    let final_json = last_resp.expect("final response");
    assert_eq!(final_json["state"], "complete");
    assert_eq!(final_json["witnesses_collected"], 5);
    assert!(final_json["broadcast_txid"].is_string());

    // Broadcaster was called exactly once.
    assert_eq!(broadcaster.count(), 1);
    let broadcast_tx = broadcaster.last().expect("tx broadcast");

    // Each tx input now carries the placeholder witness.
    for txin in &broadcast_tx.input {
        assert!(!txin.witness.is_empty(), "merged witness present");
    }

    // Session state in the registry is Complete.
    let snapshot = state.sessions.get(&session_id).expect("present");
    assert!(matches!(
        snapshot.state,
        wraith_protocol::LiteSessionState::Complete
    ));

    // Reported broadcast_txid matches the assembled txid.
    let assembled_txid = state
        .assembled_rounds
        .lock()
        .unwrap()
        .get(&session_id)
        .unwrap()
        .round
        .txid()
        .to_string();
    assert_eq!(final_json["broadcast_txid"], assembled_txid);
}

#[tokio::test]
async fn witness_idempotent_on_resubmission() {
    let (router, state, _broadcaster) = deterministic_router(1_000_000);
    let (session_id, _rt) = make_assembled_session(router.clone(), &state).await;
    let idx = find_input_index(&state, &session_id, "wallet-0");
    let body = serde_json::json!({
        "ghost_id": "wallet-0",
        "input_index": idx,
        "witness_hex": placeholder_witness_hex(),
    });

    let first = router
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/witness"),
            body.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(first.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(first_json["witnesses_collected"], 1);

    let second = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/witness"),
            body,
        ))
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::OK);
    let second_json: serde_json::Value =
        serde_json::from_slice(&to_bytes(second.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(second_json["witnesses_collected"], 1, "duplicate replaced");
}

// ---------------------------------------------------------------------------
// No-sign deadline: failing the round and cooling down the coins
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// No-sign deadline + slashing (B/5e)
// ---------------------------------------------------------------------------

/// Build a router whose state holds the supplied MockClock so the
/// caller can advance time and trip the no-sign deadline.
async fn deadline_test_setup(
    initial_unix: u64,
) -> (axum::Router, Arc<CoordinatorState>, Arc<MockClock>) {
    let mock_clock = Arc::new(MockClock::new(initial_unix));
    let state = Arc::new(
        CoordinatorState::with_components(
            Network::Signet,
            mock_clock.clone(),
            Arc::new(DeterministicSessionIdGenerator::new()),
            Some(TEST_FEE_ADDRESS.to_string()),
            Some(Arc::new(StubBroadcaster::new())),
        )
        .with_utxo_source(Arc::new(fixture_utxo_source())),
    );
    let router = build_router(state.clone());
    (router, state, mock_clock)
}

#[tokio::test]
async fn witness_returns_410_when_no_one_signed_before_deadline() {
    let (router, state, clock) = deadline_test_setup(1_000_000).await;
    let (session_id, _rt) = make_assembled_session(router.clone(), &state).await;

    // Advance well past the 600s deadline.
    clock.advance(700);

    // Any /witness now triggers the sweep.
    let idx = find_input_index(&state, &session_id, "wallet-0");
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/witness"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "input_index": idx,
                "witness_hex": placeholder_witness_hex(),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::GONE);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "no_sign_deadline");

    // Session is Failed.
    let snapshot = state.sessions.get(&session_id).expect("present");
    assert!(matches!(
        snapshot.state,
        wraith_protocol::LiteSessionState::Failed { .. }
    ));

    // Every coin in cooldown — nobody signed before the deadline.
    let now = state.now();
    for i in 0..MIN_5 {
        assert!(
            state
                .bans
                .banned_until(&fixture_outpoint(0x11, i as u32), now)
                .is_some(),
            "wallet-{i}'s coin should be in cooldown"
        );
    }
}

#[tokio::test]
async fn witness_partitions_signers_and_non_signers_at_deadline() {
    let (router, state, clock) = deadline_test_setup(1_000_000).await;
    let (session_id, _rt) = make_assembled_session(router.clone(), &state).await;

    // Three wallets sign within the deadline window.
    for i in 0..3 {
        let idx = find_input_index(&state, &session_id, &format!("wallet-{i}"));
        let resp = router
            .clone()
            .oneshot(post_json(
                &format!("/api/v1/session/{session_id}/witness"),
                serde_json::json!({
                    "ghost_id": format!("wallet-{i}"),
                    "input_index": idx,
                    "witness_hex": placeholder_witness_hex(),
                }),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "in-window submission #{i}");
    }

    // Clock advances past the deadline.
    clock.advance(700);

    // wallet-3 (a non-signer) tries to submit late — sweep fires.
    let idx = find_input_index(&state, &session_id, "wallet-3");
    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/witness"),
            serde_json::json!({
                "ghost_id": "wallet-3",
                "input_index": idx,
                "witness_hex": placeholder_witness_hex(),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::GONE);

    // The round failed for everyone, but only the coins that failed to
    // sign are in cooldown. Signing and losing the round anyway is not a
    // punishable act.
    let now = state.now();
    for i in 0..3 {
        assert!(
            state
                .bans
                .banned_until(&fixture_outpoint(0x11, i), now)
                .is_none(),
            "wallet-{i} signed in time and must not be in cooldown"
        );
    }
    for i in 3..MIN_5 as u32 {
        assert!(
            state
                .bans
                .banned_until(&fixture_outpoint(0x11, i), now)
                .is_some(),
            "wallet-{i} never signed and must be in cooldown"
        );
    }
}

/// Disruption puts the coin in cooldown, and only the coin that
/// disrupted (#699).
///
/// This is what replaces the bond: an attacker who wants another go must
/// buy a fresh coin on-chain, while the participants who did sign keep
/// theirs usable.
#[tokio::test]
async fn a_non_signer_has_its_outpoint_banned_and_a_signer_does_not() {
    use wraith_coordinator::bans::DISRUPTION_BAN_SECS;

    let (router, state, clock) = deadline_test_setup(1_000_000).await;
    let (session_id, _rt) = make_assembled_session(router.clone(), &state).await;

    // wallet-0 signs; wallet-1..4 do not.
    let idx = find_input_index(&state, &session_id, "wallet-0");
    let resp = router
        .clone()
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/witness"),
            serde_json::json!({
                "ghost_id": "wallet-0",
                "input_index": idx,
                "witness_hex": placeholder_witness_hex(),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    assert!(state.bans.is_empty(), "nothing banned before the deadline");

    // Past the deadline, the sweep runs.
    clock.advance(700);
    wraith_coordinator::tick::run_one_pass(&state);

    let now = state.now();
    // The four who never signed are in cooldown...
    for i in 1..MIN_5 {
        let outpoint = fixture_outpoint(0x11, i as u32);
        let until = state
            .bans
            .banned_until(&outpoint, now)
            .unwrap_or_else(|| panic!("wallet-{i} should be banned"));
        assert_eq!(until, now + DISRUPTION_BAN_SECS);
    }
    // ...and the one who signed is not.
    assert!(
        state
            .bans
            .banned_until(&fixture_outpoint(0x11, 0), now)
            .is_none(),
        "a participant who signed must not be punished for the round failing"
    );
}

/// A banned coin is refused at registration, and told when it may return.
#[tokio::test]
async fn inputs_rejects_a_banned_outpoint() {
    let (router, state, _broadcaster, _utxos) = deterministic_router_with_utxos(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;
    state.bans.ban(fixture_outpoint(0x00, 0), state.now());

    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            signed_inputs_body(
                &session_id,
                "wallet-0",
                0,
                0x00,
                0,
                MIN_INPUT_100K_MIX,
                None,
            ),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "outpoint_banned");
    assert!(
        json["detail"].as_str().unwrap().contains("cooldown"),
        "the refusal must say when the coin can be used again: {}",
        json["detail"]
    );
}

/// The cooldown ends by itself. Nothing has to run for a coin to become
/// usable again — expiry is judged at the point of the check.
#[tokio::test]
async fn a_banned_outpoint_is_accepted_again_once_its_cooldown_passes() {
    use wraith_coordinator::bans::DISRUPTION_BAN_SECS;

    let (router, state, _broadcaster, _utxos) = deterministic_router_with_utxos(1_000_000);
    let session_id = make_locked_session(router.clone(), &state).await;
    // Banned an hour and a second ago, so the cooldown has just passed.
    state.bans.ban(
        fixture_outpoint(0x00, 0),
        state.now() - DISRUPTION_BAN_SECS - 1,
    );

    let response = router
        .oneshot(post_json(
            &format!("/api/v1/session/{session_id}/inputs"),
            signed_inputs_body(
                &session_id,
                "wallet-0",
                0,
                0x00,
                0,
                MIN_INPUT_100K_MIX,
                None,
            ),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Background tick — deadline sweep without anyone pinging /witness
// ---------------------------------------------------------------------------

#[tokio::test]
async fn background_tick_sweeps_expired_signing_sessions_without_a_witness_ping() {
    use wraith_coordinator::tick::run_one_pass;

    let (router, state, clock) = deadline_test_setup(1_000_000).await;
    let (session_id, _rt) = make_assembled_session(router.clone(), &state).await;

    // Advance past the 600s deadline.
    clock.advance(700);

    // No /witness submission. Just run the background tick directly.
    run_one_pass(&state);

    // Session is in Failed.
    let snapshot = state.sessions.get(&session_id).expect("present");
    assert!(matches!(
        snapshot.state,
        wraith_protocol::LiteSessionState::Failed { .. }
    ));

    // All 5 coins in cooldown — nobody signed before the deadline.
    let now = state.now();
    for i in 0..MIN_5 as u32 {
        assert!(
            state
                .bans
                .banned_until(&fixture_outpoint(0x11, i), now)
                .is_some(),
            "wallet-{i}'s coin should be in cooldown"
        );
    }

    // Deadline entry was cleaned up so a second tick is a no-op.
    assert!(
        state.signing_deadlines.lock().unwrap().is_empty(),
        "deadline entry should be removed after sweep"
    );
    run_one_pass(&state); // second pass: no panic, no double-sweep
}
