//! End-to-end Wraith bond-seam test: the REAL coordinator↔ghost-pay wire.
//!
//! Unlike `router.rs` (which exercises the coordinator against
//! `MockBondLedger`), this test stands up the **real** `ghost-pay` binary
//! as a subprocess and drives the full bonded-mix lifecycle through the
//! coordinator using the **real** `GhostPayBondLedger` HTTP client. Every
//! load-bearing component on the bond path is the production article:
//!
//!   - the real `ghost-pay` server (subprocess, ephemeral port, non-mainnet
//!     `signet`) serving **real HTTPS** with an identity-derived cert (cert
//!     pubkey == node_id, from a `--identity-key` node.key), against which the
//!     coordinator client pins — the exact production trust path,
//!   - the real participant HMAC auth on `/escrow`
//!     (`X-Ghost-Signature` + `X-Ghost-Timestamp`),
//!   - the real coordinator Bearer auth on `/verify` + `/resolve` +
//!     snapshot `GET`,
//!   - the real SQLCipher-encrypted, schema-v38 `wraith_bonds` ledger,
//!   - the real `spendable_l2_balance` double-spend defence,
//!   - the real `GhostPayBondLedger` (`ureq`) client inside the
//!     coordinator's `/inputs` + witness/sweep handlers.
//!
//! The only stub is `StubBroadcaster` for the L1 broadcast — the on-chain
//! push is out of scope for the bond seam (and needs a live `ghostd`); the
//! coordinator treats a stub-accepted broadcast identically to a real one
//! for the purposes of resolving bonds.
//!
//! ## Why the test paces its calls
//!
//! `ghost-pay` fronts every route with a hardcoded per-IP rate limiter
//! (`burst 10`, `1 req/sec`, see `main.rs` ~L1862). All requests here come
//! from `127.0.0.1`, so they share one bucket. To behave like a
//! well-mannered client and keep the seam (not the limiter) under test, we
//! mirror the server's token bucket and sleep when a call would exceed it.
//! See the SEAM FINDING note at the bottom of this file — the limiter
//! genuinely throttles a co-located coordinator's bond traffic, which is a
//! real operational risk worth flagging.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use bitcoin::Network;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tower::ServiceExt;

use ghost_common::signer::{LocalSigner, Signer};
use ghost_common::tls::{IdentityPinningVerifier, PubkeyAllowList};
use ghost_storage::Database;
use wraith_coordinator::bond_ledger_http::GhostPayBondLedger;
use wraith_coordinator::broadcaster::{Broadcaster, StubBroadcaster};
use wraith_coordinator::{build_router, CoordinatorState};
use wraith_protocol::{
    BondLedger, BondResolution, BondStatus, DeterministicSessionIdGenerator, LiteSessionState,
    MockClock, RefundReason, SlashReason,
};

// ---------------------------------------------------------------------------
// Fixed test material
// ---------------------------------------------------------------------------

/// Participant HMAC secret — ghost-pay's `--api-secret`. Participants sign
/// `/escrow` with HMAC-SHA256(secret, ts || body).
const API_SECRET: &str = "e2e-participant-hmac-secret-do-not-use-in-prod";
/// Coordinator Bearer token — ghost-pay's `--bond-ledger-token`, which the
/// coordinator's `GhostPayBondLedger` presents on `/verify` + `/resolve`.
const BOND_TOKEN: &str = "e2e-coordinator-bearer-token-do-not-use-in-prod";
/// SQLCipher password — ghost-pay's `GHOST_PAY_PASSWORD`. The test re-derives
/// the same key to seed L2 balances directly into the encrypted DB.
const DB_PASSWORD: &str = "e2e-ghost-pay-db-password-0123456789abcdef";

/// Per-participant signet change/fee destination (valid bech32 checksum).
const TEST_FEE_ADDRESS: &str = "tb1q0xcqpzrky6eff2g52qdye53xkk9jxkvraulyla";

/// 32-byte Ed25519 identity seed written to the ghost-pay `node.key` and
/// handed to ghost-pay via `--identity-key`. ghost-pay derives its bond-endpoint
/// TLS cert from this seed (cert pubkey == node_id), and the coordinator client
/// pins against that node_id.
const NODE_IDENTITY_SEED: [u8; 32] = [0x5a; 32];

/// Five distinct valid signet P2WPKH mix-output addresses (keys `[i;32]`).
const FIVE_SIGNET_ADDRS: [&str; 5] = [
    "tb1q0xcqpzrky6eff2g52qdye53xkk9jxkvraulyla",
    "tb1qa0qwuze2h85zw7nqpsj3ga0z9geyrgwptrz29s",
    "tb1qg975h6gdx5mryeac72h6lj2nzygugxhyk6dnhr",
    "tb1q3zxmh4ue370cp48c9d8eeek43qhnzzhvz4t84j",
    "tb1qn454ga9rqwkx6ax309knw5hs0z2erz7jg4x4y7",
];

/// The 100k_sats tier's bond (0.5% of 100_000). Matches `tier.bond_sats()`.
const BOND_SATS: u64 = 500;
/// Per-participant minimum Mix input for 100k_sats at the default fee rate.
/// Same number `session_inputs::post` computes (denom + service + mining).
const MIN_INPUT_100K_MIX: u64 = 102_112;

// ---------------------------------------------------------------------------
// SQLCipher key derivation — byte-identical to ghost-pay's `derive_db_key`.
// ---------------------------------------------------------------------------

fn derive_db_key(password: &str) -> [u8; 32] {
    // ghost-pay/src/main.rs::derive_db_key — scrypt(N=2^14, r=8, p=1, len=32)
    // with the fixed salt `ghost-pay-sqlcipher-v1`.
    let params = scrypt::Params::new(14, 8, 1, 32).expect("scrypt params");
    let mut key = [0u8; 32];
    scrypt::scrypt(
        password.as_bytes(),
        b"ghost-pay-sqlcipher-v1",
        &params,
        &mut key,
    )
    .expect("scrypt");
    key
}

// ---------------------------------------------------------------------------
// Rate-limit mirror — model ghost-pay's per-IP token bucket so the test
// never trips the limiter while exercising the bond seam. Conservative
// (cap 9 vs the server's 10) with a small refill pad.
// ---------------------------------------------------------------------------

struct RateMirror {
    tokens: f64,
    last: Instant,
}

impl RateMirror {
    fn new() -> Self {
        Self {
            tokens: 9.0,
            last: Instant::now(),
        }
    }

    /// Account for `n` imminent ghost-pay requests, sleeping if the modelled
    /// bucket can't cover them yet.
    fn take(&mut self, n: f64) {
        let elapsed = self.last.elapsed().as_secs_f64();
        self.tokens = (self.tokens + elapsed).min(9.0);
        if self.tokens < n {
            let deficit = n - self.tokens + 0.25;
            std::thread::sleep(Duration::from_secs_f64(deficit));
            self.tokens = (self.tokens + deficit).min(9.0);
        }
        self.tokens -= n;
        self.last = Instant::now();
    }
}

type Pacer = Arc<Mutex<RateMirror>>;

fn pace(pacer: &Pacer, n: f64) {
    pacer.lock().unwrap().take(n);
}

// ---------------------------------------------------------------------------
// ghost-pay subprocess harness
// ---------------------------------------------------------------------------

/// Locate the freshly-built `ghost-pay` binary next to the test runner. The
/// integration-test binary lives in `target/<profile>/deps/`; the sibling
/// app binary is one directory up in `target/<profile>/`.
fn ghost_pay_binary() -> PathBuf {
    let mut dir = std::env::current_exe().expect("current_exe");
    dir.pop(); // drop the test-binary file name -> .../deps
    if dir.ends_with("deps") {
        dir.pop(); // .../<profile>
    }
    let bin = dir.join("ghost-pay");
    if !bin.exists() {
        panic!(
            "ghost-pay binary not found at {} — build it first with \
             `cargo build -p ghost-pay`",
            bin.display()
        );
    }
    bin
}

/// Bind an ephemeral loopback port, then release it so ghost-pay can claim
/// it. Small TOCTOU window, standard for spawn-based integration tests.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    l.local_addr().unwrap().port()
}

/// The `node_id` (Ed25519 pubkey) ghost-pay advertises for a 32-byte seed.
fn node_id_for(secret: &[u8; 32]) -> [u8; 32] {
    LocalSigner::from_bytes(secret).public_key()
}

/// Build a `ureq` agent that pins ghost-pay's identity TLS cert against
/// `node_id` — the same pinning the production `GhostPayBondLedger` uses, so
/// the participant HMAC `/escrow` calls and health polls in this test ride the
/// real HTTPS path too.
fn pinned_agent(node_id: [u8; 32]) -> ureq::Agent {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let allow: PubkeyAllowList = Arc::new(move |k: &[u8; 32]| *k == node_id);
    let verifier = Arc::new(IdentityPinningVerifier::new(allow));
    let tls = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(15))
        .tls_config(Arc::new(tls))
        .build()
}

struct GhostPay {
    child: Child,
    base_url: String,
    /// node_id ghost-pay serves its identity cert for (== `node_id_for(seed)`).
    node_id: [u8; 32],
    /// Pinned HTTPS agent for the test's own participant/health calls.
    agent: ureq::Agent,
    /// A long-lived handle on the same encrypted DB the server uses, opened
    /// before spawn (so migrations don't race) and kept for read-back
    /// ground-truth assertions over `wraith_bonds`.
    db: Database,
    _data_dir: tempfile::TempDir,
}

impl GhostPay {
    /// Seed the supplied `(ghost_id, sats)` L2 balances into a fresh
    /// encrypted DB, then spawn the real ghost-pay server against it.
    fn spawn(seeds: &[(&str, i64)]) -> GhostPay {
        let data_dir = tempfile::tempdir().expect("tempdir");
        let db_path = data_dir.path().join("ghost-pay.db");
        let key = derive_db_key(DB_PASSWORD);

        // Pre-create + migrate the encrypted DB to v38, seed balances, and
        // KEEP the handle for later assertions. ghost-pay re-opens the same
        // file; its migration run is a read-only no-op at v38.
        let db = Database::open_encrypted(&db_path, &key).expect("open_encrypted (seed)");
        for (ghost_id, sats) in seeds {
            seed_l2_balance(&db, ghost_id, *sats);
        }

        // Write the node.key (32-byte Ed25519 seed) ghost-pay derives its
        // identity TLS cert from, and compute the node_id we pin against.
        let key_path = data_dir.path().join("node.key");
        std::fs::write(&key_path, NODE_IDENTITY_SEED).expect("write node.key");
        let node_id = node_id_for(&NODE_IDENTITY_SEED);

        let port = free_port();
        let bin = ghost_pay_binary();
        let child = Command::new(bin)
            .arg("--network")
            .arg("signet")
            .arg("--api-listen")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--data-dir")
            .arg(data_dir.path())
            // Serve the bond endpoints over HTTPS with the identity-derived
            // cert (cert pubkey == node_id) — the production trust path.
            .arg("--identity-key")
            .arg(&key_path)
            .arg("--api-secret")
            .arg(API_SECRET)
            .arg("--bond-ledger-token")
            .arg(BOND_TOKEN)
            // RPC creds are required to boot, but the bond endpoints never
            // touch the chain — any value works; no ghostd is needed.
            .arg("--rpc-user")
            .arg("e2e")
            .arg("--rpc-password")
            .arg("e2e")
            .arg("--log-level")
            .arg("warn")
            .env("GHOST_PAY_PASSWORD", DB_PASSWORD)
            // Keep CORS permissive for the localhost test client.
            .env("GHOST_PAY_CORS_ORIGINS", "http://127.0.0.1")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn ghost-pay");

        let base_url = format!("https://127.0.0.1:{port}");
        let gp = GhostPay {
            child,
            base_url,
            node_id,
            agent: pinned_agent(node_id),
            db,
            _data_dir: data_dir,
        };
        gp.wait_healthy();
        gp
    }

    /// Poll until the server's HTTP listener answers at all, then settle.
    ///
    /// NB: `/health` returns 503 here (the L-13 health check needs a live
    /// Bitcoin RPC, which the bond endpoints don't), so readiness is "the
    /// listener produced ANY HTTP response" — a connection-refused means
    /// it's still binding. Polls run at <=1/sec so they don't drain the
    /// per-IP rate-limit bucket the rest of the test models; a final settle
    /// lets the bucket refill before real traffic starts.
    fn wait_healthy(&self) {
        let url = format!("{}/health", self.base_url);
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            match self.agent.get(&url).timeout(Duration::from_secs(2)).call() {
                // Any HTTP status (incl. 503) means the TLS listener is up and
                // the pinned handshake succeeded.
                Ok(_) | Err(ureq::Error::Status(_, _)) => break,
                // Transport error (connection refused / TLS not ready) — still binding.
                Err(_) => {}
            }
            if Instant::now() >= deadline {
                panic!("ghost-pay listener never came up at {url}");
            }
            std::thread::sleep(Duration::from_millis(1100));
        }
        // Settle so the rate-limit bucket is full before traffic.
        std::thread::sleep(Duration::from_secs(5));
    }

    /// Build a fresh real `GhostPayBondLedger` pointed at this server with
    /// the matching Bearer token.
    fn ledger(&self) -> GhostPayBondLedger {
        GhostPayBondLedger::new(&self.base_url, BOND_TOKEN, self.node_id).expect("ledger")
    }
}

impl Drop for GhostPay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// Direct DB helpers (ground-truth assertions over the real v38 ledger)
// ---------------------------------------------------------------------------

/// Establish an L2 balance the same way the production deposit path does:
/// an unsettled (`settlement_block = 0`) received instant payment credited
/// to `merchant_wallet_id`. `spendable_l2_balance` sums exactly these.
fn seed_l2_balance(db: &Database, ghost_id: &str, sats: i64) {
    db.with_connection(|conn| {
        conn.execute(
            "INSERT INTO accepted_instant_payments
                (payment_id, sender_lock_id, merchant_wallet_id, amount_sats,
                 accepted_at, settlement_block, confidence, sender_pubkey, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, 1.0, ?6, ?7)",
            rusqlite::params![
                vec![0u8; 32],
                format!("seed-lock-{ghost_id}"),
                ghost_id,
                sats,
                0i64,
                vec![2u8; 33],
                vec![0u8; 64],
            ],
        )
        .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))?;
        Ok(())
    })
    .expect("seed accepted_instant_payment");
}

/// Sum of sats currently withheld from `ghost_id`'s spendable balance by
/// live bonds — mirrors `queries::sum_held_bonds_for` (escrowed + slashed).
fn held_bonds(db: &Database, ghost_id: &str) -> i64 {
    db.with_connection(|conn| {
        ghost_storage::queries::sum_held_bonds_for(conn, ghost_id)
            .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))
    })
    .expect("held_bonds")
}

/// `(status, resolution_json)` for a single bond row, by id.
fn bond_db_row(db: &Database, bond_id: &str) -> (String, Option<String>) {
    db.with_connection(|conn| {
        ghost_storage::queries::get_bond(conn, bond_id)
            .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))
    })
    .expect("get_bond")
    .map(|b| (b.status, b.resolution))
    .expect("bond row present")
}

// ---------------------------------------------------------------------------
// Participant /escrow — real HMAC-authenticated request to ghost-pay.
// ---------------------------------------------------------------------------

/// Outcome of an escrow attempt against the real server.
enum EscrowResult {
    /// 200 — `bond_id` issued.
    Ok(String),
    /// Non-2xx — `(status, error_code)` from the `{ error, detail }` body.
    Err(u16, String),
}

/// POST `/api/v1/wraith/bond/escrow` with the participant HMAC headers the
/// real `require_api_auth` middleware verifies.
fn escrow_bond(
    pacer: &Pacer,
    agent: &ureq::Agent,
    base_url: &str,
    ghost_id: &str,
    session_id: &str,
    amount_sats: u64,
) -> EscrowResult {
    pace(pacer, 1.0);

    let body = serde_json::json!({
        "ghost_id": ghost_id,
        "session_id": session_id,
        "amount_sats": amount_sats,
    })
    .to_string();

    let ts = chrono::Utc::now().timestamp();
    // Signature = HMAC-SHA256(api_secret, ts_string || body) — exactly what
    // `ApiAuth::verify_signature` recomputes.
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(API_SECRET.as_bytes()).unwrap();
    mac.update(ts.to_string().as_bytes());
    mac.update(body.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());

    let resp = agent
        .post(&format!("{base_url}/api/v1/wraith/bond/escrow"))
        .set("content-type", "application/json")
        .set("X-Ghost-Signature", &sig)
        .set("X-Ghost-Timestamp", &ts.to_string())
        .timeout(Duration::from_secs(15))
        .send_string(&body);

    match resp {
        Ok(r) => {
            let v: serde_json::Value = r.into_json().expect("escrow json");
            EscrowResult::Ok(v["bond_id"].as_str().expect("bond_id").to_string())
        }
        Err(ureq::Error::Status(code, r)) => {
            let v: serde_json::Value = r.into_json().unwrap_or(serde_json::json!({}));
            EscrowResult::Err(code, v["error"].as_str().unwrap_or("").to_string())
        }
        Err(e) => panic!("escrow transport error: {e}"),
    }
}

fn escrow_ok(
    pacer: &Pacer,
    agent: &ureq::Agent,
    base: &str,
    ghost_id: &str,
    session_id: &str,
) -> String {
    match escrow_bond(pacer, agent, base, ghost_id, session_id, BOND_SATS) {
        EscrowResult::Ok(id) => id,
        EscrowResult::Err(code, err) => panic!("escrow {ghost_id} failed: {code} {err}"),
    }
}

// ---------------------------------------------------------------------------
// Coordinator-side helpers (axum oneshot, mirrors router.rs plumbing)
// ---------------------------------------------------------------------------

fn post_json(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> (StatusCode, serde_json::Value) {
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({}));
    (status, json)
}

/// Build a coordinator with the REAL ghost-pay ledger wired in.
fn coordinator_with_real_ledger(
    gp: &GhostPay,
    clock: Arc<MockClock>,
) -> (Arc<CoordinatorState>, axum::Router, StubBroadcaster) {
    let ledger: Arc<dyn BondLedger> = Arc::new(gp.ledger());
    let stub = StubBroadcaster::new();
    let state = Arc::new(CoordinatorState::with_components(
        Network::Signet,
        clock,
        Arc::new(DeterministicSessionIdGenerator::new()),
        Some(ledger),
        Some(TEST_FEE_ADDRESS.to_string()),
        Some(Arc::new(stub.clone()) as Arc<dyn Broadcaster>),
    ));
    let router = build_router(state.clone());
    (state, router, stub)
}

/// Enrol `ghost_ids` into a single session via /find_or_create, returning
/// the shared session_id. Each carries a placeholder bond_id (cosmetic —
/// the real bond is verified by `(ghost_id, session_id)` at /inputs).
async fn enrol_all(router: &axum::Router, ghost_ids: &[&str]) -> String {
    let mut session_id = None;
    for g in ghost_ids {
        let (status, json) = body_json(
            router
                .clone()
                .oneshot(post_json(
                    "/api/v1/session/find_or_create",
                    serde_json::json!({
                        "tier_id": "100k_sats",
                        "ghost_id": g,
                        "bond_id": format!("placeholder-{g}"),
                    }),
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "find_or_create {g}");
        let sid = json["session"]["session_id"].as_str().unwrap().to_string();
        match &session_id {
            None => session_id = Some(sid),
            Some(prev) => assert_eq!(prev, &sid, "all join the same session"),
        }
    }
    session_id.unwrap()
}

/// Force a session to `Locked` through the same gossip path production
/// `tick()` + standby failover use (router.rs does this too — we can't
/// reach the underlying MockClock through `Arc<dyn Clock>` to expire the
/// fill window organically).
fn force_locked(state: &Arc<CoordinatorState>, session_id: &str) {
    state
        .sessions
        .apply_event(wraith_protocol::SessionGossipEvent::StateChanged {
            session_id: session_id.to_string(),
            new_state: LiteSessionState::Locked,
        })
        .expect("apply Locked");
}

/// Submit one /inputs for `ghost_id`. Paces a single verify call.
async fn submit_input(
    pacer: &Pacer,
    router: &axum::Router,
    session_id: &str,
    ghost_id: &str,
    vout: u32,
) -> (StatusCode, serde_json::Value) {
    pace(pacer, 1.0); // /inputs triggers exactly one ghost-pay /verify
    body_json(
        router
            .clone()
            .oneshot(post_json(
                &format!("/api/v1/session/{session_id}/inputs"),
                serde_json::json!({
                    "ghost_id": ghost_id,
                    "input": {
                        "txid": "11".repeat(32),
                        "vout": vout,
                        "value_sats": 200_000,
                        "scriptpubkey_hex": "0014".to_string() + &"11".repeat(20),
                    },
                    "change_address": TEST_FEE_ADDRESS,
                }),
            ))
            .await
            .unwrap(),
    )
    .await
}

/// One wallet-side blind-sig pass (in-process coordinator crypto; no
/// ghost-pay traffic). Returns the `/outputs` material. Mirrors
/// router.rs::run_blind_sig_for.
async fn run_blind_sig_for(
    router: &axum::Router,
    session_id: &str,
    ghost_id: &str,
    message: Vec<u8>,
) -> (String, String) {
    use secp256k1::PublicKey;
    use wraith_protocol::{BlindSignatureResponse, BlindingContext, PublicNonce};

    let (_, nj) = body_json(
        router
            .clone()
            .oneshot(post_json(
                &format!("/api/v1/session/{session_id}/nonce"),
                serde_json::json!({ "ghost_id": ghost_id }),
            ))
            .await
            .unwrap(),
    )
    .await;

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

    let (_, sj) = body_json(
        router
            .clone()
            .oneshot(post_json(
                &format!("/api/v1/session/{session_id}/blind-sign"),
                serde_json::json!({
                    "ghost_id": ghost_id,
                    "blinded_challenge": hex::encode(blinded.challenge),
                    "blind_session_id": hex::encode(blinded.session_id),
                }),
            ))
            .await
            .unwrap(),
    )
    .await;
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

/// Submit `ghost_id`'s anonymous mix output for `addr` (in-process).
async fn submit_output(router: &axum::Router, session_id: &str, ghost_id: &str, addr: &str) {
    let (bn, sg) = run_blind_sig_for(router, session_id, ghost_id, addr.as_bytes().to_vec()).await;
    let (status, _) = body_json(
        router
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
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "outputs {ghost_id}");
}

fn placeholder_witness_hex() -> String {
    use bitcoin::consensus::encode::serialize_hex;
    let mut w = bitcoin::Witness::new();
    w.push([0xde, 0xad, 0xbe, 0xef]);
    serialize_hex(&w)
}

/// Find the assembled-tx input index whose previous_output matches
/// `ghost_id`'s submitted UTXO. Mirrors router.rs::find_input_index.
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

/// Drive a session all the way to an assembled round (inputs + outputs done,
/// round-tx built). Returns the session_id. `ghost_ids[i]` maps to
/// `FIVE_SIGNET_ADDRS[i]`.
async fn drive_to_assembled(
    pacer: &Pacer,
    state: &Arc<CoordinatorState>,
    router: &axum::Router,
    session_id: &str,
    ghost_ids: &[&str; 5],
) {
    for (i, g) in ghost_ids.iter().enumerate() {
        let (status, json) = submit_input(pacer, router, session_id, g, i as u32).await;
        assert_eq!(status, StatusCode::OK, "inputs {g}: {json}");
    }
    // Confirm Signing.
    assert!(matches!(
        state.sessions.get(session_id).unwrap().state,
        LiteSessionState::Signing
    ));
    for (i, g) in ghost_ids.iter().enumerate() {
        submit_output(router, session_id, g, FIVE_SIGNET_ADDRS[i]).await;
    }
    // Build the round-tx (assembles on the Nth output, but fetch to be sure).
    let (status, _) = body_json(
        router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/session/{session_id}/round-tx"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "round-tx assembled");
}

async fn submit_witness(
    router: &axum::Router,
    session_id: &str,
    ghost_id: &str,
    input_index: u32,
) -> (StatusCode, serde_json::Value) {
    body_json(
        router
            .clone()
            .oneshot(post_json(
                &format!("/api/v1/session/{session_id}/witness"),
                serde_json::json!({
                    "ghost_id": ghost_id,
                    "input_index": input_index,
                    "witness_hex": placeholder_witness_hex(),
                }),
            ))
            .await
            .unwrap(),
    )
    .await
}

// ===========================================================================
// THE TEST
// ===========================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bond_e2e_real_ghostpay_full_lifecycle() {
    // ---- Setup: seed every participant the test will use, once. ----------
    let happy: [&str; 5] = ["h0", "h1", "h2", "h3", "h4"];
    let slash: [&str; 5] = ["s0", "s1", "s2", "s3", "s4"];
    let seeds: Vec<(&str, i64)> = happy
        .iter()
        .chain(slash.iter())
        .map(|g| (*g, 10_000i64))
        .chain(std::iter::once(("ds", 500i64))) // double-spend boundary wallet
        .collect();

    let gp = GhostPay::spawn(&seeds);
    let pacer: Pacer = Arc::new(Mutex::new(RateMirror::new()));
    let base = gp.base_url.clone();
    // Pinned HTTPS agent for the participant `/escrow` + health calls — same
    // identity pin the coordinator's bond ledger client uses.
    let agent = gp.agent.clone();

    // ======================================================================
    // PHASE 0 — NEGATIVE PIN: a bond ledger client pinned to the WRONG node_id
    //           must FAIL the TLS handshake against the real ghost-pay server.
    //           This proves the pin actually rejects a non-matching cert — a
    //           pinning impl that accepted any cert would let `verify_bond`
    //           succeed here, which is worse than the original bug.
    // ======================================================================
    {
        let wrong_node_id = node_id_for(&[0xa5; 32]);
        assert_ne!(
            wrong_node_id, gp.node_id,
            "test setup: wrong node_id must differ from the served one"
        );
        // Same https base_url + valid Bearer token — ONLY the pinned node_id
        // is wrong, isolating the TLS pin as the cause of failure.
        let wrong_ledger =
            GhostPayBondLedger::new(&base, BOND_TOKEN, wrong_node_id).expect("ledger ctor");
        let err = wrong_ledger
            .verify_bond("h0", "any-session", BOND_SATS)
            .expect_err("wrong-node_id pin MUST NOT verify a bond");
        assert!(
            matches!(err, wraith_protocol::BondError::LedgerUnreachable(_)),
            "wrong pin must fail at the TLS handshake (LedgerUnreachable); got {err:?}"
        );
    }

    // ======================================================================
    // PHASE 1 — HAPPY PATH: escrow → join → verify → mix → resolve(refund)
    // ======================================================================
    {
        let clock = Arc::new(MockClock::new(1_700_000_000));
        let (state, router, broadcaster) = coordinator_with_real_ledger(&gp, clock);

        // 1a. Enrol 5 participants (creates session "test-session-0000").
        let session_id = enrol_all(&router, &happy).await;

        // 1b. Each escrows a real 500-sat bond via ghost-pay /escrow (HMAC).
        let mut bond_ids = Vec::new();
        for g in &happy {
            let id = escrow_ok(&pacer, &agent, &base, g, &session_id);
            assert!(id.starts_with("gpbond-"), "real bond id: {id}");
            bond_ids.push(id);
        }

        // ghost-pay + coordinator AGREE: spendable dropped by exactly the
        // bond. The double-spend defence is now armed.
        for g in &happy {
            assert_eq!(
                held_bonds(&gp.db, g),
                BOND_SATS as i64,
                "held after escrow {g}"
            );
        }

        // 1c. Lock the session, then each participant commits inputs. /inputs
        //     drives the REAL coordinator→ghost-pay /verify (Bearer auth).
        force_locked(&state, &session_id);
        for (i, g) in happy.iter().enumerate() {
            let (status, json) = submit_input(&pacer, &router, &session_id, g, i as u32).await;
            assert_eq!(status, StatusCode::OK, "inputs {g}: {json}");
        }

        // The bond_id the coordinator stored (returned by ghost-pay /verify)
        // is byte-identical to the one ghost-pay minted at /escrow — the seam
        // round-trips the identifier intact.
        {
            let store = state.inputs_store.lock().unwrap();
            let inputs = store.get(&session_id).unwrap();
            for (g, escrowed) in happy.iter().zip(bond_ids.iter()) {
                let rec = inputs.iter().find(|a| &a.ghost_id == g).unwrap();
                assert_eq!(
                    rec.bond_id.as_str(),
                    escrowed,
                    "verify echoed escrow id for {g}"
                );
            }
        }
        assert!(matches!(
            state.sessions.get(&session_id).unwrap().state,
            LiteSessionState::Signing
        ));

        // 1d. Outputs + assembly (in-process crypto).
        for (i, g) in happy.iter().enumerate() {
            submit_output(&router, &session_id, g, FIVE_SIGNET_ADDRS[i]).await;
        }
        let (status, _) = body_json(
            router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/v1/session/{session_id}/round-tx"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // 1e. Witnesses. The final one broadcasts (stub) and resolves all 5
        //     bonds via ghost-pay /resolve (Bearer). Reserve 5 tokens.
        let mut final_json = serde_json::json!({});
        for (i, g) in happy.iter().enumerate() {
            if i + 1 == happy.len() {
                pace(&pacer, 5.0); // final witness fires 5 ghost-pay /resolve
            }
            let idx = find_input_index(&state, &session_id, g);
            let (status, json) = submit_witness(&router, &session_id, g, idx).await;
            assert_eq!(status, StatusCode::OK, "witness {g}: {json}");
            final_json = json;
        }
        assert_eq!(final_json["state"], "complete");
        assert_eq!(final_json["witnesses_collected"], 5);
        assert_eq!(
            final_json["bonds_resolved"], 5,
            "all bonds resolved on completion"
        );
        assert_eq!(broadcaster.count(), 1, "broadcast happened once");
        assert!(matches!(
            state.sessions.get(&session_id).unwrap().state,
            LiteSessionState::Complete
        ));

        // 1f. ghost-pay's real ledger reflects the refund: rows flipped to
        //     'refunded' with the exact resolution, holds released, spendable
        //     restored to the full seed.
        for (g, bond_id) in happy.iter().zip(bond_ids.iter()) {
            let (db_status, resolution) = bond_db_row(&gp.db, bond_id);
            assert_eq!(db_status, "refunded", "db status {g}");
            let res: BondResolution = serde_json::from_str(&resolution.unwrap()).unwrap();
            assert_eq!(res, BondResolution::Refund(RefundReason::RoundCompleted));
            assert_eq!(held_bonds(&gp.db, g), 0, "hold released {g}");
        }

        // 1g. The coordinator's own view (via the real snapshot wire, Bearer)
        //     AGREES with the DB for a sampled bond.
        pace(&pacer, 1.0);
        let snap = gp
            .ledger()
            .snapshot_bond(&wraith_protocol::BondId::new(bond_ids[0].clone()))
            .expect("snapshot");
        assert_eq!(
            snap.status,
            BondStatus::Resolved(BondResolution::Refund(RefundReason::RoundCompleted))
        );
        assert_eq!(snap.amount_sats, BOND_SATS);
    }

    // ======================================================================
    // PHASE 2 — GATE: /inputs returns 402 when the bond is missing in the
    //                 REAL ledger (ghost-pay /verify → 404 not_bonded).
    // ======================================================================
    {
        let clock = Arc::new(MockClock::new(1_700_000_000));
        let (state, router, _b) = coordinator_with_real_ledger(&gp, clock);

        // Force a Locked session whose enrolled wallet never escrowed.
        state
            .sessions
            .apply_event(wraith_protocol::SessionGossipEvent::SessionCreated {
                session: wraith_protocol::LiteSession {
                    session_id: "gate-missing-bond".into(),
                    tier: wraith_protocol::LiteTier::Denom100kSats,
                    session_type: wraith_protocol::SessionType::Mix,
                    created_at: 1_700_000_000,
                    state: LiteSessionState::Locked,
                    participants: vec![wraith_protocol::LiteSessionParticipant {
                        ghost_id: "g0".into(),
                        bond_id: wraith_protocol::BondId::new("placeholder"),
                        registered_at: 1_700_000_000,
                    }],
                },
            })
            .unwrap();

        let (status, json) = submit_input(&pacer, &router, "gate-missing-bond", "g0", 0).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "missing bond -> 402");
        assert_eq!(json["error"], "bond_not_found");
    }

    // ======================================================================
    // PHASE 3 — DOUBLE-SPEND DEFENCE: escrowed sats are subtracted from
    //           spendable, so a participant can't escrow them twice.
    // ======================================================================
    {
        // `ds` was seeded with exactly one bond's worth (500). First escrow
        // (session ds-A) succeeds and consumes the whole spendable balance.
        let id_a = escrow_ok(&pacer, &agent, &base, "ds", "ds-A");
        assert!(id_a.starts_with("gpbond-"));
        assert_eq!(held_bonds(&gp.db, "ds"), 500, "first escrow held");

        // Second escrow (different session ds-B) must be refused: spendable
        // is now 0 because the live bond is netted out by spendable_l2_balance.
        match escrow_bond(&pacer, &agent, &base, "ds", "ds-B", BOND_SATS) {
            EscrowResult::Err(code, err) => {
                assert_eq!(code, 402, "double-spend escrow rejected");
                assert_eq!(err, "insufficient_balance");
            }
            EscrowResult::Ok(id) => panic!("double-spend escrow unexpectedly succeeded: {id}"),
        }
        // Still exactly one hold — the second attempt created no row.
        assert_eq!(held_bonds(&gp.db, "ds"), 500, "no second bond created");
    }

    // ======================================================================
    // PHASE 4 — SLASH/ABORT: no-sign deadline partitions signers (refunded)
    //           from non-signers (slashed, permanent debit) — all against
    //           the REAL ledger.
    // ======================================================================
    {
        let clock = Arc::new(MockClock::new(1_700_000_000));
        let (state, router, _b) = coordinator_with_real_ledger(&gp, clock.clone());

        let session_id = enrol_all(&router, &slash).await;

        let mut bond_ids = std::collections::HashMap::new();
        for g in &slash {
            bond_ids.insert(*g, escrow_ok(&pacer, &agent, &base, g, &session_id));
        }

        force_locked(&state, &session_id);
        drive_to_assembled(&pacer, &state, &router, &session_id, &slash).await;

        // s0,s1,s2 sign within the window; s3,s4 never do.
        for g in ["s0", "s1", "s2"] {
            let idx = find_input_index(&state, &session_id, g);
            let (status, _) = submit_witness(&router, &session_id, g, idx).await;
            assert_eq!(status, StatusCode::OK, "in-window witness {g}");
        }

        // Advance past the 600s no-sign deadline; a late submission trips the
        // sweep, which resolves all 5 bonds (3 refund + 2 slash) via ghost-pay.
        clock.advance(700);
        pace(&pacer, 5.0);
        let idx = find_input_index(&state, &session_id, "s3");
        let (status, json) = submit_witness(&router, &session_id, "s3", idx).await;
        assert_eq!(status, StatusCode::GONE, "late witness -> 410");
        assert_eq!(json["error"], "no_sign_deadline");
        assert!(matches!(
            state.sessions.get(&session_id).unwrap().state,
            LiteSessionState::Failed { .. }
        ));

        // Signers refunded (RoundVoided), holds released.
        for g in ["s0", "s1", "s2"] {
            let (db_status, resolution) = bond_db_row(&gp.db, &bond_ids[g]);
            assert_eq!(db_status, "refunded", "signer {g} refunded");
            let res: BondResolution = serde_json::from_str(&resolution.unwrap()).unwrap();
            assert_eq!(res, BondResolution::Refund(RefundReason::RoundVoided));
            assert_eq!(held_bonds(&gp.db, g), 0, "signer {g} hold released");
        }
        // Non-signers slashed (NoSignDuringSigning) — a PERMANENT debit:
        // spendable_l2_balance keeps subtracting the slashed bond.
        for g in ["s3", "s4"] {
            let (db_status, resolution) = bond_db_row(&gp.db, &bond_ids[g]);
            assert_eq!(db_status, "slashed", "non-signer {g} slashed");
            let res: BondResolution = serde_json::from_str(&resolution.unwrap()).unwrap();
            assert_eq!(res, BondResolution::Slash(SlashReason::NoSignDuringSigning));
            assert_eq!(
                held_bonds(&gp.db, g),
                BOND_SATS as i64,
                "slashed bond stays withheld from spendable for {g}"
            );
        }

        // Confirm the slash over the real snapshot wire too.
        pace(&pacer, 1.0);
        let snap = gp
            .ledger()
            .snapshot_bond(&wraith_protocol::BondId::new(bond_ids["s3"].clone()))
            .expect("snapshot s3");
        assert_eq!(
            snap.status,
            BondStatus::Resolved(BondResolution::Slash(SlashReason::NoSignDuringSigning))
        );
    }
}

// ===========================================================================
// Coordinator-only gate (no ghost-pay needed): /inputs returns 503 when the
// bond ledger isn't configured at all.
// ===========================================================================

#[tokio::test]
async fn inputs_503_when_bond_ledger_not_configured() {
    let state = Arc::new(CoordinatorState::with_components(
        Network::Signet,
        Arc::new(MockClock::new(1_700_000_000)),
        Arc::new(DeterministicSessionIdGenerator::new()),
        None, // no ledger wired
        Some(TEST_FEE_ADDRESS.to_string()),
        Some(Arc::new(StubBroadcaster::new()) as Arc<dyn Broadcaster>),
    ));
    let router = build_router(state.clone());

    state
        .sessions
        .apply_event(wraith_protocol::SessionGossipEvent::SessionCreated {
            session: wraith_protocol::LiteSession {
                session_id: "no-ledger".into(),
                tier: wraith_protocol::LiteTier::Denom100kSats,
                session_type: wraith_protocol::SessionType::Mix,
                created_at: 1_700_000_000,
                state: LiteSessionState::Locked,
                participants: vec![wraith_protocol::LiteSessionParticipant {
                    ghost_id: "w".into(),
                    bond_id: wraith_protocol::BondId::new("placeholder"),
                    registered_at: 1_700_000_000,
                }],
            },
        })
        .unwrap();

    let resp = router
        .oneshot(post_json(
            "/api/v1/session/no-ledger/inputs",
            serde_json::json!({
                "ghost_id": "w",
                "input": {
                    "txid": "00".repeat(32),
                    "vout": 0,
                    "value_sats": MIN_INPUT_100K_MIX,
                    "scriptpubkey_hex": "0014".to_string() + &"00".repeat(20),
                },
            }),
        ))
        .await
        .unwrap();
    let (status, json) = body_json(resp).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json["error"], "ledger_not_configured");
}

// ===========================================================================
// SEAM FINDING (rate limiter vs. co-located coordinator)
// ---------------------------------------------------------------------------
// ghost-pay rate-limits EVERY route per source IP at burst 10 / 1-per-sec
// (main.rs ~L1862), including the coordinator-only bond endpoints. A
// co-located Wraith coordinator completing a busy round fires up to N
// `/resolve` calls back-to-back; if the bucket is drained those return 429,
// and `bond_resolution::resolve_round_bonds` swallows the error (logs +
// counts `failed`, never retries) — leaving participant bonds stuck in
// `escrowed` and their L2 sats withheld. This test paces its calls to stay
// under the limit precisely so the BOND seam (not the limiter) is what's
// exercised; the limiter interaction is flagged here for operators. A
// loopback exemption or a resolve-retry would close it. Not fixed here:
// changing a security control is out of scope for a test PR, and the right
// remedy depends on deployment topology (co-located vs. remote coordinator).
// ===========================================================================
