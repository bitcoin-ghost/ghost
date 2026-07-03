//! Daemon-level happy-path test for the WatchPayments stream.
//!
//! This is the contract test for the **whole** push-channel: wraithd opens a
//! WS to a mock GSP, gets an Authenticate ack, the mock pushes a synthetic
//! BIP-352 candidate, the daemon's session task scans + emits on the
//! broadcast channel, and `run_watch_payments` marshals it back as a
//! `Response::PaymentDetected` envelope (id=0) on the IPC socket.
//!
//! The unit-level core/tests/watch_payments.rs covers the broadcast wiring;
//! daemon/tests/wallet_lifecycle.rs covers the IPC marshalling for one-shot
//! requests + the no-session error-push shape. This file is the only piece
//! that proves they work end-to-end together.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
    extract::{Json, State},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use ghost_gsp_proto::{
    CandidateOutput, ClientMessage, RegisterRequest, RegisterResponse, ServerMessage,
    SessionRequest, SessionResponse, SessionToken,
};
use ghost_keys::{derive_payment_address_v2, derive_shared_secret, GhostKeys};
use rand::RngCore;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use wraith_wallet_core::keystore::Keystore;
use wraith_wallet_ipc::{Envelope, Request, Response};

/// Standard BIP-39 test vector — gives us deterministic GhostKeys to target.
const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[derive(Clone)]
struct MockState {
    candidate: Arc<ServerMessage>,
}

async fn mock_register(Json(req): Json<RegisterRequest>) -> Json<RegisterResponse> {
    let wallet_id = req.proof.wallet_id().expect("proof yields wallet_id");
    Json(RegisterResponse {
        success: true,
        wallet_id: Some(wallet_id),
        error: None,
    })
}

async fn mock_session(Json(req): Json<SessionRequest>) -> Json<SessionResponse> {
    let wallet_id = req.derive_wallet_id().expect("derive session wallet_id");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let token = SessionToken {
        token: "mock.jwt.token".into(),
        wallet_id,
        created_at: now,
        expires_at: now + 3600,
    };
    Json(SessionResponse {
        success: true,
        token: Some(token.clone()),
        expires_at: Some(token.expires_at),
        error: None,
    })
}

async fn mock_ws(state: State<MockState>, ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state.candidate.clone()))
}

async fn handle_ws(mut socket: WebSocket, candidate: Arc<ServerMessage>) {
    // Drain incoming. After Authenticate, we authenticate; after GetBalance we
    // emit a balance, and from then on we push the candidate every 200 ms so
    // there's no race vs. the watch IPC connection setup. Stops on Close.
    let mut authenticated = false;
    loop {
        tokio::select! {
            biased;
            frame = socket.recv() => {
                let Some(Ok(frame)) = frame else { return };
                let text = match frame {
                    WsMessage::Text(t) => t,
                    WsMessage::Close(_) => return,
                    _ => continue,
                };
                let msg: ClientMessage = match serde_json::from_str(&text) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                match msg {
                    ClientMessage::Authenticate { .. } => {
                        let auth = ServerMessage::AuthResult {
                            success: true,
                            wallet_id: Some("mock-wallet".into()),
                            error: None,
                        };
                        let _ = socket
                            .send(WsMessage::Text(serde_json::to_string(&auth).unwrap()))
                            .await;
                        authenticated = true;
                    }
                    ClientMessage::GetBalance { .. } => {
                        let bal = ServerMessage::BalanceUpdate {
                            confirmed: 0,
                            unconfirmed: 0,
                            locked: 0,
                        };
                        let _ = socket
                            .send(WsMessage::Text(serde_json::to_string(&bal).unwrap()))
                            .await;
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(200)) => {
                if !authenticated { continue; }
                if socket
                    .send(WsMessage::Text(serde_json::to_string(&*candidate).unwrap()))
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    }
}

fn build_synthetic_candidate(keys: &GhostKeys) -> ServerMessage {
    let secp = Secp256k1::new();
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let eph_secret = SecretKey::from_slice(&bytes).expect("nonzero scalar");
    let ephemeral_pub = PublicKey::from_secret_key(&secp, &eph_secret);
    let shared = derive_shared_secret(&eph_secret, keys.scan_pubkey());
    let (output_pub, _) =
        derive_payment_address_v2(keys.spend_pubkey(), &shared, 0).expect("derive output pubkey");
    let serialized = output_pub.serialize();
    let xonly = &serialized[1..];

    ServerMessage::CandidateTransaction {
        ephemeral_pubkey: hex::encode(ephemeral_pub.serialize()),
        outputs: vec![CandidateOutput {
            output_pubkey: hex::encode(xonly),
            amount_sats: Some(73_000),
            vout: 3,
        }],
        txid: "1".repeat(64),
        block_height: Some(900_001),
    }
}

async fn spawn_mock(candidate: ServerMessage) -> std::net::SocketAddr {
    let app = Router::new()
        .route("/api/v1/register", post(mock_register))
        .route("/api/v1/session", post(mock_session))
        .route("/ws/v1", get(mock_ws))
        .with_state(MockState {
            candidate: Arc::new(candidate),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    addr
}

fn wraithd_binary() -> PathBuf {
    if let Some(p) = option_env!("CARGO_BIN_EXE_wraithd") {
        return PathBuf::from(p);
    }
    let exe = std::env::current_exe().expect("current_exe");
    let mut dir = exe.parent().expect("exe parent").to_path_buf();
    while dir.pop() {
        let candidate = dir.join("wraithd");
        if candidate.exists() {
            return candidate;
        }
    }
    panic!("wraithd binary not found")
}

async fn spawn_daemon(gsp_url: &str) -> (Child, PathBuf, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join("wraithd.sock");
    let wallets = tmp.path().join("wallets");
    std::fs::create_dir_all(&wallets).expect("mkdir wallets");

    let child = Command::new(wraithd_binary())
        .env("WRAITHD_SOCKET", &socket)
        .env("WRAITHD_WALLETS_DIR", &wallets)
        // This test imports a publicly-known test mnemonic, which the daemon now
        // (correctly) refuses on the mainnet default. Pin the test to signet.
        .env("WRAITHD_NETWORK", "signet")
        .env("WRAITHD_GSP", gsp_url)
        // ghost-pay is unused on this test path. Point it at a dead address
        // so the daemon doesn't accidentally hit a real local instance.
        .env("WRAITHD_GHOST_PAY", "http://127.0.0.1:1")
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn wraithd");

    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if socket.exists() {
            tokio::time::sleep(Duration::from_millis(40)).await;
            return (child, socket, tmp);
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
    panic!("wraithd socket never appeared");
}

async fn rpc(socket: &PathBuf, id: u64, request: Request) -> Response {
    let stream = UnixStream::connect(socket).await.expect("connect");
    let (reader, mut writer) = stream.into_split();
    let mut line = serde_json::to_string(&Envelope::new(id, request)).expect("serialise");
    line.push('\n');
    writer.write_all(line.as_bytes()).await.expect("write");
    writer.shutdown().await.expect("shutdown");
    let mut buf = String::new();
    BufReader::new(reader)
        .read_line(&mut buf)
        .await
        .expect("read");
    let env: Envelope<Response> = serde_json::from_str(&buf).expect("decode");
    assert_eq!(env.id, id);
    env.payload
}

#[tokio::test]
async fn watch_payments_happy_path_through_daemon() {
    // Deterministic keys for the synthetic match. We use the same mnemonic on
    // both sides — the test computes the candidate against these GhostKeys,
    // and the daemon-imported wallet derives the same keys via Keystore.
    let keystore = Keystore::from_mnemonic(TEST_MNEMONIC).expect("from_mnemonic");
    let keys = keystore.ghost_keys().expect("ghost_keys");
    let candidate = build_synthetic_candidate(&keys);

    let mock_addr = spawn_mock(candidate).await;
    let gsp_url = format!("ws://{mock_addr}/ws/v1");

    let (mut child, socket, _tmp) = spawn_daemon(&gsp_url).await;

    // Import the wallet keyed to the same mnemonic; gsp_auth needs an
    // unlocked active wallet to derive the auth keypair.
    match rpc(
        &socket,
        1,
        Request::WalletImport {
            name: "mock".into(),
            mnemonic: TEST_MNEMONIC.into(),
            passphrase: "watch-test-passphrase-aaa".into(),
        },
    )
    .await
    {
        Response::WalletImported { name, .. } => assert_eq!(name, "mock"),
        other => panic!("expected WalletImported, got {other:?}"),
    }

    match rpc(&socket, 2, Request::GspAuth).await {
        Response::GspAuth(_) => {}
        other => panic!("gsp_auth failed: {other:?}"),
    }

    // Open the WatchPayments stream. The first reply is the Watching ack;
    // subsequent envelopes are pushes (id=0). The mock pushes the candidate
    // every 200ms, so we should see at least one detection within ~1s.
    let stream = UnixStream::connect(&socket).await.expect("watch connect");
    let (reader, mut writer) = stream.into_split();
    let mut line =
        serde_json::to_string(&Envelope::new(99, Request::WatchPayments)).expect("serialise");
    line.push('\n');
    writer.write_all(line.as_bytes()).await.expect("write");

    let mut reader = BufReader::new(reader);
    let mut ack_line = String::new();
    reader.read_line(&mut ack_line).await.expect("read ack");
    let ack: Envelope<Response> = serde_json::from_str(&ack_line).expect("decode ack");
    assert_eq!(ack.id, 99);
    assert!(matches!(ack.payload, Response::Watching), "ack");

    // Read the first detection push within 5s.
    let mut detected_line = String::new();
    let read = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut detected_line))
        .await
        .expect("watch never delivered");
    read.expect("read detection");
    let env: Envelope<Response> = serde_json::from_str(&detected_line).expect("decode push");
    assert_eq!(env.id, 0, "push must use id=0");
    match env.payload {
        Response::PaymentDetected(d) => {
            assert_eq!(d.amount_sats, Some(73_000));
            assert_eq!(d.vout, 3);
            assert_eq!(d.k, 0);
            assert_eq!(d.block_height, Some(900_001));
            assert_eq!(d.txid, "1".repeat(64));
        }
        other => panic!("expected PaymentDetected, got {other:?}"),
    }

    child.kill().await.ok();
}
