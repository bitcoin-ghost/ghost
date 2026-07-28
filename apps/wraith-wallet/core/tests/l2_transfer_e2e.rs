//! End-to-end wiring test for `wraith light send` (the L2 transfer
//! one-shot).
//!
//! Mirrors `watch_payments.rs` in approach: spins up an in-process
//! axum WebSocket server that speaks just enough of the GSP proto
//! to (a) authenticate the client and (b) reply to
//! `ClientMessage::SendL2Payment` with `ServerMessage::PaymentSent`.
//! Then drives the wallet's real `SessionHandle::send_l2_payment` and
//! asserts the response shape.
//!
//! This is the contract test for the L2 send wire — if it goes red,
//! `wraith light send` will silently break end-to-end against a real
//! ghost-gsp + ghost-pay stack. The coverage is otherwise only via
//! `scripts/regtest-l2-transfer-demo.sh`, which needs a real
//! `ghostd`/`bitcoind` to run.

use std::time::Duration;

use axum::{
    extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
    routing::get,
    Router,
};
use ghost_gsp_proto::{ClientMessage, ServerMessage, TransactionInfo, WalletProof};
use wraith_wallet_core::gsp::spawn_session;

/// Handle the GSP WebSocket frame loop. The mock supports the two
/// message exchanges this test needs: `Authenticate` and
/// `SendL2Payment`. Anything else is silently dropped — the real
/// GSP handles a much larger surface but we only assert against
/// the L2 send round-trip here.
async fn handle_ws(mut socket: WebSocket) {
    while let Some(Ok(frame)) = socket.recv().await {
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
                    wallet_id: Some("alice-wallet".into()),
                    error: None,
                };
                let _ = socket
                    .send(WsMessage::Text(serde_json::to_string(&auth).unwrap()))
                    .await;
            }
            ClientMessage::SendL2Payment {
                recipient,
                amount_sats,
                ..
            } => {
                // Mirror what ghost-gsp does on the wire: synthesize a
                // payment_id and reply with PaymentSent.
                let reply = ServerMessage::PaymentSent {
                    success: true,
                    payment_id: Some(format!("pay_{}", &recipient[..8.min(recipient.len())])),
                    amount_sats,
                    recipient: recipient.clone(),
                    status: Some("pending".to_string()),
                    error: None,
                };
                let _ = socket
                    .send(WsMessage::Text(serde_json::to_string(&reply).unwrap()))
                    .await;
            }
            _ => {}
        }
    }
}

async fn spawn_mock() -> std::net::SocketAddr {
    let app = Router::new().route(
        "/ws/v1",
        get(|ws: WebSocketUpgrade| async move { ws.on_upgrade(handle_ws).into_response() }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    addr
}

#[tokio::test]
async fn light_send_round_trips_send_l2_payment() {
    let addr = spawn_mock().await;
    let ws_url = format!("ws://{addr}/ws/v1");

    let session = spawn_session(vec![ws_url], "mock-jwt-token".to_string(), None, None);

    // The mock accepts any structurally-valid WalletProof; the test's
    // assertion is on the wire round-trip, not on the proof crypto
    // (which has its own coverage in ghost-gsp-proto's auth tests).
    let proof = WalletProof::new("send-l2", &[7u8; 32]).expect("build proof");

    let result = tokio::time::timeout(
        Duration::from_secs(3),
        session.send_l2_payment(
            "bob_recipient_ghost_id_xyz".to_string(),
            5_000,
            proof,
            Some("groceries".to_string()),
        ),
    )
    .await
    .expect("send_l2_payment timeout")
    .expect("send_l2_payment failed");

    assert_eq!(result.amount_sats, 5_000);
    assert_eq!(result.recipient, "bob_recipient_ghost_id_xyz");
    assert_eq!(result.status, "pending");
    // payment_id is operator-synthesised; just check it has the
    // expected prefix shape (the mock builds `pay_<first-8-of-recipient>`).
    assert!(
        result.payment_id.starts_with("pay_"),
        "expected pay_ prefix, got {}",
        result.payment_id
    );
}

#[tokio::test]
async fn light_history_round_trips_get_transactions() {
    // Distinct mock that handles GetTransactions by replying with a
    // small canned ledger. Tests pin the `Transactions` reply shape
    // and the wallet's `TransactionsResult` parsing — closes the
    // other half of the L2 send/history wire.
    async fn handle_ws(mut socket: WebSocket) {
        while let Some(Ok(frame)) = socket.recv().await {
            let text = match frame {
                WsMessage::Text(t) => t,
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
                        wallet_id: Some("alice".into()),
                        error: None,
                    };
                    let _ = socket
                        .send(WsMessage::Text(serde_json::to_string(&auth).unwrap()))
                        .await;
                }
                ClientMessage::GetTransactions {
                    limit,
                    offset: _,
                    wallet_bech32: _,
                } => {
                    // Build a tiny fake ledger: one send (-5000), one
                    // receive (+5000), both with the new shape.
                    let txs = vec![
                        TransactionInfo {
                            txid: "deadbeef".repeat(8),
                            block_height: Some(123),
                            timestamp: 1_700_000_000,
                            amount_sats: -5_000,
                            fee_sats: Some(0),
                            tx_type: "send".to_string(),
                            confirmations: 6,
                            memo: Some("groceries".to_string()),
                        },
                        TransactionInfo {
                            txid: "cafef00d".repeat(8),
                            block_height: Some(124),
                            timestamp: 1_700_000_500,
                            amount_sats: 5_000,
                            fee_sats: Some(0),
                            tx_type: "receive".to_string(),
                            confirmations: 5,
                            memo: None,
                        },
                    ];
                    let total = txs.len() as u32;
                    let truncated: Vec<_> = txs.into_iter().take(limit as usize).collect();
                    let reply = ServerMessage::Transactions {
                        transactions: truncated,
                        total_count: total,
                    };
                    let _ = socket
                        .send(WsMessage::Text(serde_json::to_string(&reply).unwrap()))
                        .await;
                }
                _ => {}
            }
        }
    }

    let app = Router::new().route(
        "/ws/v1",
        get(|ws: WebSocketUpgrade| async move { ws.on_upgrade(handle_ws).into_response() }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let ws_url = format!("ws://{addr}/ws/v1");

    let session = spawn_session(vec![ws_url], "mock-jwt-token".to_string(), None, None);

    let result = tokio::time::timeout(Duration::from_secs(3), session.get_transactions(50, 0))
        .await
        .expect("get_transactions timeout")
        .expect("get_transactions failed");

    assert_eq!(result.total_count, 2);
    assert_eq!(result.transactions.len(), 2);
    let send = &result.transactions[0];
    assert_eq!(send.tx_type, "send");
    assert_eq!(send.amount_sats, -5_000);
    assert_eq!(send.memo.as_deref(), Some("groceries"));
    let receive = &result.transactions[1];
    assert_eq!(receive.tx_type, "receive");
    assert_eq!(receive.amount_sats, 5_000);
}

#[tokio::test]
async fn send_l2_payment_propagates_server_error() {
    // Distinct mock for the failure path so it doesn't share state.
    async fn handle_ws_failure(mut socket: WebSocket) {
        while let Some(Ok(frame)) = socket.recv().await {
            let text = match frame {
                WsMessage::Text(t) => t,
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
                        wallet_id: Some("alice".into()),
                        error: None,
                    };
                    let _ = socket
                        .send(WsMessage::Text(serde_json::to_string(&auth).unwrap()))
                        .await;
                }
                ClientMessage::SendL2Payment {
                    recipient,
                    amount_sats,
                    ..
                } => {
                    let reply = ServerMessage::PaymentSent {
                        success: false,
                        payment_id: None,
                        amount_sats,
                        recipient,
                        status: None,
                        error: Some("Insufficient L2 balance".to_string()),
                    };
                    let _ = socket
                        .send(WsMessage::Text(serde_json::to_string(&reply).unwrap()))
                        .await;
                }
                _ => {}
            }
        }
    }

    let app = Router::new().route(
        "/ws/v1",
        get(|ws: WebSocketUpgrade| async move { ws.on_upgrade(handle_ws_failure).into_response() }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let ws_url = format!("ws://{addr}/ws/v1");

    let session = spawn_session(vec![ws_url], "mock-jwt-token".to_string(), None, None);

    let proof = WalletProof::new("send-l2", &[8u8; 32]).expect("build proof");

    let outcome = tokio::time::timeout(
        Duration::from_secs(3),
        session.send_l2_payment("bob_ghost_id".to_string(), 999_999_999, proof, None),
    )
    .await
    .expect("timeout waiting for failure response");

    assert!(outcome.is_err(), "expected Err, got {outcome:?}");
    let err = outcome.unwrap_err();
    assert!(
        err.contains("Insufficient L2 balance"),
        "expected error to surface server message, got: {err}"
    );
}
