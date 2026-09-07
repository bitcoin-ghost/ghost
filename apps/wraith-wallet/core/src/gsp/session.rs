//! Long-lived authenticated WebSocket session to a GSP.
//!
//! The daemon spawns one of these per active wallet's GSP session token. The task:
//!
//! 1. Opens a WebSocket to the GSP's `/ws/v1` endpoint.
//! 2. Sends `ClientMessage::Authenticate { token }`.
//! 3. Waits for `ServerMessage::AuthResult { success: true }`.
//! 4. Issues `ClientMessage::GetBalance` so the cache populates immediately.
//! 5. Reads incoming messages — `BalanceUpdate` updates the cached balance,
//!    other pushes are logged and ignored for now.
//! 6. Sends a `Ping` keepalive every 30 s.
//! 7. On any IO/protocol error, marks the session as `Backoff`, sleeps with
//!    exponential backoff (1 s, 2 s, 4 s, ..., capped at 60 s), and reconnects.
//!
//! Shutdown: the daemon drops the `SessionHandle`, which closes a `watch` channel
//! the task listens on. The task exits at the next opportunity.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use ghost_gsp_proto::{
    CandidateOutput, ClientMessage, PaymentMode, PreparedPayment, ServerMessage, TransactionInfo,
    UtxoInfo, WalletProof,
};
use ghost_keys::{GhostKeys, PaymentDetector};

use tokio::sync::{broadcast, mpsc, oneshot, watch, RwLock};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionPhase {
    #[default]
    Disconnected,
    Connecting,
    Authenticating,
    Authenticated,
    Backoff,
}

/// Snapshot of a session's runtime state. Cheap to clone.
#[derive(Debug, Clone, Default)]
pub struct SessionStatus {
    pub phase: SessionPhase,
    /// Confirmed satoshi balance from the most recent `BalanceUpdate`.
    pub last_balance: Option<BalanceSnapshot>,
    /// Last error message, set on transport / protocol failure.
    pub last_error: Option<String>,
    /// Successful WS connection count (1 = connected first time, 2 = one reconnect, ...).
    pub connect_count: u64,
    /// Silent-payment detections accumulated client-side from CandidateTransaction
    /// pushes. Cleared on session restart (re-population needs server-side rescan).
    pub detections: Vec<DetectedPayment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BalanceSnapshot {
    pub confirmed_sats: u64,
    pub unconfirmed_sats: u64,
    pub locked_sats: u64,
    /// Unix seconds when this snapshot was received.
    pub received_at: i64,
}

/// One BIP-352 silent-payment detection from a `CandidateTransaction` push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedPayment {
    pub txid: String,
    pub block_height: Option<u32>,
    pub vout: u32,
    pub amount_sats: Option<u64>,
    /// Derivation index (k) used by the sender. Recorded so a future
    /// "spend this output" call can re-derive the spend key.
    pub k: u32,
    pub received_at: i64,
}

/// Daemon-side handle to a running session task. Drop to stop the task.
pub struct SessionHandle {
    status: Arc<RwLock<SessionStatus>>,
    cmd_tx: mpsc::Sender<SessionCommand>,
    shutdown_tx: watch::Sender<bool>,
    events_tx: broadcast::Sender<DetectedPayment>,
    task: Option<JoinHandle<()>>,
}

impl SessionHandle {
    pub async fn snapshot(&self) -> SessionStatus {
        self.status.read().await.clone()
    }

    /// Subscribe to a live stream of newly-detected silent payments. Each
    /// receiver gets every event published after it subscribes; lagging
    /// receivers will see RecvError::Lagged and are expected to recover by
    /// re-snapshotting `SessionStatus.detections`.
    pub fn subscribe_payments(&self) -> broadcast::Receiver<DetectedPayment> {
        self.events_tx.subscribe()
    }

    /// Issue `GetUtxos` over the persistent session and await the matching `Utxos` reply.
    pub async fn get_utxos(&self, min_confirmations: u32) -> Result<UtxosResult, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SessionCommand::GetUtxos {
                min_confirmations,
                reply: tx,
            })
            .await
            .map_err(|_| "session task closed".to_string())?;
        rx.await.map_err(|_| "reply dropped".to_string())?
    }

    /// Issue `GetTransactions` and await the matching `Transactions` reply.
    pub async fn get_transactions(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<TransactionsResult, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SessionCommand::GetTransactions {
                limit,
                offset,
                reply: tx,
            })
            .await
            .map_err(|_| "session task closed".to_string())?;
        rx.await.map_err(|_| "reply dropped".to_string())?
    }

    /// Issue `PreparePayment` and await the matching `PaymentPrepared` reply.
    pub async fn prepare_payment(
        &self,
        recipient: String,
        amount_sats: u64,
        mode: PaymentMode,
        proof: WalletProof,
        memo: Option<String>,
    ) -> Result<PreparedPayment, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SessionCommand::PreparePayment {
                recipient,
                amount_sats,
                mode,
                proof,
                memo,
                reply: tx,
            })
            .await
            .map_err(|_| "session task closed".to_string())?;
        rx.await.map_err(|_| "reply dropped".to_string())?
    }

    /// Issue `SubmitSignedPayment` and await the matching `PaymentSubmitted` reply.
    pub async fn submit_signed_payment(
        &self,
        payment_id: String,
        signature_hex: String,
        public_key_hex: String,
    ) -> Result<SubmittedPaymentResult, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SessionCommand::SubmitSignedPayment {
                payment_id,
                signature: signature_hex,
                public_key: public_key_hex,
                reply: tx,
            })
            .await
            .map_err(|_| "session task closed".to_string())?;
        rx.await.map_err(|_| "reply dropped".to_string())?
    }

    /// One-shot L2 payment. Issues `SendL2Payment` and awaits the
    /// matching `PaymentSent` reply. Replaces the prepare/sign/
    /// submit dance for the new wallet path — L2 transfers are
    /// session-authenticated ledger ops, not Bitcoin txs.
    pub async fn send_l2_payment(
        &self,
        recipient: String,
        amount_sats: u64,
        proof: WalletProof,
        memo: Option<String>,
    ) -> Result<SentL2PaymentResult, String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SessionCommand::SendL2Payment {
                recipient,
                amount_sats,
                proof,
                memo,
                reply: tx,
            })
            .await
            .map_err(|_| "session task closed".to_string())?;
        rx.await.map_err(|_| "reply dropped".to_string())?
    }

    /// Issue `RegisterScanKey` and await the matching `ScanKeyRegistered` reply.
    pub async fn register_scan_key(
        &self,
        scan_pubkey_hex: String,
        proof: WalletProof,
    ) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SessionCommand::RegisterScanKey {
                scan_pubkey: scan_pubkey_hex,
                proof,
                reply: tx,
            })
            .await
            .map_err(|_| "session task closed".to_string())?;
        rx.await.map_err(|_| "reply dropped".to_string())?
    }
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(t) = self.task.take() {
            t.abort();
        }
    }
}

/// Bag of replies the session task is waiting to deliver. Pending requests are
/// matched FIFO against incoming server messages of the corresponding shape.
enum PendingReply {
    Utxos(oneshot::Sender<Result<UtxosResult, String>>),
    Transactions(oneshot::Sender<Result<TransactionsResult, String>>),
    PaymentPrepared(oneshot::Sender<Result<PreparedPayment, String>>),
    PaymentSubmitted(oneshot::Sender<Result<SubmittedPaymentResult, String>>),
    ScanKeyRegistered(oneshot::Sender<Result<(), String>>),
    PaymentSent(oneshot::Sender<Result<SentL2PaymentResult, String>>),
}

/// Commands the daemon can send into the session task.
pub enum SessionCommand {
    GetUtxos {
        min_confirmations: u32,
        reply: oneshot::Sender<Result<UtxosResult, String>>,
    },
    GetTransactions {
        limit: u32,
        offset: u32,
        reply: oneshot::Sender<Result<TransactionsResult, String>>,
    },
    PreparePayment {
        recipient: String,
        amount_sats: u64,
        mode: PaymentMode,
        proof: WalletProof,
        memo: Option<String>,
        reply: oneshot::Sender<Result<PreparedPayment, String>>,
    },
    SubmitSignedPayment {
        payment_id: String,
        signature: String,
        public_key: String,
        reply: oneshot::Sender<Result<SubmittedPaymentResult, String>>,
    },
    RegisterScanKey {
        scan_pubkey: String,
        proof: WalletProof,
        reply: oneshot::Sender<Result<(), String>>,
    },
    SendL2Payment {
        recipient: String,
        amount_sats: u64,
        proof: WalletProof,
        memo: Option<String>,
        reply: oneshot::Sender<Result<SentL2PaymentResult, String>>,
    },
}

#[derive(Debug, Clone)]
pub struct SentL2PaymentResult {
    pub payment_id: String,
    pub status: String,
    pub recipient: String,
    pub amount_sats: u64,
}

#[derive(Debug, Clone)]
pub struct SubmittedPaymentResult {
    pub payment_id: String,
    pub txid: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UtxosResult {
    pub utxos: Vec<UtxoInfo>,
    pub total_sats: u64,
}

#[derive(Debug, Clone)]
pub struct TransactionsResult {
    pub transactions: Vec<TransactionInfo>,
    pub total_count: u32,
}

/// Spawn a long-lived authenticated session task. Returns a handle.
///
/// `ws_urls` is the failover list — the task tries them in order and rotates
/// on each reconnect attempt. Pass `vec![single_url]` for the single-endpoint case.
///
/// `scan_keys` enables BIP-352 silent-payment detection. When provided, the task
/// runs the local scanner against every `CandidateTransaction` push from the
/// server and caches matches in `SessionStatus.detections`. Pass `None` to
/// disable client-side detection (saves CPU on session-bootstrap failure paths).
///
/// `tor_proxy` (e.g. `Some("socks5h://127.0.0.1:9050")`) routes the WebSocket
/// connection through the given SOCKS5 proxy. Currently supports plain `ws://`
/// only — wss-over-Tor needs a separate TLS-aware connector. Pass `None` for
/// direct connections.
pub fn spawn_session(
    ws_urls: Vec<String>,
    jwt_token: String,
    scan_keys: Option<GhostKeys>,
    tor_proxy: Option<String>,
) -> SessionHandle {
    spawn_session_with_bech32(ws_urls, jwt_token, scan_keys, None, tor_proxy)
}

/// Same as [`spawn_session`] but accepts an explicit bech32 ghost-id
/// string. Required for non-mainnet wallets where
/// `GhostKeys::ghost_id().to_string()` (which encodes for mainnet)
/// produces the wrong HRP — the daemon knows the wallet's network
/// and computes the right `<network>ghost1q...` form before
/// spawning the session. Forwarded with each `GetTransactions` so
/// ghost-pay can match recipient-side rows.
pub fn spawn_session_with_bech32(
    ws_urls: Vec<String>,
    jwt_token: String,
    scan_keys: Option<GhostKeys>,
    ghost_id_bech32: Option<String>,
    tor_proxy: Option<String>,
) -> SessionHandle {
    let status = Arc::new(RwLock::new(SessionStatus::default()));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (cmd_tx, cmd_rx) = mpsc::channel::<SessionCommand>(32);
    let (events_tx, _) = broadcast::channel::<DetectedPayment>(256);

    let task = tokio::spawn(run(
        ws_urls,
        jwt_token,
        scan_keys,
        ghost_id_bech32,
        tor_proxy,
        status.clone(),
        events_tx.clone(),
        shutdown_rx,
        cmd_rx,
    ));

    SessionHandle {
        status,
        cmd_tx,
        shutdown_tx,
        events_tx,
        task: Some(task),
    }
}

/// Connect a WebSocket, optionally routing the underlying TCP through a
/// SOCKS5 proxy (`socks5://host:port` or `socks5h://host:port`). The `h`
/// variant does DNS through the proxy — preferred for Tor.
///
/// Returns the `(stream, response)` pair `tokio_tungstenite::connect_async`
/// would have returned.
async fn ws_connect(
    ws_url: &str,
    proxy: Option<&str>,
) -> Result<
    (
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        tokio_tungstenite::tungstenite::http::Response<Option<Vec<u8>>>,
    ),
    String,
> {
    let proxy_url = match proxy {
        Some(p) if !p.is_empty() => p,
        _ => {
            // No proxy → direct connect.
            return tokio_tungstenite::connect_async(ws_url)
                .await
                .map_err(|e| e.to_string());
        }
    };

    // Parse the WS URL to get host + port.
    let parsed = url::Url::parse(ws_url).map_err(|e| format!("ws url parse: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "ws url has no host".to_string())?
        .to_string();
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| "ws url has no port".to_string())?;
    let scheme = parsed.scheme();
    if scheme != "ws" {
        // wss-over-Tor needs an additional TLS layer that we haven't wired yet.
        return Err(format!(
            "wss-over-tor not yet supported (got scheme '{scheme}'); use ws:// or run an arti onion-service to a plain ws GSP"
        ));
    }

    // Strip the scheme so tokio_socks gets a host:port target.
    let target = format!("{host}:{port}");

    // Parse the proxy URL — only socks5/socks5h are supported.
    let proxy_parsed = url::Url::parse(proxy_url).map_err(|e| format!("proxy url parse: {e}"))?;
    let proxy_scheme = proxy_parsed.scheme();
    if proxy_scheme != "socks5" && proxy_scheme != "socks5h" {
        return Err(format!(
            "unsupported proxy scheme '{proxy_scheme}'; only socks5 and socks5h are supported"
        ));
    }
    let proxy_host = proxy_parsed
        .host_str()
        .ok_or_else(|| "proxy url has no host".to_string())?;
    let proxy_port = proxy_parsed
        .port_or_known_default()
        .ok_or_else(|| "proxy url has no port".to_string())?;
    let proxy_target = format!("{proxy_host}:{proxy_port}");

    // socks5h:// resolves the destination hostname inside the proxy (Tor),
    // socks5:// resolves locally first (leaks DNS — discouraged with Tor).
    let tcp = tokio_socks::tcp::Socks5Stream::connect(proxy_target.as_str(), target)
        .await
        .map_err(|e| format!("{proxy_scheme} connect: {e}"))?
        .into_inner();

    // Wrap as MaybeTlsStream::Plain BEFORE the WS handshake so the resulting
    // stream type matches the non-proxy path (which goes through connect_async).
    let plain = tokio_tungstenite::MaybeTlsStream::Plain(tcp);
    tokio_tungstenite::client_async(ws_url, plain)
        .await
        .map_err(|e| format!("ws handshake over socks5: {e}"))
}

const KEEPALIVE_SECS: u64 = 30;
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

#[allow(clippy::too_many_arguments)]
async fn run(
    ws_urls: Vec<String>,
    jwt_token: String,
    scan_keys: Option<GhostKeys>,
    ghost_id_bech32: Option<String>,
    tor_proxy: Option<String>,
    status: Arc<RwLock<SessionStatus>>,
    events_tx: broadcast::Sender<DetectedPayment>,
    mut shutdown: watch::Receiver<bool>,
    mut cmd_rx: mpsc::Receiver<SessionCommand>,
) {
    if ws_urls.is_empty() {
        tracing::error!("gsp session: no ws urls configured, exiting");
        return;
    }
    let mut backoff = BACKOFF_INITIAL;
    let mut url_idx: usize = 0;
    loop {
        if *shutdown.borrow() {
            tracing::debug!("gsp session: shutdown requested, exiting");
            return;
        }

        let ws_url = &ws_urls[url_idx % ws_urls.len()];

        // === connect ===
        set_phase(&status, SessionPhase::Connecting).await;
        let (mut ws, _) = match ws_connect(ws_url, tor_proxy.as_deref()).await {
            Ok(p) => p,
            Err(e) => {
                let msg = e.to_string();
                tracing::warn!(
                    url = %ws_url,
                    error = %msg,
                    backoff = ?backoff,
                    "gsp session: connect failed, will rotate endpoint"
                );
                set_error(&status, SessionPhase::Backoff, msg).await;
                // Advance to next URL for the next attempt.
                url_idx = url_idx.wrapping_add(1);
                if sleep_or_shutdown(backoff, &mut shutdown).await {
                    return;
                }
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue;
            }
        };
        // On a successful connect, reset backoff AND prefer the primary URL again
        // (so failover is sticky-during-outage, not permanent).
        backoff = BACKOFF_INITIAL;
        url_idx = 0;

        // === authenticate ===
        set_phase(&status, SessionPhase::Authenticating).await;
        let auth_msg = ClientMessage::Authenticate {
            token: jwt_token.clone(),
        };
        if let Err(e) = send_client(&mut ws, &auth_msg).await {
            set_error(&status, SessionPhase::Backoff, format!("send auth: {e}")).await;
            sleep_or_shutdown(backoff, &mut shutdown).await;
            continue;
        }

        // wait for AuthResult
        match read_until_auth_result(&mut ws).await {
            Ok(true) => {} // authenticated
            Ok(false) => {
                set_error(
                    &status,
                    SessionPhase::Backoff,
                    "server rejected authentication".into(),
                )
                .await;
                let _ = ws.close(None).await;
                if sleep_or_shutdown(backoff, &mut shutdown).await {
                    return;
                }
                continue;
            }
            Err(e) => {
                set_error(&status, SessionPhase::Backoff, format!("auth read: {e}")).await;
                let _ = ws.close(None).await;
                if sleep_or_shutdown(backoff, &mut shutdown).await {
                    return;
                }
                continue;
            }
        }

        {
            let mut s = status.write().await;
            s.phase = SessionPhase::Authenticated;
            s.connect_count += 1;
            s.last_error = None;
        }

        // bootstrap: ask for current balance + (if we have scan keys) subscribe
        // to silent-payment candidate-transaction pushes.
        let _ = send_client(&mut ws, &ClientMessage::GetBalance { max_k: None }).await;
        if scan_keys.is_some() {
            let _ = send_client(&mut ws, &ClientMessage::SubscribeSilentPayments).await;
        }

        // === main loop: drain messages + keepalive + commands ===
        let mut keepalive = tokio::time::interval(Duration::from_secs(KEEPALIVE_SECS));
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        keepalive.tick().await; // discard immediate tick

        let mut pending: VecDeque<PendingReply> = VecDeque::new();
        let outcome = run_main_loop(
            &mut ws,
            &status,
            &mut shutdown,
            &mut keepalive,
            &mut cmd_rx,
            &mut pending,
            scan_keys.as_ref(),
            ghost_id_bech32.as_deref(),
            &events_tx,
        )
        .await;

        // On disconnect, fail any pending replies so callers don't hang.
        for p in pending.drain(..) {
            match p {
                PendingReply::Utxos(tx) => {
                    let _ = tx.send(Err("session disconnected".into()));
                }
                PendingReply::Transactions(tx) => {
                    let _ = tx.send(Err("session disconnected".into()));
                }
                PendingReply::PaymentPrepared(tx) => {
                    let _ = tx.send(Err("session disconnected".into()));
                }
                PendingReply::PaymentSubmitted(tx) => {
                    let _ = tx.send(Err("session disconnected".into()));
                }
                PendingReply::ScanKeyRegistered(tx) => {
                    let _ = tx.send(Err("session disconnected".into()));
                }
                PendingReply::PaymentSent(tx) => {
                    let _ = tx.send(Err("session disconnected".into()));
                }
            }
        }

        let _ = ws.close(None).await;
        match outcome {
            MainLoopOutcome::Shutdown => return,
            MainLoopOutcome::Disconnect(reason) => {
                tracing::warn!(reason = %reason, "gsp session: disconnected, will reconnect");
                set_error(&status, SessionPhase::Backoff, reason).await;
                if sleep_or_shutdown(backoff, &mut shutdown).await {
                    return;
                }
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

enum MainLoopOutcome {
    Shutdown,
    Disconnect(String),
}

#[allow(clippy::too_many_arguments)]
async fn run_main_loop(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    status: &Arc<RwLock<SessionStatus>>,
    shutdown: &mut watch::Receiver<bool>,
    keepalive: &mut tokio::time::Interval,
    cmd_rx: &mut mpsc::Receiver<SessionCommand>,
    pending: &mut VecDeque<PendingReply>,
    scan_keys: Option<&GhostKeys>,
    ghost_id_bech32: Option<&str>,
    events_tx: &broadcast::Sender<DetectedPayment>,
) -> MainLoopOutcome {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return MainLoopOutcome::Shutdown;
                }
            }
            _ = keepalive.tick() => {
                let ping = ClientMessage::Ping {
                    timestamp: Some(now_unix_ms()),
                };
                if let Err(e) = send_client(ws, &ping).await {
                    return MainLoopOutcome::Disconnect(format!("send keepalive: {e}"));
                }
            }
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else {
                    // Sender dropped (shouldn't happen — handle owns it). Treat as shutdown.
                    return MainLoopOutcome::Shutdown;
                };
                match cmd {
                    SessionCommand::GetUtxos { min_confirmations, reply } => {
                        let msg = ClientMessage::GetUtxos { min_confirmations };
                        if let Err(e) = send_client(ws, &msg).await {
                            let _ = reply.send(Err(format!("send GetUtxos: {e}")));
                            return MainLoopOutcome::Disconnect(format!("send GetUtxos: {e}"));
                        }
                        pending.push_back(PendingReply::Utxos(reply));
                    }
                    SessionCommand::GetTransactions { limit, offset, reply } => {
                        // Forward the wallet's own bech32 ghost-id so
                        // ghost-pay can match L2 ledger rows where THIS
                        // wallet is the recipient. The daemon supplies
                        // the network-correct bech32 (mainnet/testnet/
                        // signet/regtest HRP) at session-spawn time;
                        // we just forward it.
                        let msg = ClientMessage::GetTransactions {
                            limit,
                            offset,
                            wallet_bech32: ghost_id_bech32.map(|s| s.to_string()),
                        };
                        if let Err(e) = send_client(ws, &msg).await {
                            let _ = reply.send(Err(format!("send GetTransactions: {e}")));
                            return MainLoopOutcome::Disconnect(format!(
                                "send GetTransactions: {e}"
                            ));
                        }
                        pending.push_back(PendingReply::Transactions(reply));
                    }
                    SessionCommand::PreparePayment {
                        recipient,
                        amount_sats,
                        mode,
                        proof,
                        memo,
                        reply,
                    } => {
                        let msg = ClientMessage::PreparePayment {
                            recipient,
                            amount_sats,
                            mode,
                            proof,
                            memo,
                            encrypted_metadata: None,
                        };
                        if let Err(e) = send_client(ws, &msg).await {
                            let _ = reply.send(Err(format!("send PreparePayment: {e}")));
                            return MainLoopOutcome::Disconnect(format!(
                                "send PreparePayment: {e}"
                            ));
                        }
                        pending.push_back(PendingReply::PaymentPrepared(reply));
                    }
                    SessionCommand::SubmitSignedPayment {
                        payment_id,
                        signature,
                        public_key,
                        reply,
                    } => {
                        let msg = ClientMessage::SubmitSignedPayment {
                            payment_id,
                            signature,
                            public_key,
                        };
                        if let Err(e) = send_client(ws, &msg).await {
                            let _ = reply.send(Err(format!("send SubmitSignedPayment: {e}")));
                            return MainLoopOutcome::Disconnect(format!(
                                "send SubmitSignedPayment: {e}"
                            ));
                        }
                        pending.push_back(PendingReply::PaymentSubmitted(reply));
                    }
                    SessionCommand::RegisterScanKey {
                        scan_pubkey,
                        proof,
                        reply,
                    } => {
                        let msg = ClientMessage::RegisterScanKey {
                            scan_pubkey,
                            proof,
                        };
                        if let Err(e) = send_client(ws, &msg).await {
                            let _ = reply.send(Err(format!("send RegisterScanKey: {e}")));
                            return MainLoopOutcome::Disconnect(format!(
                                "send RegisterScanKey: {e}"
                            ));
                        }
                        pending.push_back(PendingReply::ScanKeyRegistered(reply));
                    }
                    SessionCommand::SendL2Payment {
                        recipient,
                        amount_sats,
                        proof,
                        memo,
                        reply,
                    } => {
                        let msg = ClientMessage::SendL2Payment {
                            recipient,
                            amount_sats,
                            proof,
                            memo,
                        };
                        if let Err(e) = send_client(ws, &msg).await {
                            let _ = reply.send(Err(format!("send SendL2Payment: {e}")));
                            return MainLoopOutcome::Disconnect(format!(
                                "send SendL2Payment: {e}"
                            ));
                        }
                        pending.push_back(PendingReply::PaymentSent(reply));
                    }
                }
            }
            frame = ws.next() => {
                let frame = match frame {
                    Some(Ok(f)) => f,
                    Some(Err(e)) => {
                        return MainLoopOutcome::Disconnect(format!("read: {e}"));
                    }
                    None => return MainLoopOutcome::Disconnect("server closed".into()),
                };
                let text = match frame {
                    Message::Text(t) => t,
                    Message::Close(_) => {
                        return MainLoopOutcome::Disconnect("server closed".into());
                    }
                    _ => continue,
                };
                let parsed: ServerMessage = match serde_json::from_str(text.as_ref()) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(error = %e, raw = %text, "gsp session: bad server message");
                        continue;
                    }
                };
                handle_message(parsed, status, pending, scan_keys, events_tx).await;
            }
        }
    }
}

async fn handle_message(
    msg: ServerMessage,
    status: &Arc<RwLock<SessionStatus>>,
    pending: &mut VecDeque<PendingReply>,
    scan_keys: Option<&GhostKeys>,
    events_tx: &broadcast::Sender<DetectedPayment>,
) {
    match msg {
        // Push: balance update.
        ServerMessage::BalanceUpdate {
            confirmed,
            unconfirmed,
            locked,
        } => {
            let snap = BalanceSnapshot {
                confirmed_sats: confirmed,
                unconfirmed_sats: unconfirmed,
                locked_sats: locked,
                received_at: now_unix_secs(),
            };
            tracing::debug!(?snap, "gsp session: balance update");
            status.write().await.last_balance = Some(snap);
        }

        // Response to GetUtxos.
        ServerMessage::Utxos { utxos, total_sats } => {
            if let Some(idx) = pending
                .iter()
                .position(|p| matches!(p, PendingReply::Utxos(_)))
            {
                if let Some(PendingReply::Utxos(tx)) = pending.remove(idx) {
                    let _ = tx.send(Ok(UtxosResult { utxos, total_sats }));
                    return;
                }
            }
            tracing::debug!("gsp session: unmatched Utxos message (no pending)");
        }

        // Response to GetTransactions.
        ServerMessage::Transactions {
            transactions,
            total_count,
        } => {
            if let Some(idx) = pending
                .iter()
                .position(|p| matches!(p, PendingReply::Transactions(_)))
            {
                if let Some(PendingReply::Transactions(tx)) = pending.remove(idx) {
                    let _ = tx.send(Ok(TransactionsResult {
                        transactions,
                        total_count,
                    }));
                    return;
                }
            }
            tracing::debug!("gsp session: unmatched Transactions message");
        }

        // Response to PreparePayment.
        ServerMessage::PaymentPrepared {
            success,
            payment,
            error,
        } => {
            if let Some(idx) = pending
                .iter()
                .position(|p| matches!(p, PendingReply::PaymentPrepared(_)))
            {
                if let Some(PendingReply::PaymentPrepared(tx)) = pending.remove(idx) {
                    let result = if success {
                        match payment {
                            Some(p) => Ok(p),
                            None => Err("server reported success but no payment".into()),
                        }
                    } else {
                        Err(error.unwrap_or_else(|| "PaymentPrepared failed".into()))
                    };
                    let _ = tx.send(result);
                    return;
                }
            }
            tracing::debug!("gsp session: unmatched PaymentPrepared message");
        }

        // Response to SubmitSignedPayment.
        ServerMessage::PaymentSubmitted {
            success,
            payment_id,
            txid,
            error,
        } => {
            if let Some(idx) = pending
                .iter()
                .position(|p| matches!(p, PendingReply::PaymentSubmitted(_)))
            {
                if let Some(PendingReply::PaymentSubmitted(tx)) = pending.remove(idx) {
                    let result = if success {
                        Ok(SubmittedPaymentResult { payment_id, txid })
                    } else {
                        Err(error.unwrap_or_else(|| "PaymentSubmitted failed".into()))
                    };
                    let _ = tx.send(result);
                    return;
                }
            }
            tracing::debug!("gsp session: unmatched PaymentSubmitted message");
        }

        // Response to SendL2Payment.
        ServerMessage::PaymentSent {
            success,
            payment_id,
            amount_sats,
            recipient,
            status,
            error,
        } => {
            if let Some(idx) = pending
                .iter()
                .position(|p| matches!(p, PendingReply::PaymentSent(_)))
            {
                if let Some(PendingReply::PaymentSent(tx)) = pending.remove(idx) {
                    let result = if success {
                        match payment_id {
                            Some(pid) => Ok(SentL2PaymentResult {
                                payment_id: pid,
                                status: status.unwrap_or_else(|| "pending".into()),
                                recipient,
                                amount_sats,
                            }),
                            None => Err("server reported success but no payment_id".into()),
                        }
                    } else {
                        Err(error.unwrap_or_else(|| "PaymentSent failed".into()))
                    };
                    let _ = tx.send(result);
                    return;
                }
            }
            tracing::debug!("gsp session: unmatched PaymentSent message");
        }

        // Response to RegisterScanKey.
        ServerMessage::ScanKeyRegistered { success, error } => {
            if let Some(idx) = pending
                .iter()
                .position(|p| matches!(p, PendingReply::ScanKeyRegistered(_)))
            {
                if let Some(PendingReply::ScanKeyRegistered(tx)) = pending.remove(idx) {
                    let result = if success {
                        Ok(())
                    } else {
                        Err(error.unwrap_or_else(|| "ScanKeyRegistered failed".into()))
                    };
                    let _ = tx.send(result);
                    return;
                }
            }
            tracing::debug!("gsp session: unmatched ScanKeyRegistered message");
        }

        // Server-side error — surface it on the head of the pending queue.
        ServerMessage::Error {
            code,
            message,
            request_id,
        } => {
            tracing::warn!(%code, %message, ?request_id, "gsp session: server error");
            if let Some(p) = pending.pop_front() {
                let err = format!("{code}: {message}");
                match p {
                    PendingReply::Utxos(tx) => {
                        let _ = tx.send(Err(err));
                    }
                    PendingReply::Transactions(tx) => {
                        let _ = tx.send(Err(err));
                    }
                    PendingReply::PaymentPrepared(tx) => {
                        let _ = tx.send(Err(err));
                    }
                    PendingReply::PaymentSubmitted(tx) => {
                        let _ = tx.send(Err(err));
                    }
                    PendingReply::ScanKeyRegistered(tx) => {
                        let _ = tx.send(Err(err));
                    }
                    PendingReply::PaymentSent(tx) => {
                        let _ = tx.send(Err(err));
                    }
                }
            }
        }

        // Push: BIP-352 silent-payment candidate. Run local scanner.
        ServerMessage::CandidateTransaction {
            ephemeral_pubkey,
            outputs,
            txid,
            block_height,
        } => {
            let Some(keys) = scan_keys else {
                tracing::trace!("gsp session: candidate tx but no scan keys; ignoring");
                return;
            };
            match scan_candidate(keys, &ephemeral_pubkey, &outputs, &txid, block_height) {
                Ok(detected) if !detected.is_empty() => {
                    tracing::info!(
                        matches = detected.len(),
                        %txid,
                        ?block_height,
                        "gsp session: silent-payment match detected"
                    );
                    // Fan out to live subscribers BEFORE we drop the values into
                    // the status cache. send() returning Err just means no live
                    // subscribers — fine, the detection is still cached.
                    for d in &detected {
                        let _ = events_tx.send(d.clone());
                    }
                    let mut s = status.write().await;
                    s.detections.extend(detected);
                }
                Ok(_) => {
                    tracing::trace!(%txid, "gsp session: candidate tx scanned, no match");
                }
                Err(e) => {
                    tracing::debug!(%txid, error = %e, "gsp session: candidate scan error");
                }
            }
        }

        ServerMessage::Pong { .. } => {
            tracing::trace!("gsp session: pong");
        }

        other => {
            tracing::trace!(?other, "gsp session: unhandled push");
        }
    }
}

/// Run the local BIP-352 scanner against one candidate transaction. Returns
/// any detected payments belonging to `keys`.
fn scan_candidate(
    keys: &GhostKeys,
    ephemeral_pubkey_hex: &str,
    outputs: &[CandidateOutput],
    txid: &str,
    block_height: Option<u32>,
) -> Result<Vec<DetectedPayment>, String> {
    use bitcoin::secp256k1::PublicKey;

    let eph_bytes = hex::decode(ephemeral_pubkey_hex).map_err(|e| format!("ephemeral hex: {e}"))?;
    let ephemeral =
        PublicKey::from_slice(&eph_bytes).map_err(|e| format!("ephemeral pubkey: {e}"))?;

    // Decode each x-only (32-byte) output pubkey. Stash the raw x-only bytes
    // for later — BIP-352 output keys are taproot (x-only on chain), so we
    // need to try BOTH parities (0x02 / 0x03) when feeding the scanner,
    // since `PaymentDetector` compares full SEC1 byte equality and only
    // one of the two parities will be the real BIP-352-derived point.
    struct Decoded {
        xonly: [u8; 32],
        amount: Option<u64>,
        vout: u32,
    }
    let mut decoded: Vec<Decoded> = Vec::with_capacity(outputs.len());
    for out in outputs {
        let xonly_bytes =
            hex::decode(&out.output_pubkey).map_err(|e| format!("output hex: {e}"))?;
        if xonly_bytes.len() != 32 {
            return Err(format!(
                "output_pubkey must be 32 bytes (x-only), got {}",
                xonly_bytes.len()
            ));
        }
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&xonly_bytes);
        decoded.push(Decoded {
            xonly,
            amount: out.amount_sats,
            vout: out.vout,
        });
    }

    let detector = PaymentDetector::new(keys);
    let now = now_unix_secs();
    let mut detections: Vec<DetectedPayment> = Vec::new();

    // Scan once with each parity. Dedupe matches by (vout, k) since the same
    // real output can never match under both parities (each x-only key
    // belongs to exactly one curve point with a defined parity).
    for parity in [0x02u8, 0x03u8] {
        let mut scan_inputs: Vec<(PublicKey, Option<u64>)> = Vec::with_capacity(decoded.len());
        for d in &decoded {
            let mut sec1 = [0u8; 33];
            sec1[0] = parity;
            sec1[1..].copy_from_slice(&d.xonly);
            let pk = match PublicKey::from_slice(&sec1) {
                Ok(p) => p,
                Err(_) => {
                    // Off-curve x-only with this parity — skip this input.
                    continue;
                }
            };
            scan_inputs.push((pk, d.amount));
        }
        let scanned = detector.scan_transaction(&ephemeral, &scan_inputs);
        for s in scanned {
            // Map the scanner's slice-index back to our on-chain vout.
            // Note: the slice index can drift if any inputs were skipped above;
            // we only skip on parse failure which should never happen for valid
            // x-only bytes, so this is safe in practice.
            let d = match decoded.get(s.output_index as usize) {
                Some(d) => d,
                None => continue,
            };
            // Dedupe across parities.
            if detections.iter().any(|x| x.vout == d.vout && x.k == s.k) {
                continue;
            }
            detections.push(DetectedPayment {
                txid: txid.to_string(),
                block_height,
                vout: d.vout,
                amount_sats: s.amount,
                k: s.k,
                received_at: now,
            });
        }
    }
    Ok(detections)
}

/// Read frames until we see an `AuthResult`. Drops anything else.
async fn read_until_auth_result(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Result<bool, String> {
    let timeout = tokio::time::sleep(Duration::from_secs(15));
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            _ = &mut timeout => return Err("timeout waiting for AuthResult".into()),
            frame = ws.next() => {
                let frame = frame
                    .ok_or_else(|| "server closed during auth".to_string())?
                    .map_err(|e| format!("ws error during auth: {e}"))?;
                let text = match frame {
                    Message::Text(t) => t,
                    Message::Close(_) => return Err("server closed during auth".into()),
                    _ => continue,
                };
                let parsed: ServerMessage = serde_json::from_str(text.as_ref())
                    .map_err(|e| format!("decoding ServerMessage: {e}"))?;
                match parsed {
                    ServerMessage::AuthResult { success, error, .. } => {
                        if !success {
                            tracing::warn!(error = ?error, "gsp session: auth rejected");
                        }
                        return Ok(success);
                    }
                    // Server may push errors before we authenticate; surface and keep waiting.
                    ServerMessage::Error { message, .. } => {
                        return Err(format!("server error during auth: {message}"));
                    }
                    _ => continue,
                }
            }
        }
    }
}

async fn send_client(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    msg: &ClientMessage,
) -> Result<(), String> {
    let json = serde_json::to_string(msg).map_err(|e| format!("encode: {e}"))?;
    ws.send(Message::Text(json))
        .await
        .map_err(|e| format!("send: {e}"))
}

async fn set_phase(status: &Arc<RwLock<SessionStatus>>, phase: SessionPhase) {
    let mut s = status.write().await;
    s.phase = phase;
}

async fn set_error(status: &Arc<RwLock<SessionStatus>>, phase: SessionPhase, msg: String) {
    let mut s = status.write().await;
    s.phase = phase;
    s.last_error = Some(msg);
}

/// Sleep for `dur`, but return true early if shutdown was signalled.
async fn sleep_or_shutdown(dur: Duration, shutdown: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(dur) => false,
        _ = shutdown.changed() => *shutdown.borrow(),
    }
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end synthetic test: sender constructs a BIP-352 payment to a
    /// receiver's `GhostKeys`, packages it as a `CandidateTransaction`, and
    /// the wallet's `scan_candidate` detects the match.
    #[test]
    fn scan_candidate_detects_synthetic_match() {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        use ghost_keys::{derive_payment_address_v2, derive_shared_secret};
        use rand::RngCore;

        let receiver = GhostKeys::generate();

        // Sender's role: pick a one-shot ephemeral keypair (in real BIP-352
        // this is derived from the input set; the scanner only sees the pubkey).
        let secp = Secp256k1::new();
        let mut eph_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut eph_bytes);
        let eph_secret = SecretKey::from_slice(&eph_bytes).expect("nonzero scalar");
        let ephemeral_pub = PublicKey::from_secret_key(&secp, &eph_secret);

        // Both sides compute the same shared secret via ECDH (commutativity).
        // Sender side: ECDH(eph_secret, receiver.scan_pubkey).
        let shared_secret = derive_shared_secret(&eph_secret, receiver.scan_pubkey());

        // Sender derives the destination output pubkey at index k=0.
        let k: u32 = 0;
        let (output_pubkey, _tweak) =
            derive_payment_address_v2(receiver.spend_pubkey(), &shared_secret, k)
                .expect("derive output pubkey");

        // On chain we'd see the x-only form (taproot output).
        let serialized = output_pubkey.serialize();
        let xonly = &serialized[1..];

        let candidate_outputs = vec![CandidateOutput {
            output_pubkey: hex::encode(xonly),
            amount_sats: Some(50_000),
            vout: 7,
        }];

        let txid = "0".repeat(64);
        let detections = scan_candidate(
            &receiver,
            &hex::encode(ephemeral_pub.serialize()),
            &candidate_outputs,
            &txid,
            Some(123_456),
        )
        .expect("scan succeeds");

        assert_eq!(detections.len(), 1, "expected one match");
        let det = &detections[0];
        assert_eq!(det.k, k);
        assert_eq!(det.amount_sats, Some(50_000));
        assert_eq!(det.vout, 7);
        assert_eq!(det.block_height, Some(123_456));
        assert_eq!(det.txid, txid);
    }

    #[test]
    fn scan_candidate_returns_empty_on_no_match() {
        use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
        use rand::RngCore;

        let receiver = GhostKeys::generate();

        let secp = Secp256k1::new();
        let mut eph_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut eph_bytes);
        let eph_secret = SecretKey::from_slice(&eph_bytes).unwrap();
        let ephemeral_pub = PublicKey::from_secret_key(&secp, &eph_secret);

        // Output addressed to a DIFFERENT receiver — should not match.
        let other = GhostKeys::generate();
        let mut other_eph_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut other_eph_bytes);
        let other_eph_secret = SecretKey::from_slice(&other_eph_bytes).unwrap();
        let shared_secret =
            ghost_keys::derive_shared_secret(&other_eph_secret, other.scan_pubkey());
        let (output_pubkey, _tweak) =
            ghost_keys::derive_payment_address_v2(other.spend_pubkey(), &shared_secret, 0).unwrap();
        let serialized = output_pubkey.serialize();
        let xonly = &serialized[1..];

        let candidate_outputs = vec![CandidateOutput {
            output_pubkey: hex::encode(xonly),
            amount_sats: Some(1_000),
            vout: 0,
        }];

        let detections = scan_candidate(
            &receiver,
            &hex::encode(ephemeral_pub.serialize()),
            &candidate_outputs,
            "deadbeef",
            None,
        )
        .expect("scan succeeds");

        assert!(
            detections.is_empty(),
            "no match expected, got {:?}",
            detections
        );
    }
}
