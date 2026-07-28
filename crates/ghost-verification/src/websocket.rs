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
//| FILE: websocket.rs                                                                                                   |
//|======================================================================================================================|

//! WebSocket support for real-time dashboard updates
//!
//! Provides a WebSocket endpoint at `/ws` that streams live events:
//! - Miner connections/disconnections
//! - Share submissions
//! - Block found notifications
//! - Peer status changes
//! - Consensus voting updates
//! - System metrics
//!
//! ## AUTH4-M3: WebSocket Authentication
//!
//! Two modes are supported:
//! - **Public mode** (default): Limited events (health updates, block found)
//! - **Authenticated mode**: All events including sensitive operational data
//!
//! To authenticate, pass query parameters:
//! - `node_id`: Your node's public key (hex-encoded)
//! - `timestamp`: Unix timestamp of request
//! - `signature`: HMAC-SHA256 signature of `node_id|timestamp` with shared secret
//!
//! ## VF-C1: HMAC Verification
//!
//! WebSocket authentication uses HMAC-SHA256 with constant-time comparison
//! to prevent timing attacks. The signature is computed as:
//! `HMAC-SHA256(secret, node_id_bytes || timestamp_le_bytes)`

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

/// HMAC-SHA256 type alias for WebSocket auth
type HmacSha256 = Hmac<Sha256>;

/// Maximum timestamp drift allowed for WebSocket auth (5 minutes)
const WS_MAX_TIMESTAMP_DRIFT_SECS: u64 = 300;

/// WebSocket event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", content = "data")]
pub enum WsEvent {
    /// Miner connected to pool
    MinerConnected { miner_id: String, address: String },
    /// Miner disconnected from pool
    MinerDisconnected { miner_id: String },
    /// Share submitted by miner
    ShareSubmitted {
        miner_id: String,
        difficulty: f64,
        valid: bool,
    },
    /// Block found
    BlockFound {
        height: u64,
        hash: String,
        miner_id: String,
    },
    /// New round started
    RoundStarted { round_id: u64, height: u64 },
    /// Round ended
    RoundEnded {
        round_id: u64,
        total_shares: u64,
        miner_count: u32,
    },
    /// Peer connected
    PeerConnected { peer_id: String, address: String },
    /// Peer disconnected
    PeerDisconnected { peer_id: String },
    /// Consensus vote received
    ConsensusVote {
        proposal_id: String,
        voter_id: String,
        approved: bool,
    },
    /// Consensus reached
    ConsensusReached {
        proposal_id: String,
        approved: bool,
        vote_count: u32,
    },
    /// Wraith session update
    WraithSessionUpdate {
        session_id: String,
        phase: String,
        participants: u32,
    },
    /// Health metrics update (sent periodically)
    HealthUpdate {
        block_height: u64,
        round_id: u64,
        miner_count: u32,
        peer_count: u32,
        uptime_secs: u64,
    },
    /// Error event
    Error { message: String },
}

impl WsEvent {
    /// AUTH4-M3: Check if this event is allowed for unauthenticated connections
    ///
    /// Public events are safe to broadcast to anyone (no sensitive info).
    /// Sensitive events (shares, votes, wraith, peer details) require auth.
    /// Events an UNAUTHENTICATED subscriber may receive.
    ///
    /// `BlockFound` was on this list and is not any more: it carries `miner_id`, the exact
    /// value `redact_miner_id` and the M-11/M-13 work exist to keep off public responses.
    /// Publishing it on a socket while redacting it on every REST route would have undone
    /// that the first time a block was found.
    ///
    /// It was latent rather than live — nothing constructs `BlockFound` outside tests today,
    /// so no such event has ever been broadcast. That is a property of current callers, not
    /// of the allowlist, and it is the wrong thing to rely on.
    pub fn is_public(&self) -> bool {
        matches!(
            self,
            WsEvent::HealthUpdate { .. }
                | WsEvent::RoundStarted { .. }
                | WsEvent::RoundEnded { .. }
                | WsEvent::Error { .. }
        )
    }
}

/// AUTH4-M3: WebSocket authentication query parameters
#[derive(Debug, Clone, Deserialize, Default)]
pub struct WsAuthQuery {
    /// Node ID (hex-encoded 64 chars = 32 bytes)
    pub node_id: Option<String>,
    /// Unix timestamp of request
    pub timestamp: Option<u64>,
    /// Signature of "node_id|timestamp" for authentication
    pub signature: Option<String>,
}

impl WsAuthQuery {
    /// Check if authentication parameters are present
    pub fn has_auth(&self) -> bool {
        self.node_id.is_some() && self.timestamp.is_some() && self.signature.is_some()
    }

    /// VF-C1: Validate the authentication parameters with HMAC verification
    ///
    /// When a secret is provided, performs full HMAC-SHA256 verification:
    /// - Node ID must be 64 hex chars (32 bytes)
    /// - Timestamp must be within 5 minutes of server time (replay prevention)
    /// - Signature must be valid HMAC-SHA256(secret, node_id_bytes || timestamp_le_bytes)
    ///
    /// Uses constant-time comparison to prevent timing attacks.
    pub fn validate_with_secret(&self, secret: &[u8; 32]) -> bool {
        // Check node_id format (64 hex chars = 32 bytes)
        let node_id = match &self.node_id {
            Some(id) if id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()) => id,
            _ => return false,
        };

        // Decode node_id to bytes
        let node_id_bytes = match hex::decode(node_id) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        // Check timestamp is recent (within 5 minutes)
        let timestamp = match self.timestamp {
            Some(ts) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let diff = ts.abs_diff(now);
                if diff >= WS_MAX_TIMESTAMP_DRIFT_SECS {
                    return false;
                }
                ts
            }
            None => return false,
        };

        // Check signature format and decode
        let signature_bytes = match &self.signature {
            Some(sig) if sig.len() == 64 => match hex::decode(sig) {
                Ok(bytes) => bytes,
                Err(_) => return false,
            },
            _ => return false,
        };

        // Compute expected HMAC: HMAC-SHA256(secret, node_id_bytes || timestamp_le_bytes)
        let mut mac = match HmacSha256::new_from_slice(secret) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mac.update(&node_id_bytes);
        mac.update(&timestamp.to_le_bytes());
        let expected = mac.finalize().into_bytes();

        // Constant-time comparison to prevent timing attacks
        constant_time_eq(&expected, &signature_bytes)
    }

    /// Basic format validation (for when no secret is configured)
    ///
    /// Only checks format, not cryptographic validity. Use validate_with_secret()
    /// for production authentication.
    pub fn validate_format_only(&self) -> bool {
        // Check node_id format (64 hex chars)
        let valid_node_id = self
            .node_id
            .as_ref()
            .map(|id| id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()))
            .unwrap_or(false);

        // Check timestamp is recent (within 5 minutes)
        let valid_timestamp = self
            .timestamp
            .map(|ts| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let diff = ts.abs_diff(now);
                diff < WS_MAX_TIMESTAMP_DRIFT_SECS
            })
            .unwrap_or(false);

        // Check signature is present and correct length (64 hex chars = 32 bytes)
        let valid_signature = self
            .signature
            .as_ref()
            .map(|sig| sig.len() == 64 && sig.chars().all(|c| c.is_ascii_hexdigit()))
            .unwrap_or(false);

        valid_node_id && valid_timestamp && valid_signature
    }
}

/// Constant-time byte comparison to prevent timing attacks (VF-C1)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// WebSocket state for managing connections
pub struct WsState {
    /// Broadcast channel for events
    pub tx: broadcast::Sender<WsEvent>,
    /// VF-C1: Optional auth secret for HMAC verification
    /// When Some, WebSocket authentication uses HMAC-SHA256 verification
    auth_secret: Option<[u8; 32]>,
    /// VF-C1: Whether to require authentication (reject unauthenticated connections)
    require_auth: bool,
    /// L-30 FIX: Whether running on mainnet (blocks format-only validation fallback)
    is_mainnet: bool,
    /// Restrict this stream to loopback callers.
    ///
    /// The node's own dashboard reaches the backend over 127.0.0.1 and relays to browsers
    /// behind its own session auth, so loopback is all this stream needs to serve. Defaults
    /// to true: the listener binds 0.0.0.0 for the public REST API, and without this the
    /// event stream is reachable by anyone who can reach the port.
    loopback_only: bool,
}

impl WsState {
    /// Create new WebSocket state without authentication
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1000);
        Self {
            tx,
            auth_secret: None,
            require_auth: false,
            is_mainnet: false,
            loopback_only: true,
        }
    }

    /// Whether this stream only serves loopback callers.
    pub fn loopback_only(&self) -> bool {
        self.loopback_only
    }

    /// Allow non-loopback callers. Opt-in, for a deployment that genuinely terminates the
    /// relay off-box; the caller takes on providing an auth boundary in front of it.
    pub fn allow_remote(mut self) -> Self {
        self.loopback_only = false;
        self
    }

    /// Create new WebSocket state with HMAC authentication (VF-C1)
    ///
    /// When auth_secret is provided, WebSocket authentication verifies
    /// HMAC-SHA256 signatures. If require_auth is true, unauthenticated
    /// connections are rejected entirely.
    pub fn with_auth(secret: [u8; 32], require_auth: bool) -> Self {
        let (tx, _) = broadcast::channel(1000);
        Self {
            tx,
            auth_secret: Some(secret),
            require_auth,
            is_mainnet: false,
            loopback_only: true,
        }
    }

    /// HIGH-API-2: Create new WebSocket state with mandatory authentication
    ///
    /// Authentication is REQUIRED on all networks to prevent bugs in auth integration
    /// from being masked on non-mainnet environments.
    ///
    /// This method replaces the previous `mainnet()` method and is now used for all networks.
    pub fn with_required_auth(secret: [u8; 32], is_mainnet: bool) -> Self {
        let (tx, _) = broadcast::channel(1000);
        Self {
            tx,
            auth_secret: Some(secret),
            require_auth: true, // Always required on all networks (HIGH-API-2)
            is_mainnet,
            loopback_only: true,
        }
    }

    /// L-30 FIX: Create new WebSocket state for mainnet with mandatory authentication
    ///
    /// DEPRECATED: Use `with_required_auth()` instead.
    /// On mainnet, auth_secret is REQUIRED. Format-only validation fallback is blocked.
    /// This prevents accepting unauthenticated connections that could be exploited.
    ///
    /// # Panics
    /// Panics if auth_secret is not provided for mainnet. This is intentional to
    /// prevent accidental deployment without proper authentication configuration.
    #[deprecated(note = "Use with_required_auth() instead - auth now required on all networks")]
    pub fn mainnet(secret: [u8; 32]) -> Self {
        Self::with_required_auth(secret, true)
    }

    /// Get the auth secret if configured
    pub fn auth_secret(&self) -> Option<&[u8; 32]> {
        self.auth_secret.as_ref()
    }

    /// Check if authentication is required
    pub fn requires_auth(&self) -> bool {
        self.require_auth
    }

    /// L-30 FIX: Check if running on mainnet
    pub fn is_mainnet(&self) -> bool {
        self.is_mainnet
    }

    /// Get a receiver for events
    pub fn subscribe(&self) -> broadcast::Receiver<WsEvent> {
        self.tx.subscribe()
    }

    /// Broadcast an event to all connected clients
    ///
    /// AUTH4-L4: Monitors broadcast failures and logs dropped events.
    /// This provides backpressure awareness without requiring the metrics crate.
    pub fn broadcast(&self, event: WsEvent) {
        // Check subscriber count first to distinguish "no subscribers" from "buffer full"
        let subscriber_count = self.tx.receiver_count();

        if subscriber_count == 0 {
            // No subscribers - silently drop (this is expected when no clients connected)
            return;
        }

        match self.tx.send(event) {
            Ok(sent_to) => {
                debug!(subscribers = sent_to, "WebSocket event broadcast");
            }
            Err(_) => {
                // Buffer is full with active subscribers - this is actual backpressure
                warn!(
                    subscribers = subscriber_count,
                    "WebSocket broadcast buffer overflow - event dropped"
                );
            }
        }
    }
}

impl Default for WsState {
    fn default() -> Self {
        Self::new()
    }
}

/// AUTH4-M3 / VF-C1: WebSocket upgrade handler with HMAC authentication support
///
/// Query parameters:
/// - `node_id`: Optional node identifier for authenticated access (64 hex chars)
/// - `timestamp`: Unix timestamp of request (must be within 5 minutes)
/// - `signature`: HMAC-SHA256 signature for authentication (64 hex chars)
///
/// Authentication behavior:
/// - If WsState has auth_secret: validates HMAC-SHA256 signature cryptographically
/// - If WsState requires auth but client doesn't authenticate: connection rejected
/// - Unauthenticated connections only receive public events
/// - Authenticated connections receive all events
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    peer: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    Query(auth): Query<WsAuthQuery>,
    State(ws_state): State<Arc<WsState>>,
) -> axum::response::Response {
    // Refuse non-loopback callers before completing the upgrade, so a remote client never
    // reaches the stream at all rather than being handed a socket and then closed.
    //
    // The peer address comes from ConnectInfo — the real TCP socket source injected by
    // `into_make_service_with_connect_info` — and NEVER from a request header, which a remote
    // client fully controls. `rate_limit_middleware` already establishes that precedent and
    // spells out why: matching X-Forwarded-For here would let anyone forge their way in.
    //
    // Absent ConnectInfo we refuse rather than allow. That only happens in test servers built
    // without connect info, and failing closed on an unknown peer is the right default for a
    // stream that is otherwise unauthenticated.
    if ws_state.loopback_only() {
        let is_loopback = peer.as_ref().map(|ci| ci.0.ip().is_loopback());
        if is_loopback != Some(true) {
            match peer.as_ref() {
                Some(ci) => warn!(peer = %ci.0.ip(), "WebSocket connection refused: non-loopback"),
                None => warn!("WebSocket connection refused: peer address unavailable"),
            }
            return (
                axum::http::StatusCode::FORBIDDEN,
                "this endpoint serves loopback callers only",
            )
                .into_response();
        }
    }

    // VF-C1: Check if authentication is required but not provided
    if ws_state.requires_auth() && !auth.has_auth() {
        warn!("WebSocket connection rejected: authentication required");
        return ws.on_upgrade(|socket| async move {
            // Immediately close the socket with an error
            let (mut sender, _) = socket.split();
            let error = WsEvent::Error {
                message: "Authentication required".to_string(),
            };
            if let Ok(json) = serde_json::to_string(&error) {
                let _ = sender.send(Message::Text(json)).await;
            }
            let _ = sender.send(Message::Close(None)).await;
        });
    }

    // Validate authentication if provided
    let authenticated = if auth.has_auth() {
        // VF-C1: Use HMAC verification when secret is configured
        let valid = if let Some(secret) = ws_state.auth_secret() {
            auth.validate_with_secret(secret)
        } else {
            // M-15: ALWAYS require cryptographic validation - no format-only fallback on ANY network
            // Format-only validation provides no security guarantees and must never be used.
            // If auth is attempted without a configured secret, reject the connection.
            error!("M-15 SECURITY: WebSocket auth secret not configured - rejecting authenticated connection");
            return ws.on_upgrade(|socket| async move {
                let (mut sender, _) = socket.split();
                let error = WsEvent::Error {
                    message: "Server misconfigured: ws_auth_secret must be configured for authenticated connections".to_string(),
                };
                if let Ok(json) = serde_json::to_string(&error) {
                    let _ = sender.send(Message::Text(json)).await;
                }
                let _ = sender.send(Message::Close(None)).await;
            });
        };

        if valid {
            info!(
                node_id = ?auth.node_id.as_ref().map(|id| &id[..16]),
                "WebSocket client authenticated"
            );
            true
        } else {
            warn!(
                node_id = ?auth.node_id.as_ref().map(|id| &id[..16]),
                "WebSocket authentication failed"
            );
            // VF-C1: If auth is required and validation fails, reject entirely
            if ws_state.requires_auth() {
                return ws.on_upgrade(|socket| async move {
                    let (mut sender, _) = socket.split();
                    let error = WsEvent::Error {
                        message: "Authentication failed".to_string(),
                    };
                    if let Ok(json) = serde_json::to_string(&error) {
                        let _ = sender.send(Message::Text(json)).await;
                    }
                    let _ = sender.send(Message::Close(None)).await;
                });
            }
            // Auth not required - fall back to public mode
            false
        }
    } else {
        debug!("WebSocket client connected without authentication (public mode)");
        false
    };

    ws.on_upgrade(move |socket| handle_socket(socket, ws_state, authenticated))
}

/// Handle individual WebSocket connection
///
/// AUTH4-M3: If not authenticated, only public events are forwarded.
async fn handle_socket(socket: WebSocket, ws_state: Arc<WsState>, authenticated: bool) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = ws_state.subscribe();

    info!(authenticated, "WebSocket client connected");

    // Spawn task to forward broadcast events to this client
    // AUTH4-M3: Filter events based on authentication status
    let mut send_task = tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            // Skip non-public events for unauthenticated connections
            if !authenticated && !event.is_public() {
                continue;
            }

            match serde_json::to_string(&event) {
                Ok(json) => {
                    if sender.send(Message::Text(json)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to serialize event: {}", e);
                }
            }
        }
    });

    // Handle incoming messages (ping/pong, close, or commands)
    let mut recv_task = tokio::spawn(async move {
        while let Some(result) = receiver.next().await {
            match result {
                Ok(Message::Text(text)) => {
                    debug!("Received WebSocket message: {}", text);
                    // Could handle client commands here if needed
                }
                Ok(Message::Ping(data)) => {
                    debug!("Received ping");
                    // Pong is automatically sent by axum
                    let _ = data;
                }
                Ok(Message::Pong(_)) => {
                    debug!("Received pong");
                }
                Ok(Message::Close(_)) => {
                    debug!("Client sent close");
                    break;
                }
                Ok(Message::Binary(_)) => {
                    // Ignore binary messages
                }
                Err(e) => {
                    warn!("WebSocket error: {}", e);
                    break;
                }
            }
        }
    });

    // Wait for either task to complete
    tokio::select! {
        _ = &mut send_task => {
            recv_task.abort();
        }
        _ = &mut recv_task => {
            send_task.abort();
        }
    }

    info!("WebSocket client disconnected");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_serialization() {
        let event = WsEvent::MinerConnected {
            miner_id: "abc123".to_string(),
            address: "192.168.1.1:3333".to_string(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("MinerConnected"));
        assert!(json.contains("abc123"));
    }

    #[test]
    fn test_ws_state_broadcast() {
        let state = WsState::new();
        let mut rx = state.subscribe();

        state.broadcast(WsEvent::BlockFound {
            height: 12345,
            hash: "00000abc".to_string(),
            miner_id: "miner1".to_string(),
        });

        let event = rx.try_recv().unwrap();
        match event {
            WsEvent::BlockFound { height, .. } => assert_eq!(height, 12345),
            _ => panic!("Wrong event type"),
        }
    }

    // VF-C1: HMAC verification tests

    fn create_test_secret() -> [u8; 32] {
        [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ]
    }

    fn create_valid_auth(secret: &[u8; 32]) -> WsAuthQuery {
        let node_id_bytes = [0xab; 32];
        let node_id = hex::encode(node_id_bytes);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Compute valid HMAC
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(&node_id_bytes);
        mac.update(&timestamp.to_le_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        WsAuthQuery {
            node_id: Some(node_id),
            timestamp: Some(timestamp),
            signature: Some(signature),
        }
    }

    #[test]
    fn test_hmac_verification_valid() {
        let secret = create_test_secret();
        let auth = create_valid_auth(&secret);

        assert!(auth.has_auth());
        assert!(auth.validate_with_secret(&secret));
    }

    #[test]
    fn test_hmac_verification_invalid_signature() {
        let secret = create_test_secret();
        let mut auth = create_valid_auth(&secret);

        // Corrupt the signature
        auth.signature = Some("00".repeat(32)); // Wrong signature

        assert!(auth.has_auth());
        assert!(!auth.validate_with_secret(&secret));
    }

    #[test]
    fn test_hmac_verification_wrong_secret() {
        let secret = create_test_secret();
        let auth = create_valid_auth(&secret);

        // Use different secret
        let wrong_secret = [0xff; 32];
        assert!(!auth.validate_with_secret(&wrong_secret));
    }

    #[test]
    fn test_hmac_verification_expired_timestamp() {
        let secret = create_test_secret();
        let node_id_bytes = [0xab; 32];
        let node_id = hex::encode(node_id_bytes);

        // Timestamp 10 minutes ago (exceeds 5 minute drift)
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 600;

        let mut mac = HmacSha256::new_from_slice(&secret).unwrap();
        mac.update(&node_id_bytes);
        mac.update(&timestamp.to_le_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        let auth = WsAuthQuery {
            node_id: Some(node_id),
            timestamp: Some(timestamp),
            signature: Some(signature),
        };

        assert!(!auth.validate_with_secret(&secret));
    }

    #[test]
    fn test_hmac_verification_future_timestamp() {
        let secret = create_test_secret();
        let node_id_bytes = [0xab; 32];
        let node_id = hex::encode(node_id_bytes);

        // Timestamp 10 minutes in future (exceeds 5 minute drift)
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;

        let mut mac = HmacSha256::new_from_slice(&secret).unwrap();
        mac.update(&node_id_bytes);
        mac.update(&timestamp.to_le_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        let auth = WsAuthQuery {
            node_id: Some(node_id),
            timestamp: Some(timestamp),
            signature: Some(signature),
        };

        assert!(!auth.validate_with_secret(&secret));
    }

    #[test]
    fn test_hmac_verification_invalid_node_id_format() {
        let secret = create_test_secret();

        // Too short
        let auth = WsAuthQuery {
            node_id: Some("abc".to_string()),
            timestamp: Some(12345),
            signature: Some("00".repeat(32)),
        };
        assert!(!auth.validate_with_secret(&secret));

        // Non-hex characters
        let auth = WsAuthQuery {
            node_id: Some("zz".repeat(32)),
            timestamp: Some(12345),
            signature: Some("00".repeat(32)),
        };
        assert!(!auth.validate_with_secret(&secret));
    }

    #[test]
    fn test_hmac_verification_invalid_signature_format() {
        let secret = create_test_secret();
        let node_id = "ab".repeat(32);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Too short signature
        let auth = WsAuthQuery {
            node_id: Some(node_id.clone()),
            timestamp: Some(timestamp),
            signature: Some("abc".to_string()),
        };
        assert!(!auth.validate_with_secret(&secret));

        // Non-hex signature
        let auth = WsAuthQuery {
            node_id: Some(node_id),
            timestamp: Some(timestamp),
            signature: Some("zz".repeat(32)),
        };
        assert!(!auth.validate_with_secret(&secret));
    }

    #[test]
    fn test_hmac_verification_missing_fields() {
        let secret = create_test_secret();

        // Missing node_id
        let auth = WsAuthQuery {
            node_id: None,
            timestamp: Some(12345),
            signature: Some("00".repeat(32)),
        };
        assert!(!auth.has_auth());
        assert!(!auth.validate_with_secret(&secret));

        // Missing timestamp
        let auth = WsAuthQuery {
            node_id: Some("ab".repeat(32)),
            timestamp: None,
            signature: Some("00".repeat(32)),
        };
        assert!(!auth.has_auth());
        assert!(!auth.validate_with_secret(&secret));

        // Missing signature
        let auth = WsAuthQuery {
            node_id: Some("ab".repeat(32)),
            timestamp: Some(12345),
            signature: None,
        };
        assert!(!auth.has_auth());
        assert!(!auth.validate_with_secret(&secret));
    }

    #[test]
    fn test_format_only_validation() {
        let node_id = "ab".repeat(32);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let auth = WsAuthQuery {
            node_id: Some(node_id),
            timestamp: Some(timestamp),
            signature: Some("00".repeat(32)), // Any valid format
        };

        assert!(auth.validate_format_only());
    }

    #[test]
    fn test_format_only_rejects_bad_format() {
        // Invalid node_id format
        let auth = WsAuthQuery {
            node_id: Some("short".to_string()),
            timestamp: Some(12345),
            signature: Some("00".repeat(32)),
        };
        assert!(!auth.validate_format_only());

        // Expired timestamp
        let auth = WsAuthQuery {
            node_id: Some("ab".repeat(32)),
            timestamp: Some(1), // Way in the past
            signature: Some("00".repeat(32)),
        };
        assert!(!auth.validate_format_only());
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];
        let d = [1u8, 2, 3];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &d)); // Different lengths
    }

    #[test]
    fn test_ws_state_with_auth() {
        let secret = create_test_secret();
        let state = WsState::with_auth(secret, true);

        assert!(state.requires_auth());
        assert_eq!(state.auth_secret(), Some(&secret));
        assert!(!state.is_mainnet());
    }

    #[test]
    fn test_ws_state_without_auth() {
        let state = WsState::new();

        assert!(!state.requires_auth());
        assert!(state.auth_secret().is_none());
        assert!(!state.is_mainnet());
    }

    #[test]
    fn test_ws_state_mainnet() {
        // L-30 FIX: Test mainnet configuration
        let secret = create_test_secret();
        let state = WsState::with_required_auth(secret, true);

        assert!(state.requires_auth());
        assert_eq!(state.auth_secret(), Some(&secret));
        assert!(state.is_mainnet());
    }

    #[test]
    fn test_event_is_public() {
        // Public events
        assert!(WsEvent::HealthUpdate {
            block_height: 1,
            round_id: 1,
            miner_count: 1,
            peer_count: 1,
            uptime_secs: 1,
        }
        .is_public());
        // BlockFound is NOT public: it carries `miner_id`. This assertion was the other way
        // round, which is how the leak survived — the allowlist and its test agreed with each
        // other and disagreed with `redact_miner_id` everywhere else.
        assert!(
            !WsEvent::BlockFound {
                height: 1,
                hash: "".to_string(),
                miner_id: "".to_string(),
            }
            .is_public(),
            "BlockFound carries miner_id and must not reach an unauthenticated subscriber"
        );
        assert!(WsEvent::RoundStarted {
            round_id: 1,
            height: 1
        }
        .is_public());
        assert!(WsEvent::Error {
            message: "".to_string()
        }
        .is_public());

        // Private events
        assert!(!WsEvent::MinerConnected {
            miner_id: "".to_string(),
            address: "".to_string(),
        }
        .is_public());
        assert!(!WsEvent::ShareSubmitted {
            miner_id: "".to_string(),
            difficulty: 1.0,
            valid: true,
        }
        .is_public());
        assert!(!WsEvent::ConsensusVote {
            proposal_id: "".to_string(),
            voter_id: "".to_string(),
            approved: true,
        }
        .is_public());
        assert!(!WsEvent::WraithSessionUpdate {
            session_id: "".to_string(),
            phase: "".to_string(),
            participants: 0,
        }
        .is_public());
    }

    /// The event stream is reachable on the same listener as the public REST API, which binds
    /// 0.0.0.0. Its own auth is optional and off by default, so the loopback restriction is the
    /// only thing standing between a remote caller and the stream. Assert both directions, and
    /// that an unknown peer fails CLOSED rather than open.
    #[test]
    fn stream_defaults_to_loopback_only_and_fails_closed() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

        // Secure by default on every constructor, not just the plain one.
        assert!(WsState::new().loopback_only());
        assert!(WsState::with_auth([7u8; 32], false).loopback_only());
        assert!(WsState::with_required_auth([7u8; 32], true).loopback_only());

        // The decision the handler makes, expressed the same way: Some(true) admits,
        // everything else refuses. `None` models a peer address we could not determine.
        let admits = |ip: Option<IpAddr>| ip.map(|i| i.is_loopback()) == Some(true);

        assert!(admits(Some(IpAddr::V4(Ipv4Addr::LOCALHOST))));
        assert!(admits(Some(IpAddr::V6(Ipv6Addr::LOCALHOST))));
        assert!(admits(Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)))));

        // Anything routable is refused, including addresses that merely look internal.
        for ip in [
            Ipv4Addr::new(77, 22, 112, 180), // a real external caller seen on the port
            Ipv4Addr::new(192, 168, 1, 10),  // LAN is not loopback
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(0, 0, 0, 0),
        ] {
            assert!(!admits(Some(IpAddr::V4(ip))), "must refuse {ip}");
        }

        // Unknown peer must fail closed.
        assert!(
            !admits(None),
            "an undeterminable peer must be refused, not admitted"
        );

        // And the opt-out is available for a deployment that knowingly needs it.
        assert!(!WsState::new().allow_remote().loopback_only());
    }
}
