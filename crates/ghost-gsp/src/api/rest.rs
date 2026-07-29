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
//| FILE: api/rest.rs                                                                                                    |
//|======================================================================================================================|

//! REST API handlers

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, State},
    http::HeaderMap,
    Json,
};
use tracing::{info, warn};

use ghost_gsp_proto::{
    RegisterRequest, RegisterResponse, SessionRequest, SessionResponse, PROTOCOL_VERSION,
};

use crate::error::{GspError, GspResult};
use crate::server::GspState;
use crate::GSP_VERSION;

/// Health check response
#[derive(serde::Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
}

/// PAY-2 FIX: Extract client IP from request with trusted proxy validation.
///
/// Attempts to get the real client IP in this order:
/// 1. X-Forwarded-For header (only if peer is trusted proxy)
/// 2. X-Real-IP header (only if peer is trusted proxy)
/// 3. ConnectInfo (direct peer address)
///
/// SECURITY: X-Forwarded-For and X-Real-IP headers are ONLY trusted when the
/// direct peer IP is in the configured trusted_proxy_ips list. This prevents
/// IP spoofing attacks where attackers set fake headers to bypass rate limiting
/// or logging.
///
/// # Multi-Proxy Chain Support
///
/// When behind multiple proxies (e.g., CDN -> LB -> App), configure
/// `trusted_proxy_count` to match your infrastructure:
/// - X-Forwarded-For format: "client, proxy1, proxy2, ..."
/// - With `trusted_proxy_count=2`: Skip last 2 entries, use client IP
///
/// # Arguments
/// * `headers` - HTTP request headers
/// * `connect_info` - Direct peer connection info
/// * `state` - Server state containing trusted proxy configuration
fn get_client_ip(
    headers: &HeaderMap,
    connect_info: Option<&ConnectInfo<SocketAddr>>,
    state: &GspState,
) -> Option<String> {
    // Get peer IP for trust validation
    let peer_ip = connect_info.map(|ci| ci.0.ip());

    // PAY-2: Only trust proxy headers if peer is a configured trusted proxy
    let trust_proxy_headers = peer_ip
        .as_ref()
        .map(|ip| state.is_trusted_proxy(ip))
        .unwrap_or(false);

    if trust_proxy_headers {
        // Try X-Forwarded-For with multi-proxy chain support
        // Format: "client, proxy1, proxy2, ..." (left to right, appended by each proxy)
        // With N trusted proxies, skip the rightmost N entries and take the next one.
        if let Some(xff) = headers.get("X-Forwarded-For") {
            if let Ok(xff_str) = xff.to_str() {
                let ips: Vec<&str> = xff_str.split(',').map(|s| s.trim()).collect();
                let proxy_count = state.trusted_proxy_count();

                // Calculate correct index based on proxy count
                if ips.len() > proxy_count {
                    let client_index = ips.len() - 1 - proxy_count;
                    let client_ip = ips[client_index];
                    if !client_ip.is_empty() {
                        return Some(client_ip.to_string());
                    }
                } else if !ips.is_empty() {
                    // Not enough IPs in chain, take the first (client)
                    let client_ip = ips[0];
                    if !client_ip.is_empty() {
                        return Some(client_ip.to_string());
                    }
                }
            }
        }

        // Try X-Real-IP header (nginx convention)
        // This is typically set by the proxy to the actual client IP
        if let Some(xri) = headers.get("X-Real-IP") {
            if let Ok(ip_str) = xri.to_str() {
                return Some(ip_str.to_string());
            }
        }
    } else if peer_ip.is_some() {
        // PAY-2: Log when proxy headers are ignored due to untrusted peer
        if headers.get("X-Forwarded-For").is_some() || headers.get("X-Real-IP").is_some() {
            warn!(
                peer_ip = ?peer_ip,
                "PAY-2: Ignoring X-Forwarded-For/X-Real-IP from untrusted peer"
            );
        }
    }

    // Fall back to peer IP
    peer_ip.map(|ip| ip.to_string())
}

/// Health check handler
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: GSP_VERSION,
    })
}

/// GSP info response
#[derive(serde::Serialize)]
pub struct InfoResponse {
    pub version: &'static str,
    pub protocol_version: &'static str,
    pub network: String,
    pub sync_status: String,
    pub connections: usize,
}

/// GSP info handler
pub async fn info(State(state): State<Arc<GspState>>) -> Json<InfoResponse> {
    let connections = state.connection_count();

    // Check pay node connectivity
    let sync_status = match state.pay_node.health_check().await {
        Ok(true) => "synced".to_string(),
        Ok(false) => "syncing".to_string(),
        Err(_) => "disconnected".to_string(),
    };

    Json(InfoResponse {
        version: GSP_VERSION,
        protocol_version: PROTOCOL_VERSION,
        network: format!("{:?}", state.config.network),
        sync_status,
        connections,
    })
}

/// Register a new wallet
///
/// CRIT-AUTH-4: Accepts ConnectInfo for IP extraction and logging.
/// PAY-2: Uses trusted proxy validation for X-Forwarded-For.
pub async fn register(
    State(state): State<Arc<GspState>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> GspResult<Json<RegisterResponse>> {
    // CRIT-AUTH-4/PAY-2: Log client IP for audit trail (with trusted proxy validation)
    let client_ip = get_client_ip(&headers, connect_info.as_ref(), &state);
    if let Some(ref ip) = client_ip {
        info!(client_ip = %ip, "Processing wallet registration request");
    }
    // Validate proof structure
    req.proof
        .validate_structure()
        .map_err(|e| GspError::BadRequest(format!("Invalid proof: {}", e)))?;

    // Check timestamp
    if !req.proof.is_timestamp_valid() {
        return Err(GspError::BadRequest(
            "Proof timestamp out of range".to_string(),
        ));
    }

    // Verify action
    if req.proof.action() != Some("register") {
        return Err(GspError::BadRequest("Invalid proof action".to_string()));
    }

    // Get wallet ID
    let wallet_id = req
        .proof
        .wallet_id()
        .map_err(|e| GspError::BadRequest(format!("Invalid wallet ID: {}", e)))?;

    // Check if already registered
    if state.registry.is_registered(&wallet_id)? {
        return Err(GspError::WalletAlreadyRegistered);
    }

    // Get public key bytes
    let pubkey = req
        .proof
        .public_key_bytes()
        .map_err(|e| GspError::BadRequest(format!("Invalid public key: {}", e)))?;

    // Verify signature
    state.registry.verify_proof(&req.proof)?;

    // Register wallet
    state
        .registry
        .register(&wallet_id, &pubkey, req.display_name.as_deref())?;

    info!(wallet_id = %wallet_id, "Wallet registered");

    Ok(Json(RegisterResponse {
        success: true,
        wallet_id: Some(wallet_id),
        error: None,
    }))
}

/// Create a new session
///
/// CRIT-AUTH-3: Session tokens are now bound to the client IP address.
/// CRIT-AUTH-4: Extracts client IP from ConnectInfo or X-Forwarded-For header.
/// PAY-2: Uses trusted proxy validation for X-Forwarded-For.
pub async fn create_session(
    State(state): State<Arc<GspState>>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(req): Json<SessionRequest>,
) -> GspResult<Json<SessionResponse>> {
    // CRIT-AUTH-4/PAY-2: Extract client IP for session binding (with trusted proxy validation)
    let client_ip = get_client_ip(&headers, connect_info.as_ref(), &state);

    // Validate proof structure
    req.proof
        .validate_structure()
        .map_err(|e| GspError::BadRequest(format!("Invalid proof: {}", e)))?;

    // Check timestamp
    if !req.proof.is_timestamp_valid() {
        return Err(GspError::BadRequest(
            "Proof timestamp out of range".to_string(),
        ));
    }

    // Verify action
    if req.proof.action() != Some("session") {
        return Err(GspError::BadRequest("Invalid proof action".to_string()));
    }

    // Get permanent wallet ID for registration lookup
    let permanent_id = req
        .proof
        .wallet_id()
        .map_err(|e| GspError::BadRequest(format!("Invalid wallet ID: {}", e)))?;

    // Check if registered (using permanent ID)
    if !state.registry.is_registered(&permanent_id)? {
        return Err(GspError::WalletNotRegistered);
    }

    // Verify signature
    state.registry.verify_proof(&req.proof)?;

    // Derive session-rotating wallet ID (requires session nonce for privacy)
    let session_id = req
        .derive_wallet_id()
        .map_err(|e| GspError::BadRequest(format!("Session nonce error: {}", e)))?;

    // CRIT-AUTH-3: Create session token bound to client IP.
    // `sub` is the rotating session ID (privacy-preserving on the
    // wire); `static_wallet_id` is the permanent ID so per-action
    // WalletProof checks can re-derive it without the wallet
    // embedding the session nonce in every proof.
    let token = state
        .jwt
        .create_token_full(&session_id, Some(&permanent_id), client_ip.clone())?;

    if let Some(ref ip) = client_ip {
        info!(wallet_id = %session_id, client_ip = %ip, "Session created with IP binding");
    } else {
        warn!(wallet_id = %session_id, "Session created without IP binding - client IP not available");
    }

    Ok(Json(SessionResponse {
        success: true,
        token: Some(token.clone()),
        expires_at: Some(token.expires_at),
        error: None,
    }))
}

/// Admin: inject a synthetic BIP-352 candidate transaction.
///
/// Pushes the body verbatim through the silent-payments broadcaster so every
/// session that subscribed via `SubscribeSilentPayments` receives it. Useful
/// for end-to-end testing the wallet's local-scan path without standing up
/// a real chain-driven scanner.
///
/// **Dev-only:** refused on mainnet. Listens on the same surface as other
/// admin endpoints — protect with network-level rules in deployment.
#[derive(serde::Deserialize)]
pub struct InjectCandidateTxRequest {
    pub ephemeral_pubkey: String,
    pub outputs: Vec<ghost_gsp_proto::CandidateOutput>,
    pub txid: String,
    pub block_height: Option<u32>,
}

#[derive(serde::Serialize)]
pub struct InjectCandidateTxResponse {
    pub success: bool,
    pub subscribers_notified: usize,
    pub error: Option<String>,
}

pub async fn admin_inject_candidate_tx(
    State(state): State<Arc<GspState>>,
    Json(req): Json<InjectCandidateTxRequest>,
) -> Json<InjectCandidateTxResponse> {
    if matches!(state.config.network, bitcoin::Network::Bitcoin) {
        return Json(InjectCandidateTxResponse {
            success: false,
            subscribers_notified: 0,
            error: Some("admin endpoint refused on mainnet".to_string()),
        });
    }

    // Light validation: ephemeral_pubkey is 33 bytes hex, txid is 32 bytes hex.
    if req.ephemeral_pubkey.len() != 66 {
        return Json(InjectCandidateTxResponse {
            success: false,
            subscribers_notified: 0,
            error: Some("ephemeral_pubkey must be 66 hex chars (33 bytes)".to_string()),
        });
    }
    if req.txid.len() != 64 {
        return Json(InjectCandidateTxResponse {
            success: false,
            subscribers_notified: 0,
            error: Some("txid must be 64 hex chars (32 bytes)".to_string()),
        });
    }

    let msg = ghost_gsp_proto::ServerMessage::CandidateTransaction {
        ephemeral_pubkey: req.ephemeral_pubkey,
        outputs: req.outputs,
        txid: req.txid,
        block_height: req.block_height,
    };

    // No subscribers yet is fine — nobody to notify, so zero.
    let n = state.silent_payments_tx.send(msg).unwrap_or_default();
    info!(subscribers = n, "admin: candidate-tx injected");
    Json(InjectCandidateTxResponse {
        success: true,
        subscribers_notified: n,
        error: None,
    })
}
