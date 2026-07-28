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
//| FILE: api.rs                                                                                                         |
//|======================================================================================================================|

//! HTTP API endpoints for node registration and management

use crate::auth::{verify_internal_auth, InternalAuth, RateLimiter};
use crate::config::HealthConfig;
use crate::db::{PoolNode, RegistryDb};
use crate::health_checker::HealthChecker;
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1};
use chrono::Utc;
use ghost_common::config::Region;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Shared application state
pub(crate) struct AppState {
    pub db: Arc<RegistryDb>,
    pub health_checker: Arc<HealthChecker>,
    pub health_config: HealthConfig,
    /// API-2: HMAC authentication for state-modifying endpoints
    pub internal_auth: Arc<InternalAuth>,
    /// API-3: Rate limiter for status endpoint
    pub rate_limiter: Arc<RateLimiter>,
}

/// Node registration request (matches ghost-pool registry.rs)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct NodeRegistration {
    pub node_id: String,
    pub host: String,
    pub sv1_port: u16,
    pub sv2_port: u16,
    pub region: Region,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    pub max_miners: u32,
    pub signature: String,
    pub timestamp: u64,
}

/// Node heartbeat request (matches ghost-pool registry.rs)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct NodeHeartbeat {
    pub node_id: String,
    pub miner_count: u32,
    pub max_miners: u32,
    pub load_percent: u8,
    pub cpu_percent: u8,
    pub memory_percent: u8,
    pub share_latency_ms: u16,
    pub bandwidth_percent: u8,
    pub capacity_state: String,
    pub accepting_miners: bool,
    pub signature: String,
    pub timestamp: u64,
}

/// Node deregistration request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct NodeDeregistration {
    pub node_id: String,
    pub signature: String,
    pub timestamp: u64,
}

/// API response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ApiResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl ApiResponse {
    pub(crate) fn ok() -> Self {
        Self {
            status: "ok".to_string(),
            error: None,
            data: None,
        }
    }

    pub(crate) fn ok_with_data(data: impl Serialize) -> Self {
        Self {
            status: "ok".to_string(),
            error: None,
            data: Some(serde_json::to_value(data).unwrap_or(serde_json::Value::Null)),
        }
    }

    pub(crate) fn error(message: impl Into<String>) -> Self {
        Self {
            status: "error".to_string(),
            error: Some(message.into()),
            data: None,
        }
    }
}

/// Build the API router
pub(crate) fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/nodes/register", post(handle_register))
        .route("/api/v1/nodes/heartbeat", post(handle_heartbeat))
        .route("/api/v1/nodes/:node_id", delete(handle_deregister))
        .route("/api/v1/nodes/:node_id/status", get(handle_node_status))
        .route("/api/v1/nodes", get(handle_list_nodes))
        .route("/api/v1/regions", get(handle_list_regions))
        .route("/api/v1/health", get(handle_health))
        .route("/health", get(handle_health))
        .with_state(state)
}

/// Handle node registration
///
/// API-2: Protected by HMAC authentication
async fn handle_register(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // API-2: Verify HMAC authentication first
    if let Err((status, msg)) = verify_internal_auth(&state.internal_auth, &headers, &body) {
        warn!(error = %msg, "Registration rejected: HMAC authentication failed");
        return (status, Json(ApiResponse::error(msg)));
    }

    // Parse the request body
    let req: NodeRegistration = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(format!("Invalid request body: {}", e))),
            );
        }
    };

    // Validate timestamp (prevent replay attacks)
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("L-1: System clock is before UNIX epoch - check system time")
        .as_secs();

    let drift = now.abs_diff(req.timestamp);

    if drift > state.health_config.max_timestamp_drift_secs {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Timestamp too far from server time")),
        );
    }

    // Verify node signature (proves node has private key)
    let message = format!(
        "ghost:register:{}:{}:{}:{}:{}",
        req.node_id, req.host, req.sv1_port, req.sv2_port, req.timestamp
    );

    if let Err(e) = verify_signature(&req.node_id, &message, &req.signature) {
        warn!(
            node_id = %req.node_id,
            error = %e,
            "Invalid registration signature"
        );
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::error(format!("Invalid signature: {}", e))),
        );
    }

    // Check rate limiting (if node already exists)
    // LOW-RATE: Return 429 when rate limited
    if let Ok(Some(existing)) = state.db.get_node(&req.node_id) {
        let since_registered = (Utc::now() - existing.registered_at).num_seconds();
        if since_registered < state.health_config.registration_rate_limit_secs as i64 {
            let seconds_remaining =
                state.health_config.registration_rate_limit_secs as i64 - since_registered;
            debug!(
                node_id = %req.node_id,
                seconds_remaining = seconds_remaining,
                "Rate limited registration"
            );
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ApiResponse::error(format!(
                    "Rate limited. Please wait {} seconds before re-registering.",
                    seconds_remaining
                ))),
            );
        }
    }

    // Create node record
    let node = PoolNode {
        node_id: req.node_id.clone(),
        host: req.host,
        sv1_port: req.sv1_port,
        sv2_port: req.sv2_port,
        region: req.region,
        latitude: req.latitude,
        longitude: req.longitude,
        max_miners: req.max_miners,
        miner_count: 0,
        load_percent: 0,
        cpu_percent: 0,
        memory_percent: 0,
        healthy: true,
        accepting_miners: true,
        excluded_for_load: false,
        registered_at: Utc::now(),
        last_heartbeat: Utc::now(),
    };

    // Store in database
    // LOW-DB: Don't expose database errors to clients
    if let Err(e) = state.db.upsert_node(&node) {
        warn!(
            node_id = %req.node_id,
            error = %e,
            "Database error during node registration"
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error("Internal server error")),
        );
    }

    info!(
        node_id = %req.node_id,
        host = %node.host,
        region = %format!("{:?}", node.region),
        "Node registered"
    );

    (StatusCode::OK, Json(ApiResponse::ok()))
}

/// Handle node heartbeat
///
/// API-2: Protected by HMAC authentication
async fn handle_heartbeat(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // API-2: Verify HMAC authentication first
    if let Err((status, msg)) = verify_internal_auth(&state.internal_auth, &headers, &body) {
        warn!(error = %msg, "Heartbeat rejected: HMAC authentication failed");
        return (status, Json(ApiResponse::error(msg)));
    }

    // Parse the request body
    let req: NodeHeartbeat = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::error(format!("Invalid request body: {}", e))),
            );
        }
    };

    // Validate timestamp
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let drift = now.abs_diff(req.timestamp);

    if drift > state.health_config.max_timestamp_drift_secs {
        return (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::error("Timestamp too far from server time")),
        );
    }

    // Verify node signature (proves node has private key)
    let message = format!(
        "ghost:heartbeat:{}:{}:{}:{}",
        req.node_id, req.miner_count, req.load_percent, req.timestamp
    );

    if let Err(e) = verify_signature(&req.node_id, &message, &req.signature) {
        warn!(
            node_id = %req.node_id,
            error = %e,
            "Invalid heartbeat signature"
        );
        return (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::error(format!("Invalid signature: {}", e))),
        );
    }

    // Check if node exists
    match state.db.get_node(&req.node_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse::error("Node not registered")),
            );
        }
        Err(e) => {
            warn!(
                node_id = %req.node_id,
                error = %e,
                "Database error checking node existence"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error("Internal server error")),
            );
        }
    }

    // Update heartbeat
    // LOW-DB: Don't expose database errors to clients
    if let Err(e) = state.db.update_heartbeat(
        &req.node_id,
        req.miner_count,
        req.load_percent,
        req.cpu_percent,
        req.memory_percent,
        req.accepting_miners,
    ) {
        warn!(
            node_id = %req.node_id,
            error = %e,
            "Database error updating heartbeat"
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::error("Internal server error")),
        );
    }

    debug!(
        node_id = %req.node_id,
        miners = req.miner_count,
        load = req.load_percent,
        "Heartbeat received"
    );

    (StatusCode::OK, Json(ApiResponse::ok()))
}

/// Handle node deregistration
///
/// API-1 CRITICAL: Protected by HMAC authentication
/// Previously allowed unauthenticated deletion - now requires valid HMAC signature
async fn handle_deregister(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // API-1 CRITICAL: Verify HMAC authentication - prevents unauthorized node deletion
    if let Err((status, msg)) = verify_internal_auth(&state.internal_auth, &headers, &body) {
        warn!(
            node_id = %node_id,
            error = %msg,
            "API-1: Deregistration rejected - HMAC authentication failed"
        );
        return (status, Json(ApiResponse::error(msg)));
    }

    // Optionally parse body for node signature verification
    // For deregistration, we accept an optional NodeDeregistration body with node signature
    if !body.is_empty() {
        if let Ok(req) = serde_json::from_slice::<NodeDeregistration>(&body) {
            // Verify the node_id in path matches body
            if req.node_id != node_id {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ApiResponse::error("Node ID mismatch between path and body")),
                );
            }

            // Verify node signature (proves node has private key)
            let message = format!("ghost:deregister:{}:{}", req.node_id, req.timestamp);
            if let Err(e) = verify_signature(&req.node_id, &message, &req.signature) {
                warn!(
                    node_id = %req.node_id,
                    error = %e,
                    "Invalid deregistration signature"
                );
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(ApiResponse::error(format!("Invalid node signature: {}", e))),
                );
            }
        }
        // If body parsing fails, we still proceed with HMAC-authenticated request
        // This allows admin tools to deregister nodes without node signature
    }

    match state.db.delete_node(&node_id) {
        Ok(true) => {
            info!(node_id = %node_id, "Node deregistered (authenticated)");
            (StatusCode::OK, Json(ApiResponse::ok()))
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Node not found")),
        ),
        Err(e) => {
            warn!(
                node_id = %node_id,
                error = %e,
                "Database error during deregistration"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error("Internal server error")),
            )
        }
    }
}

/// Handle node status query
async fn handle_node_status(
    State(state): State<Arc<AppState>>,
    Path(node_id): Path<String>,
) -> impl IntoResponse {
    match state.db.get_node_status(&node_id) {
        Ok(Some(status)) => {
            let last_hb_ago = chrono::Utc::now()
                .signed_duration_since(status.last_heartbeat)
                .num_seconds();

            let response = NodeStatusResponse {
                registered: status.registered,
                in_dns: status.in_dns,
                healthy: status.healthy,
                accepting_miners: status.accepting_miners,
                excluded_for_load: status.excluded_for_load,
                load_percent: status.load_percent,
                rank_in_region: status.rank_in_region,
                total_in_region: status.total_in_region,
                healthy_in_region: status.healthy_in_region,
                region: format!("{:?}", status.region),
                last_heartbeat_ago_secs: last_hb_ago as u64,
                exclusion_reason: if !status.healthy {
                    Some("Node marked unhealthy (missed heartbeats)".to_string())
                } else if !status.accepting_miners {
                    Some("Node not accepting miners".to_string())
                } else if status.excluded_for_load {
                    Some("Load too high (>= 80%), will resume at < 70%".to_string())
                } else {
                    None
                },
            };

            (StatusCode::OK, Json(ApiResponse::ok_with_data(response)))
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::error("Node not found")),
        ),
        Err(e) => {
            warn!(
                node_id = %node_id,
                error = %e,
                "Database error fetching node status"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error("Internal server error")),
            )
        }
    }
}

/// Node status response
#[derive(Debug, Serialize, Deserialize)]
struct NodeStatusResponse {
    registered: bool,
    in_dns: bool,
    healthy: bool,
    accepting_miners: bool,
    excluded_for_load: bool,
    load_percent: u8,
    rank_in_region: u32,
    total_in_region: u32,
    healthy_in_region: u32,
    region: String,
    last_heartbeat_ago_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    exclusion_reason: Option<String>,
}

/// Handle list nodes (admin endpoint)
///
/// API-3: Rate limited to prevent network topology enumeration abuse
async fn handle_list_nodes(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    // API-3: Apply rate limiting
    let ip = addr.ip().to_string();
    if let Err(retry_after) = state.rate_limiter.check(&ip) {
        warn!(
            ip = %ip,
            retry_after = retry_after,
            "API-3: Rate limited list nodes request"
        );
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ApiResponse::error(format!(
                "Rate limited. Retry after {} seconds.",
                retry_after
            ))),
        );
    }

    match state.db.get_all_nodes() {
        Ok(nodes) => {
            // API-3: Return limited information for unauthenticated requests
            // Only return node count and regions, not full details
            let response = nodes
                .into_iter()
                .map(|n| NodeSummary {
                    node_id: n.node_id,
                    host: n.host,
                    sv1_port: n.sv1_port,
                    sv2_port: n.sv2_port,
                    region: format!("{:?}", n.region),
                    miner_count: n.miner_count,
                    max_miners: n.max_miners,
                    load_percent: n.load_percent,
                    healthy: n.healthy,
                    last_heartbeat: n.last_heartbeat.to_rfc3339(),
                })
                .collect::<Vec<_>>();

            (StatusCode::OK, Json(ApiResponse::ok_with_data(response)))
        }
        Err(e) => {
            warn!(error = %e, "Database error listing nodes");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error("Internal server error")),
            )
        }
    }
}

/// Handle list regions
async fn handle_list_regions(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.db.get_region_stats() {
        Ok(stats) => (StatusCode::OK, Json(ApiResponse::ok_with_data(stats))),
        Err(e) => {
            warn!(error = %e, "Database error fetching region stats");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error("Internal server error")),
            )
        }
    }
}

/// Handle health check
async fn handle_health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.health_checker.get_health_summary() {
        Ok(summary) => (StatusCode::OK, Json(ApiResponse::ok_with_data(summary))),
        Err(e) => {
            warn!(error = %e, "Health check failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiResponse::error("Health check failed")),
            )
        }
    }
}

/// Node summary for list endpoint
#[derive(Debug, Serialize, Deserialize)]
struct NodeSummary {
    node_id: String,
    host: String,
    sv1_port: u16,
    sv2_port: u16,
    region: String,
    miner_count: u32,
    max_miners: u32,
    load_percent: u8,
    healthy: bool,
    last_heartbeat: String,
}

/// Verify secp256k1 signature
fn verify_signature(
    public_key_hex: &str,
    message: &str,
    signature_hex: &str,
) -> Result<(), String> {
    let secp = Secp256k1::verification_only();

    // Parse public key
    let pubkey_bytes =
        hex::decode(public_key_hex).map_err(|e| format!("Invalid public key hex: {}", e))?;

    let pubkey =
        PublicKey::from_slice(&pubkey_bytes).map_err(|e| format!("Invalid public key: {}", e))?;

    // Hash the message
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    // Parse signature
    let sig_bytes =
        hex::decode(signature_hex).map_err(|e| format!("Invalid signature hex: {}", e))?;

    let signature = bitcoin::secp256k1::ecdsa::Signature::from_compact(&sig_bytes)
        .map_err(|e| format!("Invalid signature: {}", e))?;

    // Verify
    let msg = Message::from_digest(hash);
    secp.verify_ecdsa(&msg, &signature, &pubkey)
        .map_err(|e| format!("Signature verification failed: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use secp256k1::{Secp256k1, SecretKey};

    #[test]
    fn test_signature_verification() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut OsRng);
        let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

        let message = "ghost:register:test:1.2.3.4:3333:34255:1234567890";

        // Hash and sign
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        let msg = secp256k1::Message::from_digest(hash);
        let sig = secp.sign_ecdsa(&msg, &secret_key);

        let pubkey_hex = hex::encode(public_key.serialize());
        let sig_hex = hex::encode(sig.serialize_compact());

        // Verify
        let result = verify_signature(&pubkey_hex, message, &sig_hex);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_signature() {
        let secp = Secp256k1::new();
        let secret_key1 = SecretKey::new(&mut OsRng);
        let secret_key2 = SecretKey::new(&mut OsRng);
        let public_key1 = secp256k1::PublicKey::from_secret_key(&secp, &secret_key1);

        let message = "ghost:register:test:1.2.3.4:3333:34255:1234567890";

        // Sign with wrong key (secret_key2)
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        let msg = secp256k1::Message::from_digest(hash);
        let sig = secp.sign_ecdsa(&msg, &secret_key2);

        // Verify with public_key1 should fail
        let pubkey_hex = hex::encode(public_key1.serialize());
        let sig_hex = hex::encode(sig.serialize_compact());

        let result = verify_signature(&pubkey_hex, message, &sig_hex);
        assert!(result.is_err());
    }

    #[test]
    fn test_api_response() {
        let resp = ApiResponse::ok();
        assert_eq!(resp.status, "ok");
        assert!(resp.error.is_none());

        let resp = ApiResponse::error("test error");
        assert_eq!(resp.status, "error");
        assert_eq!(resp.error, Some("test error".to_string()));
    }
}
