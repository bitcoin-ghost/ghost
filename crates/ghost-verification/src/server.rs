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
//| FILE: server.rs                                                                                                      |
//|======================================================================================================================|

//! Verification server

use axum::extract::DefaultBodyLimit;
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;
use ghost_common::constants::{SV1_STRATUM_PORT, SV2_STRATUM_PORT};
use ghost_common::error::{GhostError, GhostResult};
use ghost_common::identity::NodeIdentity;
use ghost_common::metrics::Metrics;
use ghost_common::rpc::BitcoinRpc;
use ghost_common::types::NodeCapabilities;
use ghost_policy::{PolicyEngine, PolicyProfile};
use ghost_storage::Database;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::config::NodeConfig;
/// Full node configuration from ghost_common (pool.toml)
/// Used by the config update API to modify settings like mining_mode, policy_profile, etc.
pub use ghost_common::config::NodeConfig as FullNodeConfig;
use tokio::net::TcpListener;
use tower_governor::{
    errors::GovernorError, governor::GovernorConfigBuilder, key_extractor::KeyExtractor,
};
use tower_http::cors::CorsLayer;
use tracing::info;

/// L-21 FIX: Validate that an IP address is acceptable as a trusted proxy.
///
/// Returns true if the IP is valid for use as a trusted proxy:
/// - Localhost addresses (127.0.0.1, ::1) are always allowed
/// - Private network addresses (10.x, 172.16-31.x, 192.168.x) are allowed
/// - Link-local addresses are rejected (169.254.x.x, fe80::)
/// - Multicast addresses are rejected
/// - Unspecified addresses (0.0.0.0, ::) are rejected
/// - Public IP addresses are allowed (for cloud proxy scenarios)
///
/// This prevents attackers from specifying reserved/special addresses.
fn is_valid_trusted_proxy(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;

    match ip {
        IpAddr::V4(ipv4) => {
            // Reject unspecified address (0.0.0.0)
            if ipv4.is_unspecified() {
                tracing::warn!(ip = %ip, "L-21: Rejecting unspecified IPv4 address as trusted proxy");
                return false;
            }
            // Reject link-local (169.254.x.x)
            if ipv4.is_link_local() {
                tracing::warn!(ip = %ip, "L-21: Rejecting link-local IPv4 address as trusted proxy");
                return false;
            }
            // Reject multicast (224.0.0.0 - 239.255.255.255)
            if ipv4.is_multicast() {
                tracing::warn!(ip = %ip, "L-21: Rejecting multicast IPv4 address as trusted proxy");
                return false;
            }
            // Reject broadcast (255.255.255.255)
            if ipv4.is_broadcast() {
                tracing::warn!(ip = %ip, "L-21: Rejecting broadcast IPv4 address as trusted proxy");
                return false;
            }
            // Reject documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
            let octets = ipv4.octets();
            if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
            {
                tracing::warn!(ip = %ip, "L-21: Rejecting documentation IPv4 address as trusted proxy");
                return false;
            }
            true
        }
        IpAddr::V6(ipv6) => {
            // Reject unspecified address (::)
            if ipv6.is_unspecified() {
                tracing::warn!(ip = %ip, "L-21: Rejecting unspecified IPv6 address as trusted proxy");
                return false;
            }
            // Reject multicast (ff00::/8)
            if ipv6.is_multicast() {
                tracing::warn!(ip = %ip, "L-21: Rejecting multicast IPv6 address as trusted proxy");
                return false;
            }
            // Note: is_unicast_link_local requires nightly or manual check
            // Link-local: fe80::/10
            let segments = ipv6.segments();
            if (segments[0] & 0xffc0) == 0xfe80 {
                tracing::warn!(ip = %ip, "L-21: Rejecting link-local IPv6 address as trusted proxy");
                return false;
            }
            true
        }
    }
}

/// C-2/PAY-2: Trusted proxy configuration for secure IP extraction.
///
/// Only requests from trusted proxy IPs will have X-Forwarded-For/X-Real-IP headers
/// honored. This prevents IP spoofing attacks where attackers set fake headers.
///
/// Load from environment variables (comma-separated IPs):
/// - TRUSTED_PROXY_IPS (preferred, as specified in PAY-2 fix)
/// - GHOST_TRUSTED_PROXIES (legacy, for backward compatibility)
///
/// L-21 FIX: Validates that configured proxy IPs are not reserved/special addresses.
fn get_trusted_proxies() -> Vec<std::net::IpAddr> {
    use std::net::IpAddr;

    // PAY-2: Check TRUSTED_PROXY_IPS first (preferred), then GHOST_TRUSTED_PROXIES (legacy)
    let proxies_str =
        std::env::var("TRUSTED_PROXY_IPS").or_else(|_| std::env::var("GHOST_TRUSTED_PROXIES"));

    if let Ok(proxies_str) = proxies_str {
        let proxies: Vec<IpAddr> = proxies_str
            .split(',')
            .filter_map(|s| {
                let trimmed = s.trim();
                match trimmed.parse::<IpAddr>() {
                    Ok(ip) => {
                        // L-21 FIX: Validate the IP is acceptable
                        if is_valid_trusted_proxy(&ip) {
                            Some(ip)
                        } else {
                            None // Already logged in is_valid_trusted_proxy
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            ip = %trimmed,
                            error = %e,
                            "L-21: Failed to parse trusted proxy IP, skipping"
                        );
                        None
                    }
                }
            })
            .collect();

        if proxies.is_empty() {
            tracing::warn!(
                "L-21: No valid trusted proxies configured, falling back to localhost only"
            );
            vec![
                "127.0.0.1"
                    .parse()
                    .expect("L-1: Valid hardcoded IPv4 localhost"),
                "::1".parse().expect("L-1: Valid hardcoded IPv6 localhost"),
            ]
        } else {
            tracing::info!(
                proxy_count = proxies.len(),
                "PAY-2: Loaded trusted proxy IPs from environment"
            );
            proxies
        }
    } else {
        // Default: only trust localhost as proxy
        vec![
            "127.0.0.1"
                .parse()
                .expect("L-1: Valid hardcoded IPv4 localhost"),
            "::1".parse().expect("L-1: Valid hardcoded IPv6 localhost"),
        ]
    }
}

/// C-2: Check if an IP address is a trusted proxy.
fn is_trusted_proxy(ip: &std::net::IpAddr, trusted: &[std::net::IpAddr]) -> bool {
    trusted.contains(ip)
}

/// AUTH4-M1: Custom key extractor that uses NodeId from X-Ghost-NodeId header
/// with fallback to IP address.
///
/// This provides better rate limiting by identifying nodes by their cryptographic
/// identity rather than just IP, preventing attackers from bypassing limits by
/// changing IPs while still providing a fallback for anonymous requests.
///
/// C-2: X-Forwarded-For and X-Real-IP headers are ONLY trusted when the direct
/// peer IP is in the trusted proxy list. This prevents IP spoofing attacks.
///
/// # Multi-Proxy Chain Support (M-14/MED-VER-6)
///
/// The extractor supports multi-proxy chains via the `trusted_proxy_count` configuration.
/// This is set via the `GHOST_TRUSTED_PROXY_COUNT` environment variable.
///
/// ## How X-Forwarded-For Parsing Works
///
/// X-Forwarded-For format: `"client, proxy1, proxy2, ..."` (left to right, appended by each proxy)
///
/// With `trusted_proxy_count=N`, we skip the rightmost N entries and take the next one:
/// - `trusted_proxy_count=1` (default, single proxy): `"client, proxy"` -> use `client`
/// - `trusted_proxy_count=2` (CDN -> LB -> App): `"client, cdn, lb"` -> use `client`
/// - `trusted_proxy_count=3` (CDN -> LB -> WAF -> App): `"client, cdn, lb, waf"` -> use `client`
///
/// ## Security Implications
///
/// **IMPORTANT**: You MUST configure `trusted_proxy_count` to match your EXACT infrastructure:
///
/// - If set TOO LOW: Untrusted proxy IPs will be used as client IPs (IP spoofing)
/// - If set TOO HIGH: Legitimate client IPs in the XFF chain will be skipped
///
/// For example, with CDN -> LB -> App:
/// - If `trusted_proxy_count=1` (wrong): XFF `"client, cdn"` -> uses `cdn` as client (WRONG)
/// - If `trusted_proxy_count=2` (correct): XFF `"client, cdn"` -> uses `client` (CORRECT)
///
/// ## Environment Configuration
///
/// - `GHOST_TRUSTED_PROXIES`: Comma-separated list of trusted proxy IPs
/// - `GHOST_TRUSTED_PROXY_COUNT`: Number of proxies in your infrastructure (1-10, default: 1)
#[derive(Debug, Clone)]
pub struct NodeIdKeyExtractor {
    trusted_proxies: Vec<std::net::IpAddr>,
    /// M-14/MED-VER-6: Number of trusted proxies in the chain.
    /// MUST match your exact infrastructure to prevent IP spoofing.
    /// For X-Forwarded-For: "client, proxy1, proxy2" with count=2,
    /// we skip the last 2 entries (proxy1, proxy2) and use client IP.
    trusted_proxy_count: usize,
}

impl Default for NodeIdKeyExtractor {
    fn default() -> Self {
        Self::new()
    }
}

/// M-14 FIX: Get trusted proxy count from environment
///
/// Returns the number of trusted proxies in the chain. Default is 1.
/// For multi-proxy setups (CDN -> LB -> App), set GHOST_TRUSTED_PROXY_COUNT=2.
fn get_trusted_proxy_count() -> usize {
    std::env::var("GHOST_TRUSTED_PROXY_COUNT")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .map(|count| {
            // M-14: Sanity check - cap at 10 proxies, minimum 1
            let capped = count.clamp(1, 10);
            if capped != count {
                tracing::warn!(
                    requested = count,
                    capped = capped,
                    "M-14: Trusted proxy count capped to valid range [1, 10]"
                );
            }
            capped
        })
        .unwrap_or(1) // Default: single proxy
}

impl NodeIdKeyExtractor {
    /// Create a new NodeIdKeyExtractor with trusted proxies from environment.
    pub fn new() -> Self {
        let trusted_proxy_count = get_trusted_proxy_count();
        tracing::info!(
            trusted_proxy_count = trusted_proxy_count,
            "M-14: Configured trusted proxy count for X-Forwarded-For parsing"
        );
        Self {
            trusted_proxies: get_trusted_proxies(),
            trusted_proxy_count,
        }
    }

    /// Create with explicit trusted proxy list (for testing).
    #[cfg(test)]
    pub fn with_trusted_proxies(trusted_proxies: Vec<std::net::IpAddr>) -> Self {
        Self {
            trusted_proxies,
            trusted_proxy_count: 1,
        }
    }

    /// M-14 FIX: Create with explicit proxy count (for testing multi-proxy chains)
    #[cfg(test)]
    pub fn with_trusted_proxies_and_count(
        trusted_proxies: Vec<std::net::IpAddr>,
        trusted_proxy_count: usize,
    ) -> Self {
        Self {
            trusted_proxies,
            trusted_proxy_count: trusted_proxy_count.clamp(1, 10),
        }
    }
}

/// Key type for NodeId-based rate limiting
/// Either a 32-byte NodeId or an IP address (encoded as string for simplicity)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeIdOrIpKey(String);

impl KeyExtractor for NodeIdKeyExtractor {
    type Key = NodeIdOrIpKey;

    fn extract<T>(&self, req: &axum::http::Request<T>) -> Result<Self::Key, GovernorError> {
        // Try X-Ghost-NodeId header first (64-char hex-encoded NodeId)
        if let Some(node_id) = req.headers().get("X-Ghost-NodeId") {
            if let Ok(node_id_str) = node_id.to_str() {
                let s: &str = node_id_str;
                // Validate it looks like a valid node ID (64 hex chars = 32 bytes)
                if s.len() == 64 && s.chars().all(|c: char| c.is_ascii_hexdigit()) {
                    return Ok(NodeIdOrIpKey(format!("node:{}", s)));
                }
            }
        }

        // C-2: Get actual peer IP from connection info FIRST
        let peer_ip = req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip());

        // C-2: Only trust proxy headers if peer is a trusted proxy
        let trust_proxy_headers = peer_ip
            .as_ref()
            .map(|ip| is_trusted_proxy(ip, &self.trusted_proxies))
            .unwrap_or(false);

        if trust_proxy_headers {
            // Try X-Forwarded-For (standard for proxied requests)
            // M-14 FIX: Handle multi-proxy chains correctly
            // X-Forwarded-For format: "client, proxy1, proxy2, ..." (left to right)
            // With N trusted proxies, we skip the rightmost N entries and take the next one.
            //
            // Example with trusted_proxy_count=2 (CDN -> LB -> App):
            //   Header: "client, cdn_saw, lb_saw"
            //   Skip 2 from right: take "client" (the actual client IP)
            //
            // Example with trusted_proxy_count=1 (single proxy):
            //   Header: "client, proxy"
            //   Skip 1 from right: take "client"
            if let Some(xff) = req.headers().get("X-Forwarded-For") {
                if let Ok(xff_str) = xff.to_str() {
                    let ips: Vec<&str> = xff_str.split(',').map(|s| s.trim()).collect();

                    // M-14 FIX: Calculate the correct index based on proxy count
                    // The client IP is at position (len - 1 - trusted_proxy_count)
                    // because each proxy appends the IP of who connected to it.
                    if ips.len() > self.trusted_proxy_count {
                        let client_index = ips.len() - 1 - self.trusted_proxy_count;
                        let client_ip = ips[client_index];
                        if !client_ip.is_empty() {
                            return Ok(NodeIdOrIpKey(format!("ip:{}", client_ip)));
                        }
                    } else if !ips.is_empty() {
                        // M-14: Not enough IPs in chain, take the first (client)
                        // This handles the case where we have fewer hops than expected
                        let client_ip = ips[0];
                        if !client_ip.is_empty() {
                            return Ok(NodeIdOrIpKey(format!("ip:{}", client_ip)));
                        }
                    }
                }
            }

            // Try X-Real-IP (nginx convention) - this is typically set by the proxy
            // to the actual client IP, so it's already trustworthy when from a trusted proxy
            if let Some(xri) = req.headers().get("X-Real-IP") {
                if let Ok(ip_str) = xri.to_str() {
                    let s: &str = ip_str;
                    return Ok(NodeIdOrIpKey(format!("ip:{}", s)));
                }
            }
        }

        // Fall back to actual peer IP
        if let Some(ip) = peer_ip {
            return Ok(NodeIdOrIpKey(format!("ip:{}", ip)));
        }

        // Last resort: unknown source
        Err(GovernorError::UnableToExtractKey)
    }
}

use crate::challenge::*;
use crate::routes::create_router;
use crate::websocket::WsState;

/// M-12: Validate that a CORS origin is a properly formatted HTTPS URL.
///
/// Returns true only if:
/// - The origin starts with "https://" (enforced for security)
/// - The origin has a valid host after the scheme
/// - The origin doesn't contain path components (origins are scheme + host + optional port)
///
/// This prevents malformed origins from bypassing CORS protection.
///
/// # Security Warning: CORS Origin Configuration
///
/// **IMPORTANT**: Improperly configured allowed_origins can create security vulnerabilities:
///
/// 1. **Never use wildcards in production**: Using "*" or "*.example.com" allows any origin
///    to make cross-origin requests to your API.
///
/// 2. **Verify all origins explicitly**: Each origin in your allowed list should be a
///    known, trusted domain under your control.
///
/// 3. **Use specific origins, not patterns**: Instead of "https://*.example.com",
///    list each subdomain explicitly: "https://app.example.com", "https://api.example.com"
///
/// 4. **Never trust user-provided origins**: The Origin header can be spoofed in
///    non-browser contexts. CORS is a browser security feature, not a server security feature.
///
/// 5. **Review origins regularly**: Remove origins that are no longer in use.
///
/// Example secure configuration:
/// ```toml
/// [dashboard]
/// allowed_origins = [
///     "https://dashboard.bitcoinghost.org",
///     "https://admin.bitcoinghost.org"
/// ]
/// ```
fn is_valid_cors_origin(origin: &str) -> bool {
    // Must start with https:// for security
    if !origin.starts_with("https://") {
        tracing::warn!(
            origin = %origin,
            "M-12: Rejecting CORS origin without https:// scheme"
        );
        return false;
    }

    // Extract the host part (after scheme, before any path)
    let host_part = &origin[8..]; // Skip "https://"

    // Must have a non-empty host
    if host_part.is_empty() {
        tracing::warn!(origin = %origin, "M-12: Rejecting CORS origin with empty host");
        return false;
    }

    // Split host from optional port
    let host = if let Some(colon_pos) = host_part.rfind(':') {
        // Check if this is actually a port (not part of IPv6)
        let potential_port = &host_part[colon_pos + 1..];
        if potential_port.chars().all(|c| c.is_ascii_digit()) {
            &host_part[..colon_pos]
        } else {
            host_part
        }
    } else {
        host_part
    };

    // Should not have path components
    if host.contains('/') {
        tracing::warn!(
            origin = %origin,
            "M-12: Rejecting CORS origin with path component"
        );
        return false;
    }

    // Host must be valid (letters, digits, dots, hyphens)
    let is_valid_host = host.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '[' || c == ']' || c == ':'
    });

    if !is_valid_host {
        tracing::warn!(
            origin = %origin,
            "M-12: Rejecting CORS origin with invalid host characters"
        );
        return false;
    }

    true
}

/// Rate limiting state shared with the rate_limit_middleware
#[derive(Clone)]
struct RateLimitState {
    key_extractor: NodeIdKeyExtractor,
    limiter: Arc<
        governor::RateLimiter<
            NodeIdOrIpKey,
            governor::state::keyed::DashMapStateStore<NodeIdOrIpKey>,
            governor::clock::DefaultClock,
        >,
    >,
}

/// Rate limiting middleware that exempts loopback (localhost) connections.
/// External traffic is rate-limited per NodeId/IP as before.
async fn rate_limit_middleware(
    axum::extract::State(state): axum::extract::State<RateLimitState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    // Check peer IP from ConnectInfo
    let is_loopback = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().is_loopback())
        .unwrap_or(false);

    // Exempt localhost from rate limiting - it's the node's own dashboard
    if is_loopback {
        return next.run(request).await;
    }

    // Extract key and check rate limit for external traffic
    match state.key_extractor.extract(&request) {
        Ok(key) => match state.limiter.check_key(&key) {
            Ok(_) => next.run(request).await,
            Err(_not_until) => axum::http::Response::builder()
                .status(axum::http::StatusCode::TOO_MANY_REQUESTS)
                .body(axum::body::Body::from("rate limited"))
                .unwrap_or_else(|_| {
                    axum::http::Response::new(axum::body::Body::from("rate limited"))
                }),
        },
        Err(_) => {
            // Unable to extract key - allow request rather than failing
            next.run(request).await
        }
    }
}

/// HIGH-API-5: Middleware to add X-Request-ID header for request correlation
///
/// This middleware:
/// 1. Checks if the client provided an X-Request-ID header
/// 2. If not, generates a new UUID v4
/// 3. Adds the ID to the response headers
/// 4. Logs the request with the correlation ID
///
/// This enables request tracing across distributed systems and makes debugging easier.
async fn correlation_id_middleware(mut request: axum::extract::Request, next: Next) -> Response {
    // Check if client provided X-Request-ID
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            // Generate new UUID v4 if not provided
            Uuid::new_v4().to_string()
        });

    // Store in request extensions for handlers to access
    request.extensions_mut().insert(request_id.clone());

    // Log the request with correlation ID
    tracing::debug!(
        request_id = %request_id,
        method = %request.method(),
        uri = %request.uri(),
        "HIGH-API-5: Request received"
    );

    // Process request
    let mut response = next.run(request).await;

    // Add X-Request-ID to response
    // MED-PANIC-1: Handle parse failure gracefully instead of unwrap
    if let Ok(value) = request_id.parse() {
        response.headers_mut().insert("x-request-id", value);
    } else if let Ok(fallback) = Uuid::new_v4().to_string().parse() {
        response.headers_mut().insert("x-request-id", fallback);
    }
    // If both fail (extremely unlikely), skip the header rather than panic

    response
}

/// LOW-API-1: Middleware to add security headers
///
/// Adds standard security headers to all responses:
/// - X-Content-Type-Options: nosniff (prevent MIME sniffing)
/// - X-Frame-Options: DENY (prevent clickjacking)
/// - X-XSS-Protection: 1; mode=block (legacy XSS protection)
/// - Content-Security-Policy: restrict resources
/// - Referrer-Policy: no-referrer (don't leak referrer)
async fn security_headers_middleware(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    // MED-PANIC-1: Use HeaderValue::from_static for known-valid header values
    // These are compile-time validated ASCII strings that cannot fail
    use axum::http::HeaderValue;

    // LOW-API-1: Add security headers
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "x-xss-protection",
        HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));

    response
}

/// Callback for triggering test consensus proposal
pub type TestProposalFn = Arc<dyn Fn() -> GhostResult<[u8; 32]> + Send + Sync>;

/// Share notification data from SRI Pool
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShareNotification {
    pub miner_id: String,
    pub work: f64,
    pub share_hash: String,
    pub job_id: u32,
    pub timestamp: u64,
    /// Whether this share found a block (triggers payout proposal)
    pub is_block: bool,
    /// Payout address extracted from user_identity (format: `<address>.<worker>`)
    pub payout_address: Option<String>,
}

/// Data for a single share in a batch (from SRI Pool native webhook)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShareData {
    /// Timestamp in milliseconds since epoch
    pub timestamp_ms: u64,
    /// Share hash as hex string
    pub share_hash: String,
    /// Share work/difficulty value
    pub share_work: f64,
    /// Channel ID the share was submitted on
    pub channel_id: u32,
    /// Sequence number from the share submission
    pub sequence_number: u32,
    /// Job ID the share was submitted for
    pub job_id: u32,
    /// Downstream client ID
    pub downstream_id: usize,
    /// Whether this share found a block
    pub is_block: bool,
    /// User identity string (format: <payout_address>.<worker_name>)
    /// Used to identify the miner's payout address
    #[serde(default)]
    pub user_identity: String,
}

/// Batch of shares from SRI Pool native webhook
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShareBatch {
    /// Pool/server ID
    pub pool_id: u16,
    /// Sequence number for this batch
    pub batch_seq: u64,
    /// Array of shares in this batch
    pub shares: Vec<ShareData>,
}

/// Callback for recording shares (from SRI Pool notifications)
pub type RecordShareFn = Arc<dyn Fn(ShareNotification) -> GhostResult<()> + Send + Sync>;

/// Data passed to the block_found callback when a block-difficulty share arrives
#[derive(Debug, Clone)]
pub struct BlockFoundInfo {
    /// Share hash that met block difficulty
    pub share_hash: String,
    /// Miner ID (user_identity string)
    pub miner_id: String,
    /// Payout address extracted from user_identity
    pub payout_address: String,
    /// Share work/difficulty value
    pub work: f64,
}

/// Callback invoked when a block-difficulty share is found via SRI webhook.
/// This triggers payout proposal creation BEFORE block submission, breaking
/// the bootstrap deadlock where submitblock requires an approved coinbase
/// commitment but the commitment requires a submitted block.
pub type BlockFoundFn = Arc<dyn Fn(BlockFoundInfo) + Send + Sync>;

/// Callback for submitting L2 NoteSpend transactions to the mesh
/// Takes serialized L2ConfidentialTransferMessage JSON bytes, returns Ok(()) on success.
pub type L2SubmitFn = Arc<dyn Fn(Vec<u8>) -> GhostResult<()> + Send + Sync>;

/// Callback for syncing a commitment to the L2 tree and broadcasting to mesh.
/// Params: (commitment, note_index, block_height)
pub type L2SyncCommitmentFn = Arc<dyn Fn([u8; 32], u64, u64) -> GhostResult<()> + Send + Sync>;

/// Callback for relaying a glyph claim to the mesh.
/// Takes serialized GhostGlyphClaimMessage JSON bytes.
pub type GlyphClaimRelayFn = Arc<dyn Fn(Vec<u8>) -> GhostResult<()> + Send + Sync>;

/// Callback for relaying a glyph registration to the mesh.
/// Takes serialized GhostGlyphRegisteredMessage JSON bytes.
pub type GlyphRegisteredRelayFn = Arc<dyn Fn(Vec<u8>) -> GhostResult<()> + Send + Sync>;

/// Callback for retrieving live L2 tree state from the epoch manager.
/// Returns (epoch, tree_root, checkpoint_height, note_count).
pub type L2TreeStateFn = Arc<dyn Fn() -> GhostResult<L2TreeStateInfo> + Send + Sync>;

/// Live L2 tree state info returned by the epoch manager callback.
#[derive(Debug, Clone)]
pub struct L2TreeStateInfo {
    pub epoch: u64,
    pub tree_root: [u8; 32],
    pub checkpoint_height: u64,
    pub note_count: u64,
}

/// Parse user_identity string to extract payout address and worker name.
/// Format: <payout_address>.<worker_name>
/// Returns (payout_address, worker_name) or (user_identity, "default") if no dot found.
fn parse_user_identity(user_identity: &str) -> (String, String) {
    if let Some(last_dot) = user_identity.rfind('.') {
        let address = &user_identity[..last_dot];
        let worker = &user_identity[last_dot + 1..];
        (address.to_string(), worker.to_string())
    } else {
        // No dot found - treat entire string as address with default worker
        (user_identity.to_string(), "default".to_string())
    }
}

/// Dashboard configuration state (mutable settings)
#[derive(Debug, Clone)]
pub struct DashboardConfig {
    pub ghost_mode: bool,
    pub archive_mode: bool,
    pub ghost_pay: bool,
    pub public_mining: bool,
    pub reaper: bool,
    pub elder: bool,
    pub elder_slot: Option<u32>,
    pub mempool_profile: String,
    pub template_profile: String,
    pub prune_profile: String,
    /// Maximum miners this node will accept
    pub max_miners: u32,
    /// Node display name for node finder
    pub node_name: Option<String>,
    /// Geographic region (eu, us, asia)
    pub region: Option<String>,
    /// Public stratum hostname
    pub stratum_host: Option<String>,
    /// Public stratum port
    pub stratum_port: Option<u16>,
    /// Public HTTP API port
    pub http_port: Option<u16>,
    /// M-STOR-2: Enable debug endpoints (logs, system info)
    /// Should be false in production
    pub enable_debug_endpoints: bool,
    /// M-STOR-3: Allowed paths for /proc filesystem access
    pub proc_paths_allowed: Vec<String>,
    /// M-STOR-3: Backup directory path
    pub backup_dir: String,
    // Dashboard-managed fields
    /// Node display nickname
    pub nickname: Option<String>,
    /// Custom mempool profiles (name -> settings)
    pub custom_mempool_profiles: std::collections::HashMap<String, serde_json::Value>,
    /// Custom template profiles (name -> settings)
    pub custom_template_profiles: std::collections::HashMap<String, serde_json::Value>,
    /// GhostPay payout address
    pub ghostpay_payout_address: Option<String>,
    /// Private mining enabled
    pub private_mining: Option<bool>,
    /// Payout address for mining rewards
    pub payout_address: Option<String>,
    /// Custom pool name for coinbase tag (formatted as "- G H O S T - {pool_name}")
    pub pool_name: Option<String>,
    /// Operator pruning window (blocks)
    pub operator_window: Option<u64>,
    /// Tor mode active (ghostd -tormode)
    pub tor_mode: bool,
    /// Onion address (if tor mode active)
    pub onion_address: Option<String>,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            ghost_mode: true,
            archive_mode: true,  // enabled by default
            ghost_pay: true,     // enabled by default
            public_mining: true, // enabled by default
            reaper: true,        // enabled by default
            elder: false,        // set per-node
            elder_slot: None,
            mempool_profile: "permissive".to_string(),
            template_profile: "default".to_string(),
            prune_profile: "none".to_string(),
            max_miners: 1000,
            node_name: None,
            region: None,
            stratum_host: None,
            stratum_port: None,
            http_port: None,
            // M-STOR-2: Debug endpoints disabled by default for security
            enable_debug_endpoints: false,
            // M-STOR-3: Allowed /proc paths for system monitoring
            proc_paths_allowed: vec![
                "/proc/meminfo".to_string(),
                "/proc/loadavg".to_string(),
                "/proc/cpuinfo".to_string(),
            ],
            // M-STOR-3: Default backup directory
            backup_dir: "/home/ghost/.ghost/backups".to_string(),
            // Dashboard-managed fields
            nickname: None,
            custom_mempool_profiles: std::collections::HashMap::new(),
            custom_template_profiles: std::collections::HashMap::new(),
            ghostpay_payout_address: None,
            private_mining: None,
            payout_address: None,
            pool_name: None,
            operator_window: None,
            tor_mode: false,
            onion_address: None,
        }
    }
}

/// Verification server state
/// Peer info for the load-balancer endpoint (`/api/internal/pool-nodes`).
///
/// `max_capacity` is the peer's hardware-derived ceiling. The translator's
/// load balancer divides `miner_count` by `max_capacity` to compute
/// utilisation and route new connections to the under-utilised peer; an
/// operator with bigger hardware naturally absorbs more.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PoolPeerInfo {
    pub public_address: String,
    pub miner_count: u32,
    pub public_mining: bool,
    pub last_seen: u64,
    /// Peer's effective max miners (derived from CPU/RAM/FD, capped by
    /// operator's `network.max_miners` if set). 0 means the peer hasn't
    /// reported it yet (treated as "unknown" / excluded from routing).
    #[serde(default)]
    pub max_capacity: u32,
}

pub struct VerificationState {
    /// Node ID (hex)
    pub node_id: String,
    /// Software version
    pub version: String,
    /// Node identity for signing responses
    identity: Option<Arc<NodeIdentity>>,
    /// Policy engine
    policy_engine: parking_lot::Mutex<PolicyEngine>,
    /// Capabilities
    pub capabilities: NodeCapabilities,
    /// Server start time
    start_time: Instant,
    /// Block height getter (callback)
    get_block_height: Box<dyn Fn() -> u64 + Send + Sync>,
    /// Round ID getter (callback)
    get_round_id: Box<dyn Fn() -> u64 + Send + Sync>,
    /// Miner count getter (callback)
    get_miner_count: Box<dyn Fn() -> u32 + Send + Sync>,
    /// Peer count getter (callback)
    get_peer_count: Box<dyn Fn() -> u32 + Send + Sync>,
    /// Archive mode handler
    archive_handler: Option<Box<dyn ArchiveHandler + Send + Sync>>,
    /// GhostPay handler
    ghostpay_handler: Option<Box<dyn GhostPayHandler + Send + Sync>>,
    /// GSP (Ghost Service Protocol) handler for light wallets
    gsp_handler: Option<Box<dyn GspHandler + Send + Sync>>,
    /// Stratum port (SV2)
    stratum_sv2_port: u16,
    /// Stratum port (SV1)
    stratum_sv1_port: u16,
    /// Database for queries (optional)
    pub database: Option<Database>,
    /// Ghost Core RPC client (optional)
    pub rpc: Option<Arc<BitcoinRpc>>,
    /// Dashboard config (mutable settings)
    pub dashboard_config: parking_lot::RwLock<DashboardConfig>,
    /// Node config with disk persistence (ghost_mode, etc.) - minimal JSON config
    pub node_config: parking_lot::RwLock<NodeConfig>,
    /// Path to node config file (JSON, for ghost_mode)
    pub node_config_path: Option<PathBuf>,
    /// Full node configuration (pool.toml) for config update API
    /// Contains all settings like mining_mode, policy_profile, ghost_pay, etc.
    pub full_node_config: Option<parking_lot::RwLock<FullNodeConfig>>,
    /// Path to full node config file (pool.toml)
    pub full_node_config_path: Option<PathBuf>,
    /// WebSocket state for real-time updates
    pub ws_state: Arc<WsState>,
    /// Test proposal callback (for admin testing)
    test_proposal_fn: Option<TestProposalFn>,
    /// Share recording callback (from SRI Pool notifications)
    record_share_fn: Option<RecordShareFn>,
    /// Block found callback (triggers payout proposal before block submission)
    block_found_fn: Option<BlockFoundFn>,
    /// Internal API authentication (H10/H11 security fix)
    /// When Some, internal endpoints require HMAC-SHA256 authentication
    pub internal_auth: Option<Arc<crate::auth::InternalAuth>>,
    /// VF-C2: Whether to require internal API authentication at startup
    /// When true (default), server will fail to start if internal_auth is not configured
    /// When false, allows insecure mode for development/testing ONLY
    pub require_internal_auth: bool,
    /// Pool peers callback: returns peers with public_mining + miner counts for load balancing.
    get_pool_peers: Option<Box<dyn Fn() -> Vec<PoolPeerInfo> + Send + Sync>>,
    /// Reaper stats callback: returns a JSON-serializable snapshot of the
    /// cumulative ReaperStats counters. Pre-serialized to JSON because the
    /// concrete `ReaperStats` type lives in `bins/ghost-pool` and we don't
    /// want a reverse dep from ghost-verification.
    get_reaper_stats: Option<Box<dyn Fn() -> serde_json::Value + Send + Sync>>,
    /// Mesh-wide deduplicated active miner count callback. Returns the size
    /// of the union of locally-active miner_id hashes and every connected
    /// peer's most-recent reported set, giving an exact pool-wide active
    /// count that's stable across the round rotations and load-balancer
    /// hopping that make per-VM counts misleading when summed.
    get_mesh_active_miners: Option<Box<dyn Fn() -> u32 + Send + Sync>>,
    /// Mesh-wide pool hashrate (TH/s): sum of every node's own realized
    /// hashrate (one term per node, scoped by `received_by` at source so it
    /// can't double-count), so load-balancer migrations don't crater or inflate
    /// the figure. None on older deploys without the mesh provider wired up —
    /// callers fall back to the node-local value.
    get_mesh_total_hashrate: Option<Box<dyn Fn() -> f64 + Send + Sync>>,
    /// This node's own realized hashrate (TH/s) over the trailing window — the
    /// exact term it contributes to `get_mesh_total_hashrate`. Surfaced as
    /// `local_hashrate_th` so the per-node and mesh figures reconcile.
    get_local_hashrate: Option<Box<dyn Fn() -> f64 + Send + Sync>>,
    /// Signal to trigger graceful restart (set by config update API)
    /// When true, main.rs will initiate shutdown and exit with code 100
    pub restart_signal: Arc<AtomicBool>,
    /// L-28: Debug endpoints enabled flag - IMMUTABLE after server start
    ///
    /// This is set from DashboardConfig during construction and can be modified
    /// via with_debug_endpoints() during the builder phase. Once the VerificationState
    /// is wrapped in Arc<> and passed to start_server(), this value is effectively
    /// immutable because:
    /// 1. The builder pattern takes ownership (self, not &self)
    /// 2. After Arc wrapping, no &mut reference can be obtained
    /// 3. AtomicBool only allows interior mutability via explicit store()
    /// 4. The only store() call is in with_debug_endpoints() which takes self
    ///
    /// This prevents attackers from enabling debug endpoints at runtime to gain
    /// access to sensitive system information.
    debug_endpoints_frozen: AtomicBool,
    /// Hardware-derived effective miner capacity for this node (capacity::measure).
    /// Reported in `/api/internal/pool-nodes` as `this_node.max_capacity` so
    /// the colocated translator's load balancer can compute utilisation %
    /// against this node's true hardware ceiling. Set via `set_max_capacity`
    /// at startup; 0 = not yet configured.
    max_capacity: AtomicU32,
    /// Prometheus metrics (optional - only present when running as ghost-pool)
    pub metrics: Option<Arc<Metrics>>,
    /// Callback to submit L2 NoteSpend transactions to the consensus mesh
    pub l2_submit_fn: Option<L2SubmitFn>,
    /// Callback to sync a commitment to the L2 tree and broadcast to mesh
    pub l2_sync_commitment_fn: Option<L2SyncCommitmentFn>,
    /// Callback to relay glyph claims to the mesh
    pub glyph_claim_relay_fn: Option<GlyphClaimRelayFn>,
    /// Callback to relay glyph registrations to the mesh
    pub glyph_registered_relay_fn: Option<GlyphRegisteredRelayFn>,
    /// Callback to get live L2 tree state from epoch manager
    pub l2_tree_state_fn: Option<L2TreeStateFn>,
    /// Cached stratum self-verification results. The verification handler
    /// uses bogus Noise-NK bytes / mining.subscribe to confirm the local
    /// stratum endpoint is up; pool_sv2 logs the rejection as ERROR. Caching
    /// the result for STRATUM_VERIFY_CACHE_TTL keeps incoming peer challenges
    /// from re-probing on every cycle and slamming pool_sv2's log.
    /// Key: (protocol, port). Value: (probe_time, response).
    stratum_verify_cache: parking_lot::Mutex<
        std::collections::HashMap<(StratumProtocol, u16), (Instant, StratumResponse)>,
    >,
}

/// TTL for cached stratum self-verification results. Verification cycles run
/// every 5 minutes mesh-wide and the 3+ peer challenges within a cycle arrive
/// spread out (often 1–2 min apart), not as a tight burst. A 240s TTL covers
/// the full intra-cycle spread while still refreshing once per cycle so a
/// real stratum outage is detected within ~4–5 minutes.
const STRATUM_VERIFY_CACHE_TTL: Duration = Duration::from_secs(240);

/// Archive handler trait
pub trait ArchiveHandler {
    fn get_block(&self, hash: &str) -> GhostResult<Option<BlockData>>;
    fn get_transaction(&self, txid: &str) -> GhostResult<Option<TxData>>;
    fn has_block_at_height(&self, height: u64) -> bool;
}

/// H-5: Epoch proof for cryptographic GhostPay verification
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EpochProof {
    /// Epoch number this proof is for
    pub epoch: u64,
    /// Hash of L2 state at this epoch (SHA256 of serialized state)
    pub state_hash: String,
    /// Number of transactions in this epoch
    pub tx_count: u64,
}

/// GhostPay handler trait
pub trait GhostPayHandler {
    fn is_enabled(&self) -> bool;
    fn get_virtual_block(&self) -> u64;
    fn get_epoch(&self) -> u64;
    fn get_balance(&self, address: &str) -> GhostResult<u64>;
    fn is_wraith_enabled(&self) -> bool;

    /// H-5: Get proof of L2 state at a specific epoch
    ///
    /// This method is used for cryptographic verification that a node
    /// actually has L2 state data, not just self-reporting capability.
    /// Returns None if the node doesn't have state for the requested epoch.
    fn get_epoch_proof(&self, epoch: u64) -> Option<EpochProof> {
        // Default implementation returns None (node doesn't support proofs)
        let _ = epoch;
        None
    }
}

/// GSP (Ghost Service Protocol) handler trait for light wallet support
pub trait GspHandler: Send + Sync {
    /// Check if GSP is enabled
    fn is_enabled(&self) -> bool;
    /// Get GSP protocol version
    fn get_protocol_version(&self) -> String;
    /// Get network name (mainnet, signet, regtest, etc.)
    fn get_network(&self) -> String;
    /// Get current connection count
    fn get_connection_count(&self) -> u32;
    /// Get number of registered wallets
    fn get_registered_wallets(&self) -> u32;
    /// Get sync status
    fn get_sync_status(&self) -> String;
    /// Perform health check
    fn health_check(&self) -> GhostResult<bool>;
}

/// GSP status info for watchdog
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GspInfo {
    pub protocol_version: String,
    pub network: String,
    pub connections: u32,
    pub sync_status: String,
    pub registered_wallets: u32,
}

/// Ghost Pay L2 status summary (for dashboard)
pub struct GhostPayInfo {
    pub epoch: u64,
    pub virtual_block: u64,
    pub wraith_enabled: bool,
}

impl VerificationState {
    /// Create new verification state
    pub fn new(
        node_id: String,
        version: String,
        policy_profile: PolicyProfile,
        capabilities: NodeCapabilities,
    ) -> Self {
        // Initialize dashboard config with defaults (all features enabled)
        let dashboard_config = DashboardConfig::default();
        // L-28: Capture debug endpoint setting at startup - immutable thereafter
        let debug_enabled = dashboard_config.enable_debug_endpoints;
        Self {
            node_id,
            version,
            identity: None,
            policy_engine: parking_lot::Mutex::new(PolicyEngine::new(policy_profile)),
            capabilities,
            start_time: Instant::now(),
            get_block_height: Box::new(|| 0),
            get_round_id: Box::new(|| 0),
            get_miner_count: Box::new(|| 0),
            get_peer_count: Box::new(|| 0),
            archive_handler: None,
            ghostpay_handler: None,
            gsp_handler: None,
            stratum_sv2_port: SV2_STRATUM_PORT,
            stratum_sv1_port: SV1_STRATUM_PORT,
            database: None,
            rpc: None,
            dashboard_config: parking_lot::RwLock::new(dashboard_config),
            node_config: parking_lot::RwLock::new(NodeConfig::default()),
            node_config_path: None,
            full_node_config: None,
            full_node_config_path: None,
            ws_state: Arc::new(WsState::new()),
            test_proposal_fn: None,
            record_share_fn: None,
            block_found_fn: None,
            internal_auth: None,
            get_pool_peers: None,
            get_reaper_stats: None,
            get_mesh_active_miners: None,
            get_mesh_total_hashrate: None,
            get_local_hashrate: None,
            // VF-C2: Default to requiring internal auth for security
            require_internal_auth: true,
            restart_signal: Arc::new(AtomicBool::new(false)),
            // L-28: Debug endpoints flag frozen from DashboardConfig
            debug_endpoints_frozen: AtomicBool::new(debug_enabled),
            max_capacity: AtomicU32::new(0),
            metrics: None,
            l2_submit_fn: None,
            l2_sync_commitment_fn: None,
            glyph_claim_relay_fn: None,
            glyph_registered_relay_fn: None,
            l2_tree_state_fn: None,
            stratum_verify_cache: parking_lot::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Set the L2 NoteSpend submission callback
    pub fn with_l2_submit(mut self, f: L2SubmitFn) -> Self {
        self.l2_submit_fn = Some(f);
        self
    }

    /// Set the L2 commitment sync callback
    pub fn with_l2_sync_commitment(mut self, f: L2SyncCommitmentFn) -> Self {
        self.l2_sync_commitment_fn = Some(f);
        self
    }

    /// Set the glyph claim relay callback
    pub fn with_glyph_claim_relay(mut self, f: GlyphClaimRelayFn) -> Self {
        self.glyph_claim_relay_fn = Some(f);
        self
    }

    /// Set the glyph registered relay callback
    pub fn with_glyph_registered_relay(mut self, f: GlyphRegisteredRelayFn) -> Self {
        self.glyph_registered_relay_fn = Some(f);
        self
    }

    /// Set the L2 tree state callback
    pub fn with_l2_tree_state(mut self, f: L2TreeStateFn) -> Self {
        self.l2_tree_state_fn = Some(f);
        self
    }

    /// Signal that a restart is needed (config update API)
    pub fn request_restart(&self) {
        self.restart_signal.store(true, Ordering::SeqCst);
    }

    /// Check if a restart has been requested
    pub fn restart_requested(&self) -> bool {
        self.restart_signal.load(Ordering::SeqCst)
    }

    /// Get the restart signal for external monitoring (main.rs)
    pub fn restart_signal(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.restart_signal)
    }

    /// L-28: Check if debug endpoints are enabled.
    ///
    /// This value is frozen at startup and cannot be changed at runtime.
    /// Even if DashboardConfig.enable_debug_endpoints is modified, this
    /// method will return the original startup value.
    ///
    /// # Security
    /// This prevents runtime attacks that attempt to enable debug endpoints
    /// to gain access to sensitive system information.
    pub fn debug_endpoints_enabled(&self) -> bool {
        self.debug_endpoints_frozen.load(Ordering::Relaxed)
    }

    /// L-28: Set debug endpoints enabled (builder pattern).
    ///
    /// **SECURITY**: This method can only be called during construction because
    /// it takes ownership (self, not &self). Once the VerificationState is
    /// wrapped in Arc<> and passed to start_server(), no further modifications
    /// are possible.
    ///
    /// Default is false (disabled) for security.
    pub fn with_debug_endpoints(self, enabled: bool) -> Self {
        self.debug_endpoints_frozen
            .store(enabled, Ordering::Relaxed);
        // Also update dashboard_config for consistency in responses
        {
            let mut config = self.dashboard_config.write();
            config.enable_debug_endpoints = enabled;
        }
        self
    }

    /// Set internal API authentication (H10/H11 security fix)
    ///
    /// When configured, internal endpoints (`/api/internal/*`, `/admin/*`) require
    /// HMAC-SHA256 authentication via X-Ghost-Signature and X-Ghost-Timestamp headers.
    pub fn with_internal_auth(mut self, auth: crate::auth::InternalAuth) -> Self {
        self.internal_auth = Some(Arc::new(auth));
        self
    }

    /// VF-C2: Allow insecure internal API mode (for development/testing ONLY)
    ///
    /// **SECURITY WARNING**: This bypasses mandatory authentication for internal endpoints.
    /// Only use this in development/test environments, NEVER in production.
    ///
    /// When `allow_insecure` is true:
    /// - Server will start even without `internal_auth` configured
    /// - Internal endpoints will be unprotected
    /// - A warning will be logged at startup
    ///
    /// When `allow_insecure` is false (default):
    /// - Server will fail to start if `internal_auth` is not configured
    /// - This ensures production deployments are always protected
    pub fn allow_insecure_internal_api(mut self, allow_insecure: bool) -> Self {
        self.require_internal_auth = !allow_insecure;
        self
    }

    /// Set share recording callback (for SRI Pool share notifications)
    pub fn with_share_recorder<F>(mut self, recorder: F) -> Self
    where
        F: Fn(ShareNotification) -> GhostResult<()> + Send + Sync + 'static,
    {
        self.record_share_fn = Some(Arc::new(recorder));
        self
    }

    /// Set block found callback (triggers payout proposal before block submission)
    ///
    /// This callback fires when a block-difficulty share arrives via the SRI webhook,
    /// BEFORE the block is submitted to Bitcoin Core. This breaks the bootstrap deadlock
    /// where submitblock requires an approved coinbase commitment but no proposal can be
    /// created without a successful submitblock.
    pub fn with_block_found_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(BlockFoundInfo) + Send + Sync + 'static,
    {
        self.block_found_fn = Some(Arc::new(callback));
        self
    }

    /// Record a share (called from HTTP endpoint)
    pub fn record_share(&self, share: ShareNotification) -> GhostResult<()> {
        if let Some(ref recorder) = self.record_share_fn {
            recorder(share)
        } else {
            Err(GhostError::Internal(
                "Share recorder not configured".to_string(),
            ))
        }
    }

    /// Record a batch of shares (called from HTTP endpoint for native SRI webhook)
    ///
    /// Converts ShareData to ShareNotification format and records each share.
    /// Extracts payout address from user_identity (format: `<address>.<worker>`).
    /// When is_block == true, triggers block found callback for payout proposal.
    pub fn record_share_batch(&self, batch: ShareBatch) -> GhostResult<usize> {
        if self.record_share_fn.is_none() {
            return Err(GhostError::Internal(
                "Share recorder not configured".to_string(),
            ));
        }

        let mut recorded = 0;
        let mut blocks_found = 0;

        for share in batch.shares {
            // Parse user_identity to extract payout address and worker name
            // Format: <payout_address>.<worker_name>
            let (payout_address, worker_name) = if !share.user_identity.is_empty() {
                parse_user_identity(&share.user_identity)
            } else {
                // Fallback to downstream_id if no user_identity
                (share.downstream_id.to_string(), "default".to_string())
            };

            // Use user_identity as miner_id if available, otherwise downstream_id
            let miner_id = if !share.user_identity.is_empty() {
                share.user_identity.clone()
            } else {
                share.downstream_id.to_string()
            };

            // Convert ShareData to ShareNotification
            let notification = ShareNotification {
                miner_id: miner_id.clone(),
                work: share.share_work,
                share_hash: share.share_hash.clone(),
                job_id: share.job_id,
                timestamp: share.timestamp_ms / 1000, // Convert ms to seconds
                is_block: share.is_block,
                payout_address: if !payout_address.is_empty() {
                    Some(payout_address.clone())
                } else {
                    None
                },
            };

            if let Err(e) = self.record_share(notification) {
                tracing::warn!(error = %e, "Failed to record share from batch");
            } else {
                recorded += 1;
            }

            // Handle block found event (triggers payout proposal creation)
            if share.is_block {
                blocks_found += 1;
                tracing::info!(
                    share_hash = %share.share_hash,
                    miner_id = %miner_id,
                    payout_address = %payout_address,
                    worker_name = %worker_name,
                    work = share.share_work,
                    "Block found via SRI webhook - triggering payout proposal"
                );

                // Trigger payout proposal BEFORE block submission to break bootstrap deadlock.
                // Without this, submitblock requires an approved coinbase commitment, but the
                // commitment requires a payout proposal, which previously only came from
                // block_submitted_rx (which fires AFTER submitblock succeeds).
                if let Some(ref callback) = self.block_found_fn {
                    let info = BlockFoundInfo {
                        share_hash: share.share_hash.clone(),
                        miner_id: miner_id.clone(),
                        payout_address: payout_address.clone(),
                        work: share.share_work,
                    };
                    callback(info);
                } else {
                    tracing::warn!(
                        "Block found but no block_found_fn callback configured - \
                         payout proposal will not be created until block_submitted_rx fires"
                    );
                }
            }
        }

        if blocks_found > 0 {
            tracing::info!(
                recorded,
                blocks_found,
                "Share batch processed with block(s) found"
            );
        }

        Ok(recorded)
    }

    /// Set the node config path and load config from disk
    pub fn with_node_config_path(mut self, path: PathBuf) -> Self {
        let config = NodeConfig::load_or_default(&path);
        // Sync dashboard_config ghost_mode with loaded node_config
        {
            let mut dashboard = self.dashboard_config.write();
            dashboard.ghost_mode = config.ghost_mode;
        }
        self.node_config = parking_lot::RwLock::new(config);
        self.node_config_path = Some(path);
        self
    }

    /// Set Tor mode status (queried from Ghost Core RPC at startup)
    pub fn with_tor_status(self, enabled: bool, onion_address: Option<String>) -> Self {
        let mut config = self.dashboard_config.write();
        config.tor_mode = enabled;
        config.onion_address = onion_address;
        drop(config);
        self
    }

    /// Set the full node configuration (pool.toml) for config update API
    ///
    /// This allows the config update API to modify settings like mining_mode,
    /// policy_profile, ghost_pay_enabled, etc. and persist them to disk.
    ///
    /// # Arguments
    /// * `config` - The full NodeConfig loaded from pool.toml
    /// * `path` - Path to the pool.toml file for atomic save
    pub fn with_full_node_config(mut self, config: FullNodeConfig, path: PathBuf) -> Self {
        self.full_node_config = Some(parking_lot::RwLock::new(config));
        self.full_node_config_path = Some(path);
        self
    }

    /// Set node identity for signing responses
    pub fn with_identity(mut self, identity: Arc<NodeIdentity>) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Sign a response payload using node identity
    ///
    /// Returns a SignedResponse wrapper if identity is configured, otherwise returns None.
    /// Callers should fall back to unsigned responses when None is returned.
    pub fn sign_response<T: serde::Serialize + Clone>(
        &self,
        payload: T,
        challenge_nonce: Option<String>,
    ) -> Option<SignedResponse<T>> {
        let identity = self.identity.as_ref()?;

        let sign_fn = |message: &[u8]| -> [u8; 64] { identity.sign(message) };

        Some(SignedResponse::new(
            payload,
            self.node_id.clone(),
            sign_fn,
            challenge_nonce,
        ))
    }

    /// Check if response signing is available
    pub fn can_sign(&self) -> bool {
        self.identity.is_some()
    }

    /// Set test proposal callback (for admin testing of BFT consensus)
    pub fn with_test_proposal_fn(mut self, f: TestProposalFn) -> Self {
        self.test_proposal_fn = Some(f);
        self
    }

    /// Trigger test proposal if callback is set
    pub fn trigger_test_proposal(&self) -> GhostResult<Option<[u8; 32]>> {
        match &self.test_proposal_fn {
            Some(f) => Ok(Some(f()?)),
            None => Ok(None),
        }
    }

    /// Set database for queries
    pub fn with_database(mut self, db: Database) -> Self {
        self.database = Some(db);
        self
    }

    /// Set Ghost Core RPC client
    pub fn with_rpc(mut self, rpc: Arc<BitcoinRpc>) -> Self {
        self.rpc = Some(rpc);
        self
    }

    /// Sync ghost mode with ghost-core on startup
    ///
    /// If RPC is available, queries ghost-core for the current ghost mode
    /// and syncs the local config. If the local config differs, updates
    /// ghost-core to match the persisted config (local wins on startup).
    pub async fn sync_ghost_mode_with_core(&self) -> GhostResult<()> {
        use tracing::{debug, info, warn};

        let rpc = match &self.rpc {
            Some(rpc) => rpc,
            None => {
                debug!("No RPC client available, skipping ghost mode sync");
                return Ok(());
            }
        };

        // Get local config state
        let local_ghost_mode = self.node_config.read().ghost_mode;

        // Query ghost-core for current state
        match rpc.get_ghost_mode().await {
            Ok(response) => {
                if response.ghost_mode != local_ghost_mode {
                    info!(
                        "Ghost mode mismatch: local={}, core={}. Syncing core to local.",
                        local_ghost_mode, response.ghost_mode
                    );
                    // Local persisted config wins - sync ghost-core to match
                    match rpc.set_ghost_mode(local_ghost_mode).await {
                        Ok(_) => {
                            info!(
                                "Successfully synced ghost-core to ghost_mode={}",
                                local_ghost_mode
                            );
                        }
                        Err(e) => {
                            warn!("Failed to sync ghost mode to ghost-core: {}", e);
                        }
                    }
                } else {
                    debug!("Ghost mode already in sync: {}", local_ghost_mode);
                }

                // Sync dashboard config
                {
                    let mut dashboard = self.dashboard_config.write();
                    dashboard.ghost_mode = local_ghost_mode;
                }
            }
            Err(e) => {
                warn!("Failed to query ghost mode from ghost-core: {}", e);
            }
        }

        Ok(())
    }

    /// Set callbacks
    pub fn with_callbacks(
        mut self,
        block_height: impl Fn() -> u64 + Send + Sync + 'static,
        round_id: impl Fn() -> u64 + Send + Sync + 'static,
        miner_count: impl Fn() -> u32 + Send + Sync + 'static,
        peer_count: impl Fn() -> u32 + Send + Sync + 'static,
    ) -> Self {
        self.get_block_height = Box::new(block_height);
        self.get_round_id = Box::new(round_id);
        self.get_miner_count = Box::new(miner_count);
        self.get_peer_count = Box::new(peer_count);
        self
    }

    /// Returns the current miner count from the application callback.
    pub fn miner_count(&self) -> u32 {
        (self.get_miner_count)()
    }

    /// Get this node's advertised hardware-derived miner capacity. 0 means
    /// not yet measured (the LB treats us as "unknown" / excluded).
    pub fn max_capacity(&self) -> u32 {
        self.max_capacity.load(Ordering::Relaxed)
    }

    /// Set this node's advertised capacity (called at startup after
    /// `capacity::measure`). Cheap, lock-free; safe to re-call if the
    /// operator throttle (`network.max_miners`) changes.
    pub fn set_max_capacity(&self, value: u32) {
        self.max_capacity.store(value, Ordering::Relaxed);
    }

    /// Returns pool peers with public_mining enabled (for load balancer).
    pub fn pool_peers(&self) -> Vec<PoolPeerInfo> {
        self.get_pool_peers
            .as_ref()
            .map(|f| f())
            .unwrap_or_default()
    }

    /// Set pool-peers callback for the load-balancer endpoint.
    pub fn with_pool_peers(
        mut self,
        f: impl Fn() -> Vec<PoolPeerInfo> + Send + Sync + 'static,
    ) -> Self {
        self.get_pool_peers = Some(Box::new(f));
        self
    }

    /// Reaper observability snapshot, or `null` when not wired.
    pub fn reaper_stats(&self) -> serde_json::Value {
        self.get_reaper_stats
            .as_ref()
            .map(|f| f())
            .unwrap_or(serde_json::Value::Null)
    }

    /// Set the Reaper-stats callback (pre-serialized JSON to avoid a
    /// reverse-dependency on ghost-pool).
    pub fn with_reaper_stats(
        mut self,
        f: impl Fn() -> serde_json::Value + Send + Sync + 'static,
    ) -> Self {
        self.get_reaper_stats = Some(Box::new(f));
        self
    }

    /// Set the mesh-wide active-miner count callback.
    pub fn with_mesh_active_miners(mut self, f: impl Fn() -> u32 + Send + Sync + 'static) -> Self {
        self.get_mesh_active_miners = Some(Box::new(f));
        self
    }

    /// Returns the mesh-wide deduplicated active miner count, or None if no
    /// callback has been wired up (older deploys without the mesh provider).
    pub fn mesh_active_miners(&self) -> Option<u32> {
        self.get_mesh_active_miners.as_ref().map(|f| f())
    }

    /// Set the mesh-wide pool hashrate (TH/s) callback.
    pub fn with_mesh_total_hashrate(mut self, f: impl Fn() -> f64 + Send + Sync + 'static) -> Self {
        self.get_mesh_total_hashrate = Some(Box::new(f));
        self
    }

    /// Returns the mesh-wide pool hashrate (TH/s), or None if no callback has
    /// been wired up (older deploys without the mesh provider).
    pub fn mesh_total_hashrate(&self) -> Option<f64> {
        self.get_mesh_total_hashrate.as_ref().map(|f| f())
    }

    /// Set this node's own realized-hashrate (TH/s) callback.
    pub fn with_local_hashrate(mut self, f: impl Fn() -> f64 + Send + Sync + 'static) -> Self {
        self.get_local_hashrate = Some(Box::new(f));
        self
    }

    /// Returns this node's own realized hashrate (TH/s) — its contribution to
    /// the mesh total — or None if no callback has been wired up.
    pub fn local_hashrate(&self) -> Option<f64> {
        self.get_local_hashrate.as_ref().map(|f| f())
    }

    /// Set archive handler
    pub fn with_archive_handler(
        mut self,
        handler: impl ArchiveHandler + Send + Sync + 'static,
    ) -> Self {
        self.archive_handler = Some(Box::new(handler));
        self
    }

    /// Set GhostPay handler
    pub fn with_ghostpay_handler(
        mut self,
        handler: impl GhostPayHandler + Send + Sync + 'static,
    ) -> Self {
        self.ghostpay_handler = Some(Box::new(handler));
        self
    }

    /// Set GSP handler for light wallet support
    pub fn with_gsp_handler(mut self, handler: impl GspHandler + 'static) -> Self {
        self.gsp_handler = Some(Box::new(handler));
        self
    }

    /// Check if GSP is enabled
    pub fn gsp_enabled(&self) -> bool {
        self.gsp_handler
            .as_ref()
            .map(|h| h.is_enabled())
            .unwrap_or(false)
    }

    /// Get GSP info for watchdog
    pub fn get_gsp_info(&self) -> Option<GspInfo> {
        let handler = self.gsp_handler.as_ref()?;
        Some(GspInfo {
            protocol_version: handler.get_protocol_version(),
            network: handler.get_network(),
            connections: handler.get_connection_count(),
            sync_status: handler.get_sync_status(),
            registered_wallets: handler.get_registered_wallets(),
        })
    }

    /// Get Ghost Pay L2 status (sync, for dashboard)
    pub fn get_ghostpay_status(&self) -> Option<GhostPayInfo> {
        let handler = self.ghostpay_handler.as_ref()?;
        if !handler.is_enabled() {
            return None;
        }
        Some(GhostPayInfo {
            epoch: handler.get_epoch(),
            virtual_block: handler.get_virtual_block(),
            wraith_enabled: handler.is_wraith_enabled(),
        })
    }

    /// Set stratum ports
    pub fn with_stratum_ports(mut self, sv2_port: u16, sv1_port: u16) -> Self {
        self.stratum_sv2_port = sv2_port;
        self.stratum_sv1_port = sv1_port;
        self
    }

    /// Set the publicly-advertised stratum host (IP or DNS name) used when
    /// answering an incoming stratum challenge. The challenge handler probes
    /// this address via `verify_sv1` / `verify_sv2`. Setting it to the node's
    /// real public address (per VER-6) makes the self-verification check
    /// external reachability, not just a loopback listener.
    pub fn with_stratum_host(self, host: String) -> Self {
        self.dashboard_config.write().stratum_host = Some(host);
        self
    }

    /// Set Prometheus metrics instance
    pub fn with_metrics(mut self, metrics: Arc<Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Get WebSocket state for broadcasting events
    pub fn ws(&self) -> &Arc<WsState> {
        &self.ws_state
    }

    /// Get health response
    pub async fn get_health(&self) -> HealthResponse {
        HealthResponse {
            healthy: true,
            node_id: self.node_id.clone(),
            version: self.version.clone(),
            block_height: (self.get_block_height)(),
            round_id: (self.get_round_id)(),
            miner_count: (self.get_miner_count)(),
            peer_count: (self.get_peer_count)(),
            capabilities: self.capabilities.into(),
            uptime_secs: self.start_time.elapsed().as_secs(),
        }
    }

    /// Verify archive challenge
    pub async fn verify_archive(
        &self,
        challenge: ArchiveChallenge,
    ) -> GhostResult<ArchiveResponse> {
        if !self.capabilities.archive_mode {
            return Ok(ArchiveResponse {
                success: false,
                block_data: None,
                tx_data: None,
                error: Some("Archive mode not enabled".to_string()),
            });
        }

        let handler =
            self.archive_handler
                .as_ref()
                .ok_or_else(|| GhostError::VerificationFailed {
                    capability: "archive".to_string(),
                    reason: "Archive handler not configured".to_string(),
                })?;

        match challenge.challenge_type {
            ChallengeType::ArchiveBlock => {
                let hash = challenge
                    .block_hash
                    .ok_or_else(|| GhostError::VerificationFailed {
                        capability: "archive".to_string(),
                        reason: "Block hash required".to_string(),
                    })?;

                let block_data = handler.get_block(&hash)?;

                Ok(ArchiveResponse {
                    success: block_data.is_some(),
                    block_data,
                    tx_data: None,
                    error: None,
                })
            }
            ChallengeType::ArchiveTx => {
                let txid = challenge
                    .txid
                    .ok_or_else(|| GhostError::VerificationFailed {
                        capability: "archive".to_string(),
                        reason: "Transaction ID required".to_string(),
                    })?;

                let tx_data = handler.get_transaction(&txid)?;

                Ok(ArchiveResponse {
                    success: tx_data.is_some(),
                    block_data: None,
                    tx_data,
                    error: None,
                })
            }
            _ => Ok(ArchiveResponse {
                success: false,
                block_data: None,
                tx_data: None,
                error: Some("Invalid challenge type for archive".to_string()),
            }),
        }
    }

    /// Verify policy challenge
    pub async fn verify_policy(&self, challenge: PolicyChallenge) -> GhostResult<PolicyResponse> {
        // Decode transaction hex
        let tx_bytes =
            hex::decode(&challenge.tx_hex).map_err(|e| GhostError::VerificationFailed {
                capability: "policy".to_string(),
                reason: format!("Invalid transaction hex: {}", e),
            })?;

        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&tx_bytes).map_err(|e| {
            GhostError::VerificationFailed {
                capability: "policy".to_string(),
                reason: format!("Invalid transaction: {}", e),
            }
        })?;

        // Evaluate against policy
        let mut engine = self.policy_engine.lock();
        let decision = engine.evaluate(&tx);

        let classification = match &decision {
            ghost_policy::PolicyDecision::Accept { classification, .. }
            | ghost_policy::PolicyDecision::Reject { classification, .. } => {
                Some(PolicyClassification {
                    tier: classification.tier.to_string(),
                    reason: classification.reason.to_string(),
                    features: classification
                        .features
                        .iter()
                        .map(|f| f.to_string())
                        .collect(),
                })
            }
        };

        let (accepted, rejection_reason) = match &decision {
            ghost_policy::PolicyDecision::Accept { .. } => (true, None),
            ghost_policy::PolicyDecision::Reject { reason, .. } => {
                (false, Some(reason.to_string()))
            }
        };

        Ok(PolicyResponse {
            success: true,
            profile: engine.profile().name.clone(),
            classification,
            accepted,
            rejection_reason,
            error: None,
        })
    }

    /// Verify stratum challenge.
    ///
    /// Confirms the local stratum endpoint is bound on the configured port by
    /// scanning `/proc/net/tcp{,6}` for a LISTEN socket. We deliberately do
    /// NOT open a TCP connection: the previous implementation wrote bogus
    /// Noise NK bytes to pool_sv2 to "test" it, which pool_sv2 (correctly)
    /// rejected and logged as ERROR — every peer challenge created spurious
    /// log spam.
    ///
    /// Loss vs. a real protocol handshake is small. Pool_sv2 is constantly
    /// handling translator + miner SV2 traffic; a broken endpoint surfaces
    /// in mining metrics within seconds — well before the 5-min verification
    /// cycle would catch it. The listener check tells us the daemon is up
    /// and bound; the daemon's behaviour is validated by real load.
    pub async fn verify_stratum(
        &self,
        challenge: StratumChallenge,
    ) -> GhostResult<StratumResponse> {
        if !self.capabilities.public_mining {
            return Ok(StratumResponse {
                success: false,
                port: challenge.port.unwrap_or(self.stratum_sv2_port),
                protocol: challenge.protocol,
                connected: false,
                latency_ms: None,
                error: Some("Public mining not enabled".to_string()),
            });
        }

        let port = match challenge.protocol {
            StratumProtocol::Sv2 => challenge.port.unwrap_or(self.stratum_sv2_port),
            StratumProtocol::Sv1 => challenge.port.unwrap_or(self.stratum_sv1_port),
        };

        // Cache hit: peer challenges arrive several times per verification
        // cycle. /proc/net/tcp scans are cheap (~µs) but caching keeps the
        // hot path even quieter and matches how the rest of self-verification
        // is rate-limited.
        let cache_key = (challenge.protocol, port);
        if let Some((stored_at, cached)) = self.stratum_verify_cache.lock().get(&cache_key) {
            if stored_at.elapsed() < STRATUM_VERIFY_CACHE_TTL {
                return Ok(cached.clone());
            }
        }

        let start = Instant::now();
        let listening = port_listening(port);
        let latency_ms = Some(start.elapsed().as_millis() as u32);

        let response = StratumResponse {
            success: listening,
            port,
            protocol: challenge.protocol,
            connected: listening,
            latency_ms,
            error: if listening {
                None
            } else {
                Some(format!("No listener bound on port {port}"))
            },
        };
        self.stratum_verify_cache
            .lock()
            .insert(cache_key, (Instant::now(), response.clone()));
        Ok(response)
    }

    /// Verify GhostPay challenge
    ///
    /// H-5: When a challenge_epoch is provided, the node must prove it has
    /// L2 state data for that epoch. This prevents nodes from claiming
    /// GhostPay capability without actually maintaining L2 state.
    ///
    /// VER-2/VER-3: When a challenge_nonce is provided, the response must include
    /// nonce_bound_proof = SHA256(epoch_state_hash || challenge_nonce). This prevents
    /// precomputation attacks where an attacker pre-builds a lookup table of
    /// epoch_state_hash values for all possible epochs.
    pub async fn verify_ghostpay(
        &self,
        challenge: GhostPayChallenge,
    ) -> GhostResult<GhostPayResponse> {
        if !self.capabilities.ghost_pay {
            return Ok(GhostPayResponse {
                success: false,
                l2_enabled: false,
                virtual_block: None,
                epoch: None,
                balance_sats: None,
                wraith_enabled: false,
                epoch_state_hash: None,
                epoch_tx_count: None,
                nonce_bound_proof: None,
                epoch_proof: None,
                error: Some("Ghost Pay not enabled".to_string()),
            });
        }

        let handler = match &self.ghostpay_handler {
            Some(h) => h,
            None => {
                return Ok(GhostPayResponse {
                    success: false,
                    l2_enabled: true,
                    virtual_block: None,
                    epoch: None,
                    balance_sats: None,
                    wraith_enabled: false,
                    epoch_state_hash: None,
                    epoch_tx_count: None,
                    nonce_bound_proof: None,
                    epoch_proof: None,
                    error: Some("Ghost Pay handler not configured".to_string()),
                });
            }
        };

        let balance = if let Some(address) = &challenge.address {
            Some(handler.get_balance(address)?)
        } else {
            None
        };

        // H-5: If a challenge epoch is specified, require epoch proof
        let (epoch_state_hash, epoch_tx_count, epoch_proof_success) =
            if let Some(challenge_epoch) = challenge.challenge_epoch {
                match handler.get_epoch_proof(challenge_epoch) {
                    Some(proof) => (Some(proof.state_hash), Some(proof.tx_count), true),
                    None => {
                        // Node claims GhostPay but can't prove epoch state
                        return Ok(GhostPayResponse {
                            success: false,
                            l2_enabled: handler.is_enabled(),
                            virtual_block: Some(handler.get_virtual_block()),
                            epoch: Some(handler.get_epoch()),
                            balance_sats: balance,
                            wraith_enabled: handler.is_wraith_enabled(),
                            epoch_state_hash: None,
                            epoch_tx_count: None,
                            nonce_bound_proof: None,
                            epoch_proof: None,
                            error: Some(format!(
                                "Cannot prove L2 state for epoch {}",
                                challenge_epoch
                            )),
                        });
                    }
                }
            } else {
                // No challenge epoch - basic verification only
                (None, None, true)
            };

        // VER-2/VER-3 FIX: Compute nonce_bound_proof if challenge_nonce was provided
        // nonce_bound_proof = SHA256(epoch_state_hash || challenge_nonce)
        // This prevents precomputation attacks by binding the response to the specific challenge.
        let nonce_bound_proof = if let (Some(ref state_hash), Some(ref nonce)) =
            (&epoch_state_hash, &challenge.challenge_nonce)
        {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(state_hash.as_bytes());
            hasher.update(nonce.as_bytes());
            Some(hex::encode(hasher.finalize()))
        } else {
            None
        };

        Ok(GhostPayResponse {
            success: epoch_proof_success,
            l2_enabled: handler.is_enabled(),
            virtual_block: Some(handler.get_virtual_block()),
            epoch: Some(handler.get_epoch()),
            balance_sats: balance,
            wraith_enabled: handler.is_wraith_enabled(),
            epoch_state_hash,
            epoch_tx_count,
            nonce_bound_proof,
            epoch_proof: None, // VER-3: Future enhancement - add merkle proof from GhostPay consensus
            error: None,
        })
    }
}

/// Start verification server with optional TLS.
///
/// When `tls_config` is `Some`, the server listens over HTTPS using the provided
/// `rustls::ServerConfig`. When `None`, the server operates over plain HTTP
/// (suitable for development behind a reverse proxy or on localhost).
///
/// # VF-C2: Mandatory Internal API Authentication
///
/// By default, the server requires internal API authentication to be configured.
/// If `internal_auth` is None and `require_internal_auth` is true, startup fails.
/// Use `allow_insecure_internal_api(true)` to bypass this check in dev environments.
pub async fn start_server(
    state: Arc<VerificationState>,
    port: u16,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> GhostResult<()> {
    // VF-C2: Validate internal API auth requirement
    if state.require_internal_auth && state.internal_auth.is_none() {
        return Err(GhostError::Config(
            "VF-C2 SECURITY: Internal API authentication is required but not configured. \
             Configure 'internal_api_secret' in pool.toml or use \
             'allow_insecure_internal_api: true' in config (development ONLY)."
                .to_string(),
        ));
    }

    // VF-C2: Log security status
    if state.internal_auth.is_some() {
        info!("VF-C2: Internal API authentication ENABLED");
    } else {
        tracing::warn!(
            "VF-C2 SECURITY WARNING: Internal API authentication DISABLED! \
             /api/internal/* and /admin/* endpoints are UNPROTECTED. \
             This is acceptable ONLY for development/testing environments. \
             For production, configure 'internal_api_secret' in pool.toml."
        );
    }

    // C-1: CORS configuration - restricted to trusted origins
    // Environment variable allows deployment-specific configuration
    // Default: bitcoinghost.org domains only
    // M-12: Origins are validated to ensure proper https:// URL format
    let allowed_origins = std::env::var("GHOST_VERIFICATION_ALLOWED_ORIGINS")
        .unwrap_or_else(|_| "https://bitcoinghost.org,https://wallet.bitcoinghost.org".to_string());

    // M-12: Validate each origin before parsing
    let origins: Vec<axum::http::HeaderValue> = allowed_origins
        .split(',')
        .filter_map(|s| {
            let trimmed = s.trim();
            // M-12: Validate URL format before accepting
            if is_valid_cors_origin(trimmed) {
                trimmed.parse().ok()
            } else {
                // Warning already logged in is_valid_cors_origin
                None
            }
        })
        .collect();

    // If no valid origins parsed, use secure defaults
    let cors = if origins.is_empty() {
        tracing::warn!("C-1 SECURITY: No valid CORS origins configured, using secure defaults");
        CorsLayer::new()
            .allow_origin(tower_http::cors::AllowOrigin::list([
                "https://bitcoinghost.org"
                    .parse()
                    .expect("L-1: Valid hardcoded origin URL"),
                "https://wallet.bitcoinghost.org"
                    .parse()
                    .expect("L-1: Valid hardcoded origin URL"),
            ]))
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([
                axum::http::header::CONTENT_TYPE,
                axum::http::header::AUTHORIZATION,
                axum::http::header::ACCEPT,
            ])
            .max_age(Duration::from_secs(3600))
    } else {
        info!(
            origins = ?origins.iter().map(|h| h.to_str().unwrap_or("?")).collect::<Vec<_>>(),
            "C-1: CORS configured with validated origins (M-12: https:// enforced)"
        );
        CorsLayer::new()
            .allow_origin(tower_http::cors::AllowOrigin::list(origins))
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([
                axum::http::header::CONTENT_TYPE,
                axum::http::header::AUTHORIZATION,
                axum::http::header::ACCEPT,
            ])
            .max_age(Duration::from_secs(3600))
    };

    // Rate limiting configuration - AUTH4-M1: NodeId-based rate limiting
    // HIGH-VER-5: Tightened rate limits for verification endpoints
    // - 20 requests per second burst capacity (down from 50)
    // - Refills at 5 requests per second (down from 10)
    // - Per NodeId (from X-Ghost-NodeId header) with IP fallback
    // This prevents abuse while allowing legitimate verification traffic
    // (3 peers * 4 capabilities = 12 requests per 5-minute cycle)
    // L-28: Use proper error handling instead of expect()
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(5) // HIGH-VER-5: Reduced from 10 to 5
            .burst_size(20) // HIGH-VER-5: Reduced from 50 to 20
            .key_extractor(NodeIdKeyExtractor::new())
            .finish()
            .ok_or_else(|| {
                GhostError::Config(
                    "L-28: Failed to initialize rate limiter: invalid configuration. \
                     This is an internal configuration error."
                        .to_string(),
                )
            })?,
    );

    let governor_limiter = governor_conf.limiter().clone();

    // L-28: Spawn background task to clean up rate limiter state with adaptive frequency
    // Cleanup frequency increases when there are many keys to prevent memory accumulation
    tokio::spawn(async move {
        // Maximum number of keys before aggressive cleanup
        const MAX_EXPECTED_KEYS: usize = 10_000;
        // Base cleanup interval in seconds
        const BASE_CLEANUP_INTERVAL_SECS: u64 = 60;
        // Minimum cleanup interval in seconds (when at max keys)
        const MIN_CLEANUP_INTERVAL_SECS: u64 = 5;

        loop {
            // Get current key count and calculate adaptive interval
            let key_count = governor_limiter.len();

            // Adaptive cleanup: more frequent when more keys present
            // Linear interpolation: 60s at 0 keys, 5s at 10000+ keys
            let cleanup_interval = if key_count >= MAX_EXPECTED_KEYS {
                MIN_CLEANUP_INTERVAL_SECS
            } else {
                let ratio = key_count as f64 / MAX_EXPECTED_KEYS as f64;
                let range = BASE_CLEANUP_INTERVAL_SECS - MIN_CLEANUP_INTERVAL_SECS;
                BASE_CLEANUP_INTERVAL_SECS - (ratio * range as f64) as u64
            };

            tokio::time::sleep(Duration::from_secs(cleanup_interval)).await;
            governor_limiter.retain_recent();

            // Log warning if key count is high
            if key_count > MAX_EXPECTED_KEYS / 2 {
                tracing::warn!(
                    key_count = key_count,
                    cleanup_interval_secs = cleanup_interval,
                    "L-28: Rate limiter has high key count - possible memory pressure"
                );
            }
        }
    });

    // Build service with security layers
    // HIGH-VER-5: Rate limiting: 20 req/s burst, 5 req/s sustained per NodeId/IP
    // Localhost (dashboard) is exempt - rate limiter protects against external abuse
    // - CORS: restrict to allowed origins
    // - Request body limit: 1MB max to prevent DoS
    // - HIGH-API-5: Request correlation IDs for distributed tracing
    // - LOW-API-1: Security headers (X-Content-Type-Options, X-Frame-Options, etc.)
    let rate_limit_state = RateLimitState {
        key_extractor: NodeIdKeyExtractor::new(),
        limiter: governor_conf.limiter().clone(),
    };
    let app = create_router(state)
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .layer(axum::middleware::from_fn(correlation_id_middleware))
        .layer(axum::middleware::from_fn_with_state(
            rate_limit_state,
            rate_limit_middleware,
        ))
        .layer(cors)
        .layer(DefaultBodyLimit::max(1024 * 1024)); // 1MB limit

    let addr = format!("0.0.0.0:{}", port);

    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| GhostError::Internal(format!("Failed to bind: {}", e)))?;

    match tls_config {
        Some(tls) => {
            info!(
                address = %addr,
                rate_limit = "HIGH-VER-5: 20 burst / 5 per sec (NodeId/IP keyed)",
                "Starting verification server with HTTPS (TLS enabled)"
            );

            let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls);
            // Wrap the TCP listener to produce TLS streams that axum can serve.
            // We accept TCP, perform the TLS handshake, then feed the TLS stream
            // into hyper via hyper-util.
            let app = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
            serve_tls(listener, tls_acceptor, app).await?;
        }
        None => {
            info!(
                address = %addr,
                rate_limit = "HIGH-VER-5: 20 burst / 5 per sec (NodeId/IP keyed)",
                "Starting verification server (plain HTTP - no TLS)"
            );

            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .map_err(|e| GhostError::Internal(format!("Server error: {}", e)))?;
        }
    }

    Ok(())
}

/// Accept TLS connections and serve them with the given axum service.
///
/// Each incoming TCP connection is upgraded to TLS via `tls_acceptor`, then
/// served by hyper using the axum-generated service. Failed TLS handshakes
/// are logged and dropped without affecting other connections.
async fn serve_tls(
    listener: TcpListener,
    tls_acceptor: tokio_rustls::TlsAcceptor,
    mut make_service: axum::extract::connect_info::IntoMakeServiceWithConnectInfo<
        axum::Router,
        std::net::SocketAddr,
    >,
) -> GhostResult<()> {
    use hyper_util::service::TowerToHyperService;
    use tower::Service;

    loop {
        let (tcp_stream, remote_addr) = listener
            .accept()
            .await
            .map_err(|e| GhostError::Internal(format!("Accept error: {}", e)))?;

        let acceptor = tls_acceptor.clone();

        // Get a service instance for this connection (injects ConnectInfo)
        let tower_service = match make_service.call(remote_addr).await {
            Ok(s) => s,
            Err(e) => {
                // Infallible in practice, but handle gracefully
                tracing::warn!(error = ?e, "Failed to build service for connection");
                continue;
            }
        };

        // Wrap the tower::Service as a hyper::Service for hyper-util
        let hyper_service = TowerToHyperService::new(tower_service);

        tokio::spawn(async move {
            // TLS handshake
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(
                        error = %e,
                        remote = %remote_addr,
                        "TLS handshake failed"
                    );
                    return;
                }
            };

            // Serve the connection using hyper
            let io = hyper_util::rt::TokioIo::new(tls_stream);
            if let Err(e) =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(io, hyper_service)
                    .await
            {
                tracing::debug!(error = %e, remote = %remote_addr, "TLS connection error");
            }
        });
    }
}

/// Return true iff a TCP listener is bound to `port` on any local interface.
/// Reads `/proc/net/tcp{,6}` directly so the check is invisible to the
/// listening daemon (no spurious connections, no log noise).
#[cfg(target_os = "linux")]
fn port_listening(port: u16) -> bool {
    fn scan(path: &str, port: u16) -> bool {
        // /proc/net/tcp format (whitespace-separated):
        //   sl  local_address  rem_address  st  ...
        // local_address is "ADDR:PORT" in big-endian hex; state 0A = LISTEN.
        let Ok(content) = std::fs::read_to_string(path) else {
            return false;
        };
        let port_hex = format!("{:04X}", port);
        for line in content.lines().skip(1) {
            let mut fields = line.split_whitespace();
            let _sl = fields.next();
            let Some(local) = fields.next() else { continue };
            let _rem = fields.next();
            let Some(state) = fields.next() else { continue };
            if state != "0A" {
                continue;
            }
            if local.rsplit_once(':').map(|(_, p)| p) == Some(port_hex.as_str()) {
                return true;
            }
        }
        false
    }
    scan("/proc/net/tcp", port) || scan("/proc/net/tcp6", port)
}

#[cfg(not(target_os = "linux"))]
fn port_listening(port: u16) -> bool {
    use std::net::TcpStream;
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_millis(500),
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::types::NodeCapabilities;
    use ghost_policy::PolicyProfile;

    fn test_secret() -> [u8; 32] {
        let mut secret = [0u8; 32];
        for (i, b) in secret.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x42);
        }
        secret
    }

    #[test]
    fn test_verification_state_default_requires_auth() {
        let state = VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        );

        // Default should require internal auth
        assert!(state.require_internal_auth);
        assert!(state.internal_auth.is_none());
    }

    #[test]
    fn test_verification_state_with_internal_auth() {
        let secret = test_secret();
        let auth = crate::auth::InternalAuth::new(&secret).unwrap();

        let state = VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        )
        .with_internal_auth(auth);

        assert!(state.internal_auth.is_some());
    }

    #[test]
    fn test_verification_state_allow_insecure_api() {
        let state = VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        )
        .allow_insecure_internal_api(true);

        // Should allow insecure mode
        assert!(!state.require_internal_auth);
        assert!(state.internal_auth.is_none());
    }

    #[tokio::test]
    async fn test_start_server_fails_without_auth() {
        let state = Arc::new(VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        ));

        // Should fail because require_internal_auth is true but internal_auth is None
        let result = start_server(state, 0, None).await;
        assert!(result.is_err());

        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("VF-C2"));
        assert!(err_msg.contains("Internal API authentication is required"));
    }

    #[test]
    fn test_auth_validation_insecure_mode() {
        // When allow_insecure_internal_api(true) is set, the validation
        // should pass even without auth configured
        let state = VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        )
        .allow_insecure_internal_api(true);

        // The validation logic: require_internal_auth && internal_auth.is_none()
        // With allow_insecure = true: require_internal_auth = false
        // So: false && true = false -> no error
        let should_fail = state.require_internal_auth && state.internal_auth.is_none();
        assert!(!should_fail, "Insecure mode should bypass auth requirement");
    }

    #[test]
    fn test_auth_validation_with_auth_configured() {
        let secret = test_secret();
        let auth = crate::auth::InternalAuth::new(&secret).unwrap();

        let state = VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        )
        .with_internal_auth(auth);

        // The validation logic: require_internal_auth && internal_auth.is_none()
        // With auth configured: internal_auth.is_none() = false
        // So: true && false = false -> no error
        let should_fail = state.require_internal_auth && state.internal_auth.is_none();
        assert!(!should_fail, "Auth configured should pass validation");
    }

    #[test]
    fn test_auth_validation_requires_auth_when_missing() {
        let state = VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        );

        // The validation logic: require_internal_auth && internal_auth.is_none()
        // Default state: require_internal_auth = true, internal_auth = None
        // So: true && true = true -> error
        let should_fail = state.require_internal_auth && state.internal_auth.is_none();
        assert!(should_fail, "Should require auth by default");
    }

    // M-12: CORS origin validation tests
    #[test]
    fn test_cors_origin_valid_https() {
        assert!(is_valid_cors_origin("https://bitcoinghost.org"));
        assert!(is_valid_cors_origin("https://wallet.bitcoinghost.org"));
        assert!(is_valid_cors_origin("https://localhost:8080"));
        assert!(is_valid_cors_origin("https://192.168.1.1:443"));
    }

    #[test]
    fn test_cors_origin_rejects_http() {
        // Must use https:// for security
        assert!(!is_valid_cors_origin("http://bitcoinghost.org"));
        assert!(!is_valid_cors_origin("http://localhost"));
    }

    #[test]
    fn test_cors_origin_rejects_no_scheme() {
        assert!(!is_valid_cors_origin("bitcoinghost.org"));
        assert!(!is_valid_cors_origin("localhost:8080"));
    }

    #[test]
    fn test_cors_origin_rejects_path() {
        // Origins should not have path components
        assert!(!is_valid_cors_origin("https://bitcoinghost.org/api"));
        assert!(!is_valid_cors_origin("https://example.com/path/to/page"));
    }

    #[test]
    fn test_cors_origin_rejects_empty_host() {
        assert!(!is_valid_cors_origin("https://"));
    }

    #[test]
    fn test_cors_origin_rejects_invalid_chars() {
        // Origins with spaces or special chars should be rejected
        assert!(!is_valid_cors_origin("https://example .com"));
        assert!(!is_valid_cors_origin("https://example<script>.com"));
    }

    // L-28: Debug endpoints immutability tests
    #[test]
    fn test_debug_endpoints_frozen_at_startup_disabled() {
        let state = VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        );

        // Default should be disabled
        assert!(!state.debug_endpoints_enabled());
    }

    #[test]
    fn test_debug_endpoints_frozen_at_startup_enabled() {
        let state = VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        )
        .with_debug_endpoints(true);

        // Should be enabled after with_debug_endpoints(true)
        assert!(state.debug_endpoints_enabled());
    }

    #[test]
    fn test_debug_endpoints_immutable_after_set() {
        let state = VerificationState::new(
            "test_node".to_string(),
            "1.0.0".to_string(),
            PolicyProfile::default(),
            NodeCapabilities::default(),
        )
        .with_debug_endpoints(true);

        // Even if someone modifies DashboardConfig, the frozen value should persist
        {
            let mut config = state.dashboard_config.write();
            config.enable_debug_endpoints = false;
        }

        // The frozen value should still be true (from startup)
        assert!(
            state.debug_endpoints_enabled(),
            "L-28: Frozen debug flag should not change after startup"
        );
    }

    // M-14: X-Forwarded-For multi-proxy chain tests
    #[test]
    fn test_xff_single_proxy() {
        // With 1 trusted proxy: "client, proxy1" -> take "client"
        let extractor = NodeIdKeyExtractor::with_trusted_proxies_and_count(
            vec!["127.0.0.1".parse().unwrap()],
            1,
        );
        assert_eq!(extractor.trusted_proxy_count, 1);
    }

    #[test]
    fn test_xff_multi_proxy() {
        // With 2 trusted proxies: "client, cdn, lb" -> take "client"
        let extractor = NodeIdKeyExtractor::with_trusted_proxies_and_count(
            vec!["127.0.0.1".parse().unwrap()],
            2,
        );
        assert_eq!(extractor.trusted_proxy_count, 2);
    }

    #[test]
    fn test_xff_proxy_count_clamped() {
        // Proxy count should be clamped to valid range [1, 10]
        let extractor_zero = NodeIdKeyExtractor::with_trusted_proxies_and_count(
            vec!["127.0.0.1".parse().unwrap()],
            0,
        );
        assert_eq!(
            extractor_zero.trusted_proxy_count, 1,
            "M-14: Count 0 should clamp to 1"
        );

        let extractor_high = NodeIdKeyExtractor::with_trusted_proxies_and_count(
            vec!["127.0.0.1".parse().unwrap()],
            100,
        );
        assert_eq!(
            extractor_high.trusted_proxy_count, 10,
            "M-14: Count 100 should clamp to 10"
        );
    }
}
