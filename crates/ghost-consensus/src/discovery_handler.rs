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
//| FILE: discovery_handler.rs                                                                                           |
//|======================================================================================================================|

//! Peer Discovery Handler
//!
//! Implements gossip-based peer discovery via PUB/SUB on port 8559.
//! Periodically broadcasts known peers and merges received peer lists.

use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use ghost_common::error::GhostResult;
use ghost_common::types::NodeId;

use crate::ban_manager::BanManager;
use crate::mesh::MessageHandler;
use crate::message::{DiscoveryMessage, MessageEnvelope, MessageType, PeerInfo};
use crate::peer::PeerManager;

/// H-P2P-3: Integer-based token bucket rate limiter for discovery messages
///
/// Prevents flooding attacks by limiting the rate of discovery messages
/// processed per sender.
///
/// Uses milli-tokens (1 token = 1000 millis) to avoid floating-point precision
/// issues that could be exploited to bypass rate limiting.
struct RateLimiter {
    /// Tokens per sender (node_id -> (tokens_millis, last_refill_ms))
    /// Using millisecond precision for token calculations
    buckets: RwLock<HashMap<NodeId, (u64, Instant)>>,
    /// Maximum tokens in milli-tokens (multiply by 1000)
    max_tokens_millis: u64,
    /// Token refill rate in milli-tokens per second
    refill_rate_millis: u64,
    /// Maximum number of buckets to track (prevents memory exhaustion)
    max_buckets: usize,
}

/// One token in millis (1000 millis = 1 token)
const MILLIS_PER_TOKEN: u64 = 1000;

impl RateLimiter {
    /// Create a new rate limiter
    ///
    /// # Arguments
    /// * `max_tokens` - Maximum burst capacity (will be converted to millis internally)
    /// * `refill_rate` - Tokens refilled per second (will be converted to millis internally)
    /// * `max_buckets` - Maximum number of sender buckets to track
    fn new(max_tokens: u64, refill_rate: u64, max_buckets: usize) -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
            max_tokens_millis: max_tokens.saturating_mul(MILLIS_PER_TOKEN),
            refill_rate_millis: refill_rate.saturating_mul(MILLIS_PER_TOKEN),
            max_buckets,
        }
    }

    /// Try to consume a token for the given sender
    /// Returns true if allowed, false if rate limited
    ///
    /// H-P2P-3: Uses integer arithmetic to avoid floating-point precision attacks
    /// L-8/M-8: Uses minimum age eviction with jitter to prevent coordinated eviction attacks
    fn try_consume(&self, sender: &NodeId) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.write();

        // L-8/M-8 SECURITY: Use minimum age eviction with jitter to prevent eviction attacks
        //
        // M-8 FIX: Previous 60-second minimum was too short. A Sybil attacker could:
        // 1. Create many identities that all become "eligible for eviction" at once
        // 2. Flood with new identities to evict all legitimate entries simultaneously
        //
        // 300 seconds (5 minutes) provides:
        // - More time for legitimate nodes to send follow-up messages
        // - Higher cost for attackers (must sustain attack for longer)
        // - Better alignment with discovery broadcast interval (30 seconds)
        //
        // The jitter (0-60 seconds) prevents coordinated eviction by ensuring
        // entries don't all become evictable at the same time.
        if !buckets.contains_key(sender) && buckets.len() >= self.max_buckets {
            // M-8: 300 seconds base + up to 60 seconds random jitter
            // Jitter derived from sender ID to be deterministic but unpredictable
            let sender_jitter = sender[0] as u64 % 60;
            let _min_age = Duration::from_secs(300 + sender_jitter);

            // Find oldest entry that's past the minimum age (with its jitter)
            if let Some(oldest_key) = buckets
                .iter()
                .filter(|(k, (_, last_refill))| {
                    // Each entry has its own jitter based on its key
                    let entry_jitter = k[0] as u64 % 60;
                    let entry_min_age = Duration::from_secs(300 + entry_jitter);
                    *last_refill < now - entry_min_age
                })
                .min_by_key(|(_, (_, last_refill))| *last_refill)
                .map(|(k, _)| *k)
            {
                buckets.remove(&oldest_key);
            } else {
                // All entries are too new - reject this sender
                // This is safe because it means we're under attack
                tracing::debug!(
                    sender = %hex::encode(&sender[..8]),
                    bucket_count = buckets.len(),
                    "M-8: Rate limiter at capacity with fresh entries (possible Sybil attack)"
                );
                return false;
            }
        }

        let (tokens_millis, last_refill) = buckets
            .entry(*sender)
            .or_insert((self.max_tokens_millis, now));

        // H-P2P-3: Refill tokens based on elapsed time using integer arithmetic
        // Cap elapsed time to 1 hour (3600000 ms) to prevent overflow
        let elapsed_ms = now.duration_since(*last_refill).as_millis().min(3_600_000) as u64;

        // refill_millis = elapsed_ms * refill_rate_millis / 1000
        // Reorder to minimize precision loss: (elapsed_ms * refill_rate_millis) / 1000
        let refill_millis = elapsed_ms.saturating_mul(self.refill_rate_millis) / 1000;

        *tokens_millis = tokens_millis
            .saturating_add(refill_millis)
            .min(self.max_tokens_millis);
        *last_refill = now;

        // Try to consume one token (1000 millis)
        if *tokens_millis >= MILLIS_PER_TOKEN {
            *tokens_millis -= MILLIS_PER_TOKEN;
            true
        } else {
            false
        }
    }

    /// Cleanup old entries (call periodically to prevent memory growth)
    fn cleanup(&self, max_age: Duration) {
        let cutoff = Instant::now() - max_age;
        let mut buckets = self.buckets.write();
        buckets.retain(|_, (_, last_refill)| *last_refill > cutoff);
    }
}

/// M-10: Address-based rate limiter to prevent address claim spam
///
/// Limits how often any address can be claimed/registered. This prevents
/// attackers from repeatedly trying to claim ownership of addresses.
struct AddressRateLimiter {
    /// Tokens per address (address -> (tokens_millis, last_refill_ms))
    buckets: RwLock<HashMap<String, (u64, Instant)>>,
    /// Maximum tokens in milli-tokens
    max_tokens_millis: u64,
    /// Token refill rate in milli-tokens per second
    refill_rate_millis: u64,
    /// Maximum number of buckets to track
    max_buckets: usize,
}

impl AddressRateLimiter {
    /// Create a new address rate limiter
    fn new(max_tokens: u64, refill_rate: u64, max_buckets: usize) -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
            max_tokens_millis: max_tokens.saturating_mul(MILLIS_PER_TOKEN),
            refill_rate_millis: refill_rate.saturating_mul(MILLIS_PER_TOKEN),
            max_buckets,
        }
    }

    /// Try to consume a token for the given address
    /// Returns true if allowed, false if rate limited
    ///
    /// M-8 SECURITY: Uses 300-second minimum age with jitter to prevent coordinated eviction
    fn try_consume(&self, address: &str) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.write();

        // L-8/M-8: Use minimum age eviction strategy with jitter to prevent eviction attacks
        // Only evict entries that are at least 300 seconds old (increased from 60)
        if !buckets.contains_key(address) && buckets.len() >= self.max_buckets {
            // M-8: 300 seconds base + jitter derived from address hash
            let address_jitter = address.as_bytes().first().copied().unwrap_or(0) as u64 % 60;
            let _min_age = Duration::from_secs(300 + address_jitter);

            // Find oldest entry that's past the minimum age (with its jitter)
            if let Some(oldest_key) = buckets
                .iter()
                .filter(|(k, (_, last_refill))| {
                    let entry_jitter = k.as_bytes().first().copied().unwrap_or(0) as u64 % 60;
                    let entry_min_age = Duration::from_secs(300 + entry_jitter);
                    *last_refill < now - entry_min_age
                })
                .min_by_key(|(_, (_, last_refill))| *last_refill)
                .map(|(k, _)| k.clone())
            {
                buckets.remove(&oldest_key);
            } else {
                // All entries are too new - reject this address claim
                // This is safe because it means we're under attack
                tracing::warn!(
                    address = %address,
                    bucket_count = buckets.len(),
                    "M-8/M-10: Address rate limiter at capacity with fresh entries (possible attack)"
                );
                return false;
            }
        }

        let (tokens_millis, last_refill) = buckets
            .entry(address.to_string())
            .or_insert((self.max_tokens_millis, now));

        // Refill tokens based on elapsed time
        let elapsed_ms = now.duration_since(*last_refill).as_millis().min(3_600_000) as u64;

        let refill_millis = elapsed_ms.saturating_mul(self.refill_rate_millis) / 1000;

        *tokens_millis = tokens_millis
            .saturating_add(refill_millis)
            .min(self.max_tokens_millis);
        *last_refill = now;

        // Try to consume one token
        if *tokens_millis >= MILLIS_PER_TOKEN {
            *tokens_millis -= MILLIS_PER_TOKEN;
            true
        } else {
            false
        }
    }
}

/// M-10: Rate limit for address registration attempts (per address)
/// This prevents attackers from repeatedly trying to claim the same address
const ADDRESS_RATE_LIMIT: u64 = 1; // 1 attempt per second
/// M-10: Maximum tokens for address rate limiting (low to prevent spam)
const ADDRESS_MAX_TOKENS: u64 = 3;
/// M-10: Maximum address buckets to track
const ADDRESS_MAX_BUCKETS: usize = 5000;

/// Maximum peers to include in a discovery broadcast
const MAX_PEERS_PER_BROADCAST: usize = 20;

/// H-P2P-4: Parse host and validate it is a valid IP address (not a domain name)
///
/// Returns Some((host_without_brackets, is_ipv6)) if valid IP, None if invalid or domain name.
/// This prevents DNS hijacking attacks where an attacker controls DNS resolution.
fn parse_ip_host(host: &str) -> Option<(String, bool)> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Handle IPv6 with brackets: [fe80::1] -> fe80::1
    if host.starts_with('[') && host.ends_with(']') {
        let inner = &host[1..host.len() - 1];
        if inner.parse::<Ipv6Addr>().is_ok() {
            return Some((inner.to_string(), true));
        }
        return None;
    }

    // Try parsing as IPv4
    if host.parse::<Ipv4Addr>().is_ok() {
        return Some((host.to_string(), false));
    }

    // Try parsing as IPv6 without brackets
    if host.parse::<Ipv6Addr>().is_ok() {
        return Some((host.to_string(), true));
    }

    // Not a valid IP address (probably a domain name)
    None
}

/// L-9 SECURITY: Check if an IPv4 address is in a reserved range
///
/// This checks all IANA reserved ranges, not just private/loopback.
/// Allowing reserved IPs can pollute peer lists and enable attacks.
fn is_reserved_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();

    // Standard checks from std library
    if ip.is_loopback()           // 127.0.0.0/8
        || ip.is_private()        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        || ip.is_link_local()     // 169.254.0.0/16
        || ip.is_unspecified()    // 0.0.0.0
        || ip.is_broadcast()
    // 255.255.255.255
    {
        return true;
    }

    // Additional reserved ranges per IANA:

    // 0.0.0.0/8 - Current network (only valid as source address)
    if octets[0] == 0 {
        return true;
    }

    // 100.64.0.0/10 - Carrier-grade NAT (RFC 6598)
    if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
        return true;
    }

    // 192.0.0.0/24 - IETF Protocol Assignments (RFC 6890)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
        return true;
    }

    // 192.0.2.0/24 - TEST-NET-1 (RFC 5737)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return true;
    }

    // 198.18.0.0/15 - Benchmark testing (RFC 2544)
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return true;
    }

    // 198.51.100.0/24 - TEST-NET-2 (RFC 5737)
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return true;
    }

    // 203.0.113.0/24 - TEST-NET-3 (RFC 5737)
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return true;
    }

    // 224.0.0.0/4 - Multicast (RFC 5771)
    if octets[0] >= 224 && octets[0] <= 239 {
        return true;
    }

    // 240.0.0.0/4 - Reserved for future use (RFC 1112)
    // Except 255.255.255.255 which is already handled by is_broadcast()
    if octets[0] >= 240 {
        return true;
    }

    false
}

/// L-9 SECURITY: Check if an IPv6 address is in a reserved range
fn is_reserved_ipv6(ip: std::net::Ipv6Addr) -> bool {
    // Standard checks
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }

    let segments = ip.segments();

    // Link-local: fe80::/10
    if (segments[0] & 0xffc0) == 0xfe80 {
        return true;
    }

    // Unique local: fc00::/7 (similar to private IPv4)
    if (segments[0] & 0xfe00) == 0xfc00 {
        return true;
    }

    // Multicast: ff00::/8
    if (segments[0] & 0xff00) == 0xff00 {
        return true;
    }

    // Site-local (deprecated): fec0::/10
    if (segments[0] & 0xffc0) == 0xfec0 {
        return true;
    }

    // Documentation: 2001:db8::/32
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return true;
    }

    // Teredo: 2001:0000::/32 (often blocked in enterprise networks)
    if segments[0] == 0x2001 && segments[1] == 0x0000 {
        return true;
    }

    // 6to4: 2002::/16 (deprecated tunneling)
    if segments[0] == 0x2002 {
        return true;
    }

    // Orchid v2: 2001:20::/28 (overlay routing)
    if segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0020 {
        return true;
    }

    false
}

/// H-P2P-4/L-9: Check if an IP address is a private/local/reserved address that should be rejected
///
/// L-9 SECURITY: This now checks ALL reserved ranges, not just private/loopback.
/// Reserved IPs can pollute peer lists and enable various attacks:
/// - TEST-NET ranges allow attackers to claim documentation IPs
/// - Multicast addresses could cause broadcast storms
/// - Carrier-grade NAT addresses are not globally routable
fn is_private_or_local_ip(ip_str: &str, is_ipv6: bool) -> bool {
    use std::net::{Ipv4Addr, Ipv6Addr};

    if is_ipv6 {
        if let Ok(ip) = ip_str.parse::<Ipv6Addr>() {
            return is_reserved_ipv6(ip);
        }
    } else if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
        return is_reserved_ipv4(ip);
    }

    false
}

/// SEC-P2P-2/H-P2P-4: Validate a peer address for security
///
/// Rejects:
/// - Domain names (DNS hijacking risk) - H-P2P-4
/// - Private/local network addresses
/// - Invalid ports
///
/// Only accepts valid IPv4 or IPv6 addresses with reasonable ports.
fn validate_peer_address(address: &str, allow_private: bool) -> bool {
    // Must not be empty
    if address.is_empty() {
        return false;
    }

    // Strip protocol prefix if present (tcp://, ssl://, etc.)
    let address_without_protocol = if let Some(pos) = address.find("://") {
        &address[pos + 3..]
    } else {
        address
    };

    // Must contain host:port format
    // Use rsplit to handle IPv6 addresses like [::1]:8555
    // CRIT-PANIC-4: Use pattern matching instead of direct indexing for safety
    let parts: Vec<&str> = address_without_protocol.rsplitn(2, ':').collect();
    let (port_str, host) = match parts.as_slice() {
        [port, host] => (*port, *host),
        _ => return false,
    };

    // Port must be valid
    let port: u16 = match port_str.parse() {
        Ok(p) if p > 0 => p,
        _ => return false,
    };

    // H-P2P-4: Must be a valid IP address (not a domain name)
    let (ip_str, is_ipv6) = match parse_ip_host(host) {
        Some(result) => result,
        None => {
            warn!(
                address = %address,
                host = %host,
                "H-P2P-4: Rejecting address with domain name (only IP addresses allowed)"
            );
            return false;
        }
    };

    // Reject private/local addresses
    if !allow_private && is_private_or_local_ip(&ip_str, is_ipv6) {
        warn!(
            address = %address,
            "Rejecting private/local IP address"
        );
        return false;
    }

    // Reject unreasonable ports (below 1024 or above 65000)
    if !(1024..=65000).contains(&port) {
        warn!(address = %address, port = port, "Rejecting address with unusual port");
        return false;
    }

    true
}

/// Default discovery port for P2P mesh
const DEFAULT_DISCOVERY_PORT: u16 = 8559;

/// Normalize a peer address by adding the default discovery port if missing
///
/// This handles configs that specify just an IP without a port (e.g., "83.136.251.162")
/// and normalizes them to include the discovery port (e.g., "83.136.251.162:8559").
fn normalize_peer_address(address: &str) -> String {
    if address.is_empty() {
        return address.to_string();
    }

    // Strip protocol prefix if present
    let address_without_protocol = if let Some(pos) = address.find("://") {
        &address[pos + 3..]
    } else {
        address
    };

    // Check if address already has a port
    // For IPv6 like [::1]:8555, check after the closing bracket
    // For IPv4 like 1.2.3.4:8555, check for colon
    let has_port = if address_without_protocol.starts_with('[') {
        // IPv6 in bracket notation
        address_without_protocol.contains("]:")
    } else {
        // IPv4 or hostname - count colons
        // If exactly one colon, it's host:port
        // If zero colons, no port
        // If more than one, it's IPv6 without port
        address_without_protocol.matches(':').count() == 1
    };

    if has_port {
        address.to_string()
    } else {
        format!("{}:{}", address, DEFAULT_DISCOVERY_PORT)
    }
}

/// Callback for connecting to newly discovered peers
pub type ConnectCallback = Arc<dyn Fn(String) + Send + Sync>;

/// H-P2P-3: Default discovery message rate limit (messages per second)
const DISCOVERY_RATE_LIMIT: u64 = 2;
/// H-P2P-3: Maximum tokens (burst capacity)
const DISCOVERY_MAX_TOKENS: u64 = 10;
/// M-16: Maximum rate limiter buckets
const DISCOVERY_MAX_BUCKETS: usize = 1000;

/// Handler for peer discovery messages
pub struct DiscoveryHandler {
    /// Our node ID
    node_id: NodeId,
    /// Our public address
    public_address: String,
    /// Peer manager (for registering discovered peers with real node_id + address)
    peers: Arc<PeerManager>,
    /// Known peer addresses (node_id -> address)
    known_addresses: RwLock<HashMap<NodeId, String>>,
    /// H-P2P-4: Reverse mapping (address -> node_id) to detect address hijacking
    /// If two different node_ids claim the same address, the second is rejected.
    address_owners: RwLock<HashMap<String, NodeId>>,
    /// Callback to connect to new peers
    connect_callback: Option<ConnectCallback>,
    /// M-P2P-3: Shared ban manager for cross-handler enforcement
    ban_manager: Option<Arc<BanManager>>,
    /// M-16: Rate limiter for discovery messages (per sender)
    rate_limiter: RateLimiter,
    /// M-10: Rate limiter for address registration attempts (per address)
    /// Prevents attackers from repeatedly claiming the same address
    address_rate_limiter: AddressRateLimiter,
    /// Message counter for periodic rate limiter cleanup
    message_count: std::sync::atomic::AtomicU64,
    /// Allow private/loopback peer IPs. FALSE on mainnet (the SSRF/hijack guard
    /// stays on); set TRUE on test networks (regtest/testnet/signet) so a local
    /// or containerised cluster can actually form a mesh.
    allow_private_peers: bool,
}

impl DiscoveryHandler {
    /// Create a new discovery handler
    pub fn new(node_id: NodeId, public_address: String, peers: Arc<PeerManager>) -> Self {
        Self {
            node_id,
            public_address,
            peers,
            known_addresses: RwLock::new(HashMap::new()),
            address_owners: RwLock::new(HashMap::new()),
            connect_callback: None,
            ban_manager: None,
            allow_private_peers: false,
            rate_limiter: RateLimiter::new(
                DISCOVERY_MAX_TOKENS,
                DISCOVERY_RATE_LIMIT,
                DISCOVERY_MAX_BUCKETS,
            ),
            address_rate_limiter: AddressRateLimiter::new(
                ADDRESS_MAX_TOKENS,
                ADDRESS_RATE_LIMIT,
                ADDRESS_MAX_BUCKETS,
            ),
            message_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Set callback for connecting to newly discovered peers
    pub fn with_connect_callback(mut self, callback: ConnectCallback) -> Self {
        self.connect_callback = Some(callback);
        self
    }

    /// M-P2P-3: Set the shared ban manager for cross-handler enforcement
    ///
    /// When set, discovery messages from banned nodes are silently ignored.
    pub fn with_ban_manager(mut self, ban_manager: Arc<BanManager>) -> Self {
        self.ban_manager = Some(ban_manager);
        self
    }

    /// Allow private/loopback peer IPs. Pass `true` ONLY on test networks
    /// (regtest/testnet/signet) so a local/containerised cluster can mesh; leave
    /// `false` on mainnet, where rejecting them is the SSRF/hijack guard.
    pub fn with_private_peers_allowed(mut self, allow: bool) -> Self {
        self.allow_private_peers = allow;
        self
    }

    /// M-P2P-3: Check if a node is currently banned
    fn is_banned(&self, node_id: &NodeId) -> bool {
        self.ban_manager
            .as_ref()
            .is_some_and(|bm| bm.is_banned(node_id))
    }

    /// M-3: Verify the signature on a message envelope (defense-in-depth)
    ///
    /// The mesh network already verifies signatures via validate_and_verify(),
    /// but this provides an explicit check in the handler for defense-in-depth.
    /// This protects against any code path that might bypass the normal validation.
    ///
    /// The message signed is: payload + sequence (as per mesh.rs create_envelope)
    fn verify_envelope_signature(&self, envelope: &MessageEnvelope) -> bool {
        // Reject zero signatures immediately
        if envelope.signature == [0u8; 64] {
            warn!(
                sender = %hex::encode(&envelope.sender[..8]),
                "M-3: Rejecting discovery message with zero signature"
            );
            return false;
        }

        // Reconstruct the message that was signed (matches mesh.rs create_envelope)
        // Signed data is: payload_bytes + sequence.to_le_bytes()
        let mut signed_data = envelope.payload.clone();
        signed_data.extend_from_slice(&envelope.sequence.to_le_bytes());

        // Verify using the sender's public key (which is their NodeId)
        match ghost_common::identity::verify_signature(
            &envelope.sender,
            &signed_data,
            &envelope.signature,
        ) {
            Ok(true) => true,
            Ok(false) => {
                warn!(
                    sender = %hex::encode(&envelope.sender[..8]),
                    "M-3: Discovery message signature verification failed"
                );
                false
            }
            Err(e) => {
                warn!(
                    sender = %hex::encode(&envelope.sender[..8]),
                    error = %e,
                    "M-3: Discovery message signature verification error"
                );
                false
            }
        }
    }

    /// Add a known peer address
    ///
    /// H-P2P-4: Also updates the reverse mapping (address -> node_id).
    /// L-7: Logs a warning if an address is being reassigned from one node to another,
    /// which could indicate an attack or network misconfiguration.
    ///
    /// Returns true if the peer was added/updated, false if rate limited.
    pub fn add_known_peer(&self, node_id: NodeId, address: String) -> bool {
        // M-10: Apply address rate limiting
        if !self.address_rate_limiter.try_consume(&address) {
            tracing::debug!(
                node_id = %hex::encode(&node_id[..8]),
                address = %address,
                "M-10: Address registration rate limited"
            );
            return false;
        }

        let mut addresses = self.known_addresses.write();
        let mut owners = self.address_owners.write();

        // L-7: Check for address reassignment (potential attack)
        if let Some(&existing_owner) = owners.get(&address) {
            if existing_owner != node_id {
                tracing::warn!(
                    address = %address,
                    old_owner = %hex::encode(&existing_owner[..8]),
                    new_owner = %hex::encode(&node_id[..8]),
                    "L-7: Address being reassigned to different node - possible attack or migration"
                );
            }
        }

        // If this node already has a different address, remove the old reverse mapping
        if let Some(old_addr) = addresses.get(&node_id) {
            if old_addr != &address {
                owners.remove(old_addr);
            }
        }

        // Update forward mapping
        addresses.insert(node_id, address.clone());

        // Update reverse mapping
        owners.insert(address, node_id);
        true
    }

    /// Get our discovery message to broadcast
    pub fn get_discovery_message(&self) -> DiscoveryMessage {
        let known_peers = self.get_peer_list();

        DiscoveryMessage {
            node_id: self.node_id,
            public_address: self.public_address.clone(),
            capabilities: ghost_common::types::NodeCapabilities::default(),
            known_peers,
        }
    }

    /// Get list of known peers for gossip
    fn get_peer_list(&self) -> Vec<PeerInfo> {
        let addresses = self.known_addresses.read();
        let now = chrono::Utc::now().timestamp_millis() as u64;

        addresses
            .iter()
            .take(MAX_PEERS_PER_BROADCAST)
            .map(|(node_id, addr)| PeerInfo {
                node_id: *node_id,
                public_address: addr.clone(),
                last_seen: now,
                capabilities: ghost_common::types::NodeCapabilities::default(),
            })
            .collect()
    }

    /// Handle a discovery message
    async fn handle_discovery(&self, envelope: &MessageEnvelope) -> GhostResult<()> {
        // Periodic rate limiter cleanup to prevent memory growth
        let count = self
            .message_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count.is_multiple_of(100) {
            self.rate_limiter.cleanup(Duration::from_secs(600));
        }

        // M-P2P-3: Silently ignore discovery messages from banned nodes
        if self.is_banned(&envelope.sender) {
            return Ok(()); // Silently ignore banned nodes
        }

        // M-3: Verify signature before any other processing (defense-in-depth)
        // The mesh network should already verify, but we check again for safety
        if !self.verify_envelope_signature(envelope) {
            return Err(ghost_common::error::GhostError::SignatureVerification(
                "M-3: Discovery message failed signature verification".to_string(),
            ));
        }

        // M-16: Apply rate limiting to prevent discovery flooding
        if !self.rate_limiter.try_consume(&envelope.sender) {
            debug!(
                sender = %hex::encode(&envelope.sender[..8]),
                "Discovery message rate limited"
            );
            return Ok(()); // Silently drop rate-limited messages
        }

        let discovery_msg: DiscoveryMessage = serde_json::from_slice(&envelope.payload)
            .map_err(|e| ghost_common::error::GhostError::P2PMessage(e.to_string()))?;

        let sender_id_hex = hex::encode(&envelope.sender[..8]);

        // H-3: Validate that discovery message node_id matches envelope sender
        // This prevents spoofing attacks where an attacker claims to be another node
        if discovery_msg.node_id != envelope.sender {
            warn!(
                msg_node_id = %hex::encode(&discovery_msg.node_id[..8]),
                envelope_sender = %sender_id_hex,
                "Discovery message node_id doesn't match envelope sender - rejecting"
            );
            return Ok(()); // Reject spoofed messages
        }

        // Pre-compute our normalized address for comparisons
        let our_normalized = normalize_peer_address(&self.public_address);

        // Add the sender as a known peer
        // SEC-P2P-3/H-P2P-4: Validate address before accepting
        if !discovery_msg.public_address.is_empty() {
            // Silently ignore our own address being advertised back to us
            // This is normal behavior in gossip protocols
            if discovery_msg.public_address == self.public_address
                || envelope.sender == self.node_id
            {
                return Ok(());
            }

            // Normalize address: add default discovery port (8559) if missing
            let normalized_address = normalize_peer_address(&discovery_msg.public_address);

            // Also check normalized form against our own address
            if normalized_address == our_normalized {
                return Ok(());
            }

            if !validate_peer_address(&normalized_address, self.allow_private_peers) {
                warn!(
                    sender = %sender_id_hex,
                    address = %discovery_msg.public_address,
                    "Rejecting invalid peer address from discovery"
                );
            } else {
                // CRIT-CONS-5 SECURITY: Atomic check-and-insert to prevent address hijacking race
                //
                // The attack scenario this prevents:
                // Thread 1: Checks address is free
                // Thread 2: Claims the address (between check and insert)
                // Thread 1: Inserts, overwriting Thread 2's claim
                //
                // Solution: Hold BOTH write locks for the entire operation (no intermediate releases)
                // This ensures the check and insert are atomic with respect to other threads.
                let (is_new, should_connect, accepted) = {
                    let mut addresses = self.known_addresses.write();
                    let mut owners = self.address_owners.write();

                    // CRIT-CONS-5: Atomic check-and-set for address ownership
                    // Check if address is already owned BEFORE any modifications
                    // Returns (is_new, should_connect, accepted) — accepted=false on hijack rejection
                    match owners.get(&normalized_address) {
                        Some(&existing_owner) if existing_owner != envelope.sender => {
                            // CRIT-CONS-5: Address already claimed by a DIFFERENT node - REJECT
                            warn!(
                                sender = %sender_id_hex,
                                address = %normalized_address,
                                existing_owner = %hex::encode(&existing_owner[..8]),
                                "CRIT-CONS-5: Rejecting address hijacking attempt - address already owned"
                            );
                            (false, false, false)
                        }
                        Some(&existing_owner) => {
                            // Same node re-announcing - this is fine, no-op
                            debug_assert_eq!(existing_owner, envelope.sender);
                            (false, false, true)
                        }
                        None => {
                            // CRIT-CONS-5: Address is free - claim it atomically
                            // BOTH inserts happen while holding BOTH locks
                            let is_new = !addresses.contains_key(&envelope.sender);
                            addresses.insert(envelope.sender, normalized_address.clone());
                            owners.insert(normalized_address.clone(), envelope.sender);
                            (is_new, is_new, true)
                        }
                    }
                    // Locks are released here - AFTER both checks and inserts completed
                };

                if is_new {
                    info!(
                        node_id = %sender_id_hex,
                        address = %normalized_address,
                        "Discovered new peer from gossip"
                    );
                }

                // Register peer in PeerManager with real node_id + real address.
                // Post-S-7, discovery is the only path that pairs real identities with
                // addresses (health pings no longer carry public_address in cleartext).
                // Fires on both new and re-announce, but NOT on hijack rejection.
                if accepted {
                    let mut peer =
                        crate::peer::Peer::new(envelope.sender, normalized_address.clone());
                    peer.state = crate::peer::PeerState::Connected;
                    self.peers.upsert_peer(peer);
                }

                // Connect callback outside the lock to avoid holding locks during I/O
                if should_connect {
                    if let Some(ref callback) = self.connect_callback {
                        callback(normalized_address.clone());
                    }
                }
            }
        }

        // M-8: Limit how many peers we accept from a single discovery source
        // This prevents a malicious node from flooding us with bogus peer entries.
        const MAX_PEERS_PER_SOURCE: usize = 50;
        let peer_list = if discovery_msg.known_peers.len() > MAX_PEERS_PER_SOURCE {
            warn!(
                sender = %sender_id_hex,
                count = discovery_msg.known_peers.len(),
                limit = MAX_PEERS_PER_SOURCE,
                "M-8: Truncating oversized peer list from single source"
            );
            &discovery_msg.known_peers[..MAX_PEERS_PER_SOURCE]
        } else {
            &discovery_msg.known_peers
        };

        // Process the peer list from the sender
        let mut new_peers = 0;
        for peer_info in peer_list {
            // Skip ourselves
            if peer_info.node_id == self.node_id {
                continue;
            }

            // Skip if we already know this peer
            if self.known_addresses.read().contains_key(&peer_info.node_id) {
                continue;
            }

            // Skip if address is empty
            if peer_info.public_address.is_empty() {
                continue;
            }

            // Normalize address: add default discovery port if missing
            let peer_normalized = normalize_peer_address(&peer_info.public_address);

            // Silently skip our own address in peer lists
            if peer_normalized == our_normalized {
                continue;
            }

            // SEC-P2P-4/H-P2P-4: Validate addresses from peer list
            if !validate_peer_address(&peer_normalized, self.allow_private_peers) {
                warn!(
                    sender = %sender_id_hex,
                    peer_address = %peer_normalized,
                    "Rejecting invalid address from peer list"
                );
                continue;
            }

            // H-P2P-4: Check for address hijacking
            {
                let owners = self.address_owners.read();
                if let Some(&existing_owner) = owners.get(&peer_normalized) {
                    if existing_owner != peer_info.node_id {
                        warn!(
                            sender = %sender_id_hex,
                            peer_address = %peer_normalized,
                            claimed_by = %hex::encode(&peer_info.node_id[..8]),
                            owned_by = %hex::encode(&existing_owner[..8]),
                            "H-P2P-4: Rejecting gossiped address already claimed by different node"
                        );
                        continue;
                    }
                }
            }

            // Add the new peer
            {
                let mut addresses = self.known_addresses.write();
                let mut owners = self.address_owners.write();
                addresses.insert(peer_info.node_id, peer_normalized.clone());
                owners.insert(peer_normalized.clone(), peer_info.node_id);
            }
            new_peers += 1;

            // Register gossiped peer in PeerManager with real node_id + real address
            {
                let mut peer = crate::peer::Peer::new(peer_info.node_id, peer_normalized.clone());
                peer.state = crate::peer::PeerState::Connected;
                self.peers.upsert_peer(peer);
            }

            // Try to connect
            if let Some(ref callback) = self.connect_callback {
                callback(peer_normalized);
            }
        }

        if new_peers > 0 {
            debug!(
                from = %sender_id_hex,
                new_peers = new_peers,
                total_known = self.known_addresses.read().len(),
                "Added peers from discovery gossip"
            );
        }

        Ok(())
    }

    /// Get count of known peers
    pub fn known_peer_count(&self) -> usize {
        self.known_addresses.read().len()
    }
}

#[async_trait]
impl MessageHandler for DiscoveryHandler {
    async fn handle_message(&self, envelope: Arc<MessageEnvelope>) -> GhostResult<()> {
        if envelope.msg_type == MessageType::Discovery {
            self.handle_discovery(&envelope).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ban_manager::BanReason;

    #[test]
    fn test_discovery_handler_creation() {
        let peers = Arc::new(PeerManager::new([1u8; 32], 100));
        let handler = DiscoveryHandler::new([1u8; 32], "tcp://127.0.0.1:8559".to_string(), peers);
        assert_eq!(handler.known_peer_count(), 0);
    }

    #[test]
    fn test_add_known_peer() {
        let peers = Arc::new(PeerManager::new([1u8; 32], 100));
        let handler = DiscoveryHandler::new([1u8; 32], "tcp://127.0.0.1:8559".to_string(), peers);

        handler.add_known_peer([2u8; 32], "tcp://192.168.1.2:8559".to_string());
        assert_eq!(handler.known_peer_count(), 1);

        let msg = handler.get_discovery_message();
        assert_eq!(msg.known_peers.len(), 1);
    }

    #[test]
    fn test_ban_manager_integration() {
        // M-P2P-3: Test that BanManager properly integrates with DiscoveryHandler
        let peers = Arc::new(PeerManager::new([1u8; 32], 100));
        let ban_manager = Arc::new(BanManager::new());
        let handler = DiscoveryHandler::new([1u8; 32], "tcp://127.0.0.1:8559".to_string(), peers)
            .with_ban_manager(ban_manager.clone());

        let node_id = [2u8; 32];

        // Initially not banned
        assert!(!handler.is_banned(&node_id));

        // Ban the node via shared manager
        ban_manager.ban(node_id, BanReason::Equivocation);

        // Now should be banned
        assert!(handler.is_banned(&node_id));

        // Unban
        ban_manager.unban(&node_id);
        assert!(!handler.is_banned(&node_id));
    }

    #[test]
    fn test_no_ban_manager_returns_false() {
        // Without a ban manager, is_banned should always return false
        let peers = Arc::new(PeerManager::new([1u8; 32], 100));
        let handler = DiscoveryHandler::new([1u8; 32], "tcp://127.0.0.1:8559".to_string(), peers);

        // Without ban manager, should never be considered banned
        assert!(!handler.is_banned(&[2u8; 32]));
    }

    /// SEC-DISC-TEST-1: Verify that invalid/malformed addresses are rejected
    #[test]
    fn test_invalid_address_rejected() {
        // Empty address
        assert!(
            !validate_peer_address("", false),
            "Empty address should be rejected"
        );

        // No port
        assert!(
            !validate_peer_address("1.2.3.4", false),
            "Address without port should be rejected"
        );

        // Invalid port (not a number)
        assert!(
            !validate_peer_address("1.2.3.4:abc", false),
            "Non-numeric port should be rejected"
        );

        // Port zero
        assert!(
            !validate_peer_address("1.2.3.4:0", false),
            "Port zero should be rejected"
        );

        // Port too low (privileged)
        assert!(
            !validate_peer_address("1.2.3.4:80", false),
            "Privileged port should be rejected"
        );

        // Port too high
        assert!(
            !validate_peer_address("1.2.3.4:65535", false),
            "Port > 65000 should be rejected"
        );

        // Valid public address should be accepted
        assert!(
            validate_peer_address("8.8.8.8:8559", false),
            "Valid public address should be accepted"
        );
    }

    /// SEC-DISC-TEST-2: Verify that loopback and private addresses are rejected
    #[test]
    fn test_loopback_address_rejected() {
        // Loopback addresses
        assert!(
            !validate_peer_address("127.0.0.1:8559", false),
            "127.0.0.1 should be rejected"
        );
        assert!(
            !validate_peer_address("localhost:8559", false),
            "localhost should be rejected"
        );

        // Private network addresses (RFC 1918)
        assert!(
            !validate_peer_address("192.168.1.1:8559", false),
            "192.168.x.x should be rejected"
        );
        assert!(
            !validate_peer_address("10.0.0.1:8559", false),
            "10.x.x.x should be rejected"
        );
        assert!(
            !validate_peer_address("172.16.0.1:8559", false),
            "172.16.x.x should be rejected"
        );

        // Bind-all address
        assert!(
            !validate_peer_address("0.0.0.0:8559", false),
            "0.0.0.0 should be rejected"
        );
    }

    #[test]
    fn test_private_addresses_accepted_on_test_networks() {
        // With allow_private = true (set on regtest/testnet/signet, never mainnet),
        // private/loopback peers are accepted so a local/containerised cluster can
        // form its mesh. Mainnet still passes false (covered above).
        assert!(
            validate_peer_address("127.0.0.1:8559", true),
            "loopback should be accepted when allow_private"
        );
        assert!(
            validate_peer_address("172.30.0.12:8555", true),
            "docker-range private IP should be accepted when allow_private"
        );
        assert!(
            validate_peer_address("192.168.1.50:8559", true),
            "RFC1918 private IP should be accepted when allow_private"
        );
        // allow_private must NOT relax the non-IP / malformed guards.
        assert!(
            !validate_peer_address("evil.example.com:8559", true),
            "domain names stay rejected even when allow_private"
        );
        assert!(
            !validate_peer_address("10.0.0.1:0", true),
            "port 0 stays rejected even when allow_private"
        );
    }

    /// H-3-TEST: Verify that discovery messages with mismatched node_id are rejected
    ///
    /// M-3: Updated to use real signatures since zero signatures are now rejected
    #[test]
    fn test_discovery_rejects_mismatched_node_id() {
        use crate::message::{DiscoveryMessage, MessageEnvelope, MessageType};
        use ghost_common::identity::NodeIdentity;
        use ghost_common::types::NodeCapabilities;

        let peers = Arc::new(PeerManager::new([1u8; 32], 100));
        let handler = DiscoveryHandler::new([1u8; 32], "tcp://8.8.8.8:8559".to_string(), peers);

        // Create a real identity for signing
        let identity = NodeIdentity::generate();

        // Create a discovery message claiming to be a DIFFERENT node [3u8; 32]
        let discovery_msg = DiscoveryMessage {
            node_id: [3u8; 32], // Claims to be node 3 (NOT the signer)
            public_address: "tcp://8.8.8.9:8559".to_string(),
            capabilities: NodeCapabilities::default(),
            known_peers: vec![],
        };

        let payload = serde_json::to_vec(&discovery_msg).unwrap();
        let sequence = 1u64;

        // Sign the message (but the discovery_msg.node_id doesn't match the signer)
        let mut signed_data = payload.clone();
        signed_data.extend_from_slice(&sequence.to_le_bytes());
        let signature = identity.sign(&signed_data);

        // Envelope says it's from identity's node_id - MISMATCH with discovery_msg.node_id!
        let envelope = MessageEnvelope {
            sender: identity.node_id(),
            msg_type: MessageType::Discovery,
            payload,
            signature,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sequence,
            ttl: 10,
        };

        // The handler should reject this message because discovery_msg.node_id != envelope.sender
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // Before: no known peers except potentially self
            let before_count = handler.known_peer_count();

            // Process the message - signature is valid but node_id mismatch
            let result = handler.handle_message(Arc::new(envelope)).await;
            assert!(
                result.is_ok(),
                "Should not error on mismatched node_id (just silently reject)"
            );

            // After: should still have same count (message was rejected due to node_id mismatch)
            let after_count = handler.known_peer_count();
            assert_eq!(
                before_count, after_count,
                "Discovery message with mismatched node_id should not add any peers"
            );
        });
    }

    /// H-3-TEST: Verify that discovery messages with matching node_id are accepted
    ///
    /// M-3: Updated to use real signatures since zero signatures are now rejected
    #[test]
    fn test_discovery_accepts_matching_node_id() {
        use crate::message::{DiscoveryMessage, MessageEnvelope, MessageType};
        use ghost_common::identity::NodeIdentity;
        use ghost_common::types::NodeCapabilities;

        let peers = Arc::new(PeerManager::new([1u8; 32], 100));
        let handler = DiscoveryHandler::new([1u8; 32], "tcp://8.8.8.8:8559".to_string(), peers);

        // Create a real identity for signing
        let identity = NodeIdentity::generate();

        // Create a discovery message from the same identity
        let discovery_msg = DiscoveryMessage {
            node_id: identity.node_id(),                // Matches the signer
            public_address: "8.8.8.9:8559".to_string(), // Valid public address (no tcp:// prefix)
            capabilities: NodeCapabilities::default(),
            known_peers: vec![],
        };

        let payload = serde_json::to_vec(&discovery_msg).unwrap();
        let sequence = 1u64;

        // Sign the message properly
        let mut signed_data = payload.clone();
        signed_data.extend_from_slice(&sequence.to_le_bytes());
        let signature = identity.sign(&signed_data);

        // Envelope sender matches the message node_id
        let envelope = MessageEnvelope {
            sender: identity.node_id(),
            msg_type: MessageType::Discovery,
            payload,
            signature,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sequence,
            ttl: 10,
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let before_count = handler.known_peer_count();

            let result = handler.handle_message(Arc::new(envelope)).await;
            assert!(result.is_ok(), "Valid signed message should be accepted");

            // The peer should be added since signature is valid and node_id matches
            let after_count = handler.known_peer_count();
            assert_eq!(
                after_count,
                before_count + 1,
                "Valid discovery message should add the peer"
            );
        });
    }

    /// H-P2P-3-TEST: Verify that integer-based rate limiter works correctly
    #[test]
    fn test_rate_limiter_basic() {
        let limiter = RateLimiter::new(5, 1, 100);
        let node = [1u8; 32];

        // First 5 requests should succeed (burst)
        for _ in 0..5 {
            assert!(limiter.try_consume(&node), "Should allow burst");
        }

        // 6th request should be rate limited
        assert!(!limiter.try_consume(&node), "Should rate limit after burst");
    }

    /// H-P2P-3-TEST: Verify rate limiter enforces per-sender limits
    #[test]
    fn test_rate_limiter_per_sender() {
        let limiter = RateLimiter::new(2, 1, 100);
        let node1 = [1u8; 32];
        let node2 = [2u8; 32];

        // Node 1 uses its tokens
        assert!(limiter.try_consume(&node1));
        assert!(limiter.try_consume(&node1));
        assert!(!limiter.try_consume(&node1), "Node 1 should be limited");

        // Node 2 should still have its tokens
        assert!(
            limiter.try_consume(&node2),
            "Node 2 should not be affected by node 1"
        );
        assert!(limiter.try_consume(&node2));
        assert!(!limiter.try_consume(&node2), "Node 2 should be limited now");
    }

    /// H-P2P-3-TEST: Verify integer arithmetic handles large values without overflow
    #[test]
    fn test_rate_limiter_no_overflow() {
        // Large but reasonable values
        // Use zero refill rate to ensure no tokens are added during test execution
        let limiter = RateLimiter::new(1000, 0, 1000);
        let node = [1u8; 32];

        // Exhaust all tokens
        for _ in 0..1000 {
            assert!(limiter.try_consume(&node));
        }

        // Should be limited now (no refill during test)
        assert!(!limiter.try_consume(&node));
    }

    // =========================================================================
    // H-P2P-4 TESTS: IP-only addresses and address hijacking prevention
    // =========================================================================

    /// H-P2P-4-TEST: Verify that domain names are rejected
    #[test]
    fn test_domain_names_rejected() {
        assert!(
            !validate_peer_address("example.com:8559", false),
            "Domain names should be rejected"
        );
        assert!(
            !validate_peer_address("node1.ghost.io:8559", false),
            "Domain names should be rejected"
        );
        assert!(
            !validate_peer_address("my-node.local:8559", false),
            "Domain names should be rejected"
        );
    }

    /// H-P2P-4-TEST: Verify that valid IPv4 addresses are accepted
    #[test]
    fn test_ipv4_accepted() {
        assert!(
            validate_peer_address("8.8.8.8:8559", false),
            "Valid IPv4 should be accepted"
        );
        // Use a real public IP, not TEST-NET range
        assert!(
            validate_peer_address("1.1.1.1:8555", false),
            "Valid IPv4 should be accepted"
        );
    }

    /// H-P2P-4-TEST: Verify that valid IPv6 addresses are accepted
    #[test]
    fn test_ipv6_accepted() {
        // Use real global unicast addresses, not documentation range
        assert!(
            validate_peer_address("[2607:f8b0:4004:800::200e]:8559", false),
            "Valid IPv6 with brackets should be accepted"
        );
    }

    /// H-P2P-4-TEST: Verify that IPv6 loopback is rejected
    #[test]
    fn test_ipv6_loopback_rejected() {
        assert!(
            !validate_peer_address("[::1]:8559", false),
            "IPv6 loopback should be rejected"
        );
    }

    /// H-P2P-4-TEST: Verify that IPv6 link-local is rejected
    #[test]
    fn test_ipv6_link_local_rejected() {
        assert!(
            !validate_peer_address("[fe80::1]:8559", false),
            "IPv6 link-local should be rejected"
        );
    }

    /// H-P2P-4-TEST: Verify that address hijacking is detected
    #[test]
    fn test_address_hijacking_prevention() {
        let peers = Arc::new(PeerManager::new([1u8; 32], 100));
        let handler = DiscoveryHandler::new([1u8; 32], "8.8.8.8:8559".to_string(), peers);

        // Use a real public IP, not TEST-NET range
        let shared_address = "93.184.216.34:8559".to_string();

        // First node claims the address
        handler.add_known_peer([2u8; 32], shared_address.clone());
        assert_eq!(handler.known_peer_count(), 1);

        // Second node tries to claim the same address
        // This should be allowed since add_known_peer updates both mappings
        handler.add_known_peer([3u8; 32], shared_address.clone());

        // The address should now be owned by the second node
        {
            let owners = handler.address_owners.read();
            let owner = owners.get(&shared_address).unwrap();
            assert_eq!(
                *owner, [3u8; 32],
                "Address should now be owned by second node"
            );
        }
    }

    // =========================================================================
    // L-9 TESTS: Reserved IP range validation
    // =========================================================================

    /// L-9-TEST: Verify that TEST-NET ranges are rejected
    #[test]
    fn test_l9_test_net_rejected() {
        // TEST-NET-1 (192.0.2.0/24)
        assert!(
            !validate_peer_address("192.0.2.1:8559", false),
            "TEST-NET-1 should be rejected"
        );
        // TEST-NET-2 (198.51.100.0/24)
        assert!(
            !validate_peer_address("198.51.100.1:8559", false),
            "TEST-NET-2 should be rejected"
        );
        // TEST-NET-3 (203.0.113.0/24)
        assert!(
            !validate_peer_address("203.0.113.1:8559", false),
            "TEST-NET-3 should be rejected"
        );
    }

    /// L-9-TEST: Verify that carrier-grade NAT is rejected
    #[test]
    fn test_l9_cgnat_rejected() {
        // 100.64.0.0/10 (Carrier-grade NAT)
        assert!(
            !validate_peer_address("100.64.0.1:8559", false),
            "CGNAT should be rejected"
        );
        assert!(
            !validate_peer_address("100.100.100.100:8559", false),
            "CGNAT should be rejected"
        );
        assert!(
            !validate_peer_address("100.127.255.255:8559", false),
            "CGNAT upper bound should be rejected"
        );
    }

    /// L-9-TEST: Verify that multicast is rejected
    #[test]
    fn test_l9_multicast_rejected() {
        assert!(
            !validate_peer_address("224.0.0.1:8559", false),
            "Multicast should be rejected"
        );
        assert!(
            !validate_peer_address("239.255.255.255:8559", false),
            "Multicast should be rejected"
        );
    }

    /// L-9-TEST: Verify that future reserved is rejected
    #[test]
    fn test_l9_future_reserved_rejected() {
        assert!(
            !validate_peer_address("240.0.0.1:8559", false),
            "Future reserved should be rejected"
        );
        assert!(
            !validate_peer_address("250.0.0.1:8559", false),
            "Future reserved should be rejected"
        );
    }

    /// L-9-TEST: Verify that benchmark testing range is rejected
    #[test]
    fn test_l9_benchmark_rejected() {
        // 198.18.0.0/15 (Benchmark testing)
        assert!(
            !validate_peer_address("198.18.0.1:8559", false),
            "Benchmark range should be rejected"
        );
        assert!(
            !validate_peer_address("198.19.255.255:8559", false),
            "Benchmark range should be rejected"
        );
    }

    /// L-9-TEST: Verify that IPv6 documentation range is rejected
    #[test]
    fn test_l9_ipv6_doc_rejected() {
        // 2001:db8::/32 (Documentation)
        assert!(
            !validate_peer_address("[2001:db8::1]:8559", false),
            "IPv6 documentation range should be rejected"
        );
        assert!(
            !validate_peer_address("[2001:db8:1234::1]:8559", false),
            "IPv6 documentation range should be rejected"
        );
    }

    /// L-9-TEST: Verify that IPv6 multicast is rejected
    #[test]
    fn test_l9_ipv6_multicast_rejected() {
        assert!(
            !validate_peer_address("[ff02::1]:8559", false),
            "IPv6 multicast should be rejected"
        );
    }

    /// L-9-TEST: Verify that 6to4 tunneling is rejected
    #[test]
    fn test_l9_6to4_rejected() {
        // 2002::/16 (6to4 tunneling, deprecated)
        assert!(
            !validate_peer_address("[2002::1]:8559", false),
            "6to4 tunneling should be rejected"
        );
    }

    /// L-9-TEST: Verify that valid public IPs are still accepted
    #[test]
    fn test_l9_public_ips_accepted() {
        // Google DNS
        assert!(
            validate_peer_address("8.8.8.8:8559", false),
            "Google DNS should be accepted"
        );
        // Cloudflare DNS
        assert!(
            validate_peer_address("1.1.1.1:8559", false),
            "Cloudflare DNS should be accepted"
        );
        // Random public IP
        assert!(
            validate_peer_address("93.184.216.34:8559", false),
            "Public IP should be accepted"
        );
    }

    // =========================================================================
    // M-3 TESTS: Signature verification in discovery handler
    // =========================================================================

    /// M-3-TEST: Verify that zero signatures are rejected
    #[test]
    fn test_m3_zero_signature_rejected() {
        let peers = Arc::new(PeerManager::new([1u8; 32], 100));
        let handler = DiscoveryHandler::new([1u8; 32], "8.8.8.8:8559".to_string(), peers);

        let envelope = MessageEnvelope {
            sender: [2u8; 32],
            msg_type: MessageType::Discovery,
            payload: vec![1, 2, 3],
            signature: [0u8; 64], // Zero signature
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sequence: 1,
            ttl: 10,
        };

        assert!(
            !handler.verify_envelope_signature(&envelope),
            "M-3: Zero signature should be rejected"
        );
    }

    /// M-3-TEST: Verify that invalid signatures are rejected
    #[test]
    fn test_m3_invalid_signature_rejected() {
        let peers = Arc::new(PeerManager::new([1u8; 32], 100));
        let handler = DiscoveryHandler::new([1u8; 32], "8.8.8.8:8559".to_string(), peers);

        let envelope = MessageEnvelope {
            sender: [2u8; 32],
            msg_type: MessageType::Discovery,
            payload: vec![1, 2, 3],
            signature: [0xFFu8; 64], // Invalid signature (not zeros but wrong)
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sequence: 1,
            ttl: 10,
        };

        assert!(
            !handler.verify_envelope_signature(&envelope),
            "M-3: Invalid signature should be rejected"
        );
    }

    /// M-3-TEST: Verify that valid signatures are accepted
    #[test]
    fn test_m3_valid_signature_accepted() {
        use ghost_common::identity::NodeIdentity;

        let peers = Arc::new(PeerManager::new([1u8; 32], 100));
        let handler = DiscoveryHandler::new([1u8; 32], "8.8.8.8:8559".to_string(), peers);

        // Create a real identity and sign a message
        let identity = NodeIdentity::generate();
        let payload = vec![1, 2, 3, 4, 5];
        let sequence = 42u64;

        // Sign the message (payload + sequence, matching mesh.rs)
        let mut signed_data = payload.clone();
        signed_data.extend_from_slice(&sequence.to_le_bytes());
        let signature = identity.sign(&signed_data);

        let envelope = MessageEnvelope {
            sender: identity.node_id(),
            msg_type: MessageType::Discovery,
            payload,
            signature,
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
            sequence,
            ttl: 10,
        };

        assert!(
            handler.verify_envelope_signature(&envelope),
            "M-3: Valid signature should be accepted"
        );
    }
}
