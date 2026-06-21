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
//| FILE: peer.rs                                                                                                        |
//|======================================================================================================================|

//! Peer management for the consensus mesh

use parking_lot::RwLock;
use std::collections::HashMap;
use tracing::{debug, info};

use ghost_common::types::{NodeCapabilities, NodeId};

/// L-3 FIX: Extract host portion from an address, handling both IPv4 and IPv6 formats.
///
/// IPv6 addresses are formatted as [::1]:8080, so we can't just split on ':'.
/// This function properly handles:
/// - IPv4: "192.168.1.1:8080" -> "192.168.1.1"
/// - IPv6: "[::1]:8080" -> "::1"
/// - IPv6 without port: "[::1]" -> "::1"
/// - Invalid format: returns the original string
fn extract_host_from_address(address: &str) -> String {
    // Check for IPv6 format: [host]:port
    if address.starts_with('[') {
        if let Some(bracket_end) = address.find(']') {
            // Extract the IPv6 address between brackets
            return address[1..bracket_end].to_string();
        }
    }

    // IPv4 format: host:port
    // Only split on the last colon to handle cases correctly
    if let Some(colon_pos) = address.rfind(':') {
        // Verify the part after colon looks like a port (all digits)
        let potential_port = &address[colon_pos + 1..];
        if potential_port.chars().all(|c| c.is_ascii_digit()) {
            return address[..colon_pos].to_string();
        }
    }

    // No port found or unparseable, return as-is
    address.to_string()
}

/// Extract the /24 subnet prefix from an address string.
/// Returns `Some("a.b.c")` for IPv4 addresses, `None` for IPv6 or unparseable.
fn extract_ipv4_subnet(address: &str) -> Option<String> {
    let host = extract_host_from_address(address);
    let ip: std::net::IpAddr = host.parse().ok()?;
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            Some(format!("{}.{}.{}", octets[0], octets[1], octets[2]))
        }
        std::net::IpAddr::V6(_) => None, // IPv6 subnet diversity handled separately if needed
    }
}

/// Maximum peers allowed from the same /24 subnet.
/// Limits eclipse attack surface while allowing legitimate multi-node operators.
const MAX_PEERS_PER_SUBNET: usize = 3;

/// Peer manager for tracking connected peers
#[derive(Debug)]
pub struct PeerManager {
    /// Known peers
    peers: RwLock<HashMap<NodeId, Peer>>,
    /// Our node ID
    our_node_id: NodeId,
    /// Maximum peers to maintain
    max_peers: usize,
}

impl PeerManager {
    /// Create a new peer manager
    pub fn new(our_node_id: NodeId, max_peers: usize) -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            our_node_id,
            max_peers,
        }
    }

    /// Add or update a peer.
    ///
    /// Enforces /24 subnet diversity: at most `MAX_PEERS_PER_SUBNET` peers from
    /// the same IPv4 /24 to limit eclipse attack surface.
    #[allow(clippy::map_entry)] // entry() API doesn't fit: we need checks between contains_key and insert
    pub fn upsert_peer(&self, peer: Peer) {
        let mut peers = self.peers.write();

        // Allow updates to existing peers unconditionally
        if peers.contains_key(&peer.node_id) {
            peers.insert(peer.node_id, peer);
            return;
        }

        // Reconcile by host: one physical host belongs to one identity. If a
        // DIFFERENT node_id already holds this exact host, it is a superseded
        // bootstrap placeholder — the seed-connect path ("Connecting to peer")
        // registers peers with a temp node_id = hash(address) until the real
        // identity is learned via discovery (on a different port). Remove the
        // stale entry so the real identity can take the slot. Without this,
        // co-located nodes (all on one /24 — a docker bridge or any test
        // cluster) exhaust MAX_PEERS_PER_SUBNET with placeholders and the real
        // identities are rejected below, leaving peers that HealthPings (keyed
        // by the real node_id) can never refresh — so they age out of
        // get_connected_peers and encrypted broadcasts reach zero peers.
        // Matching the EXACT host (not the /24) keeps Sybil protection intact:
        // genuinely distinct hosts still count toward the subnet limit.
        let new_host = extract_host_from_address(&peer.public_address);
        if !new_host.is_empty() {
            let superseded: Vec<NodeId> = peers
                .iter()
                .filter(|(nid, p)| {
                    **nid != peer.node_id
                        && extract_host_from_address(&p.public_address) == new_host
                })
                .map(|(nid, _)| *nid)
                .collect();
            for nid in superseded {
                peers.remove(&nid);
            }
        }

        if peers.len() >= self.max_peers {
            return;
        }

        // M2: Enforce subnet diversity for new peers
        if let Some(new_subnet) = extract_ipv4_subnet(&peer.public_address) {
            let subnet_count = peers
                .values()
                .filter(|p| {
                    extract_ipv4_subnet(&p.public_address).as_deref() == Some(new_subnet.as_str())
                })
                .count();

            if subnet_count >= MAX_PEERS_PER_SUBNET {
                debug!(
                    subnet = %new_subnet,
                    count = subnet_count,
                    max = MAX_PEERS_PER_SUBNET,
                    peer_addr = %peer.public_address,
                    "Rejecting peer: /24 subnet limit reached"
                );
                return;
            }
        }

        peers.insert(peer.node_id, peer);
    }

    /// Get a peer by node ID
    pub fn get_peer(&self, node_id: &NodeId) -> Option<Peer> {
        self.peers.read().get(node_id).cloned()
    }

    /// Remove a peer
    ///
    /// P2P4-L1: Logs peer disconnection for observability
    pub fn remove_peer(&self, node_id: &NodeId) -> Option<Peer> {
        let removed = self.peers.write().remove(node_id);
        if removed.is_some() {
            info!(node_id = %hex::encode(&node_id[..8]), "Peer removed");
        }
        removed
    }

    /// Get all peers
    pub fn get_all_peers(&self) -> Vec<Peer> {
        self.peers.read().values().cloned().collect()
    }

    /// Get connected peers (recently seen)
    pub fn get_connected_peers(&self, max_age_secs: u64) -> Vec<Peer> {
        let now = chrono::Utc::now().timestamp() as u64;
        let cutoff = now.saturating_sub(max_age_secs);

        self.peers
            .read()
            .values()
            .filter(|p| p.last_seen >= cutoff && p.state == PeerState::Connected)
            .cloned()
            .collect()
    }

    /// Get elder peers
    pub fn get_elder_peers(&self) -> Vec<Peer> {
        self.peers
            .read()
            .values()
            .filter(|p| p.is_elder)
            .cloned()
            .collect()
    }

    /// Update peer last seen
    pub fn update_last_seen(&self, node_id: &NodeId) {
        if let Some(peer) = self.peers.write().get_mut(node_id) {
            peer.last_seen = chrono::Utc::now().timestamp() as u64;
            peer.state = PeerState::Connected;
        }
    }

    /// Update live metrics from a health ping (miner count + capabilities).
    pub fn update_health_metrics(
        &self,
        node_id: &NodeId,
        miner_count: u32,
        capabilities: ghost_common::types::NodeCapabilities,
    ) {
        if let Some(peer) = self.peers.write().get_mut(node_id) {
            peer.miner_count = miner_count;
            peer.capabilities = capabilities;
        }
    }

    /// Update a peer's hardware-derived `max_capacity` (advertised in their
    /// most recent health ping). Used by the load balancer to compute
    /// utilisation for routing decisions.
    pub fn update_max_capacity(&self, node_id: &NodeId, max_capacity: u32) {
        if let Some(peer) = self.peers.write().get_mut(node_id) {
            peer.max_capacity = max_capacity;
        }
    }

    /// Replace the active miner_id hash list and the peer's own realized
    /// hashrate with the most recent from a health ping. The hashes feed the
    /// mesh-wide deduplicated active count; `local_hashrate_th` is summed
    /// (one term per node) for the pool-wide hashrate. Older peers that don't
    /// report hashrate pass `0.0`.
    pub fn update_active_miner_hashes(
        &self,
        node_id: &NodeId,
        hashes: Vec<[u8; 16]>,
        local_hashrate_th: f64,
    ) {
        if let Some(peer) = self.peers.write().get_mut(node_id) {
            peer.active_miner_id_hashes = hashes;
            peer.local_hashrate_th = local_hashrate_th;
        }
    }

    /// Mark peer as disconnected
    ///
    /// P2P4-L1: Logs peer disconnection for observability
    pub fn mark_disconnected(&self, node_id: &NodeId) {
        if let Some(peer) = self.peers.write().get_mut(node_id) {
            peer.state = PeerState::Disconnected;
            info!(node_id = %hex::encode(&node_id[..8]), "Peer disconnected");
        }
    }

    /// Get peer count (total entries in peer map)
    pub fn peer_count(&self) -> usize {
        self.peers.read().len()
    }

    /// S-3: Check if a peer is "established" (first seen > 1 hour ago).
    /// Unknown/new peers should be rate-limited more aggressively.
    pub fn is_established(&self, node_id: &NodeId) -> bool {
        let peers = self.peers.read();
        if let Some(peer) = peers.get(node_id) {
            let now = chrono::Utc::now().timestamp() as u64;
            now.saturating_sub(peer.first_seen) >= 3600 // 1 hour
        } else {
            false // Unknown peer = not established
        }
    }

    /// Get unique peer count by address
    ///
    /// Returns count of unique IP addresses, which represents actual peer nodes.
    /// This avoids double-counting when temp and real node_ids exist for same peer.
    ///
    /// L-3 FIX: Properly handles IPv6 addresses like `[::1]:8080` by extracting
    /// the host portion between brackets, not just splitting on colon.
    pub fn unique_peer_count(&self) -> usize {
        let peers = self.peers.read();
        let unique_hosts: std::collections::HashSet<String> = peers
            .values()
            .filter(|p| !p.public_address.is_empty())
            .map(|p| extract_host_from_address(&p.public_address))
            .collect();
        unique_hosts.len()
    }

    /// Get connected peer count
    pub fn connected_count(&self) -> usize {
        self.peers
            .read()
            .values()
            .filter(|p| p.state == PeerState::Connected)
            .count()
    }

    /// Our node ID
    pub fn our_node_id(&self) -> NodeId {
        self.our_node_id
    }
}

/// Peer information
#[derive(Debug, Clone)]
pub struct Peer {
    /// Node ID
    pub node_id: NodeId,
    /// Public address (IP:port)
    pub public_address: String,
    /// Display name
    pub display_name: Option<String>,
    /// First seen timestamp
    pub first_seen: u64,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Connection state
    pub state: PeerState,
    /// Is an elder
    pub is_elder: bool,
    /// Elder order (if elder)
    pub elder_order: Option<u32>,
    /// Node capabilities
    pub capabilities: NodeCapabilities,
    /// Latency in milliseconds
    pub latency_ms: Option<u32>,
    /// Messages received from this peer
    pub messages_received: u64,
    /// Messages sent to this peer
    pub messages_sent: u64,
    /// Number of miners connected to this peer (from health pings)
    pub miner_count: u32,
    /// Truncated SHA-256 hashes of miner_ids active on this peer in the
    /// last ~5 min, from the most recent health ping. Used for mesh-wide
    /// deduplicated active-miner counting.
    pub active_miner_id_hashes: Vec<[u8; 16]>,
    /// This peer's own realized hashrate (TH/s) over a trailing window, from
    /// its most recent health ping. Summed across the mesh (one term per node)
    /// for the pool-wide hashrate. 0 for older peers that don't report it.
    pub local_hashrate_th: f64,
    /// Peer's hardware-derived effective miner capacity, advertised in its
    /// health pings. The translator's load balancer divides `miner_count`
    /// by this value to compute utilisation and pick the under-utilised
    /// peer for new connections. 0 means the peer hasn't reported yet
    /// (legacy or pre-update node) — treated as "unknown" and excluded
    /// from utilisation-based routing.
    pub max_capacity: u32,
}

impl Peer {
    /// Create a new peer
    pub fn new(node_id: NodeId, public_address: String) -> Self {
        let now = chrono::Utc::now().timestamp() as u64;
        Self {
            node_id,
            public_address,
            display_name: None,
            first_seen: now,
            last_seen: now,
            state: PeerState::Connecting,
            is_elder: false,
            elder_order: None,
            capabilities: NodeCapabilities::default(),
            latency_ms: None,
            messages_received: 0,
            messages_sent: 0,
            miner_count: 0,
            active_miner_id_hashes: Vec::new(),
            local_hashrate_th: 0.0,
            max_capacity: 0,
        }
    }

    /// Node ID as hex string
    pub fn node_id_hex(&self) -> String {
        hex::encode(self.node_id)
    }

    /// Short node ID (first 8 chars)
    pub fn node_id_short(&self) -> String {
        self.node_id_hex()[..8].to_string()
    }

    /// Calculate uptime since first seen
    pub fn uptime_secs(&self) -> u64 {
        let now = chrono::Utc::now().timestamp() as u64;
        now.saturating_sub(self.first_seen)
    }

    /// Check if peer is stale (not seen recently)
    pub fn is_stale(&self, max_age_secs: u64) -> bool {
        let now = chrono::Utc::now().timestamp() as u64;
        now.saturating_sub(self.last_seen) > max_age_secs
    }
}

/// Peer connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PeerState {
    /// Connecting to peer
    #[default]
    Connecting,
    /// Connected and healthy
    Connected,
    /// Temporarily disconnected
    Disconnected,
    /// Banned (misbehavior)
    Banned,
}

/// Peer scoring for selection
#[derive(Debug, Clone)]
pub struct PeerScore {
    /// Node ID
    pub node_id: NodeId,
    /// Overall score (higher is better)
    pub score: f64,
    /// Latency component
    pub latency_score: f64,
    /// Reliability component
    pub reliability_score: f64,
    /// Capability component
    pub capability_score: f64,
}

impl PeerScore {
    /// Calculate peer score
    pub fn calculate(peer: &Peer) -> Self {
        // Latency score (lower latency = higher score)
        let latency_score = match peer.latency_ms {
            Some(ms) if ms < 50 => 1.0,
            Some(ms) if ms < 100 => 0.8,
            Some(ms) if ms < 200 => 0.6,
            Some(ms) if ms < 500 => 0.4,
            Some(_) => 0.2,
            None => 0.5, // Unknown
        };

        // Reliability score based on uptime
        let uptime = peer.uptime_secs();
        let reliability_score = if uptime > 86400 * 30 {
            1.0 // 30+ days
        } else if uptime > 86400 * 7 {
            0.8 // 7+ days
        } else if uptime > 86400 {
            0.6 // 1+ day
        } else {
            0.4 // < 1 day
        };

        // Capability score
        let capability_score = peer.capabilities.total_shares() as f64 / 15.0;

        // LOW-CONS-2: Elder bonus capped at 0.1 to prevent Sybil-boosted elder advantage
        // A higher bonus (e.g., 0.2) combined with malicious elder registration could give
        // disproportionate influence in peer selection. Capped to balance legitimate elder
        // priority while limiting potential Sybil amplification.
        let elder_bonus = if peer.is_elder { 0.1 } else { 0.0 };

        // L-4 FIX: Weights adjusted to sum to 1.0 for proper scoring
        // 0.30 + 0.30 + 0.30 + 0.10 = 1.0
        // Elder bonus is included in the base calculation, not added separately
        let score = (latency_score * 0.30)
            + (reliability_score * 0.30)
            + (capability_score * 0.30)
            + elder_bonus; // 0.10 for elders, 0.0 for non-elders

        Self {
            node_id: peer.node_id,
            score,
            latency_score,
            reliability_score,
            capability_score,
        }
    }
}

/// Select best peers for propagation
pub fn select_best_peers(peers: &[Peer], count: usize) -> Vec<&Peer> {
    let mut scored: Vec<_> = peers.iter().map(|p| (p, PeerScore::calculate(p))).collect();

    scored.sort_by(|a, b| {
        b.1.score
            .partial_cmp(&a.1.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    scored.into_iter().take(count).map(|(p, _)| p).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_manager() {
        let our_id = [1u8; 32];
        let manager = PeerManager::new(our_id, 100);

        let peer = Peer::new([2u8; 32], "127.0.0.1:8555".to_string());
        manager.upsert_peer(peer);

        assert_eq!(manager.peer_count(), 1);
    }

    #[test]
    fn test_upsert_reconciles_same_host_placeholder() {
        // Regression: the seed-connect path creates bootstrap *placeholder* peers
        // with a temp node_id = hash(address) (mesh.rs "Connecting to peer"). When
        // many nodes share one /24 (e.g. a docker bridge, or any co-located test
        // cluster), three such placeholders fill MAX_PEERS_PER_SUBNET (=3). The
        // real identity for the same host, learned later via discovery on a
        // different port, was then REJECTED by the subnet limit and never landed —
        // and HealthPings (keyed by the real node_id) could never refresh the
        // surviving placeholder, which aged out of get_connected_peers, so the
        // encrypted broadcast reached zero peers. upsert_peer must reconcile by
        // host: a real identity supersedes the same-host placeholder.
        let mgr = PeerManager::new([0u8; 32], 100);
        for i in 10u8..13 {
            let mut p = Peer::new([i; 32], format!("172.30.0.{}:8555", i));
            p.state = PeerState::Connected;
            mgr.upsert_peer(p);
        }
        assert_eq!(
            mgr.get_all_peers().len(),
            3,
            "three placeholders fill the /24 quota"
        );

        // Real identity for the same host as the first placeholder (172.30.0.10),
        // discovered on the discovery port (:8559) with a different node_id.
        let real_id = [99u8; 32];
        let mut real = Peer::new(real_id, "172.30.0.10:8559".to_string());
        real.state = PeerState::Connected;
        mgr.upsert_peer(real);

        let all = mgr.get_all_peers();
        assert!(
            all.iter().any(|p| p.node_id == real_id),
            "real identity must supersede the same-host placeholder despite the subnet limit"
        );
        assert!(
            !all.iter().any(|p| p.node_id == [10u8; 32]),
            "the superseded same-host placeholder must be removed"
        );
        // A genuinely new host in the same /24 is still capped (Sybil protection intact).
        let mut sybil = Peer::new([200u8; 32], "172.30.0.99:8555".to_string());
        sybil.state = PeerState::Connected;
        mgr.upsert_peer(sybil);
        assert!(
            !mgr.get_all_peers().iter().any(|p| p.node_id == [200u8; 32]),
            "a new distinct host in a full /24 must still be rejected (Sybil cap holds)"
        );
    }

    #[test]
    fn test_peer_scoring() {
        let mut peer = Peer::new([1u8; 32], "127.0.0.1:8555".to_string());
        peer.latency_ms = Some(50);
        peer.is_elder = true;

        let score = PeerScore::calculate(&peer);
        assert!(score.score > 0.0);
        assert!(score.latency_score > 0.5);
    }

    // --- 15 new tests below ---

    #[test]
    fn test_extract_host_ipv4_with_port() {
        let result = extract_host_from_address("192.168.1.1:8080");
        assert_eq!(result, "192.168.1.1");
    }

    #[test]
    fn test_extract_host_ipv6_with_port() {
        let result = extract_host_from_address("[::1]:8080");
        assert_eq!(result, "::1");
    }

    #[test]
    fn test_extract_host_ipv6_no_port() {
        let result = extract_host_from_address("[::1]");
        assert_eq!(result, "::1");
    }

    #[test]
    fn test_extract_host_no_port() {
        let result = extract_host_from_address("hostname");
        assert_eq!(result, "hostname");
    }

    #[test]
    fn test_extract_host_empty() {
        let result = extract_host_from_address("");
        assert_eq!(result, "");
    }

    #[test]
    fn test_extract_subnet_valid() {
        let result = extract_ipv4_subnet("192.168.1.100:8080");
        assert_eq!(result, Some("192.168.1".to_string()));
    }

    #[test]
    fn test_extract_subnet_ipv6() {
        let result = extract_ipv4_subnet("[::1]:8080");
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_subnet_unparseable() {
        let result = extract_ipv4_subnet("not-an-ip:8080");
        assert_eq!(result, None);
    }

    #[test]
    fn test_score_low_latency_elder() {
        let mut peer = Peer::new([10u8; 32], "10.0.0.1:8555".to_string());
        peer.latency_ms = Some(10);
        peer.is_elder = true;
        // Max out capabilities for highest possible score
        peer.capabilities = NodeCapabilities {
            archive_mode: true,
            ghost_pay: true,
            public_mining: true,
            reaper: true,
            elder_status: true,
        };
        // Set first_seen far in the past for max reliability (30+ days)
        peer.first_seen = peer.first_seen.saturating_sub(86400 * 31);

        let score = PeerScore::calculate(&peer);
        // latency_score = 1.0 (10ms < 50), reliability_score = 1.0 (31 days),
        // capability_score = 15/15 = 1.0, elder_bonus = 0.1
        // score = 0.30 + 0.30 + 0.30 + 0.10 = 1.0
        assert!(
            score.score >= 0.95,
            "Expected score near max, got {}",
            score.score
        );
        assert_eq!(score.latency_score, 1.0);
    }

    #[test]
    fn test_score_high_latency_non_elder() {
        let mut peer = Peer::new([11u8; 32], "10.0.0.2:8555".to_string());
        peer.latency_ms = Some(1000);
        peer.is_elder = false;
        // No capabilities
        peer.capabilities = NodeCapabilities::default();

        let score = PeerScore::calculate(&peer);
        // latency_score = 0.2 (1000ms >= 500), reliability_score = 0.4 (just created, < 1 day),
        // capability_score = 0/15 = 0.0, elder_bonus = 0.0
        // score = 0.06 + 0.12 + 0.0 + 0.0 = 0.18
        assert!(score.score < 0.3, "Expected low score, got {}", score.score);
        assert_eq!(score.latency_score, 0.2);
    }

    #[test]
    fn test_score_unknown_latency() {
        let peer = Peer::new([12u8; 32], "10.0.0.3:8555".to_string());
        // latency_ms defaults to None

        let score = PeerScore::calculate(&peer);
        assert_eq!(
            score.latency_score, 0.5,
            "Unknown latency should yield 0.5 latency component"
        );
    }

    #[test]
    fn test_select_best_peers_ordering() {
        // Create 3 peers with clearly different scores
        let mut peer_high = Peer::new([20u8; 32], "10.0.0.10:8555".to_string());
        peer_high.latency_ms = Some(10);
        peer_high.is_elder = true;
        peer_high.capabilities = NodeCapabilities {
            archive_mode: true,
            ghost_pay: true,
            public_mining: true,
            reaper: true,
            elder_status: true,
        };
        peer_high.first_seen = peer_high.first_seen.saturating_sub(86400 * 31);

        let mut peer_mid = Peer::new([21u8; 32], "10.0.1.10:8555".to_string());
        peer_mid.latency_ms = Some(150);
        peer_mid.capabilities.archive_mode = true;

        let mut peer_low = Peer::new([22u8; 32], "10.0.2.10:8555".to_string());
        peer_low.latency_ms = Some(1000);

        let peers = vec![peer_low, peer_mid, peer_high];
        let selected = select_best_peers(&peers, 3);

        assert_eq!(selected.len(), 3);
        // Best peer (highest score) should be first
        assert_eq!(selected[0].node_id, [20u8; 32]);
        // Worst peer should be last
        assert_eq!(selected[2].node_id, [22u8; 32]);
    }

    #[test]
    fn test_select_best_peers_count_limit() {
        let peers: Vec<Peer> = (0..5)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = i;
                // Different subnets to avoid any subnet-related issues
                Peer::new(id, format!("10.{}.0.1:8555", i))
            })
            .collect();

        let selected = select_best_peers(&peers, 2);
        assert_eq!(
            selected.len(),
            2,
            "select_best_peers should return exactly the requested count"
        );
    }

    #[test]
    fn test_subnet_diversity_enforcement() {
        let our_id = [0u8; 32];
        let manager = PeerManager::new(our_id, 100);

        // Add 3 peers from the same /24 subnet (192.168.1.x) -- should all succeed
        for i in 1..=3u8 {
            let mut id = [0u8; 32];
            id[0] = i;
            let peer = Peer::new(id, format!("192.168.1.{}:8555", i));
            manager.upsert_peer(peer);
        }
        assert_eq!(manager.peer_count(), 3);

        // 4th peer from the same /24 subnet should be rejected
        let mut id4 = [0u8; 32];
        id4[0] = 4;
        let peer4 = Peer::new(id4, "192.168.1.4:8555".to_string());
        manager.upsert_peer(peer4);

        assert_eq!(
            manager.peer_count(),
            3,
            "4th peer from same /24 subnet should be rejected (MAX_PEERS_PER_SUBNET=3)"
        );

        // A peer from a different /24 should still be accepted
        let mut id5 = [0u8; 32];
        id5[0] = 5;
        let peer5 = Peer::new(id5, "192.168.2.1:8555".to_string());
        manager.upsert_peer(peer5);

        assert_eq!(
            manager.peer_count(),
            4,
            "Peer from different /24 subnet should be accepted"
        );
    }

    #[test]
    fn test_peer_stale_detection() {
        let mut peer = Peer::new([30u8; 32], "10.0.0.30:8555".to_string());
        // Set last_seen to 120 seconds ago
        peer.last_seen = peer.last_seen.saturating_sub(120);

        assert!(
            peer.is_stale(60),
            "Peer not seen for 120s should be stale with threshold 60s"
        );
        assert!(
            !peer.is_stale(300),
            "Peer not seen for 120s should NOT be stale with threshold 300s"
        );
    }
}
