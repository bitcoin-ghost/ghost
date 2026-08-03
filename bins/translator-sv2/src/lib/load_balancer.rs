//! Capacity-aware load balancer for the SV1 stratum endpoint.
//!
//! Polls the colocated ghost-pool's `/api/internal/pool-nodes` endpoint,
//! which now reports per-peer hardware-derived `max_capacity`. New miner
//! connections are routed to the peer with the lowest *utilisation*
//! (`miner_count / max_capacity`), so a small Pi at 80% loses to a beefy
//! server at 30%.
//!
//! Capacity thresholds (default 80 / 90 / 95) gate local behaviour:
//!
//! | local utilisation | state           | what happens                                     |
//! |-------------------|-----------------|--------------------------------------------------|
//! | < warn_pct        | Normal          | accept + maybe proxy via utilisation routing     |
//! | ≥ warn_pct        | Warning         | log warning, still accept, prefer-proxy harder   |
//! | ≥ reject_pct      | RejectNew       | TCP-close incoming connections immediately       |
//! | ≥ evict_pct       | Critical        | reject new AND shed existing miners              |
//!
//! Utilisation above is `miner_count / max_capacity`. Separately, opt-in
//! **compute protection** (`compute_shed_enabled`) forces `Critical` when this
//! node's per-core 1-minute load average reaches `compute_evict_pct`, so a node
//! under real CPU pressure sheds miners (they reconnect elsewhere via DNS)
//! rather than starving share validation / template building.
//!
//! See `bins/ghost-pool/src/capacity.rs` for how `max_capacity` is derived
//! per node from CPU/RAM/FD limits.

use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Deserialize)]
pub struct LoadBalancerConfig {
    #[serde(default = "default_ghost_pool_url")]
    pub ghost_pool_url: String,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// Minimum utilisation gap (in percentage points) before redirecting a
    /// new connection. Default 5: only divert if a peer is ≥5% less utilised.
    /// Setting this too low causes ping-pong on near-balanced clusters.
    #[serde(default = "default_proxy_threshold_pct")]
    pub proxy_threshold_pct: u32,
    #[serde(default = "default_proxy_timeout_ms")]
    pub proxy_timeout_ms: u64,

    // Capacity thresholds (% of local max_capacity).
    #[serde(default = "default_warn_pct")]
    pub warn_pct: u32,
    #[serde(default = "default_reject_pct")]
    pub reject_pct: u32,
    #[serde(default = "default_evict_pct")]
    pub evict_pct: u32,

    /// Compute-protection shedding (opt-in, default off). When enabled, if this node's
    /// 1-minute load average per core reaches `compute_evict_pct`%, the node enters `Critical`:
    /// it stops accepting new miners and sheds existing ones (they reconnect via DNS to a
    /// less-loaded node), so a node under compute pressure protects itself instead of degrading
    /// share validation / block-template building.
    #[serde(default)]
    pub compute_shed_enabled: bool,
    #[serde(default = "default_compute_evict_pct")]
    pub compute_evict_pct: u32,
    /// Miners to shed per shedding tick (gentle: re-evaluated each tick).
    #[serde(default = "default_shed_batch_size")]
    pub shed_batch_size: u32,
}

fn default_ghost_pool_url() -> String {
    "127.0.0.1:8080".to_string()
}
fn default_poll_interval() -> u64 {
    10
}
fn default_proxy_threshold_pct() -> u32 {
    5
}
fn default_proxy_timeout_ms() -> u64 {
    5000
}
fn default_warn_pct() -> u32 {
    80
}
fn default_reject_pct() -> u32 {
    90
}
fn default_evict_pct() -> u32 {
    95
}
fn default_compute_evict_pct() -> u32 {
    90
}
fn default_shed_batch_size() -> u32 {
    1
}

#[derive(Debug, Clone, Deserialize)]
struct PoolNodesResponse {
    this_node: ThisNode,
    peers: Vec<PeerInfo>,
}

#[derive(Debug, Clone, Deserialize)]
struct ThisNode {
    miner_count: u32,
    /// 0 = peer (ghost-pool) hasn't reported capacity yet (very early boot).
    #[serde(default)]
    max_capacity: u32,
}

/// Which listener a connection arrived on, and therefore which listener it may be sent to.
///
/// These are NOT interchangeable. The tiers exist because one difficulty cannot serve both a
/// bitaxe and a rented petahash order, so proxying a farm connection to a peer's hobby port
/// hands a large miner a floor sized for a small one — the exact flood the tier prevents. A
/// 100 TH/s miner on a 2,328 floor produces ~896 shares in four minutes against the ~24 it
/// should, so misrouting one is worse than not balancing it at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Hobby,
    Farm,
}

#[derive(Debug, Clone, Deserialize)]
struct PeerInfo {
    public_address: String,
    miner_count: u32,
    public_mining: bool,
    #[allow(dead_code)]
    last_seen: u64,
    /// Hardware-derived effective max miners. 0 = legacy / pre-update peer
    /// that doesn't broadcast capacity yet — the LB excludes such peers
    /// from utilisation routing (treated as fully utilised) so we don't
    /// flood them with traffic on stale assumptions.
    #[serde(default)]
    max_capacity: u32,
    /// The peer's SV1 hobby listener. `None` on a peer that predates tier advertisement;
    /// such a peer is assumed to serve hobby on the default port, which is what every node
    /// did before the farm tier existed.
    #[serde(default)]
    hobby_port: Option<u16>,
    /// The peer's SV1 farm/rental listener, if it runs one.
    ///
    /// `None` means either "no farm tier" or "too old to say", and both must be treated the
    /// same way: NOT a farm routing target. Assuming a port here is how a farm miner ends up
    /// on a hobby floor, so absence disqualifies the peer rather than defaulting.
    #[serde(default)]
    farm_port: Option<u16>,
}

impl PeerInfo {
    /// The peer's listener for `tier`, or `None` if it does not advertise one.
    fn port_for(&self, tier: Tier) -> Option<u16> {
        match tier {
            Tier::Hobby => Some(self.hobby_port.unwrap_or(DEFAULT_HOBBY_PORT)),
            Tier::Farm => self.farm_port,
        }
    }

    /// Host half of `public_address`, which peers report as `ip:port`.
    fn host(&self) -> &str {
        self.public_address
            .split(':')
            .next()
            .unwrap_or(&self.public_address)
    }

    /// Routing target for `tier`, or `None` if this peer cannot serve it.
    fn target_for(&self, tier: Tier) -> Option<SocketAddr> {
        let port = self.port_for(tier)?;
        format!("{}:{}", self.host(), port).parse().ok()
    }
}

/// Where hobby miners have always been served. Used only for peers that predate tier
/// advertisement — a peer that DOES advertise is believed rather than assumed.
const DEFAULT_HOBBY_PORT: u16 = 3333;

struct Cache {
    this_node: ThisNode,
    peers: Vec<PeerInfo>,
    updated_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapacityState {
    Normal,
    Warning,
    RejectNew,
    Critical,
}

pub struct LoadBalancer {
    config: LoadBalancerConfig,
    cache: Arc<RwLock<Option<Cache>>>,
    connections_proxied: AtomicU64,
    proxy_failures: AtomicU64,
    rejections_capacity: AtomicU64,
    /// Round-robin index for tie-breaking among equally-utilised peers.
    /// Without this we always pick the first peer in cache order, biasing
    /// toward whichever VM was registered first at the source side.
    rr_index: AtomicU32,
}

impl LoadBalancer {
    pub fn new(config: LoadBalancerConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            cache: Arc::new(RwLock::new(None)),
            connections_proxied: AtomicU64::new(0),
            proxy_failures: AtomicU64::new(0),
            rejections_capacity: AtomicU64::new(0),
            rr_index: AtomicU32::new(0),
        })
    }

    pub fn spawn_poller(self: &Arc<Self>) {
        let lb = Arc::clone(self);
        tokio::spawn(async move {
            let interval = Duration::from_secs(lb.config.poll_interval_secs);
            loop {
                match poll_pool_nodes(&lb.config.ghost_pool_url).await {
                    Ok(resp) => {
                        let mut cache = lb.cache.write().await;
                        *cache = Some(Cache {
                            this_node: resp.this_node,
                            peers: resp.peers,
                            updated_at: Instant::now(),
                        });
                    }
                    Err(e) => {
                        debug!("Load balancer poll failed (non-fatal): {}", e);
                    }
                }
                tokio::time::sleep(interval).await;
            }
        });
    }

    /// Compute this node's capacity state for accept/reject decisions.
    /// Falls back to `Normal` if the cache hasn't populated yet (better to
    /// err on the side of accepting connections than to refuse during boot).
    pub async fn check_capacity(&self) -> CapacityState {
        // Compute protection (opt-in): a node under real CPU pressure goes straight to Critical
        // regardless of miner count, so share validation / template building never starves.
        if self.config.compute_shed_enabled {
            if let Some(load_pct) = read_loadavg_pct() {
                if load_pct >= self.config.compute_evict_pct {
                    return CapacityState::Critical;
                }
            }
        }
        let cache = self.cache.read().await;
        let Some(cache) = cache.as_ref() else {
            return CapacityState::Normal;
        };
        let this = &cache.this_node;
        if this.max_capacity == 0 {
            return CapacityState::Normal;
        }
        let pct = (this.miner_count.saturating_mul(100)) / this.max_capacity;
        state_for_pct(
            pct,
            self.config.warn_pct,
            self.config.reject_pct,
            self.config.evict_pct,
        )
    }

    /// Should this connection be rejected at the TCP layer due to local
    /// over-capacity? sv1_server calls this BEFORE registering the downstream.
    pub async fn should_reject_for_capacity(&self) -> bool {
        matches!(
            self.check_capacity().await,
            CapacityState::RejectNew | CapacityState::Critical
        )
    }

    /// Decide whether to proxy an incoming connection to a less-utilised peer.
    /// Returns `Some(target_addr)` if proxying, `None` to handle locally.
    pub async fn should_proxy(
        &self,
        local_downstream_count: usize,
        source_addr: std::net::IpAddr,
        tier: Tier,
    ) -> Option<SocketAddr> {
        let cache = self.cache.read().await;
        let cache = cache.as_ref()?;

        // Stale cache (>3x poll interval) → handle locally.
        if cache.updated_at.elapsed() > Duration::from_secs(self.config.poll_interval_secs * 3) {
            return None;
        }

        // Never re-proxy a connection that arrived from a known peer node.
        // Without this check, A → B → A creates an infinite connection storm.
        let source_str = source_addr.to_string();
        let from_peer = cache.peers.iter().any(|p| {
            p.public_address
                .split(':')
                .next()
                .map(|ip| ip == source_str)
                .unwrap_or(false)
        });
        if from_peer {
            return None;
        }

        // Compute our local utilisation (overrides cache.this_node.miner_count
        // because the cache lags by up to poll_interval_secs and the live
        // count from sv1_server is more accurate for THIS decision).
        let my_capacity = cache.this_node.max_capacity;
        if my_capacity == 0 {
            // No capacity reported — fall back to absolute-count comparison
            // so the LB still does *something* during early boot.
            return self.fallback_pick_by_count(local_downstream_count, cache, tier);
        }
        let my_util_pct =
            ((local_downstream_count as u32).saturating_mul(100)) / my_capacity.max(1);

        // Filter eligible peers: public_mining, with reported capacity,
        // not over their own reject threshold.
        let candidates: Vec<&PeerInfo> = cache
            .peers
            .iter()
            .filter(|p| {
                p.public_mining
                    && !p.public_address.is_empty()
                    && p.max_capacity > 0
                    && peer_util_pct(p) < self.config.reject_pct
                    // A peer that does not serve this tier is not a candidate for it. For
                    // Farm this excludes every peer that has not advertised a farm port,
                    // including all peers running a build from before tier advertisement.
                    && p.port_for(tier).is_some()
            })
            .collect();
        if candidates.is_empty() {
            return None;
        }

        // Lowest utilisation wins. Round-robin among ties.
        let min_pct = candidates.iter().map(|p| peer_util_pct(p)).min()?;
        let tied: Vec<&PeerInfo> = candidates
            .iter()
            .copied()
            .filter(|p| peer_util_pct(p) == min_pct)
            .collect();
        if tied.is_empty() {
            return None;
        }
        let idx = self.rr_index.fetch_add(1, Ordering::Relaxed) as usize % tied.len();
        let best = tied[idx];

        // Only redirect if we exceed the best peer by the threshold percentage.
        // Without this guard, perfectly-balanced clusters ping-pong every tick.
        if my_util_pct < min_pct.saturating_add(self.config.proxy_threshold_pct) {
            return None;
        }

        best.target_for(tier)
    }

    fn fallback_pick_by_count(
        &self,
        local_downstream_count: usize,
        cache: &Cache,
        tier: Tier,
    ) -> Option<SocketAddr> {
        let local_count = local_downstream_count as u32;
        let best = cache
            .peers
            .iter()
            .filter(|p| {
                p.public_mining && !p.public_address.is_empty() && p.port_for(tier).is_some()
            })
            .min_by_key(|p| p.miner_count)?;
        // Conservative fallback threshold: only divert if local exceeds peer by 2.
        if local_count < best.miner_count + 2 {
            return None;
        }
        best.target_for(tier)
    }

    /// Spawn a background task that pipes bytes between the miner and the target node.
    pub fn spawn_proxy(self: &Arc<Self>, client: TcpStream, target: SocketAddr) {
        let lb = Arc::clone(self);
        let timeout = Duration::from_millis(lb.config.proxy_timeout_ms);
        tokio::spawn(async move {
            match tokio::time::timeout(timeout, TcpStream::connect(target)).await {
                Ok(Ok(mut server)) => {
                    lb.connections_proxied.fetch_add(1, Ordering::Relaxed);
                    info!("Proxying miner to {} (utilisation-based)", target);
                    let mut client = client;
                    if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut server).await {
                        debug!("Proxied connection ended: {}", e);
                    }
                }
                Ok(Err(e)) => {
                    lb.proxy_failures.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        "Proxy target {} unreachable: {} — miner will reconnect via DNS",
                        target, e
                    );
                }
                Err(_) => {
                    lb.proxy_failures.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        "Proxy connect to {} timed out — miner will reconnect via DNS",
                        target
                    );
                }
            }
        });
    }

    /// Record a capacity-based rejection for stats.
    pub fn record_capacity_rejection(&self) {
        self.rejections_capacity.fetch_add(1, Ordering::Relaxed);
    }

    pub fn stats(&self) -> (u64, u64, u64) {
        (
            self.connections_proxied.load(Ordering::Relaxed),
            self.proxy_failures.load(Ordering::Relaxed),
            self.rejections_capacity.load(Ordering::Relaxed),
        )
    }

    /// Whether compute-protection shedding is enabled (accept loop only spawns the
    /// shed tick when this is true).
    pub fn compute_shed_enabled(&self) -> bool {
        self.config.compute_shed_enabled
    }

    /// Miners to shed per shedding tick.
    pub fn shed_batch_size(&self) -> usize {
        self.config.shed_batch_size.max(1) as usize
    }

    /// True when this node is `Critical` (over compute or miner-capacity threshold) — the
    /// accept loop's shed tick uses this to evict existing miners so they reconnect elsewhere.
    pub async fn should_shed(&self) -> bool {
        self.config.compute_shed_enabled
            && matches!(self.check_capacity().await, CapacityState::Critical)
    }
}

/// Map a utilisation percentage to a capacity state given the three thresholds. Pure so the
/// tiering is unit-testable independent of the cache/poll plumbing.
fn state_for_pct(pct: u32, warn: u32, reject: u32, evict: u32) -> CapacityState {
    match pct {
        x if x >= evict => CapacityState::Critical,
        x if x >= reject => CapacityState::RejectNew,
        x if x >= warn => CapacityState::Warning,
        _ => CapacityState::Normal,
    }
}

/// This node's 1-minute load average as a percentage of available cores (100 = one full
/// core-equivalent of load per core). Linux-only via `/proc/loadavg`; `None` elsewhere or on
/// read failure, which callers treat as "no compute-pressure signal".
fn read_loadavg_pct() -> Option<u32> {
    let contents = std::fs::read_to_string("/proc/loadavg").ok()?;
    let load1: f64 = contents.split_whitespace().next()?.parse().ok()?;
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1) as f64;
    let pct = (load1 / cores * 100.0).round().clamp(0.0, 100_000.0);
    Some(pct as u32)
}

fn peer_util_pct(p: &PeerInfo) -> u32 {
    if p.max_capacity == 0 {
        return 100; // unknown → treat as full so LB never preferentially routes here
    }
    p.miner_count.saturating_mul(100) / p.max_capacity
}

/// Minimal HTTP/1.1 GET to a local endpoint, returns parsed JSON.
async fn poll_pool_nodes(host_port: &str) -> Result<PoolNodesResponse, String> {
    let mut stream = TcpStream::connect(host_port)
        .await
        .map_err(|e| format!("connect: {}", e))?;

    let request = format!(
        "GET /api/internal/pool-nodes HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        host_port
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write: {}", e))?;

    let mut buf = Vec::with_capacity(4096);
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("read: {}", e))?;

    let response = String::from_utf8_lossy(&buf);
    let body = response.split("\r\n\r\n").nth(1).ok_or("no HTTP body")?;

    serde_json::from_str(body).map_err(|e| format!("json: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_thresholds_map_correctly() {
        assert_eq!(state_for_pct(0, 80, 90, 95), CapacityState::Normal);
        assert_eq!(state_for_pct(79, 80, 90, 95), CapacityState::Normal);
        assert_eq!(state_for_pct(80, 80, 90, 95), CapacityState::Warning);
        assert_eq!(state_for_pct(89, 80, 90, 95), CapacityState::Warning);
        assert_eq!(state_for_pct(90, 80, 90, 95), CapacityState::RejectNew);
        assert_eq!(state_for_pct(94, 80, 90, 95), CapacityState::RejectNew);
        assert_eq!(state_for_pct(95, 80, 90, 95), CapacityState::Critical);
        assert_eq!(state_for_pct(200, 80, 90, 95), CapacityState::Critical);
    }

    #[test]
    fn loadavg_pct_is_bounded() {
        // On Linux this reads real /proc/loadavg; just assert it's a sane bounded value.
        if let Some(pct) = read_loadavg_pct() {
            assert!(pct < 100_000);
        }
    }

    fn cfg() -> LoadBalancerConfig {
        LoadBalancerConfig {
            ghost_pool_url: "127.0.0.1:8080".into(),
            poll_interval_secs: 10,
            proxy_threshold_pct: 5,
            proxy_timeout_ms: 5000,
            warn_pct: 80,
            reject_pct: 90,
            evict_pct: 95,
            compute_shed_enabled: false,
            compute_evict_pct: 90,
            shed_batch_size: 1,
        }
    }

    fn cache_with(this_count: u32, this_cap: u32, peers: Vec<(u32, u32, &str)>) -> Cache {
        Cache {
            this_node: ThisNode {
                miner_count: this_count,
                max_capacity: this_cap,
            },
            peers: peers
                .into_iter()
                .map(|(c, cap, addr)| PeerInfo {
                    public_address: addr.into(),
                    miner_count: c,
                    public_mining: true,
                    last_seen: 0,
                    max_capacity: cap,
                    hobby_port: None,
                    farm_port: None,
                })
                .collect(),
            updated_at: Instant::now(),
        }
    }

    fn peer(addr: &str, hobby: Option<u16>, farm: Option<u16>) -> PeerInfo {
        PeerInfo {
            public_address: addr.into(),
            miner_count: 0,
            public_mining: true,
            last_seen: 0,
            max_capacity: 100,
            hobby_port: hobby,
            farm_port: farm,
        }
    }

    /// A peer too old to advertise ports is still a valid HOBBY target — that is where every
    /// node served SV1 before the farm tier existed, so assuming it preserves old behaviour.
    #[test]
    fn a_peer_that_advertises_nothing_is_still_a_hobby_target() {
        let p = peer("10.0.0.1:8080", None, None);
        assert_eq!(
            p.target_for(Tier::Hobby),
            Some("10.0.0.1:3333".parse().unwrap())
        );
    }

    /// ...but it is NOT a farm target. This is the whole point of #472: guessing a farm port
    /// is how a 100 TH/s miner lands on a 2,328 hobby floor, which is worse than not
    /// balancing it at all.
    #[test]
    fn a_peer_that_advertises_no_farm_port_is_never_a_farm_target() {
        let p = peer("10.0.0.1:8080", None, None);
        assert_eq!(p.target_for(Tier::Farm), None);

        // Advertising a hobby port does not imply a farm one either.
        let hobby_only = peer("10.0.0.2:8080", Some(3333), None);
        assert_eq!(hobby_only.target_for(Tier::Farm), None);
    }

    /// An advertised port is believed rather than assumed, for both tiers.
    #[test]
    fn advertised_ports_are_used_verbatim() {
        let p = peer("10.0.0.3:8080", Some(3400), Some(4444));
        assert_eq!(
            p.target_for(Tier::Hobby),
            Some("10.0.0.3:3400".parse().unwrap())
        );
        assert_eq!(
            p.target_for(Tier::Farm),
            Some("10.0.0.3:4444".parse().unwrap())
        );
    }

    /// Farm routing stays inert on a fleet where nobody advertises, which is the state this
    /// change ships in — so it cannot alter behaviour until the gossip half lands.
    #[tokio::test]
    async fn farm_routing_is_inert_until_peers_advertise() {
        let lb = LoadBalancer::new(cfg());
        // A wildly under-utilised peer that would certainly win hobby routing.
        *lb.cache.write().await = Some(cache_with(900, 1000, vec![(0, 1000, "10.0.0.9:8080")]));

        let src: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        assert!(
            lb.should_proxy(900, src, Tier::Hobby).await.is_some(),
            "hobby routing must still work"
        );
        assert!(
            lb.should_proxy(900, src, Tier::Farm).await.is_none(),
            "farm routing must not fall back to a hobby port"
        );
    }

    #[tokio::test]
    async fn capacity_state_thresholds() {
        let lb = LoadBalancer::new(cfg());
        // 0% util → Normal
        *lb.cache.write().await = Some(cache_with(0, 1000, vec![]));
        assert_eq!(lb.check_capacity().await, CapacityState::Normal);

        // 80% → Warning
        *lb.cache.write().await = Some(cache_with(800, 1000, vec![]));
        assert_eq!(lb.check_capacity().await, CapacityState::Warning);

        // 90% → RejectNew
        *lb.cache.write().await = Some(cache_with(900, 1000, vec![]));
        assert_eq!(lb.check_capacity().await, CapacityState::RejectNew);

        // 95% → Critical
        *lb.cache.write().await = Some(cache_with(950, 1000, vec![]));
        assert_eq!(lb.check_capacity().await, CapacityState::Critical);

        // 0 max_capacity (pre-update) → Normal (don't refuse during boot)
        *lb.cache.write().await = Some(cache_with(500, 0, vec![]));
        assert_eq!(lb.check_capacity().await, CapacityState::Normal);
    }

    #[tokio::test]
    async fn utilisation_routing_prefers_low_util() {
        let lb = LoadBalancer::new(cfg());
        // me: 200/1000 = 20% util
        // peer A: 50/100 = 50% util  (small node, half full)
        // peer B: 5000/10000 = 50% util  (big node, half full)
        // peer C: 100/10000 = 1% util  (big node, mostly empty)
        *lb.cache.write().await = Some(cache_with(
            200,
            1000,
            vec![
                (50, 100, "10.0.0.1:8559"),
                (5000, 10000, "10.0.0.2:8559"),
                (100, 10000, "10.0.0.3:8559"),
            ],
        ));
        // I'm at 20%. Best peer (C) is at 1%. Gap is 19% > threshold 5%.
        // Should pick C even though A has more absolute free count headroom
        // than C in % terms — wait, all three peers have less util than me,
        // but C has the LOWEST util.
        let target = lb
            .should_proxy(200, "8.8.8.8".parse().unwrap(), Tier::Hobby)
            .await
            .expect("should propose a target");
        assert!(
            target.to_string().starts_with("10.0.0.3:"),
            "expected peer C (lowest utilisation), got {}",
            target
        );
    }

    #[tokio::test]
    async fn no_proxy_when_within_threshold() {
        let lb = LoadBalancer::new(cfg());
        // me: 100/1000 = 10%, peer: 80/1000 = 8% — gap 2%, threshold 5% → no
        *lb.cache.write().await = Some(cache_with(100, 1000, vec![(80, 1000, "10.0.0.1:8559")]));
        assert!(lb
            .should_proxy(100, "8.8.8.8".parse().unwrap(), Tier::Hobby)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn skips_peers_at_or_above_reject_threshold() {
        let lb = LoadBalancer::new(cfg());
        // me: 200/1000 = 20%; only peer is at 91% (over reject_pct 90)
        *lb.cache.write().await = Some(cache_with(200, 1000, vec![(910, 1000, "10.0.0.1:8559")]));
        assert!(lb
            .should_proxy(200, "8.8.8.8".parse().unwrap(), Tier::Hobby)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn legacy_peers_with_zero_capacity_excluded() {
        let lb = LoadBalancer::new(cfg());
        // me: 100/1000 = 10%; peer reports 0 capacity (legacy)
        *lb.cache.write().await = Some(cache_with(500, 1000, vec![(0, 0, "10.0.0.1:8559")]));
        assert!(
            lb.should_proxy(500, "8.8.8.8".parse().unwrap(), Tier::Hobby)
                .await
                .is_none(),
            "legacy peers shouldn't be routed to before they upgrade"
        );
    }

    #[tokio::test]
    async fn round_robin_among_tied_peers() {
        let lb = LoadBalancer::new(cfg());
        // Three peers all at 0% utilisation, me at 20%.
        *lb.cache.write().await = Some(cache_with(
            200,
            1000,
            vec![
                (0, 1000, "10.0.0.1:8559"),
                (0, 1000, "10.0.0.2:8559"),
                (0, 1000, "10.0.0.3:8559"),
            ],
        ));
        let mut hits = std::collections::HashSet::new();
        for _ in 0..6 {
            if let Some(t) = lb
                .should_proxy(200, "8.8.8.8".parse().unwrap(), Tier::Hobby)
                .await
            {
                hits.insert(t.to_string());
            }
        }
        assert!(
            hits.len() >= 2,
            "round-robin should pick more than one peer when all tied: {:?}",
            hits
        );
    }
}
