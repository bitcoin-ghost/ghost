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
//| FILE: metrics.rs                                                                                                     |
//|======================================================================================================================|

//! Prometheus Metrics for Bitcoin Ghost
//!
//! Provides metric collection and exposition for monitoring.
//!
//! # Example
//!
//! ```ignore
//! use ghost_common::metrics::{Metrics, MetricsConfig};
//!
//! let metrics = Metrics::new(MetricsConfig::default());
//! metrics.miners_connected.set(42);
//! metrics.shares_total.inc();
//!
//! // Get prometheus-formatted output
//! let output = metrics.render();
//! ```

use parking_lot::RwLock;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Metrics configuration
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Metric name prefix
    pub prefix: String,
    /// Include process metrics
    pub include_process_metrics: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            prefix: "ghost_pool".to_string(),
            include_process_metrics: true,
        }
    }
}

/// Counter metric (monotonically increasing)
#[derive(Debug, Default)]
pub struct Counter {
    value: AtomicU64,
}

impl Counter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_by(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// Gauge metric (can go up or down)
#[derive(Debug, Default)]
pub struct Gauge {
    value: AtomicI64,
}

impl Gauge {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, v: i64) {
        self.value.store(v, Ordering::Relaxed);
    }

    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn get(&self) -> i64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// Histogram bucket
#[derive(Debug)]
pub struct HistogramBucket {
    le: f64,
    count: AtomicU64,
}

/// Histogram metric for measuring distributions
#[derive(Debug)]
pub struct Histogram {
    buckets: Vec<HistogramBucket>,
    sum: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    pub fn new(bucket_boundaries: &[f64]) -> Self {
        let buckets = bucket_boundaries
            .iter()
            .map(|&le| HistogramBucket {
                le,
                count: AtomicU64::new(0),
            })
            .collect();

        Self {
            buckets,
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Default buckets for latency measurements (milliseconds)
    pub fn latency_buckets() -> Self {
        Self::new(&[
            1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 5000.0,
        ])
    }

    pub fn observe(&self, value: f64) {
        // Increment appropriate buckets
        for bucket in &self.buckets {
            if value <= bucket.le {
                bucket.count.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Add to sum (convert to u64 bits for atomic storage)
        let value_bits = (value * 1000.0) as u64; // Store as millis for precision
        self.sum.fetch_add(value_bits, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

/// Main metrics registry for Ghost Pool
#[derive(Debug)]
pub struct Metrics {
    /// Configuration
    config: MetricsConfig,
    /// Start time for uptime calculation
    start_time: Instant,

    // =========================================================================
    // Connection Metrics
    // =========================================================================
    /// Number of connected miners
    pub miners_connected: Gauge,
    /// Number of active miners (submitted share recently)
    pub miners_active: Gauge,
    /// Total miner connections ever
    pub connections_total: Counter,
    /// Connection errors
    pub connection_errors_total: Counter,

    // =========================================================================
    // Mining Metrics
    // =========================================================================
    /// Total shares submitted
    pub shares_total: Counter,
    /// Valid shares
    pub shares_valid: Counter,
    /// Invalid/rejected shares
    pub shares_invalid: Counter,
    /// Stale shares
    pub shares_stale: Counter,
    /// Total work (difficulty sum)
    pub work_total: Counter,
    /// Current pool hashrate estimate
    pub hashrate_total: Gauge,
    /// Blocks found
    pub blocks_found_total: Counter,

    // =========================================================================
    // Round Metrics
    // =========================================================================
    /// Current round ID
    pub current_round: Gauge,
    /// Round duration histogram (seconds)
    pub round_duration_seconds: Histogram,
    /// Shares per round histogram
    pub shares_per_round: Histogram,

    // =========================================================================
    // Consensus Metrics
    // =========================================================================
    /// Consensus votes cast
    pub consensus_votes_total: Counter,
    /// Consensus rounds completed
    pub consensus_rounds_total: Counter,
    /// Consensus participation percentage
    pub consensus_participation_percent: Gauge,
    /// Connected peers in mesh
    pub peers_connected: Gauge,

    // =========================================================================
    // Payout Metrics
    // =========================================================================
    /// Payouts processed
    pub payouts_total: Counter,
    /// Total satoshis paid out
    pub payout_sats_total: Counter,
    /// Pending payouts
    pub pending_payouts: Gauge,
    /// Payout errors
    pub payout_errors_total: Counter,

    // =========================================================================
    // Bitcoin Core Metrics
    // =========================================================================
    /// Bitcoin Core connected status (1 = connected, 0 = disconnected)
    pub bitcoin_connected: Gauge,
    /// Current block height
    pub block_height: Gauge,
    /// Network difficulty
    pub network_difficulty: Gauge,

    // =========================================================================
    // Reorg / Chain Metrics
    // =========================================================================
    /// Number of reorgs detected
    pub reorgs_detected_total: Counter,
    /// Rounds orphaned due to reorgs
    pub rounds_orphaned_total: Counter,
    /// Proposals cancelled due to reorgs
    pub proposals_cancelled_total: Counter,

    // =========================================================================
    // Fault Tolerance Metrics
    // =========================================================================
    /// Circuit breaker trips
    pub circuit_breaker_trips_total: Counter,
    /// Circuit breaker currently open (1 = open, 0 = closed)
    pub circuit_breaker_open: Gauge,
    /// Clock skew detected (seconds, can be negative)
    pub clock_skew_secs: Gauge,

    // =========================================================================
    // Performance Metrics
    // =========================================================================
    /// Share processing latency (milliseconds)
    pub share_latency_ms: Histogram,
    /// Template generation latency (milliseconds)
    pub template_latency_ms: Histogram,
    /// RPC call latency (milliseconds)
    pub rpc_latency_ms: Histogram,

    /// Cached render output with TTL
    cached_render: RwLock<(String, Instant)>,
}

impl Metrics {
    /// Create a new metrics registry
    pub fn new(config: MetricsConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            start_time: Instant::now(),

            // Connection
            miners_connected: Gauge::new(),
            miners_active: Gauge::new(),
            connections_total: Counter::new(),
            connection_errors_total: Counter::new(),

            // Mining
            shares_total: Counter::new(),
            shares_valid: Counter::new(),
            shares_invalid: Counter::new(),
            shares_stale: Counter::new(),
            work_total: Counter::new(),
            hashrate_total: Gauge::new(),
            blocks_found_total: Counter::new(),

            // Round
            current_round: Gauge::new(),
            round_duration_seconds: Histogram::new(&[10.0, 30.0, 60.0, 120.0, 300.0, 600.0]),
            shares_per_round: Histogram::new(&[100.0, 500.0, 1000.0, 5000.0, 10000.0, 50000.0]),

            // Consensus
            consensus_votes_total: Counter::new(),
            consensus_rounds_total: Counter::new(),
            consensus_participation_percent: Gauge::new(),
            peers_connected: Gauge::new(),

            // Payout
            payouts_total: Counter::new(),
            payout_sats_total: Counter::new(),
            pending_payouts: Gauge::new(),
            payout_errors_total: Counter::new(),

            // Bitcoin
            bitcoin_connected: Gauge::new(),
            block_height: Gauge::new(),
            network_difficulty: Gauge::new(),

            // Reorg / Chain
            reorgs_detected_total: Counter::new(),
            rounds_orphaned_total: Counter::new(),
            proposals_cancelled_total: Counter::new(),

            // Fault Tolerance
            circuit_breaker_trips_total: Counter::new(),
            circuit_breaker_open: Gauge::new(),
            clock_skew_secs: Gauge::new(),

            // Performance
            share_latency_ms: Histogram::latency_buckets(),
            template_latency_ms: Histogram::latency_buckets(),
            rpc_latency_ms: Histogram::latency_buckets(),

            cached_render: RwLock::new((String::new(), Instant::now())),
        })
    }

    /// Create with default configuration
    pub fn default_metrics() -> Arc<Self> {
        Self::new(MetricsConfig::default())
    }

    /// Get uptime in seconds
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Render metrics in Prometheus exposition format
    pub fn render(&self) -> String {
        let prefix = &self.config.prefix;
        let mut output = String::with_capacity(4096);

        // Helper macro to write a metric
        macro_rules! write_counter {
            ($name:expr, $help:expr, $value:expr) => {
                output.push_str(&format!(
                    "# HELP {}_{} {}\n# TYPE {}_{} counter\n{}_{} {}\n",
                    prefix, $name, $help, prefix, $name, prefix, $name, $value
                ));
            };
        }

        macro_rules! write_gauge {
            ($name:expr, $help:expr, $value:expr) => {
                output.push_str(&format!(
                    "# HELP {}_{} {}\n# TYPE {}_{} gauge\n{}_{} {}\n",
                    prefix, $name, $help, prefix, $name, prefix, $name, $value
                ));
            };
        }

        // Uptime
        write_gauge!("uptime_secs", "Node uptime in seconds", self.uptime_secs());

        // Connection metrics
        write_gauge!(
            "miners_connected",
            "Number of connected miners",
            self.miners_connected.get()
        );
        write_gauge!(
            "miners_active",
            "Number of active miners",
            self.miners_active.get()
        );
        write_counter!(
            "connections_total",
            "Total miner connections",
            self.connections_total.get()
        );
        write_counter!(
            "connection_errors_total",
            "Connection errors",
            self.connection_errors_total.get()
        );

        // Mining metrics
        write_counter!(
            "shares_total",
            "Total shares submitted",
            self.shares_total.get()
        );
        write_counter!("shares_valid", "Valid shares", self.shares_valid.get());
        write_counter!(
            "shares_invalid",
            "Invalid shares",
            self.shares_invalid.get()
        );
        write_counter!("shares_stale", "Stale shares", self.shares_stale.get());
        write_counter!(
            "work_total",
            "Total work (difficulty sum)",
            self.work_total.get()
        );
        write_gauge!(
            "hashrate_total",
            "Estimated pool hashrate",
            self.hashrate_total.get()
        );
        write_counter!(
            "blocks_found_total",
            "Blocks found",
            self.blocks_found_total.get()
        );

        // Round metrics
        write_gauge!(
            "current_round",
            "Current round ID",
            self.current_round.get()
        );

        // Consensus metrics
        write_counter!(
            "consensus_votes_total",
            "Consensus votes cast",
            self.consensus_votes_total.get()
        );
        write_counter!(
            "consensus_rounds_total",
            "Consensus rounds completed",
            self.consensus_rounds_total.get()
        );
        write_gauge!(
            "consensus_participation_percent",
            "Consensus participation percentage",
            self.consensus_participation_percent.get()
        );
        write_gauge!(
            "peers_connected",
            "Connected P2P peers",
            self.peers_connected.get()
        );

        // Payout metrics
        write_counter!(
            "payouts_total",
            "Payouts processed",
            self.payouts_total.get()
        );
        write_counter!(
            "payout_sats_total",
            "Total satoshis paid out",
            self.payout_sats_total.get()
        );
        write_gauge!(
            "pending_payouts",
            "Pending payouts",
            self.pending_payouts.get()
        );
        write_counter!(
            "payout_errors_total",
            "Payout errors",
            self.payout_errors_total.get()
        );

        // Bitcoin metrics
        write_gauge!(
            "bitcoin_connected",
            "Bitcoin Core connection status",
            self.bitcoin_connected.get()
        );
        write_gauge!(
            "block_height",
            "Current block height",
            self.block_height.get()
        );
        write_gauge!(
            "network_difficulty",
            "Network difficulty",
            self.network_difficulty.get()
        );

        // Reorg metrics
        write_counter!(
            "reorgs_detected_total",
            "Number of blockchain reorgs detected",
            self.reorgs_detected_total.get()
        );
        write_counter!(
            "rounds_orphaned_total",
            "Rounds orphaned due to reorgs",
            self.rounds_orphaned_total.get()
        );
        write_counter!(
            "proposals_cancelled_total",
            "Proposals cancelled due to reorgs",
            self.proposals_cancelled_total.get()
        );

        // Fault tolerance metrics
        write_counter!(
            "circuit_breaker_trips_total",
            "Circuit breaker trips",
            self.circuit_breaker_trips_total.get()
        );
        write_gauge!(
            "circuit_breaker_open",
            "Circuit breaker open status (1 = open)",
            self.circuit_breaker_open.get()
        );
        write_gauge!(
            "clock_skew_secs",
            "Detected clock skew in seconds",
            self.clock_skew_secs.get()
        );

        // Latency histograms
        self.write_histogram(
            &mut output,
            "share_latency_ms",
            "Share processing latency in milliseconds",
            &self.share_latency_ms,
        );
        self.write_histogram(
            &mut output,
            "template_latency_ms",
            "Template generation latency in milliseconds",
            &self.template_latency_ms,
        );
        self.write_histogram(
            &mut output,
            "rpc_latency_ms",
            "RPC call latency in milliseconds",
            &self.rpc_latency_ms,
        );

        output
    }

    /// Render with 5-second TTL cache. Avoids regenerating Prometheus text on every scrape.
    pub fn render_cached(&self) -> String {
        const TTL: Duration = Duration::from_secs(5);

        // Fast path: read lock
        {
            let cached = self.cached_render.read();
            if !cached.0.is_empty() && cached.1.elapsed() < TTL {
                return cached.0.clone();
            }
        }

        // Slow path: write lock, double-check
        let mut cached = self.cached_render.write();
        if !cached.0.is_empty() && cached.1.elapsed() < TTL {
            return cached.0.clone();
        }

        let rendered = self.render();
        *cached = (rendered.clone(), Instant::now());
        rendered
    }

    fn write_histogram(&self, output: &mut String, name: &str, help: &str, histogram: &Histogram) {
        let prefix = &self.config.prefix;
        let full_name = format!("{}_{}", prefix, name);

        output.push_str(&format!(
            "# HELP {} {}\n# TYPE {} histogram\n",
            full_name, help, full_name
        ));

        let mut cumulative = 0u64;
        for bucket in &histogram.buckets {
            cumulative += bucket.count.load(Ordering::Relaxed);
            output.push_str(&format!(
                "{}_bucket{{le=\"{}\"}} {}\n",
                full_name, bucket.le, cumulative
            ));
        }

        output.push_str(&format!(
            "{}_bucket{{le=\"+Inf\"}} {}\n",
            full_name, cumulative
        ));
        output.push_str(&format!(
            "{}_sum {}\n",
            full_name,
            histogram.sum.load(Ordering::Relaxed) as f64 / 1000.0
        ));
        output.push_str(&format!(
            "{}_count {}\n",
            full_name,
            histogram.count.load(Ordering::Relaxed)
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter() {
        let counter = Counter::new();
        assert_eq!(counter.get(), 0);

        counter.inc();
        assert_eq!(counter.get(), 1);

        counter.inc_by(10);
        assert_eq!(counter.get(), 11);
    }

    #[test]
    fn test_gauge() {
        let gauge = Gauge::new();
        assert_eq!(gauge.get(), 0);

        gauge.set(42);
        assert_eq!(gauge.get(), 42);

        gauge.inc();
        assert_eq!(gauge.get(), 43);

        gauge.dec();
        assert_eq!(gauge.get(), 42);
    }

    #[test]
    fn test_histogram() {
        let histogram = Histogram::new(&[10.0, 50.0, 100.0]);

        histogram.observe(5.0);
        histogram.observe(25.0);
        histogram.observe(75.0);
        histogram.observe(150.0);

        assert_eq!(histogram.get_count(), 4);
    }

    #[test]
    fn test_metrics_render() {
        let metrics = Metrics::default_metrics();

        metrics.miners_connected.set(42);
        metrics.shares_total.inc_by(1000);
        metrics.blocks_found_total.inc();

        let output = metrics.render();

        assert!(output.contains("ghost_pool_miners_connected 42"));
        assert!(output.contains("ghost_pool_shares_total 1000"));
        assert!(output.contains("ghost_pool_blocks_found_total 1"));
    }

    #[test]
    fn test_metrics_render_cached() {
        let metrics = Metrics::new(MetricsConfig::default());
        let first = metrics.render_cached();
        assert!(!first.is_empty());
        // Second call within 5s returns same cached string
        let second = metrics.render_cached();
        assert_eq!(first, second);
    }

    #[test]
    fn test_uptime() {
        let metrics = Metrics::default_metrics();
        std::thread::sleep(std::time::Duration::from_millis(10));
        // uptime_secs returns u64, verify the function works (will be 0 since 10ms < 1s)
        let _ = metrics.uptime_secs();
    }
}
