//! ## Translator Configuration Module
//!
//! Defines [`TranslatorConfig`], the primary configuration structure for the Translator.
//!
//! This module provides the necessary structures to configure the Translator,
//! managing connections and settings for both upstream and downstream interfaces.
//!
//! This module handles:
//! - Upstream server address, port, and authentication key ([`UpstreamConfig`])
//! - Downstream interface address and port ([`DownstreamConfig`])
//! - Supported protocol versions
//! - Downstream difficulty adjustment parameters ([`DownstreamDifficultyConfig`])
use std::path::{Path, PathBuf};

use serde::Deserialize;
use std::net::SocketAddr;
use stratum_apps::{
    config_helpers::opt_path_from_toml,
    key_utils::Secp256k1PublicKey,
    utils::types::{Hashrate, SharesPerMinute},
};

/// Configuration for the Translator.
#[derive(Debug, Deserialize, Clone)]
pub struct TranslatorConfig {
    pub upstreams: Vec<Upstream>,
    /// The address for the downstream interface.
    pub downstream_address: String,
    /// The port for the downstream interface.
    pub downstream_port: u16,
    /// The maximum supported protocol version for communication.
    pub max_supported_version: u16,
    /// The minimum supported protocol version for communication.
    pub min_supported_version: u16,
    /// The size of the extranonce2 field for downstream mining connections.
    pub downstream_extranonce2_size: u16,
    /// The user identity/username to use when connecting to the pool.
    /// This will be appended with a counter for each mining channel (e.g., username.miner1,
    /// username.miner2).
    pub user_identity: String,
    /// Configuration settings for managing difficulty on the downstream connection.
    pub downstream_difficulty_config: DownstreamDifficultyConfig,
    /// Optional second listener for farm-scale and rented hashrate.
    ///
    /// One difficulty cannot serve both a 500 GH/s bitaxe and a 1 PH/s order. Sized for the
    /// bitaxe, a large order floods the pool for minutes while vardiff ramps (it caps
    /// corrections above 1000% to x3-x5 per 60s tick), and marketplaces reject a pool whose
    /// starting difficulty is far below the hashrate they are pointing at it. Sized for the
    /// order, a bitaxe finds a share every few minutes and looks dead.
    ///
    /// `None` (the default, and the shape of every existing config file) leaves the single
    /// listener exactly as it was.
    ///
    /// Note this is a CAPACITY control, not an anti-fraud one. Payout is proportional to
    /// work, and a share's work IS its difficulty (see `round.rs`), so 20 shares at
    /// difficulty 1,164 and one share at 23,283 are worth the same. A large miner on the
    /// hobby port gains nothing; it just costs the node 20x the share validation, bandwidth
    /// and database writes.
    #[serde(default)]
    pub farm_tier: Option<FarmTierConfig>,
    /// Whether to aggregate all downstream connections into a single upstream channel.
    /// If true, all miners share one channel. If false, each miner gets its own channel.
    pub aggregate_channels: bool,
    /// Protocol extensions that the translator supports (will request if supported by server).
    #[serde(default)]
    pub supported_extensions: Vec<u16>,
    /// Protocol extensions that the translator requires (server must support these).
    /// If the upstream server doesn't support these, the translator will fail over to another
    /// upstream.
    #[serde(default)]
    pub required_extensions: Vec<u16>,
    /// The path to the log file for the Translator.
    #[serde(default, deserialize_with = "opt_path_from_toml")]
    log_file: Option<PathBuf>,
    /// Optional monitoring server bind address
    #[serde(default)]
    monitoring_address: Option<SocketAddr>,
    #[serde(default)]
    monitoring_cache_refresh_secs: Option<u64>,
    /// Optional load balancer for distributing miners across pool nodes.
    /// When configured, the translator will proxy incoming connections to
    /// less-loaded peers discovered via the local ghost-pool mesh.
    #[serde(default)]
    pub load_balancer: Option<crate::load_balancer::LoadBalancerConfig>,
    /// Optional port for an opt-in TLS stratum listener.
    ///
    /// When `tls_port`, `tls_cert_path` and `tls_key_path` are all set, the translator binds a
    /// second listener on this port and terminates TLS for connecting miners (e.g. AxeOS/Bitaxe
    /// with "Connection Security: TLS" enabled), feeding accepted connections through the same
    /// downstream path as the plain-TCP listener. If any of the three are unset, no TLS listener
    /// is created and behaviour is unchanged.
    #[serde(default)]
    pub tls_port: Option<u16>,
    /// Path to the PEM-encoded certificate chain for the TLS listener.
    #[serde(default)]
    pub tls_cert_path: Option<String>,
    /// Path to the PEM-encoded private key for the TLS listener.
    #[serde(default)]
    pub tls_key_path: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Upstream {
    /// The address of the upstream server.
    pub address: String,
    /// The port of the upstream server.
    pub port: u16,
    /// The Secp256k1 public key used to authenticate the upstream authority.
    pub authority_pubkey: Secp256k1PublicKey,
}

impl Upstream {
    /// Creates a new `UpstreamConfig` instance.
    pub fn new(address: String, port: u16, authority_pubkey: Secp256k1PublicKey) -> Self {
        Self {
            address,
            port,
            authority_pubkey,
        }
    }
}

impl TranslatorConfig {
    /// Creates a new `TranslatorConfig` instance with the specified upstream and downstream
    /// configurations and version constraints.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        upstreams: Vec<Upstream>,
        downstream_address: String,
        downstream_port: u16,
        downstream_difficulty_config: DownstreamDifficultyConfig,
        max_supported_version: u16,
        min_supported_version: u16,
        downstream_extranonce2_size: u16,
        user_identity: String,
        aggregate_channels: bool,
        supported_extensions: Vec<u16>,
        required_extensions: Vec<u16>,
        monitoring_address: Option<SocketAddr>,
        monitoring_cache_refresh_secs: Option<u64>,
    ) -> Self {
        Self {
            upstreams,
            downstream_address,
            downstream_port,
            max_supported_version,
            min_supported_version,
            downstream_extranonce2_size,
            user_identity,
            downstream_difficulty_config,
            aggregate_channels,
            supported_extensions,
            required_extensions,
            log_file: None,
            monitoring_address,
            monitoring_cache_refresh_secs,
            load_balancer: None,
            // Optional like the TLS listener: absent means the single hobby listener only,
            // which is what every existing config file produces.
            farm_tier: None,
            tls_port: None,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }

    /// Returns the monitoring server bind address (if enabled)
    pub fn monitoring_address(&self) -> Option<SocketAddr> {
        self.monitoring_address
    }

    /// Returns the monitoring cache refresh interval in seconds.
    pub fn monitoring_cache_refresh_secs(&self) -> Option<u64> {
        self.monitoring_cache_refresh_secs
    }

    pub fn set_log_dir(&mut self, log_dir: Option<PathBuf>) {
        if let Some(dir) = log_dir {
            self.log_file = Some(dir);
        }
    }
    pub fn log_dir(&self) -> Option<&Path> {
        self.log_file.as_deref()
    }
}

/// Configuration settings for managing difficulty adjustments on the downstream connection.
#[derive(Debug, Deserialize, Clone)]
pub struct DownstreamDifficultyConfig {
    /// The minimum hashrate expected from an individual miner on the downstream connection.
    pub min_individual_miner_hashrate: Hashrate,
    /// The target number of shares per minute for difficulty adjustment.
    pub shares_per_minute: SharesPerMinute,
    /// Whether to enable variable difficulty adjustment mechanism.
    /// If false, difficulty will be managed by upstream (useful with JDC).
    pub enable_vardiff: bool,
    /// Interval in seconds for sending keepalive jobs to downstream miners.
    /// The translator will send periodic mining.notify messages with updated time
    /// to prevent SV1 miners from timing out when the upstream doesn't send new jobs
    /// frequently enough (e.g., due to low Bitcoin mempool activity).
    /// Set to 0 to disable keepalive jobs.
    pub job_keepalive_interval_secs: u16,
}

/// Second listener for farm-scale and rented hashrate, on its own port with its own floor.
#[derive(Debug, Deserialize, Clone)]
pub struct FarmTierConfig {
    /// Port for the farm/rental listener. The hobby listener keeps `downstream_port`, so every
    /// miner already pointed at this node stays where it is and nobody has to be told to move.
    pub port: u16,
    /// Starting hashrate assumed for a connection arriving on this port, in H/s. Applied as the
    /// per-connection floor exactly as a miner-declared `mining.suggest_difficulty` would be, so
    /// it reuses a path that is already exercised rather than adding a second one.
    pub min_individual_miner_hashrate: Hashrate,
    /// Hashrate above which a connection on the HOBBY port is told to move here, in H/s.
    /// `None` disables the nudge. This is the capacity control described on `farm_tier`: it
    /// exists because a large miner on the hobby port costs the node share-validation and
    /// database load, not because it could earn more.
    #[serde(default)]
    pub hobby_max_individual_miner_hashrate: Option<Hashrate>,
}

impl DownstreamDifficultyConfig {
    /// Creates a new `DownstreamDifficultyConfig` instance.
    pub fn new(
        min_individual_miner_hashrate: Hashrate,
        shares_per_minute: SharesPerMinute,
        enable_vardiff: bool,
        job_keepalive_interval_secs: u16,
    ) -> Self {
        Self {
            min_individual_miner_hashrate,
            shares_per_minute,
            enable_vardiff,
            job_keepalive_interval_secs,
        }
    }
}

#[cfg(test)]
mod farm_tier_tests {
    use super::*;

    /// The whole point of two ports is that they hand out DIFFERENT starting difficulties.
    /// A config where both tiers resolve to the same floor is a misconfiguration that would
    /// otherwise look fine — two listeners, no benefit.
    #[test]
    fn the_two_tiers_produce_different_starting_difficulties() {
        // Same arithmetic vardiff uses: difficulty = hashrate * target_interval / (2^48/0xFFFF).
        const HASHES_PER_DIFFICULTY: f64 = ((1u64 << 48) as f64) / (0xFFFF as f64);
        let shares_per_minute = 6.0_f64;
        let interval = 60.0 / shares_per_minute;

        let hobby_hs = 500_000_000_000.0_f64; // a ~500 GH/s bitaxe
        let farm_hs = 10_000_000_000_000.0_f64; // rented hashrate

        let hobby_diff = hobby_hs * interval / HASHES_PER_DIFFICULTY;
        let farm_diff = farm_hs * interval / HASHES_PER_DIFFICULTY;

        assert!(
            farm_diff > hobby_diff * 10.0,
            "farm tier must start far above the hobby tier, else the two ports are pointless \
             (hobby {hobby_diff:.0}, farm {farm_diff:.0})"
        );

        // And the hobby tier must stay low enough that a bitaxe still submits often enough to
        // look alive — the failure that made the dashboard flap when the single floor was
        // raised for rented hashrate.
        let bitaxe_interval_s = hobby_diff * HASHES_PER_DIFFICULTY / hobby_hs;
        assert!(
            bitaxe_interval_s <= 30.0,
            "a bitaxe on the hobby port would only submit every {bitaxe_interval_s:.0}s"
        );
    }

    /// Absent `farm_tier` must leave the single-listener behaviour untouched, because every
    /// config file currently deployed omits it. `#[serde(default)]` gives that for parsing;
    /// this pins the constructor, which is the other way a config is built.
    #[test]
    fn farm_tier_defaults_to_absent() {
        let cfg = TranslatorConfig::new(
            vec![],
            "0.0.0.0".to_string(),
            3333,
            DownstreamDifficultyConfig::new(500_000_000_000.0, 6.0, true, 60),
            2,
            2,
            8,
            "bc1qexample".to_string(),
            false,
            vec![],
            vec![],
            None,
            None,
        );
        assert!(
            cfg.farm_tier.is_none(),
            "farm_tier must default to None so existing single-listener configs are unchanged"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn create_test_upstream() -> Upstream {
        // Use a valid base58-encoded public key from the key-utils test cases
        let pubkey_str = "9bDuixKmZqAJnrmP746n8zU1wyAQRrus7th9dxnkPg6RzQvCnan";
        let pubkey = Secp256k1PublicKey::from_str(pubkey_str).unwrap();
        Upstream::new("127.0.0.1".to_string(), 4444, pubkey)
    }

    fn create_test_difficulty_config() -> DownstreamDifficultyConfig {
        DownstreamDifficultyConfig::new(100.0, 5.0, true, 60)
    }

    #[test]
    fn test_upstream_creation() {
        let upstream = create_test_upstream();
        assert_eq!(upstream.address, "127.0.0.1");
        assert_eq!(upstream.port, 4444);
    }

    #[test]
    fn test_downstream_difficulty_config_creation() {
        let config = create_test_difficulty_config();
        assert_eq!(config.min_individual_miner_hashrate, 100.0);
        assert_eq!(config.shares_per_minute, 5.0);
        assert!(config.enable_vardiff);
    }

    #[test]
    fn test_translator_config_creation() {
        let upstreams = vec![create_test_upstream()];
        let difficulty_config = create_test_difficulty_config();

        let config = TranslatorConfig::new(
            upstreams,
            "0.0.0.0".to_string(),
            3333,
            difficulty_config,
            2,
            1,
            4,
            "test_user".to_string(),
            true,
            vec![],
            vec![],
            None,
            None,
        );

        assert_eq!(config.upstreams.len(), 1);
        assert_eq!(config.downstream_address, "0.0.0.0");
        assert_eq!(config.downstream_port, 3333);
        assert_eq!(config.max_supported_version, 2);
        assert_eq!(config.min_supported_version, 1);
        assert_eq!(config.downstream_extranonce2_size, 4);
        assert_eq!(config.user_identity, "test_user");
        assert!(config.aggregate_channels);
        assert!(config.supported_extensions.is_empty());
        assert!(config.required_extensions.is_empty());
        assert!(config.log_file.is_none());
    }

    #[test]
    fn test_translator_config_log_dir() {
        let upstreams = vec![create_test_upstream()];
        let difficulty_config = create_test_difficulty_config();

        let mut config = TranslatorConfig::new(
            upstreams,
            "0.0.0.0".to_string(),
            3333,
            difficulty_config,
            2,
            1,
            4,
            "test_user".to_string(),
            false,
            vec![],
            vec![],
            None,
            None,
        );

        assert!(config.log_dir().is_none());

        let log_path = PathBuf::from("/tmp/logs");
        config.set_log_dir(Some(log_path.clone()));
        assert_eq!(config.log_dir(), Some(log_path.as_path()));

        config.set_log_dir(None);
        assert_eq!(config.log_dir(), Some(log_path.as_path())); // Should remain unchanged
    }

    #[test]
    fn test_multiple_upstreams() {
        let upstream1 = create_test_upstream();
        let mut upstream2 = create_test_upstream();
        upstream2.address = "192.168.1.1".to_string();
        upstream2.port = 5555;

        let upstreams = vec![upstream1, upstream2];
        let difficulty_config = create_test_difficulty_config();

        let config = TranslatorConfig::new(
            upstreams,
            "0.0.0.0".to_string(),
            3333,
            difficulty_config,
            2,
            1,
            4,
            "test_user".to_string(),
            true,
            vec![],
            vec![],
            None,
            None,
        );

        assert_eq!(config.upstreams.len(), 2);
        assert_eq!(config.upstreams[0].address, "127.0.0.1");
        assert_eq!(config.upstreams[0].port, 4444);
        assert_eq!(config.upstreams[1].address, "192.168.1.1");
        assert_eq!(config.upstreams[1].port, 5555);
    }

    #[test]
    fn test_vardiff_disabled_config() {
        let mut difficulty_config = create_test_difficulty_config();
        difficulty_config.enable_vardiff = false;

        let upstreams = vec![create_test_upstream()];
        let config = TranslatorConfig::new(
            upstreams,
            "0.0.0.0".to_string(),
            3333,
            difficulty_config,
            2,
            1,
            4,
            "test_user".to_string(),
            false,
            vec![],
            vec![],
            None,
            None,
        );

        assert!(!config.downstream_difficulty_config.enable_vardiff);
        assert!(!config.aggregate_channels);
    }
}
