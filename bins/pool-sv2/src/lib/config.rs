//! ## Configuration Module
//!
//! Defines [`PoolConfig`], the configuration structure for the Pool, along with its supporting
//! types.
//!
//! This module handles:
//! - Initializing [`PoolConfig`]
//! - Managing [`TemplateProviderConfig`], [`AuthorityConfig`], [`CoinbaseOutput`], and
//!   [`ConnectionConfig`]
//! - Validating and converting coinbase outputs
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use stratum_apps::{
    config_helpers::{opt_path_from_toml, CoinbaseRewardScript},
    key_utils::{Secp256k1PublicKey, Secp256k1SecretKey},
    stratum_core::bitcoin::{Amount, TxOut},
    tp_type::TemplateProviderType,
    utils::types::{SharesBatchSize, SharesPerMinute},
};

fn default_share_webhook_batch_size() -> usize {
    100
}

fn default_share_webhook_batch_timeout_ms() -> u64 {
    5000
}

fn default_share_webhook_max_retries() -> u32 {
    3
}

/// Configuration for webhook notifications of valid shares.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct ShareWebhookConfig {
    /// URL to POST share batches to.
    pub url: String,
    /// Shared secret for signing each batch, hex (64 chars = 32 bytes). Must equal the
    /// co-located ghost-mining's `[network] internal_api_secret` (H-13).
    ///
    /// **Mandatory when this section is present, and deliberately has no default.** ghost-mining
    /// authorised this webhook by `is_loopback()` alone, so every process on the box could write
    /// to the payout ledger; it now requires an HMAC-SHA256 over `timestamp || body` under this
    /// secret.
    ///
    /// Two ways to get this wrong, both closed. A `#[serde(default)]` would let a stale config
    /// start a pool that mines happily while every batch is rejected `401` and the shares are
    /// lost — silent, and paid for in miners' work; without one, the file fails to parse. And a
    /// key that is PRESENT but unusable is refused by `ShareWebhookWorker::new`, which propagates
    /// to `PoolSv2::start` and stops the process. Neither is survivable at runtime, because the
    /// runtime symptom is total share loss behind an SV2 acknowledgement the miner already has.
    ///
    /// The acceptance rule is `InternalAuthKey`'s — at least 32 bytes of hex, first 32 used —
    /// which is the same code ghost-mining verifies with, so "acceptable" cannot mean two different
    /// things on the two ends of the socket.
    pub secret: String,
    /// Number of shares to accumulate before sending a batch.
    #[serde(default = "default_share_webhook_batch_size")]
    pub batch_size: usize,
    /// Maximum time (ms) to wait before sending a partial batch.
    #[serde(default = "default_share_webhook_batch_timeout_ms")]
    pub batch_timeout_ms: u64,
    /// Number of retry attempts for failed requests.
    #[serde(default = "default_share_webhook_max_retries")]
    pub max_retries: u32,
}

/// `[node_pool]`: the node pool, the only mode this pool runs in. Required: startup refuses a
/// config without it.
///
/// Every channel gets its own job: a `GhostShare/v2` share tag (slot class, parent anchor), the
/// canonical coinbase of the snapshot table for its slot class (spec 2.1), SV2 standard channels
/// at the full class, and per-miner slot-class sensing. The translator must run with
/// `quantise_to_tiers = true` and list the Ghost agent extension (`0x4748`) in its
/// `supported_extensions` for SV1 user agents to reach the sensing loop. See `node_pool.rs`.
#[derive(Clone, Debug, Default, serde::Deserialize)]
pub struct NodePoolConfig {
    /// This node's 32-byte identity, hex. Normally omitted: read from the co-located
    /// ghost-mining's health endpoint, and checked against it when pinned.
    #[serde(default)]
    pub node_id: Option<String>,
    /// Where to read this node's identity from. Defaults to the co-located ghost-mining.
    #[serde(default)]
    pub ghost_pool_health_url: Option<String>,
    /// The node operator's fee address: the finder output, which takes every transaction fee of
    /// a block this node's miners find (spec 1). P2SH, P2WPKH, P2WSH or P2TR.
    pub fee_address: String,
    /// Valid shares a class needs before a miner is stepped up. Defaults to 20.
    #[serde(default)]
    pub sensing_min_shares: Option<u32>,
    /// `[node_pool.relay]`: the share-chain relay and settlement. Required: without it this node
    /// holds no ledger and cannot build a canonical coinbase.
    #[serde(default)]
    pub relay: Option<crate::node_pool_relay::NodePoolRelayConfig>,
}

/// Configuration for the Pool, including connection, authority, and coinbase settings.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct PoolConfig {
    listen_address: SocketAddr,
    template_provider_type: TemplateProviderType,
    authority_public_key: Secp256k1PublicKey,
    authority_secret_key: Secp256k1SecretKey,
    cert_validity_sec: u64,
    coinbase_reward_script: CoinbaseRewardScript,
    pool_signature: String,
    shares_per_minute: SharesPerMinute,
    share_batch_size: SharesBatchSize,
    #[serde(default, deserialize_with = "opt_path_from_toml")]
    log_file: Option<PathBuf>,
    #[serde(default)]
    server_id: u16,
    #[serde(default)]
    supported_extensions: Vec<u16>,
    #[serde(default)]
    required_extensions: Vec<u16>,
    #[serde(default)]
    monitoring_address: Option<SocketAddr>,
    #[serde(default)]
    monitoring_cache_refresh_secs: Option<u64>,
    #[serde(default)]
    share_webhook: Option<ShareWebhookConfig>,
    #[serde(default)]
    node_pool: Option<NodePoolConfig>,

    /// Concurrent downstream connections allowed in total. `None` takes
    /// [`crate::connection_limit::DEFAULT_MAX_DOWNSTREAM_CONNECTIONS`].
    ///
    /// ⛔ Absent means DEFAULTED, not unlimited. The SV2 port is world-open and had no cap at all
    /// (#994), so an unset key must still bound the node.
    max_downstream_connections: Option<u32>,

    /// Concurrent connections allowed from one address. `None` takes
    /// [`crate::connection_limit::DEFAULT_MAX_CONNECTIONS_PER_IP`].
    max_connections_per_ip: Option<u32>,
}

impl PoolConfig {
    pub fn share_webhook(&self) -> Option<&ShareWebhookConfig> {
        self.share_webhook.as_ref()
    }

    /// The `[node_pool]` section, if the config has one. Startup refuses a config without it.
    pub fn node_pool(&self) -> Option<&NodePoolConfig> {
        self.node_pool.as_ref()
    }

    /// Sets the `[node_pool]` section, for a config built with [`PoolConfig::new`] rather than
    /// read from TOML. Startup checks it exactly as it checks one read from a file.
    pub fn set_node_pool(&mut self, node_pool: NodePoolConfig) {
        self.node_pool = Some(node_pool);
    }
}

impl PoolConfig {
    /// Creates a new instance of the [`PoolConfig`].
    ///
    /// # Panics
    ///
    /// Panics if `coinbase_reward_script` is empty.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_connection: ConnectionConfig,
        template_provider_type: TemplateProviderType,
        authority_config: AuthorityConfig,
        coinbase_reward_script: CoinbaseRewardScript,
        shares_per_minute: SharesPerMinute,
        share_batch_size: SharesBatchSize,
        server_id: u16,
        supported_extensions: Vec<u16>,
        required_extensions: Vec<u16>,
        monitoring_address: Option<SocketAddr>,
        monitoring_cache_refresh_secs: Option<u64>,
    ) -> Self {
        Self {
            listen_address: pool_connection.listen_address,
            template_provider_type,
            authority_public_key: authority_config.public_key,
            authority_secret_key: authority_config.secret_key,
            cert_validity_sec: pool_connection.cert_validity_sec,
            coinbase_reward_script,
            pool_signature: pool_connection.signature,
            shares_per_minute,
            share_batch_size,
            log_file: None,
            server_id,
            supported_extensions,
            required_extensions,
            monitoring_address,
            monitoring_cache_refresh_secs,
            share_webhook: None,
            node_pool: None,
            // `None` is DEFAULTED, not unlimited — see the field docs. This constructor is the
            // programmatic path (tests); the TOML path gets the same defaults through serde.
            max_downstream_connections: None,
            max_connections_per_ip: None,
        }
    }

    /// Returns the coinbase output.
    pub fn coinbase_reward_script(&self) -> &CoinbaseRewardScript {
        &self.coinbase_reward_script
    }

    /// Returns Pool listenining address.
    pub fn listen_address(&self) -> &SocketAddr {
        &self.listen_address
    }

    /// Returns the authority public key.
    pub fn authority_public_key(&self) -> &Secp256k1PublicKey {
        &self.authority_public_key
    }

    /// Returns the authority secret key.
    pub fn authority_secret_key(&self) -> &Secp256k1SecretKey {
        &self.authority_secret_key
    }

    /// Returns the certificate validity in seconds.
    pub fn cert_validity_sec(&self) -> u64 {
        self.cert_validity_sec
    }

    /// Total concurrent downstream connections allowed, or `None` for the default.
    pub fn max_downstream_connections(&self) -> Option<u32> {
        self.max_downstream_connections
    }

    /// Concurrent connections allowed from one address, or `None` for the default.
    pub fn max_connections_per_ip(&self) -> Option<u32> {
        self.max_connections_per_ip
    }

    /// Returns the Pool signature.
    pub fn pool_signature(&self) -> &String {
        &self.pool_signature
    }

    /// Returns the Template Provider type.
    pub fn template_provider_type(&self) -> &TemplateProviderType {
        &self.template_provider_type
    }

    /// Returns the share batch size.
    pub fn share_batch_size(&self) -> usize {
        self.share_batch_size
    }

    /// Sets the coinbase output.
    pub fn set_coinbase_reward_script(&mut self, coinbase_output: CoinbaseRewardScript) {
        self.coinbase_reward_script = coinbase_output;
    }

    /// Returns the shares per minute.
    pub fn shares_per_minute(&self) -> f32 {
        self.shares_per_minute
    }

    /// Returns the supported extensions.
    pub fn supported_extensions(&self) -> &[u16] {
        &self.supported_extensions
    }

    /// Returns the required extensions.
    pub fn required_extensions(&self) -> &[u16] {
        &self.required_extensions
    }

    /// Sets the log directory.
    pub fn set_log_dir(&mut self, log_dir: Option<PathBuf>) {
        if let Some(dir) = log_dir {
            self.log_file = Some(dir);
        }
    }
    /// Returns the log directory.
    pub fn log_dir(&self) -> Option<&Path> {
        self.log_file.as_deref()
    }

    /// Returns the server id.
    pub fn server_id(&self) -> u16 {
        self.server_id
    }

    pub fn get_txout(&self) -> TxOut {
        TxOut {
            value: Amount::from_sat(0),
            script_pubkey: self.coinbase_reward_script.script_pubkey().to_owned(),
        }
    }

    /// Returns the monitoring address (optional).
    pub fn monitoring_address(&self) -> Option<SocketAddr> {
        self.monitoring_address
    }

    /// Returns the monitoring cache refresh interval in seconds.
    pub fn monitoring_cache_refresh_secs(&self) -> Option<u64> {
        self.monitoring_cache_refresh_secs
    }
}

/// Pool's authority public and secret keys.
pub struct AuthorityConfig {
    pub public_key: Secp256k1PublicKey,
    pub secret_key: Secp256k1SecretKey,
}

impl AuthorityConfig {
    pub fn new(public_key: Secp256k1PublicKey, secret_key: Secp256k1SecretKey) -> Self {
        Self {
            public_key,
            secret_key,
        }
    }
}

/// Connection settings for the Pool listener.
pub struct ConnectionConfig {
    listen_address: SocketAddr,
    cert_validity_sec: u64,
    signature: String,
}

impl ConnectionConfig {
    pub fn new(listen_address: SocketAddr, cert_validity_sec: u64, signature: String) -> Self {
        Self {
            listen_address,
            cert_validity_sec,
            signature,
        }
    }
}
