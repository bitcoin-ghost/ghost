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

fn default_sv1_ports() -> Vec<u16> {
    vec![3333, 4444]
}

/// `[solo]`: the solo pool's settings. Optional: a config without it runs on mainnet, keeps its
/// statistics and found blocks in memory, and submits found blocks to the local node only.
///
/// ```toml
/// [solo]
/// network = "mainnet"                 # mainnet, signet or regtest: the subsidy schedule and
///                                     # which addresses miners may use
/// state_dir = "/var/lib/ghost/solo"   # miner-stats.json and blocks-found.json
/// submit_rpc = ["http://10.0.0.2:8332"]  # other nodes every found block is sent to
/// submit_rpc_auth_file = "/etc/ghost/solo-submit-rpc.auth"  # their credentials (never logged)
/// sv1_ports = [3333, 4444]            # the translator's ports, shown by /api/v1/pool/status
/// ```
#[derive(Clone, Debug, serde::Deserialize)]
pub struct SoloConfig {
    /// `mainnet` (the default), `signet` or `regtest`.
    #[serde(default)]
    pub network: Option<String>,
    /// Where the miner statistics and the found blocks are saved. `None` keeps them in memory.
    #[serde(default)]
    pub state_dir: Option<PathBuf>,
    /// Other Bitcoin nodes' JSON-RPC URLs: every found block is sent to each of them too, in
    /// parallel, after the local node. See `submit_rpc.rs`.
    #[serde(default)]
    pub submit_rpc: Vec<String>,
    /// Their credentials, one `user:password` (or `url user:password`) a line. Falls back to the
    /// `GHOST_SOLO_SUBMIT_RPC_AUTH_FILE` environment variable.
    #[serde(default)]
    pub submit_rpc_auth_file: Option<PathBuf>,
    /// The translator's SV1 ports, for the status API.
    #[serde(default = "default_sv1_ports")]
    pub sv1_ports: Vec<u16>,
}

impl Default for SoloConfig {
    fn default() -> Self {
        Self {
            network: None,
            state_dir: None,
            submit_rpc: vec![],
            submit_rpc_auth_file: None,
            sv1_ports: default_sv1_ports(),
        }
    }
}

impl SoloConfig {
    /// The configured network; mainnet when unset.
    pub fn network(&self) -> Result<ghost_common::solo::SoloNetwork, String> {
        match &self.network {
            Some(n) => ghost_common::solo::SoloNetwork::parse(n),
            None => Ok(ghost_common::solo::SoloNetwork::Mainnet),
        }
    }
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
    solo: Option<SoloConfig>,
    /// A `[node_pool]` section left by an older installer: ignored (the share chain is gone),
    /// and said so at start.
    #[serde(default)]
    node_pool: Option<serde::de::IgnoredAny>,

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

    /// The `[solo]` section, defaulted when absent.
    pub fn solo(&self) -> SoloConfig {
        self.solo.clone().unwrap_or_default()
    }

    /// Sets the `[solo]` section, for a config built with [`PoolConfig::new`].
    pub fn set_solo(&mut self, solo: SoloConfig) {
        self.solo = Some(solo);
    }

    /// Whether the config still carries an old `[node_pool]` section (ignored).
    pub fn has_legacy_node_pool_section(&self) -> bool {
        self.node_pool.is_some()
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
            solo: None,
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
