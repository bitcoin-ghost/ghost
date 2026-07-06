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
//| FILE: config.rs                                                                                                      |
//|======================================================================================================================|

//! Configuration structures for Bitcoin Ghost v1.4
//!
//! All node and pool configuration is defined here.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::constants::*;
use crate::signer::SignerConfig;
use crate::types::TreasuryAddress;

/// H-11: Validate config file permissions on Unix systems
///
/// Config files should not be group or world readable as they may contain
/// sensitive information like RPC passwords, signing keys, and API secrets.
///
/// On mainnet: returns `Err` if the config is group/world accessible (mode & 0o077 != 0).
/// On other networks: logs a warning but allows startup to continue.
///
/// Pass `None` for network to get the legacy warn-only behavior.
#[cfg(unix)]
pub fn validate_config_permissions(
    path: &Path,
    network: Option<&BitcoinNetwork>,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    match std::fs::metadata(path) {
        Ok(metadata) => {
            let mode = metadata.permissions().mode();
            // Check if group or world readable/writable (0o077 mask)
            if mode & 0o077 != 0 {
                let is_mainnet = matches!(network, Some(BitcoinNetwork::Mainnet));
                if is_mainnet {
                    return Err(format!(
                        "H-11 SECURITY: Config file {} has overly permissive mode {:o}. \
                         Mainnet requires chmod 600 on config files containing secrets.",
                        path.display(),
                        mode & 0o777,
                    ));
                } else {
                    tracing::warn!(
                        "H-11 SECURITY: Config file {} has overly permissive mode {:o}. \
                         Recommended: chmod 600 {}",
                        path.display(),
                        mode & 0o777,
                        path.display()
                    );
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                "H-11: Could not check permissions on config file {}: {}",
                path.display(),
                e
            );
        }
    }
    Ok(())
}

/// H-11: No-op on non-Unix platforms
#[cfg(not(unix))]
pub fn validate_config_permissions(
    _path: &Path,
    _network: Option<&BitcoinNetwork>,
) -> Result<(), String> {
    // Config permission validation is only applicable on Unix systems
    Ok(())
}

/// Main node configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeConfig {
    /// Node identity configuration
    pub identity: IdentityConfig,
    /// Bitcoin Core RPC configuration
    pub bitcoin: BitcoinConfig,
    /// Network configuration
    pub network: NetworkConfig,
    /// Policy configuration
    pub policy: PolicyConfig,
    /// Storage configuration
    pub storage: StorageConfig,
    /// Pool configuration (treasury, fees)
    pub pool: PoolConfig,
    /// Ghost Pay L2 configuration (optional)
    pub ghost_pay: Option<GhostPayConfig>,
    /// Reaper configuration (dead code detection in witness scripts)
    #[serde(default)]
    pub reaper: ReaperSettings,
    /// Registry configuration (optional, for load balancer registration)
    pub registry: Option<RegistryConfig>,
    /// Decentralised Wraith coordinator-election configuration.
    ///
    /// Read-only and gated OFF by default: when `wraith_election_enabled` is
    /// false the election service is never constructed and has zero effect on
    /// the node (`tasks/plan_decentralised_coordinators.md`, increment 4).
    #[serde(default)]
    pub coordinator: CoordinatorConfig,
    /// Operator alerting configuration (email / push / Telegram). Off by
    /// default; delivery is inert until an operator enables a channel.
    #[serde(default)]
    pub alerts: AlertsConfig,
}

/// Decentralised Wraith coordinator-election settings.
///
/// This increment only *computes and exposes* the election read-only; it never
/// activates a coordinator role, touches `coordinator_redundancy`, or changes
/// any Wraith mixing or consensus message. With `wraith_election_enabled =
/// false` (the default) it is inert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorConfig {
    /// Compute the per-epoch coordinator election and expose it read-only via
    /// `GET /api/v1/pool/coordinator`. Default false — dead code when off.
    #[serde(default)]
    pub wraith_election_enabled: bool,
    /// Opt in to being an eligible Wraith coordinator — the same opt-in model as
    /// `public_mining` for miners. When true the node advertises itself as
    /// coordinator-capable to the mesh and may be elected. Earns the mixing
    /// service fee, not 5-4-3-2-1 shares. Default false.
    #[serde(default)]
    pub coordinator_enabled: bool,
    /// The reachable coordinator endpoint this node advertises: a public
    /// `host:port` or a `.onion` hidden service. Operator-controlled so home
    /// operators can advertise Tor instead of doxxing an IP. Required (non-empty)
    /// before the node can actually be elected — no endpoint means wallets have
    /// nowhere to dial.
    #[serde(default)]
    pub advertised_endpoint: Option<String>,
    /// Port the in-process coordinator binds when this node is elected to a seat.
    #[serde(default = "default_coordinator_port")]
    pub coordinator_port: u16,
    /// Actually RUN the coordinator when elected (vs. only advertising + being
    /// electable). Separate from `coordinator_enabled` so discovery can be on
    /// without auto-activating. SECURE-BY-DEFAULT: on mainnet, activation is
    /// refused unless a real ghost-pay bond ledger is configured (an unbonded
    /// coordinator lets participants grief rounds for free). Default false.
    #[serde(default)]
    pub coordinator_role_enabled: bool,
    /// ghost-pay L2 bond-ledger base URL the coordinator calls to verify/refund/
    /// slash participant bonds. REQUIRED to activate on mainnet.
    #[serde(default)]
    pub bond_ledger_url: Option<String>,
    /// Bearer token for the bond-ledger API.
    #[serde(default)]
    pub bond_ledger_token: Option<String>,
    /// Destination address for this coordinator's per-round service fee
    /// (`service_fee_bps`). Without it rounds run fee-less.
    #[serde(default)]
    pub coordinator_fee_address: Option<String>,
}

/// Default port for the in-process Wraith coordinator (matches the standalone
/// `wraith-coordinator` binary's default).
fn default_coordinator_port() -> u16 {
    9100
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            wraith_election_enabled: false,
            coordinator_enabled: false,
            advertised_endpoint: None,
            coordinator_port: default_coordinator_port(),
            coordinator_role_enabled: false,
            bond_ledger_url: None,
            bond_ledger_token: None,
            coordinator_fee_address: None,
        }
    }
}

/// Configuration validation error
#[derive(Debug, Clone)]
pub struct ConfigValidationError {
    /// Field path that failed validation
    pub field: String,
    /// Error message
    pub message: String,
    /// Whether this is a warning (can continue) or error (must stop)
    pub is_warning: bool,
}

impl std::fmt::Display for ConfigValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = if self.is_warning { "WARNING" } else { "ERROR" };
        write!(f, "[{}] {}: {}", prefix, self.field, self.message)
    }
}

/// Result of configuration validation
#[derive(Debug, Default)]
pub struct ConfigValidationResult {
    /// Errors that prevent startup
    pub errors: Vec<ConfigValidationError>,
    /// Warnings that allow startup but should be addressed
    pub warnings: Vec<ConfigValidationError>,
}

impl ConfigValidationResult {
    /// Check if validation passed (no errors)
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    /// Get all issues (errors and warnings combined)
    pub fn all_issues(&self) -> impl Iterator<Item = &ConfigValidationError> {
        self.errors.iter().chain(self.warnings.iter())
    }

    fn add_error(&mut self, field: &str, message: &str) {
        self.errors.push(ConfigValidationError {
            field: field.to_string(),
            message: message.to_string(),
            is_warning: false,
        });
    }

    fn add_warning(&mut self, field: &str, message: &str) {
        self.warnings.push(ConfigValidationError {
            field: field.to_string(),
            message: message.to_string(),
            is_warning: true,
        });
    }
}

impl NodeConfig {
    /// Whether a local ghost-pay L2 daemon is enabled on this node.
    ///
    /// Ghost Pay counts as enabled only when the `[ghost_pay]` block is present
    /// AND its `enabled` flag is true. Pool-only nodes carry a `[ghost_pay]`
    /// block (setup emits one by default) but with `enabled = false` and never
    /// run the ghost-pay daemon, so the block's mere presence must NOT be read
    /// as "ghost-pay is running here". This mirrors `validate_ghost_pay`, which
    /// likewise treats `enabled = false` as off, and is the single source of
    /// truth for whether ghost-pool should talk to a local ghost-pay.
    pub fn ghost_pay_enabled(&self) -> bool {
        self.ghost_pay.as_ref().is_some_and(|gp| gp.enabled)
    }

    /// Whether the operator enabled Wraith mixing on this node.
    ///
    /// Sourced from the `[ghost_pay] wraith_enabled` setting — the operator's
    /// on/off choice. This is what the public status endpoints must surface,
    /// as opposed to ghost-pay's internal "does this process host CoinJoin
    /// sessions" signal (always false since mixing moved to wraith-coordinator).
    /// Reads as false when no `[ghost_pay]` block is present.
    pub fn wraith_enabled(&self) -> bool {
        self.ghost_pay.as_ref().is_some_and(|gp| gp.wraith_enabled)
    }

    /// Validate the configuration
    ///
    /// Returns validation result with any errors and warnings found.
    pub fn validate(&self) -> ConfigValidationResult {
        let mut result = ConfigValidationResult::default();

        // Validate pool configuration
        self.validate_pool(&mut result);

        // Validate Bitcoin RPC configuration
        self.validate_bitcoin(&mut result);

        // Validate network configuration
        self.validate_network(&mut result);

        // Validate storage configuration
        self.validate_storage(&mut result);

        // Validate signer configuration
        self.validate_signer(&mut result);

        // Validate Ghost Pay configuration (if enabled)
        if let Some(ref gp) = self.ghost_pay {
            self.validate_ghost_pay(gp, &mut result);
        }

        // CRITICAL: Validate mainnet security requirements (no overrides allowed)
        self.validate_mainnet_security(&mut result);

        result
    }

    /// Validate mainnet security requirements
    ///
    /// On mainnet, certain security features are MANDATORY with no override option.
    /// This prevents operators from accidentally running insecure nodes on mainnet.
    ///
    /// # Requirements (Mainnet Only)
    ///
    /// 1. **Noise Protocol Encryption** (`noise_enabled = true`)
    ///    - P2P traffic must be encrypted to prevent eavesdropping and MITM attacks
    ///
    /// 2. **Internal API Authentication** (`internal_api_secret` configured)
    ///    - Admin endpoints must be protected to prevent unauthorized access
    ///
    /// 3. **Seed Nodes Configured** (`seed_nodes` non-empty) [M-15]
    ///    - At least one seed node required for P2P network discovery
    ///    - Without seed nodes, the node will be isolated and unable to participate
    ///
    /// These checks only apply when `bitcoin.network = "mainnet"`. Testnets allow
    /// relaxed security for development and testing purposes.
    fn validate_mainnet_security(&self, result: &mut ConfigValidationResult) {
        // Only enforce on mainnet
        if self.bitcoin.network != BitcoinNetwork::Mainnet {
            return;
        }

        // MAINNET REQUIREMENT 1: Noise Protocol encryption
        if !self.network.noise_enabled {
            result.add_error(
                "network.noise_enabled",
                "MAINNET SECURITY: Noise Protocol encryption is REQUIRED for mainnet. \
                 Set noise_enabled = true in [network] section. \
                 P2P traffic without encryption is vulnerable to eavesdropping and MITM attacks.",
            );
        }

        // MAINNET REQUIREMENT 2: Internal API authentication
        match &self.network.internal_api_secret {
            None => {
                result.add_error(
                    "network.internal_api_secret",
                    "MAINNET SECURITY: Internal API authentication is REQUIRED for mainnet. \
                     Set internal_api_secret in [network] section. \
                     Generate with: openssl rand -hex 32",
                );
            }
            Some(secret) => {
                // Validate secret format (64 hex chars = 32 bytes)
                if secret.len() != 64 {
                    result.add_error(
                        "network.internal_api_secret",
                        &format!(
                            "MAINNET SECURITY: internal_api_secret must be exactly 64 hex characters (32 bytes), got {}",
                            secret.len()
                        ),
                    );
                } else if !secret.chars().all(|c| c.is_ascii_hexdigit()) {
                    result.add_error(
                        "network.internal_api_secret",
                        "MAINNET SECURITY: internal_api_secret must contain only hexadecimal characters (0-9, a-f, A-F)",
                    );
                }
            }
        }

        // MAINNET REQUIREMENT 3: Seed nodes must be configured
        // M-15: Without seed nodes, a mainnet node cannot discover peers and will be isolated,
        // making it unable to participate in the P2P mesh or consensus.
        if self.network.seed_nodes.is_empty() {
            result.add_error(
                "network.seed_nodes",
                "MAINNET SECURITY: At least one seed node is REQUIRED for mainnet. \
                 Configure seed_nodes in [network] section with valid peer addresses. \
                 Without seed nodes, this node cannot discover the P2P network and will be isolated.",
            );
        }

        // MAINNET REQUIREMENT 4: TLS certificates must be operator-provided
        // Self-signed certificates are not acceptable for mainnet because they provide
        // no chain of trust. Clients have no way to verify they are connecting to the
        // legitimate node rather than a MITM attacker.
        if self.network.tls.cert_path.is_none() {
            result.add_warning(
                "network.tls.cert_path",
                "TLS certificate path is not configured. \
                 For production mainnet deployments, configure tls.cert_path and \
                 tls.key_path in [network] section for encrypted P2P communication.",
            );
        }
        if self.network.tls.cert_path.is_some() && self.network.tls.key_path.is_none() {
            result.add_error(
                "network.tls.key_path",
                "MAINNET SECURITY: TLS key path is REQUIRED when cert_path is set. \
                 Configure tls.key_path in [network] section.",
            );
        }
    }

    fn validate_pool(&self, result: &mut ConfigValidationResult) {
        // Treasury address validation
        if self.pool.treasury_address.is_empty() {
            result.add_warning(
                "pool.treasury_address",
                "Treasury address not configured - pool fee collection disabled",
            );
        } else {
            // Validate the TreasuryAddress configuration
            if let Err(e) = self.pool.treasury_address.validate() {
                result.add_error("pool.treasury_address", &e.to_string());
            }

            // Basic bech32 prefix validation
            let addr = self.pool.treasury_address.address();
            let valid_prefix = match self.bitcoin.network {
                BitcoinNetwork::Mainnet => addr.starts_with("bc1"),
                BitcoinNetwork::Signet | BitcoinNetwork::Testnet => addr.starts_with("tb1"),
                BitcoinNetwork::Regtest => addr.starts_with("bcrt1"),
            };
            if !valid_prefix {
                result.add_error(
                    "pool.treasury_address",
                    &format!(
                        "Invalid address prefix for {} network",
                        format!("{:?}", self.bitcoin.network).to_lowercase()
                    ),
                );
            }

            // Additional validation for multi-sig
            if self.pool.treasury_address.is_multisig() {
                if let Some((m, n)) = self.pool.treasury_address.multisig_params() {
                    if m > n || n > 15 || m == 0 {
                        result.add_error(
                            "pool.treasury_address",
                            &format!(
                                "Invalid M-of-N multi-sig: {}-of-{} (M must be 1-N, N must be 1-15)",
                                m, n
                            ),
                        );
                    }
                }
            }
        }

        // Minimum payout validation
        const DUST_LIMIT: u64 = 546;
        if self.pool.min_payout_sats < DUST_LIMIT {
            result.add_error(
                "pool.min_payout_sats",
                &format!("Must be at least {} sats (dust limit)", DUST_LIMIT),
            );
        }
    }

    fn validate_bitcoin(&self, result: &mut ConfigValidationResult) {
        // RPC credentials
        if self.bitcoin.rpc_user.is_empty() {
            result.add_error("bitcoin.rpc_user", "RPC username not configured");
        }
        if self.bitcoin.rpc_password.is_empty() {
            result.add_error("bitcoin.rpc_password", "RPC password not configured");
        }
        if self.bitcoin.rpc_user == "bitcoin" && self.bitcoin.rpc_password == "bitcoin" {
            // M-18: Default credentials are an ERROR on mainnet, not just a warning
            if self.bitcoin.network == BitcoinNetwork::Mainnet {
                result.add_error(
                    "bitcoin.rpc_user/rpc_password",
                    "M-18: Default credentials not allowed on mainnet",
                );
            } else {
                result.add_warning(
                    "bitcoin.rpc_user/rpc_password",
                    "Using default credentials - change in production",
                );
            }
        }

        // Port validation
        if self.bitcoin.rpc_port == 0 {
            result.add_error("bitcoin.rpc_port", "Invalid port 0");
        }

        // Network-port mismatch warning
        let expected_port = self.bitcoin.network.default_rpc_port();
        if self.bitcoin.rpc_port != expected_port {
            result.add_warning(
                "bitcoin.rpc_port",
                &format!(
                    "Port {} differs from default {} for {:?}",
                    self.bitcoin.rpc_port, expected_port, self.bitcoin.network
                ),
            );
        }

        // ZMQ endpoints
        if self.bitcoin.zmq_hashblock.is_none() {
            result.add_warning(
                "bitcoin.zmq_hashblock",
                "ZMQ hashblock not configured - will poll for new blocks",
            );
        }
    }

    fn validate_network(&self, result: &mut ConfigValidationResult) {
        // Check for port conflicts
        let ports = [
            ("sv2_port", self.network.sv2_port),
            ("sv1_port", self.network.sv1_port),
            ("http_port", self.network.http_port),
            ("p2p.share_propagation", self.network.p2p.share_propagation),
            (
                "p2p.block_announcement",
                self.network.p2p.block_announcement,
            ),
            ("p2p.consensus_voting", self.network.p2p.consensus_voting),
            ("p2p.health_monitoring", self.network.p2p.health_monitoring),
            ("p2p.discovery", self.network.p2p.discovery),
            ("p2p.elder_management", self.network.p2p.elder_management),
            ("p2p.payout_proposal", self.network.p2p.payout_proposal),
            (
                "p2p.payout_transaction",
                self.network.p2p.payout_transaction,
            ),
        ];

        // Check for zero ports
        for (name, port) in &ports {
            if *port == 0 {
                result.add_error(&format!("network.{}", name), "Invalid port 0");
            }
        }

        // Check for duplicates
        for i in 0..ports.len() {
            for j in (i + 1)..ports.len() {
                if ports[i].1 == ports[j].1 && ports[i].1 != 0 {
                    result.add_error(
                        &format!("network.{} / network.{}", ports[i].0, ports[j].0),
                        &format!("Port conflict: both use port {}", ports[i].1),
                    );
                }
            }
        }

        // Max miners validation
        if self.network.max_miners == 0 {
            result.add_warning("network.max_miners", "Set to 0 - no miners can connect");
        }

        // Public mining without public address
        if matches!(self.network.mining_mode, MiningMode::PublicPool)
            && self.network.public_address.is_none()
        {
            result.add_warning(
                "network.public_address",
                "Public mining enabled but no public address configured",
            );
        }

        // MANDATORY: Signing key required for public mining
        if matches!(self.network.mining_mode, MiningMode::PublicPool) {
            match &self.network.signing_key {
                None => {
                    result.add_error(
                        "network.signing_key",
                        "signing_key is REQUIRED when mining_mode = PublicPool. \
                         Generate with: ghostd --generate-signing-key",
                    );
                }
                Some(key) => {
                    // Validate signing key format (64 hex chars = 32 bytes)
                    if key.len() != 64 {
                        result.add_error(
                            "network.signing_key",
                            &format!(
                                "signing_key must be exactly 64 hex characters (32 bytes), got {}",
                                key.len()
                            ),
                        );
                    } else if !key.chars().all(|c| c.is_ascii_hexdigit()) {
                        result.add_error(
                            "network.signing_key",
                            "signing_key must contain only hexadecimal characters (0-9, a-f, A-F)",
                        );
                    }
                }
            }
        }

        // Validate seed nodes use secure protocols and have valid format
        for (i, seed) in self.network.seed_nodes.iter().enumerate() {
            let field = format!("network.seed_nodes[{}]", i);

            // Allow localhost without TLS for development
            let is_localhost = seed.starts_with("127.0.0.1")
                || seed.starts_with("localhost")
                || seed.starts_with("::1")
                || seed.contains("://127.0.0.1")
                || seed.contains("://localhost")
                || seed.contains("://[::1]");

            // If it's a URL, check for HTTP vs HTTPS
            if seed.starts_with("http://") && !is_localhost {
                result.add_error(
                    &field,
                    &format!(
                        "Insecure HTTP URL for remote seed node: {}. Use HTTPS or TCP for P2P.",
                        seed
                    ),
                );
            }

            // Warn about insecure localhost (defense in depth)
            if seed.starts_with("http://") && is_localhost {
                result.add_warning(
                    &field,
                    "Using HTTP for localhost seed node. Consider HTTPS for defense in depth.",
                );
            }

            // Validate host:port format for non-URL seeds
            if !seed.starts_with("http://") && !seed.starts_with("https://") {
                // IPv6 format: [::1]:8559 or plain host:port
                let has_port = if seed.starts_with('[') {
                    // IPv6: expect [addr]:port
                    seed.contains("]:")
                } else {
                    seed.contains(':') && seed.matches(':').count() == 1
                };

                if !has_port {
                    result.add_error(
                        &field,
                        &format!(
                            "Seed node '{}' must be in host:port format (e.g. 'seed1.example.com:8559')",
                            seed
                        ),
                    );
                } else {
                    // Validate port is numeric
                    let port_str = if seed.starts_with('[') {
                        seed.rsplit("]:").next().unwrap_or("")
                    } else {
                        seed.rsplit(':').next().unwrap_or("")
                    };
                    if port_str.parse::<u16>().is_err() {
                        result.add_error(
                            &field,
                            &format!("Seed node '{}' has invalid port: '{}'", seed, port_str),
                        );
                    }
                }
            }
        }

        // M1: Mainnet requires at least 3 seed nodes for network redundancy
        if self.bitcoin.network == BitcoinNetwork::Mainnet && self.network.seed_nodes.len() < 3 {
            result.add_error(
                "network.seed_nodes",
                &format!(
                    "MAINNET SECURITY: At least 3 seed nodes are required for mainnet (got {}). \
                     A single seed node is a single point of failure for peer discovery.",
                    self.network.seed_nodes.len()
                ),
            );
        }

        // Validate mining mode configuration
        self.validate_mining_mode(result);
    }

    fn validate_mining_mode(&self, result: &mut ConfigValidationResult) {
        match self.network.mining_mode {
            MiningMode::PublicPool => {
                // PublicPool requires signing_key for DNS registration
                // (already validated above in public_mining check).
                // The legacy `public_mining` bool was removed — mining_mode is
                // the single source of truth.
            }
            MiningMode::PrivatePool => {
                // PrivatePool requires private_mining_password
                match &self.network.private_mining_password {
                    None => {
                        result.add_error(
                            "network.private_mining_password",
                            "private_mining_password is REQUIRED when mining_mode = private_pool",
                        );
                    }
                    Some(password) => {
                        // L-17: Enforce minimum password length with an error, not just a warning
                        // Weak passwords expose private mining endpoints to brute-force attacks
                        if password.len() < 8 {
                            result.add_error(
                                "network.private_mining_password",
                                &format!(
                                    "L-17: Password must be at least 8 characters (got {}). \
                                     Weak passwords expose private mining to brute-force attacks.",
                                    password.len()
                                ),
                            );
                        }
                    }
                }
            }
            MiningMode::PrivateSolo => {
                // PrivateSolo requires both password and solo_payout_address
                match &self.network.private_mining_password {
                    None => {
                        result.add_error(
                            "network.private_mining_password",
                            "private_mining_password is REQUIRED when mining_mode = private_solo",
                        );
                    }
                    Some(password) => {
                        // L-17: Enforce minimum password length with an error, not just a warning
                        // Weak passwords expose private mining endpoints to brute-force attacks
                        if password.len() < 8 {
                            result.add_error(
                                "network.private_mining_password",
                                &format!(
                                    "L-17: Password must be at least 8 characters (got {}). \
                                     Weak passwords expose private mining to brute-force attacks.",
                                    password.len()
                                ),
                            );
                        }
                    }
                }

                // solo_payout_address is required
                match &self.network.solo_payout_address {
                    None => {
                        result.add_error(
                            "network.solo_payout_address",
                            "solo_payout_address is REQUIRED when mining_mode = private_solo",
                        );
                    }
                    Some(addr) => {
                        if addr.is_empty() {
                            result.add_error(
                                "network.solo_payout_address",
                                "solo_payout_address cannot be empty",
                            );
                        } else {
                            // Validate bech32 prefix matches network
                            let valid_prefix = match self.bitcoin.network {
                                BitcoinNetwork::Mainnet => addr.starts_with("bc1"),
                                BitcoinNetwork::Signet | BitcoinNetwork::Testnet => {
                                    addr.starts_with("tb1")
                                }
                                BitcoinNetwork::Regtest => addr.starts_with("bcrt1"),
                            };
                            if !valid_prefix {
                                result.add_error(
                                    "network.solo_payout_address",
                                    &format!(
                                        "Invalid address prefix for {} network",
                                        format!("{:?}", self.bitcoin.network).to_lowercase()
                                    ),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    fn validate_storage(&self, result: &mut ConfigValidationResult) {
        // Check db_path is not empty
        if self.storage.db_path.as_os_str().is_empty() {
            result.add_error("storage.db_path", "Database path not configured");
        }

        // Archive mode warning
        if self.storage.archive_mode && self.storage.prune_height > 0 {
            result.add_warning(
                "storage.archive_mode / storage.prune_height",
                "Both archive mode and pruning enabled - archive mode takes precedence",
            );
        }
    }

    fn validate_signer(&self, result: &mut ConfigValidationResult) {
        if let Some(ref signer) = self.identity.signer {
            if signer.is_hsm() {
                result.add_error(
                    "identity.signer",
                    "HSM signer is not yet implemented. Use type = \"local\".",
                );
            }
            if signer.is_kms() {
                result.add_error(
                    "identity.signer",
                    "KMS signer is not yet implemented. Use type = \"local\".",
                );
            }
        }
    }

    fn validate_ghost_pay(&self, gp: &GhostPayConfig, result: &mut ConfigValidationResult) {
        if !gp.enabled {
            return;
        }

        // Virtual block time
        if gp.virtual_block_secs == 0 {
            result.add_error("ghost_pay.virtual_block_secs", "Cannot be 0");
        }
        if gp.virtual_block_secs < 10 {
            result.add_warning(
                "ghost_pay.virtual_block_secs",
                "Very short virtual block time may cause issues",
            );
        }

        // Epoch blocks
        if gp.epoch_blocks == 0 {
            result.add_error("ghost_pay.epoch_blocks", "Cannot be 0");
        }
    }

    /// Save configuration to file atomically using temp file + rename pattern
    ///
    /// This ensures crash safety: the config file is never left in a partial state.
    /// If the process crashes mid-write, the original file remains intact.
    ///
    /// # Arguments
    /// * `path` - Path to save the configuration file
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err` if serialization, writing, or renaming fails
    /// Load a `NodeConfig` from a TOML file.
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let content =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        toml::from_str(&content).map_err(|e| format!("parse {}: {e}", path.display()))
    }

    pub fn save_atomic(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;

        // Serialize to TOML
        let toml_str = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Create temp file in same directory (ensures same filesystem for atomic rename)
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        // L-8: Use random suffix instead of predictable PID to prevent temp file attacks
        let random_suffix = {
            let mut random_bytes = [0u8; 8];
            if getrandom::getrandom(&mut random_bytes).is_err() {
                // Fallback to PID + timestamp if getrandom fails
                let pid_bytes = std::process::id().to_le_bytes();
                let time_bytes = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u32;
                random_bytes[..4].copy_from_slice(&pid_bytes);
                random_bytes[4..8].copy_from_slice(&time_bytes.to_le_bytes());
            }
            hex::encode(&random_bytes[..4])
        };
        let temp_path = parent.join(format!(
            ".{}.tmp.{}",
            path.file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "config".to_string()),
            random_suffix
        ));

        // Write to temp file
        {
            let mut file = std::fs::File::create(&temp_path)?;
            file.write_all(toml_str.as_bytes())?;
            file.sync_all()?; // Ensure data is on disk before rename
        }

        // Atomic rename (on POSIX systems, rename is atomic if same filesystem)
        std::fs::rename(&temp_path, path)?;

        Ok(())
    }
}

/// Identity configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Path to Ed25519 private key file (legacy, use signer.key_path instead)
    #[serde(default = "default_key_path")]
    pub key_path: PathBuf,
    /// Node display name (optional)
    pub display_name: Option<String>,
    /// Signer configuration (optional, defaults to local with key_path)
    ///
    /// When not specified, uses SignerConfig::Local with key_path.
    /// When specified, key_path is ignored in favor of signer configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<SignerConfig>,
}

fn default_key_path() -> PathBuf {
    PathBuf::from("~/.ghost/node.key")
}

impl IdentityConfig {
    /// Get the effective signer configuration
    ///
    /// If `signer` is specified, returns it directly.
    /// Otherwise, returns a Local signer using `key_path`.
    pub fn signer_config(&self) -> SignerConfig {
        self.signer.clone().unwrap_or_else(|| SignerConfig::Local {
            key_path: self.key_path.clone(),
        })
    }
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            key_path: default_key_path(),
            display_name: None,
            signer: None,
        }
    }
}

/// Bitcoin Core RPC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinConfig {
    /// RPC host
    pub rpc_host: String,
    /// RPC port
    pub rpc_port: u16,
    /// RPC username
    pub rpc_user: String,
    /// RPC password
    pub rpc_password: String,
    /// Network (mainnet, signet, testnet)
    pub network: BitcoinNetwork,
    /// ZMQ hashblock endpoint
    pub zmq_hashblock: Option<String>,
    /// ZMQ hashtx endpoint
    pub zmq_hashtx: Option<String>,
    /// ZMQ sequence endpoint (for reorg detection)
    pub zmq_sequence: Option<String>,
}

impl Default for BitcoinConfig {
    fn default() -> Self {
        Self {
            rpc_host: "127.0.0.1".to_string(),
            rpc_port: BITCOIN_RPC_PORT_SIGNET,
            rpc_user: "bitcoin".to_string(),
            rpc_password: "bitcoin".to_string(),
            network: BitcoinNetwork::Signet,
            zmq_hashblock: Some(format!("tcp://127.0.0.1:{}", ZMQ_HASHBLOCK_PORT)),
            zmq_hashtx: Some(format!("tcp://127.0.0.1:{}", ZMQ_HASHTX_PORT)),
            zmq_sequence: Some(format!("tcp://127.0.0.1:{}", ZMQ_SEQUENCE_PORT)),
        }
    }
}

/// Bitcoin network type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BitcoinNetwork {
    Mainnet,
    Signet,
    Testnet,
    Regtest,
}

/// Mining mode configuration
///
/// Determines how the pool operates and who can mine.
///
/// # TOML Example
/// ```toml
/// [network]
/// mining_mode = "private_solo"
/// private_mining_password = "mysecretpassword"
/// solo_payout_address = "tb1q..."
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MiningMode {
    /// DNS registered, anyone can mine, pool-aggregated rewards
    #[default]
    PublicPool,
    /// Password required, pool-aggregated rewards, not in DNS
    PrivatePool,
    /// Password required, 99% + fees to operator's address, not in DNS
    PrivateSolo,
}

impl MiningMode {
    /// Returns the default coinbase scriptsig tag for this mining mode.
    /// Visible on block explorers to identify the pool and its mode.
    pub fn default_coinbase_tag(&self) -> &'static str {
        match self {
            MiningMode::PublicPool => "- G H O S T - PublicPool",
            MiningMode::PrivatePool => "- G H O S T - PrivatePool",
            MiningMode::PrivateSolo => "- G H O S T - PrivateSolo",
        }
    }
}

impl BitcoinNetwork {
    /// Canonical lowercase network name, matching the serde representation and
    /// the names used by the `bitcoin` crate, ghostd (`chain`), and pool.toml.
    pub fn as_str(&self) -> &'static str {
        match self {
            BitcoinNetwork::Mainnet => "mainnet",
            BitcoinNetwork::Signet => "signet",
            BitcoinNetwork::Testnet => "testnet",
            BitcoinNetwork::Regtest => "regtest",
        }
    }

    /// Convert to the `bitcoin` crate's `Network` type for address validation
    pub fn to_bitcoin_network(&self) -> bitcoin::Network {
        match self {
            BitcoinNetwork::Mainnet => bitcoin::Network::Bitcoin,
            BitcoinNetwork::Signet => bitcoin::Network::Signet,
            BitcoinNetwork::Testnet => bitcoin::Network::Testnet,
            BitcoinNetwork::Regtest => bitcoin::Network::Regtest,
        }
    }

    pub fn default_rpc_port(&self) -> u16 {
        match self {
            Self::Mainnet => BITCOIN_RPC_PORT_MAINNET,
            Self::Signet => BITCOIN_RPC_PORT_SIGNET,
            Self::Testnet => 18332,
            Self::Regtest => 18443,
        }
    }

    pub fn default_p2p_port(&self) -> u16 {
        match self {
            Self::Mainnet => BITCOIN_P2P_PORT_MAINNET,
            Self::Signet => BITCOIN_P2P_PORT_SIGNET,
            Self::Testnet => 18333,
            Self::Regtest => 18444,
        }
    }
}

/// TLS configuration for HTTP servers
///
/// Controls HTTPS for the verification (8080), Ghost Pay (8800), and GSP (8900) servers.
/// P2P mesh (ports 8555-8562) uses Noise protocol and does NOT need TLS.
///
/// If neither `cert_path` nor `key_path` is set, a self-signed certificate is
/// automatically generated at startup. For mainnet, operator-provided certificates
/// are REQUIRED (see `validate_mainnet_security`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsConfig {
    /// Path to PEM-encoded certificate file. If unset, a self-signed cert is auto-generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_path: Option<PathBuf>,
    /// Path to PEM-encoded private key file. Required if `cert_path` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_path: Option<PathBuf>,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Public IP address or hostname
    pub public_address: Option<String>,
    /// SV2 Stratum port
    pub sv2_port: u16,
    /// SV1 Stratum port (translator)
    pub sv1_port: u16,
    /// HTTP API port (plain HTTP — SRI webhook, nginx upstream, dashboard).
    pub http_port: u16,
    /// HTTPS port for the inter-peer verification mesh.
    ///
    /// When set (default 8443), ghost-pool also binds an HTTPS listener on
    /// this port serving the same routes as `http_port` but with identity-
    /// derived TLS + cert pinning. The verification client uses this port
    /// for cross-VM peer challenges so the mesh traffic is encrypted while
    /// SRI / nginx / dashboard keep talking plain HTTP on `http_port`.
    #[serde(default = "default_verification_https_port")]
    pub verification_https_port: u16,
    /// P2P consensus ports
    pub p2p: P2PPortConfig,
    /// Seed nodes for P2P discovery
    pub seed_nodes: Vec<String>,
    /// Maximum connected miners
    pub max_miners: u32,
    /// Signing key for message authentication (REQUIRED for mining_mode = PublicPool)
    /// Must be 64 hex characters (32 bytes). Generate with: ghostd --generate-signing-key
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key: Option<String>,
    /// Mining mode: public_pool, private_pool, or private_solo
    ///
    /// - PublicPool: DNS registered, anyone can mine, pool-aggregated rewards
    /// - PrivatePool: Password required, pool-aggregated rewards, not in DNS
    /// - PrivateSolo: Password required, 99% + fees to operator's address
    #[serde(default)]
    pub mining_mode: MiningMode,
    /// Password required for private mining modes (PrivatePool, PrivateSolo)
    /// Minimum 8 characters recommended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_mining_password: Option<String>,
    /// Payout address for PrivateSolo mode (required when mining_mode = private_solo)
    /// Must be a valid bech32 address for the configured network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub solo_payout_address: Option<String>,
    /// Internal API authentication secret (REQUIRED for mainnet)
    ///
    /// Protects `/api/internal/*` and `/admin/*` endpoints with HMAC-SHA256 authentication.
    /// Must be 64 hex characters (32 bytes). Generate with: openssl rand -hex 32
    ///
    /// # Security (AUTH4-1)
    ///
    /// Without this, internal endpoints are UNPROTECTED and attackers could:
    /// - Inject fake shares to manipulate payout calculations
    /// - Trigger admin operations (test-consensus)
    /// - Submit fraudulent block notifications
    ///
    /// **MAINNET REQUIREMENT**: This MUST be configured for mainnet. The node will
    /// refuse to start on mainnet without this setting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internal_api_secret: Option<String>,
    /// Enable Noise Protocol encryption for P2P communication (REQUIRED for mainnet)
    ///
    /// When enabled, sensitive P2P messages (shares, blocks, votes, payouts)
    /// are sent over encrypted Noise TCP channels instead of plaintext ZMQ.
    ///
    /// # Security (C-1)
    ///
    /// Without this, P2P traffic is unencrypted and vulnerable to:
    /// - Eavesdropping on share submissions
    /// - Man-in-the-middle attacks on consensus messages
    /// - Traffic analysis of payout information
    ///
    /// **MAINNET REQUIREMENT**: This MUST be true for mainnet. The node will
    /// refuse to start on mainnet with noise_enabled = false.
    #[serde(default = "default_noise_enabled")]
    pub noise_enabled: bool,
    /// TLS configuration for HTTP servers (verification, Ghost Pay, GSP)
    ///
    /// When configured with cert/key paths, HTTPS is enabled for all HTTP servers.
    /// When not configured, a self-signed certificate is auto-generated.
    ///
    /// **MAINNET REQUIREMENT**: `tls.cert_path` MUST be set for mainnet (no self-signed).
    #[serde(default)]
    pub tls: TlsConfig,
    /// Ghost Mode: privacy-enhanced relay + stealth addressing
    #[serde(default)]
    pub ghost_mode: bool,
    /// Ghost Shroud: random relay delay (0-5s) to prevent origin analysis
    #[serde(default)]
    pub shroud_enabled: bool,
    /// SV2 pool authority public key advertised on `/api/v1/mining/status`.
    ///
    /// SV2/Noise miners must pin the pool's authority public key to connect.
    /// This is the `authority_public_key` that the colocated `pool_sv2` instance
    /// publishes in its own pool config; it is identical across every node on
    /// the public pool. Leave unset to advertise the network-wide default
    /// (`constants::SV2_AUTHORITY_PUBLIC_KEY`); set this only when running a
    /// bespoke authority keypair so the dashboard reports the correct value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sv2_authority_public_key: Option<String>,
    /// HTTP rate-limiter trusted-IP allowlist.
    ///
    /// Requests whose **real TCP peer address** matches an entry here bypass the
    /// per-IP HTTP rate limiter (`HIGH-VER-5`: 5 req/s, burst 20). This lets the
    /// pool's own website poll the public stats endpoints without being throttled
    /// while every unknown client keeps the exact same limit. Entries may be plain
    /// IPs (`"83.136.255.218"`) or CIDR ranges (`"10.0.0.0/8"`, `"2001:db8::/32"`).
    ///
    /// # Security
    ///
    /// The allowlist is matched **only** against the direct socket peer IP
    /// (`ConnectInfo` — the actual TCP source), never a client-supplied
    /// `X-Forwarded-For` / `X-Real-IP` header. A remote attacker therefore cannot
    /// forge a header to obtain a bypass. Default **empty** (opt-in): with no
    /// entries the limiter behaves identically to before for every client.
    #[serde(default)]
    pub rate_limit_trusted_ips: Vec<String>,
}

fn default_noise_enabled() -> bool {
    true
}

fn default_verification_https_port() -> u16 {
    crate::constants::VERIFICATION_HTTPS_PORT
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            public_address: None,
            sv2_port: SV2_STRATUM_PORT,
            sv1_port: SV1_STRATUM_PORT,
            http_port: HTTP_API_PORT,
            verification_https_port: crate::constants::VERIFICATION_HTTPS_PORT,
            p2p: P2PPortConfig::default(),
            seed_nodes: Vec::new(),
            max_miners: 1000,
            signing_key: None,
            mining_mode: MiningMode::default(),
            private_mining_password: None,
            solo_payout_address: None,
            internal_api_secret: None,
            noise_enabled: true,
            tls: TlsConfig::default(),
            ghost_mode: false,
            shroud_enabled: false,
            sv2_authority_public_key: None,
            rate_limit_trusted_ips: Vec::new(),
        }
    }
}

/// P2P consensus port configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PPortConfig {
    /// Share propagation port
    pub share_propagation: u16,
    /// Block announcement port
    pub block_announcement: u16,
    /// Consensus voting port
    pub consensus_voting: u16,
    /// Health monitoring port
    pub health_monitoring: u16,
    /// Discovery port
    pub discovery: u16,
    /// Elder management port
    pub elder_management: u16,
    /// Payout proposal port
    pub payout_proposal: u16,
    /// Payout transaction port
    pub payout_transaction: u16,
}

impl Default for P2PPortConfig {
    fn default() -> Self {
        Self {
            share_propagation: SHARE_PROPAGATION_PORT,
            block_announcement: BLOCK_ANNOUNCEMENT_PORT,
            consensus_voting: CONSENSUS_VOTING_PORT,
            health_monitoring: HEALTH_MONITORING_PORT,
            discovery: DISCOVERY_PORT,
            elder_management: ELDER_MANAGEMENT_PORT,
            payout_proposal: PAYOUT_PROPOSAL_PORT,
            payout_transaction: PAYOUT_TRANSACTION_PORT,
        }
    }
}

/// Policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Policy profile name
    pub profile: PolicyProfile,
    /// Custom policy settings (overrides profile defaults)
    pub custom: Option<CustomPolicyConfig>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            profile: PolicyProfile::Permissive,
            custom: None,
        }
    }
}

/// Built-in policy profiles
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProfile {
    /// Only T0 + T1 transactions (financial-only). Serialized as `strict`; the
    /// legacy `bitcoin_pure` value is still accepted so existing pool.toml files
    /// keep parsing. The internal `BitcoinPure` identifier is unchanged.
    #[serde(rename = "strict", alias = "bitcoin_pure")]
    BitcoinPure,
    /// T0 + T1 + T2 (most common)
    Permissive,
    /// Accept all valid transactions (T0-T3)
    FullOpen,
    /// Custom policy rules
    Custom,
}

/// Custom policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPolicyConfig {
    /// Allowed BUDS tiers
    pub allowed_tiers: Vec<BudsTier>,
    /// Maximum OP_RETURN size (0 = none allowed)
    pub max_op_return_size: usize,
    /// Maximum witness size per input
    pub max_witness_per_input: usize,
    /// Maximum outputs per transaction
    pub max_tx_outputs: usize,
    /// Maximum transaction size
    pub max_tx_size: usize,
    /// Allow Ordinals/inscriptions
    pub allow_inscriptions: bool,
    /// Allow Runes
    pub allow_runes: bool,
    /// Allow BRC-20 token transfers
    #[serde(default)]
    pub allow_brc20: bool,
    /// Minimum fee rate (sat/vB, 0 = no minimum)
    #[serde(default = "default_custom_min_fee_rate")]
    pub min_fee_rate: f64,
}

/// Default minimum fee rate for a custom policy (sat/vB). Matches the
/// `strict`/`permissive` preset default so an operator who only tweaks
/// content toggles keeps a sane floor.
fn default_custom_min_fee_rate() -> f64 {
    1.0
}

impl Default for CustomPolicyConfig {
    fn default() -> Self {
        Self {
            allowed_tiers: vec![BudsTier::T0, BudsTier::T1, BudsTier::T2],
            max_op_return_size: MAX_OP_RETURN_SMALL_BYTES,
            max_witness_per_input: MAX_WITNESS_BYTES_PER_INPUT,
            max_tx_outputs: MAX_TX_OUTPUTS_BITCOIN_PURE,
            max_tx_size: MAX_TX_SIZE_BITCOIN_PURE,
            allow_inscriptions: false,
            allow_runes: false,
            allow_brc20: false,
            min_fee_rate: default_custom_min_fee_rate(),
        }
    }
}

/// BUDS transaction tier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BudsTier {
    /// Core financial transactions
    T0,
    /// Extended financial (multisig, timelocks)
    T1,
    /// Data-anchoring (small OP_RETURN)
    T2,
    /// Heavy data (inscriptions, large witness)
    T3,
}

/// Ghost Haze storage mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HazeMode {
    #[default]
    Standard,
    Hazed,
    FullArchive,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Database directory path
    pub db_path: PathBuf,
    /// Enable WAL mode for SQLite
    pub wal_mode: bool,
    /// Enable archive mode (full history)
    pub archive_mode: bool,
    /// Pruning height (blocks to keep, 0 = no pruning)
    pub prune_height: u64,
    /// Ghost Haze storage mode
    #[serde(default)]
    pub haze_mode: HazeMode,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            db_path: PathBuf::from("~/.ghost/data"),
            wal_mode: true,
            archive_mode: false,
            prune_height: 0,
            haze_mode: HazeMode::default(),
        }
    }
}

/// Ghost Pay L2 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostPayConfig {
    /// Enable Ghost Pay
    pub enabled: bool,
    /// Virtual block time (seconds)
    pub virtual_block_secs: u64,
    /// Epoch length (virtual blocks)
    pub epoch_blocks: u64,
    /// Enable Wraith mixing
    pub wraith_enabled: bool,
}

impl Default for GhostPayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            virtual_block_secs: L2_VIRTUAL_BLOCK_SECS,
            epoch_blocks: L2_EPOCH_BLOCKS,
            wraith_enabled: true,
        }
    }
}

/// Geographic region for miner routing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum Region {
    UsEast,
    UsWest,
    EuWest,
    EuCentral,
    AsiaSoutheast,
    AsiaNortheast,
    Oceania,
    SouthAmerica,
    Africa,
    #[default]
    Unknown,
}

impl std::fmt::Display for Region {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::UsEast => "us-east",
            Self::UsWest => "us-west",
            Self::EuWest => "eu-west",
            Self::EuCentral => "eu-central",
            Self::AsiaSoutheast => "asia-southeast",
            Self::AsiaNortheast => "asia-northeast",
            Self::Oceania => "oceania",
            Self::SouthAmerica => "south-america",
            Self::Africa => "africa",
            Self::Unknown => "unknown",
        };
        write!(f, "{}", s)
    }
}

/// Registry configuration for load balancer registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryConfig {
    /// URL of the registry/load balancer (e.g., "http://83.136.255.218:8333")
    pub url: String,
    /// Heartbeat interval in seconds
    pub heartbeat_interval_secs: u64,
    /// Geographic region of this node
    pub region: Region,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            heartbeat_interval_secs: 30,
            region: Region::Unknown,
        }
    }
}

/// Reaper settings for dead code detection in witness scripts
///
/// Controls filtering of transactions that contain inscriptions, data stuffing,
/// fake pubkeys, and other witness abuse patterns.
///
/// # TOML Example
/// ```toml
/// [reaper]
/// enabled = true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaperSettings {
    /// Master switch. When false, every detector is off on both layers.
    #[serde(default = "default_true")]
    pub enabled: bool,

    // --- Shared detectors (pool template reaper AND ghostd mempool reaper) ---
    /// Reject OP_FALSE OP_IF ... OP_ENDIF inscription envelopes.
    #[serde(default = "default_true")]
    pub reject_inscription: bool,
    /// Reject a large data push immediately followed by OP_DROP/OP_2DROP.
    #[serde(default = "default_true")]
    pub reject_dropstuffing: bool,
    /// Reject bare multisig outputs whose pubkey pushes have invalid prefixes.
    #[serde(default = "default_true")]
    pub reject_fakepubkey: bool,
    /// Reject P2TR inputs carrying a witness annex.
    #[serde(default = "default_true")]
    pub reject_annex: bool,

    // --- Node-only detectors (ghostd mempool reaper) ---
    /// Reject outputs whose OP_RETURN payload exceeds `max_op_return_bytes`.
    #[serde(default = "default_true")]
    pub reject_opreturn: bool,
    /// Reject Runestone protocol outputs (OP_RETURN OP_13).
    #[serde(default = "default_true")]
    pub reject_runestone: bool,
    /// Reject 1-in/1-out transactions whose sole non-OP_RETURN output is at/below the dust-flood threshold (UTXO-flood spam).
    #[serde(default = "default_true")]
    pub reject_dustflood: bool,
    /// Sole-output value (sats) at/below which a 1-in/1-out tx is treated as dust-flood spam.
    #[serde(default = "default_dustflood_threshold")]
    pub dust_flood_threshold: u64,

    // --- Pool-only detectors (Rust template reaper) ---
    /// Reject witness code after an OP_RETURN opcode.
    #[serde(default = "default_true")]
    pub reject_unreachable_code: bool,
    /// Reject witness data beyond what execution requires.
    #[serde(default = "default_true")]
    pub reject_excess_witness: bool,
    /// Reject non-signature/non-pubkey data stuffing in legacy scriptSig.
    #[serde(default = "default_true")]
    pub reject_legacy_data_stuffing: bool,
    /// Also validate that bare-multisig pubkey pushes are on the secp256k1 curve.
    #[serde(default = "default_true")]
    pub validate_pubkey_curve_point: bool,

    // --- Thresholds ---
    /// Max OP_RETURN payload bytes (shared with ghostd).
    #[serde(default = "default_max_op_return_bytes")]
    pub max_op_return_bytes: usize,
    /// Min push size (bytes) that triggers drop-stuffing detection (shared with ghostd).
    #[serde(default = "default_min_drop_size")]
    pub min_drop_size: usize,
    /// Min excess-witness bytes that triggers rejection (pool-only).
    #[serde(default = "default_min_excess_witness_bytes")]
    pub min_excess_witness_bytes: usize,
    /// Max legitimate scriptSig push bytes before legacy stuffing is flagged (pool-only).
    #[serde(default = "default_legacy_max_push_bytes")]
    pub legacy_max_push_bytes: usize,
}

fn default_true() -> bool {
    true
}
fn default_max_op_return_bytes() -> usize {
    82
}
fn default_min_drop_size() -> usize {
    76
}
fn default_dustflood_threshold() -> u64 {
    330
}
fn default_min_excess_witness_bytes() -> usize {
    500
}
fn default_legacy_max_push_bytes() -> usize {
    80
}

impl Default for ReaperSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            reject_inscription: true,
            reject_dropstuffing: true,
            reject_fakepubkey: true,
            reject_annex: true,
            reject_opreturn: true,
            reject_runestone: true,
            reject_dustflood: true,
            dust_flood_threshold: default_dustflood_threshold(),
            reject_unreachable_code: true,
            reject_excess_witness: true,
            reject_legacy_data_stuffing: true,
            validate_pubkey_curve_point: true,
            max_op_return_bytes: default_max_op_return_bytes(),
            min_drop_size: default_min_drop_size(),
            min_excess_witness_bytes: default_min_excess_witness_bytes(),
            legacy_max_push_bytes: default_legacy_max_push_bytes(),
        }
    }
}

impl ReaperSettings {
    /// The ghostd (Bitcoin Core) CLI flags that mirror these settings on the
    /// node mempool reaper. Only the detectors ghostd implements are emitted —
    /// pool-only vectors (`reject_unreachable_code`, `reject_excess_witness`,
    /// `reject_legacy_data_stuffing`, `validate_pubkey_curve_point`) have no
    /// ghostd equivalent and are omitted. Booleans use `1`/`0`; the master uses
    /// `enabled`/`disabled`. When the master is off, every per-vector flag is
    /// emitted as `0` so the node matches the all-off intent (master gate).
    pub fn ghostd_flags(&self) -> Vec<String> {
        let on = self.enabled;
        let b = |x: bool| if on && x { "1" } else { "0" };
        vec![
            format!("-ghostreaper={}", if on { "enabled" } else { "disabled" }),
            format!(
                "-ghostreaper-rejectinscription={}",
                b(self.reject_inscription)
            ),
            format!(
                "-ghostreaper-rejectdropstuffing={}",
                b(self.reject_dropstuffing)
            ),
            format!(
                "-ghostreaper-rejectfakepubkey={}",
                b(self.reject_fakepubkey)
            ),
            format!("-ghostreaper-rejectannex={}", b(self.reject_annex)),
            format!("-ghostreaper-rejectopreturn={}", b(self.reject_opreturn)),
            format!("-ghostreaper-rejectrunestone={}", b(self.reject_runestone)),
            format!("-ghostreaper-rejectdustflood={}", b(self.reject_dustflood)),
            format!("-ghostreaper-maxopreturn={}", self.max_op_return_bytes),
            format!(
                "-ghostreaper-dustfloodthreshold={}",
                self.dust_flood_threshold
            ),
            format!("-ghostreaper-mindropsize={}", self.min_drop_size),
        ]
    }
}

/// Operator alerting configuration. Persisted to pool.toml `[alerts]`.
///
/// Delivers node-event notifications to one or more operator channels. Secure
/// by default: `enabled = false` and every channel `enabled = false`, so no
/// alert is ever sent until an operator opts in and supplies a destination.
///
/// Secrets (Telegram bot token) live in this struct exactly like the
/// `[coordinator] bond_ledger_token` secret already does — persisted only to
/// the root-owned pool.toml and never logged.
///
/// # TOML Example
/// ```toml
/// [alerts]
/// enabled = true
///
/// [alerts.channels.telegram]
/// enabled = true
/// bot_token = "123456:ABC-DEF..."
/// chat_id = "987654321"
///
/// [alerts.events]
/// block_found = true
/// node_offline = true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AlertsConfig {
    /// Master switch. When false, no alert is delivered on any channel,
    /// regardless of the per-channel `enabled` flags.
    #[serde(default)]
    pub enabled: bool,
    /// Per-channel delivery configuration.
    #[serde(default)]
    pub channels: AlertChannels,
    /// Which node events fire an alert.
    #[serde(default)]
    pub events: AlertEvents,
}

/// The set of delivery channels an operator can enable.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AlertChannels {
    #[serde(default)]
    pub email: EmailChannel,
    #[serde(default)]
    pub push: PushChannel,
    #[serde(default)]
    pub telegram: TelegramChannel,
}

/// Email delivery via a configured HTTP webhook. The node POSTs
/// `{ "to", "subject", "body" }` JSON to `webhook_url`; the operator points
/// this at their own mail relay / transactional-email HTTP API (Mailgun,
/// Postmark, a self-hosted SMTP-bridge, etc.). This keeps the node free of a
/// heavyweight SMTP client while still delivering a real email end-to-end.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EmailChannel {
    #[serde(default)]
    pub enabled: bool,
    /// HTTP(S) endpoint that accepts `{to, subject, body}` and sends the mail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    /// Destination email address placed in the `to` field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_address: Option<String>,
}

/// Push delivery via a generic / ntfy-style HTTP webhook. The node POSTs
/// `{ "title", "message" }` JSON to `webhook_url`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PushChannel {
    #[serde(default)]
    pub enabled: bool,
    /// HTTP(S) endpoint that receives the push payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
}

/// Telegram delivery via the Bot API `sendMessage` method.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TelegramChannel {
    #[serde(default)]
    pub enabled: bool,
    /// Bot token from @BotFather. SECRET — never logged; redacted on the read
    /// API. Persisted only to the root-owned pool.toml.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bot_token: Option<String>,
    /// Destination chat id (user, group, or channel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chat_id: Option<String>,
}

/// Which node events fire an alert. Every event defaults ON so that enabling
/// the feature is useful out of the box; an operator narrows the set as they
/// like. These names are the stable wire keys shared with the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvents {
    /// Node became unreachable / unhealthy (health monitor).
    #[serde(default = "default_true")]
    pub node_offline: bool,
    /// A verified capability regressed from qualified to drift/failing.
    #[serde(default = "default_true")]
    pub capability_drift: bool,
    /// Free disk fell below the low-disk threshold.
    #[serde(default = "default_true")]
    pub low_disk: bool,
    /// A configuration change or update needs a node restart to apply.
    #[serde(default = "default_true")]
    pub restart_needed: bool,
    /// Connected peer count dropped (mesh partition / peers lost).
    #[serde(default = "default_true")]
    pub peer_count_drop: bool,
    /// This node found a block.
    #[serde(default = "default_true")]
    pub block_found: bool,
}

impl Default for AlertEvents {
    fn default() -> Self {
        Self {
            node_offline: true,
            capability_drift: true,
            low_disk: true,
            restart_needed: true,
            peer_count_drop: true,
            block_found: true,
        }
    }
}

/// Pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    /// Treasury address for pool fees
    ///
    /// Can be either:
    /// - Simple string (single-sig bech32 address)
    /// - Multi-sig configuration with witness script
    ///
    /// # Example (TOML)
    /// ```toml
    /// # Single-sig (simple)
    /// treasury_address = "bc1q..."
    ///
    /// # Multi-sig (object)
    /// [pool.treasury_address]
    /// address = "bc1q..."
    /// witness_script = "522102..."
    /// required = 2
    /// total = 3
    /// ```
    #[serde(default)]
    pub treasury_address: TreasuryAddress,
    /// Minimum payout threshold (satoshis)
    pub min_payout_sats: u64,
    /// Payout frequency (blocks)
    pub payout_interval_blocks: u64,
    /// Payout address for node rewards (5-4-3-2-1 capability shares)
    /// Broadcast in health pings so peers know where to send node reward payouts.
    /// Must be a valid bech32 address for the configured network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_payout_address: Option<String>,
    /// Optional custom pool name shown in coinbase (e.g. "SatoshiPool").
    /// Formatted as "- G H O S T - {pool_name}" in the coinbase scriptsig.
    /// If not set, falls back to mining_mode default (PublicPool, PrivatePool, PrivateSolo).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_name: Option<String>,
    /// Optional coinbase scriptsig tag shown on block explorers.
    /// Advanced override — takes priority over pool_name if both are set.
    /// If not set, auto-derives from pool_name or mining_mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coinbase_extra: Option<String>,
    /// Optional password required for --genesis flag. When set in the config,
    /// the operator must also pass --genesis-password on the CLI for genesis to proceed.
    /// Prevents accidental dual-genesis if someone mistakenly runs --genesis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genesis_password: Option<String>,
}

impl PoolConfig {
    /// Validate pool configuration
    ///
    /// Returns an error if required fields are missing or invalid.
    pub fn validate(&self) -> Result<(), String> {
        if self.treasury_address.is_empty() {
            return Err("treasury_address must be configured".to_string());
        }

        // Validate treasury address
        if let Err(e) = self.treasury_address.validate() {
            return Err(format!("treasury_address: {}", e));
        }

        if self.min_payout_sats == 0 {
            return Err("min_payout_sats must be greater than 0".to_string());
        }
        Ok(())
    }

    /// Get the treasury address string (for backward compatibility)
    pub fn treasury_address_str(&self) -> &str {
        self.treasury_address.address()
    }

    /// Check if treasury is multi-sig
    pub fn is_multisig_treasury(&self) -> bool {
        self.treasury_address.is_multisig()
    }
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            // Default placeholder - MUST be configured in production
            treasury_address: TreasuryAddress::default(),
            min_payout_sats: 100_000, // 0.001 BTC minimum
            payout_interval_blocks: 100,
            node_payout_address: None,
            pool_name: None,
            coinbase_extra: None,
            genesis_password: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = NodeConfig::default();
        assert_eq!(config.network.sv2_port, SV2_STRATUM_PORT);
        assert_eq!(config.bitcoin.network, BitcoinNetwork::Signet);
    }

    #[test]
    fn test_ghost_pay_enabled_predicate() {
        // Pool-only node: no [ghost_pay] block at all → not enabled.
        let mut config = NodeConfig::default();
        assert!(config.ghost_pay.is_none());
        assert!(
            !config.ghost_pay_enabled(),
            "absent [ghost_pay] must read as disabled"
        );

        // Pool-only node: [ghost_pay] block present but enabled = false
        // (this is exactly what `setup` writes via GhostPayConfig::default()).
        // The block's presence must NOT be mistaken for a running ghost-pay.
        config.ghost_pay = Some(GhostPayConfig::default());
        assert!(!config.ghost_pay.as_ref().unwrap().enabled);
        assert!(
            !config.ghost_pay_enabled(),
            "[ghost_pay] with enabled = false must read as disabled"
        );

        // Core node: ghost-pay actually enabled.
        config.ghost_pay = Some(GhostPayConfig {
            enabled: true,
            ..GhostPayConfig::default()
        });
        assert!(
            config.ghost_pay_enabled(),
            "[ghost_pay] with enabled = true must read as enabled"
        );
    }

    #[test]
    fn test_wraith_enabled_predicate() {
        // No [ghost_pay] block → Wraith reads as off.
        let mut config = NodeConfig::default();
        assert!(config.ghost_pay.is_none());
        assert!(
            !config.wraith_enabled(),
            "absent [ghost_pay] must read wraith as disabled"
        );

        // Operator disabled Wraith explicitly.
        config.ghost_pay = Some(GhostPayConfig {
            wraith_enabled: false,
            ..GhostPayConfig::default()
        });
        assert!(!config.wraith_enabled());

        // Operator enabled Wraith → predicate reflects the choice regardless of
        // whether ghost-pay's `enabled` flag is set (it's a separate signal).
        config.ghost_pay = Some(GhostPayConfig {
            enabled: false,
            wraith_enabled: true,
            ..GhostPayConfig::default()
        });
        assert!(
            config.wraith_enabled(),
            "[ghost_pay] wraith_enabled = true must read as enabled"
        );
    }

    #[test]
    fn test_ghost_pay_enabled_from_toml() {
        // The `enabled` flag round-trips through TOML: a pool-only node writes
        // `enabled = false`, a core node `enabled = true`. Deserialise the
        // [ghost_pay] block in isolation to confirm the flag is what the
        // predicate keys off (NodeConfig sections other than reaper/coordinator
        // aren't serde(default), so we parse the sub-struct directly).
        let pool_only: GhostPayConfig = toml::from_str(
            "enabled = false\nvirtual_block_secs = 10\nepoch_blocks = 2160\nwraith_enabled = true\n",
        )
        .unwrap();
        assert!(!pool_only.enabled);

        let core: GhostPayConfig = toml::from_str(
            "enabled = true\nvirtual_block_secs = 10\nepoch_blocks = 2160\nwraith_enabled = true\n",
        )
        .unwrap();
        assert!(core.enabled);

        let mut config = NodeConfig::default();
        config.ghost_pay = Some(pool_only);
        assert!(!config.ghost_pay_enabled());
        config.ghost_pay = Some(core);
        assert!(config.ghost_pay_enabled());
    }

    #[test]
    fn test_reaper_settings_backward_compat() {
        // Legacy pool.toml with only the master switch must deserialise to
        // all-detectors-on (today's behaviour) via the per-field serde defaults.
        let legacy: ReaperSettings = toml::from_str("enabled = true").unwrap();
        assert!(legacy.enabled);
        assert!(legacy.reject_inscription);
        assert!(legacy.reject_runestone);
        assert!(legacy.reject_legacy_data_stuffing);
        assert!(legacy.validate_pubkey_curve_point);
        assert_eq!(legacy.max_op_return_bytes, 82);
        assert_eq!(legacy.min_drop_size, 76);
        assert_eq!(legacy.min_excess_witness_bytes, 500);
        assert_eq!(legacy.legacy_max_push_bytes, 80);

        // An entirely empty table is also all-on.
        let empty: ReaperSettings = toml::from_str("").unwrap();
        assert!(empty.enabled && empty.reject_annex && empty.reject_opreturn);

        // enabled=false leaves the per-vector fields deserialising to their
        // defaults; the master gate is what disables enforcement.
        let off: ReaperSettings = toml::from_str("enabled = false").unwrap();
        assert!(!off.enabled);
        assert!(off.reject_inscription);
    }

    #[test]
    fn test_reaper_settings_per_vector_roundtrip() {
        // A partial per-vector config: only some detectors disabled.
        let cfg: ReaperSettings = toml::from_str(
            "enabled = true\nreject_runestone = false\nreject_annex = false\nmax_op_return_bytes = 40\n",
        )
        .unwrap();
        assert!(cfg.enabled);
        assert!(!cfg.reject_runestone);
        assert!(!cfg.reject_annex);
        assert!(cfg.reject_inscription); // untouched -> default true
        assert_eq!(cfg.max_op_return_bytes, 40);

        // Round-trips through serialisation unchanged.
        let s = toml::to_string(&cfg).unwrap();
        let back: ReaperSettings = toml::from_str(&s).unwrap();
        assert!(!back.reject_runestone && !back.reject_annex && back.reject_inscription);
        assert_eq!(back.max_op_return_bytes, 40);
    }

    #[test]
    fn test_ghostd_flags_all_on() {
        let flags = ReaperSettings::default().ghostd_flags();
        assert!(flags.contains(&"-ghostreaper=enabled".to_string()));
        assert!(flags.contains(&"-ghostreaper-rejectinscription=1".to_string()));
        assert!(flags.contains(&"-ghostreaper-rejectannex=1".to_string()));
        assert!(flags.contains(&"-ghostreaper-rejectopreturn=1".to_string()));
        assert!(flags.contains(&"-ghostreaper-rejectrunestone=1".to_string()));
        assert!(flags.contains(&"-ghostreaper-rejectdustflood=1".to_string()));
        assert!(flags.contains(&"-ghostreaper-dustfloodthreshold=330".to_string()));
        assert!(flags.contains(&"-ghostreaper-maxopreturn=82".to_string()));
        assert!(flags.contains(&"-ghostreaper-mindropsize=76".to_string()));
        // Pool-only vectors must NOT leak into ghostd flags.
        assert!(!flags.iter().any(|f| f.contains("unreachable")));
        assert!(!flags.iter().any(|f| f.contains("excess")));
        assert!(!flags.iter().any(|f| f.contains("legacy")));
    }

    #[test]
    fn test_ghostd_flags_master_off_zeroes_all() {
        let s = ReaperSettings {
            enabled: false,
            ..Default::default()
        };
        let flags = s.ghostd_flags();
        assert!(flags.contains(&"-ghostreaper=disabled".to_string()));
        // every per-vector flag is 0 regardless of its individual setting
        assert!(flags.iter().all(|f| !f.ends_with("=1")));
        assert!(flags.contains(&"-ghostreaper-rejectannex=0".to_string()));
    }

    #[test]
    fn test_ghostd_flags_mixed() {
        let s = ReaperSettings {
            enabled: true,
            reject_runestone: false,
            reject_opreturn: false,
            ..Default::default()
        };
        let flags = s.ghostd_flags();
        assert!(flags.contains(&"-ghostreaper-rejectrunestone=0".to_string()));
        assert!(flags.contains(&"-ghostreaper-rejectopreturn=0".to_string()));
        assert!(flags.contains(&"-ghostreaper-rejectinscription=1".to_string()));
    }

    #[test]
    fn test_network_ports() {
        assert_eq!(BitcoinNetwork::Mainnet.default_rpc_port(), 8332);
        assert_eq!(BitcoinNetwork::Signet.default_rpc_port(), 38332);
    }

    #[test]
    fn test_policy_profiles() {
        let config = PolicyConfig {
            profile: PolicyProfile::BitcoinPure,
            custom: None,
        };
        assert_eq!(config.profile, PolicyProfile::BitcoinPure);
    }

    #[test]
    fn test_signing_key_required_for_public_mining() {
        let mut config = NodeConfig::default();
        config.network.mining_mode = MiningMode::PublicPool;
        config.network.signing_key = None;

        let result = config.validate();
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "network.signing_key"));
    }

    #[test]
    fn test_signing_key_valid_format() {
        let mut config = NodeConfig::default();
        config.network.mining_mode = MiningMode::PublicPool;
        // 64 hex chars = valid 32-byte key
        config.network.signing_key =
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string());

        let result = config.validate();
        // Should not have signing_key error (may have other errors like missing treasury)
        assert!(!result
            .errors
            .iter()
            .any(|e| e.field == "network.signing_key" && e.message.contains("REQUIRED")));
    }

    #[test]
    fn test_signing_key_invalid_length() {
        let mut config = NodeConfig::default();
        config.network.mining_mode = MiningMode::PublicPool;
        // Too short
        config.network.signing_key = Some("0123456789abcdef".to_string());

        let result = config.validate();
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "network.signing_key" && e.message.contains("64 hex")));
    }

    #[test]
    fn test_signing_key_invalid_chars() {
        let mut config = NodeConfig::default();
        config.network.mining_mode = MiningMode::PublicPool;
        // Contains non-hex chars (g, h, i, j)
        config.network.signing_key =
            Some("ghij456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string());

        let result = config.validate();
        assert!(!result.is_valid());
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "network.signing_key" && e.message.contains("hexadecimal")));
    }

    #[test]
    fn test_signing_key_not_required_private_mining() {
        let mut config = NodeConfig::default();
        config.network.mining_mode = MiningMode::PrivatePool;
        config.network.private_mining_password = Some("strong-password".to_string());
        config.network.signing_key = None;

        let result = config.validate();
        // Should not have signing_key error when not in PublicPool mode
        assert!(!result
            .errors
            .iter()
            .any(|e| e.field == "network.signing_key"));
    }

    #[test]
    fn test_mining_mode_public_pool() {
        let mut config = NodeConfig::default();
        config.network.mining_mode = MiningMode::PublicPool;
        config.network.signing_key =
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string());

        let result = config.validate();
        // Should not have mining_mode errors
        assert!(!result
            .errors
            .iter()
            .any(|e| e.field.contains("mining_mode")));
    }

    #[test]
    fn test_mining_mode_private_pool_requires_password() {
        let mut config = NodeConfig::default();
        config.network.mining_mode = MiningMode::PrivatePool;
        config.network.private_mining_password = None;

        let result = config.validate();
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "network.private_mining_password"));
    }

    #[test]
    fn test_mining_mode_private_pool_with_password() {
        let mut config = NodeConfig::default();
        config.network.mining_mode = MiningMode::PrivatePool;
        config.network.private_mining_password = Some("mysecretpassword".to_string());

        let result = config.validate();
        // Should not have password error
        assert!(!result
            .errors
            .iter()
            .any(|e| e.field == "network.private_mining_password"));
    }

    #[test]
    fn test_mining_mode_private_pool_short_password_error() {
        // L-17 FIX: Short passwords now produce errors, not warnings
        // Weak passwords expose private mining endpoints to brute-force attacks
        let mut config = NodeConfig::default();
        config.network.mining_mode = MiningMode::PrivatePool;
        config.network.private_mining_password = Some("short".to_string()); // 5 chars

        let result = config.validate();
        // L-17: Should now be an error instead of a warning
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "network.private_mining_password"
                && e.message.contains("at least 8 characters")));
    }

    #[test]
    fn test_mining_mode_private_solo_requires_password_and_address() {
        let mut config = NodeConfig::default();
        config.network.mining_mode = MiningMode::PrivateSolo;
        config.network.private_mining_password = None;
        config.network.solo_payout_address = None;

        let result = config.validate();
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "network.private_mining_password"));
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "network.solo_payout_address"));
    }

    #[test]
    fn test_mining_mode_private_solo_valid() {
        let mut config = NodeConfig::default();
        config.bitcoin.network = BitcoinNetwork::Signet;
        config.network.mining_mode = MiningMode::PrivateSolo;
        config.network.private_mining_password = Some("mysecretpassword".to_string());
        config.network.solo_payout_address =
            Some("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string());

        let result = config.validate();
        // Should not have mining mode related errors
        assert!(!result
            .errors
            .iter()
            .any(|e| e.field == "network.private_mining_password"));
        assert!(!result
            .errors
            .iter()
            .any(|e| e.field == "network.solo_payout_address"));
    }

    #[test]
    fn test_mining_mode_private_solo_wrong_network_address() {
        let mut config = NodeConfig::default();
        config.bitcoin.network = BitcoinNetwork::Mainnet;
        config.network.mining_mode = MiningMode::PrivateSolo;
        config.network.private_mining_password = Some("mysecretpassword".to_string());
        // Using signet address on mainnet
        config.network.solo_payout_address =
            Some("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string());

        let result = config.validate();
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "network.solo_payout_address"
                && e.message.contains("Invalid address prefix")));
    }

    #[test]
    fn test_mainnet_requires_seed_nodes() {
        // M-15: Mainnet nodes must have seed_nodes configured to discover peers
        let mut config = NodeConfig::default();
        config.bitcoin.network = BitcoinNetwork::Mainnet;
        config.network.noise_enabled = true;
        config.network.internal_api_secret =
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string());
        config.network.seed_nodes = vec![]; // Empty seed nodes

        let result = config.validate();
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "network.seed_nodes" && e.message.contains("MAINNET SECURITY")));
    }

    #[test]
    fn test_mainnet_with_seed_nodes_valid() {
        // M-15: Mainnet nodes with seed_nodes configured should not error
        // M1: Mainnet requires at least 3 seed nodes
        let mut config = NodeConfig::default();
        config.bitcoin.network = BitcoinNetwork::Mainnet;
        config.network.noise_enabled = true;
        config.network.internal_api_secret =
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string());
        config.network.seed_nodes = vec![
            "seed1.bitcoinghost.org:8559".to_string(),
            "seed2.bitcoinghost.org:8559".to_string(),
            "seed3.bitcoinghost.org:8559".to_string(),
        ];

        let result = config.validate();
        // Should not have seed_nodes error
        assert!(!result
            .errors
            .iter()
            .any(|e| e.field == "network.seed_nodes"));
    }

    #[test]
    fn test_signet_allows_empty_seed_nodes() {
        // M-15: Signet (non-mainnet) nodes do not require seed nodes
        let mut config = NodeConfig::default();
        config.bitcoin.network = BitcoinNetwork::Signet;
        config.network.seed_nodes = vec![]; // Empty is OK for signet

        let result = config.validate();
        // Should not have seed_nodes error on non-mainnet
        assert!(!result
            .errors
            .iter()
            .any(|e| e.field == "network.seed_nodes"));
    }

    #[test]
    fn test_hsm_signer_rejected_at_config_validation() {
        let mut config = NodeConfig::default();
        config.identity.signer = Some(SignerConfig::Hsm {
            library_path: None,
            slot: 0,
            pin_env: "HSM_PIN".to_string(),
            key_label: None,
        });

        let result = config.validate();
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "identity.signer" && e.message.contains("HSM")));
    }

    #[test]
    fn test_kms_signer_rejected_at_config_validation() {
        let mut config = NodeConfig::default();
        config.identity.signer = Some(SignerConfig::Kms {
            key_id: "test-key".to_string(),
            region: "us-east-1".to_string(),
            provider: crate::signer::KmsProvider::Aws,
        });

        let result = config.validate();
        assert!(result
            .errors
            .iter()
            .any(|e| e.field == "identity.signer" && e.message.contains("KMS")));
    }

    #[test]
    fn test_local_signer_passes_config_validation() {
        let mut config = NodeConfig::default();
        config.identity.signer = Some(SignerConfig::Local {
            key_path: std::path::PathBuf::from("~/.ghost/node.key"),
        });

        let result = config.validate();
        assert!(!result.errors.iter().any(|e| e.field == "identity.signer"));
    }

    #[test]
    fn test_mainnet_without_tls_cert_warns_but_does_not_error() {
        // Identity-derived TLS is the mainnet-allowed default — explicit
        // cert_path is optional. The validator should emit a warning (so
        // operators are aware of the cert source) but NOT a hard error.
        let mut config = NodeConfig::default();
        config.bitcoin.network = BitcoinNetwork::Mainnet;
        config.network.noise_enabled = true;
        config.network.internal_api_secret =
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string());
        config.network.seed_nodes = vec![
            "seed1.bitcoinghost.org:8559".to_string(),
            "seed2.bitcoinghost.org:8559".to_string(),
            "seed3.bitcoinghost.org:8559".to_string(),
        ];
        config.network.tls = TlsConfig::default();

        let result = config.validate();
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.field == "network.tls.cert_path"),
            "Mainnet must NOT error on missing cert_path (identity-derived TLS is allowed)"
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.field == "network.tls.cert_path"),
            "Mainnet should warn when cert_path is unset so operators understand the source"
        );
    }

    #[test]
    fn test_mainnet_tls_cert_without_key_errors() {
        let mut config = NodeConfig::default();
        config.bitcoin.network = BitcoinNetwork::Mainnet;
        config.network.noise_enabled = true;
        config.network.internal_api_secret =
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string());
        config.network.seed_nodes = vec![
            "seed1.bitcoinghost.org:8559".to_string(),
            "seed2.bitcoinghost.org:8559".to_string(),
            "seed3.bitcoinghost.org:8559".to_string(),
        ];
        config.network.tls = TlsConfig {
            cert_path: Some(PathBuf::from("/etc/ghost/cert.pem")),
            key_path: None, // Missing key
        };

        let result = config.validate();
        assert!(
            result.errors.iter().any(
                |e| e.field == "network.tls.key_path" && e.message.contains("MAINNET SECURITY")
            ),
            "Mainnet should require TLS key_path when cert_path is set"
        );
    }

    #[test]
    fn test_mainnet_with_tls_cert_and_key_passes() {
        let mut config = NodeConfig::default();
        config.bitcoin.network = BitcoinNetwork::Mainnet;
        config.network.noise_enabled = true;
        config.network.internal_api_secret =
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string());
        config.network.seed_nodes = vec![
            "seed1.bitcoinghost.org:8559".to_string(),
            "seed2.bitcoinghost.org:8559".to_string(),
            "seed3.bitcoinghost.org:8559".to_string(),
        ];
        config.network.tls = TlsConfig {
            cert_path: Some(PathBuf::from("/etc/ghost/cert.pem")),
            key_path: Some(PathBuf::from("/etc/ghost/key.pem")),
        };

        let result = config.validate();
        // Should not have TLS errors
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.field.starts_with("network.tls")),
            "Mainnet with cert and key should not have TLS errors"
        );
    }

    #[test]
    fn test_signet_allows_no_tls_cert() {
        let mut config = NodeConfig::default();
        config.bitcoin.network = BitcoinNetwork::Signet;
        config.network.tls = TlsConfig::default(); // No cert

        let result = config.validate();
        // Should not have TLS errors on non-mainnet
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.field.starts_with("network.tls")),
            "Signet should not require TLS cert"
        );
    }

    #[test]
    fn test_tls_config_default() {
        let tls = TlsConfig::default();
        assert!(tls.cert_path.is_none());
        assert!(tls.key_path.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn test_config_permissions_mainnet_rejects_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.toml");
        std::fs::write(&path, "# test config").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let result = validate_config_permissions(&path, Some(&BitcoinNetwork::Mainnet));
        assert!(
            result.is_err(),
            "Mainnet must reject world-readable config files"
        );
        assert!(
            result.unwrap_err().contains("Mainnet"),
            "Error should mention mainnet"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_config_permissions_mainnet_accepts_secure() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.toml");
        std::fs::write(&path, "# test config").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let result = validate_config_permissions(&path, Some(&BitcoinNetwork::Mainnet));
        assert!(
            result.is_ok(),
            "Mainnet should accept 0600 config: {:?}",
            result.err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_config_permissions_signet_warns_but_succeeds() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pool.toml");
        std::fs::write(&path, "# test config").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let result = validate_config_permissions(&path, Some(&BitcoinNetwork::Signet));
        assert!(
            result.is_ok(),
            "Signet should warn but allow world-readable config"
        );
    }
}
