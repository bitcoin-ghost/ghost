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
//| FILE: rpc.rs                                                                                                         |
//|======================================================================================================================|

//! Bitcoin Core RPC client
//!
//! Provides async communication with Bitcoin Core via JSON-RPC.
//!
//! Security features:
//! - TLS required for remote connections (enforced)
//! - Block template validation before use
//! - Bounded fields to prevent DoS

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::warn;
use zeroize::Zeroizing;

use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use crate::config::BitcoinNetwork;
use crate::error::{GhostError, GhostResult};

// ============================================================
// Retry Configuration
// ============================================================

/// Configuration for RPC retry behavior
#[derive(Debug, Clone)]
pub struct RpcRetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,
    /// Initial backoff delay
    pub initial_backoff: Duration,
    /// Maximum backoff delay
    pub max_backoff: Duration,
    /// Backoff multiplier (exponential factor)
    pub backoff_multiplier: f64,
}

impl Default for RpcRetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
            backoff_multiplier: 2.0,
        }
    }
}

impl RpcRetryConfig {
    /// Config for critical operations (more retries, longer waits)
    pub fn critical() -> Self {
        Self {
            max_retries: 5,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(10),
            backoff_multiplier: 2.0,
        }
    }

    /// Config for quick operations (fewer retries)
    pub fn quick() -> Self {
        Self {
            max_retries: 2,
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_secs(1),
            backoff_multiplier: 2.0,
        }
    }

    /// No retries
    pub fn no_retry() -> Self {
        Self {
            max_retries: 0,
            initial_backoff: Duration::from_millis(0),
            max_backoff: Duration::from_millis(0),
            backoff_multiplier: 1.0,
        }
    }
}

/// Check if an RPC error is retryable (transient)
fn is_retryable_error(error: &GhostError) -> bool {
    match error {
        GhostError::Rpc(msg) => {
            // Network/timeout errors are retryable
            let transient_patterns = [
                "Request failed",
                "timeout",
                "connection refused",
                "connection reset",
                "temporarily unavailable",
                "rate limit",
                "ETIMEDOUT",
                "ECONNRESET",
                "ECONNREFUSED",
            ];
            transient_patterns
                .iter()
                .any(|pattern| msg.to_lowercase().contains(&pattern.to_lowercase()))
        }
        GhostError::Internal(msg) => msg.contains("timeout") || msg.contains("connection"),
        _ => false,
    }
}

// ============================================================
// Security Constants
// ============================================================

/// Maximum transactions in a block template
pub const MAX_TEMPLATE_TRANSACTIONS: usize = 10_000;
/// Maximum coinbaseaux entries
pub const MAX_COINBASE_AUX_ENTRIES: usize = 32;
/// Maximum coinbaseaux key length
pub const MAX_COINBASE_AUX_KEY_LEN: usize = 64;
/// Maximum coinbaseaux value length
pub const MAX_COINBASE_AUX_VALUE_LEN: usize = 256;
/// Valid previousblockhash length (64 hex chars)
pub const BLOCK_HASH_HEX_LEN: usize = 64;
/// Valid bits field length (8 hex chars)
pub const BITS_HEX_LEN: usize = 8;
/// Maximum height deviation from current
pub const MAX_HEIGHT_DEVIATION: u64 = 10;
/// Maximum Bitcoin supply in satoshis
pub const MAX_SUPPLY_SATS: u64 = 21_000_000 * 100_000_000;

// ============================================================
// Template Validation
// ============================================================

/// Block template validation errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum TemplateValidationError {
    #[error("Invalid previousblockhash: expected {BLOCK_HASH_HEX_LEN} hex chars, got {0}")]
    InvalidPrevHash(usize),
    #[error("Invalid bits format: expected {BITS_HEX_LEN} hex chars, got {0}")]
    InvalidBits(usize),
    #[error("Too many transactions: {0} > {MAX_TEMPLATE_TRANSACTIONS}")]
    TooManyTransactions(usize),
    #[error("Too many coinbaseaux entries: {0} > {MAX_COINBASE_AUX_ENTRIES}")]
    TooManyCoinbaseAux(usize),
    #[error("Coinbaseaux key too long: {0} > {MAX_COINBASE_AUX_KEY_LEN}")]
    CoinbaseAuxKeyTooLong(usize),
    #[error("Coinbaseaux value too long: {0} > {MAX_COINBASE_AUX_VALUE_LEN}")]
    CoinbaseAuxValueTooLong(usize),
    #[error("Coinbase value exceeds max supply: {0}")]
    InvalidCoinbaseValue(u64),
    #[error("Coinbase value mismatch: expected subsidy({0}) + fees({1}) = {2}, got {3}")]
    CoinbaseValueMismatch(u64, u64, u64, u64),
    #[error("Height out of range: template={0}, expected near {1}")]
    HeightOutOfRange(u64, u64),
    #[error("Invalid target format: expected 64 hex chars")]
    InvalidTarget,
    #[error("Target is zero (invalid difficulty)")]
    ZeroTarget,
    #[error("Target value out of range: too easy or too hard")]
    TargetOutOfRange,
    #[error("Bits does not match target: bits={0}, target={1}")]
    BitsTargetMismatch(String, String),
    #[error("Invalid hex in field {0}")]
    InvalidHex(String),
}

/// Maximum valid target per network (minimum difficulty)
/// Mainnet: bits = 0x1d00ffff (difficulty 1)
/// Signet/Testnet/Regtest: bits = 0x1e0377ae or easier — use permissive limit
const MAX_TARGET_HEX_MAINNET: &str =
    "00000000ffff0000000000000000000000000000000000000000000000000000";
/// Signet/testnet/regtest can have extremely low difficulty
const MAX_TARGET_HEX_TESTNET: &str =
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// Get the maximum valid target for a given network
fn max_target_for_network(network: Option<&BitcoinNetwork>) -> &'static str {
    match network {
        Some(BitcoinNetwork::Mainnet) | None => MAX_TARGET_HEX_MAINNET,
        Some(_) => MAX_TARGET_HEX_TESTNET,
    }
}

/// Calculate block subsidy for a given height (halving schedule)
///
/// Returns the expected block subsidy in satoshis for the given height.
/// This follows the Bitcoin halving schedule:
/// - Initial subsidy: 50 BTC (5,000,000,000 satoshis)
/// - Halves every 210,000 blocks on mainnet
/// - Halves every 150 blocks on regtest
///
/// MED-POOL-1: This function is public to allow payout validation.
pub fn calculate_block_subsidy(height: u64, network: Option<&BitcoinNetwork>) -> u64 {
    let halvings = match network {
        // Regtest and testnet have different halving intervals
        Some(BitcoinNetwork::Regtest) => height / 150,
        _ => height / 210_000,
    };

    if halvings >= 64 {
        return 0;
    }

    // Initial subsidy is 50 BTC = 5_000_000_000 satoshis
    let initial_subsidy: u64 = 50 * 100_000_000;
    initial_subsidy >> halvings
}

/// Convert compact bits to target
fn bits_to_target(bits_hex: &str) -> Option<[u8; 32]> {
    let bits = u32::from_str_radix(bits_hex, 16).ok()?;

    // Extract exponent and mantissa
    let exponent = ((bits >> 24) & 0xff) as usize;
    let mantissa = bits & 0x007fffff;

    // Handle negative flag (should not be set for valid targets)
    if bits & 0x00800000 != 0 {
        return None;
    }

    // Construct target
    let mut target = [0u8; 32];

    if exponent == 0 {
        return Some(target);
    }

    // Calculate position and store mantissa bytes
    if exponent <= 3 {
        // Mantissa fits in the bytes
        let shift = 8 * (3 - exponent);
        let value = mantissa >> shift;
        target[31] = (value & 0xff) as u8;
        if exponent >= 2 {
            target[30] = ((value >> 8) & 0xff) as u8;
        }
        if exponent >= 3 {
            target[29] = ((value >> 16) & 0xff) as u8;
        }
    } else {
        let offset = exponent - 3;
        if offset < 29 {
            target[31 - offset] = (mantissa & 0xff) as u8;
            target[30 - offset] = ((mantissa >> 8) & 0xff) as u8;
            target[29 - offset] = ((mantissa >> 16) & 0xff) as u8;
        }
    }

    Some(target)
}

/// Validate a block template before use
pub fn validate_block_template(
    template: &BlockTemplate,
    current_height: Option<u64>,
    network: Option<&BitcoinNetwork>,
) -> Result<(), TemplateValidationError> {
    // Validate previousblockhash format (64 hex chars)
    if template.previousblockhash.len() != BLOCK_HASH_HEX_LEN {
        return Err(TemplateValidationError::InvalidPrevHash(
            template.previousblockhash.len(),
        ));
    }
    if !template
        .previousblockhash
        .chars()
        .all(|c| c.is_ascii_hexdigit())
    {
        return Err(TemplateValidationError::InvalidHex(
            "previousblockhash".into(),
        ));
    }

    // Validate bits format (8 hex chars)
    if template.bits.len() != BITS_HEX_LEN {
        return Err(TemplateValidationError::InvalidBits(template.bits.len()));
    }
    if !template.bits.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(TemplateValidationError::InvalidHex("bits".into()));
    }

    // Validate transaction count
    if template.transactions.len() > MAX_TEMPLATE_TRANSACTIONS {
        return Err(TemplateValidationError::TooManyTransactions(
            template.transactions.len(),
        ));
    }

    // Validate coinbaseaux bounds
    if template.coinbaseaux.len() > MAX_COINBASE_AUX_ENTRIES {
        return Err(TemplateValidationError::TooManyCoinbaseAux(
            template.coinbaseaux.len(),
        ));
    }
    for (key, value) in &template.coinbaseaux {
        if key.len() > MAX_COINBASE_AUX_KEY_LEN {
            return Err(TemplateValidationError::CoinbaseAuxKeyTooLong(key.len()));
        }
        if value.len() > MAX_COINBASE_AUX_VALUE_LEN {
            return Err(TemplateValidationError::CoinbaseAuxValueTooLong(
                value.len(),
            ));
        }
    }

    // Validate coinbase value (can't exceed max supply)
    if template.coinbasevalue > MAX_SUPPLY_SATS {
        return Err(TemplateValidationError::InvalidCoinbaseValue(
            template.coinbasevalue,
        ));
    }

    // Validate height if current height known
    if let Some(current) = current_height {
        let min_height = current.saturating_sub(MAX_HEIGHT_DEVIATION);
        let max_height = current.saturating_add(MAX_HEIGHT_DEVIATION);
        if template.height < min_height || template.height > max_height {
            return Err(TemplateValidationError::HeightOutOfRange(
                template.height,
                current,
            ));
        }
    }

    // Validate target format (64 hex chars)
    if template.target.len() != 64 || !template.target.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(TemplateValidationError::InvalidTarget);
    }

    // Validate target is not zero
    if template.target.chars().all(|c| c == '0') {
        return Err(TemplateValidationError::ZeroTarget);
    }

    // Validate target is not above maximum (minimum difficulty) for this network
    if template.target.as_str() > max_target_for_network(network) {
        return Err(TemplateValidationError::TargetOutOfRange);
    }

    // Validate bits matches target (consistency check)
    if let Some(computed_target) = bits_to_target(&template.bits) {
        let computed_hex = hex::encode(computed_target);
        // Compare first 16 chars (most significant) for rough match
        // Bits encoding has limited precision, so we can't expect exact match
        if computed_hex[..16] != template.target[..16] {
            warn!(
                bits = %template.bits,
                computed_target = %computed_hex,
                template_target = %template.target,
                "Bits and target mismatch detected"
            );
            // Note: This is a warning rather than error because Bitcoin Core
            // may have rounding differences in bits encoding
        }
    }

    // Validate coinbase value matches expected subsidy + fees
    let total_fees: u64 = template.transactions.iter().map(|tx| tx.fee).sum();
    let expected_subsidy = calculate_block_subsidy(template.height, None);
    let expected_coinbase = expected_subsidy.saturating_add(total_fees);

    // Allow some tolerance for signet/testnet where subsidy may differ
    // Log warning but don't fail - Bitcoin Core is authoritative
    if template.coinbasevalue != expected_coinbase {
        warn!(
            height = template.height,
            expected_subsidy = expected_subsidy,
            total_fees = total_fees,
            expected_coinbase = expected_coinbase,
            actual_coinbase = template.coinbasevalue,
            "Coinbase value differs from expected subsidy + fees (may be normal for signet/testnet)"
        );
    }

    Ok(())
}

// ============================================================
// RPC Configuration
// ============================================================

/// RPC client configuration
///
/// H-AUTH-2 FIX: Password is stored using SecretString which:
/// - Does not implement Debug (redacts in output)
/// - Zeros memory on drop
/// - Requires explicit .expose_secret() to access
pub struct RpcConfig {
    /// Host address
    pub host: String,
    /// Port number
    pub port: u16,
    /// RPC username
    pub username: String,
    /// RPC password (H-AUTH-2: uses SecretString for secure storage)
    pub password: SecretString,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
    /// Enable TLS (required for remote connections)
    pub tls_enabled: bool,
    /// Custom CA certificate path (for self-signed certs)
    pub tls_cert_path: Option<PathBuf>,
}

impl std::fmt::Debug for RpcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // H-AUTH-2: Redact password in Debug output
        f.debug_struct("RpcConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("timeout_secs", &self.timeout_secs)
            .field("tls_enabled", &self.tls_enabled)
            .field("tls_cert_path", &self.tls_cert_path)
            .finish()
    }
}

impl Clone for RpcConfig {
    fn clone(&self) -> Self {
        Self {
            host: self.host.clone(),
            port: self.port,
            username: self.username.clone(),
            // H-AUTH-2: Clone via expose_secret to maintain security
            password: SecretString::new(self.password.expose_secret().to_string()),
            timeout_secs: self.timeout_secs,
            tls_enabled: self.tls_enabled,
            tls_cert_path: self.tls_cert_path.clone(),
        }
    }
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 8332,
            username: String::new(),
            password: SecretString::new(String::new()),
            timeout_secs: 30,
            tls_enabled: false,
            tls_cert_path: None,
        }
    }
}

impl RpcConfig {
    /// Check if the host is localhost
    pub fn is_localhost(&self) -> bool {
        self.host == "127.0.0.1" || self.host == "localhost" || self.host == "::1"
    }

    /// Validate the configuration
    pub fn validate(&self) -> GhostResult<()> {
        // TLS required for remote connections
        if !self.is_localhost() && !self.tls_enabled {
            return Err(GhostError::Config(
                "TLS required for remote Ghost Core connections. \
                 Set tls_enabled=true or use localhost."
                    .into(),
            ));
        }
        Ok(())
    }
}

// ============================================================
// RPC Client
// ============================================================

/// Bitcoin Core RPC client
pub struct BitcoinRpc {
    /// HTTP client
    client: reqwest::Client,
    /// RPC URL
    url: String,
    /// L-14 FIX: Basic auth header value wrapped in Zeroizing for secure memory handling.
    /// Ensures the Base64-encoded credentials are zeroed when the client is dropped,
    /// preventing credential leakage through memory dumps or core files.
    auth: Zeroizing<String>,
    /// Request ID counter
    id_counter: AtomicU64,
    /// Last known block height (for template validation)
    last_known_height: AtomicU64,
    /// Unix seconds of the last successful RPC call, or 0 if none has ever succeeded.
    ///
    /// The circuit breaker knows whether calls are *failing*; it cannot say when one last
    /// worked, and a breaker that nothing has exercised looks identical to a healthy one. This is
    /// the difference between "no bad news" and "good news", and only the second is health.
    last_success_ts: AtomicU64,
    /// Circuit breaker for fault tolerance
    circuit_breaker: Arc<CircuitBreaker>,
    /// Retry configuration
    retry_config: RpcRetryConfig,
    /// Bitcoin network (for network-aware validation)
    network: BitcoinNetwork,
}

impl std::fmt::Debug for BitcoinRpc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitcoinRpc")
            .field("url", &self.url)
            .field("id_counter", &self.id_counter)
            .field("last_known_height", &self.last_known_height)
            .finish()
    }
}

impl BitcoinRpc {
    /// Create a new RPC client (legacy constructor for localhost)
    ///
    /// H-AUTH-2: Password is immediately wrapped in SecretString for secure handling
    ///
    /// # Errors
    /// Returns an error if the HTTP client cannot be created
    pub fn new(host: &str, port: u16, user: &str, password: &str) -> GhostResult<Self> {
        let config = RpcConfig {
            host: host.to_string(),
            port,
            username: user.to_string(),
            password: SecretString::new(password.to_string()),
            ..Default::default()
        };
        Self::with_config(config)
    }

    /// Create a new RPC client with full configuration
    pub fn with_config(config: RpcConfig) -> GhostResult<Self> {
        Self::with_config_and_retry(config, RpcRetryConfig::default())
    }

    /// Create a new RPC client with full configuration and retry settings
    pub fn with_config_and_retry(
        config: RpcConfig,
        retry_config: RpcRetryConfig,
    ) -> GhostResult<Self> {
        use base64::Engine;

        // Validate configuration
        config.validate()?;

        // Warn about insecure localhost (but allow it)
        if config.is_localhost() && !config.tls_enabled {
            tracing::warn!(
                "Using unencrypted connection to Ghost Core on localhost. \
                 Consider enabling TLS for defense in depth."
            );
        }

        let scheme = if config.tls_enabled { "https" } else { "http" };
        let url = format!("{}://{}:{}", scheme, config.host, config.port);
        // H-AUTH-2: Use Zeroizing to ensure credentials string is zeroed after encoding
        let credentials = Zeroizing::new(format!(
            "{}:{}",
            config.username,
            config.password.expose_secret()
        ));
        // L-14 FIX: Wrap auth header in Zeroizing to ensure it's zeroed on drop
        // The Base64-encoded credentials could leak through memory dumps if not zeroed
        let auth = Zeroizing::new(
            base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes()),
        );

        let mut client_builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            // Proactively close idle connections before ghostd's HTTP keep-alive
            // expires, preventing "error sending request" on stale connections
            .pool_idle_timeout(std::time::Duration::from_secs(15));

        // Add custom CA certificate if provided
        if let Some(ref cert_path) = config.tls_cert_path {
            let cert_pem = std::fs::read(cert_path).map_err(|e| {
                GhostError::Config(format!("Failed to read TLS cert at {:?}: {}", cert_path, e))
            })?;
            let cert = reqwest::Certificate::from_pem(&cert_pem)
                .map_err(|e| GhostError::Config(format!("Invalid TLS cert: {}", e)))?;
            client_builder = client_builder.add_root_certificate(cert);
        }

        let client = client_builder
            .build()
            .map_err(|e| GhostError::Internal(format!("Failed to create HTTP client: {}", e)))?;

        // Create circuit breaker for this RPC client
        let circuit_breaker = Arc::new(CircuitBreaker::new(
            format!("bitcoin_rpc_{}", config.host),
            CircuitBreakerConfig::default(),
        ));

        Ok(Self {
            client,
            url,
            auth,
            id_counter: AtomicU64::new(1),
            last_known_height: AtomicU64::new(0),
            last_success_ts: AtomicU64::new(0),
            circuit_breaker,
            retry_config,
            network: BitcoinNetwork::Mainnet,
        })
    }

    /// Set the Bitcoin network for network-aware validation
    pub fn set_network(&mut self, network: BitcoinNetwork) {
        self.network = network;
    }

    /// Get a reference to the circuit breaker for manual control
    /// Record that Ghost Core just answered.
    fn mark_rpc_success(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.last_success_ts.store(now, Ordering::Relaxed);
    }

    /// Liveness of Ghost Core as `(reachable, seconds since it last answered)`.
    ///
    /// `reachable` is false until a call has actually succeeded — an unexercised client is not a
    /// healthy one — and false again once answers go `stale_after` seconds cold. Staleness rather
    /// than error-counting, because the failure that matters is silence: on 2026-08-01 a node's
    /// Core died and the node kept reporting health because nothing was asking whether it was
    /// still there.
    pub fn core_liveness(&self, stale_after: u64) -> (bool, u64) {
        let last = self.last_success_ts.load(Ordering::Relaxed);
        if last == 0 {
            return (false, u64::MAX);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let age = now.saturating_sub(last);
        (age <= stale_after, age)
    }

    pub fn circuit_breaker(&self) -> &CircuitBreaker {
        &self.circuit_breaker
    }

    /// Make an RPC call with retry and circuit breaker protection
    async fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: Vec<Value>,
    ) -> GhostResult<T> {
        self.call_with_options(method, params, &self.retry_config, None)
            .await
    }

    /// Make an RPC call with per-operation timeout
    ///
    /// M-CFG-1 FIX: Allows specifying a custom timeout for operations that may take
    /// longer than the default (e.g., getblocktemplate during high mempool activity).
    async fn call_with_timeout<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: Vec<Value>,
        timeout: Duration,
    ) -> GhostResult<T> {
        self.call_with_options(method, params, &self.retry_config, Some(timeout))
            .await
    }

    /// Make an RPC call with custom retry configuration
    #[allow(dead_code)]
    async fn call_with_retry<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: Vec<Value>,
        retry_config: &RpcRetryConfig,
    ) -> GhostResult<T> {
        self.call_with_options(method, params, retry_config, None)
            .await
    }

    /// Make an RPC call with full options (retry config and per-operation timeout)
    ///
    /// M-CFG-1 FIX: Per-operation timeout configuration for different RPC operations
    async fn call_with_options<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: Vec<Value>,
        retry_config: &RpcRetryConfig,
        operation_timeout: Option<Duration>,
    ) -> GhostResult<T> {
        let mut attempt = 0;
        let mut backoff = retry_config.initial_backoff;

        loop {
            // Check circuit breaker first
            if !self.circuit_breaker.is_allowed() {
                return Err(GhostError::Rpc(
                    "Circuit breaker open - Ghost Core RPC unavailable".to_string(),
                ));
            }

            match self
                .call_inner_with_timeout(method, &params, operation_timeout)
                .await
            {
                Ok(result) => {
                    self.mark_rpc_success();
                    self.mark_rpc_success();
                    self.circuit_breaker.record_success();
                    return Ok(result);
                }
                Err(e) => {
                    self.circuit_breaker.record_failure();

                    // Check if we should retry
                    if attempt < retry_config.max_retries && is_retryable_error(&e) {
                        attempt += 1;
                        warn!(
                            method,
                            attempt,
                            max_retries = retry_config.max_retries,
                            backoff_ms = backoff.as_millis(),
                            error = %e,
                            "RPC call failed, retrying"
                        );
                        sleep(backoff).await;
                        backoff = Duration::from_millis(
                            ((backoff.as_millis() as f64 * retry_config.backoff_multiplier) as u64)
                                .min(retry_config.max_backoff.as_millis() as u64),
                        );
                    } else {
                        if attempt > 0 {
                            warn!(
                                method,
                                attempts = attempt + 1,
                                "RPC call failed after retries"
                            );
                        }
                        return Err(e);
                    }
                }
            }
        }
    }

    /// Internal call without retry logic
    #[allow(dead_code)]
    async fn call_inner<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: &[Value],
    ) -> GhostResult<T> {
        self.call_inner_with_timeout(method, params, None).await
    }

    /// Internal call with optional per-operation timeout
    ///
    /// M-CFG-1 FIX: Supports per-operation timeout override
    async fn call_inner_with_timeout<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: &[Value],
        timeout: Option<Duration>,
    ) -> GhostResult<T> {
        let id = self.id_counter.fetch_add(1, Ordering::SeqCst);

        let request = json!({
            "jsonrpc": "1.0",
            "id": id,
            "method": method,
            "params": params,
        });

        let mut request_builder = self
            .client
            .post(&self.url)
            .header("Authorization", format!("Basic {}", self.auth.as_str()))
            .json(&request);

        // M-CFG-1 FIX: Apply per-operation timeout if specified
        if let Some(op_timeout) = timeout {
            request_builder = request_builder.timeout(op_timeout);
        }

        let response = request_builder
            .send()
            .await
            .map_err(|e| GhostError::Rpc(format!("Request failed: {}", e)))?;

        let rpc_response: RpcResponse<T> = response
            .json()
            .await
            .map_err(|e| GhostError::Rpc(format!("Failed to parse response: {}", e)))?;

        if let Some(error) = rpc_response.error {
            return Err(GhostError::Rpc(format!(
                "RPC error {}: {}",
                error.code, error.message
            )));
        }

        rpc_response
            .result
            .ok_or_else(|| GhostError::Rpc("Empty response".to_string()))
    }

    /// Update last known height (call after successful blockchain queries)
    fn update_height(&self, height: u64) {
        self.last_known_height.store(height, Ordering::SeqCst);
    }

    /// Get last known height
    pub fn last_known_height(&self) -> u64 {
        self.last_known_height.load(Ordering::SeqCst)
    }

    /// Get blockchain info
    pub async fn get_blockchain_info(&self) -> GhostResult<BlockchainInfo> {
        let info: BlockchainInfo = self.call("getblockchaininfo", vec![]).await?;
        self.update_height(info.blocks);
        Ok(info)
    }

    /// Get best block hash
    pub async fn get_best_block_hash(&self) -> GhostResult<String> {
        self.call("getbestblockhash", vec![]).await
    }

    /// Get Stage-1 mempool filtering counters (cumulative since ghostd start).
    ///
    /// Surfaces the tier-policy and mempool-reaper rejection totals that
    /// `getmempoolinfo` does not carry. Available only on ghostd builds that
    /// expose the `getmempoolfilterstats` RPC; callers should degrade
    /// gracefully to zeros when the call errors on older nodes.
    pub async fn get_mempool_filter_stats(&self) -> GhostResult<MempoolFilterStats> {
        self.call("getmempoolfilterstats", vec![]).await
    }

    /// Get block by hash
    pub async fn get_block(&self, hash: &str, verbosity: u8) -> GhostResult<Value> {
        self.call("getblock", vec![json!(hash), json!(verbosity)])
            .await
    }

    /// Address-index balance for a single address (`getaddressbalance`).
    /// Only available on nodes running with `-addressindex`; callers should
    /// surface the RPC error as "index not enabled" rather than a hard failure.
    pub async fn get_address_balance(&self, address: &str) -> GhostResult<Value> {
        self.call("getaddressbalance", vec![json!(address)]).await
    }

    /// Address-index UTXOs for a single address (`getaddressutxos`).
    pub async fn get_address_utxos(&self, address: &str) -> GhostResult<Value> {
        self.call("getaddressutxos", vec![json!(address)]).await
    }

    /// Address-index txids touching a single address (`getaddresstxids`).
    pub async fn get_address_txids(&self, address: &str) -> GhostResult<Value> {
        self.call("getaddresstxids", vec![json!(address)]).await
    }

    /// Scan a descriptor/xpub against the address index (`scanaddressindex`),
    /// aggregating balance, UTXOs and history across every derived address.
    /// `range` is an optional single number or `[begin, end]` gap limit.
    pub async fn scan_address_index(
        &self,
        descriptor: &str,
        range: Option<Value>,
    ) -> GhostResult<Value> {
        let mut params = vec![json!(descriptor)];
        if let Some(r) = range {
            params.push(r);
        }
        self.call("scanaddressindex", params).await
    }

    /// Get block header
    pub async fn get_block_header(&self, hash: &str) -> GhostResult<BlockHeader> {
        self.call("getblockheader", vec![json!(hash), json!(true)])
            .await
    }

    /// Get block count (height)
    pub async fn get_block_count(&self) -> GhostResult<u64> {
        let height: u64 = self.call("getblockcount", vec![]).await?;
        self.update_height(height);
        Ok(height)
    }

    /// Get network difficulty
    pub async fn get_difficulty(&self) -> GhostResult<f64> {
        self.call("getdifficulty", vec![]).await
    }

    /// Get block template for mining (with validation)
    ///
    /// Validates the template before returning to prevent malicious/malformed templates.
    ///
    /// M-CFG-1 FIX: Uses a longer timeout (60s) for getblocktemplate since this operation
    /// can take significant time during high mempool activity.
    pub async fn get_block_template(&self, rules: Vec<&str>) -> GhostResult<BlockTemplate> {
        let params = json!({
            "rules": rules,
            "capabilities": ["coinbasetxn", "workid", "coinbase/append"],
        });
        // M-CFG-1 FIX: Use 60 second timeout for getblocktemplate
        let template: BlockTemplate = self
            .call_with_timeout("getblocktemplate", vec![params], Duration::from_secs(60))
            .await?;

        // Validate template before returning
        let current_height = {
            let h = self.last_known_height.load(Ordering::SeqCst);
            if h > 0 {
                Some(h)
            } else {
                None
            }
        };

        validate_block_template(&template, current_height, Some(&self.network)).map_err(|e| {
            tracing::error!("Block template validation failed: {}", e);
            GhostError::InvalidBlockTemplate(e.to_string())
        })?;

        // Update height from template
        self.update_height(template.height);

        Ok(template)
    }

    /// Get block template without validation (use with caution)
    ///
    /// Only use this if you're doing your own validation.
    ///
    /// M-CFG-1 FIX: Uses a longer timeout (60s) for getblocktemplate.
    pub async fn get_block_template_unchecked(
        &self,
        rules: Vec<&str>,
    ) -> GhostResult<BlockTemplate> {
        let params = json!({
            "rules": rules,
            "capabilities": ["coinbasetxn", "workid", "coinbase/append"],
        });
        // M-CFG-1 FIX: Use 60 second timeout for getblocktemplate
        self.call_with_timeout("getblocktemplate", vec![params], Duration::from_secs(60))
            .await
    }

    /// Submit a block
    ///
    /// Returns:
    /// - Ok(None) if block was accepted
    /// - Ok(Some(reason)) if block was rejected with a specific reason
    /// - Err if RPC call failed
    pub async fn submit_block(&self, block_hex: &str) -> GhostResult<Option<String>> {
        // Bitcoin Core returns null on success, so we need special handling
        // for this method (null is not an error, it means accepted)
        self.call_nullable("submitblock", vec![json!(block_hex)])
            .await
    }

    /// Make an RPC call that can return null as a valid success response
    async fn call_nullable<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: Vec<Value>,
    ) -> GhostResult<Option<T>> {
        // Check circuit breaker first
        if !self.circuit_breaker.is_allowed() {
            return Err(GhostError::Rpc(
                "Circuit breaker open - Ghost Core RPC unavailable".to_string(),
            ));
        }

        let id = self.id_counter.fetch_add(1, Ordering::SeqCst);
        let request = json!({
            "jsonrpc": "1.0",
            "id": id,
            "method": method,
            "params": params,
        });

        let response = self
            .client
            .post(&self.url)
            .header("Authorization", format!("Basic {}", self.auth.as_str()))
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                self.circuit_breaker.record_failure();
                GhostError::Rpc(format!("Request failed: {}", e))
            })?;

        let rpc_response: RpcResponse<T> = response.json().await.map_err(|e| {
            self.circuit_breaker.record_failure();
            GhostError::Rpc(format!("Failed to parse response: {}", e))
        })?;

        if let Some(error) = rpc_response.error {
            self.circuit_breaker.record_failure();
            return Err(GhostError::Rpc(format!(
                "RPC error {}: {}",
                error.code, error.message
            )));
        }

        // For nullable methods, None is a valid success response
        self.circuit_breaker.record_success();
        Ok(rpc_response.result)
    }

    /// Get raw mempool
    pub async fn get_raw_mempool(&self, verbose: bool) -> GhostResult<Value> {
        self.call("getrawmempool", vec![json!(verbose)]).await
    }

    /// Get mempool entry
    pub async fn get_mempool_entry(&self, txid: &str) -> GhostResult<MempoolEntry> {
        self.call("getmempoolentry", vec![json!(txid)]).await
    }

    /// Get raw transaction
    pub async fn get_raw_transaction(&self, txid: &str, verbose: bool) -> GhostResult<Value> {
        self.call("getrawtransaction", vec![json!(txid), json!(verbose)])
            .await
    }

    /// Get wallet transaction (for transactions in the wallet, does not require -txindex)
    pub async fn get_transaction(&self, txid: &str) -> GhostResult<Value> {
        self.call("gettransaction", vec![json!(txid), json!(true)])
            .await
    }

    /// Send raw transaction
    pub async fn send_raw_transaction(&self, tx_hex: &str) -> GhostResult<String> {
        self.call("sendrawtransaction", vec![json!(tx_hex)]).await
    }

    /// Decode raw transaction
    pub async fn decode_raw_transaction(&self, tx_hex: &str) -> GhostResult<Value> {
        self.call("decoderawtransaction", vec![json!(tx_hex)]).await
    }

    /// Get network info
    pub async fn get_network_info(&self) -> GhostResult<NetworkInfo> {
        self.call("getnetworkinfo", vec![]).await
    }

    /// Get Tor mode status
    pub async fn get_tor_mode(&self) -> GhostResult<TorModeStatus> {
        self.call("gettormode", vec![]).await
    }

    /// Get mining info
    pub async fn get_mining_info(&self) -> GhostResult<MiningInfo> {
        self.call("getmininginfo", vec![]).await
    }

    /// Test mempool accept
    pub async fn test_mempool_accept(
        &self,
        tx_hexes: Vec<&str>,
    ) -> GhostResult<Vec<MempoolAcceptResult>> {
        self.call("testmempoolaccept", vec![json!(tx_hexes)]).await
    }

    /// Estimate smart fee
    pub async fn estimate_smart_fee(&self, conf_target: u32) -> GhostResult<FeeEstimate> {
        self.call("estimatesmartfee", vec![json!(conf_target)])
            .await
    }

    /// Get block hash by height
    pub async fn get_block_hash(&self, height: u64) -> GhostResult<String> {
        self.call("getblockhash", vec![json!(height)]).await
    }

    /// Get UTXO info
    pub async fn get_tx_out(
        &self,
        txid: &str,
        vout: u32,
        include_mempool: bool,
    ) -> GhostResult<Option<TxOut>> {
        self.call(
            "gettxout",
            vec![json!(txid), json!(vout), json!(include_mempool)],
        )
        .await
    }

    /// Validate an address (LEGACY - does not check network)
    ///
    /// WARNING: This only validates address format, not network compatibility.
    /// For production use, prefer `validate_address_for_network()` which also
    /// verifies the address matches the expected Bitcoin network (H-BTC-2).
    pub async fn validate_address(&self, address: &str) -> GhostResult<AddressValidation> {
        self.call("validateaddress", vec![json!(address)]).await
    }

    /// H-BTC-2: Validate an address for a specific Bitcoin network
    ///
    /// This method validates that an address:
    /// 1. Has valid format (calls Bitcoin Core validateaddress)
    /// 2. Matches the expected network (mainnet, testnet, signet, regtest)
    ///
    /// This prevents accidentally using testnet addresses on mainnet or vice versa,
    /// which would result in unspendable outputs and permanent fund loss.
    ///
    /// # Arguments
    /// * `address` - The Bitcoin address to validate
    /// * `expected_network` - The network the address should belong to
    ///
    /// # Returns
    /// * `Ok(AddressValidation)` if the address is valid for the expected network
    /// * `Err(GhostError::InvalidAddress)` if the address is invalid or wrong network
    pub async fn validate_address_for_network(
        &self,
        address: &str,
        expected_network: BitcoinNetwork,
    ) -> GhostResult<AddressValidation> {
        // First validate the address format via Bitcoin Core
        let validation = self.validate_address(address).await?;

        if !validation.isvalid {
            return Err(GhostError::InvalidAddress(format!(
                "Address '{}' is not a valid Bitcoin address",
                address
            )));
        }

        // H-BTC-2: Check network prefix matches expected network
        // Bech32 prefixes: bc1 (mainnet), tb1 (testnet/signet), bcrt1 (regtest)
        // Legacy prefixes: 1/3 (mainnet), m/n/2 (testnet/signet/regtest)
        let address_network = Self::detect_address_network(address);

        if address_network != expected_network {
            return Err(GhostError::InvalidAddress(format!(
                "H-BTC-2 SECURITY: Address '{}' is for {:?} but expected {:?}. \
                 Using wrong-network addresses would create unspendable outputs!",
                address, address_network, expected_network
            )));
        }

        Ok(validation)
    }

    /// H-BTC-2: Detect network from address prefix
    ///
    /// Determines which Bitcoin network an address belongs to based on its prefix:
    /// - bc1/1/3 = Mainnet
    /// - tb1/m/n/2 = Testnet/Signet
    /// - bcrt1 = Regtest
    fn detect_address_network(address: &str) -> BitcoinNetwork {
        // Bech32 addresses (most common)
        if address.starts_with("bc1") {
            BitcoinNetwork::Mainnet
        } else if address.starts_with("bcrt1") {
            BitcoinNetwork::Regtest
        } else if address.starts_with("tb1") {
            // Could be testnet or signet - default to Signet as it's more commonly used
            BitcoinNetwork::Signet
        // Legacy P2PKH addresses
        } else if address.starts_with('1') || address.starts_with('3') {
            BitcoinNetwork::Mainnet
        } else if address.starts_with('m') || address.starts_with('n') || address.starts_with('2') {
            // Testnet/signet legacy addresses
            BitcoinNetwork::Signet
        } else {
            // Unknown prefix - assume mainnet to be safe (will fail validation)
            BitcoinNetwork::Mainnet
        }
    }

    /// Get address info (for wallet addresses)
    pub async fn get_address_info(&self, address: &str) -> GhostResult<Value> {
        self.call("getaddressinfo", vec![json!(address)]).await
    }

    /// List unspent outputs (requires wallet)
    pub async fn list_unspent(
        &self,
        min_conf: u32,
        max_conf: u32,
        addresses: Vec<&str>,
    ) -> GhostResult<Vec<UnspentOutput>> {
        self.call(
            "listunspent",
            vec![json!(min_conf), json!(max_conf), json!(addresses)],
        )
        .await
    }

    /// Scan the chain UTXO set for outputs matching one or more
    /// scan objects. Unlike `listunspent`, this does NOT require a
    /// loaded bitcoind wallet — it walks the full UTXO set on each
    /// call. Useful for wallets that derive their own addresses and
    /// just need bitcoind for chain access.
    ///
    /// `scan_objects` is a list of descriptors, e.g. `addr(<addr>)`
    /// or `tr(<xpub>/*)`. Bitcoin Core caps the count per call at
    /// 10000 — callers above that should chunk.
    ///
    /// Bitcoin Core: a scantxoutset call with N=1000 addresses on
    /// mainnet currently takes ~5-15s wall-clock; signet/regtest
    /// finishes in well under 1s. Surface this latency in any UI.
    pub async fn scan_tx_out_set(
        &self,
        scan_objects: Vec<&str>,
    ) -> GhostResult<ScanTxOutSetResult> {
        self.call("scantxoutset", vec![json!("start"), json!(scan_objects)])
            .await
    }

    /// Create raw transaction
    pub async fn create_raw_transaction(
        &self,
        inputs: Vec<TxInput>,
        outputs: &serde_json::Map<String, Value>,
    ) -> GhostResult<String> {
        self.call("createrawtransaction", vec![json!(inputs), json!(outputs)])
            .await
    }

    /// Sign raw transaction with wallet
    pub async fn sign_raw_transaction_with_wallet(
        &self,
        tx_hex: &str,
    ) -> GhostResult<SignedTransaction> {
        self.call("signrawtransactionwithwallet", vec![json!(tx_hex)])
            .await
    }

    /// Get wallet balance in satoshis
    pub async fn get_balance(&self) -> GhostResult<u64> {
        let btc: f64 = self.call("getbalance", vec![]).await?;
        Ok((btc * 100_000_000.0).round() as u64)
    }

    /// Get a new address from the wallet
    pub async fn get_new_address(&self) -> GhostResult<String> {
        self.call("getnewaddress", vec![]).await
    }

    /// Call an arbitrary RPC method (for methods not wrapped with typed helpers)
    pub async fn call_raw(&self, method: &str, params: Vec<Value>) -> GhostResult<Value> {
        self.call(method, params).await
    }

    /// Get chain tips
    pub async fn get_chain_tips(&self) -> GhostResult<Vec<ChainTip>> {
        self.call("getchaintips", vec![]).await
    }

    /// Verify chain
    pub async fn verify_chain(&self, check_level: u32, num_blocks: u32) -> GhostResult<bool> {
        self.call("verifychain", vec![json!(check_level), json!(num_blocks)])
            .await
    }

    /// Get mempool info
    pub async fn get_mempool_info(&self) -> GhostResult<MempoolInfo> {
        self.call("getmempoolinfo", vec![]).await
    }

    // ============================================================
    // Ghost Mode RPC Methods
    // ============================================================

    /// Set ghost mode on the node
    ///
    /// When enabled, the node will not request, relay, or announce unconfirmed transactions.
    pub async fn set_ghost_mode(&self, enable: bool) -> GhostResult<GhostModeResponse> {
        self.call("setghostmode", vec![json!(enable)]).await
    }

    /// Get current ghost mode state
    pub async fn get_ghost_mode(&self) -> GhostResult<GhostModeResponse> {
        self.call("getghostmode", vec![]).await
    }

    /// Set ghost mode local egress on the node
    ///
    /// Only meaningful while ghost mode is enabled. When on, the node still
    /// announces and serves its own (locally-submitted) transactions so a
    /// connected wallet can reach miners; peer-received txs stay suppressed.
    pub async fn set_ghost_mode_local_egress(
        &self,
        enable: bool,
    ) -> GhostResult<GhostModeResponse> {
        self.call("setghostmodelocalegress", vec![json!(enable)])
            .await
    }

    /// Get current ghost mode local egress state
    pub async fn get_ghost_mode_local_egress(&self) -> GhostResult<GhostModeResponse> {
        self.call("getghostmodelocalegress", vec![]).await
    }

    // ============================================================
    // Ghost Haze RPC Methods
    // ============================================================

    /// Get the current Ghost Haze operating status.
    ///
    /// Surfaces the Exorcism state and storage statistics — including
    /// `bytes_stripped` (the arbitrary-content-kept-off-disk metric) and the
    /// structural archive size — that `getblockchaininfo` does not expose.
    pub async fn get_haze_status(&self) -> GhostResult<HazeRpcStatus> {
        self.call("gethazestatus", vec![]).await
    }

    /// Generate the Legal Compliance Packet proving this node does not persist
    /// hazeable content. Only available on hazed nodes; the RPC returns an error
    /// on Full Archive / non-hazed nodes (surfaced here as `GhostError::Rpc`).
    ///
    /// Returned as a raw JSON value because the packet is a court-ready document
    /// whose shape is defined by ghostd and forwarded verbatim to the dashboard.
    pub async fn get_legal_packet(&self) -> GhostResult<Value> {
        self.call("getlegalpacket", vec![]).await
    }

    /// Get the Ghost Haze signed-checkpoint status (serving / downloading /
    /// neither), the trust anchor for a hazed node's UTXO snapshot.
    pub async fn get_checkpoint_status(&self) -> GhostResult<Value> {
        self.call("getcheckpointstatus", vec![]).await
    }

    // ============================================================
    // Ghost-Core Specific RPC Methods
    // ============================================================

    /// Get the wallet's Ghost ID (Silent Payment address)
    pub async fn get_silent_payment_address(&self) -> GhostResult<SilentPaymentAddress> {
        self.call("getsilentpaymentaddress", vec![]).await
    }

    /// Derive a one-time P2TR address from a Ghost ID
    pub async fn derive_silent_payment_address(
        &self,
        ghost_id: &str,
        index: u32,
        nonce: u16,
    ) -> GhostResult<DerivedAddress> {
        self.call(
            "derivesilentpaymentaddress",
            vec![json!(ghost_id), json!(index), json!(nonce)],
        )
        .await
    }

    /// Check if a transaction output belongs to this wallet via Silent Payment
    pub async fn check_silent_payment(
        &self,
        txid: &str,
        vout: u32,
        ephemeral_pubkey: &str,
    ) -> GhostResult<SilentPaymentCheck> {
        self.call(
            "checksilentpayment",
            vec![json!(txid), json!(vout), json!(ephemeral_pubkey)],
        )
        .await
    }

    /// Parse Ghost Lock OP_RETURN data
    pub async fn parse_ghost_op_return(&self, data_hex: &str) -> GhostResult<GhostOpReturnData> {
        self.call("parseghostopreturn", vec![json!(data_hex)]).await
    }

    /// Rescan blockchain for Silent Payment outputs
    pub async fn rescan_silent_payments(
        &self,
        start_height: Option<u64>,
        stop_height: Option<u64>,
    ) -> GhostResult<RescanResult> {
        let params = match (start_height, stop_height) {
            (Some(start), Some(stop)) => vec![json!(start), json!(stop)],
            (Some(start), None) => vec![json!(start)],
            _ => vec![],
        };
        self.call("rescansilentpayments", params).await
    }

    /// Get Silent Payment scanning statistics
    pub async fn get_silent_payment_stats(&self) -> GhostResult<SilentPaymentStats> {
        self.call("getsilentpaymentstats", vec![]).await
    }

    /// Create a Wraith Phase 1 (Split) transaction
    pub async fn create_wraith_tx(
        &self,
        inputs: Vec<WraithInputRpc>,
        intermediate_addresses: Vec<Vec<String>>,
        session_id: &str,
        denomination: &str,
    ) -> GhostResult<WraithTxResult> {
        self.call(
            "createwraithtx",
            vec![
                json!(inputs),
                json!(intermediate_addresses),
                json!(session_id),
                json!(denomination),
            ],
        )
        .await
    }

    /// Create a Wraith Phase 2 (Merge) transaction
    pub async fn create_wraith_final_tx(
        &self,
        intermediate_inputs: Vec<WraithInputRpc>,
        final_addresses: Vec<String>,
        session_id: &str,
    ) -> GhostResult<WraithTxResult> {
        self.call(
            "createwraithfinaltx",
            vec![
                json!(intermediate_inputs),
                json!(final_addresses),
                json!(session_id),
            ],
        )
        .await
    }

    /// Parse Wraith transaction metadata
    pub async fn parse_wraith_tx(&self, txid: &str) -> GhostResult<WraithTxInfo> {
        self.call("parsewraithtx", vec![json!(txid)]).await
    }

    /// Shuffle transaction outputs deterministically
    pub async fn shuffle_outputs(&self, tx_hex: &str, seed: &str) -> GhostResult<String> {
        self.call("shuffleoutputs", vec![json!(tx_hex), json!(seed)])
            .await
    }

    /// Create a reconciliation batch transaction
    pub async fn create_reconciliation_tx(
        &self,
        inputs: Vec<ReconciliationInputRpc>,
        outputs: Vec<ReconciliationOutputRpc>,
        epoch_id: u32,
        state_root: &str,
        treasury_address: Option<&str>,
        treasury_amount: Option<u64>,
    ) -> GhostResult<ReconciliationTxResult> {
        let mut params = vec![
            json!(inputs),
            json!(outputs),
            json!(epoch_id),
            json!(state_root),
        ];
        if let Some(addr) = treasury_address {
            params.push(json!(addr));
            params.push(json!(treasury_amount.unwrap_or(0)));
        }
        self.call("createreconciliationtx", params).await
    }

    /// Create a PSBT for batch signing coordination
    pub async fn coordinate_batch_signing(
        &self,
        inputs: Vec<ReconciliationInputRpc>,
        outputs: Vec<ReconciliationOutputRpc>,
    ) -> GhostResult<String> {
        self.call(
            "coordinatebatchsigning",
            vec![json!(inputs), json!(outputs)],
        )
        .await
    }

    /// Combine multiple PSBTs from batch signing participants
    pub async fn combine_batch_psbt(&self, psbts: Vec<String>) -> GhostResult<CombinedPsbtResult> {
        self.call("combinebatchpsbt", vec![json!(psbts)]).await
    }

    /// Estimate fee for a batch reconciliation transaction
    pub async fn estimate_batch_fee(
        &self,
        input_count: u32,
        output_count: u32,
        conf_target: u32,
    ) -> GhostResult<BatchFeeEstimate> {
        self.call(
            "estimatebatchfee",
            vec![json!(input_count), json!(output_count), json!(conf_target)],
        )
        .await
    }

    /// Derive reconciliation output addresses from Ghost IDs
    pub async fn derive_reconciliation_outputs(
        &self,
        ghost_ids: Vec<String>,
        amounts: Vec<u64>,
    ) -> GhostResult<Vec<DerivedAddress>> {
        self.call(
            "derivereconciliationoutputs",
            vec![json!(ghost_ids), json!(amounts)],
        )
        .await
    }
}

// ============================================================
// Response Types
// ============================================================

/// RPC response wrapper
#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
    #[allow(dead_code)]
    id: u64,
}

/// RPC error
#[derive(Debug, Deserialize)]
struct RpcError {
    code: i32,
    message: String,
}

/// Blockchain info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainInfo {
    pub chain: String,
    pub blocks: u64,
    pub headers: u64,
    pub bestblockhash: String,
    pub difficulty: f64,
    pub time: u64,
    pub mediantime: u64,
    pub verificationprogress: f64,
    pub initialblockdownload: bool,
    pub chainwork: String,
    pub size_on_disk: u64,
    pub pruned: bool,
    #[serde(default)]
    pub hazed: bool,
    // Additional fields that may be present in newer Bitcoin Core versions
    #[serde(default)]
    pub bits: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub signet_challenge: Option<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// Stage-1 mempool filtering counters, as returned by ghostd's
/// `getmempoolfilterstats` RPC. All counts are cumulative since ghostd start
/// and reset on daemon restart.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MempoolFilterStats {
    /// Transactions rejected by the mempool Reaper (dead-code detection).
    #[serde(default)]
    pub reaper_rejected_txs: u64,
    /// Total vbytes of transactions rejected by the mempool Reaper.
    #[serde(default)]
    pub reaper_rejected_vbytes: u64,
    /// Transactions rejected by tier fee-policy enforcement.
    #[serde(default)]
    pub tier_rejected_txs: u64,
    /// Total vbytes of transactions rejected by tier fee-policy enforcement.
    #[serde(default)]
    pub tier_rejected_vbytes: u64,
}

/// Ghost Haze operating status, as returned by ghostd's `gethazestatus` RPC.
///
/// Distinct from the dashboard-facing `HazeStatus` response (which merges these
/// fields with `getblockchaininfo`); this mirrors ghostd's raw RPC contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HazeRpcStatus {
    /// Operating mode: "hazed" or "full_archive".
    pub mode: String,
    /// Whether Ghost Exorcism is stripping incoming blocks.
    #[serde(default)]
    pub exorcism_active: bool,
    /// Total blocks processed through Exorcism.
    #[serde(default)]
    pub blocks_stripped: i64,
    /// Total bytes stripped from blocks (arbitrary content kept off disk).
    #[serde(default)]
    pub bytes_stripped: i64,
    /// Current chain tip height.
    #[serde(default)]
    pub chain_tip: i64,
    /// Approximate structural archive size in GB (sum of `.gsb` files).
    #[serde(default)]
    pub storage_gb: f64,
}

/// Block header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub hash: String,
    pub confirmations: i64,
    pub height: u64,
    pub version: u32,
    #[serde(rename = "versionHex")]
    pub version_hex: Option<String>,
    pub merkleroot: String,
    pub time: u64,
    pub mediantime: u64,
    pub nonce: u64,
    pub bits: String,
    pub difficulty: f64,
    pub chainwork: String,
    #[serde(rename = "nTx")]
    pub n_tx: u64,
    pub previousblockhash: Option<String>,
    pub nextblockhash: Option<String>,
}

/// Block template from getblocktemplate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockTemplate {
    pub version: u32,
    pub rules: Vec<String>,
    pub vbavailable: std::collections::HashMap<String, u32>,
    pub vbrequired: u32,
    pub previousblockhash: String,
    pub transactions: Vec<TemplateTransaction>,
    /// Coinbase auxiliary data (bounded during validation)
    pub coinbaseaux: std::collections::HashMap<String, String>,
    pub coinbasevalue: u64,
    pub longpollid: Option<String>,
    pub target: String,
    pub mintime: u64,
    pub mutable: Vec<String>,
    pub noncerange: String,
    pub sigoplimit: u64,
    pub sizelimit: u64,
    pub weightlimit: u64,
    pub curtime: u64,
    pub bits: String,
    pub height: u64,
    #[serde(default)]
    pub default_witness_commitment: Option<String>,
}

/// Transaction in block template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateTransaction {
    pub data: String,
    pub txid: String,
    pub hash: String,
    pub depends: Vec<u32>,
    pub fee: u64,
    pub sigops: u64,
    pub weight: u64,
}

/// Mempool entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolEntry {
    pub vsize: u64,
    pub weight: u64,
    pub fee: f64,
    pub modifiedfee: f64,
    pub time: u64,
    pub height: u64,
    pub descendantcount: u64,
    pub descendantsize: u64,
    pub descendantfees: u64,
    pub ancestorcount: u64,
    pub ancestorsize: u64,
    pub ancestorfees: u64,
    pub wtxid: String,
    pub fees: MempoolFees,
    pub depends: Vec<String>,
    pub spentby: Vec<String>,
    #[serde(rename = "bip125-replaceable")]
    pub bip125_replaceable: bool,
}

/// Mempool fees
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolFees {
    pub base: f64,
    pub modified: f64,
    pub ancestor: f64,
    pub descendant: f64,
}

/// Network info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub version: u64,
    pub subversion: String,
    pub protocolversion: u64,
    pub localservices: String,
    pub localservicesnames: Vec<String>,
    pub localrelay: bool,
    pub timeoffset: i64,
    pub networkactive: bool,
    #[serde(default)]
    pub tormode: bool,
    pub connections: u64,
    pub connections_in: u64,
    pub connections_out: u64,
    pub networks: Vec<NetworkType>,
    pub relayfee: f64,
    pub incrementalfee: f64,
    pub localaddresses: Vec<LocalAddress>,
    pub warnings: String,
}

/// Tor mode status from gettormode RPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TorModeStatus {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub onion_address: Option<String>,
    pub embedded_tor: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tor_pid: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tor_running: Option<bool>,
}

/// Network type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkType {
    pub name: String,
    pub limited: bool,
    pub reachable: bool,
    pub proxy: String,
    pub proxy_randomize_credentials: bool,
}

/// Local address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalAddress {
    pub address: String,
    pub port: u16,
    pub score: u64,
}

/// Mining info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningInfo {
    pub blocks: u64,
    pub difficulty: f64,
    pub networkhashps: f64,
    pub pooledtx: u64,
    pub chain: String,
    #[serde(default)]
    pub warnings: serde_json::Value,
}

/// Mempool accept result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolAcceptResult {
    pub txid: String,
    pub wtxid: String,
    pub allowed: Option<bool>,
    #[serde(rename = "reject-reason")]
    pub reject_reason: Option<String>,
    pub vsize: Option<u64>,
    pub fees: Option<MempoolAcceptFees>,
}

/// Mempool accept fees
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolAcceptFees {
    pub base: f64,
}

/// Fee estimate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimate {
    pub feerate: Option<f64>,
    pub errors: Option<Vec<String>>,
    pub blocks: u64,
}

/// Transaction output info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOut {
    pub bestblock: String,
    pub confirmations: i64,
    pub value: f64,
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: ScriptPubKey,
    pub coinbase: bool,
}

/// Script pubkey info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptPubKey {
    pub asm: String,
    pub desc: Option<String>,
    pub hex: String,
    pub address: Option<String>,
    #[serde(rename = "type")]
    pub script_type: String,
}

/// Address validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressValidation {
    pub isvalid: bool,
    pub address: Option<String>,
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: Option<String>,
    pub isscript: Option<bool>,
    pub iswitness: Option<bool>,
    pub witness_version: Option<u32>,
    pub witness_program: Option<String>,
}

/// H-BTC-2: Detect which Bitcoin network an address belongs to based on its prefix
///
/// Address prefixes:
/// - Mainnet Bech32: bc1 (native segwit)
/// - Mainnet Legacy: 1 (P2PKH), 3 (P2SH)
/// - Testnet/Signet Bech32: tb1
/// - Testnet/Signet Legacy: m, n (P2PKH), 2 (P2SH)
/// - Regtest Bech32: bcrt1
/// - Regtest Legacy: m, n (P2PKH), 2 (P2SH)
///
/// Note: Testnet and Signet share the same address formats, so we return Testnet
/// for tb1/m/n/2 prefixes. For regtest-specific detection, we look for bcrt1.
pub fn detect_address_network(address: &str) -> BitcoinNetwork {
    // Bech32 addresses (native segwit)
    if address.starts_with("bc1") {
        return BitcoinNetwork::Mainnet;
    }
    if address.starts_with("bcrt1") {
        return BitcoinNetwork::Regtest;
    }
    if address.starts_with("tb1") {
        // Note: tb1 is used by both testnet and signet
        // We default to Testnet; caller should handle signet explicitly if needed
        return BitcoinNetwork::Testnet;
    }

    // Legacy addresses (P2PKH and P2SH)
    if let Some(first_char) = address.chars().next() {
        match first_char {
            // Mainnet
            '1' | '3' => return BitcoinNetwork::Mainnet,
            // Testnet/Signet/Regtest P2PKH (these share prefixes)
            'm' | 'n' => return BitcoinNetwork::Testnet,
            // Testnet/Signet/Regtest P2SH
            '2' => return BitcoinNetwork::Testnet,
            _ => {}
        }
    }

    // Default to Mainnet for unknown prefixes (will fail validation anyway)
    BitcoinNetwork::Mainnet
}

/// One row in `scantxoutset start` output. Field names match the
/// Bitcoin Core JSON exactly so deserialisation is direct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTxOutEntry {
    pub txid: String,
    pub vout: u32,
    /// Hex-encoded scriptPubKey of the output.
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: String,
    /// Descriptor that matched this output (e.g. `addr(...)#chk`).
    pub desc: String,
    /// Amount in BTC (Bitcoin Core's wire format). Convert with
    /// `(amount * 1e8).round() as u64` for sats — but be aware that
    /// f64 round-tripping is lossy beyond 2099-09 worth of sats; use
    /// the raw RPC string if you need consensus-exact values.
    pub amount: f64,
    /// Block height where the output was confirmed.
    pub height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTxOutSetResult {
    pub success: bool,
    /// Block height at which the scan was taken — useful as a
    /// cache key.
    #[serde(default)]
    pub height: u32,
    #[serde(rename = "bestblock", default)]
    pub best_block: String,
    #[serde(default)]
    pub unspents: Vec<ScanTxOutEntry>,
    #[serde(default)]
    pub total_amount: f64,
}

/// Unspent output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnspentOutput {
    pub txid: String,
    pub vout: u32,
    pub address: Option<String>,
    pub label: Option<String>,
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: String,
    pub amount: f64,
    pub confirmations: u64,
    pub spendable: bool,
    pub solvable: bool,
    pub safe: bool,
}

/// Transaction input for creating raw transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInput {
    pub txid: String,
    pub vout: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u32>,
}

/// Signed transaction result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransaction {
    pub hex: String,
    pub complete: bool,
    pub errors: Option<Vec<SigningError>>,
}

/// Signing error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningError {
    pub txid: String,
    pub vout: u32,
    #[serde(rename = "scriptSig")]
    pub script_sig: String,
    pub sequence: u64,
    pub error: String,
}

/// Chain tip info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainTip {
    pub height: u64,
    pub hash: String,
    pub branchlen: u64,
    pub status: String,
}

/// Mempool info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolInfo {
    pub loaded: bool,
    pub size: u64,
    pub bytes: u64,
    pub usage: u64,
    pub total_fee: f64,
    pub maxmempool: u64,
    pub mempoolminfee: f64,
    pub minrelaytxfee: f64,
    pub incrementalrelayfee: f64,
    pub unbroadcastcount: u64,
    pub fullrbf: bool,
}

// ============================================================
// Ghost Mode Types
// ============================================================

/// Response from setghostmode/getghostmode RPC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostModeResponse {
    pub ghost_mode: bool,
    /// Whether local egress (own-tx broadcast) is enabled. Defaults to false so
    /// responses from older ghost-core builds (which omit the field) still parse.
    #[serde(default)]
    pub ghost_mode_local_egress: bool,
}

// ============================================================
// Ghost-Core Specific Types
// ============================================================

/// Silent Payment address (Ghost ID)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SilentPaymentAddress {
    pub address: String,
    pub scan_pubkey: String,
    pub spend_pubkey: String,
}

/// Derived address from Silent Payment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivedAddress {
    pub address: String,
    pub output_pubkey: String,
    pub ephemeral_pubkey: String,
    pub tweak: String,
}

/// Result of checking Silent Payment ownership
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SilentPaymentCheck {
    pub is_mine: bool,
    pub tweak: Option<String>,
    pub amount: Option<u64>,
}

/// Parsed Ghost Lock OP_RETURN data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostOpReturnData {
    pub valid: bool,
    pub ephemeral_pubkey: Option<String>,
    pub extra_data: Option<String>,
}

/// Result of Silent Payment rescan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RescanResult {
    pub outputs_found: u64,
    pub total_amount: u64,
    pub start_height: u64,
    pub end_height: u64,
}

/// Silent Payment statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SilentPaymentStats {
    pub output_count: u64,
    pub total_balance: u64,
    pub earliest_block: Option<u64>,
    pub latest_block: Option<u64>,
}

/// Input for Wraith RPC calls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WraithInputRpc {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub script_pubkey: Option<String>,
}

/// Result of Wraith transaction creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WraithTxResult {
    pub hex: String,
    pub txid: String,
    pub complete: bool,
    pub fee: u64,
    pub input_count: u32,
    pub output_count: u32,
}

/// Wraith transaction info from parsing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WraithTxInfo {
    pub session_id: String,
    pub phase: u8,
    pub participant_count: u16,
    pub valid: bool,
}

/// Input for Reconciliation RPC calls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationInputRpc {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub lock_id: String,
}

/// Output for Reconciliation RPC calls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationOutputRpc {
    pub ghost_id: String,
    pub amount: u64,
    pub output_type: String,
}

/// Result of Reconciliation transaction creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciliationTxResult {
    pub hex: String,
    pub txid: String,
    pub complete: bool,
    pub fee: u64,
    pub state_root: String,
    pub epoch_id: u32,
}

/// Result of combining PSBTs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CombinedPsbtResult {
    pub psbt: String,
    pub complete: bool,
    pub hex: Option<String>,
}

/// Batch fee estimate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchFeeEstimate {
    pub fee: u64,
    pub fee_rate: f64,
    pub vsize: u64,
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {

    /// **The bug this exists to prevent.** A client that has never spoken to Core is not healthy,
    /// however willing it is to answer an HTTP request. `/health` used to be a hardcoded `true`,
    /// which is exactly this mistake with no way to notice it.
    #[test]
    fn a_client_that_never_reached_core_is_not_live() {
        let rpc = BitcoinRpc::new("127.0.0.1", 8332, "u", "p").expect("rpc");
        let (reachable, age) = rpc.core_liveness(120);
        assert!(!reachable, "never having succeeded is not health");
        assert_eq!(age, u64::MAX, "and the age must say never, not zero");
    }

    /// A success makes it live, and the reported age is fresh.
    #[test]
    fn a_successful_call_marks_core_live() {
        let rpc = BitcoinRpc::new("127.0.0.1", 8332, "u", "p").expect("rpc");
        rpc.mark_rpc_success();
        let (reachable, age) = rpc.core_liveness(120);
        assert!(reachable);
        assert!(age <= 1, "age should be ~0, got {age}");
    }

    /// **Silence is the failure mode that matters.** vm7's Core did not return errors — it stopped
    /// existing, and the node kept reporting health because nothing asked how long it had been
    /// since Core last answered. A zero staleness budget makes any past success already stale.
    #[test]
    fn a_stale_success_stops_counting_as_live() {
        let rpc = BitcoinRpc::new("127.0.0.1", 8332, "u", "p").expect("rpc");
        rpc.mark_rpc_success();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let (reachable, age) = rpc.core_liveness(0);
        assert!(
            !reachable,
            "a success {age}s old must not count with a 0s budget"
        );
    }

    use super::*;

    #[test]
    fn test_rpc_client_creation() {
        let client = BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap();
        assert!(client.url.contains("127.0.0.1"));
    }

    #[test]
    fn test_rpc_config_localhost_no_tls() {
        let config = RpcConfig {
            host: "127.0.0.1".into(),
            port: 8332,
            tls_enabled: false,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_rpc_config_remote_requires_tls() {
        let config = RpcConfig {
            host: "192.168.1.100".into(),
            port: 8332,
            tls_enabled: false,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_rpc_config_remote_with_tls() {
        let config = RpcConfig {
            host: "192.168.1.100".into(),
            port: 8332,
            tls_enabled: true,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_template_validation_valid() {
        // Use a valid non-zero target within acceptable range
        let template = BlockTemplate {
            version: 0x20000000,
            rules: vec!["segwit".into()],
            vbavailable: Default::default(),
            vbrequired: 0,
            previousblockhash: "0".repeat(64),
            transactions: vec![],
            coinbaseaux: Default::default(),
            coinbasevalue: 312_500_000,
            longpollid: None,
            // Valid target (not zero, within range)
            target: "00000000ffff0000000000000000000000000000000000000000000000000000".to_string(),
            mintime: 0,
            mutable: vec![],
            noncerange: "00000000ffffffff".into(),
            sigoplimit: 80000,
            sizelimit: 4000000,
            weightlimit: 4000000,
            curtime: 1700000000,
            bits: "1d00ffff".into(), // Matches the target
            height: 800000,
            default_witness_commitment: None,
        };

        assert!(validate_block_template(&template, Some(800000), None).is_ok());
    }

    #[test]
    fn test_template_validation_invalid_prev_hash() {
        let template = BlockTemplate {
            version: 0x20000000,
            rules: vec![],
            vbavailable: Default::default(),
            vbrequired: 0,
            previousblockhash: "short".into(), // Invalid
            transactions: vec![],
            coinbaseaux: Default::default(),
            coinbasevalue: 312_500_000,
            longpollid: None,
            target: "0".repeat(64),
            mintime: 0,
            mutable: vec![],
            noncerange: "00000000ffffffff".into(),
            sigoplimit: 80000,
            sizelimit: 4000000,
            weightlimit: 4000000,
            curtime: 1700000000,
            bits: "1a0377ae".into(),
            height: 800000,
            default_witness_commitment: None,
        };

        assert!(validate_block_template(&template, None, None).is_err());
    }

    #[test]
    fn test_template_validation_too_many_coinbaseaux() {
        let mut coinbaseaux = std::collections::HashMap::new();
        for i in 0..50 {
            coinbaseaux.insert(format!("key{}", i), "value".into());
        }

        let template = BlockTemplate {
            version: 0x20000000,
            rules: vec![],
            vbavailable: Default::default(),
            vbrequired: 0,
            previousblockhash: "0".repeat(64),
            transactions: vec![],
            coinbaseaux, // Too many entries
            coinbasevalue: 312_500_000,
            longpollid: None,
            target: "0".repeat(64),
            mintime: 0,
            mutable: vec![],
            noncerange: "00000000ffffffff".into(),
            sigoplimit: 80000,
            sizelimit: 4000000,
            weightlimit: 4000000,
            curtime: 1700000000,
            bits: "1a0377ae".into(),
            height: 800000,
            default_witness_commitment: None,
        };

        assert!(matches!(
            validate_block_template(&template, None, None),
            Err(TemplateValidationError::TooManyCoinbaseAux(_))
        ));
    }

    #[test]
    fn test_template_validation_height_out_of_range() {
        let template = BlockTemplate {
            version: 0x20000000,
            rules: vec![],
            vbavailable: Default::default(),
            vbrequired: 0,
            previousblockhash: "0".repeat(64),
            transactions: vec![],
            coinbaseaux: Default::default(),
            coinbasevalue: 312_500_000,
            longpollid: None,
            target: "0".repeat(64),
            mintime: 0,
            mutable: vec![],
            noncerange: "00000000ffffffff".into(),
            sigoplimit: 80000,
            sizelimit: 4000000,
            weightlimit: 4000000,
            curtime: 1700000000,
            bits: "1a0377ae".into(),
            height: 900000, // Way off from 800000
            default_witness_commitment: None,
        };

        assert!(matches!(
            validate_block_template(&template, Some(800000), None),
            Err(TemplateValidationError::HeightOutOfRange(_, _))
        ));
    }

    #[test]
    fn test_template_validation_invalid_coinbase_value() {
        let template = BlockTemplate {
            version: 0x20000000,
            rules: vec![],
            vbavailable: Default::default(),
            vbrequired: 0,
            previousblockhash: "0".repeat(64),
            transactions: vec![],
            coinbaseaux: Default::default(),
            coinbasevalue: MAX_SUPPLY_SATS + 1, // Exceeds max
            longpollid: None,
            target: "0".repeat(64),
            mintime: 0,
            mutable: vec![],
            noncerange: "00000000ffffffff".into(),
            sigoplimit: 80000,
            sizelimit: 4000000,
            weightlimit: 4000000,
            curtime: 1700000000,
            bits: "1a0377ae".into(),
            height: 800000,
            default_witness_commitment: None,
        };

        assert!(matches!(
            validate_block_template(&template, None, None),
            Err(TemplateValidationError::InvalidCoinbaseValue(_))
        ));
    }

    #[test]
    fn test_retry_config_default() {
        let config = RpcRetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_backoff, Duration::from_millis(100));
    }

    #[test]
    fn test_retry_config_critical() {
        let config = RpcRetryConfig::critical();
        assert_eq!(config.max_retries, 5);
        assert!(config.initial_backoff > Duration::from_millis(100));
    }

    #[test]
    fn test_retry_config_quick() {
        let config = RpcRetryConfig::quick();
        assert_eq!(config.max_retries, 2);
        assert!(config.initial_backoff < Duration::from_millis(100));
    }

    #[test]
    fn test_retry_config_no_retry() {
        let config = RpcRetryConfig::no_retry();
        assert_eq!(config.max_retries, 0);
    }

    #[test]
    fn test_is_retryable_error() {
        // Transient errors should be retryable
        assert!(is_retryable_error(&GhostError::Rpc(
            "Request failed: timeout".to_string()
        )));
        assert!(is_retryable_error(&GhostError::Rpc(
            "Request failed: connection refused".to_string()
        )));
        assert!(is_retryable_error(&GhostError::Rpc(
            "Request failed: connection reset by peer".to_string()
        )));

        // RPC errors (like invalid method) should NOT be retryable
        assert!(!is_retryable_error(&GhostError::Rpc(
            "RPC error -32601: Method not found".to_string()
        )));
        assert!(!is_retryable_error(&GhostError::Rpc(
            "RPC error -8: Block height out of range".to_string()
        )));

        // Other error types
        assert!(!is_retryable_error(&GhostError::Database(
            "some db error".to_string()
        )));
    }

    #[test]
    fn test_rpc_client_has_circuit_breaker() {
        let client = BitcoinRpc::new("127.0.0.1", 8332, "user", "pass").unwrap();
        // Circuit breaker should be initialized and closed
        assert!(client.circuit_breaker().is_allowed());
    }

    /// H-BTC-2: Test address network detection
    #[test]
    fn test_detect_address_network() {
        // Mainnet bech32 (native segwit)
        assert_eq!(
            detect_address_network("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
            BitcoinNetwork::Mainnet
        );
        assert_eq!(
            detect_address_network(
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut"
            ),
            BitcoinNetwork::Mainnet
        );

        // Mainnet legacy P2PKH (starts with 1)
        assert_eq!(
            detect_address_network("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
            BitcoinNetwork::Mainnet
        );

        // Mainnet legacy P2SH (starts with 3)
        assert_eq!(
            detect_address_network("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"),
            BitcoinNetwork::Mainnet
        );

        // Testnet/Signet bech32
        assert_eq!(
            detect_address_network("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"),
            BitcoinNetwork::Testnet
        );

        // Testnet/Signet legacy P2PKH (starts with m or n)
        assert_eq!(
            detect_address_network("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"),
            BitcoinNetwork::Testnet
        );
        assert_eq!(
            detect_address_network("n3zWAo2eBnxLr3ueohXnuAa8mTVBhxmPhq"),
            BitcoinNetwork::Testnet
        );

        // Testnet/Signet legacy P2SH (starts with 2)
        assert_eq!(
            detect_address_network("2N4Q5FhU2497BryFfUgbqkAJE87aKHUhXMp"),
            BitcoinNetwork::Testnet
        );

        // Regtest bech32
        assert_eq!(
            detect_address_network("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"),
            BitcoinNetwork::Regtest
        );
    }
}
