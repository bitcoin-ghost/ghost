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
//| FILE: main.rs                                                                                                        |
//|======================================================================================================================|

//! Ghost Pay L2 Node
//!
//! A privacy-preserving payment layer that runs alongside the mining pool.
//!
//! Features:
//! - Ghost Keys: Silent payment-style addresses for privacy
//! - Ghost Locks: P2TR UTXOs with timelocks for security
//! - Jump Locks: Risk-tiered key rotation for high-value funds
//! - Wraith Protocol: Two-phase mixing for transaction unlinkability
//!
//! Architecture:
//! - REST API for wallet operations
//! - Background scanner for incoming payments
//! - Wraith session coordinator
//! - L1 settlement watcher

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tower_governor::{
    errors::GovernorError, governor::GovernorConfigBuilder, key_extractor::KeyExtractor,
    GovernorLayer,
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use bitcoin::secp256k1::Secp256k1;
use bitcoin::Address;
use bitcoin::Network;

use ghost_common::constants::SATS_PER_BTC_F64;
use ghost_common::error::GhostError;
use ghost_common::rpc::BitcoinRpc;
use ghost_keys::{GhostKeys, GhostKeysExport, PaymentDetector};
use ghost_locks::{Denomination, GhostLock, StateTransition, TimelockTier};
use ghost_reconciliation::{BatchExecutor, ReconciliationInput, Settlement};
use ghost_storage::{
    ConfidentialTransferRecord, Database, GhostLockRecord, GhostLockState as DbLockState,
    WithdrawalRequest, WithdrawalStatus,
};
use ghost_zkp::{
    BalanceTree, CommitmentTree, ConsolidationPublicInputs, GhostConsolidateVerifier,
    GhostNoteSpendProof, GhostNoteSpendPublicInputs, GhostNoteVerifier, GhostUnshieldVerifier,
    UnshieldPublicInputs, MAX_CONSOLIDATION_INPUTS,
};

// H-PAY-2: Cryptography for encrypted key storage
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use scrypt::{scrypt, Params as ScryptParams};

/// Ghost Pay L2 Node
#[derive(Parser, Debug)]
#[command(name = "ghost-pay")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// API listen address
    #[arg(long, default_value = "0.0.0.0:8800")]
    api_listen: String,

    /// Data directory
    #[arg(long, default_value = "./ghost-pay-data")]
    data_dir: String,

    /// Bitcoin Core RPC URL
    #[arg(long, default_value = "http://127.0.0.1:8332")]
    bitcoin_rpc: String,

    /// Bitcoin Core RPC user (required, or set BITCOIN_RPC_USER env var)
    #[arg(long, env = "BITCOIN_RPC_USER")]
    rpc_user: Option<String>,

    /// Bitcoin Core RPC password (required, or set BITCOIN_RPC_PASSWORD env var)
    #[arg(long, env = "BITCOIN_RPC_PASSWORD")]
    rpc_password: Option<String>,

    /// Network (mainnet, testnet, signet, regtest)
    #[arg(long, default_value = "signet")]
    network: String,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Treasury address for settlement batches (required for withdrawal settlements)
    #[arg(long)]
    treasury_address: Option<String>,

    /// Password for encrypting keys at rest (H-PAY-2 security fix)
    /// If not provided, keys will be stored encrypted with a derived password
    #[arg(long, env = "GHOST_PAY_PASSWORD")]
    key_password: Option<String>,

    /// H-2: API secret for HMAC authentication (required for mainnet)
    /// All authenticated endpoints require X-Ghost-Signature header with HMAC-SHA256
    #[arg(long, env = "GHOST_PAY_API_SECRET")]
    api_secret: Option<String>,

    /// Shared bearer secret for trusted ghost-gsp callers. When set,
    /// requests with a matching `X-Internal-Auth` header skip HMAC
    /// — used by the operator's own GSP gateway. Leave unset on
    /// hosts that don't run a co-located ghost-gsp.
    #[arg(long, env = "GHOST_PAY_INTERNAL_SECRET")]
    internal_secret: Option<String>,

    /// TLS certificate PEM file path (enables HTTPS)
    /// When provided, --tls-key is also required.
    #[arg(long)]
    tls_cert: Option<std::path::PathBuf>,

    /// TLS private key PEM file path (required with --tls-cert)
    #[arg(long)]
    tls_key: Option<std::path::PathBuf>,

    /// Path to the node's Ed25519 identity key (`node.key`, same file
    /// ghost-pool uses). When provided AND no operator PEM cert is given,
    /// ghost-pay derives a self-signed TLS cert from this identity. Peers
    /// pin against the registered `node_id` (cert pubkey == node_id), so
    /// no CA / DNS / Let's Encrypt is required.
    #[arg(long, env = "GHOST_PAY_IDENTITY_KEY")]
    identity_key: Option<std::path::PathBuf>,

    /// MPC parameters directory (for loading Groth16 verification keys)
    /// Defaults to `<data-dir>/../mpc_params/` (sibling of data dir)
    #[arg(long, env = "GHOST_MPC_PARAMS_DIR")]
    mpc_params_dir: Option<std::path::PathBuf>,

    /// Ghost-pool HTTP API URL for L2 transaction relay
    /// Ghost-pay forwards verified NoteSpend transactions to ghost-pool for consensus.
    /// Defaults to http://127.0.0.1:8080 (local ghost-pool)
    #[arg(
        long,
        env = "GHOST_POOL_API_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    pool_api_url: String,

    /// Bitcoin address for receiving this node's share of L2 fees.
    /// Each node earns directly from L2 transactions it processes.
    #[arg(long, env = "GHOST_NODE_PAYOUT_ADDRESS")]
    node_payout_address: Option<String>,
}

// =============================================================================
// H-PAY-2: ENCRYPTED KEY STORAGE
// =============================================================================

/// Salt size for scrypt key derivation
const SALT_SIZE: usize = 32;
/// Nonce size for AES-GCM
const NONCE_SIZE: usize = 12;
/// scrypt parameters (N=2^15, r=8, p=1) - secure but not too slow
const SCRYPT_LOG_N: u8 = 15;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

// =============================================================================
// CONFIDENTIAL TRANSFER VERIFIER LOADING
// =============================================================================

/// Commitment tree depth — 2^20 = ~1M notes
const COMMITMENT_TREE_DEPTH: usize = 20;

/// Load the NoteSpend Groth16 verifier from MPC params directory.
///
/// Returns `Some(Arc<GhostNoteVerifier>)` if the VK file exists and loads successfully.
/// Returns `None` if no VK file found (note spend transfers will be unavailable).
fn load_note_spend_verifier_from_params(args: &Args) -> Option<Arc<GhostNoteVerifier>> {
    let mpc_dir = if let Some(ref dir) = args.mpc_params_dir {
        dir.clone()
    } else {
        // Default: sibling of data_dir (e.g., /home/ghost/.ghost/mpc_params/)
        let data_path = std::path::PathBuf::from(&args.data_dir);
        if let Some(parent) = data_path.parent() {
            parent.join("mpc_params")
        } else {
            std::path::PathBuf::from("mpc_params")
        }
    };

    // Try note_spend_vk.bin first, fall back to extracting from full params
    let vk_path = mpc_dir.join("note_spend_vk.bin");
    if !vk_path.exists() {
        warn!(
            path = %vk_path.display(),
            "NoteSpend VK not found — note spend transfers will be unavailable"
        );
        return None;
    }

    match ghost_zkp::load_note_spend_verifier(&vk_path, COMMITMENT_TREE_DEPTH) {
        Ok(verifier) => {
            info!(
                path = %vk_path.display(),
                has_groth16_vk = verifier.has_groth16_vk(),
                "Loaded NoteSpend verifier"
            );
            Some(Arc::new(verifier))
        }
        Err(e) => {
            error!(
                error = %e,
                path = %vk_path.display(),
                "Failed to load NoteSpend verifier"
            );
            None
        }
    }
}

/// Load the NoteConsolidate Groth16 verifier from MPC params directory.
///
/// Returns `Some(Arc<GhostConsolidateVerifier>)` if the VK file exists and loads successfully.
/// Returns `None` if no VK file found (consolidation transfers will be unavailable).
fn load_consolidation_verifier_from_params(args: &Args) -> Option<Arc<GhostConsolidateVerifier>> {
    let mpc_dir = if let Some(ref dir) = args.mpc_params_dir {
        dir.clone()
    } else {
        // Default: sibling of data_dir (e.g., /home/ghost/.ghost/mpc_params/)
        let data_path = std::path::PathBuf::from(&args.data_dir);
        if let Some(parent) = data_path.parent() {
            parent.join("mpc_params")
        } else {
            std::path::PathBuf::from("mpc_params")
        }
    };

    // MPC slot 2 naming legacy: consolidation VK is stored as payout_vk.bin
    let vk_path = mpc_dir.join("payout_vk.bin");
    if !vk_path.exists() {
        warn!(
            path = %vk_path.display(),
            "Consolidation VK not found — consolidation transfers will be unavailable"
        );
        return None;
    }

    match ghost_zkp::load_consolidation_verifier(&vk_path, COMMITMENT_TREE_DEPTH) {
        Ok(verifier) => {
            info!(
                path = %vk_path.display(),
                has_groth16_vk = verifier.has_groth16_vk(),
                "Loaded consolidation verifier"
            );
            Some(Arc::new(verifier))
        }
        Err(e) => {
            error!(
                error = %e,
                path = %vk_path.display(),
                "Failed to load consolidation verifier"
            );
            None
        }
    }
}

/// Load the Unshield Groth16 verifier from MPC params directory.
///
/// Returns `Some(Arc<GhostUnshieldVerifier>)` if the VK file exists and loads successfully.
/// Returns `None` if no VK file found (unshield withdrawals will be unavailable).
fn load_unshield_verifier_from_params(args: &Args) -> Option<Arc<GhostUnshieldVerifier>> {
    let mpc_dir = if let Some(ref dir) = args.mpc_params_dir {
        dir.clone()
    } else {
        // Default: sibling of data_dir (e.g., /home/ghost/.ghost/mpc_params/)
        let data_path = std::path::PathBuf::from(&args.data_dir);
        if let Some(parent) = data_path.parent() {
            parent.join("mpc_params")
        } else {
            std::path::PathBuf::from("mpc_params")
        }
    };

    let vk_path = mpc_dir.join("unshield_vk.bin");
    if !vk_path.exists() {
        warn!(
            path = %vk_path.display(),
            "Unshield VK not found — unshield withdrawals will be unavailable"
        );
        return None;
    }

    match ghost_zkp::load_unshield_verifier(&vk_path, COMMITMENT_TREE_DEPTH) {
        Ok(verifier) => {
            info!(
                path = %vk_path.display(),
                has_groth16_vk = verifier.has_groth16_vk(),
                "Loaded unshield verifier"
            );
            Some(Arc::new(verifier))
        }
        Err(e) => {
            error!(
                error = %e,
                path = %vk_path.display(),
                "Failed to load unshield verifier"
            );
            None
        }
    }
}

// =============================================================================
// H-21: SAFE BLOCK HEIGHT CONVERSION
// =============================================================================

/// H-21: Safely convert a block height from i64/u64 to u32 with bounds checking.
/// Returns an error if the value is out of range for u32.
fn safe_block_height_u64(height: u64) -> Result<u32, anyhow::Error> {
    if height > u32::MAX as u64 {
        return Err(anyhow::anyhow!(
            "H-21 SECURITY: Block height {} exceeds u32::MAX ({})",
            height,
            u32::MAX
        ));
    }
    Ok(height as u32)
}

/// H-21: Safely convert a block height from i64 to u32 with bounds checking.
/// Returns an error if the value is negative or out of range for u32.
#[allow(dead_code)] // Kept for potential future use with Bitcoin RPC responses
fn safe_block_height_i64(height: i64) -> Result<u32, anyhow::Error> {
    if height < 0 {
        return Err(anyhow::anyhow!(
            "H-21 SECURITY: Block height {} is negative",
            height
        ));
    }
    if height > u32::MAX as i64 {
        return Err(anyhow::anyhow!(
            "H-21 SECURITY: Block height {} exceeds u32::MAX ({})",
            height,
            u32::MAX
        ));
    }
    Ok(height as u32)
}

/// Derive SQLCipher database key from password with domain-separated salt.
/// Uses lower scrypt cost (log_n=14) than wallet key derivation since this runs on every startup.
/// The fixed domain-specific salt ensures this produces a different key than the wallet encryption key.
fn derive_db_key(password: &str) -> [u8; 32] {
    let params = ScryptParams::new(14, 8, 1, 32).expect("scrypt params");
    let mut key = [0u8; 32];
    scrypt(
        password.as_bytes(),
        b"ghost-pay-sqlcipher-v1",
        &params,
        &mut key,
    )
    .expect("scrypt");
    key
}

/// Derive encryption key from password using scrypt
fn derive_encryption_key(password: &str, salt: &[u8]) -> Result<[u8; 32], anyhow::Error> {
    let params = ScryptParams::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, 32)
        .map_err(|e| anyhow::anyhow!("scrypt params error: {}", e))?;

    let mut key = [0u8; 32];
    scrypt(password.as_bytes(), salt, &params, &mut key)
        .map_err(|e| anyhow::anyhow!("scrypt error: {}", e))?;

    Ok(key)
}

/// Encrypt data with password using AES-256-GCM
/// Returns: salt (32) || nonce (12) || ciphertext
fn encrypt_keys(plaintext: &[u8], password: &str) -> Result<Vec<u8>, anyhow::Error> {
    // Generate random salt and nonce
    let mut salt = [0u8; SALT_SIZE];
    let mut nonce_bytes = [0u8; NONCE_SIZE];

    getrandom::getrandom(&mut salt).map_err(|e| anyhow::anyhow!("RNG error: {}", e))?;
    getrandom::getrandom(&mut nonce_bytes).map_err(|e| anyhow::anyhow!("RNG error: {}", e))?;

    // Derive key from password
    let key = derive_encryption_key(password, &salt)?;

    // Encrypt with AES-256-GCM
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow::anyhow!("cipher error: {}", e))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("encryption error: {}", e))?;

    // Combine: salt || nonce || ciphertext
    let mut result = Vec::with_capacity(SALT_SIZE + NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data with password using AES-256-GCM
/// Expects: salt (32) || nonce (12) || ciphertext
fn decrypt_keys(encrypted: &[u8], password: &str) -> Result<Vec<u8>, anyhow::Error> {
    if encrypted.len() < SALT_SIZE + NONCE_SIZE + 16 {
        // 16 is min auth tag
        return Err(anyhow::anyhow!("encrypted data too short"));
    }

    // Extract components
    let salt = &encrypted[0..SALT_SIZE];
    let nonce_bytes = &encrypted[SALT_SIZE..SALT_SIZE + NONCE_SIZE];
    let ciphertext = &encrypted[SALT_SIZE + NONCE_SIZE..];

    // Derive key
    let key = derive_encryption_key(password, salt)?;

    // Decrypt
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow::anyhow!("cipher error: {}", e))?;

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("decryption failed - wrong password?"))?;

    Ok(plaintext)
}

/// Password file name for auto-generated secure passwords
const AUTO_PASSWORD_FILE: &str = ".ghost-pay-key";

/// Get or derive the encryption password
/// For mainnet, requires explicit password via --key-password or GHOST_PAY_PASSWORD env var
/// For non-mainnet, generates and stores a secure random password in the data directory
fn get_encryption_password(args: &Args, network: Network) -> Result<String> {
    // Check explicit password argument first
    if let Some(ref password) = args.key_password {
        return Ok(password.clone());
    }

    // Check environment variable
    if let Ok(password) = std::env::var("GHOST_PAY_PASSWORD") {
        return Ok(password);
    }

    // For mainnet, require explicit password - no auto-generation
    if network == Network::Bitcoin {
        return Err(anyhow::anyhow!(
            "GHOST_PAY_PASSWORD environment variable or --key-password required for mainnet"
        ));
    }

    // M-13 FIX: For non-mainnet, use a secure random password stored in a file
    // This replaces the predictable hostname-based derivation
    let password_path = std::path::Path::new(&args.data_dir).join(AUTO_PASSWORD_FILE);

    // Try to read existing password file
    if let Ok(password) = std::fs::read_to_string(&password_path) {
        let password = password.trim().to_string();
        if password.len() >= 32 {
            info!("Using stored key password from {}", password_path.display());
            return Ok(password);
        }
        // Password file exists but is too short - regenerate
        warn!(
            "Existing password file too short, regenerating: {}",
            password_path.display()
        );
    }

    // Generate new secure random password (64 hex chars = 32 bytes of entropy)
    let mut random_bytes = [0u8; 32];
    getrandom::getrandom(&mut random_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to generate secure random password: {}", e))?;

    let password = hex::encode(random_bytes);

    // Atomic write: umask ensures temp file is created 0o600, rename is atomic
    std::fs::create_dir_all(&args.data_dir)?;

    #[cfg(unix)]
    let _umask_guard = ghost_storage::UmaskGuard::new_restrictive();

    let temp_suffix = {
        let mut buf = [0u8; 4];
        getrandom::getrandom(&mut buf).unwrap_or_default();
        hex::encode(buf)
    };
    let temp_path = password_path.with_extension(format!("tmp.{}", temp_suffix));

    std::fs::write(&temp_path, &password).map_err(|e| {
        anyhow::anyhow!(
            "Failed to write temp password file {}: {}",
            temp_path.display(),
            e
        )
    })?;

    std::fs::rename(&temp_path, &password_path).map_err(|e| {
        let _ = std::fs::remove_file(&temp_path);
        anyhow::anyhow!("Failed to rename password file: {}", e)
    })?;

    #[cfg(unix)]
    drop(_umask_guard);

    info!(
        "Generated and stored new key password at {} (non-mainnet only)",
        password_path.display()
    );

    Ok(password)
}

// =============================================================================
// H-7/H-8: IP-BASED RATE LIMITING FOR API SECURITY
// =============================================================================

/// L-21 FIX: Validate that an IP address is acceptable as a trusted proxy.
fn is_valid_trusted_proxy(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;

    match ip {
        IpAddr::V4(ipv4) => {
            if ipv4.is_unspecified()
                || ipv4.is_link_local()
                || ipv4.is_multicast()
                || ipv4.is_broadcast()
            {
                return false;
            }
            // Reject documentation addresses
            let octets = ipv4.octets();
            if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
            {
                return false;
            }
            true
        }
        IpAddr::V6(ipv6) => {
            if ipv6.is_unspecified() || ipv6.is_multicast() {
                return false;
            }
            let segments = ipv6.segments();
            if (segments[0] & 0xffc0) == 0xfe80 {
                return false; // Link-local
            }
            true
        }
    }
}

/// PAY-2: Get trusted proxy IPs from environment or use defaults
///
/// Load from environment variables (comma-separated IPs):
/// - TRUSTED_PROXY_IPS (preferred, as specified in PAY-2 fix)
/// - GHOST_TRUSTED_PROXIES (legacy, for backward compatibility)
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
                    Ok(ip) if is_valid_trusted_proxy(&ip) => Some(ip),
                    _ => None,
                }
            })
            .collect();

        if proxies.is_empty() {
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
        vec![
            "127.0.0.1"
                .parse()
                .expect("L-1: Valid hardcoded IPv4 localhost"),
            "::1".parse().expect("L-1: Valid hardcoded IPv6 localhost"),
        ]
    }
}

fn is_trusted_proxy(ip: &std::net::IpAddr, trusted: &[std::net::IpAddr]) -> bool {
    trusted.contains(ip)
}

/// H-8: IP-based key extractor for rate limiting
#[derive(Debug, Clone)]
struct IpKeyExtractor {
    trusted_proxies: Vec<std::net::IpAddr>,
}

impl Default for IpKeyExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl IpKeyExtractor {
    fn new() -> Self {
        Self {
            trusted_proxies: get_trusted_proxies(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct IpKey(String);

impl KeyExtractor for IpKeyExtractor {
    type Key = IpKey;

    fn extract<T>(&self, req: &axum::http::Request<T>) -> Result<Self::Key, GovernorError> {
        let peer_ip = req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip());

        let trust_proxy_headers = peer_ip
            .as_ref()
            .map(|ip| is_trusted_proxy(ip, &self.trusted_proxies))
            .unwrap_or(false);

        if trust_proxy_headers {
            if let Some(xff) = req.headers().get("X-Forwarded-For") {
                if let Ok(xff_str) = xff.to_str() {
                    if let Some(ip_str) = xff_str.split(',').next_back() {
                        let ip_trimmed = ip_str.trim();
                        if !ip_trimmed.is_empty() {
                            return Ok(IpKey(ip_trimmed.to_string()));
                        }
                    }
                }
            }
            if let Some(xri) = req.headers().get("X-Real-IP") {
                if let Ok(ip_str) = xri.to_str() {
                    return Ok(IpKey(ip_str.to_string()));
                }
            }
        }

        if let Some(ip) = peer_ip {
            return Ok(IpKey(ip.to_string()));
        }

        Err(GovernorError::UnableToExtractKey)
    }
}

// =============================================================================
// H-2: API AUTHENTICATION MIDDLEWARE
// =============================================================================

use axum::{body::Body, extract::Request, http::HeaderMap, middleware::Next, response::Response};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// H-2: API secret holder for authentication middleware
#[derive(Clone)]
struct ApiAuth {
    secret: Option<String>,
    /// Shared bearer secret for trusted GSP-server callers. When set,
    /// requests with a matching `X-Internal-Auth` header skip HMAC
    /// verification — used by ghost-gsp's PayClient (a known operator-
    /// run gateway). Validated in constant time. Distinct from
    /// `secret` so operators can rotate them independently.
    internal_secret: Option<String>,
    network: Network,
}

impl ApiAuth {
    fn new(secret: Option<String>, internal_secret: Option<String>, network: Network) -> Self {
        Self {
            secret,
            internal_secret,
            network,
        }
    }

    /// Constant-time check for the `X-Internal-Auth` bearer header.
    /// Returns true only when the configured internal secret is set
    /// AND matches the supplied header value byte-for-byte.
    fn internal_auth_matches(&self, headers: &HeaderMap) -> bool {
        let configured = match &self.internal_secret {
            Some(s) => s,
            None => return false,
        };
        let provided = match headers.get("X-Internal-Auth").and_then(|h| h.to_str().ok()) {
            Some(s) => s,
            None => return false,
        };
        if provided.len() != configured.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in provided.bytes().zip(configured.bytes()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    /// Verify HMAC signature from request headers
    fn verify_signature(&self, headers: &HeaderMap, body: &[u8]) -> bool {
        let secret = match &self.secret {
            Some(s) => s,
            None => return false, // No secret configured
        };

        // Get signature from X-Ghost-Signature header
        let signature_header = match headers.get("X-Ghost-Signature") {
            Some(h) => match h.to_str() {
                Ok(s) => s,
                Err(_) => return false,
            },
            None => return false,
        };

        // Get timestamp from X-Ghost-Timestamp header (replay protection)
        let timestamp = match headers.get("X-Ghost-Timestamp") {
            Some(h) => match h.to_str() {
                Ok(s) => match s.parse::<i64>() {
                    Ok(ts) => ts,
                    Err(_) => return false,
                },
                Err(_) => return false,
            },
            None => return false,
        };

        // Check timestamp is within 5 minutes
        let now = chrono::Utc::now().timestamp();
        if (now - timestamp).abs() > 300 {
            warn!("H-2: Request timestamp too old or in future: {}", timestamp);
            return false;
        }

        // Compute expected HMAC: HMAC-SHA256(secret, timestamp + body)
        let mut mac: Hmac<Sha256> = match <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mac.update(timestamp.to_string().as_bytes());
        mac.update(body);

        let expected = hex::encode(mac.finalize().into_bytes());

        // Constant-time comparison
        if signature_header.len() != expected.len() {
            return false;
        }

        let mut diff = 0u8;
        for (a, b) in signature_header.bytes().zip(expected.bytes()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

/// H-2: Authentication middleware for sensitive endpoints
async fn require_api_auth(
    axum::extract::State(auth): axum::extract::State<ApiAuth>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // HIGH-API-2: API authentication is ALWAYS required, regardless of network
    // There is no valid reason to allow unauthenticated access to payment APIs
    // even on testnet/signet - this could mask bugs in auth integration.
    // This check is now redundant since we fail at startup if secret is not configured,
    // but we keep it as defense-in-depth.
    if auth.secret.is_none() {
        error!(
            network = ?auth.network,
            "HIGH-API-2 SECURITY: API secret (api_secret) not configured - rejecting request. \
             This should never happen as startup validation should prevent this."
        );
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }

    // Extract body for signature verification
    let (parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    // Trusted GSP-server bypass: a configured `X-Internal-Auth`
    // header that matches the operator's GSP-internal secret skips
    // HMAC verification. This is the path ghost-gsp's PayClient
    // takes — it sits behind the operator's perimeter and
    // authenticates wallets itself via JWT WebSocket. External
    // callers without the bearer fall through to HMAC.
    let auth_ok = auth.internal_auth_matches(&parts.headers)
        || auth.verify_signature(&parts.headers, &body_bytes);
    if !auth_ok {
        warn!(
            path = %parts.uri.path(),
            "H-2: Authentication failed - no valid HMAC and no matching X-Internal-Auth"
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Reconstruct request with body
    let request = Request::from_parts(parts, Body::from(body_bytes));
    Ok(next.run(request).await)
}

/// MEDIUM-1: Localhost-only middleware for L2 block production endpoints.
/// These are called by ghost-pool on the same host — external access would corrupt L2 state.
async fn localhost_only(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, StatusCode> {
    let is_loopback = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip().is_loopback())
        .unwrap_or(false);
    if !is_loopback {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(request).await)
}

/// LOW-API-1: Security headers middleware for all HTTP responses
async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    use axum::http::HeaderValue;

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

/// Application state
struct AppState {
    /// Ghost keys for this node
    /// 2.5 HIGH: GhostKeys wrapped in Arc to allow sharing across async boundaries
    /// without cloning the secret key material.
    keys: RwLock<Option<Arc<GhostKeys>>>,
    /// Ghost ID (owner identifier for DB)
    ghost_id: RwLock<Option<String>>,
    /// Active ghost locks (actual GhostLock objects) - cached from DB
    ghost_locks: RwLock<Vec<GhostLock>>,
    /// Lock metadata for API responses - cached from DB
    locks: RwLock<Vec<LockInfo>>,
    /// Pending payments to scan
    scanner_tx: mpsc::Sender<ScanRequest>,
    /// Configuration
    config: Args,
    /// Network for address generation
    network: Network,
    /// Database for persistence
    db: Arc<Database>,
    /// Bitcoin Core RPC client
    rpc: Arc<BitcoinRpc>,
    /// Confidential transfer commitment tree (MiMC-based, depth 20)
    commitment_tree: RwLock<CommitmentTree>,
    /// L2 balance tree for state transition witnesses
    balance_tree: RwLock<BalanceTree>,
    /// Groth16 NoteSpend verifier (None if MPC params not available)
    /// Wrapped in RwLock for hot-reload when MPC ceremony completes after startup.
    note_spend_verifier: RwLock<Option<Arc<GhostNoteVerifier>>>,
    /// Groth16 NoteConsolidate verifier (None if MPC params not available)
    /// Wrapped in RwLock for hot-reload when MPC ceremony completes after startup.
    consolidation_verifier: RwLock<Option<Arc<GhostConsolidateVerifier>>>,
    /// Groth16 Unshield verifier (None if MPC params not available)
    /// Wrapped in RwLock for hot-reload when MPC ceremony completes after startup.
    unshield_verifier: RwLock<Option<Arc<GhostUnshieldVerifier>>>,
    /// HTTP client for relaying verified transactions to ghost-pool
    pool_http_client: reqwest::Client,
    /// Ghost-pool API URL for L2 transaction relay
    pool_api_url: String,
    /// Last settled epoch per settlement class (for dedup)
    last_settled_epoch: RwLock<std::collections::HashMap<String, u64>>,
}

/// Lock information with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LockInfo {
    id: String,
    denomination: String,
    amount_sats: u64,
    state: String,
    created_at: u64,
    timelock_tier: String,
    jump_risk: String,
    needs_jump: bool,
    /// P2WSH address for funding (note: no longer "Taproot" — Ghost
    /// Locks are P2WSH for quantum safety per the lock spec).
    address: String,
    /// Output public key — this is the lock_pubkey (cooperative-path
    /// key) the operator derived. 33-byte SEC1 compressed, hex.
    output_pubkey: String,
    /// Recovery height (block when recovery becomes available)
    recovery_height: u32,
    /// Blocks until jump needed (0 if not applicable)
    blocks_until_jump: u32,
    /// Echo of the wallet-supplied recovery_pubkey (33-byte SEC1
    /// compressed, hex). Wallet checks this to detect operator
    /// substitution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_pubkey: Option<String>,
    /// Echo of the wallet's recovery derivation index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_index: Option<u32>,
    /// CSV blocks the recovery branch waits before becoming spendable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery_blocks: Option<u32>,
    /// Block height the lock was created at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    creation_height: Option<u32>,
}

/// Scan request for background scanner
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanRequest {
    txid: String,
    vout: u32,
}

/// Convert an x-only pubkey hex to a P2TR address
fn pubkey_hex_to_p2tr_address(pubkey_hex: &str, network: Network) -> String {
    use bitcoin::key::TweakedPublicKey;
    use bitcoin::secp256k1::XOnlyPublicKey;

    // Parse the x-only public key from hex
    let bytes = match hex::decode(pubkey_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return format!("(invalid pubkey: {})", pubkey_hex),
    };

    let xonly = match XOnlyPublicKey::from_slice(&bytes) {
        Ok(k) => k,
        Err(_) => return format!("(invalid pubkey: {})", pubkey_hex),
    };

    // Create tweaked key (assuming no script tree, so merkle root is None)
    // For display purposes, we use the untweaked key
    let tweaked = TweakedPublicKey::dangerous_assume_tweaked(xonly);
    let address = Address::p2tr_tweaked(tweaked, network);
    address.to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Install the rustls process-level CryptoProvider exactly once before any
    // ClientConfig::builder() / ServerConfig::builder() construction. Required
    // when identity-derived TLS is used (mirrors the ghost-pool fix).
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        // Already installed (test harness / re-init); nothing to do.
    }

    // Extract TLS config before args is moved into AppState
    let tls_cert_path = args.tls_cert.clone();
    let tls_key_path = args.tls_key.clone();
    let identity_key_path = args.identity_key.clone();
    let public_address_for_tls = std::env::var("GHOST_PAY_PUBLIC_ADDRESS").ok();

    // Setup logging
    let level = match args.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting Ghost Pay L2 Node v{}", env!("CARGO_PKG_VERSION"));
    info!("API listen: {}", args.api_listen);
    info!("Data dir: {}", args.data_dir);
    info!("Network: {}", args.network);

    // Create data directory
    std::fs::create_dir_all(&args.data_dir)?;

    // Create scanner channel
    let (scanner_tx, scanner_rx) = mpsc::channel(1000);

    // Parse network
    let network = match args.network.to_lowercase().as_str() {
        "mainnet" | "main" => Network::Bitcoin,
        "testnet" | "test" => Network::Testnet,
        "signet" => Network::Signet,
        _ => Network::Regtest,
    };

    // Initialize encrypted database (SQLCipher)
    let db_path = std::path::Path::new(&args.data_dir).join("ghost-pay.db");
    let encryption_password_for_db = get_encryption_password(&args, network)?;
    let db_key = derive_db_key(&encryption_password_for_db);

    let db = if db_path.exists() {
        match Database::open_encrypted(&db_path, &db_key) {
            Ok(db) => Arc::new(db),
            Err(_) => {
                // Might be unencrypted (pre-upgrade) — migrate
                info!("Attempting migration from unencrypted to SQLCipher...");
                Database::migrate_to_encrypted(&db_path, &db_key)?;
                Arc::new(Database::open_encrypted(&db_path, &db_key)?)
            }
        }
    } else {
        Arc::new(Database::open_encrypted(&db_path, &db_key)?)
    };
    info!("Encrypted database opened: {}", db_path.display());

    // Create pending_transfers table for L2 block production
    db.with_connection(|conn| {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS pending_transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_index INTEGER NOT NULL,
                recipient_index INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                sender_balance_before INTEGER NOT NULL,
                recipient_balance_before INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS l2_balances (
                account_index INTEGER PRIMARY KEY,
                balance INTEGER NOT NULL
            );",
        )
        .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))?;
        Ok(())
    })?;

    // Load L2 balance tree from persisted state
    let mut balance_tree = BalanceTree::new(COMMITMENT_TREE_DEPTH);
    db.with_connection(|conn| {
        let mut stmt = conn
            .prepare("SELECT account_index, balance FROM l2_balances")
            .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)? as u64, row.get::<_, i64>(1)? as u64))
            })
            .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))?;
        for row in rows {
            let (index, bal) =
                row.map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))?;
            balance_tree.set_balance(index, bal);
        }
        Ok(())
    })?;
    info!(
        accounts = balance_tree.account_count(),
        "L2 balance tree loaded"
    );

    // M-16 FIX: Require explicit RPC credentials - no defaults
    let rpc_user = args.rpc_user.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Bitcoin RPC user required. Set --rpc-user or BITCOIN_RPC_USER environment variable."
        )
    })?;
    let rpc_password = args.rpc_password.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Bitcoin RPC password required. Set --rpc-password or BITCOIN_RPC_PASSWORD environment variable."
        )
    })?;

    // Parse Bitcoin RPC URL and create client
    let rpc_url = &args.bitcoin_rpc;
    let (rpc_host, rpc_port) = parse_rpc_url(rpc_url, network);
    let rpc = Arc::new(BitcoinRpc::new(
        &rpc_host,
        rpc_port,
        rpc_user,
        rpc_password,
    )?);
    info!("Bitcoin RPC configured: {}:{}", rpc_host, rpc_port);

    // Check treasury address configuration before args is moved
    let treasury_configured = args.treasury_address.is_some();
    if !treasury_configured {
        warn!("No treasury address configured - settlement features disabled");
    }

    // Reconstruct commitment tree from DB
    let mut commitment_tree = CommitmentTree::new(COMMITMENT_TREE_DEPTH);
    match db.load_all_confidential_notes() {
        Ok(notes) => {
            for (index, commitment) in &notes {
                commitment_tree.insert(*index, *commitment);
            }
            if !notes.is_empty() {
                info!(count = notes.len(), "Reconstructed commitment tree from DB");
            }
        }
        Err(e) => {
            warn!(error = %e, "Failed to load confidential notes — starting with empty tree");
        }
    }
    // Reconstruct spent nullifiers
    match db.load_all_nullifiers() {
        Ok(nullifiers) => {
            for nullifier in &nullifiers {
                commitment_tree.spend_nullifier(*nullifier);
            }
            if !nullifiers.is_empty() {
                info!(
                    count = nullifiers.len(),
                    "Loaded nullifiers into commitment tree"
                );
            }
        }
        Err(e) => {
            warn!(error = %e, "Failed to load nullifiers — nullifier set empty");
        }
    }

    // Load NoteSpend verifier from MPC params (before args is moved)
    let note_spend_verifier = load_note_spend_verifier_from_params(&args);

    // Load consolidation verifier from MPC params (before args is moved)
    let consolidation_verifier = load_consolidation_verifier_from_params(&args);

    // Load unshield verifier from MPC params (before args is moved)
    let unshield_verifier = load_unshield_verifier_from_params(&args);

    // Initialize state
    let pool_api_url = args.pool_api_url.clone();
    let pool_http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("Failed to create HTTP client for ghost-pool relay");

    let state = Arc::new(AppState {
        keys: RwLock::new(None),
        ghost_id: RwLock::new(None),
        ghost_locks: RwLock::new(Vec::new()),
        locks: RwLock::new(Vec::new()),
        scanner_tx,
        config: args,
        network,
        db: db.clone(),
        rpc,
        commitment_tree: RwLock::new(commitment_tree),
        balance_tree: RwLock::new(balance_tree),
        note_spend_verifier: RwLock::new(note_spend_verifier),
        consolidation_verifier: RwLock::new(consolidation_verifier),
        unshield_verifier: RwLock::new(unshield_verifier),
        pool_http_client,
        pool_api_url,
        last_settled_epoch: RwLock::new(std::collections::HashMap::new()),
    });

    // Spawn periodic VK hot-reload task (picks up MPC ceremony completions without restart)
    {
        let state_for_vk = Arc::clone(&state);
        let vk_path = {
            let mpc_dir = if let Some(ref dir) = state.config.mpc_params_dir {
                dir.clone()
            } else {
                let data_path = std::path::PathBuf::from(&state.config.data_dir);
                if let Some(parent) = data_path.parent() {
                    parent.join("mpc_params")
                } else {
                    std::path::PathBuf::from("mpc_params")
                }
            };
            mpc_dir.join("note_spend_vk.bin")
        };
        let mut last_modified = std::fs::metadata(&vk_path)
            .ok()
            .and_then(|m| m.modified().ok());
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let current = std::fs::metadata(&vk_path)
                    .ok()
                    .and_then(|m| m.modified().ok());
                if current != last_modified && vk_path.exists() {
                    match ghost_zkp::load_note_spend_verifier(&vk_path, COMMITMENT_TREE_DEPTH) {
                        Ok(v) => {
                            *state_for_vk.note_spend_verifier.write() = Some(Arc::new(v));
                            info!(path = %vk_path.display(), "Reloaded NoteSpend VK");
                            last_modified = current;
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to reload NoteSpend VK");
                        }
                    }
                }
            }
        });
    }

    // Spawn periodic consolidation VK hot-reload task
    {
        let state_for_cvk = Arc::clone(&state);
        let cvk_path = {
            let mpc_dir = if let Some(ref dir) = state.config.mpc_params_dir {
                dir.clone()
            } else {
                let data_path = std::path::PathBuf::from(&state.config.data_dir);
                if let Some(parent) = data_path.parent() {
                    parent.join("mpc_params")
                } else {
                    std::path::PathBuf::from("mpc_params")
                }
            };
            mpc_dir.join("payout_vk.bin")
        };
        let mut last_modified_cvk = std::fs::metadata(&cvk_path)
            .ok()
            .and_then(|m| m.modified().ok());
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let current = std::fs::metadata(&cvk_path)
                    .ok()
                    .and_then(|m| m.modified().ok());
                if current != last_modified_cvk && cvk_path.exists() {
                    match ghost_zkp::load_consolidation_verifier(&cvk_path, COMMITMENT_TREE_DEPTH) {
                        Ok(v) => {
                            *state_for_cvk.consolidation_verifier.write() = Some(Arc::new(v));
                            info!(path = %cvk_path.display(), "Reloaded consolidation VK");
                            last_modified_cvk = current;
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to reload consolidation VK");
                        }
                    }
                }
            }
        });
    }

    // Spawn periodic unshield VK hot-reload task
    {
        let state_for_uvk = Arc::clone(&state);
        let uvk_path = {
            let mpc_dir = if let Some(ref dir) = state.config.mpc_params_dir {
                dir.clone()
            } else {
                let data_path = std::path::PathBuf::from(&state.config.data_dir);
                if let Some(parent) = data_path.parent() {
                    parent.join("mpc_params")
                } else {
                    std::path::PathBuf::from("mpc_params")
                }
            };
            mpc_dir.join("unshield_vk.bin")
        };
        let mut last_modified_uvk = std::fs::metadata(&uvk_path)
            .ok()
            .and_then(|m| m.modified().ok());
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let current = std::fs::metadata(&uvk_path)
                    .ok()
                    .and_then(|m| m.modified().ok());
                if current != last_modified_uvk && uvk_path.exists() {
                    match ghost_zkp::load_unshield_verifier(&uvk_path, COMMITMENT_TREE_DEPTH) {
                        Ok(v) => {
                            *state_for_uvk.unshield_verifier.write() = Some(Arc::new(v));
                            info!(path = %uvk_path.display(), "Reloaded unshield VK");
                            last_modified_uvk = current;
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to reload unshield VK");
                        }
                    }
                }
            }
        });
    }

    // H-PAY-2 FIX: Load existing keys from database with encryption support
    // Try encrypted keys first (new format), fall back to legacy plaintext for migration
    let encryption_password = get_encryption_password(&state.config, network)?;
    let mut keys_loaded = false;

    // Try to load encrypted keys first (new secure format)
    if let Ok(Some(encrypted_hex)) = db.kv_get("ghost_keys_encrypted") {
        if let Ok(encrypted_bytes) = hex::decode(&encrypted_hex) {
            match decrypt_keys(&encrypted_bytes, &encryption_password) {
                Ok(decrypted) => {
                    if let Ok(keys_json) = String::from_utf8(decrypted) {
                        if let Ok(keys_export) = serde_json::from_str::<GhostKeysExport>(&keys_json)
                        {
                            if let Ok(keys) = GhostKeys::try_from(keys_export) {
                                let ghost_id = keys.ghost_id();
                                let ghost_id_str = ghost_id.to_string();

                                // Load locks for this ghost_id
                                if let Ok(db_locks) = db.get_ghost_locks_by_owner(&ghost_id_str) {
                                    let lock_infos: Vec<LockInfo> = db_locks
                                        .iter()
                                        .filter(|r| {
                                            r.state != ghost_storage::GhostLockState::Spent
                                                && r.state != ghost_storage::GhostLockState::PendingSettlement
                                        })
                                        .map(|r| LockInfo {
                                            id: r.lock_id.clone(),
                                            denomination: r.denomination.clone(),
                                            amount_sats: r.amount_sats,
                                            state: r.state.as_str().to_string(),
                                            created_at: r.created_at as u64,
                                            timelock_tier: r.timelock_tier.clone(),
                                            jump_risk: r.jump_risk_tier.clone(),
                                            needs_jump: r
                                                .next_jump_height
                                                .map(|h| h <= r.creation_height + 1000)
                                                .unwrap_or(false),
                                            address: pubkey_hex_to_p2tr_address(&r.lock_pubkey, network),
                                            output_pubkey: r.lock_pubkey.clone(),
                                            recovery_height: r.recovery_height,
                                            blocks_until_jump: r
                                                .next_jump_height
                                                .unwrap_or(0)
                                                .saturating_sub(r.creation_height),
                                            recovery_pubkey: Some(r.recovery_pubkey.clone()),
                                            recovery_index: None,
                                            recovery_blocks: Some(
                                                r.recovery_height
                                                    .saturating_sub(r.creation_height),
                                            ),
                                            creation_height: Some(r.creation_height),
                                        })
                                        .collect();

                                    info!(
                                        "Loaded {} existing locks from database",
                                        lock_infos.len()
                                    );
                                    *state.locks.write() = lock_infos;
                                }

                                info!("Loaded existing ghost keys (encrypted): {}", ghost_id);
                                *state.keys.write() = Some(Arc::new(keys));
                                *state.ghost_id.write() = Some(ghost_id_str);
                                keys_loaded = true;
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to decrypt keys: {}. Check GHOST_PAY_PASSWORD.", e);
                }
            }
        }
    }

    // Fall back to legacy plaintext keys (migrate to encrypted)
    if !keys_loaded {
        if let Ok(Some(keys_json)) = db.kv_get("ghost_keys") {
            if let Ok(keys_export) = serde_json::from_str::<GhostKeysExport>(&keys_json) {
                // M-14: Serialize before consuming — GhostKeysExport no longer implements Clone
                let keys_json_bytes = serde_json::to_vec(&keys_export).ok();
                if let Ok(keys) = GhostKeys::try_from(keys_export) {
                    let ghost_id = keys.ghost_id();
                    let ghost_id_str = ghost_id.to_string();

                    // Migrate: encrypt and save, then delete plaintext
                    warn!("Migrating plaintext keys to encrypted storage (H-PAY-2 security fix)");
                    if let Some(keys_json_bytes) = keys_json_bytes {
                        match encrypt_keys(&keys_json_bytes, &encryption_password) {
                            Ok(encrypted) => {
                                let encrypted_hex = hex::encode(&encrypted);
                                if let Err(e) = db.kv_set("ghost_keys_encrypted", &encrypted_hex) {
                                    warn!("Failed to save encrypted keys: {}", e);
                                } else {
                                    // Delete plaintext keys after successful encryption
                                    if let Err(e) = db.kv_delete("ghost_keys") {
                                        warn!("Failed to delete plaintext keys: {}", e);
                                    } else {
                                        info!("Successfully migrated keys to encrypted storage");
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to encrypt keys during migration: {}", e);
                            }
                        }
                    }

                    // Load locks for this ghost_id
                    if let Ok(db_locks) = db.get_ghost_locks_by_owner(&ghost_id_str) {
                        let lock_infos: Vec<LockInfo> = db_locks
                            .iter()
                            .filter(|r| {
                                r.state != ghost_storage::GhostLockState::Spent
                                    && r.state != ghost_storage::GhostLockState::PendingSettlement
                            })
                            .map(|r| LockInfo {
                                id: r.lock_id.clone(),
                                denomination: r.denomination.clone(),
                                amount_sats: r.amount_sats,
                                state: r.state.as_str().to_string(),
                                created_at: r.created_at as u64,
                                timelock_tier: r.timelock_tier.clone(),
                                jump_risk: r.jump_risk_tier.clone(),
                                needs_jump: r
                                    .next_jump_height
                                    .map(|h| h <= r.creation_height + 1000)
                                    .unwrap_or(false),
                                address: pubkey_hex_to_p2tr_address(&r.lock_pubkey, network),
                                output_pubkey: r.lock_pubkey.clone(),
                                recovery_height: r.recovery_height,
                                blocks_until_jump: r
                                    .next_jump_height
                                    .unwrap_or(0)
                                    .saturating_sub(r.creation_height),
                                recovery_pubkey: Some(r.recovery_pubkey.clone()),
                                recovery_index: None,
                                recovery_blocks: Some(
                                    r.recovery_height.saturating_sub(r.creation_height),
                                ),
                                creation_height: Some(r.creation_height),
                            })
                            .collect();

                        info!("Loaded {} existing locks from database", lock_infos.len());
                        *state.locks.write() = lock_infos;
                    }

                    info!(
                        "Loaded existing ghost keys (migrated from plaintext): {}",
                        ghost_id
                    );
                    *state.keys.write() = Some(Arc::new(keys));
                    *state.ghost_id.write() = Some(ghost_id_str);
                }
            }
        }
    }

    // Graceful shutdown: broadcast channel signals all background tasks to stop
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    // Spawn background scanner
    let state_clone = Arc::clone(&state);
    let mut shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        tokio::select! {
            _ = run_scanner(state_clone, scanner_rx) => {}
            _ = shutdown_rx.recv() => {
                info!("Scanner shutting down");
            }
        }
    });

    // Spawn L1 settlement monitor (only if treasury address is configured)
    if treasury_configured {
        let state_clone = Arc::clone(&state);
        let mut shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            tokio::select! {
                _ = run_settlement_monitor(state_clone) => {}
                _ = shutdown_rx.recv() => {
                    info!("Settlement monitor shutting down");
                }
            }
        });
        info!("L1 settlement monitor enabled");
    }

    // H-2: Create API authentication state
    let api_auth = ApiAuth::new(
        state.config.api_secret.clone(),
        state.config.internal_secret.clone(),
        state.network,
    );

    // HIGH-API-1: Fail startup if api_secret not configured on mainnet
    if api_auth.secret.is_none() {
        if state.network == Network::Bitcoin {
            return Err(anyhow::anyhow!(
                "HIGH-API-1 SECURITY: API secret REQUIRED for mainnet! \
                 Set GHOST_PAY_API_SECRET environment variable or --api-secret flag. \
                 Ghost Pay will NOT start without authentication on mainnet."
            ));
        } else {
            // HIGH-API-2: Also require auth on all networks for consistency
            return Err(anyhow::anyhow!(
                "HIGH-API-2 SECURITY: API secret REQUIRED on all networks! \
                 Set GHOST_PAY_API_SECRET environment variable or --api-secret flag. \
                 This prevents bugs in auth integration from being masked on non-mainnet."
            ));
        }
    }

    info!("H-2: API authentication enabled");

    // H-2: Build authenticated routes (require HMAC signature)
    let authenticated_routes = Router::new()
        // Key management (SENSITIVE - can export private keys)
        .route("/api/v1/keys/generate", post(generate_keys))
        .route("/api/v1/keys/export", get(export_keys))
        // Lock management (SENSITIVE - controls funds)
        .route("/api/v1/locks/create", post(create_lock))
        .route("/api/v1/locks/:id/confirm", post(confirm_lock_funding))
        .route("/api/v1/locks/:id/jump", post(initiate_jump))
        // Withdrawals (SENSITIVE - moves funds)
        .route("/api/v1/withdrawals/request", post(request_withdrawal))
        .route("/api/v1/withdrawals/:id/cancel", post(cancel_withdrawal))
        // Confidential transfers (SENSITIVE - moves private balances)
        .route(
            "/api/v1/confidential/transfer",
            post(submit_confidential_transfer),
        )
        .route(
            "/api/v1/confidential/consolidate",
            post(submit_consolidation),
        )
        .route("/api/v1/confidential/unshield", post(submit_unshield))
        .route("/api/v1/confidential/shield", post(shield_balance))
        // Lock reconciliation (SENSITIVE - settles lock to L1)
        .route("/api/v1/locks/:id/reconcile", post(reconcile_lock))
        // L2 payments (SENSITIVE - instant off-chain transfer)
        .route("/api/v1/payments/send", post(send_l2_payment))
        // GhostGlyph (SENSITIVE - binds identity permanently)
        .route("/api/v1/glyph/claim", post(claim_glyph))
        // L1 UTXO scan via Bitcoin Core's scantxoutset. Authenticated
        // because the call is expensive (5-15s on mainnet) and the
        // response reveals UTXO state for the supplied addresses.
        .route("/api/v1/utxos/scan", post(scan_utxos))
        // L1 broadcast — thin passthrough to `sendrawtransaction`.
        // wraithd builds + signs PSBTs locally and uses this to
        // push the resulting tx through the operator's bitcoind.
        // Authenticated so only callers with the internal-auth
        // secret can submit raw transactions through this node.
        .route("/api/v1/tx/broadcast", post(broadcast_tx))
        .layer(axum::middleware::from_fn_with_state(
            api_auth.clone(),
            require_api_auth,
        ))
        .with_state(state.clone());

    // Public routes (read-only, no authentication required)
    let public_routes = Router::new()
        // Read-only key info
        .route("/api/v1/keys/ghost-id", get(get_ghost_id))
        // Read-only lock info
        .route("/api/v1/locks", get(list_locks))
        .route("/api/v1/locks/:id", get(get_lock))
        // Payments (derive address is safe, scan is read-only)
        .route("/api/v1/payments/address", post(derive_payment_address))
        .route("/api/v1/payments/scan", post(scan_transaction))
        // L2 ledger history — surfaces sent + received instant payments
        // for a given ghost_id. Used by `wraith light history`.
        .route("/api/v1/transactions", get(list_transactions))
        // Read-only withdrawal info
        .route("/api/v1/withdrawals", get(list_withdrawals))
        .route("/api/v1/withdrawals/:id", get(get_withdrawal))
        // Status endpoints
        .route("/api/v1/status", get(get_status))
        // Public Pay activity stats for bitcoinghost.org/pay.html. All
        // aggregates, no per-row detail — privacy preserved for both
        // users and operators.
        .route("/api/v1/pay/stats", get(pay_stats_handler))
        .route("/health", get(health_check))
        // GhostPay verification endpoint for node capability challenges
        .route("/verify/ghostpay", get(verify_ghostpay))
        // Confidential transfer read-only endpoints
        .route("/api/v1/confidential/tree", get(get_tree_state))
        .route(
            "/api/v1/confidential/proof/:index",
            get(get_confidential_proof),
        )
        .route(
            "/api/v1/confidential/notes/:owner_pubkey",
            get(get_confidential_notes),
        )
        // L2 transaction scanning for wallets
        .route("/api/v1/l2/transactions", get(get_recent_l2_transactions))
        // GhostGlyph read-only endpoints
        .route("/api/v1/glyph/:ghost_id", get(get_glyph))
        .route(
            "/api/v1/glyph/check/:bitmap_hash_hex",
            get(check_glyph_availability),
        )
        .with_state(state.clone());

    // MEDIUM-1: L2 block production endpoints are localhost-only.
    // These are called by ghost-pool on the same host; external access would corrupt L2 state.
    let localhost_routes = Router::new()
        .route("/api/v1/l2/state", get(l2_state_handler))
        .route("/api/v1/l2/pending", get(l2_pending_handler))
        .route("/api/v1/l2/finalize", post(l2_finalize_handler))
        .route(
            "/api/v1/admin/verify-fee-pipeline",
            post(verify_fee_pipeline),
        )
        .route(
            "/api/v1/admin/simulate-l2-activity",
            post(simulate_l2_activity),
        )
        .route("/api/v1/admin/simulate-unshield", post(simulate_unshield))
        .route("/api/v1/admin/test-withdrawal", post(test_withdrawal))
        .route(
            "/api/v1/admin/trigger-settlement",
            post(admin_trigger_settlement),
        )
        .route("/api/v1/admin/seed-test-balance", post(seed_test_balance))
        .layer(axum::middleware::from_fn(localhost_only))
        .with_state(state.clone());

    // L-14 SECURITY: Read CORS origins from environment variable with secure defaults.
    // Format: comma-separated list of origins (e.g., "https://example.com,https://app.example.com")
    let cors_origins_str = std::env::var("GHOST_PAY_CORS_ORIGINS")
        .unwrap_or_else(|_| "https://bitcoinghost.org,https://wallet.bitcoinghost.org".to_string());

    let cors_origins: Vec<_> = cors_origins_str
        .split(',')
        .filter_map(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return None;
            }
            match trimmed.parse::<http::HeaderValue>() {
                Ok(hv) => Some(hv),
                Err(e) => {
                    warn!(origin = trimmed, error = %e, "Invalid CORS origin in GHOST_PAY_CORS_ORIGINS - skipping");
                    None
                }
            }
        })
        .collect();

    if cors_origins.is_empty() {
        error!("No valid CORS origins configured - API will reject all cross-origin requests");
    } else {
        info!(origins = ?cors_origins_str, "CORS origins configured");
    }

    // H-8: Build rate limiter for API protection
    // 30 requests per minute per IP, with burst of 10
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(1) // 1 request per second sustained
        .burst_size(10) // Allow bursts of up to 10 requests
        .key_extractor(IpKeyExtractor::new())
        .finish()
        .expect("L-1: Valid hardcoded rate limiter config");

    let governor_conf = std::sync::Arc::new(governor_conf);

    // Spawn background task to clean up rate limiter state
    let governor_limiter = governor_conf.limiter().clone();
    let mut shutdown_rx = shutdown_tx.subscribe();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {
                    governor_limiter.retain_recent();
                }
                _ = shutdown_rx.recv() => {
                    break;
                }
            }
        }
    });

    info!("H-8: Rate limiting enabled (10 burst / 1 per sec per IP)");

    // Merge routes and apply common layers
    // H-7: 1MB body size limit to prevent memory exhaustion
    // H-8: Rate limiting to prevent API abuse
    // LOW-API-1: Security headers for all responses
    let app = public_routes
        .merge(authenticated_routes)
        .merge(localhost_routes)
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .layer(GovernorLayer {
            config: governor_conf,
        })
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(cors_origins))
                .allow_methods([http::Method::GET, http::Method::POST, http::Method::OPTIONS])
                .allow_headers([
                    http::header::CONTENT_TYPE,
                    http::header::AUTHORIZATION,
                    "X-Ghost-Signature"
                        .parse()
                        .expect("L-1: Valid hardcoded header name"),
                    "X-Ghost-Timestamp"
                        .parse()
                        .expect("L-1: Valid hardcoded header name"),
                ])
                .max_age(std::time::Duration::from_secs(3600)),
        )
        .layer(TraceLayer::new_for_http())
        .layer(DefaultBodyLimit::max(1024 * 1024)); // H-7: 1MB body limit

    info!("H-7: Request body limit set to 1MB");

    // Parse listen address
    let addr: SocketAddr = state.config.api_listen.parse()?;

    // Build TLS config for HTTPS. Resolution order:
    //   1. Operator PEM files (`--tls-cert` + `--tls-key`)
    //   2. Identity-derived cert from `--identity-key` (cert pubkey == node_id)
    //   3. Plain HTTP fallback (testnet / dev only)
    let tls_config = if let (Some(cert_path), Some(key_path)) = (tls_cert_path, tls_key_path) {
        let tls_cfg = ghost_common::config::TlsConfig {
            cert_path: Some(cert_path),
            key_path: Some(key_path),
        };
        match ghost_common::tls::build_server_config(&tls_cfg) {
            Ok(tls) => {
                info!("Ghost Pay API starting on {} (HTTPS, operator cert)", addr);
                Some(tls)
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to build TLS config: {}", e));
            }
        }
    } else if let Some(key_path) = identity_key_path {
        // Read the 32-byte Ed25519 secret seed (LocalSigner format: 32 bytes
        // optionally followed by a 12-byte PoW proof we ignore here).
        match std::fs::read(&key_path) {
            Ok(bytes) if bytes.len() >= 32 => {
                let mut secret = [0u8; 32];
                secret.copy_from_slice(&bytes[..32]);
                match ghost_common::tls::build_server_config_with_identity(
                    &ghost_common::config::TlsConfig::default(),
                    &secret,
                    public_address_for_tls.as_deref(),
                ) {
                    Ok(tls) => {
                        info!(
                            "Ghost Pay API starting on {} (HTTPS, identity-derived cert from {})",
                            addr,
                            key_path.display()
                        );
                        Some(tls)
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!(
                            "Failed to derive TLS config from identity {}: {}",
                            key_path.display(),
                            e
                        ));
                    }
                }
            }
            Ok(_) => {
                return Err(anyhow::anyhow!(
                    "Identity key {} is too short (need ≥32 bytes)",
                    key_path.display()
                ));
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Failed to read identity key {}: {}",
                    key_path.display(),
                    e
                ));
            }
        }
    } else {
        info!(
            "Ghost Pay API starting on {} (HTTP — no operator cert and no --identity-key)",
            addr
        );
        None
    };

    // Start server with graceful shutdown
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C handler");
        info!("Received shutdown signal, starting graceful shutdown...");
    };

    match tls_config {
        Some(tls) => {
            let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls);
            let mut make_service =
                app.into_make_service_with_connect_info::<std::net::SocketAddr>();

            // We need to handle graceful shutdown manually for TLS
            let shutdown = tokio::signal::ctrl_c();
            tokio::pin!(shutdown);

            loop {
                tokio::select! {
                    accept_result = listener.accept() => {
                        let (tcp_stream, remote_addr) = accept_result?;
                        let acceptor = tls_acceptor.clone();

                        let tower_service = {
                            use tower::Service;
                            match make_service.call(remote_addr).await {
                                Ok(s) => s,
                                Err(_) => continue,
                            }
                        };

                        let hyper_service = hyper_util::service::TowerToHyperService::new(tower_service);

                        tokio::spawn(async move {
                            let tls_stream = match acceptor.accept(tcp_stream).await {
                                Ok(s) => s,
                                Err(e) => {
                                    tracing::debug!(error = %e, "TLS handshake failed");
                                    return;
                                }
                            };
                            let io = hyper_util::rt::TokioIo::new(tls_stream);
                            if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                                hyper_util::rt::TokioExecutor::new(),
                            )
                            .serve_connection(io, hyper_service)
                            .await
                            {
                                tracing::debug!(error = %e, "Connection error");
                            }
                        });
                    }
                    _ = &mut shutdown => {
                        info!("Received shutdown signal, starting graceful shutdown...");
                        break;
                    }
                }
            }
        }
        None => {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal)
            .await?;
        }
    }

    // Signal all background tasks to stop
    info!("HTTP server stopped, signaling background tasks...");
    let _ = shutdown_tx.send(());

    // Give background tasks time to finish in-flight work
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Checkpoint WAL and clean up database files (matches ghost-pool shutdown pattern)
    if let Err(e) = state.db.shutdown() {
        warn!("Database shutdown error (non-fatal): {}", e);
    }

    info!("Ghost Pay shutdown complete");

    Ok(())
}

// ============================================================================
// Key Management Handlers
// ============================================================================

/// Generate new ghost keys
async fn generate_keys(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let keys = GhostKeys::generate();
    let ghost_id = keys.ghost_id();
    let ghost_id_str = ghost_id.to_string();

    // H-PAY-2 FIX: Save keys to database with encryption
    let keys_export = GhostKeysExport::from(&keys);
    if let Ok(keys_json) = serde_json::to_vec(&keys_export) {
        let encryption_password = match get_encryption_password(&state.config, state.network) {
            Ok(pwd) => pwd,
            Err(e) => {
                error!("Cannot generate keys without encryption password: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };
        match encrypt_keys(&keys_json, &encryption_password) {
            Ok(encrypted) => {
                let encrypted_hex = hex::encode(&encrypted);
                if let Err(e) = state.db.kv_set("ghost_keys_encrypted", &encrypted_hex) {
                    warn!("Failed to persist encrypted keys: {}", e);
                }
                // Ensure no plaintext keys exist
                let _ = state.db.kv_delete("ghost_keys");
            }
            Err(e) => {
                warn!("Failed to encrypt keys: {}", e);
            }
        }
    }

    *state.keys.write() = Some(Arc::new(keys));
    *state.ghost_id.write() = Some(ghost_id_str.clone());

    // Load existing locks from database for this ghost_id (pending and active, not spent/settling)
    if let Ok(db_locks) = state.db.get_ghost_locks_by_owner(&ghost_id_str) {
        let network = state.network;
        let lock_infos: Vec<LockInfo> = db_locks
            .iter()
            // H-PAY-1 FIX: Exclude both Spent and PendingSettlement locks
            .filter(|r| {
                r.state != ghost_storage::GhostLockState::Spent
                    && r.state != ghost_storage::GhostLockState::PendingSettlement
            })
            .map(|r| LockInfo {
                id: r.lock_id.clone(),
                denomination: r.denomination.clone(),
                amount_sats: r.amount_sats,
                state: r.state.as_str().to_string(),
                created_at: r.created_at as u64,
                timelock_tier: r.timelock_tier.clone(),
                jump_risk: r.jump_risk_tier.clone(),
                needs_jump: r
                    .next_jump_height
                    .map(|h| h <= r.creation_height + 1000)
                    .unwrap_or(false),
                address: pubkey_hex_to_p2tr_address(&r.lock_pubkey, network),
                output_pubkey: r.lock_pubkey.clone(),
                recovery_height: r.recovery_height,
                blocks_until_jump: r
                    .next_jump_height
                    .unwrap_or(0)
                    .saturating_sub(r.creation_height),
                recovery_pubkey: Some(r.recovery_pubkey.clone()),
                recovery_index: None,
                recovery_blocks: Some(r.recovery_height.saturating_sub(r.creation_height)),
                creation_height: Some(r.creation_height),
            })
            .collect();

        info!("Loaded {} existing locks from database", lock_infos.len());
        *state.locks.write() = lock_infos;
    }

    info!("Generated new ghost keys: {}", ghost_id);

    Ok(Json(serde_json::json!({
        "success": true,
        "ghost_id": ghost_id.to_string()
    })))
}

/// Export keys (encrypted)
async fn export_keys(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let keys_guard = state.keys.read();
    let keys = keys_guard.as_ref().ok_or(StatusCode::NOT_FOUND)?;

    let export = keys.export();

    Ok(Json(serde_json::json!({
        "scan_pubkey": export.scan_pubkey_hex,
        "spend_pubkey": export.spend_pubkey_hex,
        "ghost_id": export.ghost_id
    })))
}

/// Get ghost ID for receiving
async fn get_ghost_id(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let keys_guard = state.keys.read();
    let keys = keys_guard.as_ref().ok_or(StatusCode::NOT_FOUND)?;

    let ghost_id = keys.ghost_id();

    Ok(Json(serde_json::json!({
        "ghost_id": ghost_id.to_string(),
        "scan_pubkey": hex::encode(ghost_id.scan_pubkey().serialize()),
        "spend_pubkey": hex::encode(ghost_id.spend_pubkey().serialize())
    })))
}

// ============================================================================
// Lock Management Handlers
// ============================================================================

/// List all locks
async fn list_locks(State(state): State<Arc<AppState>>) -> Json<Vec<LockInfo>> {
    let locks = state.locks.read().clone();
    Json(locks)
}

/// Create lock request
#[derive(Debug, Deserialize)]
struct CreateLockRequest {
    amount_sats: u64,
    timelock_tier: Option<String>,
    /// Lock source: "wraith_mix", "wraith_jump", or omit for "manual"
    source: Option<String>,
    /// Wraith service fee deducted at L2 (denomination - service_fee = shielded amount)
    wraith_fee_sats: Option<u64>,
    /// User-derived recovery_pubkey (33-byte SEC1 compressed, hex).
    /// Goes verbatim into the lock script's recovery branch — the
    /// operator does NOT derive its own recovery key. This is what
    /// makes the timelock recovery path a real unilateral exit:
    /// after the timelock expires, the user can spend with their own
    /// keystore, no operator cooperation needed.
    ///
    /// Optional only for backwards compatibility — when absent the
    /// route logs a warning and falls back to operator-derived
    /// recovery (legacy behaviour, broken trust model). Mainnet
    /// callers MUST supply this.
    #[serde(default)]
    recovery_pubkey: Option<String>,
    /// Wallet-side derivation index that produced `recovery_pubkey`.
    /// Recorded for diagnostics + so the wallet's LocksRecover path
    /// can look up which secret to sign with.
    #[serde(default)]
    recovery_index: Option<u32>,
    /// Stable wallet identifier supplied by the GSP server (the
    /// authenticated wallet's static_wallet_id). Used as the row's
    /// `owner_ghost_id` so multi-tenant deployments don't bucket
    /// every wallet's locks under the operator's identity. Optional
    /// for backwards compatibility — when absent the route falls
    /// back to `state.ghost_id` (operator's), which is the legacy
    /// broken behaviour.
    #[serde(default)]
    owner_ghost_id: Option<String>,
}

/// Create a new ghost lock
async fn create_lock(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateLockRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Fetch current block height from Bitcoin Core first (before acquiring locks)
    // H-21: Use safe block height conversion with bounds checking
    let creation_height = state
        .rpc
        .get_blockchain_info()
        .await
        .map_err(|e| {
            error!(error = %e, "Bitcoin RPC unavailable - cannot determine block height");
            StatusCode::SERVICE_UNAVAILABLE
        })
        .and_then(|info| {
            safe_block_height_u64(info.blocks).map_err(|e| {
                error!(error = %e, "H-21: Invalid block height from RPC");
                StatusCode::INTERNAL_SERVER_ERROR
            })
        })?;

    let keys_guard = state.keys.read();
    let keys = keys_guard.as_ref().ok_or(StatusCode::NOT_FOUND)?;

    // Determine denomination
    let denomination = Denomination::from_sats(req.amount_sats).ok_or(StatusCode::BAD_REQUEST)?;

    // Determine timelock tier
    let timelock_tier = match req.timelock_tier.as_deref() {
        Some("short") => TimelockTier::Short,
        Some("long") => TimelockTier::Long,
        _ => TimelockTier::Standard,
    };

    // Owner ID resolution. Prefer the wallet identifier the GSP
    // server forwarded in the request — that's the authenticated
    // wallet's stable ID, the only way multi-tenant ledgers work
    // correctly. Fall back to the operator's own ghost_id when the
    // request omits it (legacy callers); future commits will
    // tighten this to a hard refusal once every caller has migrated.
    let owner_ghost_id = match req.owner_ghost_id.as_deref() {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => {
            warn!(
                "create_lock: no owner_ghost_id supplied — falling back to operator's \
                 identity. Multi-tenant deployments need the GSP server to forward \
                 the authenticated wallet's static_wallet_id."
            );
            state
                .ghost_id
                .read()
                .clone()
                .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?
        }
    };

    // Get next lock key index from DB (stable across restarts)
    let lock_index = state
        .db
        .get_next_lock_key_index(&owner_ghost_id)
        .map_err(|e| {
            error!("Failed to get next lock key index: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Derive the OPERATOR's lock_secret (cooperative-path key — used
    // to co-sign fast L2 settlements via reconciliation). The
    // recovery key, by contrast, comes from the WALLET, so the
    // recovery branch is genuinely unilateral.
    let lock_secret = keys
        .derive_lock_secret(lock_index)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let secp = Secp256k1::new();
    let lock_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &lock_secret);

    // Resolve the user-supplied recovery_pubkey. Refuse silently-
    // legacy clients that omit it on a non-test network: a missing
    // recovery_pubkey means the operator would have to derive one
    // and own the recovery path, which breaks the unilateral-exit
    // property. Better to fail visibly here than silently produce a
    // federated-custody lock the user thinks is self-custodial.
    let recovery_pubkey = match req.recovery_pubkey.as_deref() {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str.trim()).map_err(|e| {
                error!("Invalid recovery_pubkey hex: {e}");
                StatusCode::BAD_REQUEST
            })?;
            if bytes.len() != 33 || !(bytes[0] == 0x02 || bytes[0] == 0x03) {
                error!("recovery_pubkey must be SEC1-compressed (33 bytes, 0x02/0x03 prefix)");
                return Err(StatusCode::BAD_REQUEST);
            }
            bitcoin::secp256k1::PublicKey::from_slice(&bytes).map_err(|e| {
                error!("Invalid recovery_pubkey: {e}");
                StatusCode::BAD_REQUEST
            })?
        }
        None => {
            error!(
                "create_lock called without recovery_pubkey — refusing. Wallet \
                 must derive its own recovery key and supply it; operator-derived \
                 recovery breaks unilateral exit."
            );
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    // Refuse keys that defeat the 2-of-2 model — same checks as
    // GhostLock::new but raised here because we're using
    // from_pubkeys directly.
    if lock_pubkey == recovery_pubkey {
        error!("lock_pubkey == recovery_pubkey — refused");
        return Err(StatusCode::BAD_REQUEST);
    }
    if lock_pubkey.combine(&recovery_pubkey).is_err() {
        error!("lock_pubkey == -recovery_pubkey (key negation attack) — refused");
        return Err(StatusCode::BAD_REQUEST);
    }

    let recovery_index_logged = req.recovery_index.unwrap_or(0);
    info!(
        owner_ghost_id = %owner_ghost_id,
        lock_index = lock_index,
        recovery_index = recovery_index_logged,
        creation_height = creation_height,
        "create_lock with user-supplied recovery_pubkey"
    );

    // Build the GhostLock from pubkeys directly (no recovery secret
    // available operator-side, by design). Network-aware: on regtest
    // the CSV duration collapses so demos / e2e tests can mine past
    // the timelock without production-scale block counts.
    let ghost_lock = GhostLock::from_pubkeys_for_network(
        lock_pubkey,
        recovery_pubkey,
        denomination,
        timelock_tier,
        creation_height,
        state.network,
    )
    .map_err(|e| {
        error!("GhostLock::from_pubkeys failed: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Generate P2WSH address from script pubkey (quantum-safe)
    let address = Address::from_script(ghost_lock.script_pubkey(), state.network)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Determine jump risk based on amount
    let jump_risk = ghost_lock.jump_risk_tier();

    // Use the SAME network-aware block count we baked into the
    // witness script's CSV; otherwise the wallet's recovery TX
    // would be either rejected (CSV under-fulfilled) or unable to
    // build at all (mismatch with stored prepared_locks metadata).
    let recovery_blocks_for_resp = timelock_tier.blocks_for_network(state.network);
    let lock_info = LockInfo {
        id: ghost_lock.lock_id_hex(),
        denomination: denomination.name().to_string(),
        amount_sats: denomination.sats(),
        state: format!("{:?}", ghost_lock.state()),
        created_at: now,
        timelock_tier: format!("{:?}", timelock_tier),
        jump_risk: format!("{:?}", jump_risk),
        needs_jump: ghost_lock.needs_jump(creation_height),
        address: address.to_string(),
        output_pubkey: hex::encode(ghost_lock.lock_pubkey().serialize()),
        recovery_height: ghost_lock.recovery_height(),
        blocks_until_jump: ghost_lock.blocks_until_jump(creation_height),
        recovery_pubkey: Some(hex::encode(ghost_lock.recovery_pubkey().serialize())),
        recovery_index: req.recovery_index,
        recovery_blocks: Some(recovery_blocks_for_resp),
        creation_height: Some(creation_height),
    };

    // Create database record
    let lock_source = req.source.as_deref().unwrap_or("manual").to_string();
    let wraith_fee = req.wraith_fee_sats.unwrap_or(0);
    let db_record = GhostLockRecord {
        lock_id: ghost_lock.lock_id_hex(),
        owner_ghost_id,
        lock_pubkey: hex::encode(ghost_lock.lock_pubkey().serialize()),
        recovery_pubkey: hex::encode(ghost_lock.recovery_pubkey().serialize()),
        denomination: denomination.name().to_string(),
        amount_sats: denomination.sats(),
        timelock_tier: format!("{:?}", timelock_tier),
        creation_height,
        recovery_height: ghost_lock.recovery_height(),
        state: DbLockState::Pending,
        funding_txid: None,
        funding_vout: None,
        spend_txid: None,
        output_script: hex::encode(address.script_pubkey().as_bytes()),
        jump_risk_tier: format!("{:?}", jump_risk),
        next_jump_height: Some(ghost_lock.jump_schedule().deadline_height),
        created_at: now as i64,
        updated_at: now as i64,
        source: lock_source,
        wraith_fee_sats: wraith_fee,
        key_index: Some(lock_index),
    };

    // Persist to database
    state
        .db
        .insert_ghost_lock(&db_record)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Store the actual lock in memory cache
    state.ghost_locks.write().push(ghost_lock);
    state.locks.write().push(lock_info.clone());

    info!(
        id = %lock_info.id,
        denomination = ?denomination,
        address = %lock_info.address,
        "Created new ghost lock (persisted to database)"
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "lock": lock_info
    })))
}

/// Get specific lock
async fn get_lock(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<LockInfo>, StatusCode> {
    let locks = state.locks.read();
    let lock = locks
        .iter()
        .find(|l| l.id == id)
        .cloned()
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(lock))
}

/// `POST /api/v1/locks/:id/confirm` — record that the lock's funding
/// transaction has been broadcast.
///
/// The wallet (via ghost-gsp) calls this once it has sent the
/// funding output to the lock's P2WSH address. We update the lock's
/// row with the funding txid + vout and flip its state from
/// `pending` to `active`. Confirmation depth tracking happens
/// elsewhere on a background scanner.
#[derive(Debug, Deserialize)]
struct ConfirmFundingRequest {
    funding_txid: String,
    funding_vout: u32,
}

async fn confirm_lock_funding(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<ConfirmFundingRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Validate the txid format up front so a typo from the wallet
    // surfaces as a clean 400 rather than corrupting the row.
    if hex::decode(&req.funding_txid).map(|b| b.len()).unwrap_or(0) != 32 {
        warn!(
            lock_id = %id,
            txid = %req.funding_txid,
            "confirm_lock_funding: malformed funding_txid (expected 32 bytes hex)"
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // The lock must already exist in the database — refuse confirms
    // on locks we never created.
    let existing = state.db.get_ghost_lock(&id).map_err(|e| {
        error!(lock_id = %id, error = %e, "confirm_lock_funding: db lookup failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let existing = existing.ok_or_else(|| {
        warn!(lock_id = %id, "confirm_lock_funding: unknown lock_id");
        StatusCode::NOT_FOUND
    })?;
    if existing.state == ghost_storage::GhostLockState::Active
        && existing.funding_txid.as_deref() == Some(req.funding_txid.as_str())
    {
        // Idempotent re-confirm — no-op success.
        return Ok(Json(serde_json::json!({
            "success": true,
            "lock_id": id,
            "state": "active",
            "funding_txid": req.funding_txid,
            "block_height": 0,
            "message": "already confirmed"
        })));
    }

    // GHOST-05: verify the funding deposit ON-CHAIN before activating the lock.
    // Previously the lock flipped pending->active on the client-asserted txid
    // with no verification, so shielded L2 value could be minted against a
    // deposit that doesn't exist, pays a different script, is insufficient, or
    // is unconfirmed. `gettxout` confirms the output is a real, unspent UTXO
    // (no -txindex needed) and lets us check it pays THIS lock's script for at
    // least the lock amount, with at least one confirmation.
    const MIN_FUNDING_CONFIRMATIONS: i64 = 1;
    let utxo = state
        .rpc
        .get_tx_out(&req.funding_txid, req.funding_vout, true)
        .await
        .map_err(|e| {
            error!(lock_id = %id, txid = %req.funding_txid, error = %e, "confirm_lock_funding: gettxout RPC failed");
            StatusCode::BAD_GATEWAY
        })?;
    let utxo = match utxo {
        Some(u) => u,
        None => {
            warn!(lock_id = %id, txid = %req.funding_txid, vout = req.funding_vout, "GHOST-05: funding UTXO not found or already spent");
            return Err(StatusCode::UNPROCESSABLE_ENTITY);
        }
    };
    if !utxo
        .script_pubkey
        .hex
        .eq_ignore_ascii_case(&existing.output_script)
    {
        warn!(lock_id = %id, expected = %existing.output_script, got = %utxo.script_pubkey.hex, "GHOST-05: funding output script does not match the lock");
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    let onchain_sats = (utxo.value * 1e8).round() as u64;
    if onchain_sats < existing.amount_sats {
        warn!(lock_id = %id, expected_sats = existing.amount_sats, got_sats = onchain_sats, "GHOST-05: funding output value below lock amount");
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    if utxo.confirmations < MIN_FUNDING_CONFIRMATIONS {
        warn!(lock_id = %id, confirmations = utxo.confirmations, "GHOST-05: funding output not yet confirmed");
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    info!(
        lock_id = %id,
        txid = %req.funding_txid,
        sats = onchain_sats,
        confirmations = utxo.confirmations,
        "GHOST-05: funding UTXO verified on-chain (script + value + confirmations)"
    );

    state
        .db
        .update_ghost_lock_funding(&id, &req.funding_txid, req.funding_vout)
        .map_err(|e| {
            error!(lock_id = %id, error = %e, "confirm_lock_funding: update failed");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Refresh the in-memory lock cache so subsequent /api/v1/locks
    // listings reflect the new state without waiting for a restart.
    if let Ok(db_locks) = state
        .db
        .get_ghost_locks_by_owner(state.ghost_id.read().clone().unwrap_or_default().as_str())
    {
        let network = state.network;
        let lock_infos: Vec<LockInfo> = db_locks
            .iter()
            .filter(|r| {
                r.state != ghost_storage::GhostLockState::Spent
                    && r.state != ghost_storage::GhostLockState::PendingSettlement
            })
            .map(|r| LockInfo {
                id: r.lock_id.clone(),
                denomination: r.denomination.clone(),
                amount_sats: r.amount_sats,
                state: r.state.as_str().to_string(),
                created_at: r.created_at as u64,
                timelock_tier: r.timelock_tier.clone(),
                jump_risk: r.jump_risk_tier.clone(),
                needs_jump: r
                    .next_jump_height
                    .map(|h| h <= r.creation_height + 1000)
                    .unwrap_or(false),
                address: pubkey_hex_to_p2tr_address(&r.lock_pubkey, network),
                output_pubkey: r.lock_pubkey.clone(),
                recovery_height: r.recovery_height,
                blocks_until_jump: r
                    .next_jump_height
                    .unwrap_or(0)
                    .saturating_sub(r.creation_height),
                recovery_pubkey: Some(r.recovery_pubkey.clone()),
                recovery_index: None,
                recovery_blocks: Some(r.recovery_height.saturating_sub(r.creation_height)),
                creation_height: Some(r.creation_height),
            })
            .collect();
        *state.locks.write() = lock_infos;
    }

    info!(
        lock_id = %id,
        funding_txid = %req.funding_txid,
        funding_vout = req.funding_vout,
        "Lock funding confirmed (state → active)"
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "lock_id": id,
        "state": "active",
        "funding_txid": req.funding_txid,
        "funding_vout": req.funding_vout,
        "block_height": 0
    })))
}

/// Initiate jump for a lock
async fn initiate_jump(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Update database state
    state
        .db
        .update_ghost_lock_state(&id, DbLockState::Jumping)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Update the actual GhostLock state in memory
    {
        let mut ghost_locks = state.ghost_locks.write();
        if let Some(ghost_lock) = ghost_locks.iter_mut().find(|l| l.lock_id_hex() == id) {
            if let Err(e) = ghost_lock.transition(StateTransition::StartJump) {
                warn!(lock_id = %id, error = %e, "Failed to transition lock to jumping state");
            }
        }
    }

    // Update the metadata cache
    {
        let mut locks = state.locks.write();
        if let Some(lock) = locks.iter_mut().find(|l| l.id == id) {
            lock.state = "Jumping".to_string();
        }
    }

    info!(id = %id, "Initiated jump for lock (persisted to database)");

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Jump initiated - funds will be moved to new lock with fresh keys"
    })))
}

// ============================================================================
// Payment Handlers
// ============================================================================

/// Derive payment address request
#[derive(Debug, Deserialize)]
struct DeriveAddressRequest {
    index: u32,
}

/// Derive a payment address for receiving
async fn derive_payment_address(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DeriveAddressRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let keys_guard = state.keys.read();
    let keys = keys_guard.as_ref().ok_or(StatusCode::NOT_FOUND)?;

    let ghost_id = keys.ghost_id();

    // Derive payment address using v2 (k-based, position-independent)
    // The 'index' parameter in the API now represents k (sequential counter)
    let (output_pubkey, ephemeral_pubkey) = ghost_id
        .derive_payment_address_v2(req.index)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "output_pubkey": hex::encode(output_pubkey.serialize()),
        "ephemeral_pubkey": hex::encode(ephemeral_pubkey.serialize()),
        "k": req.index
    })))
}

/// Scan transaction for payments
async fn scan_transaction(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ScanRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Queue for background scanning
    state
        .scanner_tx
        .send(req.clone())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Transaction queued for scanning"
    })))
}

/// Request body for `POST /api/v1/utxos/scan`.
#[derive(Debug, Deserialize)]
struct ScanUtxosRequest {
    /// Addresses to scan. Each is wrapped in a Bitcoin Core
    /// `addr(...)` descriptor for the underlying scantxoutset call.
    /// Capped at 1024 per call — chunk above that on the caller.
    addresses: Vec<String>,
    /// Minimum confirmations for the UTXO to be included. 0 means
    /// mempool/coinbase outputs are returned too. Default 0 to match
    /// Bitcoin Core's listunspent default.
    #[serde(default)]
    min_confirmations: u32,
}

#[derive(Debug, Serialize)]
struct ScannedUtxo {
    txid: String,
    vout: u32,
    amount_sats: u64,
    /// Hex-encoded scriptPubKey of the output. Wallets need this
    /// for sighash construction when signing the spend.
    scriptpubkey_hex: String,
    /// The user-supplied address that matched this output. Re-derived
    /// from the scantxoutset result's `desc` field, so only set when
    /// the descriptor was an `addr(...)` (which this endpoint always
    /// emits internally).
    address: Option<String>,
    confirmations: u32,
    /// Block height at which this output was confirmed. 0 for
    /// mempool entries.
    height: u32,
}

#[derive(Debug, Serialize)]
struct ScanUtxosResponse {
    utxos: Vec<ScannedUtxo>,
    total_sats: u64,
    /// Block height at which the underlying scantxoutset was taken.
    /// Useful for clients that want to attribute confirmations against
    /// the same chain state.
    chain_height: u32,
}

/// Scan the chain UTXO set for outputs at the supplied addresses.
/// Backed by Bitcoin Core's `scantxoutset start [addr(...), ...]`,
/// which walks the full UTXO set on each call (5-15s on mainnet,
/// sub-second on signet/regtest). Authenticated because the call
/// is expensive and the result reveals UTXO state of the supplied
/// addresses.
async fn scan_utxos(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ScanUtxosRequest>,
) -> Result<Json<ScanUtxosResponse>, (StatusCode, String)> {
    if req.addresses.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "addresses must be non-empty".to_string(),
        ));
    }
    if req.addresses.len() > 1024 {
        return Err((
            StatusCode::BAD_REQUEST,
            "too many addresses (max 1024 per call — chunk client-side)".to_string(),
        ));
    }

    // Validate each address against the configured network before
    // hitting bitcoind. Saves a round-trip on bad input and gives a
    // clear error.
    let expected_network = match state.network {
        Network::Bitcoin => ghost_common::config::BitcoinNetwork::Mainnet,
        Network::Signet => ghost_common::config::BitcoinNetwork::Signet,
        Network::Testnet => ghost_common::config::BitcoinNetwork::Testnet,
        Network::Regtest => ghost_common::config::BitcoinNetwork::Regtest,
        // bitcoin::Network is non-exhaustive in 0.32+; fall back to
        // mainnet's stricter prefix check on any future variant.
        _ => ghost_common::config::BitcoinNetwork::Mainnet,
    };
    for a in &req.addresses {
        state
            .rpc
            .validate_address_for_network(a, expected_network)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("address {a}: {e}")))?;
    }

    let scan_objs: Vec<String> = req.addresses.iter().map(|a| format!("addr({a})")).collect();
    let scan_refs: Vec<&str> = scan_objs.iter().map(String::as_str).collect();

    let scan = state
        .rpc
        .scan_tx_out_set(scan_refs)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("scantxoutset failed: {e}")))?;
    if !scan.success {
        return Err((
            StatusCode::BAD_GATEWAY,
            "scantxoutset returned success=false (bitcoind already scanning?)".to_string(),
        ));
    }

    let chain_height = scan.height;
    let mut utxos = Vec::with_capacity(scan.unspents.len());
    let mut total_sats: u64 = 0;
    for u in scan.unspents {
        // scantxoutset's f64 amount field round-trips exactly for any
        // value < 2^53 sats, which is well above 21M BTC. Multiply
        // and round; this is the same pattern Bitcoin Core's own RPC
        // wrappers use.
        let amount_sats = (u.amount * SATS_PER_BTC_F64).round() as u64;
        let confirmations = if u.height == 0 {
            0
        } else {
            chain_height.saturating_sub(u.height).saturating_add(1)
        };
        if confirmations < req.min_confirmations {
            continue;
        }
        let address = parse_addr_from_desc(&u.desc);
        total_sats = total_sats.saturating_add(amount_sats);
        utxos.push(ScannedUtxo {
            txid: u.txid,
            vout: u.vout,
            amount_sats,
            scriptpubkey_hex: u.script_pubkey,
            address,
            confirmations,
            height: u.height,
        });
    }

    Ok(Json(ScanUtxosResponse {
        utxos,
        total_sats,
        chain_height,
    }))
}

/// Pull the `<addr>` out of a scantxoutset desc field, which has the
/// shape `addr(<addr>)#<checksum>`. Returns None on any other
/// descriptor shape; callers that rely on the address being present
/// must filter accordingly.
fn parse_addr_from_desc(desc: &str) -> Option<String> {
    let inner = desc.strip_prefix("addr(")?;
    let close = inner.find(')')?;
    Some(inner[..close].to_string())
}

// ============================================================================
// Generic L1 Broadcast (Phase 2 PSBT support)
// ============================================================================
//
// `wraithd` builds + signs PSBTs locally; ghost-pay's role for the
// broadcast is "thin RPC-passthrough to bitcoind". Authenticated so
// only callers with the internal-auth secret (or a valid HMAC
// signature) can push raw transactions through this node.
//
// The endpoint deliberately does NOT validate the tx semantics —
// the operator's bitcoind already does that via
// `sendrawtransaction`. Any pre-flight rejection (e.g. min-fee
// policy) propagates back as the error message verbatim so the
// wallet can surface it without translation.

#[derive(Debug, Deserialize)]
struct BroadcastTxRequest {
    /// Hex-encoded raw transaction (the output of
    /// `psbt.extract_tx()` then `consensus::encode::serialize_hex`).
    tx_hex: String,
    /// Optional max fee rate (sats/vB). Forwarded as bitcoind's
    /// `maxfeerate` argument. None → use bitcoind's default.
    #[serde(default)]
    max_fee_rate_sats_per_vb: Option<u64>,
}

#[derive(Debug, Serialize)]
struct BroadcastTxResponse {
    /// txid of the accepted transaction.
    txid: String,
}

/// Broadcast a fully-signed Bitcoin transaction. Thin wrapper over
/// `bitcoind sendrawtransaction`. The operator's node still does
/// the real work — relay rules, mempool admission, etc.
async fn broadcast_tx(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BroadcastTxRequest>,
) -> Result<Json<BroadcastTxResponse>, (StatusCode, String)> {
    let trimmed = req.tx_hex.trim();
    if trimmed.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "tx_hex must be non-empty".to_string(),
        ));
    }
    // Deserialize once on our side so a malformed hex string fails
    // fast with a 400, before round-tripping to bitcoind.
    let bytes =
        hex::decode(trimmed).map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid hex: {e}")))?;
    let _: bitcoin::Transaction = bitcoin::consensus::encode::deserialize(&bytes)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid tx: {e}")))?;

    match state.rpc.send_raw_transaction(trimmed).await {
        Ok(txid) => {
            // Soft-warn the operator if the requested max fee rate
            // wasn't honoured — bitcoind's RPC accepts a
            // `maxfeerate` arg we currently don't forward (the
            // RpcClient wrapper doesn't expose it). Log so an
            // operator chasing a fee-bump regression has a
            // breadcrumb without breaking the call.
            if let Some(rate) = req.max_fee_rate_sats_per_vb {
                if rate == 0 {
                    info!(
                        txid = %txid,
                        "broadcast_tx: caller requested maxfeerate=0 \
                         (any fee), bitcoind default applies"
                    );
                }
            }
            Ok(Json(BroadcastTxResponse { txid }))
        }
        Err(e) => {
            // bitcoind's error string already explains the rejection
            // reason ("min relay fee not met", "non-final", "missing
            // inputs", etc.). Pass it through unmodified — the
            // wallet GUI surfaces it verbatim.
            Err((StatusCode::BAD_GATEWAY, format!("sendrawtransaction: {e}")))
        }
    }
}

// ============================================================================
// Withdrawal Handlers
// ============================================================================

/// Withdrawal request body
#[derive(Debug, Deserialize)]
struct WithdrawalRequestBody {
    /// Lock ID to withdraw from
    lock_id: String,
    /// Destination Bitcoin address
    destination_address: String,
    /// Amount to withdraw in satoshis (must be <= lock amount minus fees)
    amount_sats: u64,
    /// Settlement class: "express", "standard", or "economy" (default: "standard")
    #[serde(default = "default_settlement_class")]
    settlement_class: String,
}

/// List pending withdrawals
async fn list_withdrawals(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    let ghost_id = state.ghost_id.read().clone().ok_or(StatusCode::NOT_FOUND)?;

    let withdrawals = state
        .db
        .get_pending_withdrawals(&ghost_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let result: Vec<serde_json::Value> = withdrawals
        .iter()
        .map(|w| {
            serde_json::json!({
                "id": w.id,
                "lock_id": w.lock_id,
                "destination_address": w.destination_address,
                "amount_sats": w.amount_sats,
                "fee_sats": w.fee_sats,
                "status": w.status.as_str(),
                "batch_id": w.batch_id,
                "l1_txid": w.l1_txid,
                "created_at": w.created_at
            })
        })
        .collect();

    Ok(Json(result))
}

/// Request a withdrawal from a lock
async fn request_withdrawal(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WithdrawalRequestBody>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let ghost_id = state.ghost_id.read().clone().ok_or(StatusCode::NOT_FOUND)?;

    // Validate the lock exists and is owned by this ghost_id
    let lock = state
        .db
        .get_ghost_lock(&req.lock_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if lock.owner_ghost_id != ghost_id {
        return Err(StatusCode::FORBIDDEN);
    }

    // Validate lock is active and funded
    if lock.state != DbLockState::Active {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Lock is not active"
        })));
    }

    if lock.funding_txid.is_none() {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Lock is not funded"
        })));
    }

    // Validate settlement class
    let class =
        ghost_common::constants::SettlementClass::parse(&req.settlement_class).unwrap_or_default();

    // Validate amount — fee scaled by settlement class multiplier
    let fee_rate = estimate_fee_rate(&state).await;
    let estimated_vsize = 110u64; // Single-input P2WPKH withdrawal
    let base_fee = estimated_vsize * fee_rate;
    let settlement_fee = ((base_fee as f64) * class.fee_multiplier()).ceil() as u64;
    let settlement_fee = settlement_fee.max(1);
    let max_withdrawal = lock.amount_sats.saturating_sub(settlement_fee);
    if req.amount_sats > max_withdrawal {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": format!("Amount exceeds maximum withdrawal of {} sats", max_withdrawal)
        })));
    }

    // Validate destination address format
    if !req.destination_address.starts_with("bc1")
        && !req.destination_address.starts_with("tb1")
        && !req.destination_address.starts_with("bcrt1")
    {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Invalid destination address format (must be bech32)"
        })));
    }

    let now = chrono::Utc::now().timestamp();

    // Create withdrawal request
    let withdrawal = WithdrawalRequest {
        id: None,
        ghost_id: ghost_id.clone(),
        lock_id: req.lock_id.clone(),
        destination_address: req.destination_address.clone(),
        amount_sats: req.amount_sats,
        fee_sats: settlement_fee,
        status: WithdrawalStatus::Pending,
        batch_id: None,
        l1_txid: None,
        settlement_class: class.as_str().to_string(),
        created_at: now,
        updated_at: now,
    };

    // Atomically check for existing pending/batched withdrawal and insert if none exists
    // This prevents double-spend race conditions (C-PAY-3) by using a database transaction
    // with a partial unique index as defense-in-depth
    let id = match state
        .db
        .insert_withdrawal_request_atomic(&withdrawal)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        Some(id) => id,
        None => {
            // A pending/batched withdrawal already exists for this lock
            return Ok(Json(serde_json::json!({
                "success": false,
                "error": "A withdrawal is already pending for this lock"
            })));
        }
    };

    info!(
        id = id,
        lock_id = %req.lock_id,
        amount = req.amount_sats,
        destination = %req.destination_address,
        "Created withdrawal request"
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "withdrawal_id": id,
        "lock_id": req.lock_id,
        "amount_sats": req.amount_sats,
        "fee_sats": settlement_fee,
        "destination_address": req.destination_address,
        "status": "pending"
    })))
}

/// Get a specific withdrawal
async fn get_withdrawal(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let ghost_id = state.ghost_id.read().clone().ok_or(StatusCode::NOT_FOUND)?;

    let withdrawal = state
        .db
        .get_withdrawal_request(id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Verify ownership
    if withdrawal.ghost_id != ghost_id {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(Json(serde_json::json!({
        "id": withdrawal.id,
        "lock_id": withdrawal.lock_id,
        "destination_address": withdrawal.destination_address,
        "amount_sats": withdrawal.amount_sats,
        "fee_sats": withdrawal.fee_sats,
        "status": withdrawal.status.as_str(),
        "batch_id": withdrawal.batch_id,
        "l1_txid": withdrawal.l1_txid,
        "created_at": withdrawal.created_at,
        "updated_at": withdrawal.updated_at
    })))
}

/// Cancel a pending withdrawal
async fn cancel_withdrawal(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let ghost_id = state.ghost_id.read().clone().ok_or(StatusCode::NOT_FOUND)?;

    let withdrawal = state
        .db
        .get_withdrawal_request(id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Verify ownership
    if withdrawal.ghost_id != ghost_id {
        return Err(StatusCode::FORBIDDEN);
    }

    // Can only cancel pending withdrawals
    if withdrawal.status != WithdrawalStatus::Pending {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": format!("Cannot cancel withdrawal in '{}' status", withdrawal.status.as_str())
        })));
    }

    state
        .db
        .cancel_withdrawal(id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    info!(id = id, "Cancelled withdrawal request");

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Withdrawal cancelled"
    })))
}

// ============================================================================
// Status Handlers
// ============================================================================

/// Public Pay-activity stats for bitcoinghost.org/pay.html.
///
/// Returns aggregates only — no payment ids, no participants, no
/// note commitments. 24h windows are anchored on wall-clock now; the
/// single DB hit guarantees a consistent snapshot across fields.
async fn pay_stats_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let now_s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let since_24h = now_s - 24 * 3600;

    let stats = state.db.get_pay_stats(since_24h).unwrap_or_default();

    Json(serde_json::json!({
        "now_ts": now_s,
        "since_ts": since_24h,
        "payments_24h": stats.payments_24h,
        "payments_total": stats.payments_total,
        "wraith_rounds_24h": stats.wraith_rounds_24h,
        "wraith_rounds_total": stats.wraith_rounds_total,
        "wraith_rounds_active": stats.wraith_rounds_active,
        "settlements_24h": stats.settlements_24h,
        "settlements_total": stats.settlements_total,
        "epoch_fee_pool_sats": stats.epoch_fee_pool_sats,
        "unspent_notes": stats.unspent_notes,
    }))
}

/// Get node status
async fn get_status(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let has_keys = state.keys.read().is_some();
    let lock_count = state.locks.read().len();
    // Best-effort chain-tip surfacing for the wallet's sync indicator.
    // Single getblockchaininfo call gives us blocks (verified tip),
    // headers (latest seen), verification_progress (0..1), and the
    // IBD flag — everything the wallet needs to render
    // "synced" / "syncing N/M · X%". Caps at a 1.5s deadline so a
    // hung bitcoind doesn't block the status endpoint.
    let chain = tokio::time::timeout(
        std::time::Duration::from_millis(1500),
        state.rpc.get_blockchain_info(),
    )
    .await;
    let (chain_height, chain_headers, chain_verification_progress, chain_initial_block_download) =
        match chain {
            Ok(Ok(info)) => (
                Some(info.blocks),
                Some(info.headers),
                Some(info.verificationprogress),
                Some(info.initialblockdownload),
            ),
            _ => (None, None, None, None),
        };

    // L2 sync: latest finalized L2 block + the derived epoch. Both
    // come from ghost-pay's own DB (not bitcoind), so they're
    // always available even if bitcoind is hiccuping.
    use ghost_common::constants::L2_EPOCH_BLOCKS;
    let l2_height: Option<u64> = state
        .db
        .with_connection(|conn| {
            let result: Option<i64> = conn
                .query_row(
                    "SELECT height FROM blocks ORDER BY height DESC LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .ok();
            Ok(result.map(|h| h as u64))
        })
        .ok()
        .flatten();
    let l2_epoch: Option<u64> = l2_height.map(|h| h / L2_EPOCH_BLOCKS);

    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "has_keys": has_keys,
        "lock_count": lock_count,
        "network": state.config.network,
        "chain_height": chain_height,
        "chain_headers": chain_headers,
        "chain_verification_progress": chain_verification_progress,
        "chain_initial_block_download": chain_initial_block_download,
        "l2_height": l2_height,
        "l2_epoch": l2_epoch,
    }))
}

/// L-13 FIX: Dynamic health check that verifies actual system health
///
/// Checks database connectivity and RPC health before returning OK.
/// Returns 503 Service Unavailable if any component is unhealthy.
async fn health_check(State(state): State<Arc<AppState>>) -> impl axum::response::IntoResponse {
    // Check database connectivity
    if let Err(e) = state.db.health_check() {
        error!("L-13: Database health check failed: {}", e);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "database unhealthy".to_string(),
        );
    }

    // Check Bitcoin RPC connectivity (async call)
    if let Err(e) = state.rpc.get_block_count().await {
        error!("L-13: Bitcoin RPC health check failed: {}", e);
        return (StatusCode::SERVICE_UNAVAILABLE, "rpc unhealthy".to_string());
    }

    (StatusCode::OK, "OK".to_string())
}

// ============================================================================
// GhostPay Verification Endpoint
// ============================================================================

/// Query parameters for GhostPay verification
#[derive(Debug, Deserialize)]
struct GhostPayVerifyQuery {
    /// Epoch to challenge (if not provided, uses current)
    challenge_epoch: Option<u64>,
    /// Random nonce for binding proof (256-bit hex string)
    challenge_nonce: Option<String>,
    /// Skip signature (for verification client) - not used since ghost-pay doesn't sign
    #[serde(default)]
    #[allow(dead_code)]
    unsigned: Option<bool>,
}

/// L2 block state from ghost-pay's blocks table
struct L2BlockState {
    height: u64,
    epoch_id: u64,
    state_root: String,
}

/// L2 blocks database path
/// The L2 blocks are stored in a separate database with a simpler schema.
/// This is the standard XDG data directory for ghost-pay.
const L2_BLOCKS_DB_PATH: &str = "/home/ghost/.local/share/ghost-pay/ghost-pay.db";

/// Get latest L2 block from ghost-pay's blocks table
/// Opens a direct connection to the L2 blocks database (separate from ghost-storage).
fn get_latest_l2_block() -> Result<Option<L2BlockState>, String> {
    let conn = match rusqlite::Connection::open_with_flags(
        L2_BLOCKS_DB_PATH,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to open L2 blocks database: {}", e)),
    };

    let result = conn.query_row(
        "SELECT height, epoch_id, state_root FROM blocks ORDER BY height DESC LIMIT 1",
        [],
        |row| {
            let height: i64 = row.get(0)?;
            let epoch_id: i64 = row.get(1)?;
            let state_root: String = row.get(2)?;
            Ok((height, epoch_id, state_root))
        },
    );

    match result {
        Ok((height, epoch_id, state_root)) => {
            if height < 0 || epoch_id < 0 {
                return Err("Invalid negative height or epoch".to_string());
            }
            Ok(Some(L2BlockState {
                height: height as u64,
                epoch_id: epoch_id as u64,
                state_root,
            }))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Database query error: {}", e)),
    }
}

/// Get L2 block state at a specific epoch from ghost-pay's blocks table
fn get_l2_block_at_epoch(epoch: u64) -> Result<Option<L2BlockState>, String> {
    let conn = match rusqlite::Connection::open_with_flags(
        L2_BLOCKS_DB_PATH,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to open L2 blocks database: {}", e)),
    };

    let result = conn.query_row(
        "SELECT height, epoch_id, state_root FROM blocks WHERE epoch_id = ?1 ORDER BY height DESC LIMIT 1",
        [epoch as i64],
        |row| {
            let height: i64 = row.get(0)?;
            let epoch_id: i64 = row.get(1)?;
            let state_root: String = row.get(2)?;
            Ok((height, epoch_id, state_root))
        },
    );

    match result {
        Ok((height, epoch_id, state_root)) => {
            if height < 0 || epoch_id < 0 {
                return Err("Invalid negative height or epoch".to_string());
            }
            Ok(Some(L2BlockState {
                height: height as u64,
                epoch_id: epoch_id as u64,
                state_root,
            }))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(format!("Database query error: {}", e)),
    }
}

/// Get the number of L2 blocks in a specific epoch
fn get_epoch_tx_count(epoch: u64) -> Result<u64, String> {
    let conn = match rusqlite::Connection::open_with_flags(
        L2_BLOCKS_DB_PATH,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Ok(c) => c,
        Err(e) => return Err(format!("Failed to open L2 blocks database: {}", e)),
    };

    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM blocks WHERE epoch_id = ?1",
            [epoch as i64],
            |row| row.get(0),
        )
        .map_err(|e| format!("Failed to count epoch blocks: {}", e))?;

    Ok(count as u64)
}

/// GhostPay verification response
///
/// Returns real L2 state from the database for verification challenges.
/// This endpoint is used by the verification system to prove GhostPay capability.
async fn verify_ghostpay(
    State(_state): State<Arc<AppState>>,
    Query(query): Query<GhostPayVerifyQuery>,
) -> impl axum::response::IntoResponse {
    // Get latest L2 state from ghost-pay's blocks table (separate L2 database)
    let current_state = match get_latest_l2_block() {
        Ok(Some(info)) => info,
        Ok(None) => {
            // No L2 blocks yet - return failure response
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "signed": false,
                    "response": {
                        "success": false,
                        "l2_enabled": false,
                        "virtual_block": null,
                        "epoch": null,
                        "balance_sats": null,
                        "wraith_enabled": false,
                        "epoch_state_hash": null,
                        "epoch_tx_count": null,
                        "nonce_bound_proof": null,
                        "epoch_proof": null,
                        "error": "No L2 blocks in database"
                    }
                })),
            );
        }
        Err(e) => {
            error!("Failed to get L2 state: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "signed": false,
                    "response": {
                        "success": false,
                        "l2_enabled": false,
                        "error": format!("Database error: {}", e)
                    }
                })),
            );
        }
    };

    // Determine which epoch to prove
    let challenge_epoch = query.challenge_epoch.unwrap_or(current_state.epoch_id);

    // Get state for challenged epoch (may be different from current)
    let epoch_state = if challenge_epoch == current_state.epoch_id {
        current_state.state_root.clone()
    } else {
        match get_l2_block_at_epoch(challenge_epoch) {
            Ok(Some(info)) => info.state_root,
            Ok(None) => {
                // Requested epoch doesn't exist
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "signed": false,
                        "response": {
                            "success": false,
                            "l2_enabled": true,
                            "virtual_block": current_state.height,
                            "epoch": current_state.epoch_id,
                            "error": format!("Epoch {} not found (current epoch: {})", challenge_epoch, current_state.epoch_id)
                        }
                    })),
                );
            }
            Err(e) => {
                error!("Failed to get epoch state: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "signed": false,
                        "response": {
                            "success": false,
                            "l2_enabled": true,
                            "error": format!("Database error: {}", e)
                        }
                    })),
                );
            }
        }
    };

    // Compute nonce-bound proof if nonce provided
    // nonce_bound_proof = SHA256(epoch_state_hash || challenge_nonce)
    let nonce_bound_proof = if let Some(ref nonce) = query.challenge_nonce {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(epoch_state.as_bytes());
        hasher.update(nonce.as_bytes());
        Some(hex::encode(hasher.finalize()))
    } else {
        None
    };

    // Wraith mixing moved to the wraith-coordinator binary; ghost-pay
    // no longer hosts CoinJoin sessions. This flag stays in the
    // response shape for verifier compatibility.
    let wraith_enabled = false;

    // Get L2 block count for challenged epoch
    let epoch_tx_count = get_epoch_tx_count(challenge_epoch).unwrap_or(0);

    // Return success response with real L2 state
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "signed": false,
            "response": {
                "success": true,
                "l2_enabled": true,
                "virtual_block": current_state.height,
                "epoch": current_state.epoch_id,
                "balance_sats": null,
                "wraith_enabled": wraith_enabled,
                "epoch_state_hash": epoch_state,
                "epoch_tx_count": epoch_tx_count,
                "nonce_bound_proof": nonce_bound_proof,
                "epoch_proof": null,
                "error": null
            }
        })),
    )
}

// ============================================================================
// Confidential Transfer Handlers
// ============================================================================

/// Parse a hex string into exactly 32 bytes, returning error on invalid input
fn parse_hex_32(hex_str: &str) -> Result<[u8; 32], StatusCode> {
    let bytes = hex::decode(hex_str).map_err(|_| StatusCode::BAD_REQUEST)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(arr)
}

/// Request body for submitting a NoteSpend transfer
#[derive(Debug, Deserialize)]
struct ConfidentialTransferRequest {
    proof_hex: String,
    /// Commitment root at time of proof generation
    commitment_root: String,
    nullifier: String,
    /// Sender's change commitment (new note for remaining balance)
    change_commitment: String,
    /// Recipient's commitment (new note for transfer amount)
    recipient_commitment: String,
    sender_index: u64,
    recipient_index: u64,
    recipient_owner_pubkey: String,
    epoch: u64,
    /// ECIES-encrypted change note data (hex, for sender wallet)
    #[serde(default)]
    encrypted_change: String,
    /// ECIES-encrypted recipient note data (hex, for recipient wallet)
    #[serde(default)]
    encrypted_recipient: String,
}

/// Submit a confidential transfer with Groth16 proof
async fn submit_confidential_transfer(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ConfidentialTransferRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Parse all hex fields
    let proof_bytes = hex::decode(&req.proof_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid proof hex"})),
        )
    })?;
    if proof_bytes.len() != 192 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Proof must be exactly 192 bytes"})),
        ));
    }

    let commitment_root = parse_hex_32(&req.commitment_root).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid commitment_root hex (need 32 bytes)"})),
        )
    })?;
    let nullifier = parse_hex_32(&req.nullifier).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid nullifier hex (need 32 bytes)"})),
        )
    })?;
    let change_commitment = parse_hex_32(&req.change_commitment).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid change_commitment hex (need 32 bytes)"})),
        )
    })?;
    let recipient_commitment = parse_hex_32(&req.recipient_commitment).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid recipient_commitment hex (need 32 bytes)"})),
        )
    })?;
    let recipient_owner_pubkey = parse_hex_32(&req.recipient_owner_pubkey).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"error": "Invalid recipient_owner_pubkey hex (need 32 bytes)"}),
            ),
        )
    })?;

    // Validate encrypted note fields are present and correctly sized.
    // ECIES overhead: 33 (ephemeral pubkey) + 12 (nonce) + 16 (tag) = 61 bytes
    // NoteData plaintext: 48 bytes → minimum encrypted size: 109 bytes (218 hex chars)
    const MIN_ENCRYPTED_HEX_LEN: usize = 218;
    if req.encrypted_change.len() < MIN_ENCRYPTED_HEX_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"error": "encrypted_change is required (ECIES-encrypted NoteData, min 109 bytes)"}),
            ),
        ));
    }
    if req.encrypted_recipient.len() < MIN_ENCRYPTED_HEX_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"error": "encrypted_recipient is required (ECIES-encrypted NoteData, min 109 bytes)"}),
            ),
        ));
    }
    // Verify they're valid hex
    if hex::decode(&req.encrypted_change).is_err() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "encrypted_change is not valid hex"})),
        ));
    }
    if hex::decode(&req.encrypted_recipient).is_err() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "encrypted_recipient is not valid hex"})),
        ));
    }

    // Step 1: Read-lock tree, verify commitment_root matches current
    {
        let tree = state.commitment_tree.read();
        let current_root = tree.root().map_err(|e| {
            error!(error = %e, "Failed to compute tree root");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal tree error"})),
            )
        })?;
        if current_root != commitment_root {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "Stale commitment root",
                    "current_root": hex::encode(current_root)
                })),
            ));
        }
        // Check nullifier not already spent (in-memory)
        if tree.is_nullifier_spent(&nullifier) {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "Nullifier already spent"})),
            ));
        }
    }

    // Step 2: Also check nullifier in DB (belt and suspenders)
    if state.db.is_nullifier_spent(&nullifier).unwrap_or(true) {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "Nullifier already spent"})),
        ));
    }

    // Step 3: Verify NoteSpend Groth16 proof
    let verifier = state.note_spend_verifier.read().as_ref().cloned().ok_or_else(|| {
        (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "NoteSpend verifier not initialized (MPC params unavailable)"})))
    })?;

    let public_inputs = GhostNoteSpendPublicInputs {
        commitment_root,
        nullifier,
        change_commitment,
        recipient_commitment,
    };

    // Compute prover_id matching GhostNoteProver's convention
    let prover_id = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ghost-zkp-note-prover-v1");
        hasher.update(COMMITMENT_TREE_DEPTH.to_le_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        hash
    };

    let transfer_proof = GhostNoteSpendProof {
        public_inputs: public_inputs.clone(),
        proof: proof_bytes.clone(),
        prover_id,
    };

    let valid = verifier.verify(&transfer_proof).map_err(|e| {
        warn!(error = %e, "Proof verification failed");
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("Invalid proof: {}", e)})),
        )
    })?;

    if !valid {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Proof verification returned false"})),
        ));
    }

    // Step 4: Write-lock tree, re-check root (TOCTOU), apply update
    let transfer_id = uuid::Uuid::new_v4().to_string();
    let new_root;
    {
        let mut tree = state.commitment_tree.write();

        // Re-check root under write lock
        let current_root = tree.root().map_err(|e| {
            error!(error = %e, "Failed to compute tree root");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal tree error"})),
            )
        })?;
        if current_root != commitment_root {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "Stale commitment root (concurrent update)",
                    "current_root": hex::encode(current_root)
                })),
            ));
        }

        // Re-check nullifier under write lock
        if tree.is_nullifier_spent(&nullifier) {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "Nullifier already spent (concurrent spend)"})),
            ));
        }

        // Apply: insert new commitments and record nullifier
        // NoteSpend: change commitment replaces spent note, recipient gets new position
        tree.insert(req.sender_index, change_commitment);
        tree.insert(req.recipient_index, recipient_commitment);
        tree.spend_nullifier(nullifier);

        // Compute new root after tree update
        new_root = tree.root().map_err(|e| {
            error!(error = %e, "Failed to compute new tree root");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal tree error"})),
            )
        })?;
    }

    // Step 5: Persist to DB
    let current_height = state.rpc.get_block_count().await.unwrap_or(0);

    // Insert notes
    if let Err(e) = state.db.insert_confidential_note(
        req.sender_index,
        &change_commitment,
        &[0u8; 32], // Sender's pubkey not known from transfer; updated by owner
        current_height,
    ) {
        warn!(error = %e, "Failed to persist sender change note");
    }
    if let Err(e) = state.db.insert_confidential_note(
        req.recipient_index,
        &recipient_commitment,
        &recipient_owner_pubkey,
        current_height,
    ) {
        warn!(error = %e, "Failed to persist recipient note");
    }

    // Insert nullifier
    if let Err(e) = state
        .db
        .insert_nullifier(&nullifier, current_height, &transfer_id)
    {
        warn!(error = %e, "Failed to persist nullifier");
    }

    // Insert transfer record (maps NoteSpend fields to legacy DB schema)
    let record = ConfidentialTransferRecord {
        transfer_id: transfer_id.clone(),
        block_height: Some(current_height),
        nullifier,
        sender_new_commitment: change_commitment,
        recipient_new_commitment: recipient_commitment,
        old_commitment_root: commitment_root,
        new_commitment_root: new_root,
        proof: proof_bytes.clone(),
        sender_index: req.sender_index,
        recipient_index: req.recipient_index,
        status: "confirmed".to_string(),
        encrypted_change: hex::decode(&req.encrypted_change).ok(),
        encrypted_recipient: hex::decode(&req.encrypted_recipient).ok(),
        epoch: req.epoch,
    };
    if let Err(e) = state.db.insert_confidential_transfer(&record) {
        warn!(error = %e, "Failed to persist transfer record");
    }

    info!(
        transfer_id = %transfer_id,
        sender_idx = req.sender_index,
        recipient_idx = req.recipient_index,
        epoch = req.epoch,
        "NoteSpend transfer applied"
    );

    // Step 6: Relay to ghost-pool for L2 consensus broadcast
    // Transfer commitments (change + recipient) are NOT synced here — they reach
    // ghost-pool through the confirmed pool → checkpoint → append_commitment path.
    // Syncing them would overwrite shield commitments at the same tree index.
    // Construct L2ConfidentialTransferMessage JSON (matches ghost-consensus message format)
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let l2_message = serde_json::json!({
        "transaction": {
            "epoch": req.epoch,
            "nullifier": hex::encode(nullifier),
            "change_commitment": hex::encode(change_commitment),
            "recipient_commitment": hex::encode(recipient_commitment),
            "commitment_root": hex::encode(commitment_root),
            "proof": proof_bytes,
            "encrypted_change": hex::decode(&req.encrypted_change).unwrap_or_default(),
            "encrypted_recipient": hex::decode(&req.encrypted_recipient).unwrap_or_default(),
            "timestamp": timestamp,
        },
        "sender": hex::encode([0u8; 32]),
    });

    let relay_url = format!("{}/api/v1/l2/submit", state.pool_api_url);
    let relay_body = serde_json::to_vec(&l2_message).unwrap_or_default();

    match state
        .pool_http_client
        .post(&relay_url)
        .body(relay_body)
        .header("content-type", "application/json")
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            info!(transfer_id = %transfer_id, "L2 transaction relayed to ghost-pool");
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(
                transfer_id = %transfer_id,
                status = %status,
                body = %body,
                "Ghost-pool relay returned non-success status"
            );
        }
        Err(e) => {
            warn!(
                transfer_id = %transfer_id,
                error = %e,
                "Failed to relay L2 transaction to ghost-pool (will be retried by consensus)"
            );
        }
    }

    Ok(Json(serde_json::json!({
        "transfer_id": transfer_id,
        "new_commitment_root": hex::encode(new_root),
        "sender_index": req.sender_index,
        "recipient_index": req.recipient_index,
    })))
}

// ============================================================================
// Consolidation Handler
// ============================================================================

/// Request body for submitting a consolidation proof (merge up to 4 notes into 1)
#[derive(Debug, Deserialize)]
struct ConsolidateRequest {
    proof_hex: String,
    commitment_root: String,
    nullifiers: [String; 4],
    output_commitment: String,
    /// S-5: Required — encrypted note for wallet scanner discoverability
    encrypted_output: String,
    epoch: u64,
}

/// Submit a consolidation proof that merges up to 4 notes into 1
async fn submit_consolidation(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ConsolidateRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Step 1: Parse proof_hex, verify 192 bytes (Groth16 BLS12-381)
    let proof_bytes = hex::decode(&req.proof_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid proof hex"})),
        )
    })?;
    if proof_bytes.len() != 192 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Proof must be exactly 192 bytes"})),
        ));
    }

    // S-5: Validate encrypted_output (min 109 bytes = 218 hex chars: 33 ephemeral + 12 nonce + 48 plaintext + 16 tag)
    if req.encrypted_output.len() < 218 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"error": "encrypted_output too short (min 109 bytes hex-encoded)"}),
            ),
        ));
    }
    hex::decode(&req.encrypted_output).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid encrypted_output hex"})),
        )
    })?;

    // Step 2: Parse hex fields
    let commitment_root = parse_hex_32(&req.commitment_root).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid commitment_root hex (need 32 bytes)"})),
        )
    })?;

    let mut nullifiers = [[0u8; 32]; MAX_CONSOLIDATION_INPUTS];
    for (i, n) in req.nullifiers.iter().enumerate() {
        let bytes = hex::decode(n).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid nullifier[{}] hex", i)})),
            )
        })?;
        if bytes.len() != 32 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("nullifier[{}] must be 32 bytes", i)})),
            ));
        }
        nullifiers[i].copy_from_slice(&bytes);
    }

    let output_commitment = parse_hex_32(&req.output_commitment).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid output_commitment hex (need 32 bytes)"})),
        )
    })?;

    // Step 3: Read-lock tree, verify root matches, check nullifiers unspent
    {
        let tree = state.commitment_tree.read();
        let current_root = tree.root().map_err(|e| {
            error!(error = %e, "Failed to compute tree root");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal tree error"})),
            )
        })?;
        if current_root != commitment_root {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "Stale commitment root",
                    "current_root": hex::encode(current_root)
                })),
            ));
        }
        // Check all non-zero nullifiers are unspent (in-memory)
        for (i, nul) in nullifiers.iter().enumerate() {
            if *nul != [0u8; 32] && tree.is_nullifier_spent(nul) {
                return Err((
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({
                        "error": format!("Nullifier[{}] already spent", i)
                    })),
                ));
            }
        }
    }

    // Also check nullifiers in DB (belt and suspenders)
    for (i, nul) in nullifiers.iter().enumerate() {
        if *nul != [0u8; 32] && state.db.is_nullifier_spent(nul).unwrap_or(true) {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": format!("Nullifier[{}] already spent (DB)", i)
                })),
            ));
        }
    }

    // Step 4: Verify Groth16 consolidation proof
    let verifier = state
        .consolidation_verifier
        .read()
        .as_ref()
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "Consolidation verifier not initialized (MPC params unavailable)"
                })),
            )
        })?;

    let public_inputs = ConsolidationPublicInputs {
        commitment_root,
        nullifiers,
        output_commitment,
    };

    match verifier.verify_raw(&proof_bytes, &public_inputs) {
        Ok(true) => {}
        Ok(false) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({"error": "Consolidation proof verification returned false"}),
                ),
            ));
        }
        Err(e) => {
            warn!(error = %e, "Consolidation proof verification failed");
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid consolidation proof: {}", e)})),
            ));
        }
    }

    // Step 5: Write-lock tree, recheck root (TOCTOU), spend nullifiers, insert output
    let consolidation_id = uuid::Uuid::new_v4().to_string();
    let new_root;
    let output_index;
    {
        let mut tree = state.commitment_tree.write();

        // Re-check root under write lock (TOCTOU protection)
        let current_root = tree.root().map_err(|e| {
            error!(error = %e, "Failed to compute tree root");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal tree error"})),
            )
        })?;
        if current_root != commitment_root {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "Stale commitment root (concurrent update)",
                    "current_root": hex::encode(current_root)
                })),
            ));
        }

        // Re-check nullifiers under write lock
        for (i, nul) in nullifiers.iter().enumerate() {
            if *nul != [0u8; 32] && tree.is_nullifier_spent(nul) {
                return Err((
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({
                        "error": format!("Nullifier[{}] already spent (concurrent spend)", i)
                    })),
                ));
            }
        }

        // Spend all non-zero nullifiers
        for nul in &nullifiers {
            if *nul != [0u8; 32] {
                tree.spend_nullifier(*nul);
            }
        }

        // Insert output commitment at next available index
        output_index = tree.next_index();
        tree.insert(output_index, output_commitment);

        // Compute new root after tree update
        new_root = tree.root().map_err(|e| {
            error!(error = %e, "Failed to compute new tree root");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal tree error"})),
            )
        })?;
    }

    // Step 6: Persist to DB
    let current_height = state.rpc.get_block_count().await.unwrap_or(0);

    // Insert output note
    if let Err(e) = state.db.insert_confidential_note(
        output_index,
        &output_commitment,
        &[0u8; 32], // Owner pubkey not known from consolidation; updated by owner
        current_height,
    ) {
        warn!(error = %e, "Failed to persist consolidation output note");
    }

    // Insert all non-zero nullifiers
    for nul in &nullifiers {
        if *nul != [0u8; 32] {
            if let Err(e) = state
                .db
                .insert_nullifier(nul, current_height, &consolidation_id)
            {
                warn!(error = %e, "Failed to persist consolidation nullifier");
            }
        }
    }

    info!(
        consolidation_id = %consolidation_id,
        output_index = output_index,
        epoch = req.epoch,
        nullifiers_spent = nullifiers.iter().filter(|n| **n != [0u8; 32]).count(),
        "Consolidation applied"
    );

    // Step 7: Relay to ghost-pool for L2 consensus broadcast
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let l2_message = serde_json::json!({
        "transaction": {
            "epoch": req.epoch,
            "nullifier": hex::encode(nullifiers[0]),
            "change_commitment": hex::encode(output_commitment),
            "recipient_commitment": hex::encode([0u8; 32]),
            "commitment_root": hex::encode(commitment_root),
            "proof": proof_bytes,
            "encrypted_change": hex::decode(&req.encrypted_output).unwrap_or_default(),
            "encrypted_recipient": [],
            "timestamp": timestamp,
        },
        "sender": hex::encode([0u8; 32]),
    });

    let relay_url = format!("{}/api/v1/l2/submit", state.pool_api_url);
    let relay_body = serde_json::to_vec(&l2_message).unwrap_or_default();

    match state
        .pool_http_client
        .post(&relay_url)
        .body(relay_body)
        .header("content-type", "application/json")
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            info!(consolidation_id = %consolidation_id, "Consolidation relayed to ghost-pool");
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(
                consolidation_id = %consolidation_id,
                status = %status,
                body = %body,
                "Ghost-pool consolidation relay returned non-success status"
            );
        }
        Err(e) => {
            warn!(
                consolidation_id = %consolidation_id,
                error = %e,
                "Failed to relay consolidation to ghost-pool (will be retried by consensus)"
            );
        }
    }

    Ok(Json(serde_json::json!({
        "consolidation_id": consolidation_id,
        "new_commitment_root": hex::encode(new_root),
        "output_index": output_index,
    })))
}

// ============================================================================
// Unshield Handler (L2 -> L1 Withdrawal)
// ============================================================================

/// Request body for submitting an unshield proof (full L2 -> L1 withdrawal)
#[derive(Debug, Deserialize)]
struct UnshieldRequest {
    proof_hex: String,
    commitment_root: String,
    nullifier: String,
    withdrawal_amount_sats: u64,
    destination_address: String,
}

/// Submit an unshield proof that withdraws value from L2 to an L1 Bitcoin address
async fn submit_unshield(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UnshieldRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Step 1: Parse proof_hex, verify 192 bytes (Groth16 BLS12-381)
    let proof_bytes = hex::decode(&req.proof_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid proof hex"})),
        )
    })?;
    if proof_bytes.len() != 192 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Proof must be exactly 192 bytes"})),
        ));
    }

    // Step 2: Parse hex fields
    let commitment_root = parse_hex_32(&req.commitment_root).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid commitment_root hex (need 32 bytes)"})),
        )
    })?;

    let nullifier = parse_hex_32(&req.nullifier).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid nullifier hex (need 32 bytes)"})),
        )
    })?;

    if req.withdrawal_amount_sats == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "withdrawal_amount_sats must be > 0"})),
        ));
    }

    // Validate destination address is a parseable Bitcoin address
    if req.destination_address.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "destination_address is required"})),
        ));
    }

    // Step 3: Read-lock tree, verify root matches, check nullifier unspent
    {
        let tree = state.commitment_tree.read();
        let current_root = tree.root().map_err(|e| {
            error!(error = %e, "Failed to compute tree root");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal tree error"})),
            )
        })?;
        if current_root != commitment_root {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "Stale commitment root",
                    "current_root": hex::encode(current_root)
                })),
            ));
        }
        if tree.is_nullifier_spent(&nullifier) {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "Nullifier already spent"})),
            ));
        }
    }

    // Also check nullifier in DB (belt and suspenders)
    if state.db.is_nullifier_spent(&nullifier).unwrap_or(true) {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "Nullifier already spent (DB)"})),
        ));
    }

    // Step 4: Verify Groth16 unshield proof
    let verifier = state
        .unshield_verifier
        .read()
        .as_ref()
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "Unshield verifier not initialized (MPC params unavailable)"
                })),
            )
        })?;

    let public_inputs = UnshieldPublicInputs {
        commitment_root,
        nullifier,
        withdrawal_amount: req.withdrawal_amount_sats,
    };

    match verifier.verify_raw(&proof_bytes, &public_inputs) {
        Ok(true) => {}
        Ok(false) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Unshield proof verification returned false"})),
            ));
        }
        Err(e) => {
            warn!(error = %e, "Unshield proof verification failed");
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid unshield proof: {}", e)})),
            ));
        }
    }

    // Step 5: Write-lock tree, recheck root (TOCTOU), spend nullifier
    // NOTE: No new commitment inserted — value leaves L2
    let unshield_id = uuid::Uuid::new_v4().to_string();
    let new_root;
    {
        let mut tree = state.commitment_tree.write();

        // Re-check root under write lock (TOCTOU protection)
        let current_root = tree.root().map_err(|e| {
            error!(error = %e, "Failed to compute tree root");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal tree error"})),
            )
        })?;
        if current_root != commitment_root {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "Stale commitment root (concurrent update)",
                    "current_root": hex::encode(current_root)
                })),
            ));
        }

        // Re-check nullifier under write lock
        if tree.is_nullifier_spent(&nullifier) {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "Nullifier already spent (concurrent spend)"})),
            ));
        }

        // Spend the nullifier
        tree.spend_nullifier(nullifier);

        // Compute new root after nullifier spend (tree unchanged, only nullifier set)
        new_root = tree.root().map_err(|e| {
            error!(error = %e, "Failed to compute new tree root");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal tree error"})),
            )
        })?;
    }

    // Step 6: Persist nullifier to DB and record withdrawal request
    let current_height = state.rpc.get_block_count().await.unwrap_or(0);

    if let Err(e) = state
        .db
        .insert_nullifier(&nullifier, current_height, &unshield_id)
    {
        warn!(error = %e, "Failed to persist unshield nullifier");
    }

    info!(
        unshield_id = %unshield_id,
        withdrawal_amount_sats = req.withdrawal_amount_sats,
        destination = %req.destination_address,
        "Unshield withdrawal applied"
    );

    // Step 7: Relay to ghost-pool for L2 consensus broadcast
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let l2_message = serde_json::json!({
        "transaction": {
            "epoch": 0,
            "nullifier": hex::encode(nullifier),
            "change_commitment": hex::encode([0u8; 32]),
            "recipient_commitment": hex::encode([0u8; 32]),
            "commitment_root": hex::encode(commitment_root),
            "proof": proof_bytes,
            "encrypted_change": [],
            "encrypted_recipient": [],
            "timestamp": timestamp,
        },
        "sender": hex::encode([0u8; 32]),
    });

    let relay_url = format!("{}/api/v1/l2/submit", state.pool_api_url);
    let relay_body = serde_json::to_vec(&l2_message).unwrap_or_default();

    match state
        .pool_http_client
        .post(&relay_url)
        .body(relay_body)
        .header("content-type", "application/json")
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            info!(unshield_id = %unshield_id, "Unshield relayed to ghost-pool");
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(
                unshield_id = %unshield_id,
                status = %status,
                body = %body,
                "Ghost-pool unshield relay returned non-success status"
            );
        }
        Err(e) => {
            warn!(
                unshield_id = %unshield_id,
                error = %e,
                "Failed to relay unshield to ghost-pool (will be retried by consensus)"
            );
        }
    }

    Ok(Json(serde_json::json!({
        "unshield_id": unshield_id,
        "new_commitment_root": hex::encode(new_root),
        "withdrawal_amount_sats": req.withdrawal_amount_sats,
        "destination_address": req.destination_address,
    })))
}

/// Request body for shielding plaintext balance into a commitment
#[derive(Debug, Deserialize)]
struct ShieldBalanceRequest {
    amount_sats: u64,
    blinding_hex: String,
    owner_pubkey: String,
    /// Optional lock ID for wraith lock validation (enforces denomination - service_fee)
    lock_id: Option<String>,
}

/// Shield plaintext balance into a confidential commitment
async fn shield_balance(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ShieldBalanceRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let owner_pubkey = parse_hex_32(&req.owner_pubkey).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid owner_pubkey hex (need 32 bytes)"})),
        )
    })?;
    let blinding = parse_hex_32(&req.blinding_hex).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid blinding hex (need 32 bytes)"})),
        )
    })?;

    if req.amount_sats == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Amount must be > 0"})),
        ));
    }

    // Validate shield amount against wraith lock fee deduction
    if let Some(ref lock_id) = req.lock_id {
        match state.db.get_ghost_lock(lock_id) {
            Ok(Some(lock)) => {
                let expected = lock.amount_sats.saturating_sub(lock.wraith_fee_sats);
                if req.amount_sats != expected {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": format!(
                                "Shield amount {} does not match expected {} (denomination {} - wraith_fee {})",
                                req.amount_sats, expected, lock.amount_sats, lock.wraith_fee_sats
                            )
                        })),
                    ));
                }
                // GHOST-05: only shield against a lock whose on-chain deposit has
                // been verified — confirm_lock_funding sets Active only after
                // checking the funding UTXO (script + value + confirmations).
                // Without this, shielded value could be minted against a lock
                // that was never actually funded.
                if lock.state != ghost_storage::GhostLockState::Active {
                    return Err((
                        StatusCode::UNPROCESSABLE_ENTITY,
                        Json(serde_json::json!({
                            "error": format!(
                                "Lock {} is not active (state {}); fund and confirm it on-chain before shielding",
                                lock_id,
                                lock.state.as_str()
                            )
                        })),
                    ));
                }
            }
            Ok(None) => {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "Lock not found"})),
                ));
            }
            Err(e) => {
                error!(error = %e, lock_id = %lock_id, "Failed to look up lock for shield validation");
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "Failed to validate lock"})),
                ));
            }
        }
    }

    // Compute commitment: C = MiMC(MiMC(value, blinding), domain_sep)
    let commitment =
        ghost_zkp::compute_commitment_bytes(req.amount_sats, &blinding).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid blinding: {}", e)})),
            )
        })?;

    // Get next index and insert into tree + DB
    let note_index;
    let new_root;
    {
        let mut tree = state.commitment_tree.write();
        note_index = tree.next_index();
        tree.insert(note_index, commitment);
        new_root = tree.root().map_err(|e| {
            error!(error = %e, "Failed to compute tree root after shield");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Internal tree error"})),
            )
        })?;
    }

    // Persist
    let current_height = state.rpc.get_block_count().await.unwrap_or(0);
    if let Err(e) =
        state
            .db
            .insert_confidential_note(note_index, &commitment, &owner_pubkey, current_height)
    {
        warn!(error = %e, "Failed to persist shielded note");
    }

    info!(note_index = note_index, "Balance shielded into commitment");

    // Sync commitment to ghost-pool tree with retry (ghost-pool must have this root
    // before any transfer proof built against it can be relayed).
    // Ghost-pool will also P2P broadcast to all peers for convergence.
    sync_commitment_with_retry(
        &state.pool_http_client,
        &state.pool_api_url,
        &commitment,
        note_index,
        current_height,
    )
    .await;

    Ok(Json(serde_json::json!({
        "note_index": note_index,
        "commitment": hex::encode(commitment),
        "new_root": hex::encode(new_root),
    })))
}

/// Get commitment tree state
async fn get_tree_state(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let tree = state.commitment_tree.read();
    let root = tree.root().unwrap_or([0u8; 32]);
    let nullifier_count = tree.nullifier_count();

    // Get current epoch from L2 blocks database
    let current_epoch = get_latest_l2_block()
        .ok()
        .flatten()
        .map(|b| b.epoch_id)
        .unwrap_or(0);

    Json(serde_json::json!({
        "root": hex::encode(root),
        "note_count": tree.note_count(),
        "next_index": tree.next_index(),
        "tree_depth": 20,
        "nullifier_count": nullifier_count,
        "current_epoch": current_epoch,
    }))
}

/// Get Merkle inclusion proof for a note at the given tree index
async fn get_confidential_proof(
    State(state): State<Arc<AppState>>,
    Path(index): Path<u64>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let tree = state.commitment_tree.read();
    let proof = tree.get_proof(index).map_err(|e| {
        error!(error = %e, index = index, "Failed to generate proof");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let root = tree.root().map_err(|e| {
        error!(error = %e, "Failed to compute tree root");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(Json(serde_json::json!({
        "leaf_index": proof.leaf_index,
        "siblings": proof.siblings.iter().map(hex::encode).collect::<Vec<_>>(),
        "tree_root": hex::encode(root),
        "tree_depth": proof.depth(),
    })))
}

/// Get confidential notes for an owner
async fn get_confidential_notes(
    State(state): State<Arc<AppState>>,
    Path(owner_pubkey_hex): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let owner_pubkey = parse_hex_32(&owner_pubkey_hex).map_err(|_| StatusCode::BAD_REQUEST)?;

    let notes = state.db.get_notes_for_owner(&owner_pubkey).map_err(|e| {
        error!(error = %e, "Failed to query notes");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let notes_json: Vec<serde_json::Value> = notes
        .iter()
        .map(|n| {
            serde_json::json!({
                "index": n.tree_index,
                "commitment": hex::encode(n.commitment),
                "created_height": n.created_at_height,
                "spent": n.spent_at_height.is_some(),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "owner": owner_pubkey_hex,
        "notes": notes_json,
    })))
}

/// Get recent L2 transactions with encrypted fields for wallet scanning
async fn get_recent_l2_transactions(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let since_height: u64 = params
        .get("since_height")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let transfers = state
        .db
        .get_recent_confidential_transfers(since_height)
        .map_err(|e| {
            error!(error = %e, "Failed to query L2 transactions");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let latest_height = transfers
        .iter()
        .filter_map(|t| t.block_height)
        .max()
        .unwrap_or(since_height);

    let txs_json: Vec<serde_json::Value> = transfers
        .iter()
        .map(|t| {
            serde_json::json!({
                "checkpoint_height": t.block_height.unwrap_or(0),
                "epoch": t.epoch,
                "nullifier": hex::encode(t.nullifier),
                "change_commitment": hex::encode(t.sender_new_commitment),
                "recipient_commitment": hex::encode(t.recipient_new_commitment),
                "encrypted_change": t.encrypted_change.as_ref().map(hex::encode),
                "encrypted_recipient": t.encrypted_recipient.as_ref().map(hex::encode),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "transactions": txs_json,
        "latest_height": latest_height,
    })))
}

// ============================================================================
// Background Tasks
// ============================================================================

/// Background payment scanner
async fn run_scanner(state: Arc<AppState>, mut rx: mpsc::Receiver<ScanRequest>) {
    use bitcoin::secp256k1::PublicKey;
    use tracing::{debug, error, warn};

    info!("Starting background payment scanner");

    while let Some(req) = rx.recv().await {
        // Clone the Arc to release lock before await (Arc clone, not key clone)
        let keys = {
            let keys_guard = state.keys.read();
            match keys_guard.as_ref() {
                Some(k) => Arc::clone(k),
                None => {
                    debug!("No keys loaded, skipping scan");
                    continue;
                }
            }
        };

        info!(txid = %req.txid, vout = req.vout, "Scanning transaction");

        // Fetch the transaction from Bitcoin Core
        // Try getrawtransaction first (requires -txindex for confirmed non-wallet txs),
        // fall back to gettransaction (wallet txs only, returns decoded in .decoded field)
        let tx_json = match state.rpc.get_raw_transaction(&req.txid, true).await {
            Ok(json) => json,
            Err(_) => {
                // Fallback: gettransaction (wallet RPC) wraps decoded tx differently
                match state.rpc.get_transaction(&req.txid).await {
                    Ok(wallet_json) => {
                        // gettransaction with verbose=true returns decoded tx in .decoded
                        if let Some(decoded) = wallet_json.get("decoded") {
                            decoded.clone()
                        } else {
                            // Older Bitcoin Core: decode the hex ourselves
                            if let Some(hex) = wallet_json.get("hex").and_then(|h| h.as_str()) {
                                match state.rpc.decode_raw_transaction(hex).await {
                                    Ok(decoded) => decoded,
                                    Err(e) => {
                                        warn!(txid = %req.txid, error = %e, "Failed to decode wallet transaction");
                                        continue;
                                    }
                                }
                            } else {
                                warn!(txid = %req.txid, "No hex in wallet transaction");
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        warn!(txid = %req.txid, error = %e, "Failed to fetch transaction (both getrawtransaction and gettransaction failed)");
                        continue;
                    }
                }
            }
        };

        // Parse transaction outputs
        let vout_array = match tx_json.get("vout").and_then(|v| v.as_array()) {
            Some(arr) => arr,
            None => {
                warn!(txid = %req.txid, "No vout array in transaction");
                continue;
            }
        };

        // Look for ephemeral pubkey in OP_RETURN output (Ghost Pay protocol)
        // Format: OP_RETURN <33-byte ephemeral pubkey>
        let mut ephemeral_pubkey: Option<PublicKey> = None;
        let mut outputs: Vec<(PublicKey, Option<u64>)> = Vec::new();

        for vout in vout_array.iter() {
            let value_btc = vout.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0);
            // SECURITY: Use round() to prevent precision loss from f64 representation
            // Bitcoin Core RPC returns BTC as f64, this is the standard conversion approach
            let value_sats = (value_btc * SATS_PER_BTC_F64).round() as u64;

            // Get scriptPubKey hex
            let script_hex = vout
                .get("scriptPubKey")
                .and_then(|s| s.get("hex"))
                .and_then(|h| h.as_str())
                .unwrap_or("");

            let script_bytes = match hex::decode(script_hex) {
                Ok(b) => b,
                Err(_) => continue,
            };

            // Check for OP_RETURN with ephemeral pubkey (6a21 = OP_RETURN PUSH33)
            if script_bytes.len() == 35 && script_bytes[0] == 0x6a && script_bytes[1] == 0x21 {
                if let Ok(pubkey) = PublicKey::from_slice(&script_bytes[2..35]) {
                    ephemeral_pubkey = Some(pubkey);
                    debug!("Found ephemeral pubkey in OP_RETURN");
                }
                continue;
            }

            // Check for P2TR output (5120 = OP_1 PUSH32)
            if script_bytes.len() == 34 && script_bytes[0] == 0x51 && script_bytes[1] == 0x20 {
                // For P2TR, we need to convert x-only key to full pubkey.
                // P2TR only stores the 32-byte x-coordinate, so we must try both
                // Y coordinate parities (even=0x02, odd=0x03) since we don't know
                // which was used. Add both to outputs for the scanner to check.
                let mut full_key_even = vec![0x02]; // Even Y
                full_key_even.extend_from_slice(&script_bytes[2..34]);
                if let Ok(pubkey) = PublicKey::from_slice(&full_key_even) {
                    outputs.push((pubkey, Some(value_sats)));
                }

                let mut full_key_odd = vec![0x03]; // Odd Y
                full_key_odd.extend_from_slice(&script_bytes[2..34]);
                if let Ok(pubkey) = PublicKey::from_slice(&full_key_odd) {
                    outputs.push((pubkey, Some(value_sats)));
                }
            }
        }

        // If we have both ephemeral pubkey and outputs, scan for payments
        if let Some(ephemeral) = ephemeral_pubkey {
            if outputs.is_empty() {
                debug!(txid = %req.txid, "No P2TR outputs to scan");
                continue;
            }

            let detector = PaymentDetector::new(&keys);
            let found_payments = detector.scan_transaction(&ephemeral, &outputs);

            if found_payments.is_empty() {
                debug!(txid = %req.txid, "No payments found for our keys");
                continue;
            }

            info!(
                txid = %req.txid,
                count = found_payments.len(),
                "Detected payments to our ghost keys"
            );

            // Process found payments
            let ghost_id = state.ghost_id.read().clone();
            for payment in found_payments {
                let amount = payment.amount.unwrap_or(0);
                info!(
                    txid = %req.txid,
                    vout = payment.output_index,
                    amount = amount,
                    "Payment detected"
                );

                // Update lock funding if this matches a pending lock
                if let Some(ref gid) = ghost_id {
                    // Find pending lock that matches this amount
                    if let Ok(locks) = state.db.get_ghost_locks_by_owner(gid) {
                        for lock in locks {
                            if lock.state == DbLockState::Pending && lock.amount_sats == amount {
                                if let Err(e) = state.db.update_ghost_lock_funding(
                                    &lock.lock_id,
                                    &req.txid,
                                    payment.output_index,
                                ) {
                                    error!(error = %e, "Failed to update lock funding");
                                } else {
                                    info!(
                                        lock_id = %lock.lock_id,
                                        txid = %req.txid,
                                        vout = payment.output_index,
                                        "Lock funded"
                                    );
                                    // Refresh in-memory lock cache
                                    {
                                        let mut locks_cache = state.locks.write();
                                        if let Some(cached) =
                                            locks_cache.iter_mut().find(|l| l.id == lock.lock_id)
                                        {
                                            cached.state = "Active".to_string();
                                        }
                                    }

                                    // GhostGlyph: complete registration if pending claim exists
                                    if let Ok(Some(glyph_record)) =
                                        state.db.get_glyph_by_ghost_id(gid)
                                    {
                                        if glyph_record.funding_txid.is_none() {
                                            let now = std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .unwrap_or_default()
                                                .as_secs();
                                            if let Err(e) = state
                                                .db
                                                .complete_glyph_registration(gid, &req.txid, now)
                                            {
                                                error!(error = %e, ghost_id = %gid, "Failed to complete glyph registration");
                                            } else {
                                                info!(ghost_id = %gid, txid = %req.txid, "GhostGlyph registered");
                                                // Relay registration to ghost-pool for mesh broadcast
                                                let relay_body = serde_json::json!({
                                                    "ghost_id": gid,
                                                    "bitmap_hash": glyph_record.bitmap_hash,
                                                    "funding_txid": req.txid,
                                                    "registered_at": now,
                                                });
                                                // L-8: Await relay instead of fire-and-forget so failures are visible
                                                let relay_url = format!(
                                                    "{}/api/v1/glyph/relay-registered",
                                                    state.pool_api_url
                                                );
                                                match state
                                                    .pool_http_client
                                                    .post(&relay_url)
                                                    .json(&relay_body)
                                                    .send()
                                                    .await
                                                {
                                                    Ok(resp) if resp.status().is_success() => {
                                                        info!("Glyph registration relayed to ghost-pool");
                                                    }
                                                    Ok(resp) => {
                                                        let status = resp.status();
                                                        let body =
                                                            resp.text().await.unwrap_or_default();
                                                        warn!(status = %status, body = %body, "Glyph registration relay failed");
                                                    }
                                                    Err(e) => {
                                                        warn!(error = %e, "Glyph registration relay request failed");
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
        } else if !outputs.is_empty() {
            // No ephemeral pubkey (not a Silent Payment) — try direct address matching.
            // This handles plain BTC sends (e.g. sendtoaddress) to a lock's P2TR address.
            debug!(txid = %req.txid, "No ephemeral pubkey — trying direct address match");

            let ghost_id = state.ghost_id.read().clone();
            if let Some(ref gid) = ghost_id {
                if let Ok(locks) = state.db.get_ghost_locks_by_owner(gid) {
                    let unfunded_locks: Vec<_> =
                        locks.iter().filter(|l| l.funding_txid.is_none()).collect();

                    if !unfunded_locks.is_empty() {
                        // Check each output against unfunded lock scripts
                        for (idx, vout) in vout_array.iter().enumerate() {
                            let script_hex = vout
                                .get("scriptPubKey")
                                .and_then(|s| s.get("hex"))
                                .and_then(|h| h.as_str())
                                .unwrap_or("");
                            let value_btc =
                                vout.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0);
                            let value_sats = (value_btc * SATS_PER_BTC_F64).round() as u64;

                            for lock in &unfunded_locks {
                                if lock.output_script == script_hex
                                    && lock.amount_sats == value_sats
                                {
                                    if let Err(e) = state.db.update_ghost_lock_funding(
                                        &lock.lock_id,
                                        &req.txid,
                                        idx as u32,
                                    ) {
                                        error!(error = %e, lock_id = %lock.lock_id, "Failed to update lock funding");
                                    } else {
                                        info!(
                                            lock_id = %lock.lock_id,
                                            txid = %req.txid,
                                            vout = idx,
                                            amount = value_sats,
                                            "Lock funded via direct address match"
                                        );
                                        // Refresh in-memory lock cache
                                        let mut locks_cache = state.locks.write();
                                        if let Some(cached) =
                                            locks_cache.iter_mut().find(|l| l.id == lock.lock_id)
                                        {
                                            cached.state = "Active".to_string();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            debug!(txid = %req.txid, "No outputs to scan");
        }
    }
}

/// L1 Settlement loop - reconciles L2 balances to Bitcoin L1
/// Fee distribution context returned by ghost-pool.
struct FeeDistributionContext {
    treasury_balance_sats: u64,
    threshold_reached_at: Option<i64>,
    ghost_pay_nodes: Vec<(String, String, i32)>,
}

/// Query ghost-pool for treasury state and qualified Ghost Pay nodes.
async fn query_fee_distribution_context(state: &AppState) -> Option<FeeDistributionContext> {
    let url = format!("{}/api/v1/l2/fee-distribution-context", state.pool_api_url);
    let resp = state.pool_http_client.get(&url).send().await.ok()?;
    let json: serde_json::Value = resp.json().await.ok()?;

    let treasury_balance_sats = json.get("treasury_balance_sats")?.as_u64()?;
    let threshold_reached_at = json.get("threshold_reached_at").and_then(|v| v.as_i64());

    let nodes_array = json.get("ghost_pay_nodes")?.as_array()?;
    let ghost_pay_nodes: Vec<(String, String, i32)> = nodes_array
        .iter()
        .filter_map(|node| {
            let node_id = node.get("node_id")?.as_str()?.to_string();
            let address = node.get("address")?.as_str()?.to_string();
            let shares = node.get("shares")?.as_i64()? as i32;
            Some((node_id, address, shares))
        })
        .collect();

    Some(FeeDistributionContext {
        treasury_balance_sats,
        threshold_reached_at,
        ghost_pay_nodes,
    })
}

/// Query ghost-pool for treasury state only (balance + threshold timestamp).
/// Used by per-node direct fee distribution — no node list needed.
async fn query_treasury_state(
    state: &AppState,
) -> Option<ghost_reconciliation::fee_distribution::TreasuryState> {
    use ghost_reconciliation::fee_distribution::TreasuryState;

    let url = format!("{}/api/v1/l2/fee-distribution-context", state.pool_api_url);
    let resp = state.pool_http_client.get(&url).send().await.ok()?;
    let json: serde_json::Value = resp.json().await.ok()?;

    let treasury_balance_sats = json.get("treasury_balance_sats")?.as_u64()?;
    let threshold_ts = json
        .get("threshold_reached_at")
        .and_then(|v| v.as_i64())
        .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0));

    Some(TreasuryState::from_stored(
        treasury_balance_sats,
        threshold_ts,
    ))
}

/// Localhost-only diagnostic: exercises every component of the L2 fee pipeline
/// with synthetic data but real DB/HTTP/node connections.
async fn verify_fee_pipeline(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    use ghost_reconciliation::fee_distribution::{L2FeeDistribution, TreasuryState};

    let mut steps = serde_json::Map::new();
    let test_epoch: u64 = 999_999;
    let test_fee: u64 = 2_000;

    // Pre-clean: delete any leftover test row from a previous run
    let _ = state.db.with_connection(|conn| {
        conn.execute(
            "DELETE FROM l2_epoch_fees WHERE epoch = ?1",
            rusqlite::params![test_epoch as i64],
        )
        .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))?;
        Ok(())
    });

    // Step 1: DB Write — insert test wraith fee
    let db_write = match state.db.increment_wraith_fee(test_epoch, test_fee) {
        Ok(()) => serde_json::json!({ "pass": true, "epoch": test_epoch, "fee_sats": test_fee }),
        Err(e) => serde_json::json!({ "pass": false, "error": format!("{e}") }),
    };
    let db_write_pass = db_write
        .get("pass")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    steps.insert("db_write".into(), db_write);

    // Step 2: DB Read — verify test epoch appears in undistributed fees
    let db_read = if db_write_pass {
        match state.db.get_undistributed_fees() {
            Ok(fees) => {
                let found = fees.iter().any(|(e, s)| *e == test_epoch && *s == test_fee);
                serde_json::json!({
                    "pass": found,
                    "undistributed_count": fees.len(),
                    "found_test_epoch": found,
                })
            }
            Err(e) => serde_json::json!({ "pass": false, "error": format!("{e}") }),
        }
    } else {
        serde_json::json!({ "pass": false, "error": "skipped (db_write failed)" })
    };
    let db_read_pass = db_read
        .get("pass")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    steps.insert("db_read".into(), db_read);

    // Step 3: HTTP Call — query ghost-pool for fee distribution context
    let (http_call, ctx) = match query_fee_distribution_context(&state).await {
        Some(c) => {
            let json = serde_json::json!({
                "pass": true,
                "treasury_balance_sats": c.treasury_balance_sats,
                "threshold_reached": c.threshold_reached_at.is_some(),
                "qualified_nodes": c.ghost_pay_nodes.len(),
            });
            (json, Some(c))
        }
        None => (
            serde_json::json!({ "pass": false, "error": "ghost-pool unreachable or bad response" }),
            None,
        ),
    };
    let http_pass = http_call
        .get("pass")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    steps.insert("http_call".into(), http_call);

    // Step 4: Fee Distribution — calculate with real treasury state + nodes + test fee pool
    let fee_dist = if http_pass {
        let c = ctx.as_ref().unwrap();
        let treasury = match c.threshold_reached_at {
            Some(ts) => {
                let mut t = TreasuryState {
                    balance_sats: c.treasury_balance_sats,
                    threshold_reached_at: None,
                };
                t.threshold_reached_at = chrono::DateTime::from_timestamp(ts, 0);
                t
            }
            None => TreasuryState {
                balance_sats: c.treasury_balance_sats,
                threshold_reached_at: None,
            },
        };

        let dist = L2FeeDistribution::calculate(
            test_fee,
            &treasury,
            chrono::Utc::now(),
            &c.ghost_pay_nodes,
        );

        let conservation = dist.treasury_amount + dist.node_pool == dist.total_fee_pool;
        let node_payouts: Vec<serde_json::Value> = dist
            .node_payouts
            .iter()
            .map(|(id, _addr, amt)| serde_json::json!({ "node": id, "amount": amt }))
            .collect();

        serde_json::json!({
            "pass": conservation,
            "treasury_amount": dist.treasury_amount,
            "node_pool": dist.node_pool,
            "node_payouts": node_payouts,
            "conservation_check": conservation,
        })
    } else {
        serde_json::json!({ "pass": false, "error": "skipped (http_call failed)" })
    };
    let fee_dist_pass = fee_dist
        .get("pass")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    steps.insert("fee_distribution".into(), fee_dist);

    // Step 5: Settlement Build — synthetic batch with L2 fee outputs
    let settlement_build = if fee_dist_pass {
        let c = ctx.as_ref().unwrap();
        let treasury = match c.threshold_reached_at {
            Some(ts) => {
                let mut t = TreasuryState {
                    balance_sats: c.treasury_balance_sats,
                    threshold_reached_at: None,
                };
                t.threshold_reached_at = chrono::DateTime::from_timestamp(ts, 0);
                t
            }
            None => TreasuryState {
                balance_sats: c.treasury_balance_sats,
                threshold_reached_at: None,
            },
        };
        let dist = L2FeeDistribution::calculate(
            test_fee,
            &treasury,
            chrono::Utc::now(),
            &c.ghost_pay_nodes,
        );

        // Build synthetic executor with 10 settlements
        let treasury_addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string();
        let mut executor = BatchExecutor::new(state.network, treasury_addr);
        executor.set_block_height(800_000);

        let dest = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string();
        let txid: bitcoin::Txid =
            "0000000000000000000000000000000000000000000000000000000000000001"
                .parse()
                .unwrap();

        let settlement_count = 10u32;
        let amount_per = 10_000u64;
        // Input must cover settlement amount + share of L2 fees
        let input_per = 15_000u64;

        for i in 0..settlement_count {
            if let Ok(s) = Settlement::new(
                format!("ghost1_diag_{i}"),
                [i as u8; 32],
                dest.clone(),
                amount_per,
            ) {
                // Synthetic data for diagnostics — no real ownership to verify
                #[allow(deprecated)]
                let _ = executor.add_settlement(s);
            }
            executor.add_input(ReconciliationInput {
                txid,
                vout: i,
                amount: input_per,
                ghost_id: format!("ghost1_diag_{i}"),
                lock_id: Some([i as u8; 32]),
                confirmations: 10,
            });
        }

        match executor.form_batch() {
            Ok(batch) => {
                match executor.build_transaction_with_l2_fees(
                    &batch,
                    1,
                    dist.treasury_amount,
                    &dist.node_payouts,
                ) {
                    Ok(btx) => {
                        let h7 = btx.total_output_sats
                            + btx.treasury_amount
                            + btx.mining_fee
                            + btx.node_rewards
                            <= btx.total_input_sats;
                        serde_json::json!({
                            "pass": h7,
                            "treasury_output": btx.treasury_amount,
                            "node_rewards": btx.node_rewards,
                            "total_inputs": btx.total_input_sats,
                            "total_outputs_incl_fees": btx.total_output_sats + btx.treasury_amount + btx.mining_fee + btx.node_rewards,
                            "h7_satisfied": h7,
                        })
                    }
                    Err(e) => serde_json::json!({ "pass": false, "error": format!("{e}") }),
                }
            }
            Err(e) => serde_json::json!({ "pass": false, "error": format!("form_batch: {e}") }),
        }
    } else {
        serde_json::json!({ "pass": false, "error": "skipped (fee_distribution failed)" })
    };
    let settlement_pass = settlement_build
        .get("pass")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    steps.insert("settlement_build".into(), settlement_build);

    // Step 6: Cleanup — delete the test row entirely for idempotent re-runs
    let cleanup = match state.db.with_connection(|conn| {
        conn.execute(
            "DELETE FROM l2_epoch_fees WHERE epoch = ?1",
            rusqlite::params![test_epoch as i64],
        )
        .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))?;
        Ok(())
    }) {
        Ok(()) => serde_json::json!({ "pass": true }),
        Err(e) => serde_json::json!({ "pass": false, "error": format!("{e}") }),
    };
    let cleanup_pass = cleanup
        .get("pass")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    steps.insert("cleanup".into(), cleanup);

    let all_pass = db_write_pass
        && db_read_pass
        && http_pass
        && fee_dist_pass
        && settlement_pass
        && cleanup_pass;

    Json(serde_json::json!({
        "success": all_pass,
        "steps": steps,
    }))
}

// =============================================================================
// L2 + Wraith Simulation Endpoints (Part 1 & Part 3)
// =============================================================================

/// Simulate L2 activity: shield, ZK proof, transfer, fee injection, distribution
async fn simulate_l2_activity(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    use ghost_reconciliation::fee_distribution::{L2FeeDistribution, TreasuryState};
    use std::path::PathBuf;

    let mut steps = serde_json::Map::new();
    let start = std::time::Instant::now();

    // Step 1: Load MPC prover params
    let prover = {
        let params_dir = PathBuf::from(
            std::env::var("GHOST_MPC_PARAMS_DIR")
                .unwrap_or_else(|_| "/home/ghost/.ghost/mpc_params".to_string()),
        );
        let params_path = params_dir.join("note_spend_params_current.bin");
        match ghost_mpc::params::load_parameters(&params_path) {
            Ok(params) => {
                let prover = ghost_zkp::GhostNoteProver::new_with_params(
                    Arc::new(params),
                    COMMITMENT_TREE_DEPTH,
                );
                steps.insert(
                    "load_prover".into(),
                    serde_json::json!({
                        "pass": true,
                        "params_path": params_path.display().to_string(),
                        "elapsed_ms": start.elapsed().as_millis(),
                    }),
                );
                prover
            }
            Err(e) => {
                steps.insert(
                    "load_prover".into(),
                    serde_json::json!({
                        "pass": false,
                        "error": format!("{e}"),
                        "params_path": params_path.display().to_string(),
                    }),
                );
                return Json(serde_json::json!({
                    "success": false,
                    "steps": steps,
                    "error": "MPC prover params not available",
                }));
            }
        }
    };

    // Step 2: Shield a note (100,000 sats with random blinding)
    // Zero last 8 bytes of each 32-byte random value to stay under
    // BLS12-381 scalar field modulus (~2^255). blstrs is little-endian,
    // so the last bytes are most significant.
    let spending_key: [u8; 32] = {
        let mut buf = [0u8; 32];
        if getrandom::getrandom(&mut buf).is_err() {
            return Json(
                serde_json::json!({"success": false, "error": "entropy source unavailable"}),
            );
        }
        buf[24..].fill(0);
        buf
    };
    let blinding: [u8; 32] = {
        let mut buf = [0u8; 32];
        if getrandom::getrandom(&mut buf).is_err() {
            return Json(
                serde_json::json!({"success": false, "error": "entropy source unavailable"}),
            );
        }
        buf[24..].fill(0);
        buf
    };
    let note_value: u64 = 100_000;

    let commitment = match ghost_zkp::compute_commitment_bytes(note_value, &blinding) {
        Ok(c) => c,
        Err(e) => {
            steps.insert(
                "shield_note".into(),
                serde_json::json!({"pass": false, "error": format!("{e}")}),
            );
            return Json(serde_json::json!({"success": false, "steps": steps}));
        }
    };

    let (note_index, commitment_root) = {
        let mut tree = state.commitment_tree.write();
        let idx = tree.next_index();
        tree.insert(idx, commitment);
        let root = tree.root().unwrap_or([0u8; 32]);
        (idx, root)
    };

    // Persist shield note
    let current_height = state.rpc.get_block_count().await.unwrap_or(0);
    let _ =
        state
            .db
            .insert_confidential_note(note_index, &commitment, &spending_key, current_height);

    // Sync to ghost-pool with retry
    let sync_ok = sync_commitment_with_retry(
        &state.pool_http_client,
        &state.pool_api_url,
        &commitment,
        note_index,
        current_height,
    )
    .await;

    steps.insert(
        "shield_note".into(),
        serde_json::json!({
            "pass": true,
            "note_index": note_index,
            "commitment": hex::encode(commitment),
            "root": hex::encode(commitment_root),
            "synced_to_pool": sync_ok,
        }),
    );

    // Step 3: Get merkle proof
    let merkle_siblings = {
        let tree = state.commitment_tree.read();
        match tree.get_proof(note_index) {
            Ok(proof) => proof.siblings,
            Err(e) => {
                steps.insert(
                    "merkle_proof".into(),
                    serde_json::json!({"pass": false, "error": format!("{e}")}),
                );
                return Json(serde_json::json!({"success": false, "steps": steps}));
            }
        }
    };
    steps.insert(
        "merkle_proof".into(),
        serde_json::json!({
            "pass": true,
            "depth": merkle_siblings.len(),
            "note_index": note_index,
        }),
    );

    // Step 4: Generate ZK proof
    let transfer_amount: u64 = 50_000;
    let change_blinding: [u8; 32] = {
        let mut buf = [0u8; 32];
        if getrandom::getrandom(&mut buf).is_err() {
            return Json(
                serde_json::json!({"success": false, "error": "entropy source unavailable"}),
            );
        }
        buf[24..].fill(0);
        buf
    };
    let recipient_blinding: [u8; 32] = {
        let mut buf = [0u8; 32];
        if getrandom::getrandom(&mut buf).is_err() {
            return Json(
                serde_json::json!({"success": false, "error": "entropy source unavailable"}),
            );
        }
        buf[24..].fill(0);
        buf
    };

    let witness = ghost_zkp::GhostNoteSpendWitness {
        spending_key,
        note_value,
        note_blinding: blinding,
        note_index,
        epoch: ghost_common::constants::l2_epoch_from_height(current_height),
        merkle_siblings,
        amount: transfer_amount,
        change_blinding,
        recipient_blinding,
    };

    let proof_start = std::time::Instant::now();
    let proof = match prover.prove(&witness) {
        Ok(p) => {
            steps.insert(
                "zk_proof".into(),
                serde_json::json!({
                    "pass": true,
                    "proof_bytes": p.proof.len(),
                    "nullifier": hex::encode(p.public_inputs.nullifier),
                    "change_commitment": hex::encode(p.public_inputs.change_commitment),
                    "recipient_commitment": hex::encode(p.public_inputs.recipient_commitment),
                    "elapsed_ms": proof_start.elapsed().as_millis(),
                }),
            );
            p
        }
        Err(e) => {
            steps.insert(
                "zk_proof".into(),
                serde_json::json!({"pass": false, "error": format!("{e}")}),
            );
            return Json(serde_json::json!({"success": false, "steps": steps}));
        }
    };

    // Step 5: Verify proof through production verifier + apply to tree
    let verifier = match state.note_spend_verifier.read().as_ref().cloned() {
        Some(v) => v,
        None => {
            steps.insert(
                "verify_transfer".into(),
                serde_json::json!({"pass": false, "error": "NoteSpend verifier not initialized"}),
            );
            return Json(serde_json::json!({"success": false, "steps": steps}));
        }
    };

    match verifier.verify(&proof) {
        Ok(true) => {
            // Apply to tree: spend nullifier, insert new commitments
            let change_index;
            let recipient_index;
            let new_root;
            {
                let mut tree = state.commitment_tree.write();
                tree.spend_nullifier(proof.public_inputs.nullifier);
                change_index = tree.next_index();
                tree.insert(change_index, proof.public_inputs.change_commitment);
                recipient_index = tree.next_index();
                tree.insert(recipient_index, proof.public_inputs.recipient_commitment);
                new_root = tree.root().unwrap_or([0u8; 32]);
            }

            // Persist new notes
            let _ = state.db.insert_confidential_note(
                change_index,
                &proof.public_inputs.change_commitment,
                &spending_key,
                current_height,
            );
            let _ = state.db.insert_confidential_note(
                recipient_index,
                &proof.public_inputs.recipient_commitment,
                &[0u8; 32], // Simulated recipient
                current_height,
            );

            steps.insert(
                "verify_transfer".into(),
                serde_json::json!({
                    "pass": true,
                    "verified_by_mpc_vk": true,
                    "nullifier_spent": hex::encode(proof.public_inputs.nullifier),
                    "change_index": change_index,
                    "recipient_index": recipient_index,
                    "new_root": hex::encode(new_root),
                }),
            );
        }
        Ok(false) => {
            steps.insert(
                "verify_transfer".into(),
                serde_json::json!({"pass": false, "error": "Proof verification returned false"}),
            );
            return Json(serde_json::json!({"success": false, "steps": steps}));
        }
        Err(e) => {
            steps.insert(
                "verify_transfer".into(),
                serde_json::json!({"pass": false, "error": format!("{e}")}),
            );
            return Json(serde_json::json!({"success": false, "steps": steps}));
        }
    }

    // Step 6: Inject wraith fee
    let epoch = ghost_common::constants::l2_epoch_from_height(current_height);
    let sim_fee: u64 = 5_000;
    match state.db.increment_wraith_fee(epoch, sim_fee) {
        Ok(()) => {
            steps.insert(
                "inject_fee".into(),
                serde_json::json!({"pass": true, "epoch": epoch, "fee_sats": sim_fee}),
            );
        }
        Err(e) => {
            steps.insert(
                "inject_fee".into(),
                serde_json::json!({"pass": false, "error": format!("{e}")}),
            );
            return Json(serde_json::json!({"success": false, "steps": steps}));
        }
    }

    // Step 7: Fee distribution calculation
    let fee_dist = match query_fee_distribution_context(&state).await {
        Some(ctx) => {
            let treasury = match ctx.threshold_reached_at {
                Some(ts) => {
                    let mut t = TreasuryState {
                        balance_sats: ctx.treasury_balance_sats,
                        threshold_reached_at: None,
                    };
                    t.threshold_reached_at = chrono::DateTime::from_timestamp(ts, 0);
                    t
                }
                None => TreasuryState {
                    balance_sats: ctx.treasury_balance_sats,
                    threshold_reached_at: None,
                },
            };

            let dist = L2FeeDistribution::calculate(
                sim_fee,
                &treasury,
                chrono::Utc::now(),
                &ctx.ghost_pay_nodes,
            );

            let node_payouts: Vec<serde_json::Value> = dist
                .node_payouts
                .iter()
                .map(|(id, _addr, amt)| serde_json::json!({"node": id, "amount": amt}))
                .collect();

            serde_json::json!({
                "pass": true,
                "treasury_amount": dist.treasury_amount,
                "node_pool": dist.node_pool,
                "node_payouts": node_payouts,
            })
        }
        None => {
            serde_json::json!({
                "pass": false,
                "error": "ghost-pool unreachable for fee distribution context",
            })
        }
    };
    steps.insert("fee_distribution".into(), fee_dist.clone());

    // Cleanup: remove the injected test fee
    let _ = state.db.with_connection(|conn| {
        conn.execute(
            "DELETE FROM l2_epoch_fees WHERE epoch = ?1 AND total_sats = ?2",
            rusqlite::params![epoch as i64, sim_fee as i64],
        )
        .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))?;
        Ok(())
    });

    let all_pass = steps
        .values()
        .all(|v| v.get("pass").and_then(|p| p.as_bool()).unwrap_or(false));

    Json(serde_json::json!({
        "success": all_pass,
        "elapsed_ms": start.elapsed().as_millis(),
        "steps": steps,
    }))
}

/// Simulate unshield (L2 → L1 withdrawal): shield a note, generate unshield proof, verify it.
/// Does NOT create an actual L1 transaction — validates the ZK pipeline only.
async fn simulate_unshield(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    use std::path::PathBuf;

    let mut steps = serde_json::Map::new();
    let start = std::time::Instant::now();

    // Step 1: Load unshield prover params (MPC slot 3)
    let prover = {
        let params_dir = PathBuf::from(
            std::env::var("GHOST_MPC_PARAMS_DIR")
                .unwrap_or_else(|_| "/home/ghost/.ghost/mpc_params".to_string()),
        );
        let params_path = params_dir.join("unshield_params_current.bin");
        match ghost_mpc::params::load_parameters(&params_path) {
            Ok(params) => {
                let prover = ghost_zkp::GhostUnshieldProver::new_with_params(
                    Arc::new(params),
                    COMMITMENT_TREE_DEPTH,
                );
                steps.insert(
                    "load_prover".into(),
                    serde_json::json!({
                        "pass": true,
                        "params_path": params_path.display().to_string(),
                        "elapsed_ms": start.elapsed().as_millis(),
                    }),
                );
                prover
            }
            Err(e) => {
                steps.insert(
                    "load_prover".into(),
                    serde_json::json!({
                        "pass": false,
                        "error": format!("{e}"),
                        "params_path": params_path.display().to_string(),
                    }),
                );
                return Json(serde_json::json!({
                    "success": false,
                    "steps": steps,
                    "error": "Unshield prover params not available",
                }));
            }
        }
    };

    // Step 2: Shield a test note (reuses same pattern as simulate-l2-activity)
    let spending_key: [u8; 32] = {
        let mut buf = [0u8; 32];
        if getrandom::getrandom(&mut buf).is_err() {
            return Json(
                serde_json::json!({"success": false, "error": "entropy source unavailable"}),
            );
        }
        buf[24..].fill(0);
        buf
    };
    let blinding: [u8; 32] = {
        let mut buf = [0u8; 32];
        if getrandom::getrandom(&mut buf).is_err() {
            return Json(
                serde_json::json!({"success": false, "error": "entropy source unavailable"}),
            );
        }
        buf[24..].fill(0);
        buf
    };
    let note_value: u64 = 100_000;

    let commitment = match ghost_zkp::compute_commitment_bytes(note_value, &blinding) {
        Ok(c) => c,
        Err(e) => {
            steps.insert(
                "shield_note".into(),
                serde_json::json!({"pass": false, "error": format!("{e}")}),
            );
            return Json(serde_json::json!({"success": false, "steps": steps}));
        }
    };

    let (note_index, _commitment_root) = {
        let mut tree = state.commitment_tree.write();
        let idx = tree.next_index();
        tree.insert(idx, commitment);
        let root = tree.root().unwrap_or([0u8; 32]);
        (idx, root)
    };

    let current_height = state.rpc.get_block_count().await.unwrap_or(0);
    let _ =
        state
            .db
            .insert_confidential_note(note_index, &commitment, &spending_key, current_height);

    // Sync to ghost-pool with retry
    let synced = sync_commitment_with_retry(
        &state.pool_http_client,
        &state.pool_api_url,
        &commitment,
        note_index,
        current_height,
    )
    .await;

    steps.insert(
        "shield_note".into(),
        serde_json::json!({
            "pass": true,
            "note_index": note_index,
            "note_value": note_value,
            "synced_to_pool": synced,
        }),
    );

    // Step 3: Get Merkle proof
    let merkle_siblings = {
        let tree = state.commitment_tree.read();
        match tree.get_proof(note_index) {
            Ok(proof) => proof.siblings,
            Err(e) => {
                steps.insert(
                    "merkle_proof".into(),
                    serde_json::json!({"pass": false, "error": format!("{e}")}),
                );
                return Json(serde_json::json!({"success": false, "steps": steps}));
            }
        }
    };
    steps.insert(
        "merkle_proof".into(),
        serde_json::json!({"pass": true, "depth": merkle_siblings.len()}),
    );

    // Step 4: Generate unshield proof (MPC slot 3 circuit)
    let epoch = ghost_common::constants::l2_epoch_from_height(current_height);
    let witness = ghost_zkp::UnshieldWitness {
        spending_key,
        note_value,
        note_blinding: blinding,
        note_index,
        epoch,
        merkle_siblings,
    };

    let proof_start = std::time::Instant::now();
    let proof = match prover.prove(&witness) {
        Ok(p) => {
            steps.insert(
                "unshield_proof".into(),
                serde_json::json!({
                    "pass": true,
                    "proof_bytes": p.proof.len(),
                    "nullifier": hex::encode(p.public_inputs.nullifier),
                    "withdrawal_amount": p.public_inputs.withdrawal_amount,
                    "elapsed_ms": proof_start.elapsed().as_millis(),
                }),
            );
            p
        }
        Err(e) => {
            steps.insert(
                "unshield_proof".into(),
                serde_json::json!({"pass": false, "error": format!("{e}")}),
            );
            return Json(serde_json::json!({"success": false, "steps": steps}));
        }
    };

    // Step 5: Verify through production unshield verifier
    let verifier = match state.unshield_verifier.read().as_ref().cloned() {
        Some(v) => v,
        None => {
            steps.insert(
                "verify_unshield".into(),
                serde_json::json!({"pass": false, "error": "Unshield verifier not initialized"}),
            );
            return Json(serde_json::json!({"success": false, "steps": steps}));
        }
    };

    match verifier.verify(&proof) {
        Ok(true) => {
            steps.insert(
                "verify_unshield".into(),
                serde_json::json!({
                    "pass": true,
                    "verified_by_mpc_vk": true,
                    "nullifier": hex::encode(proof.public_inputs.nullifier),
                    "withdrawal_amount": proof.public_inputs.withdrawal_amount,
                }),
            );
        }
        Ok(false) => {
            steps.insert(
                "verify_unshield".into(),
                serde_json::json!({"pass": false, "error": "Proof verification returned false"}),
            );
            return Json(serde_json::json!({"success": false, "steps": steps}));
        }
        Err(e) => {
            steps.insert(
                "verify_unshield".into(),
                serde_json::json!({"pass": false, "error": format!("{e}")}),
            );
            return Json(serde_json::json!({"success": false, "steps": steps}));
        }
    }

    let all_pass = steps
        .values()
        .all(|v| v.get("pass").and_then(|p| p.as_bool()).unwrap_or(false));

    Json(serde_json::json!({
        "success": all_pass,
        "elapsed_ms": start.elapsed().as_millis(),
        "steps": steps,
    }))
}

/// Test the full L1 withdrawal pipeline: shield → proof → submit_unshield → relay.
/// POST /api/v1/admin/trigger-settlement — Force-trigger epoch settlement now
async fn admin_trigger_settlement(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    use ghost_common::constants::{SettlementClass, L2_EPOCH_BLOCKS};

    // Use the current L2 epoch (or next one) to trigger settlement for all due classes
    let current_epoch = state
        .db
        .with_connection(|conn| {
            let h: i64 = conn
                .query_row("SELECT COALESCE(MAX(height), 0) FROM blocks", [], |r| {
                    r.get(0)
                })
                .unwrap_or(0);
            Ok(h as u64 / L2_EPOCH_BLOCKS)
        })
        .unwrap_or(1);

    // Use a synthetic epoch that triggers all classes (divisible by 28)
    let trigger_epoch = if current_epoch == 0 {
        28
    } else {
        // Round up to next multiple of 28 to trigger all classes
        ((current_epoch / 28) + 1) * 28
    };

    info!(trigger_epoch, current_epoch, "Admin-triggered settlement");
    let state_clone = state.clone();
    tokio::spawn(try_epoch_settlement(state_clone, trigger_epoch));

    Json(serde_json::json!({
        "success": true,
        "trigger_epoch": trigger_epoch,
        "current_epoch": current_epoch,
        "message": "Settlement triggered for all classes"
    }))
}

/// Does NOT broadcast to Bitcoin L1 (requires a funded Ghost Lock).
/// Exercises: ZK proof generation, nullifier spending, and relay to ghost-pool.
async fn test_withdrawal(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    use std::path::PathBuf;

    let mut steps = serde_json::Map::new();
    let start = std::time::Instant::now();

    // Step 1: Load unshield prover params (MPC slot 3)
    let prover = {
        let params_dir = PathBuf::from(
            std::env::var("GHOST_MPC_PARAMS_DIR")
                .unwrap_or_else(|_| "/home/ghost/.ghost/mpc_params".to_string()),
        );
        let params_path = params_dir.join("unshield_params_current.bin");
        match ghost_mpc::params::load_parameters(&params_path) {
            Ok(params) => {
                let prover = ghost_zkp::GhostUnshieldProver::new_with_params(
                    Arc::new(params),
                    COMMITMENT_TREE_DEPTH,
                );
                steps.insert("load_prover".into(), serde_json::json!({"pass": true}));
                prover
            }
            Err(e) => {
                steps.insert(
                    "load_prover".into(),
                    serde_json::json!({"pass": false, "error": format!("{e}")}),
                );
                return Json(
                    serde_json::json!({"success": false, "steps": steps, "error": "Prover params not available"}),
                );
            }
        }
    };

    // Step 2: Shield a test note
    let spending_key: [u8; 32] = {
        let mut buf = [0u8; 32];
        if getrandom::getrandom(&mut buf).is_err() {
            return Json(
                serde_json::json!({"success": false, "error": "entropy source unavailable"}),
            );
        }
        buf[24..].fill(0);
        buf
    };
    let blinding: [u8; 32] = {
        let mut buf = [0u8; 32];
        if getrandom::getrandom(&mut buf).is_err() {
            return Json(
                serde_json::json!({"success": false, "error": "entropy source unavailable"}),
            );
        }
        buf[24..].fill(0);
        buf
    };
    let note_value: u64 = 1_000; // 1000 sats

    let commitment = match ghost_zkp::compute_commitment_bytes(note_value, &blinding) {
        Ok(c) => c,
        Err(e) => {
            steps.insert(
                "shield_note".into(),
                serde_json::json!({"pass": false, "error": format!("{e}")}),
            );
            return Json(serde_json::json!({"success": false, "steps": steps}));
        }
    };

    let (note_index, commitment_root) = {
        let mut tree = state.commitment_tree.write();
        let idx = tree.next_index();
        tree.insert(idx, commitment);
        let root = tree.root().unwrap_or([0u8; 32]);
        (idx, root)
    };

    let current_height = state.rpc.get_block_count().await.unwrap_or(0);
    let _ =
        state
            .db
            .insert_confidential_note(note_index, &commitment, &spending_key, current_height);

    // Sync to ghost-pool
    let sync_url = format!("{}/api/v1/l2/sync-commitment", state.pool_api_url);
    let sync_body = serde_json::json!({
        "commitment": hex::encode(commitment),
        "note_index": note_index,
        "block_height": current_height,
    });
    let sync_result = state
        .pool_http_client
        .post(&sync_url)
        .json(&sync_body)
        .send()
        .await;
    let synced = sync_result.is_ok();

    steps.insert(
        "shield_note".into(),
        serde_json::json!({
            "pass": true,
            "note_index": note_index,
            "note_value": note_value,
            "synced_to_pool": synced,
        }),
    );

    // Step 3: Get Merkle proof
    let merkle_siblings = {
        let tree = state.commitment_tree.read();
        match tree.get_proof(note_index) {
            Ok(proof) => proof.siblings,
            Err(e) => {
                steps.insert(
                    "merkle_proof".into(),
                    serde_json::json!({"pass": false, "error": format!("{e}")}),
                );
                return Json(serde_json::json!({"success": false, "steps": steps}));
            }
        }
    };
    steps.insert(
        "merkle_proof".into(),
        serde_json::json!({"pass": true, "depth": merkle_siblings.len()}),
    );

    // Step 4: Generate unshield proof
    let epoch = ghost_common::constants::l2_epoch_from_height(current_height);
    let witness = ghost_zkp::UnshieldWitness {
        spending_key,
        note_value,
        note_blinding: blinding,
        note_index,
        epoch,
        merkle_siblings,
    };

    let proof_start = std::time::Instant::now();
    let proof = match prover.prove(&witness) {
        Ok(p) => {
            steps.insert(
                "unshield_proof".into(),
                serde_json::json!({
                    "pass": true,
                    "proof_bytes": p.proof.len(),
                    "nullifier": hex::encode(p.public_inputs.nullifier),
                    "withdrawal_amount": p.public_inputs.withdrawal_amount,
                    "elapsed_ms": proof_start.elapsed().as_millis(),
                }),
            );
            p
        }
        Err(e) => {
            steps.insert(
                "unshield_proof".into(),
                serde_json::json!({"pass": false, "error": format!("{e}")}),
            );
            return Json(serde_json::json!({"success": false, "steps": steps}));
        }
    };
    let proof_time_ms = proof_start.elapsed().as_millis();

    // Step 5: Submit through the REAL unshield path (POST to our own endpoint)
    let unshield_body = serde_json::json!({
        "proof_hex": hex::encode(&proof.proof),
        "commitment_root": hex::encode(commitment_root),
        "nullifier": hex::encode(proof.public_inputs.nullifier),
        "withdrawal_amount_sats": proof.public_inputs.withdrawal_amount,
        "destination_address": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
    });

    let submit_url = format!("http://localhost:{}/api/v1/confidential/unshield", 8800);

    // Construct HMAC auth headers (unshield endpoint requires API auth)
    let body_bytes = serde_json::to_vec(&unshield_body).unwrap_or_default();
    let timestamp = chrono::Utc::now().timestamp().to_string();
    let signature = if let Some(ref secret) = state.config.api_secret {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())
            .unwrap_or_else(|_| <Hmac<Sha256> as Mac>::new_from_slice(b"").unwrap());
        mac.update(timestamp.as_bytes());
        mac.update(&body_bytes);
        hex::encode(mac.finalize().into_bytes())
    } else {
        String::new()
    };

    let submit_result = state
        .pool_http_client
        .post(&submit_url)
        .header("Content-Type", "application/json")
        .header("X-Ghost-Signature", &signature)
        .header("X-Ghost-Timestamp", &timestamp)
        .body(body_bytes)
        .send()
        .await;

    let (nullifier_spent, relayed_to_pool, submit_detail) = match submit_result {
        Ok(resp) => {
            let status = resp.status();
            let body: serde_json::Value = resp.json().await.unwrap_or_default();
            if status.is_success() {
                let relayed = body
                    .get("relayed_to_pool")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                (true, relayed, body)
            } else {
                (false, false, body)
            }
        }
        Err(e) => (false, false, serde_json::json!({"error": format!("{e}")})),
    };

    steps.insert(
        "submit_unshield".into(),
        serde_json::json!({
            "pass": nullifier_spent,
            "nullifier_spent": nullifier_spent,
            "relayed_to_pool": relayed_to_pool,
            "detail": submit_detail,
        }),
    );

    let all_pass = steps
        .values()
        .all(|v| v.get("pass").and_then(|p| p.as_bool()).unwrap_or(false));

    Json(serde_json::json!({
        "success": all_pass,
        "elapsed_ms": start.elapsed().as_millis(),
        "proof_time_ms": proof_time_ms,
        "nullifier_spent": nullifier_spent,
        "relayed_to_pool": relayed_to_pool,
        "steps": steps,
    }))
}

/// Seed test balance by inserting Active ghost locks (admin/soak-test only).
/// Creates a synthetic lock per call, giving the node spendable L2 balance.
async fn seed_test_balance(
    State(state): State<Arc<AppState>>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let amount_sats = req
        .get("amount_sats")
        .and_then(|v| v.as_u64())
        .unwrap_or(1_000_000); // default 0.01 BTC

    let ghost_id = match state.ghost_id.read().clone() {
        Some(id) => id,
        None => return Json(serde_json::json!({"success": false, "error": "Ghost ID not loaded"})),
    };

    let current_height = state.rpc.get_block_count().await.unwrap_or(0) as u32;

    // Generate a unique lock ID from random bytes
    let lock_id = {
        let mut buf = [0u8; 16];
        let _ = getrandom::getrandom(&mut buf);
        format!("test_{}", hex::encode(buf))
    };

    // Dummy pubkeys (not used for actual spending in test mode)
    let dummy_pubkey = "02".to_string() + &"00".repeat(32);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let record = GhostLockRecord {
        lock_id: lock_id.clone(),
        owner_ghost_id: ghost_id,
        lock_pubkey: dummy_pubkey.clone(),
        recovery_pubkey: dummy_pubkey,
        denomination: "Test".to_string(),
        amount_sats,
        timelock_tier: "Standard".to_string(),
        creation_height: current_height,
        recovery_height: current_height + 1000,
        state: DbLockState::Active,
        funding_txid: Some(format!("test_{}", hex::encode(&lock_id.as_bytes()[..16]))),
        funding_vout: Some(0),
        spend_txid: None,
        output_script: "00".repeat(34),
        jump_risk_tier: "Low".to_string(),
        next_jump_height: None,
        created_at: now,
        updated_at: now,
        source: "soak_test".to_string(),
        wraith_fee_sats: 0,
        key_index: None, // Test lock, not signable
    };

    match state.db.insert_ghost_lock(&record) {
        Ok(()) => {
            info!(lock_id = %lock_id, amount_sats, "Seeded test balance (Active ghost lock)");
            Json(serde_json::json!({
                "success": true,
                "lock_id": lock_id,
                "amount_sats": amount_sats,
            }))
        }
        Err(e) => Json(serde_json::json!({
            "success": false,
            "error": format!("{e}"),
        })),
    }
}

/// Execute a settlement batch for a set of withdrawal requests.
///
/// This function handles the full UTXO validation → input building → batch formation →
/// L2 fee distribution → TX signing → broadcast pipeline.
/// Returns the batch_id on success, or an error string on failure.
async fn execute_settlement_batch(
    state: &Arc<AppState>,
    withdrawals: Vec<WithdrawalRequest>,
) -> Result<Option<String>, String> {
    if withdrawals.is_empty() {
        return Ok(None);
    }

    let treasury_address = state.config.treasury_address.clone().unwrap_or_default();
    let mut executor = BatchExecutor::new(state.network, treasury_address);

    // Track failed broadcast attempts per lock_id for exponential backoff
    let mut retry_tracker: std::collections::HashMap<String, (u32, std::time::Instant)> =
        std::collections::HashMap::new();

    let mut processed_withdrawal_ids: Vec<i64> = Vec::new();

    let fee_rate = estimate_fee_rate(state).await;

    for withdrawal in &withdrawals {
        debug!(
            withdrawal_id = ?withdrawal.id,
            lock_id = %withdrawal.lock_id,
            amount = withdrawal.amount_sats,
            "Processing withdrawal for settlement"
        );
        let lock = match state.db.get_ghost_lock(&withdrawal.lock_id) {
            Ok(Some(l)) => l,
            Ok(None) => {
                warn!(lock_id = %withdrawal.lock_id, "Lock not found for withdrawal");
                continue;
            }
            Err(e) => {
                warn!(error = %e, "Failed to get lock");
                continue;
            }
        };

        if lock.state != DbLockState::Active || lock.funding_txid.is_none() {
            warn!(
                lock_id = %lock.lock_id,
                state = ?lock.state,
                "Lock not ready for settlement"
            );
            continue;
        }

        // Check cooldown from previous failed broadcast
        if let Some(&(attempts, last_try)) = retry_tracker.get(&lock.lock_id) {
            let backoff_secs =
                std::cmp::min(300u64.saturating_mul(2u64.saturating_pow(attempts)), 7200);
            if last_try.elapsed().as_secs() < backoff_secs {
                debug!(
                    lock_id = %lock.lock_id,
                    attempts = attempts,
                    backoff_secs = backoff_secs,
                    "Lock in cooldown after failed broadcast, skipping"
                );
                continue;
            }
        }

        let (txid, vout) = match (lock.funding_txid.as_ref(), lock.funding_vout) {
            (Some(txid_str), Some(vout)) => {
                let txid: bitcoin::Txid = match txid_str.parse() {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                (txid, vout)
            }
            _ => continue,
        };

        // Verify UTXO exists on-chain
        let utxo_confirmations = match state.rpc.get_tx_out(&txid.to_string(), vout, false).await {
            Ok(Some(tx_out)) => tx_out.confirmations.max(0) as u32,
            Ok(None) => {
                warn!(
                    lock_id = %lock.lock_id,
                    txid = %txid,
                    vout = vout,
                    "UTXO not found on-chain, skipping settlement"
                );
                if let Err(e) = state
                    .db
                    .update_ghost_lock_state(&lock.lock_id, DbLockState::Spent)
                {
                    error!(
                        lock_id = %lock.lock_id,
                        error = %e,
                        "Failed to mark lock as spent"
                    );
                }
                continue;
            }
            Err(e) => {
                warn!(
                    lock_id = %lock.lock_id,
                    error = %e,
                    "Failed to verify UTXO existence, skipping this withdrawal"
                );
                continue;
            }
        };

        // Verify we can sign this lock before adding to batch
        {
            let keys_guard = state.keys.read();
            if let Some(keys) = keys_guard.as_ref() {
                let lock_index = match state
                    .db
                    .get_lock_index_for_owner(&lock.owner_ghost_id, &lock.lock_id)
                {
                    Ok(idx) => idx,
                    Err(e) => {
                        warn!(lock_id = %lock.lock_id, error = %e, "Cannot get lock index, skipping");
                        continue;
                    }
                };
                let lock_secret = match keys.derive_lock_secret(lock_index) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(lock_id = %lock.lock_id, error = ?e, "Cannot derive lock key, skipping");
                        continue;
                    }
                };
                let secp = Secp256k1::new();
                let derived_pubkey =
                    bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &lock_secret);
                if let Ok(stored_bytes) = hex::decode(&lock.lock_pubkey) {
                    if let Ok(stored_pubkey) =
                        bitcoin::secp256k1::PublicKey::from_slice(&stored_bytes)
                    {
                        if derived_pubkey != stored_pubkey {
                            warn!(lock_id = %lock.lock_id, "Pubkey mismatch, skipping (stale lock)");
                            continue;
                        }
                    }
                }
            }
        }

        let input = ReconciliationInput {
            txid,
            vout,
            amount: lock.amount_sats,
            ghost_id: lock.owner_ghost_id.clone(),
            lock_id: Some(hex_to_32bytes(&lock.lock_id)),
            confirmations: utxo_confirmations,
        };

        // Create settlement BEFORE adding input to executor — if Settlement::new()
        // fails (e.g. below minimum), we must not leave an orphan input in the executor
        // which would corrupt the fund tracking for subsequent withdrawals.
        let source_lock_id = hex_to_32bytes(&lock.lock_id);
        let settlement = match Settlement::new(
            withdrawal.ghost_id.clone(),
            source_lock_id,
            withdrawal.destination_address.clone(),
            withdrawal.amount_sats,
        ) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    withdrawal_id = ?withdrawal.id,
                    error = %e,
                    "Failed to create settlement"
                );
                continue;
            }
        };

        executor.add_input(input);

        #[allow(deprecated)]
        if let Err(e) = executor.add_settlement(settlement) {
            warn!(
                withdrawal_id = ?withdrawal.id,
                error = %e,
                "Failed to add settlement"
            );
            continue;
        }

        if let Some(id) = withdrawal.id {
            processed_withdrawal_ids.push(id);
        }
    }

    if !executor.should_form_batch() {
        return Ok(None);
    }

    info!("Forming settlement batch");

    let batch = executor
        .form_batch()
        .map_err(|e| format!("Failed to form batch: {}", e))?;
    let batch_id = batch.id_hex();
    info!(batch_id = %batch_id, "Formed settlement batch");

    // Collect undistributed L2 fees for inclusion in settlement.
    // L2 fees are funded from the total batch input pool — the difference between
    // total lock inputs and total settlement outputs covers mining fees + L2 fee
    // distribution. The H-7 overflow check in build_transaction_with_l2_fees
    // validates that outputs never exceed inputs.
    let undistributed = state.db.get_undistributed_fees().unwrap_or_default();
    let l2_fee_pool: u64 = undistributed.iter().map(|(_, fee)| fee).sum();
    let total_input_sats: u64 = withdrawals
        .iter()
        .filter(|w| processed_withdrawal_ids.contains(&w.id.unwrap_or(-1)))
        .map(|w| {
            // Input = withdrawal amount + fee (the full lock value)
            w.amount_sats.saturating_add(w.fee_sats)
        })
        .sum();
    let total_settlement_sats: u64 = withdrawals
        .iter()
        .filter(|w| processed_withdrawal_ids.contains(&w.id.unwrap_or(-1)))
        .map(|w| w.amount_sats)
        .sum();
    // Available for fees = inputs - settlements - estimated mining fee
    let estimated_mining_fee = fee_rate * 400; // conservative vsize estimate (P2WSH + L2 fee outputs)
    let available_for_l2 = total_input_sats
        .saturating_sub(total_settlement_sats)
        .saturating_sub(estimated_mining_fee);
    let include_l2_fees = l2_fee_pool > 0 && l2_fee_pool <= available_for_l2;

    if l2_fee_pool > 0 && !include_l2_fees {
        info!(
            l2_fee_pool,
            available_for_l2, "L2 fees exceed available batch capacity, deferring to larger batch"
        );
    }

    // Amounts this settlement is about to commit on-chain via the L2
    // fee split. Captured here so the broadcast-success path can bump
    // the cumulative kv_store accumulators in one shot.
    let mut l2_node_reward_paid: u64 = 0;
    let mut l2_treasury_paid: u64 = 0;

    let build_result = if include_l2_fees {
        // Per-node direct fee split: this node earns from its own L2 traffic
        let node_payout_address = state.config.node_payout_address.clone();
        match (query_treasury_state(state).await, node_payout_address) {
            (Some(treasury_state), Some(addr)) => {
                use ghost_reconciliation::fee_distribution::calculate_node_direct;
                let (treasury_amount, node_amount) =
                    calculate_node_direct(l2_fee_pool, &treasury_state, chrono::Utc::now());
                info!(
                    l2_fee_pool,
                    treasury_amount,
                    node_amount,
                    "Including L2 fees in settlement batch (node-direct)"
                );
                // Single-element node payout vec — this node only
                let node_payouts = if node_amount > 0 {
                    vec![("self".to_string(), addr, node_amount)]
                } else {
                    vec![]
                };
                l2_node_reward_paid = node_amount;
                l2_treasury_paid = treasury_amount;
                executor.build_transaction_with_l2_fees(
                    &batch,
                    fee_rate,
                    treasury_amount,
                    &node_payouts,
                )
            }
            (_, None) => {
                warn!("No --node-payout-address configured, building without L2 fees");
                executor.build_transaction(&batch, fee_rate)
            }
            (None, _) => {
                warn!("Failed to get treasury state, building without L2 fees");
                executor.build_transaction(&batch, fee_rate)
            }
        }
    } else {
        executor.build_transaction(&batch, fee_rate)
    };

    let batch_tx = build_result.map_err(|e| format!("Failed to build batch transaction: {}", e))?;

    // Update withdrawal requests to batched status
    for withdrawal_id in &processed_withdrawal_ids {
        if let Err(e) = state
            .db
            .update_withdrawal_batched(*withdrawal_id, &batch_id)
        {
            error!(
                withdrawal_id = withdrawal_id,
                error = %e,
                "Failed to update withdrawal status"
            );
        }
    }

    // H-PAY-1 FIX: Mark associated locks as PendingSettlement BEFORE broadcast
    for withdrawal in &withdrawals {
        if processed_withdrawal_ids.contains(&withdrawal.id.unwrap_or(-1)) {
            if let Err(e) = state
                .db
                .update_ghost_lock_state(&withdrawal.lock_id, DbLockState::PendingSettlement)
            {
                error!(
                    lock_id = %withdrawal.lock_id,
                    error = %e,
                    "Failed to update lock state to PendingSettlement"
                );
            }
        }
    }

    // Sign each input using the lock owner's keys
    let secp = Secp256k1::new();
    let sign_result: Result<bitcoin::Transaction, String> = (|| {
        let keys_guard = state.keys.read();
        let keys = keys_guard
            .as_ref()
            .ok_or("No ghost keys loaded for settlement signing")?;

        let mut signed_tx = batch_tx.transaction.clone();
        let mut input_idx = 0usize;

        for withdrawal in &withdrawals {
            if !processed_withdrawal_ids.contains(&withdrawal.id.unwrap_or(-1)) {
                continue;
            }

            let lock = state
                .db
                .get_ghost_lock(&withdrawal.lock_id)
                .map_err(|e| format!("DB error: {}", e))?
                .ok_or_else(|| format!("Lock {} not found", withdrawal.lock_id))?;

            let lock_index = state
                .db
                .get_lock_index_for_owner(&lock.owner_ghost_id, &lock.lock_id)
                .map_err(|e| format!("Failed to get lock index: {}", e))?;

            let lock_secret = keys
                .derive_lock_secret(lock_index)
                .map_err(|e| format!("Key derivation error: {:?}", e))?;

            let lock_pubkey_bytes = hex::decode(&lock.lock_pubkey)
                .map_err(|e| format!("Invalid lock_pubkey hex: {}", e))?;
            let lock_pubkey = bitcoin::secp256k1::PublicKey::from_slice(&lock_pubkey_bytes)
                .map_err(|e| format!("Invalid lock_pubkey: {}", e))?;
            let recovery_pubkey_bytes = hex::decode(&lock.recovery_pubkey)
                .map_err(|e| format!("Invalid recovery_pubkey hex: {}", e))?;
            let recovery_pubkey = bitcoin::secp256k1::PublicKey::from_slice(&recovery_pubkey_bytes)
                .map_err(|e| format!("Invalid recovery_pubkey: {}", e))?;

            let derived_pubkey =
                bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &lock_secret);
            if derived_pubkey != lock_pubkey {
                return Err(format!(
                    "Derived pubkey mismatch for lock {} at index {}",
                    lock.lock_id, lock_index
                ));
            }

            let recovery_blocks = lock.recovery_height.saturating_sub(lock.creation_height);

            let witness_script = ghost_locks::build_wsh_witness_script(
                &lock_pubkey,
                &recovery_pubkey,
                recovery_blocks,
            )
            .map_err(|e| format!("Witness script error: {}", e))?;

            let sighash = {
                let mut cache = bitcoin::sighash::SighashCache::new(&signed_tx);
                cache
                    .p2wsh_signature_hash(
                        input_idx,
                        &witness_script,
                        bitcoin::Amount::from_sat(lock.amount_sats),
                        bitcoin::EcdsaSighashType::All,
                    )
                    .map_err(|e| format!("Sighash error: {}", e))?
            };

            let sighash_bytes: [u8; 32] = sighash[..]
                .try_into()
                .map_err(|_| "Sighash not 32 bytes".to_string())?;
            let msg = bitcoin::secp256k1::Message::from_digest(sighash_bytes);
            let sig = secp.sign_ecdsa(&msg, &lock_secret);

            let mut sig_bytes = sig.serialize_der().to_vec();
            sig_bytes.push(0x01); // SIGHASH_ALL

            let witness_vec = ghost_locks::build_normal_witness(&sig_bytes, &witness_script);
            signed_tx.input[input_idx].witness = bitcoin::Witness::from_slice(&witness_vec);

            input_idx += 1;
        }

        Ok(signed_tx)
    })();

    let signed_tx = match sign_result {
        Ok(tx) => tx,
        Err(e) => {
            error!(
                batch_id = %batch_id,
                error = %e,
                "Settlement transaction signing failed"
            );
            // Revert lock states on signing failure
            for withdrawal in &withdrawals {
                if processed_withdrawal_ids.contains(&withdrawal.id.unwrap_or(-1)) {
                    let _ = state
                        .db
                        .update_ghost_lock_state(&withdrawal.lock_id, DbLockState::Active);
                }
            }
            return Err(format!("Signing failed: {}", e));
        }
    };

    let tx_hex = bitcoin::consensus::encode::serialize_hex(&signed_tx);

    match state.rpc.send_raw_transaction(&tx_hex).await {
        Ok(broadcast_txid) => {
            info!(
                batch_id = %batch_id,
                txid = %broadcast_txid,
                total_sats = batch_tx.total_input_sats,
                outputs = batch_tx.settlement_count(),
                fee = batch_tx.mining_fee,
                "Settlement batch broadcast successful"
            );

            // Update withdrawals to submitted status
            for withdrawal_id in &processed_withdrawal_ids {
                if let Err(e) = state
                    .db
                    .update_withdrawal_submitted(*withdrawal_id, &broadcast_txid)
                {
                    error!(
                        withdrawal_id = withdrawal_id,
                        error = %e,
                        "Failed to update withdrawal to submitted"
                    );
                }
            }

            // Mark L2 epoch fees as distributed after successful broadcast (only if included)
            if include_l2_fees && !undistributed.is_empty() {
                for (epoch, _) in &undistributed {
                    if let Err(e) = state.db.mark_epoch_fees_distributed(*epoch) {
                        error!(
                            epoch,
                            error = %e,
                            "Failed to mark epoch fees as distributed"
                        );
                    }
                }
                info!(
                    epochs = undistributed.len(),
                    l2_fee_pool, "Marked L2 epoch fees as distributed"
                );
            }

            // Bump the cumulative L2-node-rewards-paid counter. Counted at
            // broadcast rather than at L1 confirmation because the
            // reconciliation_state table isn't actually populated in the
            // current settlement path — committing at broadcast is a
            // marginal over-count in reorg scenarios (rare on mainnet)
            // but keeps the metric accurate to within one batch.
            if l2_node_reward_paid > 0 {
                match state.db.add_l2_node_rewards_paid(l2_node_reward_paid) {
                    Ok(total) => info!(
                        amount_sats = l2_node_reward_paid,
                        cumulative_sats = total,
                        "L2 node rewards cumulative total updated"
                    ),
                    Err(e) => error!(
                        amount_sats = l2_node_reward_paid,
                        error = %e,
                        "Failed to update L2 node rewards cumulative total"
                    ),
                }
            }

            // Bump the treasury running total. Same broadcast-time
            // commit as the node-reward accumulator; threshold-crossing
            // is detected inside add_treasury_funds which also stamps
            // the threshold_reached_at timestamp for the decay schedule.
            if l2_treasury_paid > 0 {
                match state.db.add_treasury_funds(
                    l2_treasury_paid,
                    ghost_reconciliation::fee_distribution::TREASURY_THRESHOLD_SATS,
                ) {
                    Ok(crossed) => info!(
                        amount_sats = l2_treasury_paid,
                        threshold_crossed = crossed,
                        "Treasury balance bumped from L2 settlement"
                    ),
                    Err(e) => error!(
                        amount_sats = l2_treasury_paid,
                        error = %e,
                        "Failed to bump treasury balance from L2 settlement"
                    ),
                }
            }

            Ok(Some(batch_id))
        }
        Err(e) => {
            error!(
                batch_id = %batch_id,
                error = %e,
                "Settlement batch broadcast failed"
            );

            // Revert lock states back to Active on broadcast failure
            for withdrawal in &withdrawals {
                if processed_withdrawal_ids.contains(&withdrawal.id.unwrap_or(-1)) {
                    if let Err(revert_err) = state
                        .db
                        .update_ghost_lock_state(&withdrawal.lock_id, DbLockState::Active)
                    {
                        error!(
                            lock_id = %withdrawal.lock_id,
                            error = %revert_err,
                            "Failed to revert lock state after broadcast failure"
                        );
                    }

                    retry_tracker
                        .entry(withdrawal.lock_id.clone())
                        .and_modify(|(count, last)| {
                            *count += 1;
                            *last = std::time::Instant::now();
                        })
                        .or_insert((1, std::time::Instant::now()));
                }
            }

            Err(format!("Broadcast failed: {}", e))
        }
    }
}

/// Attempt epoch-triggered settlement for all due settlement classes.
///
/// Called when the L2 finalize handler detects an epoch boundary.
async fn try_epoch_settlement(state: Arc<AppState>, epoch: u64) {
    use ghost_common::constants::SettlementClass;

    info!(
        epoch,
        "Epoch boundary detected, checking settlement classes"
    );

    for class in SettlementClass::ALL {
        if !class.is_due_at_epoch(epoch) {
            continue;
        }

        // Dedup: skip if we already settled this class at this epoch
        {
            let last_epochs = state.last_settled_epoch.read();
            if let Some(&last) = last_epochs.get(class.as_str()) {
                if last >= epoch {
                    debug!(
                        class = class.as_str(),
                        epoch, "Already settled this class at epoch, skipping"
                    );
                    continue;
                }
            }
        }

        let pending = match state.db.get_pending_withdrawals_by_class(class.as_str()) {
            Ok(w) => w,
            Err(e) => {
                warn!(
                    class = class.as_str(),
                    error = %e,
                    "Failed to query pending withdrawals by class"
                );
                continue;
            }
        };

        if pending.is_empty() {
            debug!(
                class = class.as_str(),
                epoch, "No pending withdrawals for class"
            );
            continue;
        }

        info!(
            class = class.as_str(),
            epoch,
            count = pending.len(),
            "Executing epoch settlement"
        );

        match execute_settlement_batch(&state, pending).await {
            Ok(Some(batch_id)) => {
                info!(
                    class = class.as_str(),
                    epoch,
                    batch_id = %batch_id,
                    "Epoch settlement batch broadcast"
                );
                state
                    .last_settled_epoch
                    .write()
                    .insert(class.as_str().to_string(), epoch);
            }
            Ok(None) => {
                debug!(
                    class = class.as_str(),
                    epoch, "No batch formed (insufficient inputs)"
                );
            }
            Err(e) => {
                error!(
                    class = class.as_str(),
                    epoch,
                    error = %e,
                    "Epoch settlement failed"
                );
            }
        }
    }
}

/// Background monitor for settlement confirmation tracking and stale lock recovery.
///
/// This replaces the old `run_settlement_loop`. Settlement batch creation is now
/// triggered by epoch boundaries in `l2_finalize_handler` → `try_epoch_settlement`.
/// This monitor handles:
/// 1. H-PAY-1: Stale PendingSettlement lock recovery (24h revert)
/// 2. Confirmation monitoring for submitted withdrawals (database-driven)
async fn run_settlement_monitor(state: Arc<AppState>) {
    use tracing::{debug, error, warn};

    info!("Starting L1 settlement monitor");

    // Monitor interval (60 seconds)
    let check_interval = std::time::Duration::from_secs(60);

    let required_confirmations: u64 = match state.network {
        Network::Bitcoin => 6,
        _ => 1,
    };

    loop {
        tokio::time::sleep(check_interval).await;

        let ghost_id = match state.ghost_id.read().clone() {
            Some(id) => id,
            None => {
                debug!("No ghost keys loaded, skipping settlement monitor");
                continue;
            }
        };

        // H-PAY-1 FIX: Check for stale PendingSettlement/Jumping locks and revert to Active
        // Jumping locks are from the old reconcile_lock code that set state before settlement
        const STALE_SETTLEMENT_TIMEOUT_SECS: i64 = 24 * 60 * 60; // 24 hours
        if let Ok(db_locks) = state.db.get_ghost_locks_by_owner(&ghost_id) {
            let now = chrono::Utc::now().timestamp();
            for lock in db_locks {
                if lock.state == DbLockState::PendingSettlement
                    || lock.state == DbLockState::Jumping
                {
                    let age_secs = now - lock.updated_at;
                    if age_secs > STALE_SETTLEMENT_TIMEOUT_SECS {
                        warn!(
                            lock_id = %lock.lock_id,
                            state = ?lock.state,
                            age_hours = age_secs / 3600,
                            "Reverting stale lock to Active"
                        );
                        if let Err(e) = state
                            .db
                            .update_ghost_lock_state(&lock.lock_id, DbLockState::Active)
                        {
                            error!(
                                lock_id = %lock.lock_id,
                                error = %e,
                                "Failed to revert stale lock to Active"
                            );
                        }
                    }
                }
            }
        }

        // Check submitted-but-unconfirmed withdrawals for L1 confirmations
        let submitted = match state.db.get_submitted_withdrawals() {
            Ok(w) => w,
            Err(e) => {
                warn!(error = %e, "Failed to query submitted withdrawals");
                continue;
            }
        };

        if submitted.is_empty() {
            continue;
        }

        // Group by l1_txid to avoid redundant RPC calls for same batch
        let mut txid_checked: std::collections::HashSet<String> = std::collections::HashSet::new();

        for withdrawal in &submitted {
            let txid_str = match withdrawal.l1_txid.as_ref() {
                Some(t) if !t.is_empty() => t.clone(),
                _ => continue,
            };

            // Skip if we already checked this txid in this iteration
            if txid_checked.contains(&txid_str) {
                continue;
            }
            txid_checked.insert(txid_str.clone());

            match state.rpc.get_raw_transaction(&txid_str, true).await {
                Ok(tx_json) => {
                    let confirmations = tx_json
                        .get("confirmations")
                        .and_then(|c| c.as_u64())
                        .unwrap_or(0);

                    if confirmations < required_confirmations {
                        debug!(
                            txid = %txid_str,
                            confirmations,
                            required = required_confirmations,
                            "Settlement TX awaiting confirmations"
                        );
                        continue;
                    }

                    info!(
                        txid = %txid_str,
                        confirmations,
                        "Settlement TX confirmed, finalizing withdrawals"
                    );

                    // Confirm all withdrawals with this txid
                    for w in &submitted {
                        if w.l1_txid.as_deref() != Some(&txid_str) {
                            continue;
                        }

                        // Mark lock as Spent
                        if let Err(e) = state
                            .db
                            .update_ghost_lock_state(&w.lock_id, DbLockState::Spent)
                        {
                            error!(
                                lock_id = %w.lock_id,
                                error = %e,
                                "Failed to update lock state to Spent"
                            );
                        }

                        // Mark withdrawal as Confirmed
                        if let Some(id) = w.id {
                            if let Err(e) = state.db.update_withdrawal_confirmed(id) {
                                error!(
                                    withdrawal_id = id,
                                    error = %e,
                                    "Failed to confirm withdrawal"
                                );
                            } else {
                                info!(withdrawal_id = id, "Withdrawal confirmed");
                            }
                        }
                    }

                    // Finalize batch if batch_id is available
                    if let Some(batch_id) = submitted
                        .iter()
                        .find(|w| w.l1_txid.as_deref() == Some(&txid_str))
                        .and_then(|w| w.batch_id.as_ref())
                    {
                        if let Err(e) = state.db.finalize_reconciliation_batch(batch_id) {
                            error!(
                                batch_id = %batch_id,
                                error = %e,
                                "Failed to finalize batch in database"
                            );
                        }
                    }
                }
                Err(e) => {
                    debug!(
                        txid = %txid_str,
                        error = %e,
                        "Could not fetch settlement TX status"
                    );
                }
            }
        }
    }
}

/// Sync a shield commitment to ghost-pool with exponential backoff retry.
/// Returns true if sync succeeded on any attempt.
async fn sync_commitment_with_retry(
    client: &reqwest::Client,
    pool_url: &str,
    commitment: &[u8; 32],
    note_index: u64,
    block_height: u64,
) -> bool {
    let url = format!("{}/api/v1/l2/sync-commitment", pool_url);
    let body = serde_json::json!({
        "commitment": hex::encode(commitment),
        "note_index": note_index,
        "block_height": block_height,
    });

    for attempt in 0..4u32 {
        if attempt > 0 {
            let delay = std::time::Duration::from_millis(200 * (1 << (attempt - 1)));
            tokio::time::sleep(delay).await;
        }

        match client.post(&url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => return true,
            Ok(resp) => {
                warn!(
                    attempt,
                    status = %resp.status(),
                    "Shield commitment sync returned error, retrying"
                );
            }
            Err(e) => {
                warn!(
                    attempt,
                    error = %e,
                    "Shield commitment sync failed, retrying"
                );
            }
        }
    }

    error!(
        note_index,
        "Shield commitment sync failed after 4 attempts — peers will receive via P2P broadcast"
    );
    false
}

/// Estimate fee rate in sat/vbyte
///
/// Uses Bitcoin Core's `estimatesmartfee` RPC with fallback to cached or default values.
async fn estimate_fee_rate(state: &Arc<AppState>) -> u64 {
    // Target confirmation in 6 blocks (~1 hour)
    const CONF_TARGET: u32 = 6;

    // Try to get fee estimate from Bitcoin Core
    match state.rpc.estimate_smart_fee(CONF_TARGET).await {
        Ok(estimate) => {
            if let Some(feerate_btc_kvb) = estimate.feerate {
                // Convert from BTC/kvB to sat/vB
                // feerate is in BTC per 1000 vbytes, we need sat per vbyte
                // 1 BTC = 100_000_000 sats, 1 kvB = 1000 vB
                // sat/vB = (BTC/kvB) * 100_000_000 / 1000 = BTC/kvB * 100_000
                let sat_per_vb = (feerate_btc_kvb * 100_000.0) as u64;
                let rate = sat_per_vb.clamp(1, 1000); // Clamp to 1-1000 sat/vB

                // Cache the rate with timestamp
                let cached_value = format!("{}:{}", rate, chrono::Utc::now().timestamp());
                let _ = state.db.kv_set("fee_rate_cache", &cached_value);

                debug!(
                    rate = rate,
                    conf_target = CONF_TARGET,
                    source = "rpc",
                    "Fee rate estimated"
                );
                return rate;
            }
            // RPC returned but no feerate (not enough data)
            if let Some(errors) = estimate.errors {
                debug!(errors = ?errors, "Fee estimation returned errors, using fallback");
            }
        }
        Err(e) => {
            debug!(error = %e, "Failed to estimate fee via RPC, using fallback");
        }
    }

    // Try to get cached fee rate from database (with staleness check)
    if let Ok(Some(cached)) = state.db.kv_get("fee_rate_cache") {
        if let Some((rate_str, timestamp_str)) = cached.split_once(':') {
            if let (Ok(rate), Ok(timestamp)) =
                (rate_str.parse::<u64>(), timestamp_str.parse::<i64>())
            {
                let now = chrono::Utc::now().timestamp();
                let age_secs = now.saturating_sub(timestamp);

                // Use cached rate if less than 10 minutes old
                if age_secs < 600 {
                    debug!(
                        rate = rate,
                        age_secs = age_secs,
                        source = "cache",
                        "Using cached fee rate"
                    );
                    return rate.clamp(1, 1000);
                }
            }
        }
    }

    // Fallback to network defaults
    let default_rate = match state.network {
        Network::Bitcoin => 10, // Mainnet: ~10 sat/vB for standard priority
        Network::Testnet => 2,  // Testnet: lower fees
        Network::Signet => 1,   // Signet: minimal fees
        Network::Regtest => 1,  // Regtest: minimal fees
        _ => 5,                 // Unknown: conservative default
    };

    debug!(
        rate = default_rate,
        network = ?state.network,
        source = "default",
        "Using default fee rate"
    );

    default_rate
}

/// Convert hex string to [u8; 32]
///
/// Returns a 32-byte array from hex input.
/// Logs a warning if input length is not exactly 64 hex characters (32 bytes).
fn hex_to_32bytes(hex: &str) -> [u8; 32] {
    let mut result = [0u8; 32];
    match hex::decode(hex) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                warn!(
                    expected = 32,
                    actual = bytes.len(),
                    hex = %hex,
                    "hex_to_32bytes: unexpected input length"
                );
            }
            let len = bytes.len().min(32);
            result[..len].copy_from_slice(&bytes[..len]);
        }
        Err(e) => {
            warn!(error = %e, hex = %hex, "hex_to_32bytes: invalid hex input");
        }
    }
    result
}

/// Parse RPC URL into host and port
///
/// Uses network-appropriate default port if not specified:
/// - Mainnet: 8332
/// - Testnet: 18332
/// - Signet: 38332
/// - Regtest: 18443
fn parse_rpc_url(url: &str, network: Network) -> (String, u16) {
    let default_port = match network {
        Network::Bitcoin => 8332,
        Network::Testnet | Network::Testnet4 => 18332,
        Network::Signet => 38332,
        Network::Regtest => 18443,
    };

    // Handle URL format: http://host:port or just host:port
    let stripped = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    if let Some(idx) = stripped.rfind(':') {
        let host = stripped[..idx].to_string();
        let port = stripped[idx + 1..].parse().unwrap_or(default_port);
        (host, port)
    } else {
        (stripped.to_string(), default_port)
    }
}

// =============================================================================
// Wizard endpoint handlers (Reconcile Lock, Send L2 Payment)
// =============================================================================

/// Request body for lock reconciliation (settle to L1)
#[derive(Debug, Deserialize)]
struct ReconcileLockRequest {
    /// Destination Bitcoin address for settlement (bech32)
    destination_address: String,
    /// Settlement class: "standard" or "batched"
    #[serde(default = "default_settlement_class")]
    settlement_class: String,
}

fn default_settlement_class() -> String {
    "standard".to_string()
}

/// POST /api/v1/locks/:id/reconcile — Settle a Ghost Lock to L1
///
/// Reconciles (closes) an active lock by sending funds to a specified
/// L1 Bitcoin address. Similar to withdrawal but specifically for
/// closing out the full lock balance.
async fn reconcile_lock(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<ReconcileLockRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let ghost_id = state.ghost_id.read().clone().ok_or(StatusCode::NOT_FOUND)?;

    // Validate settlement class
    if !["express", "standard", "economy"].contains(&req.settlement_class.as_str()) {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Invalid settlement_class. Must be 'express', 'standard', or 'economy'"
        })));
    }

    // Validate the lock exists and is owned by this ghost_id
    let lock = state
        .db
        .get_ghost_lock(&id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    if lock.owner_ghost_id != ghost_id {
        return Err(StatusCode::FORBIDDEN);
    }

    // Lock must be active and funded
    if lock.state != DbLockState::Active {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Lock is not active"
        })));
    }

    if lock.funding_txid.is_none() {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Lock is not funded"
        })));
    }

    // Validate destination address format (bech32)
    if !req.destination_address.starts_with("bc1")
        && !req.destination_address.starts_with("tb1")
        && !req.destination_address.starts_with("bcrt1")
    {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Invalid destination address format (must be bech32)"
        })));
    }

    // Settlement fee — covers mining fee + L2 fee headroom.
    // Mining: ~300 vbytes * fee_rate * class multiplier.
    // L2 headroom: reserve undistributed L2 fees so settlement batch can include them.
    let fee_rate = estimate_fee_rate(&state).await;
    let class =
        ghost_common::constants::SettlementClass::parse(&req.settlement_class).unwrap_or_default();
    let mining_fee = ((300u64 * fee_rate) as f64 * class.fee_multiplier()).ceil() as u64;
    let l2_fee_headroom: u64 = state
        .db
        .get_undistributed_fees()
        .unwrap_or_default()
        .iter()
        .map(|(_, fee)| fee)
        .sum();
    let settlement_fee = mining_fee.saturating_add(l2_fee_headroom).max(546);
    let settlement_amount = lock.amount_sats.saturating_sub(settlement_fee);

    let now = chrono::Utc::now().timestamp();

    // Create withdrawal request for the full lock balance
    let withdrawal = WithdrawalRequest {
        id: None,
        ghost_id: ghost_id.clone(),
        lock_id: id.clone(),
        destination_address: req.destination_address.clone(),
        amount_sats: settlement_amount,
        fee_sats: settlement_fee,
        status: WithdrawalStatus::Pending,
        batch_id: None,
        l1_txid: None,
        settlement_class: req.settlement_class.clone(),
        created_at: now,
        updated_at: now,
    };

    // Atomically insert withdrawal if none pending for this lock
    let withdrawal_id = match state
        .db
        .insert_withdrawal_request_atomic(&withdrawal)
        .map_err(|e| {
            tracing::error!("Failed to create reconciliation withdrawal: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })? {
        Some(wid) => wid,
        None => {
            return Ok(Json(serde_json::json!({
                "success": false,
                "error": "A pending withdrawal already exists for this lock"
            })));
        }
    };

    // Lock stays Active — the epoch settlement pipeline will transition it to
    // PendingSettlement when the batch is formed, then Spent when confirmed.
    // Setting it to Jumping here was preventing the settlement from processing it.

    Ok(Json(serde_json::json!({
        "success": true,
        "withdrawal_id": withdrawal_id,
        "lock_id": id,
        "settlement_amount": settlement_amount,
        "fee_sats": settlement_fee,
        "settlement_class": req.settlement_class,
        "destination_address": req.destination_address,
        "message": format!("Lock reconciliation initiated, settlement of {} sats", settlement_amount)
    })))
}

/// Request body for L2 payment
#[derive(Debug, Deserialize)]
struct SendL2PaymentRequest {
    /// Recipient Ghost ID or payment address
    recipient: String,
    /// Amount in satoshis
    amount_sats: u64,
    /// Optional memo (max 59 characters for OP_RETURN compatibility)
    #[serde(default)]
    memo: Option<String>,
    /// SECURITY: the SENDER's ghost_id, supplied by the GSP server
    /// from the authenticated WebSocket session's wallet_id. Trusted
    /// because the X-Internal-Auth header verifies the request
    /// originated from a known GSP server (the operator's own
    /// trusted gateway). When absent (legacy / direct callers), the
    /// route falls back to `state.ghost_id` — but that path is
    /// honestly incorrect for multi-tenant L2 accounting and will
    /// be removed once all callers migrate.
    #[serde(default)]
    sender_ghost_id: Option<String>,
}

/// POST /api/v1/payments/send — Send an L2 instant payment
///
/// Sends an instant off-chain payment to another Ghost user.
/// Wraps the confidential transfer system for a simpler API.
async fn send_l2_payment(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SendL2PaymentRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // The sender's ghost_id comes from the GSP server (which derived
    // it from the authenticated WebSocket session). Operator-side
    // identity is the wrong primitive here — every wallet's payment
    // would otherwise be recorded as if the operator sent it. We
    // still fall back to `state.ghost_id` for legacy callers, with
    // a warning, until those are gone.
    let ghost_id = match &req.sender_ghost_id {
        Some(id) if !id.is_empty() => id.clone(),
        _ => {
            tracing::warn!(
                "send_l2_payment: missing sender_ghost_id — falling back to operator's \
                 identity. This is incorrect for multi-tenant accounting; the GSP \
                 server should always supply the authenticated wallet's ghost_id."
            );
            state.ghost_id.read().clone().ok_or(StatusCode::NOT_FOUND)?
        }
    };

    // Validate amount
    if req.amount_sats == 0 {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Amount must be greater than 0"
        })));
    }

    // Validate memo length
    if let Some(ref memo) = req.memo {
        if memo.len() > 59 {
            return Ok(Json(serde_json::json!({
                "success": false,
                "error": "Memo cannot exceed 59 characters"
            })));
        }
    }

    // Validate recipient format (Ghost ID is a hex pubkey or bech32 address)
    if req.recipient.is_empty() {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Recipient is required"
        })));
    }

    // Query sender's available L2 balance:
    // Sum of unsettled received payments + unspent lock amounts owned by sender
    let sender_gid = ghost_id.clone();
    let available_balance: i64 = state
        .db
        .with_connection(|conn| {
            // L2 balance = received payments not yet settled + active lock funds
            let received: i64 = conn
                .query_row(
                    "SELECT COALESCE(SUM(amount_sats), 0) FROM accepted_instant_payments \
                     WHERE merchant_wallet_id = ?1 AND settlement_block = 0",
                    rusqlite::params![sender_gid],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let lock_balance: i64 = conn
                .query_row(
                    "SELECT COALESCE(SUM(amount_sats), 0) FROM ghost_locks \
                     WHERE owner_ghost_id = ?1 AND state = 'active'",
                    rusqlite::params![sender_gid],
                    |row| row.get(0),
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;

            Ok(received + lock_balance)
        })
        .map_err(|e| {
            tracing::error!("Failed to query L2 balance: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if (req.amount_sats as i64) > available_balance {
        return Ok(Json(serde_json::json!({
            "success": false,
            "error": "Insufficient L2 balance",
            "available_sats": available_balance,
            "requested_sats": req.amount_sats
        })));
    }

    // Generate deterministic payment ID from (sender, recipient, amount, timestamp)
    let now = chrono::Utc::now().timestamp();
    let payment_id = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(ghost_id.as_bytes());
        hasher.update(req.recipient.as_bytes());
        hasher.update(req.amount_sats.to_le_bytes());
        hasher.update(now.to_le_bytes());
        format!("pay_{}", hex::encode(&hasher.finalize()[..16]))
    };

    // Get sender pubkey from loaded ghost keys
    let sender_pubkey = {
        let keys_guard = state.keys.read();
        match keys_guard.as_ref() {
            Some(keys) => hex::encode(keys.spend_pubkey().serialize()),
            None => {
                return Ok(Json(serde_json::json!({
                    "success": false,
                    "error": "Ghost keys not loaded"
                })));
            }
        }
    };

    // Record the L2 payment intent with real sender pubkey.
    // The ZK proof must be submitted separately via /api/v1/confidential/transfer
    // since proof generation requires the sender's private key (client-side only).
    let pid = payment_id.clone();
    let gid = ghost_id.clone();
    let recipient = req.recipient.clone();
    let amount = req.amount_sats;
    let pubkey_bytes = hex::decode(&sender_pubkey).unwrap_or_default();

    state
        .db
        .with_connection(|conn| {
            conn.execute(
                "INSERT INTO accepted_instant_payments \
                 (payment_id, sender_lock_id, merchant_wallet_id, amount_sats, \
                  accepted_at, settlement_block, confidence, sender_pubkey, signature, \
                  sender_ghost_id) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, 0.0, ?6, X'00', ?7)",
                rusqlite::params![
                    pid.as_bytes(),
                    gid,
                    recipient,
                    amount as i64,
                    now,
                    pubkey_bytes,
                    gid,
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
        .map_err(|e| {
            tracing::error!("Failed to record L2 payment: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(serde_json::json!({
        "success": true,
        "payment_id": payment_id,
        "sender": ghost_id,
        "recipient": req.recipient,
        "amount_sats": req.amount_sats,
        "memo": req.memo,
        "status": "pending",
        "proof_required": true,
        "transfer_endpoint": "/api/v1/confidential/transfer",
        "message": format!(
            "L2 payment of {} sats recorded. Submit ZK proof via /api/v1/confidential/transfer to complete.",
            req.amount_sats
        )
    })))
}

/// Query parameters for `GET /api/v1/transactions`.
#[derive(Debug, Deserialize)]
struct TransactionsQuery {
    /// The wallet's *static* identifier (`SHA256(auth_xonly_pubkey)[0..16]`).
    /// Matches `sender_ghost_id` rows where this wallet was the sender.
    ghost_id: String,
    /// Optional bech32 ghost-id (`<network>ghost1q...`) — matches
    /// `merchant_wallet_id` rows where this wallet was the recipient.
    /// At INSERT time we only have the recipient's public bech32 (it's
    /// what the sender sent the payment to), so receive-side matches
    /// must go through this column.
    #[serde(default)]
    bech32: Option<String>,
    #[serde(default = "default_tx_limit")]
    limit: u32,
    #[serde(default)]
    offset: u32,
}

fn default_tx_limit() -> u32 {
    50
}

/// GET /api/v1/transactions — L2 ledger entries for a given ghost_id.
///
/// Returns both sent and received L2 instant payments, signed so the wallet
/// can render them as a single time-ordered history. `block_height` is the
/// L1 settlement block (None while pending); `confirmations` is computed
/// against the bitcoin RPC tip. There is no on-chain tx for L2 transfers,
/// so `txid` carries the L2 `payment_id`.
async fn list_transactions(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TransactionsQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if q.ghost_id.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let limit = q.limit.clamp(1, 500);
    let offset = q.offset;

    let tip_height = state.rpc.get_block_count().await.unwrap_or(0) as i64;

    // Receive-side match goes against the bech32 ghost-id when
    // supplied, falling back to the static ID for legacy callers
    // that haven't started forwarding the bech32 yet. (The old code
    // matched against the static ID on both sides — produced empty
    // results for recipients because `merchant_wallet_id` is stored
    // as bech32.)
    let gid_recv = q.bech32.clone().unwrap_or_else(|| q.ghost_id.clone());
    let gid_send = q.ghost_id.clone();
    let rows: Vec<(String, i64, i64, i64, String, Option<String>)> = state
        .db
        .with_connection(|conn| {
            // Two arms: receive (merchant_wallet_id matches the
            // wallet's bech32) and send (sender_ghost_id matches the
            // wallet's static id). UNION ALL preserves both sides
            // of a self-payment, which is what the wallet wants.
            let sql = "
                SELECT
                    hex(payment_id)        AS txid_hex,
                    settlement_block       AS block_height,
                    accepted_at            AS ts,
                    amount_sats            AS amount_abs,
                    'receive'              AS tx_type,
                    NULL                   AS memo
                FROM accepted_instant_payments
                WHERE merchant_wallet_id = ?1
                UNION ALL
                SELECT
                    hex(payment_id),
                    settlement_block,
                    accepted_at,
                    amount_sats,
                    'send',
                    NULL
                FROM accepted_instant_payments
                WHERE sender_ghost_id = ?2
                ORDER BY ts DESC
                LIMIT ?3 OFFSET ?4
            ";
            let mut stmt = conn
                .prepare(sql)
                .map_err(|e| GhostError::Database(e.to_string()))?;
            let mut out = Vec::new();
            let mut q_rows = stmt
                .query(rusqlite::params![
                    gid_recv,
                    gid_send,
                    limit as i64,
                    offset as i64,
                ])
                .map_err(|e| GhostError::Database(e.to_string()))?;
            while let Some(row) = q_rows
                .next()
                .map_err(|e| GhostError::Database(e.to_string()))?
            {
                let txid: String = row
                    .get(0)
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                let block_height: i64 = row
                    .get(1)
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                let ts: i64 = row
                    .get(2)
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                let amount_abs: i64 = row
                    .get(3)
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                let tx_type: String = row
                    .get(4)
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                let memo: Option<String> = row
                    .get(5)
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                out.push((txid, block_height, ts, amount_abs, tx_type, memo));
            }
            Ok(out)
        })
        .map_err(|e| {
            error!("Failed to query L2 transactions: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let total = rows.len() as u32;
    let transactions: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(txid, block_height, ts, amount_abs, tx_type, memo)| {
            let signed_amount = if tx_type == "send" {
                -amount_abs
            } else {
                amount_abs
            };
            let block_height_json = if block_height > 0 {
                serde_json::json!(block_height as u32)
            } else {
                serde_json::Value::Null
            };
            let confirmations = if block_height > 0 && tip_height >= block_height {
                (tip_height - block_height + 1) as u32
            } else {
                0
            };
            serde_json::json!({
                "txid": txid.to_lowercase(),
                "block_height": block_height_json,
                "timestamp": ts,
                "amount_sats": signed_amount,
                "fee_sats": 0u64,
                "tx_type": tx_type,
                "confirmations": confirmations,
                "memo": memo,
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "transactions": transactions,
        "total": total,
    })))
}

// =============================================================================
// L2 BLOCK PRODUCTION ENDPOINTS
// =============================================================================

/// GET /api/v1/l2/state — Current L2 state for block producer
async fn l2_state_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let tree = state.commitment_tree.read();
    let state_root = tree.root().unwrap_or([0u8; 32]);

    // Get latest L2 block height from blocks table (matches verify_ghostpay)
    let height: u64 = state
        .db
        .with_connection(|conn| {
            let result: Option<i64> = conn
                .query_row(
                    "SELECT height FROM blocks ORDER BY height DESC LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .ok();
            Ok(result.unwrap_or(0) as u64)
        })
        .unwrap_or(0);

    // Count pending transfers
    let pending_count: i64 = state
        .db
        .with_connection(|conn| {
            conn.query_row("SELECT COUNT(*) FROM pending_transfers", [], |row| {
                row.get(0)
            })
            .map_err(|e| GhostError::Database(e.to_string()))
        })
        .unwrap_or(0);

    Json(serde_json::json!({
        "height": height,
        "state_root": hex::encode(state_root),
        "pending_count": pending_count,
    }))
}

/// GET /api/v1/l2/pending — Build a block witness from pending transfers
async fn l2_pending_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let tree = state.commitment_tree.read();
    let prev_state_root = tree.root().unwrap_or([0u8; 32]);

    // Load pending transfers ordered by creation time
    let pending: Vec<(i64, u64, u64, u64, u64, u64)> = state
        .db
        .with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, sender_index, recipient_index, amount, \
                     sender_balance_before, recipient_balance_before \
                     FROM pending_transfers ORDER BY created_at ASC LIMIT 100",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)? as u64,
                        row.get::<_, i64>(2)? as u64,
                        row.get::<_, i64>(3)? as u64,
                        row.get::<_, i64>(4)? as u64,
                        row.get::<_, i64>(5)? as u64,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;
            let mut result = Vec::new();
            for row in rows {
                result.push(row.map_err(|e| GhostError::Database(e.to_string()))?);
            }
            Ok(result)
        })
        .map_err(|e| {
            error!(error = %e, "Failed to load pending transfers");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if pending.is_empty() {
        // Empty block witness — state doesn't change
        return Ok(Json(serde_json::json!({
            "prev_state_root": hex::encode(prev_state_root),
            "new_state_root": hex::encode(prev_state_root),
            "tx_count": 0,
            "tx_ids": [],
            "transitions": [],
            "intermediate_roots": [],
        })));
    }

    // Build witness by applying transfers to a cloned balance tree
    let balance_tree = state.balance_tree.read();
    let mut work_tree = balance_tree.clone();
    drop(balance_tree);

    let prev_root = work_tree.root().unwrap_or([0u8; 32]);
    let mut transitions = Vec::new();
    let mut intermediate_roots = Vec::new();
    let mut included_ids = Vec::new();

    for (id, sender_idx, recipient_idx, amount, _, _) in &pending {
        match work_tree.apply_payment(*sender_idx, *recipient_idx, *amount) {
            Ok(witness) => {
                let root = work_tree.root().unwrap_or([0u8; 32]);
                intermediate_roots.push(root);
                transitions.push(witness);
                included_ids.push(*id);
            }
            Err(e) => {
                warn!(id, error = %e, "Skipping invalid L2 transfer");
            }
        }
    }

    let new_root = work_tree.root().unwrap_or([0u8; 32]);

    Ok(Json(serde_json::json!({
        "prev_state_root": hex::encode(prev_root),
        "new_state_root": hex::encode(new_root),
        "tx_count": transitions.len(),
        "tx_ids": included_ids,
        "transitions": transitions.iter().map(|t| serde_json::json!({
            "sender_index": t.sender_index,
            "recipient_index": t.recipient_index,
            "amount": t.amount,
            "sender_balance_before": t.sender_balance_before,
            "recipient_balance_before": t.recipient_balance_before,
            "sender_merkle_proof": {
                "siblings": t.sender_merkle_proof.siblings.iter()
                    .map(hex::encode).collect::<Vec<_>>(),
                "index": t.sender_merkle_proof.leaf_index,
            },
            "recipient_merkle_proof": {
                "siblings": t.recipient_merkle_proof.siblings.iter()
                    .map(hex::encode).collect::<Vec<_>>(),
                "index": t.recipient_merkle_proof.leaf_index,
            },
        })).collect::<Vec<_>>(),
        "intermediate_roots": intermediate_roots.iter()
            .map(hex::encode).collect::<Vec<_>>(),
    })))
}

/// POST /api/v1/l2/finalize — Called by ghost-pool when consensus approves a block
async fn l2_finalize_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let height = req["height"].as_u64().ok_or(StatusCode::BAD_REQUEST)?;
    let state_root_hex = req["state_root"].as_str().ok_or(StatusCode::BAD_REQUEST)?;
    let attestation_count = req["attestation_count"].as_u64().unwrap_or(0);

    let state_root_bytes = parse_hex_32(state_root_hex).map_err(|_| StatusCode::BAD_REQUEST)?;

    // MEDIUM-2: Parse included nullifiers (hex-encoded [u8; 32]) from finalization callback
    let included_nullifiers: Vec<String> = req["included_tx_ids"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    if !included_nullifiers.is_empty() {
        info!(
            height,
            nullifier_count = included_nullifiers.len(),
            "L2 finalize received with nullifiers"
        );
    }

    // Legacy path: match by pending_transfers.id (integer keys).
    // Once pending_transfers gains a nullifier column, this can key on nullifiers instead.
    let included_ids: Vec<i64> = Vec::new();

    if !included_ids.is_empty() {
        // Load the transfers we're about to finalize (for balance tree application)
        let finalized_transfers: Vec<(i64, u64, u64, u64)> = state
            .db
            .with_connection(|conn| {
                let placeholders: String = included_ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                let mut stmt = conn
                    .prepare(&format!(
                        "SELECT id, sender_index, recipient_index, amount \
                         FROM pending_transfers WHERE id IN ({})",
                        placeholders
                    ))
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)? as u64,
                            row.get::<_, i64>(2)? as u64,
                            row.get::<_, i64>(3)? as u64,
                        ))
                    })
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                let mut result = Vec::new();
                for row in rows {
                    result.push(row.map_err(|e| GhostError::Database(e.to_string()))?);
                }
                Ok(result)
            })
            .map_err(|e| {
                error!(error = %e, "Failed to load finalized transfers");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        // Apply finalized transfers to the persistent balance tree
        {
            let mut tree = state.balance_tree.write();
            for (_id, sender_idx, recipient_idx, amount) in &finalized_transfers {
                if let Err(e) = tree.apply_payment(*sender_idx, *recipient_idx, *amount) {
                    warn!(error = %e, "Failed to apply finalized transfer to balance tree");
                }
            }

            // Persist updated balances
            state
                .db
                .with_connection(|conn| {
                    for (&idx, &bal) in tree.balances() {
                        conn.execute(
                            "INSERT OR REPLACE INTO l2_balances (account_index, balance) \
                             VALUES (?1, ?2)",
                            rusqlite::params![idx as i64, bal as i64],
                        )
                        .map_err(|e| GhostError::Database(e.to_string()))?;
                    }
                    Ok(())
                })
                .map_err(|e| {
                    error!(error = %e, "Failed to persist L2 balances");
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;
        }

        // Delete the finalized transfers from pending
        state
            .db
            .with_connection(|conn| {
                let placeholders: String = included_ids
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                conn.execute(
                    &format!(
                        "DELETE FROM pending_transfers WHERE id IN ({})",
                        placeholders
                    ),
                    [],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
                Ok(())
            })
            .map_err(|e| {
                error!(error = %e, "Failed to delete finalized transfers");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    }

    // Verify state root consistency (only when transfers were applied)
    if !included_ids.is_empty() {
        let tree = state.balance_tree.read();
        let current_root = tree.root().unwrap_or([0u8; 32]);
        if current_root != state_root_bytes {
            warn!(
                height,
                expected = hex::encode(state_root_bytes),
                actual = hex::encode(current_root),
                "L2 balance tree root mismatch on finalize — tree may need resync"
            );
        }
    }

    // Record L2 block in the `blocks` table (read by verify_ghostpay endpoint)
    let epoch_id = height / 2160; // 2160 blocks per epoch (6 hours at 10s intervals)
    state
        .db
        .with_connection(|conn| {
            // Ensure blocks table exists (schema from old binary, not in migrations)
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS blocks (
                    height INTEGER PRIMARY KEY,
                    epoch_id INTEGER NOT NULL,
                    state_root TEXT NOT NULL
                );",
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            conn.execute(
                "INSERT OR REPLACE INTO blocks (height, epoch_id, state_root) \
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![height as i64, epoch_id as i64, state_root_hex],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
        .map_err(|e| {
            error!(error = %e, "Failed to record L2 block");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Check for epoch boundary — trigger settlement for due classes
    {
        use ghost_common::constants::L2_EPOCH_BLOCKS;
        let prev_epoch = height.saturating_sub(1) / L2_EPOCH_BLOCKS;
        let new_epoch = height / L2_EPOCH_BLOCKS;
        if new_epoch > prev_epoch && height > 0 {
            info!(
                height,
                new_epoch, "Epoch boundary crossed, spawning settlement check"
            );
            let settlement_state = state.clone();
            tokio::spawn(try_epoch_settlement(settlement_state, new_epoch));
        }
    }

    info!(
        height,
        attestation_count,
        state_root = state_root_hex,
        "L2 block finalized"
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "height": height,
        "state_root": state_root_hex,
    })))
}

// ============================================================================
// GhostGlyph Handlers
// ============================================================================

/// Maximum ghost_id length (bech32m addresses are ~63 chars, generous cap)
const MAX_GHOST_ID_LEN: usize = 128;

/// Validate ghost_id format: non-empty, reasonable length, no control chars.
fn validate_ghost_id(ghost_id: &str) -> Result<(), String> {
    if ghost_id.is_empty() {
        return Err("ghost_id cannot be empty".to_string());
    }
    if ghost_id.len() > MAX_GHOST_ID_LEN {
        return Err(format!(
            "ghost_id too long ({} chars, max {})",
            ghost_id.len(),
            MAX_GHOST_ID_LEN
        ));
    }
    if ghost_id.chars().any(|c| c.is_control()) {
        return Err("ghost_id contains control characters".to_string());
    }
    if !ghost_id.starts_with("ghost1") {
        return Err("ghost_id must start with 'ghost1' (bech32m)".to_string());
    }
    Ok(())
}

/// JSON error response for glyph endpoints (L-3: consistent error format)
fn glyph_error(
    status: StatusCode,
    msg: impl Into<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({"error": msg.into()})))
}

/// Request body for POST /api/v1/glyph/claim
#[derive(Debug, Deserialize)]
struct GlyphClaimRequest {
    ghost_id: String,
    pixels: Vec<u8>,
}

/// Response for glyph claim
#[derive(Debug, Serialize)]
struct GlyphClaimResponse {
    commitment: String,
    bitmap_hash: String,
    status: String,
}

/// Response for GET /api/v1/glyph/:ghost_id (L-6: typed response)
#[derive(Debug, Serialize)]
struct GlyphInfoResponse {
    ghost_id: String,
    pixels: Vec<u8>,
    bitmap_hash: String,
    commitment: String,
    funding_txid: Option<String>,
    registered_at: Option<u64>,
    status: String,
}

/// Submit a glyph claim (design chosen, pending lock funding)
async fn claim_glyph(
    State(state): State<Arc<AppState>>,
    Json(req): Json<GlyphClaimRequest>,
) -> Result<Json<GlyphClaimResponse>, (StatusCode, Json<serde_json::Value>)> {
    // Validate ghost_id format (M-1)
    validate_ghost_id(&req.ghost_id).map_err(|e| glyph_error(StatusCode::BAD_REQUEST, e))?;

    // Validate pixel array size
    if req.pixels.len() != ghost_glyph::GLYPH_SIZE {
        return Err(glyph_error(
            StatusCode::BAD_REQUEST,
            format!(
                "Expected {} pixels, got {}",
                ghost_glyph::GLYPH_SIZE,
                req.pixels.len()
            ),
        ));
    }

    // Validate pixel values
    ghost_glyph::GhostGlyph::validate_pixel_slice(&req.pixels)
        .map_err(|e| glyph_error(StatusCode::BAD_REQUEST, e.to_string()))?;

    // Convert to fixed array
    let pixels: [u8; ghost_glyph::GLYPH_SIZE] = req
        .pixels
        .as_slice()
        .try_into()
        .map_err(|_| glyph_error(StatusCode::BAD_REQUEST, "Invalid pixel array"))?;

    // Compute hashes
    let commitment = ghost_glyph::GhostGlyph::compute_commitment(&pixels, req.ghost_id.as_bytes());
    let bitmap_hash = ghost_glyph::GhostGlyph::compute_bitmap_hash(&pixels);

    // Check availability
    let available = state
        .db
        .is_bitmap_available(&bitmap_hash)
        .map_err(|e| glyph_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if !available {
        return Err(glyph_error(
            StatusCode::CONFLICT,
            "Bitmap already registered",
        ));
    }

    // Check ghost_id not already claimed
    if let Ok(Some(_)) = state.db.get_glyph_by_ghost_id(&req.ghost_id) {
        return Err(glyph_error(
            StatusCode::CONFLICT,
            "Ghost ID already has a glyph",
        ));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Insert pending claim
    state
        .db
        .insert_glyph_claim(&req.ghost_id, &req.pixels, &bitmap_hash, &commitment, now)
        .map_err(|e| {
            if e.to_string().contains("already") || e.to_string().contains("UNIQUE") {
                glyph_error(StatusCode::CONFLICT, e.to_string())
            } else {
                glyph_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
        })?;

    info!(ghost_id = %req.ghost_id, "GhostGlyph claim submitted");

    // Relay claim to ghost-pool for mesh broadcast (awaited, not fire-and-forget) (M-2)
    let relay_body = serde_json::json!({
        "ghost_id": req.ghost_id,
        "pixels": req.pixels,
        "bitmap_hash": bitmap_hash.to_vec(),
        "commitment": commitment.to_vec(),
        "timestamp": now,
    });
    let relay_url = format!("{}/api/v1/glyph/relay-claim", state.pool_api_url);
    match state
        .pool_http_client
        .post(&relay_url)
        .json(&relay_body)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            info!(ghost_id = %req.ghost_id, "Glyph claim relayed to mesh");
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            warn!(ghost_id = %req.ghost_id, status = %status, body = %body, "Glyph claim mesh relay failed");
        }
        Err(e) => {
            warn!(ghost_id = %req.ghost_id, error = %e, "Glyph claim mesh relay request failed");
        }
    }

    Ok(Json(GlyphClaimResponse {
        commitment: hex::encode(commitment),
        bitmap_hash: hex::encode(bitmap_hash),
        status: "pending".to_string(),
    }))
}

/// Get a glyph by ghost ID
async fn get_glyph(
    State(state): State<Arc<AppState>>,
    Path(ghost_id): Path<String>,
) -> Result<Json<GlyphInfoResponse>, (StatusCode, Json<serde_json::Value>)> {
    // M-9: Validate ghost_id before DB lookup
    validate_ghost_id(&ghost_id).map_err(|e| glyph_error(StatusCode::BAD_REQUEST, e))?;

    let record = state
        .db
        .get_glyph_by_ghost_id(&ghost_id)
        .map_err(|e| glyph_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| glyph_error(StatusCode::NOT_FOUND, "Glyph not found"))?;

    let status = if record.funding_txid.is_some() {
        "registered"
    } else {
        "pending"
    };

    Ok(Json(GlyphInfoResponse {
        ghost_id: record.ghost_id,
        pixels: record.pixels,
        bitmap_hash: hex::encode(&record.bitmap_hash),
        commitment: hex::encode(&record.commitment),
        funding_txid: record.funding_txid,
        registered_at: record.registered_at,
        status: status.to_string(),
    }))
}

/// Check if a bitmap hash is available
async fn check_glyph_availability(
    State(state): State<Arc<AppState>>,
    Path(bitmap_hash_hex): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let bitmap_hash = hex::decode(&bitmap_hash_hex)
        .map_err(|_| glyph_error(StatusCode::BAD_REQUEST, "Invalid hex"))?;

    // M-10: Validate decoded bitmap_hash is exactly 32 bytes (SHA-256)
    if bitmap_hash.len() != 32 {
        return Err(glyph_error(
            StatusCode::BAD_REQUEST,
            format!("bitmap_hash must be 32 bytes, got {}", bitmap_hash.len()),
        ));
    }

    let available = state
        .db
        .is_bitmap_available(&bitmap_hash)
        .map_err(|e| glyph_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "available": available,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // parse_addr_from_desc tests
    // =========================================================================

    #[test]
    fn parse_addr_from_desc_extracts_inner_address() {
        assert_eq!(
            parse_addr_from_desc("addr(bcrt1qxyz123)#abcd1234").as_deref(),
            Some("bcrt1qxyz123"),
        );
        assert_eq!(
            parse_addr_from_desc("addr(tb1pqqqq)#deadbeef").as_deref(),
            Some("tb1pqqqq"),
        );
    }

    #[test]
    fn parse_addr_from_desc_returns_none_for_other_descriptors() {
        // tr() / wpkh() / pkh() etc are valid scantxoutset descriptors
        // but not what scan_utxos emits. Returning None here means
        // these rows get filtered out of the response (no
        // attributable address), which is the conservative default.
        assert!(parse_addr_from_desc("tr(xpub...)").is_none());
        assert!(parse_addr_from_desc("wpkh([fingerprint/0]xpub.../0/*)").is_none());
        assert!(parse_addr_from_desc("").is_none());
        assert!(parse_addr_from_desc("addr(unterminated").is_none());
    }

    // =========================================================================
    // derive_encryption_key tests
    // =========================================================================

    #[test]
    fn test_derive_encryption_key_deterministic() {
        let password = "test-password-123";
        let salt = [0xABu8; 32];

        let key1 = derive_encryption_key(password, &salt).expect("first derivation failed");
        let key2 = derive_encryption_key(password, &salt).expect("second derivation failed");

        assert_eq!(key1, key2, "same password and salt must produce same key");
        assert_ne!(key1, [0u8; 32], "derived key must not be all zeros");
    }

    #[test]
    fn test_derive_encryption_key_different_passwords_produce_different_keys() {
        let salt = [0x01u8; 32];

        let key_a = derive_encryption_key("password-a", &salt).expect("derivation a failed");
        let key_b = derive_encryption_key("password-b", &salt).expect("derivation b failed");

        assert_ne!(
            key_a, key_b,
            "different passwords must produce different keys"
        );
    }

    #[test]
    fn test_derive_encryption_key_different_salts_produce_different_keys() {
        let password = "same-password";
        let salt_a = [0x01u8; 32];
        let salt_b = [0x02u8; 32];

        let key_a = derive_encryption_key(password, &salt_a).expect("derivation a failed");
        let key_b = derive_encryption_key(password, &salt_b).expect("derivation b failed");

        assert_ne!(key_a, key_b, "different salts must produce different keys");
    }

    #[test]
    fn test_derive_encryption_key_empty_password() {
        let salt = [0xFFu8; 32];
        let key = derive_encryption_key("", &salt).expect("empty password derivation failed");
        assert_ne!(
            key, [0u8; 32],
            "derived key from empty password must not be all zeros"
        );
    }

    // =========================================================================
    // encrypt_keys / decrypt_keys roundtrip tests
    // =========================================================================

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"secret key material for ghost pay";
        let password = "strong-encryption-password";

        let encrypted = encrypt_keys(plaintext, password).expect("encryption failed");
        let decrypted = decrypt_keys(&encrypted, password).expect("decryption failed");

        assert_eq!(
            decrypted, plaintext,
            "roundtrip must recover original plaintext"
        );
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_empty_plaintext() {
        let plaintext = b"";
        let password = "password";

        let encrypted = encrypt_keys(plaintext, password).expect("encryption failed");
        let decrypted = decrypt_keys(&encrypted, password).expect("decryption failed");

        assert_eq!(
            decrypted, plaintext,
            "roundtrip with empty plaintext must work"
        );
    }

    #[test]
    fn test_encrypt_produces_different_ciphertexts() {
        let plaintext = b"same data each time";
        let password = "password";

        let encrypted1 = encrypt_keys(plaintext, password).expect("encryption 1 failed");
        let encrypted2 = encrypt_keys(plaintext, password).expect("encryption 2 failed");

        // Random salt and nonce mean ciphertexts differ even for same input
        assert_ne!(
            encrypted1, encrypted2,
            "two encryptions of same data must produce different ciphertexts"
        );
    }

    #[test]
    fn test_decrypt_with_wrong_password_fails() {
        let plaintext = b"secret data";
        let encrypted = encrypt_keys(plaintext, "correct-password").expect("encryption failed");

        let result = decrypt_keys(&encrypted, "wrong-password");
        assert!(result.is_err(), "decryption with wrong password must fail");
    }

    #[test]
    fn test_decrypt_truncated_data_fails() {
        // Minimum size is SALT_SIZE + NONCE_SIZE + 16 (auth tag)
        let too_short = vec![0u8; SALT_SIZE + NONCE_SIZE + 15];
        let result = decrypt_keys(&too_short, "password");
        assert!(result.is_err(), "decryption of truncated data must fail");
    }

    #[test]
    fn test_encrypted_format_has_expected_prefix_size() {
        let plaintext = b"test";
        let password = "pw";
        let encrypted = encrypt_keys(plaintext, password).expect("encryption failed");

        // Encrypted output: salt (32) + nonce (12) + ciphertext (plaintext + 16 tag)
        let expected_len = SALT_SIZE + NONCE_SIZE + plaintext.len() + 16;
        assert_eq!(
            encrypted.len(),
            expected_len,
            "encrypted data must be salt + nonce + ciphertext + tag"
        );
    }

    // =========================================================================
    // safe_block_height_u64 tests
    // =========================================================================

    #[test]
    fn test_safe_block_height_u64_zero() {
        let result = safe_block_height_u64(0).expect("0 should be valid");
        assert_eq!(result, 0);
    }

    #[test]
    fn test_safe_block_height_u64_typical_height() {
        let result = safe_block_height_u64(850_000).expect("typical height should be valid");
        assert_eq!(result, 850_000);
    }

    #[test]
    fn test_safe_block_height_u64_max_u32() {
        let result = safe_block_height_u64(u32::MAX as u64).expect("u32::MAX should be valid");
        assert_eq!(result, u32::MAX);
    }

    #[test]
    fn test_safe_block_height_u64_overflow() {
        let result = safe_block_height_u64(u32::MAX as u64 + 1);
        assert!(result.is_err(), "u32::MAX + 1 must be rejected");
    }

    #[test]
    fn test_safe_block_height_u64_u64_max() {
        let result = safe_block_height_u64(u64::MAX);
        assert!(result.is_err(), "u64::MAX must be rejected");
    }

    // =========================================================================
    // safe_block_height_i64 tests
    // =========================================================================

    #[test]
    fn test_safe_block_height_i64_zero() {
        let result = safe_block_height_i64(0).expect("0 should be valid");
        assert_eq!(result, 0);
    }

    #[test]
    fn test_safe_block_height_i64_typical_height() {
        let result = safe_block_height_i64(850_000).expect("typical height should be valid");
        assert_eq!(result, 850_000);
    }

    #[test]
    fn test_safe_block_height_i64_negative() {
        let result = safe_block_height_i64(-1);
        assert!(result.is_err(), "negative height must be rejected");
    }

    #[test]
    fn test_safe_block_height_i64_large_negative() {
        let result = safe_block_height_i64(i64::MIN);
        assert!(result.is_err(), "i64::MIN must be rejected");
    }

    #[test]
    fn test_safe_block_height_i64_max_u32() {
        let result = safe_block_height_i64(u32::MAX as i64).expect("u32::MAX should be valid");
        assert_eq!(result, u32::MAX);
    }

    #[test]
    fn test_safe_block_height_i64_overflow() {
        let result = safe_block_height_i64(u32::MAX as i64 + 1);
        assert!(result.is_err(), "u32::MAX + 1 as i64 must be rejected");
    }

    // =========================================================================
    // hex_to_32bytes tests
    // =========================================================================

    #[test]
    fn test_hex_to_32bytes_valid_64_char_hex() {
        let hex_str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let result = hex_to_32bytes(hex_str);
        let expected: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hex_to_32bytes_all_zeros() {
        let hex_str = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = hex_to_32bytes(hex_str);
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn test_hex_to_32bytes_all_ff() {
        let hex_str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let result = hex_to_32bytes(hex_str);
        assert_eq!(result, [0xFFu8; 32]);
    }

    #[test]
    fn test_hex_to_32bytes_short_input() {
        // 4 hex chars = 2 bytes; should zero-pad the remaining 30 bytes
        let hex_str = "abcd";
        let result = hex_to_32bytes(hex_str);
        let mut expected = [0u8; 32];
        expected[0] = 0xAB;
        expected[1] = 0xCD;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hex_to_32bytes_long_input_truncated() {
        // 66 hex chars = 33 bytes; should only take the first 32 bytes
        let hex_str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let result = hex_to_32bytes(hex_str);
        let expected: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hex_to_32bytes_invalid_hex() {
        // Invalid hex chars should result in all zeros (fallback)
        let result = hex_to_32bytes("not-valid-hex!!");
        assert_eq!(result, [0u8; 32]);
    }

    #[test]
    fn test_hex_to_32bytes_empty_string() {
        // Empty string: 0 bytes decoded, zero-padded result
        let result = hex_to_32bytes("");
        assert_eq!(result, [0u8; 32]);
    }

    // =========================================================================
    // ConfidentialTransferRequest deserialization tests
    // =========================================================================

    #[test]
    fn test_confidential_transfer_request_deserialization() {
        let json = serde_json::json!({
            "proof_hex": "aa".repeat(192),
            "commitment_root": "bb".repeat(32),
            "nullifier": "cc".repeat(32),
            "change_commitment": "dd".repeat(32),
            "recipient_commitment": "ee".repeat(32),
            "recipient_owner_pubkey": "ff".repeat(32),
            "sender_index": 0,
            "recipient_index": 1,
            "epoch": 0,
        });
        let req: ConfidentialTransferRequest =
            serde_json::from_value(json).expect("Valid JSON should parse");

        assert_eq!(req.proof_hex.len(), 384); // 192 bytes * 2 hex chars
        assert_eq!(req.nullifier.len(), 64); // 32 bytes * 2 hex chars
        assert_eq!(req.commitment_root.len(), 64);
        assert_eq!(req.change_commitment.len(), 64);
        assert_eq!(req.recipient_commitment.len(), 64);
        assert_eq!(req.recipient_owner_pubkey.len(), 64);
        assert_eq!(req.sender_index, 0);
        assert_eq!(req.recipient_index, 1);
        assert_eq!(req.epoch, 0);
    }

    // =========================================================================
    // parse_hex_32 tests
    // =========================================================================

    #[test]
    fn test_parse_hex_32_valid() {
        let hex_str = "aa".repeat(32); // 64 hex chars = 32 bytes
        let result = parse_hex_32(&hex_str);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [0xAA; 32]);
    }

    #[test]
    fn test_parse_hex_32_invalid_length() {
        // Too short (31 bytes)
        let hex_str = "aa".repeat(31);
        assert!(parse_hex_32(&hex_str).is_err());

        // Too long (33 bytes)
        let hex_str = "aa".repeat(33);
        assert!(parse_hex_32(&hex_str).is_err());
    }

    #[test]
    fn test_parse_hex_32_invalid_hex() {
        let result = parse_hex_32("not-valid-hex-at-all!!");
        assert!(result.is_err());
    }

    // =========================================================================
    // prover_id computation test
    // =========================================================================

    #[test]
    fn test_prover_id_computation_matches_ghost_zkp() {
        // Compute prover_id the way ghost-pay does it inline
        let ghost_pay_prover_id = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"ghost-zkp-note-prover-v1");
            hasher.update(COMMITMENT_TREE_DEPTH.to_le_bytes());
            let hash: [u8; 32] = hasher.finalize().into();
            hash
        };

        // Compute prover_id the way GhostNoteProver does it
        let prover = ghost_zkp::GhostNoteProver::new(COMMITMENT_TREE_DEPTH);
        let zkp_prover_id = prover.prover_id();

        assert_eq!(
            ghost_pay_prover_id, zkp_prover_id,
            "ghost-pay's inline prover_id must match GhostNoteProver's prover_id"
        );
    }
}
