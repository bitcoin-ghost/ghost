//! Chain client — how the wallet reads and writes the chain.
//!
//! One implementation: the owner's own node, over `ghostd`'s RPC. The
//! operator-hosted backend it used to share this trait with went with the rest
//! of L2 — a self-custody wallet that can reach a node has no business asking
//! somebody else where its money is.

use async_trait::async_trait;

pub mod ghostd_chain;
pub use ghostd_chain::GhostdChainClient;

/// One unspent output found by a scan.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ScannedL1Utxo {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    pub scriptpubkey_hex: String,
    pub address: Option<String>,
    pub confirmations: u32,
    pub height: u32,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct ScanUtxosResponse {
    pub utxos: Vec<ScannedL1Utxo>,
    pub total_sats: u64,
    /// The tip the scan was taken against. Confirmations elsewhere in the
    /// response are relative to this, not to whatever the tip is now.
    pub chain_height: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChainStatus {
    pub backend_version: String,
    pub network: String,
    /// Latest verified-block height the node reports.
    pub chain_height: Option<u64>,
    /// Highest header bitcoind has seen — equals `chain_height`
    /// when synced, exceeds it during initial block download.
    pub chain_headers: Option<u64>,
    /// Bitcoin Core's verification progress (0..1). 1.0 ≈ synced.
    pub chain_verification_progress: Option<f64>,
    /// Bitcoin Core's IBD flag — true while still syncing the
    /// initial chain history. Once false, the node is at tip.
    pub chain_initial_block_download: Option<bool>,
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("backend returned error: {0}")]
    Backend(String),
    #[error("malformed response: {0}")]
    Malformed(String),
}

#[async_trait]
pub trait ChainClient: Send + Sync {
    async fn status(&self) -> Result<ChainStatus, ChainError>;

    /// Scan the chain UTXO set for outputs at any of `addresses`.
    /// Default impl returns `ChainError::Backend("scan not supported")`
    /// — concrete clients that talk to a node with `scantxoutset`
    /// (or equivalent) override this.
    async fn scan_utxos(
        &self,
        _addresses: &[String],
        _min_confirmations: u32,
    ) -> Result<ScanUtxosResponse, ChainError> {
        Err(ChainError::Backend(
            "this chain client does not support L1 UTXO scanning".into(),
        ))
    }

    /// Broadcast a fully-signed Bitcoin transaction (hex-encoded
    /// raw consensus form). Concrete clients route to bitcoind's
    /// `sendrawtransaction` via their backend. Default impl errors
    /// — clients that don't have a node connection override.
    async fn broadcast_tx(&self, _tx_hex: &str) -> Result<String, ChainError> {
        Err(ChainError::Backend(
            "this chain client does not support broadcast".into(),
        ))
    }

    /// How deeply a transaction is buried, if the backend can say.
    ///
    /// `Ok(None)` means "this backend cannot tell you" — a node without
    /// `txindex` cannot look up an arbitrary txid once it has left the
    /// mempool. That is deliberately distinct from `Ok(Some(0))`, which is
    /// the definite answer "seen, and not yet in a block". A history that
    /// prints 0 for both would show every settled payment as pending.
    async fn tx_confirmations(&self, _txid: &str) -> Result<Option<u32>, ChainError> {
        Ok(None)
    }
}

/// The chain client for a wallet with no node configured.
///
/// Every call fails, with the same sentence saying what to do about it. This
/// exists so that state is impossible to mistake for a working wallet: the
/// alternative — quietly routing to somebody else's node — is how a
/// self-custody wallet ends up asking a stranger what it owns.
#[derive(Debug, Default)]
pub struct NoChain;

impl NoChain {
    fn refuse<T>() -> Result<T, ChainError> {
        Err(ChainError::Backend(
            "no node configured — the wallet reads and writes the chain through \
             your own ghostd. Set it in Settings, or with WRAITHD_GHOSTD_URL \
             (plus WRAITHD_GHOSTD_COOKIE, or _USER and _PASS)."
                .into(),
        ))
    }
}

#[async_trait]
impl ChainClient for NoChain {
    async fn status(&self) -> Result<ChainStatus, ChainError> {
        Self::refuse()
    }
    async fn scan_utxos(
        &self,
        _addresses: &[String],
        _min_confirmations: u32,
    ) -> Result<ScanUtxosResponse, ChainError> {
        Self::refuse()
    }
    async fn broadcast_tx(&self, _tx_hex: &str) -> Result<String, ChainError> {
        Self::refuse()
    }
    // `tx_confirmations` keeps the trait default: "cannot say" is already the
    // honest answer here, and it lets a history render with unknown depth
    // instead of failing outright.
}
