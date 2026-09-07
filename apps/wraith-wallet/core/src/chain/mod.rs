//! Chain client — talks to the wallet's configured ghost-pay backend.
//!
//! Phase 1: a single REST client over HTTPS. Transport layer (clearnet vs. Tor) and
//! GSP WebSocket subscriptions land in subsequent commits.

mod ghost_pay;

use async_trait::async_trait;

pub mod ghostd_chain;
pub use ghost_pay::{GhostPayClient, ScanUtxosResponse, ScannedL1Utxo};
pub use ghostd_chain::GhostdChainClient;

#[derive(Debug, Clone, PartialEq)]
pub struct ChainStatus {
    pub backend_version: String,
    pub network: String,
    pub has_keys: bool,
    pub lock_count: u64,
    pub active_sessions: u64,
    /// Latest verified-block height from the operator's bitcoind.
    /// `None` when ghost-pay couldn't reach bitcoind in time.
    pub chain_height: Option<u64>,
    /// Highest header bitcoind has seen — equals `chain_height`
    /// when synced, exceeds it during initial block download.
    pub chain_headers: Option<u64>,
    /// Bitcoin Core's verification progress (0..1). 1.0 ≈ synced.
    pub chain_verification_progress: Option<f64>,
    /// Bitcoin Core's IBD flag — true while still syncing the
    /// initial chain history. Once false, the node is at tip.
    pub chain_initial_block_download: Option<bool>,
    /// L2 chain tip — latest finalized ghost-pay block height.
    pub l2_height: Option<u64>,
    /// Current L2 epoch (`l2_height / L2_EPOCH_BLOCKS`).
    pub l2_epoch: Option<u64>,
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
}
