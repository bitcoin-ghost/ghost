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
//| FILE: broadcaster.rs                                                                                                 |
//|======================================================================================================================|

//! L1 Settlement Broadcaster
//!
//! Handles broadcasting reconciliation transactions to Bitcoin network
//! and monitoring for confirmations.

use bitcoin::consensus::encode::serialize;
use bitcoin::Txid;
use std::sync::Arc;

use crate::error::{ReconciliationError, ReconciliationResult};
use crate::executor::BatchTransaction;
use crate::DISPUTE_WINDOW_BLOCKS;

/// Trait for broadcasting transactions to L1
pub trait L1Broadcaster: Send + Sync {
    /// Broadcast a raw transaction
    fn broadcast(&self, tx_hex: &str) -> Result<String, String>;

    /// Get current block height
    fn get_block_height(&self) -> Result<u64, String>;

    /// Check if a transaction is confirmed
    fn is_confirmed(&self, txid: &str) -> Result<Option<u32>, String>;
}

/// RPC call function type
type RpcFn = Arc<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync>;

/// Confirmation check function type
type ConfirmFn = Arc<dyn Fn(&str) -> Result<Option<u32>, String> + Send + Sync>;

/// RPC-based broadcaster using Bitcoin Core
pub struct RpcBroadcaster {
    /// RPC client (injected)
    rpc_fn: RpcFn,
    /// Get height function
    height_fn: Arc<dyn Fn() -> Result<u64, String> + Send + Sync>,
    /// Check confirmation function
    confirm_fn: ConfirmFn,
}

impl RpcBroadcaster {
    /// Create a new RPC broadcaster with callback functions
    pub fn new<B, H, C>(broadcast: B, get_height: H, check_confirm: C) -> Self
    where
        B: Fn(&str, &str) -> Result<String, String> + Send + Sync + 'static,
        H: Fn() -> Result<u64, String> + Send + Sync + 'static,
        C: Fn(&str) -> Result<Option<u32>, String> + Send + Sync + 'static,
    {
        Self {
            rpc_fn: Arc::new(broadcast),
            height_fn: Arc::new(get_height),
            confirm_fn: Arc::new(check_confirm),
        }
    }
}

impl L1Broadcaster for RpcBroadcaster {
    fn broadcast(&self, tx_hex: &str) -> Result<String, String> {
        (self.rpc_fn)("sendrawtransaction", tx_hex)
    }

    fn get_block_height(&self) -> Result<u64, String> {
        (self.height_fn)()
    }

    fn is_confirmed(&self, txid: &str) -> Result<Option<u32>, String> {
        (self.confirm_fn)(txid)
    }
}

/// Settlement broadcaster - orchestrates the full L1 settlement lifecycle
pub struct SettlementBroadcaster<B: L1Broadcaster> {
    /// The L1 broadcaster
    broadcaster: B,
    /// Minimum confirmations before considering submitted
    min_confirmations: u32,
}

impl<B: L1Broadcaster> SettlementBroadcaster<B> {
    /// Create a new settlement broadcaster
    pub fn new(broadcaster: B) -> Self {
        Self {
            broadcaster,
            min_confirmations: 1,
        }
    }

    /// Set minimum confirmations
    pub fn with_min_confirmations(mut self, min: u32) -> Self {
        self.min_confirmations = min;
        self
    }

    /// Broadcast a batch transaction to L1
    pub fn broadcast_batch(
        &self,
        batch_tx: &BatchTransaction,
    ) -> ReconciliationResult<BroadcastResult> {
        // Serialize transaction to hex
        let tx_bytes = serialize(&batch_tx.transaction);
        let tx_hex = hex::encode(&tx_bytes);

        // Broadcast
        let txid_str = self.broadcaster.broadcast(&tx_hex).map_err(|e| {
            ReconciliationError::L1TransactionError(format!("Broadcast failed: {}", e))
        })?;

        // Parse txid
        let txid: Txid = txid_str.parse().map_err(|e| {
            ReconciliationError::L1TransactionError(format!("Invalid txid returned: {}", e))
        })?;

        Ok(BroadcastResult {
            txid,
            txid_str,
            batch_id: batch_tx.batch_id.clone(),
            total_sats: batch_tx.total_input_sats,
            fee_sats: batch_tx.mining_fee,
        })
    }

    /// Check confirmation status of a transaction
    pub fn check_confirmation(&self, txid: &str) -> ReconciliationResult<ConfirmationStatus> {
        let current_height = self.broadcaster.get_block_height().map_err(|e| {
            ReconciliationError::L1TransactionError(format!("Failed to get height: {}", e))
        })?;

        let confirm_height = self.broadcaster.is_confirmed(txid).map_err(|e| {
            ReconciliationError::L1TransactionError(format!("Failed to check confirmation: {}", e))
        })?;

        match confirm_height {
            Some(height) => {
                let confirmations = current_height.saturating_sub(height as u64) + 1;
                let dispute_remaining =
                    (DISPUTE_WINDOW_BLOCKS as u64).saturating_sub(confirmations);

                Ok(ConfirmationStatus::Confirmed {
                    block_height: height,
                    confirmations: confirmations as u32,
                    dispute_blocks_remaining: dispute_remaining as u32,
                    finalized: confirmations >= DISPUTE_WINDOW_BLOCKS as u64,
                })
            }
            None => Ok(ConfirmationStatus::Pending),
        }
    }
}

/// Result of broadcasting a batch transaction
#[derive(Debug, Clone)]
pub struct BroadcastResult {
    /// Transaction ID
    pub txid: Txid,
    /// Transaction ID as string
    pub txid_str: String,
    /// Batch ID
    pub batch_id: String,
    /// Total satoshis moved
    pub total_sats: u64,
    /// Fee paid
    pub fee_sats: u64,
}

/// Confirmation status of a transaction
#[derive(Debug, Clone)]
pub enum ConfirmationStatus {
    /// Transaction is pending (not yet in a block)
    Pending,
    /// Transaction is confirmed
    Confirmed {
        /// Block height where confirmed
        block_height: u32,
        /// Number of confirmations
        confirmations: u32,
        /// Blocks remaining in dispute window
        dispute_blocks_remaining: u32,
        /// Whether dispute window has passed
        finalized: bool,
    },
}

/// Batch lifecycle status
#[derive(Debug, Clone)]
pub enum BatchLifecycleStatus {
    /// Batch has been submitted to L1
    Submitted { txid: String },
    /// Waiting for confirmations
    WaitingConfirmations { current: u32, required: u32 },
    /// Confirmed on L1
    Confirmed {
        block_height: u32,
        confirmations: u32,
    },
    /// In dispute window
    InDisputeWindow { blocks_remaining: u32 },
    /// Fully finalized
    Finalized,
    /// Rejected (disputed)
    Rejected,
}

#[cfg(test)]
mod tests {
    use super::*;
    struct MockBroadcaster {
        broadcast_result: Result<String, String>,
        height: u64,
        confirmed_at: Option<u32>,
    }

    impl L1Broadcaster for MockBroadcaster {
        fn broadcast(&self, _tx_hex: &str) -> Result<String, String> {
            self.broadcast_result.clone()
        }

        fn get_block_height(&self) -> Result<u64, String> {
            Ok(self.height)
        }

        fn is_confirmed(&self, _txid: &str) -> Result<Option<u32>, String> {
            Ok(self.confirmed_at)
        }
    }

    #[test]
    fn test_confirmation_status_pending() {
        let broadcaster = MockBroadcaster {
            broadcast_result: Ok("abc123".to_string()),
            height: 800_000,
            confirmed_at: None,
        };

        let settlement = SettlementBroadcaster::new(broadcaster);
        let status = settlement.check_confirmation("abc123").unwrap();

        assert!(matches!(status, ConfirmationStatus::Pending));
    }

    #[test]
    fn test_confirmation_status_confirmed() {
        let broadcaster = MockBroadcaster {
            broadcast_result: Ok("abc123".to_string()),
            height: 800_010,
            confirmed_at: Some(800_000),
        };

        let settlement = SettlementBroadcaster::new(broadcaster);
        let status = settlement.check_confirmation("abc123").unwrap();

        let ConfirmationStatus::Confirmed {
            confirmations,
            finalized,
            ..
        } = status
        else {
            panic!("Expected Confirmed status, got {:?}", status);
        };
        assert_eq!(confirmations, 11);
        assert!(!finalized); // Need 144 confirmations
    }

    #[test]
    fn test_confirmation_status_finalized() {
        let broadcaster = MockBroadcaster {
            broadcast_result: Ok("abc123".to_string()),
            height: 800_200,
            confirmed_at: Some(800_000),
        };

        let settlement = SettlementBroadcaster::new(broadcaster);
        let status = settlement.check_confirmation("abc123").unwrap();

        let ConfirmationStatus::Confirmed {
            finalized,
            dispute_blocks_remaining,
            ..
        } = status
        else {
            panic!("Expected Confirmed status, got {:?}", status);
        };
        assert!(finalized);
        assert_eq!(dispute_blocks_remaining, 0);
    }
}
