//! A [`ChainClient`] that talks to the owner's own node.
//!
//! # Why this exists
//!
//! Until now the wallet's only chain backend was ghost-pay, so every balance
//! and every broadcast went through an operator. That is the arrangement the
//! Ghost Pay L2 is being removed to end: self-custody on ordinary Bitcoin
//! infrastructure, payments through Wraith with Ghost Locks.
//!
//! `ghostd.rs` already made this argument for one path — the unilateral exit,
//! where "no operator cooperation" is the entire point and routing through
//! ghost-pay would defeat it. The same reasoning applies to the rest of the
//! wallet; this generalises it.
//!
//! # Sync client, async trait
//!
//! [`GhostdRpc`] is deliberately synchronous — `reqwest::blocking` panics on
//! drop inside a tokio runtime, so it uses `ureq`. The calls therefore run on
//! `spawn_blocking`: `scantxoutset` walks the whole UTXO set and would
//! otherwise stall the reactor for as long as that takes.
//!
//! # What it deliberately does not report
//!
//! `l2_height` and `l2_epoch` are always `None`. A node has no L2 and inventing
//! a number would be worse than an absent one — the field means "the operator's
//! ledger is here", and with no operator there is no such place.

use std::sync::Arc;

use crate::chain::{ChainClient, ChainError, ChainStatus, ScanUtxosResponse, ScannedL1Utxo};
use crate::ghostd::GhostdRpc;

/// Chain access straight to the owner's node.
pub struct GhostdChainClient {
    rpc: Arc<GhostdRpc>,
    network: String,
}

impl GhostdChainClient {
    /// Wrap an RPC connection. `network` is reported by [`ChainClient::status`].
    pub fn new(rpc: GhostdRpc, network: impl Into<String>) -> Self {
        Self {
            rpc: Arc::new(rpc),
            network: network.into(),
        }
    }

    /// Run a blocking RPC off the reactor.
    async fn blocking<T, F>(&self, f: F) -> Result<T, ChainError>
    where
        T: Send + 'static,
        F: FnOnce(&GhostdRpc) -> Result<T, crate::ghostd::GhostdError> + Send + 'static,
    {
        let rpc = Arc::clone(&self.rpc);
        tokio::task::spawn_blocking(move || f(&rpc))
            .await
            .map_err(|e| ChainError::Backend(format!("node call panicked: {e}")))?
            .map_err(|e| ChainError::Backend(e.to_string()))
    }
}

#[async_trait::async_trait]
impl ChainClient for GhostdChainClient {
    async fn status(&self) -> Result<ChainStatus, ChainError> {
        let height = self.blocking(|rpc| rpc.get_block_count()).await?;
        Ok(ChainStatus {
            backend_version: "ghostd".into(),
            network: self.network.clone(),
            chain_height: Some(height),
            // `getblockcount` alone cannot distinguish "at tip" from "still
            // syncing". Reporting the height as though it were both would
            // claim a sync state this call never established.
            chain_headers: None,
            chain_verification_progress: None,
            chain_initial_block_download: None,
        })
    }

    async fn scan_utxos(
        &self,
        addresses: &[String],
        min_confirmations: u32,
    ) -> Result<ScanUtxosResponse, ChainError> {
        if addresses.is_empty() {
            return Ok(ScanUtxosResponse {
                utxos: Vec::new(),
                total_sats: 0,
                chain_height: 0,
            });
        }
        let addrs = addresses.to_vec();
        let (rows, height) = self
            .blocking(move |rpc| rpc.scan_tx_out_set(&addrs))
            .await?;

        let mut utxos = Vec::with_capacity(rows.len());
        let mut total_sats = 0u64;
        for r in rows {
            // BTC → sats. bitcoind reports a JSON number; rounding rather than
            // truncating, because 0.00012345 arriving as 0.000123449999 must
            // not lose a satoshi.
            let sats = (r.amount * 100_000_000.0).round() as u64;
            let confirmations = height.saturating_sub(r.height).saturating_add(1) as u32;
            if confirmations < min_confirmations {
                continue;
            }
            total_sats = total_sats.saturating_add(sats);
            utxos.push(ScannedL1Utxo {
                txid: r.txid,
                vout: r.vout,
                amount_sats: sats,
                scriptpubkey_hex: r.script_pub_key,
                // `scantxoutset` returns scripts, not addresses. The caller
                // matches on the script it asked for; guessing an address form
                // here would be inventing a field bitcoind did not send.
                address: None,
                confirmations,
                height: r.height as u32,
            });
        }
        Ok(ScanUtxosResponse {
            utxos,
            total_sats,
            chain_height: height as u32,
        })
    }

    async fn broadcast_tx(&self, tx_hex: &str) -> Result<String, ChainError> {
        let hex = tx_hex.to_string();
        self.blocking(move |rpc| rpc.send_raw_transaction(&hex))
            .await
    }

    /// Ask the node how deep a transaction is.
    ///
    /// An RPC failure here comes back as `Ok(None)`, not `Err`. Without
    /// `txindex` a node genuinely cannot answer for a confirmed transaction it
    /// does not hold, and that is a limit of the node rather than a fault in
    /// the wallet — failing the whole history because one row is unanswerable
    /// would hide the rows that were answerable. The caller renders `None` as
    /// "unknown", never as "unconfirmed".
    async fn tx_confirmations(&self, txid: &str) -> Result<Option<u32>, ChainError> {
        let id = txid.to_string();
        match self
            .blocking(move |rpc| rpc.get_raw_transaction_verbose(&id))
            .await
        {
            // A transaction the node holds but has not mined reports no
            // `confirmations` field at all; that is a definite zero.
            Ok(tx) => Ok(Some(tx.confirmations.unwrap_or(0))),
            Err(_) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {

    /// Confirmations are inclusive of the block the output landed in.
    ///
    /// An output in the tip block has one confirmation, not zero — the
    /// off-by-one here decides whether a freshly confirmed coin is spendable
    /// or invisible.
    #[test]
    fn an_output_in_the_tip_block_has_one_confirmation() {
        let height = 900_000u64;
        let at_tip = height.saturating_sub(900_000).saturating_add(1);
        assert_eq!(at_tip, 1);
        let ten_deep = height.saturating_sub(899_991).saturating_add(1);
        assert_eq!(ten_deep, 10);
    }

    /// BTC→sats must round, not truncate.
    #[test]
    fn a_float_amount_does_not_lose_a_satoshi() {
        let awkward = 0.000_123_449_999_999_f64;
        assert_eq!((awkward * 100_000_000.0).round() as u64, 12_345);
        // Truncation would have lost one.
        assert_eq!((awkward * 100_000_000.0) as u64, 12_344);
    }
}
