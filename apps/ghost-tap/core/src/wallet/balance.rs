//! Balance tracking and UTXO management

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Represents an unspent transaction output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    /// Transaction ID
    pub txid: String,
    /// Output index
    pub vout: u32,
    /// Amount in smallest unit
    pub amount: u64,
    /// Number of confirmations
    pub confirmations: u32,
    /// Address this UTXO belongs to
    pub address: String,
    /// Derivation path index for this address
    pub address_index: u32,
    /// BIP44 change index: 0 = receive (external), 1 = change (internal).
    #[serde(default)]
    pub change: u32,
}

/// Balance summary for a wallet
#[derive(Debug, Clone, Default)]
pub struct Balance {
    /// Confirmed balance (spendable)
    pub confirmed: u64,
    /// Unconfirmed incoming
    pub pending_incoming: u64,
    /// Unconfirmed outgoing (in mempool)
    pub pending_outgoing: u64,
}

impl Balance {
    /// Total balance including pending
    pub fn total(&self) -> u64 {
        self.confirmed + self.pending_incoming
    }

    /// Available balance for spending
    pub fn available(&self) -> u64 {
        self.confirmed.saturating_sub(self.pending_outgoing)
    }
}

/// UTXO set manager
#[derive(Debug, Default)]
pub struct UtxoSet {
    utxos: Vec<Utxo>,
    /// UTXOs that have been spent locally but not yet confirmed on-chain.
    /// Keyed by (txid, vout).
    pending_spends: HashSet<(String, u32)>,
}

impl UtxoSet {
    pub fn new() -> Self {
        Self {
            utxos: Vec::new(),
            pending_spends: HashSet::new(),
        }
    }

    /// Add a UTXO to the set
    pub fn add(&mut self, utxo: Utxo) {
        self.utxos.push(utxo);
    }

    /// Remove a spent UTXO (confirmed spend).
    pub fn spend(&mut self, txid: &str, vout: u32) -> Option<Utxo> {
        // Also clear from pending_spends if present.
        self.pending_spends.remove(&(txid.to_string(), vout));

        if let Some(pos) = self
            .utxos
            .iter()
            .position(|u| u.txid == txid && u.vout == vout)
        {
            Some(self.utxos.remove(pos))
        } else {
            None
        }
    }

    /// Mark a UTXO as pending-spend (broadcast but unconfirmed).
    ///
    /// The UTXO remains in the set so it can be referenced later,
    /// but its amount is counted as `pending_outgoing` in the balance.
    pub fn mark_pending_spend(&mut self, txid: &str, vout: u32) {
        self.pending_spends.insert((txid.to_string(), vout));
    }

    /// Clear a pending spend (e.g. if the transaction was dropped from mempool).
    pub fn clear_pending_spend(&mut self, txid: &str, vout: u32) {
        self.pending_spends.remove(&(txid.to_string(), vout));
    }

    /// Check if a UTXO is marked as pending-spend.
    pub fn is_pending_spend(&self, txid: &str, vout: u32) -> bool {
        self.pending_spends.contains(&(txid.to_string(), vout))
    }

    /// Get all UTXOs
    pub fn all(&self) -> &[Utxo] {
        &self.utxos
    }

    /// Calculate total balance
    pub fn balance(&self) -> Balance {
        let confirmed: u64 = self
            .utxos
            .iter()
            .filter(|u| u.confirmations > 0)
            .map(|u| u.amount)
            .sum();

        let pending_incoming: u64 = self
            .utxos
            .iter()
            .filter(|u| u.confirmations == 0)
            .map(|u| u.amount)
            .sum();

        let pending_outgoing: u64 = self
            .utxos
            .iter()
            .filter(|u| self.pending_spends.contains(&(u.txid.clone(), u.vout)))
            .map(|u| u.amount)
            .sum();

        Balance {
            confirmed,
            pending_incoming,
            pending_outgoing,
        }
    }

    /// Select UTXOs for spending using a simple largest-first algorithm.
    ///
    /// Excludes UTXOs that are already pending-spend or unconfirmed.
    pub fn select_for_amount(&self, target: u64) -> Option<Vec<&Utxo>> {
        let mut sorted: Vec<_> = self
            .utxos
            .iter()
            .filter(|u| {
                u.confirmations > 0 && !self.pending_spends.contains(&(u.txid.clone(), u.vout))
            })
            .collect();

        sorted.sort_by_key(|e| std::cmp::Reverse(e.amount));

        let mut selected = Vec::new();
        let mut total = 0u64;

        for utxo in sorted {
            selected.push(utxo);
            total += utxo.amount;
            if total >= target {
                return Some(selected);
            }
        }

        None // Insufficient funds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_utxo(txid: &str, amount: u64, confirmations: u32) -> Utxo {
        Utxo {
            txid: txid.into(),
            vout: 0,
            amount,
            confirmations,
            address: "addr".into(),
            address_index: 0,
            change: 0,
        }
    }

    #[test]
    fn test_utxo_selection() {
        let mut set = UtxoSet::new();

        set.add(Utxo {
            txid: "tx1".into(),
            vout: 0,
            amount: 100,
            confirmations: 6,
            address: "addr1".into(),
            address_index: 0,
            change: 0,
        });

        set.add(Utxo {
            txid: "tx2".into(),
            vout: 0,
            amount: 200,
            confirmations: 3,
            address: "addr2".into(),
            address_index: 1,
            change: 0,
        });

        let selected = set.select_for_amount(150).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].amount, 200);

        let selected = set.select_for_amount(250).unwrap();
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn test_pending_outgoing_balance() {
        let mut set = UtxoSet::new();
        set.add(test_utxo("tx1", 10000, 6));
        set.add(test_utxo("tx2", 20000, 3));

        let bal = set.balance();
        assert_eq!(bal.confirmed, 30000);
        assert_eq!(bal.pending_outgoing, 0);
        assert_eq!(bal.available(), 30000);

        // Mark tx1 as pending spend
        set.mark_pending_spend("tx1", 0);
        let bal = set.balance();
        assert_eq!(bal.confirmed, 30000);
        assert_eq!(bal.pending_outgoing, 10000);
        assert_eq!(bal.available(), 20000);
    }

    #[test]
    fn test_pending_spend_excluded_from_selection() {
        let mut set = UtxoSet::new();
        set.add(test_utxo("tx1", 10000, 6));
        set.add(test_utxo("tx2", 20000, 3));

        set.mark_pending_spend("tx2", 0);

        // tx2 is pending-spend, so only tx1 is available
        let selected = set.select_for_amount(5000).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].txid, "tx1");

        // Can't reach 15000 with only tx1
        assert!(set.select_for_amount(15000).is_none());
    }

    #[test]
    fn test_clear_pending_spend() {
        let mut set = UtxoSet::new();
        set.add(test_utxo("tx1", 10000, 6));

        set.mark_pending_spend("tx1", 0);
        assert!(set.is_pending_spend("tx1", 0));
        assert_eq!(set.balance().pending_outgoing, 10000);

        set.clear_pending_spend("tx1", 0);
        assert!(!set.is_pending_spend("tx1", 0));
        assert_eq!(set.balance().pending_outgoing, 0);
    }

    #[test]
    fn test_confirmed_spend_clears_pending() {
        let mut set = UtxoSet::new();
        set.add(test_utxo("tx1", 10000, 6));
        set.mark_pending_spend("tx1", 0);

        // Confirmed spend removes from both utxos and pending_spends
        let spent = set.spend("tx1", 0);
        assert!(spent.is_some());
        assert!(!set.is_pending_spend("tx1", 0));
        assert_eq!(set.balance().confirmed, 0);
        assert_eq!(set.balance().pending_outgoing, 0);
    }

    #[test]
    fn test_unconfirmed_utxos_as_pending_incoming() {
        let mut set = UtxoSet::new();
        set.add(test_utxo("tx1", 5000, 0)); // unconfirmed

        let bal = set.balance();
        assert_eq!(bal.confirmed, 0);
        assert_eq!(bal.pending_incoming, 5000);
        assert_eq!(bal.total(), 5000);
        assert_eq!(bal.available(), 0);
    }
}
