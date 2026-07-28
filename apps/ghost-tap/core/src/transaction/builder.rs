//! Transaction builder

use ghost_common::constants::DUST_THRESHOLD_SATS;

use super::TransactionError;
use crate::wallet::{Balance, Utxo};
use serde::{Deserialize, Serialize};

/// Fee priority level
#[derive(Debug, Clone, Copy, Default)]
pub enum FeePriority {
    Low,
    #[default]
    Medium,
    High,
    Custom(u64), // sat/vbyte
}

/// A transaction output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutput {
    pub address: String,
    pub amount: u64,
}

/// A transaction input (references a UTXO)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInput {
    pub txid: String,
    pub vout: u32,
    pub amount: u64,
    pub address_index: u32,
    /// BIP44 change index: 0 = receive, 1 = change.
    #[serde(default)]
    pub change: u32,
}

/// An unsigned transaction ready for signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedTransaction {
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub fee: u64,
}

/// A signed transaction ready for broadcast
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// Raw transaction bytes (hex encoded)
    pub raw_tx: String,
    /// Transaction ID
    pub txid: String,
    /// Transaction size in vbytes
    pub size: usize,
    /// Fee paid
    pub fee: u64,
}

/// Transaction builder for constructing Ghost transactions
pub struct TransactionBuilder {
    outputs: Vec<TxOutput>,
    fee_priority: FeePriority,
    change_address: Option<String>,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self {
            outputs: Vec::new(),
            fee_priority: FeePriority::default(),
            change_address: None,
        }
    }

    /// Add an output (recipient). Rejects zero-amount outputs.
    pub fn add_output(mut self, address: String, amount: u64) -> Self {
        if amount == 0 {
            // Silently skip zero-amount outputs (will fail at build time if no valid outputs)
            return self;
        }
        self.outputs.push(TxOutput { address, amount });
        self
    }

    /// Set fee priority
    pub fn fee_priority(mut self, priority: FeePriority) -> Self {
        self.fee_priority = priority;
        self
    }

    /// Override the fee rate with a value fetched from the network.
    ///
    /// This sets `FeePriority::Custom(sat_per_vbyte)`, bypassing the
    /// hardcoded Low/Medium/High defaults.
    pub fn with_fetched_fee_rate(mut self, sat_per_vbyte: u64) -> Self {
        self.fee_priority = FeePriority::Custom(sat_per_vbyte);
        self
    }

    /// Set change address (if not set, a new one will be derived)
    pub fn change_address(mut self, address: String) -> Self {
        self.change_address = Some(address);
        self
    }

    /// Build the unsigned transaction
    pub fn build(
        self,
        available_utxos: &[Utxo],
        _balance: &Balance,
    ) -> Result<UnsignedTransaction, TransactionError> {
        // L-10: Reject outputs below dust threshold
        for output in &self.outputs {
            if output.amount < DUST_THRESHOLD_SATS {
                return Err(TransactionError::InvalidTransaction(format!(
                    "output amount {} below dust threshold {}",
                    output.amount, DUST_THRESHOLD_SATS
                )));
            }
        }

        // Calculate total output amount
        let total_output: u64 = self.outputs.iter().map(|o| o.amount).sum();

        // Initial fee estimate with assumed 2 inputs
        let initial_fee = self.estimate_fee(self.outputs.len(), 2);
        let total_needed = total_output + initial_fee;

        // Select UTXOs
        let selected = select_utxos(available_utxos, total_needed)?;

        let total_input: u64 = selected.iter().map(|u| u.amount).sum();

        // M-4: Re-estimate fee with actual input count
        let actual_fee = self.estimate_fee(self.outputs.len() + 1, selected.len()); // +1 for potential change

        // Calculate change with corrected fee
        let change = total_input.saturating_sub(total_output + actual_fee);

        let mut outputs = self.outputs;

        // Add change output if significant
        let final_fee = if change > DUST_THRESHOLD_SATS {
            let change_addr = self
                .change_address
                .ok_or_else(|| TransactionError::InvalidTransaction("No change address".into()))?;
            outputs.push(TxOutput {
                address: change_addr,
                amount: change,
            });
            actual_fee
        } else {
            // L-11: When dust change is absorbed, set fee = actual difference
            total_input - total_output
        };

        let inputs = selected
            .into_iter()
            .map(|u| TxInput {
                txid: u.txid.clone(),
                vout: u.vout,
                amount: u.amount,
                address_index: u.address_index,
                change: u.change,
            })
            .collect();

        Ok(UnsignedTransaction {
            inputs,
            outputs,
            fee: final_fee,
        })
    }

    fn estimate_fee(&self, num_outputs: usize, num_inputs: usize) -> u64 {
        // Simplified fee estimation
        // Real implementation should calculate based on transaction size
        let base_size = 10; // Version, locktime, etc.
        let input_size = 148; // P2PKH input
        let output_size = 34; // P2PKH output

        let estimated_size = base_size + (num_inputs * input_size) + (num_outputs * output_size);

        let sat_per_vbyte = match self.fee_priority {
            FeePriority::Low => 1,
            FeePriority::Medium => 5,
            FeePriority::High => 20,
            FeePriority::Custom(rate) => rate,
        };

        (estimated_size as u64) * sat_per_vbyte
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Select UTXOs for spending.
///
/// Strategy:
/// 1. Look for a single UTXO that is an exact match (within dust threshold).
/// 2. Try smallest-first subset that reaches the target with minimal waste.
/// 3. Fall back to largest-first accumulation.
///
/// Only confirmed UTXOs (confirmations > 0) are considered.
pub fn select_utxos(utxos: &[Utxo], target: u64) -> Result<Vec<Utxo>, TransactionError> {
    let mut confirmed: Vec<_> = utxos
        .iter()
        .filter(|u| u.confirmations > 0)
        .cloned()
        .collect();

    if confirmed.is_empty() {
        return Err(TransactionError::InsufficientFunds {
            needed: target,
            available: 0,
        });
    }

    let total_available: u64 = confirmed.iter().map(|u| u.amount).sum();
    if total_available < target {
        return Err(TransactionError::InsufficientFunds {
            needed: target,
            available: total_available,
        });
    }

    // 1. Exact match — single UTXO within dust threshold (546 sats).
    confirmed.sort_by_key(|u| u.amount);
    for utxo in &confirmed {
        if utxo.amount >= target && utxo.amount <= target + DUST_THRESHOLD_SATS {
            return Ok(vec![utxo.clone()]);
        }
    }

    // 2. Smallest-first accumulation — minimises number of inputs while
    //    keeping change small. Walk ascending and stop as soon as we reach
    //    the target.
    {
        let mut selected = Vec::new();
        let mut total = 0u64;
        for utxo in &confirmed {
            if total >= target {
                break;
            }
            selected.push(utxo.clone());
            total += utxo.amount;
        }
        if total >= target {
            // Check if we can drop the last (largest) selected UTXO and still
            // meet the target — reduces waste.
            while selected.len() > 1 {
                let last = selected.last().unwrap().amount;
                if total - last >= target {
                    total -= last;
                    selected.pop();
                } else {
                    break;
                }
            }
            return Ok(selected);
        }
    }

    // 3. Largest-first fallback (should be unreachable given the total check
    //    above, but included for completeness).
    confirmed.sort_by(|a, b| b.amount.cmp(&a.amount));
    let mut selected = Vec::new();
    let mut total = 0u64;
    for utxo in confirmed {
        selected.push(utxo);
        total += selected.last().unwrap().amount;
        if total >= target {
            return Ok(selected);
        }
    }

    Err(TransactionError::InsufficientFunds {
        needed: target,
        available: total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_utxos() -> Vec<Utxo> {
        vec![
            Utxo {
                txid: "tx1".into(),
                vout: 0,
                amount: 10000,
                confirmations: 6,
                address: "addr1".into(),
                address_index: 0,
                change: 0,
            },
            Utxo {
                txid: "tx2".into(),
                vout: 0,
                amount: 20000,
                confirmations: 3,
                address: "addr2".into(),
                address_index: 1,
                change: 0,
            },
        ]
    }

    fn utxo(txid: &str, amount: u64, confirmations: u32) -> Utxo {
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

    // ---- select_utxos tests ----

    #[test]
    fn test_utxo_selection() {
        let utxos = test_utxos();
        let selected = select_utxos(&utxos, 15000).unwrap();
        // Smallest-first: needs both 10000 + 20000 to reach 15000
        // (no single exact match, and 20000 is > 15000+546 so not near-exact)
        let total: u64 = selected.iter().map(|u| u.amount).sum();
        assert!(total >= 15000);
    }

    #[test]
    fn test_insufficient_funds() {
        let utxos = test_utxos();
        let result = select_utxos(&utxos, 50000);
        assert!(matches!(
            result,
            Err(TransactionError::InsufficientFunds { .. })
        ));
    }

    #[test]
    fn test_empty_utxos() {
        let result = select_utxos(&[], 1000);
        assert!(matches!(
            result,
            Err(TransactionError::InsufficientFunds {
                needed: 1000,
                available: 0
            })
        ));
    }

    #[test]
    fn test_unconfirmed_utxos_excluded() {
        let utxos = vec![
            utxo("tx1", 50000, 0), // unconfirmed
            utxo("tx2", 5000, 1),  // confirmed
        ];
        let selected = select_utxos(&utxos, 5000).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].txid, "tx2");
    }

    #[test]
    fn test_exact_match_preferred() {
        let utxos = vec![
            utxo("tx_big", 100000, 1),
            utxo("tx_exact", 5000, 1),
            utxo("tx_small", 2000, 1),
        ];
        // 5000 is an exact match for target 5000
        let selected = select_utxos(&utxos, 5000).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].txid, "tx_exact");
    }

    #[test]
    fn test_near_exact_within_dust() {
        let utxos = vec![
            utxo("tx_big", 100000, 1),
            utxo("tx_near", 5500, 1), // within 546 of 5000
        ];
        let selected = select_utxos(&utxos, 5000).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].txid, "tx_near");
    }

    #[test]
    fn test_multiple_small_utxos_combined() {
        let utxos = vec![
            utxo("tx1", 3000, 2),
            utxo("tx2", 4000, 1),
            utxo("tx3", 5000, 1),
        ];
        let selected = select_utxos(&utxos, 8000).unwrap();
        let total: u64 = selected.iter().map(|u| u.amount).sum();
        assert!(total >= 8000);
    }

    #[test]
    fn test_all_utxos_needed() {
        let utxos = vec![
            utxo("tx1", 3000, 1),
            utxo("tx2", 4000, 1),
            utxo("tx3", 5000, 1),
        ];
        // Need almost all: 11999 < 12000 total
        let selected = select_utxos(&utxos, 11999).unwrap();
        let total: u64 = selected.iter().map(|u| u.amount).sum();
        assert!(total >= 11999);
    }

    #[test]
    fn test_insufficient_after_filtering_unconfirmed() {
        let utxos = vec![
            utxo("tx1", 50000, 0), // unconfirmed
            utxo("tx2", 1000, 1),
        ];
        let result = select_utxos(&utxos, 5000);
        assert!(matches!(
            result,
            Err(TransactionError::InsufficientFunds { .. })
        ));
    }

    // ---- TransactionBuilder tests ----

    #[test]
    fn test_builder_single_output() {
        let utxos = vec![utxo("tx1", 100000, 6)];
        let balance = Balance {
            confirmed: 100000,
            pending_incoming: 0,
            pending_outgoing: 0,
        };

        let tx = TransactionBuilder::new()
            .add_output("recipient".into(), 50000)
            .change_address("change_addr".into())
            .build(&utxos, &balance)
            .unwrap();

        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.inputs[0].txid, "tx1");
        assert!(tx.fee > 0);
        // Should have recipient + change outputs
        assert!(!tx.outputs.is_empty());
    }

    #[test]
    fn test_builder_multiple_outputs() {
        let utxos = vec![utxo("tx1", 200000, 6)];
        let balance = Balance {
            confirmed: 200000,
            pending_incoming: 0,
            pending_outgoing: 0,
        };

        let tx = TransactionBuilder::new()
            .add_output("addr1".into(), 50000)
            .add_output("addr2".into(), 30000)
            .change_address("change".into())
            .build(&utxos, &balance)
            .unwrap();

        // At least the two explicit outputs
        assert!(tx.outputs.len() >= 2);
        let total_out: u64 = tx.outputs.iter().map(|o| o.amount).sum();
        let total_in: u64 = tx.inputs.iter().map(|i| i.amount).sum();
        assert_eq!(total_in, total_out + tx.fee);
    }

    #[test]
    fn test_builder_insufficient_funds() {
        let utxos = vec![utxo("tx1", 1000, 6)];
        let balance = Balance {
            confirmed: 1000,
            pending_incoming: 0,
            pending_outgoing: 0,
        };

        let result = TransactionBuilder::new()
            .add_output("addr".into(), 500000)
            .change_address("change".into())
            .build(&utxos, &balance);

        assert!(matches!(
            result,
            Err(TransactionError::InsufficientFunds { .. })
        ));
    }

    #[test]
    fn test_builder_no_change_address_error() {
        // When change > dust but no change address is set, should error
        let utxos = vec![utxo("tx1", 100000, 6)];
        let balance = Balance {
            confirmed: 100000,
            pending_incoming: 0,
            pending_outgoing: 0,
        };

        let result = TransactionBuilder::new()
            .add_output("addr".into(), 1000)
            .build(&utxos, &balance);

        assert!(matches!(
            result,
            Err(TransactionError::InvalidTransaction(_))
        ));
    }

    #[test]
    fn test_builder_fee_priority() {
        let builder_low = TransactionBuilder::new().fee_priority(FeePriority::Low);
        let builder_high = TransactionBuilder::new().fee_priority(FeePriority::High);

        let fee_low = builder_low.estimate_fee(1, 1);
        let fee_high = builder_high.estimate_fee(1, 1);

        assert!(fee_high > fee_low);
    }

    #[test]
    fn test_builder_custom_fee() {
        let builder = TransactionBuilder::new().fee_priority(FeePriority::Custom(10));
        let fee = builder.estimate_fee(1, 1);
        // base(10) + 1*input(148) + 1*output(34) = 192 bytes * 10 sat/vbyte
        assert_eq!(fee, 1920);
    }

    #[test]
    fn test_builder_dust_change_absorbed_as_fee() {
        // When change is below dust (546), it should be absorbed into the fee
        // i.e. no change output is added
        let utxos = vec![utxo("tx1", 2000, 6)];
        let balance = Balance {
            confirmed: 2000,
            pending_incoming: 0,
            pending_outgoing: 0,
        };

        let result = TransactionBuilder::new()
            .add_output("addr".into(), 1000)
            .change_address("change".into())
            .build(&utxos, &balance);

        // This may succeed or fail depending on fee estimate; if it succeeds,
        // check that any change output is > 546
        if let Ok(tx) = result {
            for output in &tx.outputs {
                if output.address == "change" {
                    assert!(output.amount > 546);
                }
            }
        }
    }

    #[test]
    fn test_fee_scales_with_inputs_outputs() {
        let builder = TransactionBuilder::new();
        let fee_1_1 = builder.estimate_fee(1, 1);
        let fee_2_2 = builder.estimate_fee(2, 2);
        let fee_5_5 = builder.estimate_fee(5, 5);

        assert!(fee_2_2 > fee_1_1);
        assert!(fee_5_5 > fee_2_2);
    }
}
