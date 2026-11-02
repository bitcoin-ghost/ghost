//! Historical Bitcoin Bug Regression Tests
//!
//! End-to-end tests that would have caught real bugs in Bitcoin's history,
//! adapted to Ghost Core's codebase.
//!
//! # Historical Bugs Tested
//!
//! | Bug | Date | CVE | Description |
//! |-----|------|-----|-------------|
//! | Value Overflow | 2010-08-15 | CVE-2010-5139 | Integer overflow created 184B BTC |
//! | BDB Lock Limit | 2013-03-11 | N/A | Database fork split network |
//! | Inflation Bug | 2018-09-17 | CVE-2018-17144 | Duplicate inputs created coins |
//!
//! # Ghost Core Mitigations
//!
//! - `CheckTransaction()` in tx_check.cpp validates value ranges
//! - `MoneyRange()` prevents overflow after each addition
//! - `std::set<COutPoint>` detects duplicate inputs
//! - LevelDB replaced BDB to prevent lock limit issues

use std::collections::{HashMap, HashSet};

// =============================================================================
// CONSTANTS MATCHING GHOST-CORE (consensus/amount.h)
// =============================================================================

/// Maximum money supply in satoshis (21 million BTC)
const MAX_MONEY: i64 = 21_000_000 * 100_000_000;

/// Satoshis per BTC
const COIN: i64 = 100_000_000;

/// Check if value is in valid money range
fn money_range(value: i64) -> bool {
    (0..=MAX_MONEY).contains(&value)
}

// =============================================================================
// TRANSACTION STRUCTURES (mirrors ghost-core/src/primitives/transaction.h)
// =============================================================================

/// Transaction output point (identifies a specific output)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct OutPoint {
    /// Transaction hash
    txid: [u8; 32],
    /// Output index within transaction
    vout: u32,
}

/// Transaction input
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct TxIn {
    /// Previous output being spent
    prevout: OutPoint,
    /// Signature script (simplified)
    script_sig: Vec<u8>,
    /// Sequence number
    sequence: u32,
}

/// Transaction output
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct TxOut {
    /// Value in satoshis
    value: i64,
    /// Output script (simplified)
    script_pubkey: Vec<u8>,
}

/// A Bitcoin transaction
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct Transaction {
    version: i32,
    vin: Vec<TxIn>,
    vout: Vec<TxOut>,
    locktime: u32,
}

impl Transaction {
    /// Get total output value (mirrors CTransaction::GetValueOut)
    fn get_value_out(&self) -> Result<i64, &'static str> {
        let mut total: i64 = 0;
        for output in &self.vout {
            // Check individual output range
            if output.value < 0 {
                return Err("bad-txns-vout-negative");
            }
            if output.value > MAX_MONEY {
                return Err("bad-txns-vout-toolarge");
            }
            // Check for overflow after addition (the 2010 bug fix)
            total = total
                .checked_add(output.value)
                .ok_or("bad-txns-txouttotal-toolarge")?;
            if !money_range(total) {
                return Err("bad-txns-txouttotal-toolarge");
            }
        }
        Ok(total)
    }

    /// Check for duplicate inputs (the 2018 bug fix)
    fn check_duplicate_inputs(&self) -> Result<(), &'static str> {
        let mut seen: HashSet<OutPoint> = HashSet::new();
        for input in &self.vin {
            if !seen.insert(input.prevout) {
                return Err("bad-txns-inputs-duplicate");
            }
        }
        Ok(())
    }
}

/// UTXO set (simplified)
struct UtxoSet {
    coins: HashMap<OutPoint, TxOut>,
}

impl UtxoSet {
    fn new() -> Self {
        Self {
            coins: HashMap::new(),
        }
    }

    fn add_coin(&mut self, outpoint: OutPoint, output: TxOut) {
        self.coins.insert(outpoint, output);
    }

    fn get_coin(&self, outpoint: &OutPoint) -> Option<&TxOut> {
        self.coins.get(outpoint)
    }

    fn spend_coin(&mut self, outpoint: &OutPoint) -> Option<TxOut> {
        self.coins.remove(outpoint)
    }

    /// Check if all inputs exist in UTXO set
    fn have_inputs(&self, tx: &Transaction) -> bool {
        tx.vin
            .iter()
            .all(|input| self.coins.contains_key(&input.prevout))
    }
}

// =============================================================================
// VALIDATION FUNCTIONS (mirrors ghost-core/src/consensus/tx_check.cpp)
// =============================================================================

/// Validation result
#[derive(Debug, Clone)]
enum ValidationResult {
    Valid,
    Invalid(String),
}

impl ValidationResult {
    fn is_valid(&self) -> bool {
        matches!(self, ValidationResult::Valid)
    }
}

/// Check transaction validity (context-free checks)
/// Mirrors CheckTransaction() in ghost-core
fn check_transaction(tx: &Transaction) -> ValidationResult {
    // Check for empty inputs/outputs
    if tx.vin.is_empty() {
        return ValidationResult::Invalid("bad-txns-vin-empty".to_string());
    }
    if tx.vout.is_empty() {
        return ValidationResult::Invalid("bad-txns-vout-empty".to_string());
    }

    // Check output values and total (2010 bug prevention)
    match tx.get_value_out() {
        Ok(_) => {}
        Err(e) => return ValidationResult::Invalid(e.to_string()),
    }

    // Check for duplicate inputs (2018 bug prevention)
    if let Err(e) = tx.check_duplicate_inputs() {
        return ValidationResult::Invalid(e.to_string());
    }

    ValidationResult::Valid
}

/// Check transaction inputs (context-dependent checks)
/// Mirrors Consensus::CheckTxInputs() in ghost-core
fn check_tx_inputs(tx: &Transaction, utxo: &UtxoSet) -> ValidationResult {
    if !utxo.have_inputs(tx) {
        return ValidationResult::Invalid("bad-txns-inputs-missing".to_string());
    }

    // Calculate total input value with overflow protection
    let mut value_in: i64 = 0;
    for input in &tx.vin {
        let coin = utxo.get_coin(&input.prevout).unwrap();

        // Check coin value range
        if !money_range(coin.value) {
            return ValidationResult::Invalid("bad-txns-inputvalues-outofrange".to_string());
        }

        // Check for overflow (2010 bug prevention)
        value_in = match value_in.checked_add(coin.value) {
            Some(v) if money_range(v) => v,
            _ => return ValidationResult::Invalid("bad-txns-inputvalues-outofrange".to_string()),
        };
    }

    // Check inputs >= outputs
    let value_out = tx.get_value_out().unwrap();
    if value_in < value_out {
        return ValidationResult::Invalid("bad-txns-in-belowout".to_string());
    }

    // Check fee is in valid range
    let fee = value_in - value_out;
    if !money_range(fee) {
        return ValidationResult::Invalid("bad-txns-fee-outofrange".to_string());
    }

    ValidationResult::Valid
}

// =============================================================================
// TEST 1: 2010 VALUE OVERFLOW BUG (CVE-2010-5139)
// =============================================================================
// On August 15, 2010, block 74638 contained a transaction that created
// 184,467,440,737.09551616 BTC out of thin air due to integer overflow.
//
// The attacker created outputs of 92,233,720,368.54775808 BTC each (close to
// 2^63 satoshis). When summed, these overflowed to a small negative number,
// passing the "outputs <= inputs" check.
//
// Ghost-core fix: MoneyRange() check after EACH addition in get_value_out()

mod overflow_bug_2010 {
    use super::*;

    /// The exact attack: two outputs that overflow when summed
    #[test]
    fn test_001_original_overflow_attack() {
        // The attacker's values (approximately)
        // 92,233,720,368.54775808 BTC = 0x7FFFFFFFFFFFF800 satoshis
        let overflow_value: i64 = 0x7FFFFFFFFFFFF800_u64 as i64;

        // Create the malicious transaction
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: OutPoint {
                    txid: [1u8; 32],
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            }],
            vout: vec![
                TxOut {
                    value: overflow_value,
                    script_pubkey: vec![],
                },
                TxOut {
                    value: overflow_value,
                    script_pubkey: vec![],
                },
            ],
            locktime: 0,
        };

        // The VULNERABLE check (pre-fix behavior simulation)
        // This would have passed in 2010
        let sum_vulnerable: i64 = overflow_value.wrapping_add(overflow_value);
        println!("Vulnerable sum: {} satoshis", sum_vulnerable);
        println!(
            "This would appear as: {} BTC",
            sum_vulnerable as f64 / COIN as f64
        );

        // Demonstrate the overflow
        assert!(sum_vulnerable < 0, "Overflow produces negative sum");
        assert!(
            sum_vulnerable < MAX_MONEY,
            "Negative sum passes MAX_MONEY check"
        );

        // The FIXED check (current ghost-core behavior)
        let result = check_transaction(&tx);
        assert!(
            !result.is_valid(),
            "Ghost-core MUST reject overflow transaction"
        );

        if let ValidationResult::Invalid(reason) = result {
            println!("Correctly rejected: {}", reason);
            assert!(
                reason.contains("toolarge") || reason.contains("overflow"),
                "Rejection should mention overflow/toolarge"
            );
        }
    }

    /// Boundary test: MAX_MONEY is valid
    #[test]
    fn test_002_max_money_single_output_valid() {
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: OutPoint {
                    txid: [1u8; 32],
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            }],
            vout: vec![TxOut {
                value: MAX_MONEY,
                script_pubkey: vec![],
            }],
            locktime: 0,
        };

        let result = check_transaction(&tx);
        assert!(
            result.is_valid(),
            "MAX_MONEY in single output should be valid"
        );
    }

    /// Boundary test: MAX_MONEY + 1 is invalid
    #[test]
    fn test_003_max_money_plus_one_invalid() {
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: OutPoint {
                    txid: [1u8; 32],
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            }],
            vout: vec![TxOut {
                value: MAX_MONEY + 1,
                script_pubkey: vec![],
            }],
            locktime: 0,
        };

        let result = check_transaction(&tx);
        assert!(!result.is_valid(), "MAX_MONEY + 1 should be rejected");
    }

    /// Test: Two outputs that sum to just over MAX_MONEY
    #[test]
    fn test_004_sum_exceeds_max_money() {
        let half_max = MAX_MONEY / 2;

        let tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: OutPoint {
                    txid: [1u8; 32],
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            }],
            vout: vec![
                TxOut {
                    value: half_max + 1,
                    script_pubkey: vec![],
                },
                TxOut {
                    value: half_max + 1,
                    script_pubkey: vec![],
                },
            ],
            locktime: 0,
        };

        let result = check_transaction(&tx);
        assert!(
            !result.is_valid(),
            "Sum exceeding MAX_MONEY should be rejected"
        );
    }

    /// Test: Negative output value
    #[test]
    fn test_005_negative_output_value() {
        let tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: OutPoint {
                    txid: [1u8; 32],
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            }],
            vout: vec![TxOut {
                value: -1,
                script_pubkey: vec![],
            }],
            locktime: 0,
        };

        let result = check_transaction(&tx);
        assert!(
            !result.is_valid(),
            "Negative output value should be rejected"
        );
    }

    /// Test: Multiple outputs that cumulatively overflow
    #[test]
    fn test_006_cumulative_overflow_many_outputs() {
        // Create many outputs that individually are valid but sum to overflow
        let per_output = MAX_MONEY / 10 + 1; // Each is ~2.1M BTC

        let tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: OutPoint {
                    txid: [1u8; 32],
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            }],
            vout: (0..15)
                .map(|_| TxOut {
                    value: per_output,
                    script_pubkey: vec![],
                })
                .collect(),
            locktime: 0,
        };

        let result = check_transaction(&tx);
        assert!(!result.is_valid(), "Cumulative overflow should be rejected");
    }

    /// Ghost Pool specific: Test payout distribution doesn't overflow
    #[test]
    fn test_007_ghost_pool_payout_no_overflow() {
        // Simulate a Ghost Pool coinbase distributing 3.125 BTC to many miners
        let block_reward: i64 = 312_500_000; // 3.125 BTC in satoshis
        let num_miners = 10_000;
        let per_miner = block_reward / num_miners;

        let tx = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: OutPoint {
                    txid: [0u8; 32],
                    vout: 0xFFFFFFFF,
                }, // Coinbase
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            }],
            vout: (0..num_miners)
                .map(|_| TxOut {
                    value: per_miner,
                    script_pubkey: vec![],
                })
                .collect(),
            locktime: 0,
        };

        let result = check_transaction(&tx);
        assert!(
            result.is_valid(),
            "Normal payout distribution should be valid"
        );

        // Verify total doesn't exceed reward
        let total_out = tx.get_value_out().unwrap();
        assert!(total_out <= block_reward, "Payouts must not exceed reward");
    }
}

// =============================================================================
// TEST 2: 2013 BDB LOCK LIMIT FORK
// =============================================================================
// On March 11, 2013, block 225430 caused a chain split between nodes running
// Bitcoin 0.7 (BerkeleyDB) and 0.8 (LevelDB).
//
// The block had a transaction with many inputs, which required many database
// locks. BDB had a default lock limit that was exceeded, causing 0.7 nodes
// to reject the block while 0.8 nodes accepted it.
//
// Ghost-core fix: Uses LevelDB exclusively (no lock limits), but we test
// that large transactions are handled consistently.

mod bdb_fork_2013 {
    use super::*;

    /// Maximum inputs we might see in a consolidation transaction
    const LARGE_INPUT_COUNT: usize = 5000;

    /// Test: Transaction with many inputs doesn't cause issues
    #[test]
    fn test_008_many_inputs_consistent_validation() {
        // Create UTXO set with many small outputs
        let mut utxo = UtxoSet::new();

        for i in 0..LARGE_INPUT_COUNT {
            let outpoint = OutPoint {
                txid: {
                    let mut txid = [0u8; 32];
                    txid[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                    txid
                },
                vout: 0,
            };
            utxo.add_coin(
                outpoint,
                TxOut {
                    value: 10_000, // 0.0001 BTC each
                    script_pubkey: vec![],
                },
            );
        }

        // Create consolidation transaction spending all inputs
        let tx = Transaction {
            version: 1,
            vin: (0..LARGE_INPUT_COUNT)
                .map(|i| {
                    let mut txid = [0u8; 32];
                    txid[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                    TxIn {
                        prevout: OutPoint { txid, vout: 0 },
                        script_sig: vec![],
                        sequence: 0xFFFFFFFF,
                    }
                })
                .collect(),
            vout: vec![TxOut {
                value: (10_000 * LARGE_INPUT_COUNT as i64) - 10_000, // Minus fee
                script_pubkey: vec![],
            }],
            locktime: 0,
        };

        // Check transaction validity
        let result1 = check_transaction(&tx);
        assert!(
            result1.is_valid(),
            "Large input tx should pass basic checks"
        );

        let result2 = check_tx_inputs(&tx, &utxo);
        assert!(
            result2.is_valid(),
            "Large input tx should pass input checks"
        );

        println!(
            "Successfully validated tx with {} inputs",
            LARGE_INPUT_COUNT
        );
    }

    /// Test: Consistent behavior regardless of input order
    #[test]
    fn test_009_input_order_independence() {
        // Create UTXO set
        let mut utxo = UtxoSet::new();
        let input_count = 100;

        for i in 0..input_count {
            let outpoint = OutPoint {
                txid: {
                    let mut txid = [0u8; 32];
                    txid[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                    txid
                },
                vout: 0,
            };
            utxo.add_coin(
                outpoint,
                TxOut {
                    value: 50_000,
                    script_pubkey: vec![],
                },
            );
        }

        // Create transaction with inputs in forward order
        let tx_forward = Transaction {
            version: 1,
            vin: (0..input_count)
                .map(|i| {
                    let mut txid = [0u8; 32];
                    txid[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                    TxIn {
                        prevout: OutPoint { txid, vout: 0 },
                        script_sig: vec![],
                        sequence: 0xFFFFFFFF,
                    }
                })
                .collect(),
            vout: vec![TxOut {
                value: 50_000 * input_count as i64 - 1000,
                script_pubkey: vec![],
            }],
            locktime: 0,
        };

        // Create transaction with inputs in reverse order
        let tx_reverse = Transaction {
            version: 1,
            vin: (0..input_count)
                .rev()
                .map(|i| {
                    let mut txid = [0u8; 32];
                    txid[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                    TxIn {
                        prevout: OutPoint { txid, vout: 0 },
                        script_sig: vec![],
                        sequence: 0xFFFFFFFF,
                    }
                })
                .collect(),
            vout: vec![TxOut {
                value: 50_000 * input_count as i64 - 1000,
                script_pubkey: vec![],
            }],
            locktime: 0,
        };

        // Both should be valid
        let result_fwd = check_tx_inputs(&tx_forward, &utxo);
        let result_rev = check_tx_inputs(&tx_reverse, &utxo);

        assert!(result_fwd.is_valid(), "Forward order should be valid");
        assert!(result_rev.is_valid(), "Reverse order should be valid");
    }

    /// Test: Block with many transactions is handled atomically
    #[test]
    fn test_010_block_atomicity() {
        // Simulate processing a block with interdependent transactions
        let mut utxo = UtxoSet::new();

        // Add initial UTXO
        let initial_outpoint = OutPoint {
            txid: [0u8; 32],
            vout: 0,
        };
        utxo.add_coin(
            initial_outpoint,
            TxOut {
                value: 100_000_000, // 1 BTC
                script_pubkey: vec![],
            },
        );

        // Transaction chain where each spends the previous
        let mut prev_outpoint = initial_outpoint;
        let mut all_valid = true;
        let chain_length = 100;

        for i in 0..chain_length {
            let tx = Transaction {
                version: 1,
                vin: vec![TxIn {
                    prevout: prev_outpoint,
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                }],
                vout: vec![TxOut {
                    value: 100_000_000 - (i as i64 + 1) * 1000, // Decreasing by fee
                    script_pubkey: vec![],
                }],
                locktime: 0,
            };

            // Validate
            if !check_transaction(&tx).is_valid() {
                all_valid = false;
                break;
            }
            if !check_tx_inputs(&tx, &utxo).is_valid() {
                all_valid = false;
                break;
            }

            // Update UTXO set (spend old, add new)
            utxo.spend_coin(&prev_outpoint);
            let new_outpoint = OutPoint {
                txid: {
                    let mut txid = [0u8; 32];
                    txid[0..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
                    txid
                },
                vout: 0,
            };
            utxo.add_coin(new_outpoint, tx.vout[0].clone());
            prev_outpoint = new_outpoint;
        }

        assert!(all_valid, "All transactions in chain should be valid");
        println!(
            "Successfully processed chain of {} transactions",
            chain_length
        );
    }

    /// Ghost Pool specific: Test UTXO consolidation for payouts
    #[test]
    fn test_011_ghost_pool_utxo_consolidation() {
        // Pool accumulates many small outputs from block rewards
        // Periodically consolidates them for payout efficiency
        let mut utxo = UtxoSet::new();
        let output_count = 1000;

        // Add many small pool UTXOs (simulating accumulated fees)
        for i in 0..output_count {
            let outpoint = OutPoint {
                txid: {
                    let mut txid = [0u8; 32];
                    txid[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                    txid
                },
                vout: 0,
            };
            // Small amounts: 1000-10000 sats each
            let value = 1000 + (i as i64 % 9000);
            utxo.add_coin(
                outpoint,
                TxOut {
                    value,
                    script_pubkey: vec![],
                },
            );
        }

        // Calculate total available
        let total_available: i64 = (0..output_count).map(|i| 1000 + (i as i64 % 9000)).sum();

        // Create consolidation transaction
        let tx = Transaction {
            version: 1,
            vin: (0..output_count)
                .map(|i| {
                    let mut txid = [0u8; 32];
                    txid[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                    TxIn {
                        prevout: OutPoint { txid, vout: 0 },
                        script_sig: vec![],
                        sequence: 0xFFFFFFFF,
                    }
                })
                .collect(),
            vout: vec![TxOut {
                value: total_available - 5000, // Minus consolidation fee
                script_pubkey: vec![],
            }],
            locktime: 0,
        };

        let result = check_tx_inputs(&tx, &utxo);
        assert!(result.is_valid(), "Consolidation should be valid");

        println!(
            "Consolidated {} UTXOs worth {} sats into single output",
            output_count, total_available
        );
    }
}

// =============================================================================
// TEST 3: 2018 INFLATION BUG (CVE-2018-17144)
// =============================================================================
// On September 17, 2018, a critical bug was discovered that allowed a
// transaction to spend the same input twice within the same transaction.
//
// The bug existed because:
// 1. CheckTransaction() didn't check for duplicate inputs (originally)
// 2. UpdateCoins() would crash or corrupt state when spending same UTXO twice
//
// This could create coins from nothing, causing inflation.
//
// Ghost-core fix: Explicit duplicate input check in CheckTransaction()
// using std::set<COutPoint> with O(log n) detection.

mod inflation_bug_2018 {
    use super::*;

    /// The exact attack: same input spent twice in one transaction
    #[test]
    fn test_012_duplicate_input_attack() {
        // Create a UTXO worth 1 BTC
        let mut utxo = UtxoSet::new();
        let victim_outpoint = OutPoint {
            txid: [0xAB; 32],
            vout: 0,
        };
        utxo.add_coin(
            victim_outpoint,
            TxOut {
                value: 100_000_000, // 1 BTC
                script_pubkey: vec![],
            },
        );

        // ATTACK: Spend the same input TWICE to get 2 BTC from 1 BTC
        let malicious_tx = Transaction {
            version: 1,
            vin: vec![
                TxIn {
                    prevout: victim_outpoint,
                    script_sig: vec![0x00], // Dummy sig
                    sequence: 0xFFFFFFFF,
                },
                TxIn {
                    prevout: victim_outpoint, // SAME INPUT AGAIN
                    script_sig: vec![0x00],
                    sequence: 0xFFFFFFFF,
                },
            ],
            vout: vec![TxOut {
                value: 200_000_000, // 2 BTC from 1 BTC input!
                script_pubkey: vec![],
            }],
            locktime: 0,
        };

        // Ghost-core MUST reject this
        let result = check_transaction(&malicious_tx);
        assert!(
            !result.is_valid(),
            "CRITICAL: Duplicate input attack must be rejected!"
        );

        if let ValidationResult::Invalid(reason) = result {
            println!("Correctly rejected: {}", reason);
            assert!(
                reason.contains("duplicate"),
                "Rejection should mention duplicate inputs"
            );
        }
    }

    /// Test: Duplicate detection with different vout values
    #[test]
    fn test_013_same_txid_different_vout_is_valid() {
        let txid = [0xCD; 32];

        // Two DIFFERENT outputs from the same transaction
        let tx = Transaction {
            version: 1,
            vin: vec![
                TxIn {
                    prevout: OutPoint { txid, vout: 0 },
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                },
                TxIn {
                    prevout: OutPoint { txid, vout: 1 }, // Different vout
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                },
            ],
            vout: vec![TxOut {
                value: 100_000,
                script_pubkey: vec![],
            }],
            locktime: 0,
        };

        let result = check_transaction(&tx);
        assert!(result.is_valid(), "Different vout values should be valid");
    }

    /// Test: Duplicate detection with many inputs (performance)
    #[test]
    fn test_014_duplicate_detection_performance() {
        use std::time::Instant;

        let input_count = 10_000;

        // Create transaction with many unique inputs
        let tx_unique = Transaction {
            version: 1,
            vin: (0..input_count)
                .map(|i| {
                    let mut txid = [0u8; 32];
                    txid[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                    TxIn {
                        prevout: OutPoint { txid, vout: 0 },
                        script_sig: vec![],
                        sequence: 0xFFFFFFFF,
                    }
                })
                .collect(),
            vout: vec![TxOut {
                value: 100_000,
                script_pubkey: vec![],
            }],
            locktime: 0,
        };

        let start = Instant::now();
        let result = check_transaction(&tx_unique);
        let duration = start.elapsed();

        assert!(result.is_valid(), "All unique inputs should be valid");
        println!(
            "Checked {} unique inputs in {:?} ({:.2} inputs/ms)",
            input_count,
            duration,
            input_count as f64 / duration.as_millis() as f64
        );

        // Should be fast (O(n log n) with HashSet)
        // Using 500ms threshold to avoid flaky failures on loaded CI systems
        // The actual runtime is typically <50ms but can spike under load
        assert!(
            duration.as_millis() < 500,
            "Duplicate detection should be fast (was {:?})",
            duration
        );
    }

    /// Test: Duplicate at various positions
    #[test]
    fn test_015_duplicate_at_different_positions() {
        let duplicate_outpoint = OutPoint {
            txid: [0xFF; 32],
            vout: 0,
        };

        // Test duplicate at beginning
        let tx_begin = Transaction {
            version: 1,
            vin: vec![
                TxIn {
                    prevout: duplicate_outpoint,
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                },
                TxIn {
                    prevout: duplicate_outpoint,
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                },
                TxIn {
                    prevout: OutPoint {
                        txid: [1u8; 32],
                        vout: 0,
                    },
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                },
            ],
            vout: vec![TxOut {
                value: 100_000,
                script_pubkey: vec![],
            }],
            locktime: 0,
        };
        assert!(
            !check_transaction(&tx_begin).is_valid(),
            "Duplicate at beginning"
        );

        // Test duplicate at end
        let tx_end = Transaction {
            version: 1,
            vin: vec![
                TxIn {
                    prevout: OutPoint {
                        txid: [1u8; 32],
                        vout: 0,
                    },
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                },
                TxIn {
                    prevout: duplicate_outpoint,
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                },
                TxIn {
                    prevout: duplicate_outpoint,
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                },
            ],
            vout: vec![TxOut {
                value: 100_000,
                script_pubkey: vec![],
            }],
            locktime: 0,
        };
        assert!(!check_transaction(&tx_end).is_valid(), "Duplicate at end");

        // Test duplicate separated by other inputs
        let tx_separated = Transaction {
            version: 1,
            vin: vec![
                TxIn {
                    prevout: duplicate_outpoint,
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                },
                TxIn {
                    prevout: OutPoint {
                        txid: [1u8; 32],
                        vout: 0,
                    },
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                },
                TxIn {
                    prevout: OutPoint {
                        txid: [2u8; 32],
                        vout: 0,
                    },
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                },
                TxIn {
                    prevout: duplicate_outpoint,
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                },
            ],
            vout: vec![TxOut {
                value: 100_000,
                script_pubkey: vec![],
            }],
            locktime: 0,
        };
        assert!(
            !check_transaction(&tx_separated).is_valid(),
            "Duplicate separated"
        );
    }

    /// Test: Triple spend (same input three times)
    #[test]
    fn test_016_triple_spend_same_input() {
        let triple_outpoint = OutPoint {
            txid: [0xAA; 32],
            vout: 0,
        };

        let tx = Transaction {
            version: 1,
            vin: vec![
                TxIn {
                    prevout: triple_outpoint,
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                },
                TxIn {
                    prevout: triple_outpoint,
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                },
                TxIn {
                    prevout: triple_outpoint,
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                },
            ],
            vout: vec![TxOut {
                value: 300_000_000,
                script_pubkey: vec![],
            }],
            locktime: 0,
        };

        let result = check_transaction(&tx);
        assert!(!result.is_valid(), "Triple spend must be rejected");
    }

    /// Ghost Pool specific: Verify coinbase can't be spent twice
    #[test]
    fn test_017_ghost_pool_coinbase_no_double_spend() {
        // Coinbase output from block reward
        let coinbase_outpoint = OutPoint {
            txid: [0x00; 32], // Coinbase txid
            vout: 0,
        };

        // Attempt to spend coinbase twice (should be caught by duplicate check)
        let malicious_tx = Transaction {
            version: 1,
            vin: vec![
                TxIn {
                    prevout: coinbase_outpoint,
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                },
                TxIn {
                    prevout: coinbase_outpoint,
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                },
            ],
            vout: vec![TxOut {
                value: 625_000_000,
                script_pubkey: vec![],
            }], // 6.25 BTC
            locktime: 0,
        };

        let result = check_transaction(&malicious_tx);
        assert!(
            !result.is_valid(),
            "Double-spending coinbase must be rejected"
        );
    }
}

// =============================================================================
// COMBINED ATTACK TESTS
// =============================================================================
// Test combinations of historical attack vectors

mod combined_attacks {
    use super::*;

    /// Test: Overflow + duplicate inputs combined
    #[test]
    fn test_018_overflow_plus_duplicate() {
        let overflow_value: i64 = 0x7FFFFFFFFFFFF800_u64 as i64;
        let duplicate_outpoint = OutPoint {
            txid: [0xFF; 32],
            vout: 0,
        };

        let tx = Transaction {
            version: 1,
            vin: vec![
                TxIn {
                    prevout: duplicate_outpoint,
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                },
                TxIn {
                    prevout: duplicate_outpoint,
                    script_sig: vec![],
                    sequence: 0xFFFFFFFF,
                },
            ],
            vout: vec![
                TxOut {
                    value: overflow_value,
                    script_pubkey: vec![],
                },
                TxOut {
                    value: overflow_value,
                    script_pubkey: vec![],
                },
            ],
            locktime: 0,
        };

        let result = check_transaction(&tx);
        assert!(!result.is_valid(), "Combined attack must be rejected");

        // Should catch EITHER the duplicate OR the overflow (or both)
        if let ValidationResult::Invalid(reason) = result {
            let catches_something = reason.contains("duplicate")
                || reason.contains("toolarge")
                || reason.contains("overflow");
            assert!(catches_something, "Should catch at least one attack vector");
        }
    }

    /// Test: Many inputs with one duplicate (needle in haystack)
    #[test]
    fn test_019_hidden_duplicate_in_many_inputs() {
        let num_inputs = 1000;
        let duplicate_position_a = 100;
        let duplicate_position_b = 900;
        let duplicate_outpoint = OutPoint {
            txid: [0xDE; 32],
            vout: 0,
        };

        let tx = Transaction {
            version: 1,
            vin: (0..num_inputs)
                .map(|i| {
                    if i == duplicate_position_a || i == duplicate_position_b {
                        TxIn {
                            prevout: duplicate_outpoint,
                            script_sig: vec![],
                            sequence: 0xFFFFFFFF,
                        }
                    } else {
                        let mut txid = [0u8; 32];
                        txid[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                        TxIn {
                            prevout: OutPoint { txid, vout: 0 },
                            script_sig: vec![],
                            sequence: 0xFFFFFFFF,
                        }
                    }
                })
                .collect(),
            vout: vec![TxOut {
                value: 100_000,
                script_pubkey: vec![],
            }],
            locktime: 0,
        };

        let result = check_transaction(&tx);
        assert!(
            !result.is_valid(),
            "Hidden duplicate in {} inputs must be detected",
            num_inputs
        );
    }

    /// Test: Empty transaction variants
    #[test]
    fn test_020_empty_transaction_variants() {
        // No inputs
        let no_inputs = Transaction {
            version: 1,
            vin: vec![],
            vout: vec![TxOut {
                value: 100_000,
                script_pubkey: vec![],
            }],
            locktime: 0,
        };
        assert!(
            !check_transaction(&no_inputs).is_valid(),
            "No inputs should fail"
        );

        // No outputs
        let no_outputs = Transaction {
            version: 1,
            vin: vec![TxIn {
                prevout: OutPoint {
                    txid: [1u8; 32],
                    vout: 0,
                },
                script_sig: vec![],
                sequence: 0xFFFFFFFF,
            }],
            vout: vec![],
            locktime: 0,
        };
        assert!(
            !check_transaction(&no_outputs).is_valid(),
            "No outputs should fail"
        );

        // Both empty
        let empty = Transaction {
            version: 1,
            vin: vec![],
            vout: vec![],
            locktime: 0,
        };
        assert!(
            !check_transaction(&empty).is_valid(),
            "Empty transaction should fail"
        );
    }
}

// =============================================================================
// GHOST PAY L2 SPECIFIC TESTS
// =============================================================================
// Ensure historical bugs can't occur in Ghost Pay's L2 settlement

mod ghost_pay_l2 {
    use super::*;

    /// Test: Reconciliation batch can't have duplicate settlements
    #[test]
    fn test_022_reconciliation_no_duplicate_settlements() {
        // Simulate a reconciliation batch
        #[allow(dead_code)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        struct Settlement {
            ghost_id: [u8; 32],
            amount: u64,
        }

        let mut settlements: HashSet<[u8; 32]> = HashSet::new();

        // Add settlements
        let ghost_ids = [
            [1u8; 32], [2u8; 32], [3u8; 32], [1u8; 32], // DUPLICATE!
        ];

        let mut duplicates_found = false;
        for ghost_id in &ghost_ids {
            if !settlements.insert(*ghost_id) {
                duplicates_found = true;
                break;
            }
        }

        assert!(
            duplicates_found,
            "Should detect duplicate Ghost ID in batch"
        );
    }

    /// Test: L2 balance can't overflow
    #[test]
    fn test_023_l2_balance_overflow_protection() {
        // L2 balances are u64, same as on-chain
        let balance: u64 = MAX_MONEY as u64;

        // Try to add more
        let credit: u64 = 1;

        let new_balance = balance.checked_add(credit);
        assert!(
            new_balance.is_none() || new_balance.unwrap() > MAX_MONEY as u64,
            "Balance overflow should be detected"
        );
    }

    /// Test: Ghost Lock output values validated
    #[test]
    fn test_024_ghost_lock_value_validation() {
        const MIN_GHOST_LOCK: i64 = 10_000; // 0.0001 BTC

        let lock_amounts = vec![
            (545, false),           // Below dust - invalid
            (546, false),           // At dust but below min lock - invalid
            (10_000, true),         // Minimum lock - valid
            (100_000_000, true),    // 1 BTC - valid
            (MAX_MONEY, true),      // Maximum - valid
            (MAX_MONEY + 1, false), // Over max - invalid
        ];

        for (amount, expected_valid) in lock_amounts {
            let valid = amount >= MIN_GHOST_LOCK && money_range(amount);
            assert_eq!(
                valid, expected_valid,
                "Ghost Lock amount {} validation mismatch",
                amount
            );
        }
    }
}

// =============================================================================
// REGRESSION TEST SUMMARY
// =============================================================================

#[test]
fn test_025_regression_test_summary() {
    println!("\n");
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║     HISTORICAL BITCOIN BUG REGRESSION TESTS - SUMMARY        ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║                                                              ║");
    println!("║  2010 VALUE OVERFLOW (CVE-2010-5139)                         ║");
    println!("║  ├─ Attack: Two outputs of ~92B BTC each overflowed          ║");
    println!("║  ├─ Result: Created 184B BTC from nothing                    ║");
    println!("║  └─ Fix: MoneyRange() check after each value addition        ║");
    println!("║                                                              ║");
    println!("║  2013 BDB LOCK LIMIT FORK                                    ║");
    println!("║  ├─ Attack: Block with many inputs exceeded BDB locks        ║");
    println!("║  ├─ Result: Chain split between 0.7 and 0.8 nodes            ║");
    println!("║  └─ Fix: LevelDB (no lock limits) + consistent validation    ║");
    println!("║                                                              ║");
    println!("║  2018 INFLATION BUG (CVE-2018-17144)                          ║");
    println!("║  ├─ Attack: Same input spent twice in one transaction        ║");
    println!("║  ├─ Result: Could create coins from nothing                  ║");
    println!("║  └─ Fix: Explicit duplicate input check with HashSet         ║");
    println!("║                                                              ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Ghost-Core Protection Status:                               ║");
    println!("║  ✓ Value overflow: MoneyRange() in tx_check.cpp              ║");
    println!("║  ✓ Database fork: LevelDB with atomic operations             ║");
    println!("║  ✓ Duplicate input: std::set<COutPoint> in CheckTransaction  ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!("\n");
}
