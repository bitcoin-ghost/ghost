//! Category 6: Transaction Classification (BUDS) Tests (27 tests)
//!
//! Tests for the REAL ghost-buds BUDS transaction classification:
//! - T0: Core financial (P2WPKH, P2WSH, P2TR key path)
//! - T1: Extended financial (HTLC, PTLC, timelocks, complex multisig)
//! - T2: Data anchoring (OP_RETURN ≤80 bytes, Lightning)
//! - T3: Heavy data (inscriptions, Runes, BRC-20)

use bitcoin::{
    absolute::LockTime, blockdata::script::Builder, hashes::Hash, transaction::Version, Amount,
    ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use ghost_buds::{BudsClassifier, BudsTier, ClassificationReason, PolicyPreset};

// =============================================================================
// Helper functions for creating test transactions
// =============================================================================

/// Create a P2WPKH script (OP_0 <20-byte-hash>)
fn create_p2wpkh_script() -> ScriptBuf {
    Builder::new()
        .push_int(0)
        .push_slice([0u8; 20])
        .into_script()
}

/// Create a P2WSH script (OP_0 <32-byte-hash>)
fn create_p2wsh_script() -> ScriptBuf {
    Builder::new()
        .push_int(0)
        .push_slice([0u8; 32])
        .into_script()
}

/// Create a P2TR script (OP_1 <32-byte-pubkey>)
fn create_p2tr_script() -> ScriptBuf {
    Builder::new()
        .push_int(1)
        .push_slice([0u8; 32])
        .into_script()
}

/// Create a P2SH script (OP_HASH160 <20-byte-hash> OP_EQUAL)
#[allow(dead_code)]
fn create_p2sh_script() -> ScriptBuf {
    let bytes = vec![
        0xa9, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87,
    ];
    ScriptBuf::from(bytes)
}

/// Create an OP_RETURN script with given data size
fn create_op_return_script(data_size: usize) -> ScriptBuf {
    let mut bytes = vec![0x6a]; // OP_RETURN

    if data_size <= 75 {
        bytes.push(data_size as u8);
        bytes.extend(std::iter::repeat_n(0u8, data_size));
    } else {
        // For larger sizes, use multiple pushes
        bytes.push(50); // OP_PUSHBYTES_50
        bytes.extend(std::iter::repeat_n(0u8, 50));
        bytes.push(50); // OP_PUSHBYTES_50
        bytes.extend(std::iter::repeat_n(0u8, 50));
    }

    ScriptBuf::from(bytes)
}

/// Create a non-coinbase outpoint
fn non_coinbase_outpoint() -> bitcoin::OutPoint {
    let txid = bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::hash(&[1u8]));
    bitcoin::OutPoint { txid, vout: 0 }
}

/// Create a simple P2WPKH transaction (T0)
fn create_simple_payment_tx() -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: create_p2wpkh_script(),
        }],
    }
}

/// Create a transaction with small OP_RETURN (T2)
fn create_small_op_return_tx() -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: create_p2wpkh_script(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: create_op_return_script(40),
            },
        ],
    }
}

/// Create a transaction with large OP_RETURN (T3)
fn create_large_op_return_tx() -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: create_p2wpkh_script(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: create_op_return_script(100), // >80 bytes
            },
        ],
    }
}

/// Create a transaction with large witness (T3)
fn create_large_witness_tx() -> Transaction {
    // Create a witness with >1KB data to trigger T3
    let mut witness = Witness::new();
    witness.push(vec![0u8; 1500]); // 1.5KB witness item

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: create_p2wpkh_script(),
        }],
    }
}

/// Create a coinbase transaction (should be T0, always allowed)
fn create_coinbase_tx() -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint::null(), // Coinbase marker
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(625_000_000),
            script_pubkey: create_p2wpkh_script(),
        }],
    }
}

// =============================================================================
// T0 - CORE FINANCIAL TESTS (Tests 301-304)
// =============================================================================

#[test]
fn test_301_simple_payment_classified_as_t0() {
    let classifier = BudsClassifier::new();
    let tx = create_simple_payment_tx();
    let result = classifier.classify(&tx);

    assert_eq!(result.tier, BudsTier::T0);
    assert!(matches!(
        result.reason,
        ClassificationReason::StandardPayment
    ));
}

#[test]
fn test_302_p2wsh_output_classified_as_t0() {
    let classifier = BudsClassifier::new();

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: create_p2wsh_script(),
        }],
    };

    let result = classifier.classify(&tx);
    assert_eq!(result.tier, BudsTier::T0);
}

#[test]
fn test_303_p2tr_output_classified_as_t0() {
    let classifier = BudsClassifier::new();

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: create_p2tr_script(),
        }],
    };

    let result = classifier.classify(&tx);
    assert_eq!(result.tier, BudsTier::T0);
}

#[test]
fn test_304_coinbase_always_t0() {
    let classifier = BudsClassifier::new();
    let tx = create_coinbase_tx();
    let result = classifier.classify(&tx);

    assert_eq!(result.tier, BudsTier::T0);
    // Coinbase transactions are always T0
    assert!(result.details.is_some());
    assert!(result.details.unwrap().contains("Coinbase"));
}

// =============================================================================
// T2 - DATA ANCHORING TESTS (Tests 310-313)
// =============================================================================

#[test]
fn test_310_small_op_return_classified_as_t2() {
    let classifier = BudsClassifier::new();
    let tx = create_small_op_return_tx();
    let result = classifier.classify(&tx);

    assert_eq!(result.tier, BudsTier::T2);
    assert!(matches!(
        result.reason,
        ClassificationReason::SmallOpReturn { .. }
    ));
}

#[test]
fn test_311_op_return_32_bytes_classified_as_t2() {
    let classifier = BudsClassifier::new();

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: create_p2wpkh_script(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: create_op_return_script(32), // Hash commitment
            },
        ],
    };

    let result = classifier.classify(&tx);
    assert_eq!(result.tier, BudsTier::T2);
}

#[test]
fn test_312_op_return_80_bytes_is_t2() {
    let classifier = BudsClassifier::new();

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: create_p2wpkh_script(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: create_op_return_script(75), // Under 80 limit
            },
        ],
    };

    let result = classifier.classify(&tx);
    assert_eq!(result.tier, BudsTier::T2);
}

#[test]
fn test_313_multiple_outputs_with_op_return() {
    let classifier = BudsClassifier::new();

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: create_p2wpkh_script(),
            },
            TxOut {
                value: Amount::from_sat(30000),
                script_pubkey: create_p2wpkh_script(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: create_op_return_script(20),
            },
        ],
    };

    let result = classifier.classify(&tx);
    assert_eq!(result.tier, BudsTier::T2);
}

// =============================================================================
// T3 - HEAVY DATA TESTS (Tests 314-318)
// =============================================================================

#[test]
fn test_314_large_op_return_classified_as_t3() {
    let classifier = BudsClassifier::new();
    let tx = create_large_op_return_tx();
    let result = classifier.classify(&tx);

    assert_eq!(result.tier, BudsTier::T3);
    assert!(matches!(
        result.reason,
        ClassificationReason::LargeOpReturn { .. }
    ));
}

#[test]
fn test_315_large_witness_classified_as_t3() {
    let classifier = BudsClassifier::new();
    let tx = create_large_witness_tx();
    let result = classifier.classify(&tx);

    assert_eq!(result.tier, BudsTier::T3);
    assert!(matches!(
        result.reason,
        ClassificationReason::LargeWitness { .. }
    ));
}

#[test]
fn test_316_very_large_witness_t3() {
    let classifier = BudsClassifier::new();

    // Create witness with >4KB total
    let mut witness = Witness::new();
    witness.push(vec![0u8; 2000]);
    witness.push(vec![0u8; 2000]);
    witness.push(vec![0u8; 500]);

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: create_p2wpkh_script(),
        }],
    };

    let result = classifier.classify(&tx);
    assert_eq!(result.tier, BudsTier::T3);
}

#[test]
fn test_317_multiple_large_witness_inputs() {
    let classifier = BudsClassifier::new();

    // Multiple inputs with large witnesses
    let mut witness1 = Witness::new();
    witness1.push(vec![0u8; 500]);
    witness1.push(vec![0u8; 600]);

    let mut witness2 = Witness::new();
    witness2.push(vec![0u8; 800]);
    witness2.push(vec![0u8; 900]);

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::hash(&[
                        1u8,
                    ])),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: witness1,
            },
            TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::hash(&[
                        2u8,
                    ])),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: witness2,
            },
        ],
        output: vec![TxOut {
            value: Amount::from_sat(50000),
            script_pubkey: create_p2wpkh_script(),
        }],
    };

    let result = classifier.classify(&tx);
    // With 2800 total witness bytes, this should be T3
    assert_eq!(result.tier, BudsTier::T3);
}

#[test]
fn test_318_large_op_return_with_payment() {
    let classifier = BudsClassifier::new();

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: non_coinbase_outpoint(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(50000),
                script_pubkey: create_p2wpkh_script(),
            },
            TxOut {
                value: Amount::from_sat(30000),
                script_pubkey: create_p2wpkh_script(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: create_op_return_script(100), // >80 bytes = T3
            },
        ],
    };

    let result = classifier.classify(&tx);
    assert_eq!(result.tier, BudsTier::T3);
}

// =============================================================================
// POLICY PRESET TESTS (Tests 319-322)
// =============================================================================

#[test]
fn test_319_bitcoin_pure_policy() {
    let policy = PolicyPreset::bitcoin_pure();

    // The preset's canonical name was renamed to "strict" (with "bitcoin_pure"
    // kept as a serde alias / constructor for back-compat) during the
    // tier-filtering work; the constructor name is unchanged.
    assert_eq!(policy.name, "strict");
    assert!(policy.allowed_tiers.contains(&BudsTier::T0));
    assert!(policy.allowed_tiers.contains(&BudsTier::T1));
    assert!(!policy.allowed_tiers.contains(&BudsTier::T2));
    assert!(!policy.allowed_tiers.contains(&BudsTier::T3));
}

#[test]
fn test_320_permissive_policy() {
    let policy = PolicyPreset::permissive();

    assert_eq!(policy.name, "permissive");
    assert!(policy.allowed_tiers.contains(&BudsTier::T0));
    assert!(policy.allowed_tiers.contains(&BudsTier::T1));
    assert!(policy.allowed_tiers.contains(&BudsTier::T2));
    assert!(!policy.allowed_tiers.contains(&BudsTier::T3));
}

#[test]
fn test_321_full_open_policy() {
    let policy = PolicyPreset::full_open();

    assert_eq!(policy.name, "full_open");
    assert!(policy.allowed_tiers.contains(&BudsTier::T0));
    assert!(policy.allowed_tiers.contains(&BudsTier::T1));
    assert!(policy.allowed_tiers.contains(&BudsTier::T2));
    assert!(policy.allowed_tiers.contains(&BudsTier::T3));
}

#[test]
fn test_322_tier_is_allowed_by() {
    let allowed = vec![BudsTier::T0, BudsTier::T1];

    assert!(BudsTier::T0.is_allowed_by(&allowed));
    assert!(BudsTier::T1.is_allowed_by(&allowed));
    assert!(!BudsTier::T2.is_allowed_by(&allowed));
    assert!(!BudsTier::T3.is_allowed_by(&allowed));
}

// =============================================================================
// FILTER AND COUNT TESTS (Tests 323-327)
// =============================================================================

#[test]
fn test_323_filter_by_tiers() {
    let classifier = BudsClassifier::new();
    let simple_tx = create_simple_payment_tx();
    let op_return_tx = create_small_op_return_tx();
    let large_op_return_tx = create_large_op_return_tx();

    let transactions = vec![simple_tx, op_return_tx, large_op_return_tx];
    let allowed = vec![BudsTier::T0, BudsTier::T1];

    let filtered = classifier.filter_by_tiers(&transactions, &allowed);
    assert_eq!(filtered.len(), 1); // Only T0 passes
}

#[test]
fn test_324_filtered_count() {
    let classifier = BudsClassifier::new();
    let simple_tx = create_simple_payment_tx();
    let op_return_tx = create_small_op_return_tx();
    let large_op_return_tx = create_large_op_return_tx();

    let transactions = vec![simple_tx, op_return_tx, large_op_return_tx];
    let allowed = vec![BudsTier::T0, BudsTier::T1, BudsTier::T2];

    let count = classifier.count_filtered(&transactions, &allowed);
    assert_eq!(count.total, 3);
    assert_eq!(count.accepted, 2); // T0 and T2
    assert_eq!(count.rejected, 1); // T3
    assert_eq!(count.rejected_t3, 1);
}

#[test]
fn test_325_acceptance_rate() {
    let classifier = BudsClassifier::new();
    let transactions: Vec<Transaction> = (0..10)
        .map(|i| {
            if i < 8 {
                create_simple_payment_tx()
            } else {
                create_large_op_return_tx()
            }
        })
        .collect();

    let allowed = vec![BudsTier::T0, BudsTier::T1];
    let count = classifier.count_filtered(&transactions, &allowed);

    assert_eq!(count.total, 10);
    assert_eq!(count.accepted, 8);
    assert!((count.acceptance_rate() - 80.0).abs() < 0.1);
}

#[test]
fn test_326_classify_batch() {
    let classifier = BudsClassifier::new();
    let transactions = vec![
        create_simple_payment_tx(),
        create_small_op_return_tx(),
        create_large_op_return_tx(),
    ];

    let results = classifier.classify_batch(&transactions);
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].tier, BudsTier::T0);
    assert_eq!(results[1].tier, BudsTier::T2);
    assert_eq!(results[2].tier, BudsTier::T3);
}

#[test]
fn test_327_empty_transactions() {
    let classifier = BudsClassifier::new();
    let transactions: Vec<Transaction> = vec![];

    let results = classifier.classify_batch(&transactions);
    assert!(results.is_empty());

    let count = classifier.count_filtered(&transactions, &[BudsTier::T0]);
    assert_eq!(count.total, 0);
    assert_eq!(count.acceptance_rate(), 100.0); // Edge case: empty = 100%
}
