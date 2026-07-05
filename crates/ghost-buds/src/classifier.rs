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
//| FILE: classifier.rs                                                                                                  |
//|======================================================================================================================|

//! Main BUDS transaction classifier
//!
//! Classifies transactions into T0-T3 tiers based on their characteristics.

use bitcoin::Transaction;
use tracing::{debug, trace};

use crate::detector::{
    contains_brc20_pattern, is_inscription_envelope, is_runes_script, PatternDetector,
};
use crate::tier::{BudsTier, ClassificationReason, ClassificationResult, DetectedFeature};
use crate::transaction::ClassifiedTransaction;
use ghost_common::constants::{
    MAX_OP_RETURN_SMALL_BYTES, MAX_TX_SIZE_BITCOIN_PURE, MAX_WITNESS_BYTES_PER_INPUT,
};

/// BUDS transaction classifier
#[derive(Debug, Clone)]
pub struct BudsClassifier {
    /// Standard witness size threshold (T0 limit)
    standard_witness_threshold: usize,
    /// Extended witness size threshold (T1 limit)
    extended_witness_threshold: usize,
    /// Small OP_RETURN threshold (T2 limit)
    small_op_return_threshold: usize,
}

impl Default for BudsClassifier {
    fn default() -> Self {
        Self::new()
    }
}

impl BudsClassifier {
    /// Create a new classifier with default thresholds
    pub fn new() -> Self {
        Self {
            standard_witness_threshold: 108, // Standard sig (72) + pubkey (33) + some overhead
            extended_witness_threshold: MAX_WITNESS_BYTES_PER_INPUT,
            small_op_return_threshold: MAX_OP_RETURN_SMALL_BYTES,
        }
    }

    /// Create with custom thresholds
    pub fn with_thresholds(
        standard_witness: usize,
        extended_witness: usize,
        small_op_return: usize,
    ) -> Self {
        Self {
            standard_witness_threshold: standard_witness,
            extended_witness_threshold: extended_witness,
            small_op_return_threshold: small_op_return,
        }
    }

    /// Classify a transaction
    pub fn classify(&self, tx: &Transaction) -> ClassificationResult {
        trace!(txid = %tx.compute_txid(), "Classifying transaction");

        // Skip coinbase transactions - they're always allowed
        if tx.is_coinbase() {
            return ClassificationResult {
                tier: BudsTier::T0,
                reason: ClassificationReason::StandardPayment,
                details: Some("Coinbase transaction".to_string()),
                features: vec![],
            };
        }

        let mut detector = PatternDetector::new();
        let mut all_features = Vec::new();

        // Analyze outputs
        let mut has_op_return = false;
        let mut max_op_return_size = 0usize;
        let mut has_runes = false;

        for output in &tx.output {
            let features = detector.analyze_script(&output.script_pubkey);
            all_features.extend(features.clone());

            if output.script_pubkey.is_op_return() {
                has_op_return = true;
                let size = output.script_pubkey.len().saturating_sub(2);
                max_op_return_size = max_op_return_size.max(size);
            }

            if is_runes_script(&output.script_pubkey) {
                has_runes = true;
            }
        }

        // Analyze inputs (witnesses)
        let mut has_inscription = false;
        let mut has_brc20 = false;
        let mut max_witness_size = 0usize;
        let mut total_witness_size = 0usize;

        for input in &tx.input {
            let witness = &input.witness;
            let witness_vec: Vec<Vec<u8>> = witness.iter().map(|w| w.to_vec()).collect();
            let features = detector.analyze_witness(&witness_vec);
            all_features.extend(features);

            // Calculate witness sizes
            let input_witness_size: usize = witness.iter().map(|w| w.len()).sum();
            max_witness_size = max_witness_size.max(input_witness_size);
            total_witness_size += input_witness_size;

            // Check for inscription/BRC-20
            for item in witness.iter() {
                if is_inscription_envelope(item) {
                    has_inscription = true;
                }
                if contains_brc20_pattern(item) {
                    has_brc20 = true;
                }
            }
        }

        // Check for multisig and timelocks
        let has_multisig = all_features
            .iter()
            .any(|f| matches!(f, DetectedFeature::Multisig { .. }));
        let has_timelock = all_features
            .iter()
            .any(|f| matches!(f, DetectedFeature::Cltv | DetectedFeature::Csv));
        let has_htlc = all_features
            .iter()
            .any(|f| matches!(f, DetectedFeature::Htlc));

        // Deduplicate features
        all_features.sort_by_key(|f| format!("{:?}", f));
        all_features.dedup_by_key(|f| format!("{:?}", f));

        // Classification logic
        let (tier, reason) = self.determine_tier(
            has_op_return,
            max_op_return_size,
            has_inscription,
            has_brc20,
            has_runes,
            has_multisig,
            has_timelock,
            has_htlc,
            max_witness_size,
            total_witness_size,
            tx.output.len(),
            tx.weight().to_wu() as usize,
            &all_features,
        );

        debug!(
            txid = %tx.compute_txid(),
            tier = %tier,
            reason = %reason,
            "Transaction classified"
        );

        ClassificationResult {
            tier,
            reason,
            details: None,
            features: all_features,
        }
    }

    /// Determine the tier based on analyzed features
    #[allow(clippy::too_many_arguments)]
    fn determine_tier(
        &self,
        has_op_return: bool,
        max_op_return_size: usize,
        has_inscription: bool,
        has_brc20: bool,
        has_runes: bool,
        has_multisig: bool,
        has_timelock: bool,
        has_htlc: bool,
        max_witness_size: usize,
        total_witness_size: usize,
        _output_count: usize,
        tx_weight: usize,
        features: &[DetectedFeature],
    ) -> (BudsTier, ClassificationReason) {
        // T3: Inscriptions, BRC-20, Runes
        if has_inscription {
            return (BudsTier::T3, ClassificationReason::Inscription);
        }
        if has_brc20 {
            return (BudsTier::T3, ClassificationReason::Brc20);
        }
        if has_runes {
            return (BudsTier::T3, ClassificationReason::Runes);
        }

        // T3: Large OP_RETURN (>80 bytes)
        if has_op_return && max_op_return_size > self.small_op_return_threshold {
            return (
                BudsTier::T3,
                ClassificationReason::LargeOpReturn {
                    size: max_op_return_size,
                },
            );
        }

        // T3: Very large witness
        if max_witness_size > 1000 || total_witness_size > 4000 {
            return (
                BudsTier::T3,
                ClassificationReason::LargeWitness {
                    total_bytes: total_witness_size,
                },
            );
        }

        // T3: Extremely large transaction
        if tx_weight > MAX_TX_SIZE_BITCOIN_PURE * 4 {
            return (
                BudsTier::T3,
                ClassificationReason::LargeWitness {
                    total_bytes: tx_weight,
                },
            );
        }

        // T2: Small OP_RETURN (≤80 bytes) - allowed for Lightning, timestamps
        if has_op_return {
            return (
                BudsTier::T2,
                ClassificationReason::SmallOpReturn {
                    size: max_op_return_size,
                },
            );
        }

        // T1: Extended witness (>108 but ≤400 bytes per input)
        if max_witness_size > self.standard_witness_threshold
            && max_witness_size <= self.extended_witness_threshold
        {
            // Check what kind of T1 feature
            if has_htlc {
                return (BudsTier::T1, ClassificationReason::Htlc);
            }
            if has_timelock {
                return (BudsTier::T1, ClassificationReason::Timelock);
            }
            if has_multisig {
                let (m, n) = find_multisig_params(features);
                return (BudsTier::T1, ClassificationReason::Multisig { m, n });
            }
            return (BudsTier::T1, ClassificationReason::ComplexScript);
        }

        // T1: Multisig (even with small witness, it's T1)
        if has_multisig {
            let (m, n) = find_multisig_params(features);
            return (BudsTier::T1, ClassificationReason::Multisig { m, n });
        }

        // T1: Timelocks
        if has_timelock {
            return (BudsTier::T1, ClassificationReason::Timelock);
        }

        // T1: HTLC
        if has_htlc {
            return (BudsTier::T1, ClassificationReason::Htlc);
        }

        // T0: Standard payment
        (BudsTier::T0, ClassificationReason::StandardPayment)
    }

    /// Classify a transaction and wrap with metadata
    pub fn classify_full(&self, tx: &Transaction, fee: Option<u64>) -> ClassifiedTransaction {
        let classification = self.classify(tx);
        ClassifiedTransaction::new(tx, classification, fee)
    }

    /// Classify multiple transactions
    pub fn classify_batch(&self, transactions: &[Transaction]) -> Vec<ClassificationResult> {
        transactions.iter().map(|tx| self.classify(tx)).collect()
    }

    /// Classify and filter transactions by allowed tiers
    pub fn filter_by_tiers<'a>(
        &self,
        transactions: &'a [Transaction],
        allowed_tiers: &[BudsTier],
    ) -> Vec<&'a Transaction> {
        transactions
            .iter()
            .filter(|tx| {
                let result = self.classify(tx);
                result.tier.is_allowed_by(allowed_tiers)
            })
            .collect()
    }

    /// Count transactions that would be filtered out
    pub fn count_filtered(
        &self,
        transactions: &[Transaction],
        allowed_tiers: &[BudsTier],
    ) -> FilteredCount {
        let mut count = FilteredCount::default();

        for tx in transactions {
            let result = self.classify(tx);
            count.total += 1;

            if result.tier.is_allowed_by(allowed_tiers) {
                count.accepted += 1;
            } else {
                count.rejected += 1;
                match result.tier {
                    BudsTier::T0 => count.rejected_t0 += 1,
                    BudsTier::T1 => count.rejected_t1 += 1,
                    BudsTier::T2 => count.rejected_t2 += 1,
                    BudsTier::T3 => count.rejected_t3 += 1,
                }
            }
        }

        count
    }
}

/// Find multisig parameters from features
fn find_multisig_params(features: &[DetectedFeature]) -> (u8, u8) {
    for feature in features {
        if let DetectedFeature::Multisig { m, n } = feature {
            return (*m, *n);
        }
    }
    (0, 0)
}

/// Count of filtered transactions
#[derive(Debug, Clone, Default)]
pub struct FilteredCount {
    pub total: usize,
    pub accepted: usize,
    pub rejected: usize,
    pub rejected_t0: usize,
    pub rejected_t1: usize,
    pub rejected_t2: usize,
    pub rejected_t3: usize,
}

impl FilteredCount {
    pub fn acceptance_rate(&self) -> f64 {
        if self.total == 0 {
            100.0
        } else {
            self.accepted as f64 / self.total as f64 * 100.0
        }
    }
}

/// Policy preset for transaction filtering
#[derive(Debug, Clone)]
pub struct PolicyPreset {
    pub name: &'static str,
    pub allowed_tiers: Vec<BudsTier>,
}

impl PolicyPreset {
    /// Bitcoin Pure: Only T0 and T1 (financial transactions only)
    pub fn bitcoin_pure() -> Self {
        Self {
            name: "strict",
            allowed_tiers: vec![BudsTier::T0, BudsTier::T1],
        }
    }

    /// Permissive: T0, T1, T2 (allows small OP_RETURN for Lightning)
    pub fn permissive() -> Self {
        Self {
            name: "permissive",
            allowed_tiers: vec![BudsTier::T0, BudsTier::T1, BudsTier::T2],
        }
    }

    /// Full Open: All tiers allowed
    pub fn full_open() -> Self {
        Self {
            name: "full_open",
            allowed_tiers: vec![BudsTier::T0, BudsTier::T1, BudsTier::T2, BudsTier::T3],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        absolute::LockTime, blockdata::script::Builder, transaction::Version, Amount, ScriptBuf,
        Sequence, TxIn, TxOut, Witness,
    };

    /// Create a P2WPKH script (OP_0 <20-byte-hash>)
    fn create_p2wpkh_script() -> ScriptBuf {
        Builder::new()
            .push_int(0)
            .push_slice([0u8; 20])
            .into_script()
    }

    /// Create an OP_RETURN script with given data size
    fn create_op_return_script(data_size: usize) -> ScriptBuf {
        // Create OP_RETURN script using raw bytes for compatibility
        // Format: OP_RETURN (0x6a) + OP_PUSHBYTES_N (0x01-0x4b) + data
        let mut bytes = vec![0x6a]; // OP_RETURN

        if data_size <= 40 {
            // Small OP_RETURN: OP_RETURN + PUSHBYTES_40 + 40 bytes
            bytes.push(40); // OP_PUSHBYTES_40
            bytes.extend(std::iter::repeat_n(0u8, 40));
        } else {
            // Large OP_RETURN (>80 bytes): Use multiple pushes
            // OP_RETURN + PUSHBYTES_50 + 50 bytes + PUSHBYTES_50 + 50 bytes
            bytes.push(50); // OP_PUSHBYTES_50
            bytes.extend(std::iter::repeat_n(0u8, 50));
            bytes.push(50); // OP_PUSHBYTES_50
            bytes.extend(std::iter::repeat_n(0u8, 50));
        }

        ScriptBuf::from(bytes)
    }

    /// Create a non-coinbase outpoint (coinbase uses null txid + vout=0xffffffff)
    fn non_coinbase_outpoint() -> bitcoin::OutPoint {
        // Coinbase is detected by tx.is_coinbase() which checks:
        // - single input
        // - previous_output is null (all-zeros txid, vout=0xffffffff)
        // We just need a non-null previous_output
        use bitcoin::hashes::Hash;
        let txid = bitcoin::Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::hash(&[1u8]));
        bitcoin::OutPoint { txid, vout: 0 }
    }

    fn create_simple_tx() -> Transaction {
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

    fn create_op_return_tx(data_size: usize) -> Transaction {
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
                    script_pubkey: create_op_return_script(data_size),
                },
            ],
        }
    }

    #[test]
    fn test_simple_payment_is_t0() {
        let classifier = BudsClassifier::new();
        let tx = create_simple_tx();
        let result = classifier.classify(&tx);

        assert_eq!(result.tier, BudsTier::T0);
        assert!(matches!(
            result.reason,
            ClassificationReason::StandardPayment
        ));
    }

    #[test]
    fn test_small_op_return_is_t2() {
        let classifier = BudsClassifier::new();
        let tx = create_op_return_tx(40); // 40 bytes < 80
        let result = classifier.classify(&tx);

        assert_eq!(result.tier, BudsTier::T2);
        assert!(matches!(
            result.reason,
            ClassificationReason::SmallOpReturn { .. }
        ));
    }

    #[test]
    fn test_large_op_return_is_t3() {
        let classifier = BudsClassifier::new();
        let tx = create_op_return_tx(100); // 100 bytes > 80
        let result = classifier.classify(&tx);

        assert_eq!(result.tier, BudsTier::T3);
        assert!(matches!(
            result.reason,
            ClassificationReason::LargeOpReturn { .. }
        ));
    }

    #[test]
    fn test_policy_presets() {
        let bitcoin_pure = PolicyPreset::bitcoin_pure();
        assert!(bitcoin_pure.allowed_tiers.contains(&BudsTier::T0));
        assert!(bitcoin_pure.allowed_tiers.contains(&BudsTier::T1));
        assert!(!bitcoin_pure.allowed_tiers.contains(&BudsTier::T2));

        let permissive = PolicyPreset::permissive();
        assert!(permissive.allowed_tiers.contains(&BudsTier::T2));
        assert!(!permissive.allowed_tiers.contains(&BudsTier::T3));

        let full_open = PolicyPreset::full_open();
        assert!(full_open.allowed_tiers.contains(&BudsTier::T3));
    }

    #[test]
    fn test_filter_by_tiers() {
        let classifier = BudsClassifier::new();
        let simple_tx = create_simple_tx();
        let op_return_tx = create_op_return_tx(40);
        let large_op_return_tx = create_op_return_tx(100);

        let transactions = vec![simple_tx, op_return_tx, large_op_return_tx];
        let allowed = vec![BudsTier::T0, BudsTier::T1];

        let filtered = classifier.filter_by_tiers(&transactions, &allowed);
        assert_eq!(filtered.len(), 1); // Only the simple payment passes
    }

    #[test]
    fn test_filtered_count() {
        let classifier = BudsClassifier::new();
        let simple_tx = create_simple_tx();
        let small_op_return = create_op_return_tx(40);
        let large_op_return = create_op_return_tx(100);

        let transactions = vec![simple_tx, small_op_return, large_op_return];
        let allowed = vec![BudsTier::T0, BudsTier::T1, BudsTier::T2];

        let count = classifier.count_filtered(&transactions, &allowed);
        assert_eq!(count.total, 3);
        assert_eq!(count.accepted, 2); // T0 and T2
        assert_eq!(count.rejected, 1); // T3
        assert_eq!(count.rejected_t3, 1);
    }
}
