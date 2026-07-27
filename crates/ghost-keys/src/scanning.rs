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
//| FILE: scanning.rs                                                                                                    |
//|======================================================================================================================|

//! Payment scanning for Ghost Keys
//!
//! Receivers scan transactions to detect payments made to their Ghost ID.
//! This involves checking each output against possible derived addresses.

use rayon::prelude::*;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;

use crate::config::ScanConfig;
use crate::derivation::{compute_tweak_v2, derive_shared_secret, derive_spend_key};
use crate::GhostKeys;

/// Transaction data for batch scanning: (ephemeral_pubkey, outputs)
/// where outputs are (output_pubkey, optional_amount)
pub(crate) type TransactionOutputs = (PublicKey, Vec<(PublicKey, Option<u64>)>);

// Re-export constants for convenience
// (Users should prefer using ScanConfig directly)

// Custom serde for [u8; 33] using hex encoding
mod pubkey_hex {
    use super::*;

    pub(crate) fn serialize<S>(data: &[u8; 33], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(data))
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 33], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 33 bytes"))
    }
}

/// A detected payment that belongs to us
///
/// # 2.8 HIGH: Spend key is NOT stored
///
/// The spend key is derived on-demand using `derive_spend_key()` rather than
/// being stored. This prevents:
/// - Secret key material lingering in memory
/// - Accidental serialization of secrets
/// - Secrets being copied to logs, caches, or databases
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedPayment {
    /// The output pubkey (hex-encoded for serde)
    #[serde(with = "pubkey_hex")]
    pub output_pubkey: [u8; 33],
    /// The output index in the transaction (vout for spending)
    pub output_index: u32,
    /// The k value used for derivation (v2: position-independent counter)
    pub k: u32,
    /// The tweak used to derive this address
    pub tweak: [u8; 32],
    /// Amount in satoshis (if known)
    pub amount: Option<u64>,
}

impl ScannedPayment {
    /// Derive the spend key for this payment
    ///
    /// # 2.8 HIGH: Spend key is derived, not stored
    ///
    /// This recomputes the spend key from the original spend secret
    /// and tweak. The spend key is never stored in the ScannedPayment
    /// struct to prevent secret key material from lingering in memory
    /// or being accidentally serialized.
    ///
    /// # Arguments
    /// * `spend_secret` - The spend secret from GhostKeys
    ///
    /// # Returns
    /// The derived spend key for signing transactions spending this output
    pub fn derive_spend_key(
        &self,
        spend_secret: &SecretKey,
    ) -> Result<SecretKey, crate::error::GhostKeyError> {
        derive_spend_key(spend_secret, &self.tweak)
    }
}

/// Payment detector for scanning transactions (v2 - position-independent)
///
/// Uses counter-based k scanning instead of position-based index.
/// Safe for shuffled outputs (critical for Wraith Protocol).
pub struct PaymentDetector<'a> {
    keys: &'a GhostKeys,
    secp: Secp256k1<secp256k1::All>,
    /// Scan configuration (controls max_k)
    config: ScanConfig,
}

impl<'a> PaymentDetector<'a> {
    /// Create a new payment detector with default scan config
    pub fn new(keys: &'a GhostKeys) -> Self {
        Self {
            keys,
            secp: Secp256k1::new(),
            config: ScanConfig::default(),
        }
    }

    /// Create a payment detector with custom scan config
    ///
    /// Use this when you need to scan more k values (e.g., for recovery)
    /// or fewer k values (e.g., for fast initial sync)
    pub fn with_config(keys: &'a GhostKeys, config: ScanConfig) -> Self {
        Self {
            keys,
            secp: Secp256k1::new(),
            config,
        }
    }

    /// Get the current scan config
    pub fn config(&self) -> &ScanConfig {
        &self.config
    }

    /// Scan a transaction for payments to us (v2 - position-independent)
    ///
    /// This method iterates through k values (0..=max_k) for each output,
    /// making it safe for shuffled outputs.
    ///
    /// # Arguments
    /// * `ephemeral_pubkey` - The ephemeral pubkey from OP_RETURN
    /// * `outputs` - List of (output_pubkey, amount) pairs
    ///
    /// # Returns
    /// List of detected payments (includes both k and output_index)
    pub fn scan_transaction(
        &self,
        ephemeral_pubkey: &PublicKey,
        outputs: &[(PublicKey, Option<u64>)],
    ) -> Vec<ScannedPayment> {
        let mut found = Vec::new();

        // Compute shared secret once
        let shared_secret = derive_shared_secret(self.keys.scan_secret(), ephemeral_pubkey);

        // Track which k values have been used (to avoid duplicates)
        let mut used_k: std::collections::HashSet<u32> = std::collections::HashSet::new();

        // Check each output against all k values
        for (output_index, (output_pubkey, amount)) in outputs.iter().enumerate() {
            if let Some(payment) = self.check_output(
                &shared_secret,
                output_pubkey,
                output_index as u32,
                *amount,
                &used_k,
            ) {
                used_k.insert(payment.k);
                found.push(payment);
            }
        }

        found
    }

    /// Check if a single output belongs to us (v2 - position-independent)
    ///
    /// 2.8 HIGH: Spend key is NOT stored in ScannedPayment - it's derived on-demand.
    fn check_output(
        &self,
        shared_secret: &[u8; 32],
        output_pubkey: &PublicKey,
        output_index: u32,
        amount: Option<u64>,
        used_k: &std::collections::HashSet<u32>,
    ) -> Option<ScannedPayment> {
        // Try all possible k values up to max_k
        for k in 0..=self.config.max_k() {
            // Skip k values already used by other outputs in this tx
            if used_k.contains(&k) {
                continue;
            }

            let tweak = compute_tweak_v2(shared_secret, k);

            // Expected pubkey = spend_pubkey + tweak*G
            if let Ok(tweak_secret) = SecretKey::from_slice(&tweak) {
                let tweak_pubkey = PublicKey::from_secret_key(&self.secp, &tweak_secret);
                if let Ok(expected_pubkey) = self.keys.spend_pubkey().combine(&tweak_pubkey) {
                    // M-CRYPTO-3: Use constant-time comparison to prevent timing attacks
                    if expected_pubkey
                        .serialize()
                        .ct_eq(&output_pubkey.serialize())
                        .into()
                    {
                        // Found a match! Return payment info.
                        // 2.8 HIGH: We do NOT store the spend key - it's derived via
                        // ScannedPayment::derive_spend_key() when needed for signing.
                        return Some(ScannedPayment {
                            output_pubkey: output_pubkey.serialize(),
                            output_index,
                            k,
                            tweak,
                            amount,
                        });
                    }
                }
            }
        }

        None
    }

    /// Quick check if an output might belong to us (k=0 only)
    ///
    /// **M-12 WARNING: Fast-path check with false negatives.**
    /// This method ONLY tests the k=0 derivation index. Multi-output
    /// transactions that use k>0 will NOT be detected by this method.
    /// Always follow up with a full `scan()` for completeness. Use this
    /// method only as a pre-filter to avoid expensive full scans on
    /// outputs that clearly do not belong to us.
    pub fn quick_check(&self, ephemeral_pubkey: &PublicKey, output_pubkey: &PublicKey) -> bool {
        let shared_secret = derive_shared_secret(self.keys.scan_secret(), ephemeral_pubkey);
        let tweak = compute_tweak_v2(&shared_secret, 0);

        if let Ok(tweak_secret) = SecretKey::from_slice(&tweak) {
            let tweak_pubkey = PublicKey::from_secret_key(&self.secp, &tweak_secret);
            if let Ok(expected_pubkey) = self.keys.spend_pubkey().combine(&tweak_pubkey) {
                // M-CRYPTO-3: Use constant-time comparison to prevent timing attacks
                return expected_pubkey
                    .serialize()
                    .ct_eq(&output_pubkey.serialize())
                    .into();
            }
        }

        false
    }
}

/// Parallel scanner for batch processing (v2 - position-independent)
///
/// Used for L1 Silent Payment scanning where we need to check blockchain
/// outputs against our keys using ECDH.
pub struct BatchScanner {
    /// Number of worker threads
    num_workers: usize,
    /// Scan configuration
    config: ScanConfig,
}

impl BatchScanner {
    /// Create a new batch scanner with specified parallelism
    pub fn new(num_workers: usize) -> Self {
        Self {
            num_workers: num_workers.max(1),
            config: ScanConfig::default(),
        }
    }

    /// Create a batch scanner with custom scan config
    pub fn with_config(num_workers: usize, config: ScanConfig) -> Self {
        Self {
            num_workers: num_workers.max(1),
            config,
        }
    }

    /// Get the number of workers
    pub fn num_workers(&self) -> usize {
        self.num_workers
    }

    /// Get the scan config
    pub fn config(&self) -> &ScanConfig {
        &self.config
    }

    /// Scan multiple transactions in parallel using rayon
    ///
    /// Returns (tx_index, `Vec<ScannedPayment>`) for each transaction with found payments
    pub fn scan_batch(
        &self,
        keys: &GhostKeys,
        transactions: &[TransactionOutputs],
    ) -> Vec<(usize, Vec<ScannedPayment>)> {
        let config = self.config;
        transactions
            .par_iter()
            .enumerate()
            .filter_map(|(idx, (ephemeral, outputs))| {
                // Create detector per thread to avoid sharing Secp256k1 context
                let detector = PaymentDetector::with_config(keys, config);
                let found = detector.scan_transaction(ephemeral, outputs);
                if found.is_empty() {
                    None
                } else {
                    Some((idx, found))
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_scan_own_payment() {
        let keys = GhostKeys::generate();
        let ghost_id = keys.ghost_id();

        // Create a payment using v2 (k=0)
        let (output_pubkey, ephemeral_pubkey, _) =
            ghost_id.derive_payment_address_v2_full(0).unwrap();

        // Scan for it
        let detector = PaymentDetector::new(&keys);
        let found = detector.scan_transaction(&ephemeral_pubkey, &[(output_pubkey, Some(100_000))]);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].output_index, 0);
        assert_eq!(found[0].k, 0);
        assert_eq!(found[0].amount, Some(100_000));
    }

    #[test]
    fn test_scan_multiple_outputs_same_recipient() {
        let keys = GhostKeys::generate();
        let ghost_id = keys.ghost_id();

        // Create ephemeral key for this transaction
        let secp = Secp256k1::new();
        let (ephemeral_secret, _) = secp.generate_keypair(&mut OsRng);

        // Create outputs with k=0, 1, 2 (same recipient, different k values)
        let (out0, ephemeral, _) = ghost_id
            .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 0)
            .unwrap();
        let (out1, _, _) = ghost_id
            .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 1)
            .unwrap();
        let (out2, _, _) = ghost_id
            .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 2)
            .unwrap();

        let outputs = vec![
            (out0, Some(50_000)),
            (out1, Some(75_000)),
            (out2, Some(100_000)),
        ];

        let detector = PaymentDetector::new(&keys);
        let found = detector.scan_transaction(&ephemeral, &outputs);

        assert_eq!(found.len(), 3);
        assert!(found.iter().any(|p| p.k == 0 && p.amount == Some(50_000)));
        assert!(found.iter().any(|p| p.k == 1 && p.amount == Some(75_000)));
        assert!(found.iter().any(|p| p.k == 2 && p.amount == Some(100_000)));
    }

    #[test]
    fn test_scan_shuffled_outputs() {
        let keys = GhostKeys::generate();
        let ghost_id = keys.ghost_id();

        // Create ephemeral key
        let secp = Secp256k1::new();
        let (ephemeral_secret, _) = secp.generate_keypair(&mut OsRng);

        // Create outputs with k=0, 1
        let (out0, ephemeral, _) = ghost_id
            .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 0)
            .unwrap();
        let (out1, _, _) = ghost_id
            .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 1)
            .unwrap();

        // SHUFFLE: Put them in reverse order (simulating Wraith shuffle)
        let outputs = vec![
            (out1, Some(200_000)), // k=1 is first in the vec
            (out0, Some(100_000)), // k=0 is second in the vec
        ];

        let detector = PaymentDetector::new(&keys);
        let found = detector.scan_transaction(&ephemeral, &outputs);

        // Both should still be found despite shuffle
        assert_eq!(found.len(), 2);
        assert!(found.iter().any(|p| p.k == 0 && p.amount == Some(100_000)));
        assert!(found.iter().any(|p| p.k == 1 && p.amount == Some(200_000)));
    }

    #[test]
    fn test_scan_respects_max_k() {
        let keys = GhostKeys::generate();
        let ghost_id = keys.ghost_id();

        // Create ephemeral key
        let secp = Secp256k1::new();
        let (ephemeral_secret, _) = secp.generate_keypair(&mut OsRng);

        // Create output with k=15 (higher than default max_k=10)
        let (out15, ephemeral, _) = ghost_id
            .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 15)
            .unwrap();

        let outputs = vec![(out15, Some(100_000))];

        // Default detector (max_k=10) should NOT find it
        let detector_default = PaymentDetector::new(&keys);
        let found = detector_default.scan_transaction(&ephemeral, &outputs);
        assert!(found.is_empty(), "Should not find k=15 with max_k=10");

        // Detector with higher max_k SHOULD find it
        let detector_high = PaymentDetector::with_config(&keys, ScanConfig::new(20));
        let found = detector_high.scan_transaction(&ephemeral, &outputs);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].k, 15);
    }

    #[test]
    fn test_scan_recovery() {
        let keys = GhostKeys::generate();
        let ghost_id = keys.ghost_id();

        // Create ephemeral key
        let secp = Secp256k1::new();
        let (ephemeral_secret, _) = secp.generate_keypair(&mut OsRng);

        // Create output with k=500 (missed by default scanning)
        let (out500, ephemeral, _) = ghost_id
            .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 500)
            .unwrap();

        let outputs = vec![(out500, Some(100_000))];

        // Default scan misses it
        let detector_default = PaymentDetector::new(&keys);
        let found = detector_default.scan_transaction(&ephemeral, &outputs);
        assert!(found.is_empty());

        // Recovery scan finds it
        let detector_recovery = PaymentDetector::with_config(&keys, ScanConfig::recovery());
        let found = detector_recovery.scan_transaction(&ephemeral, &outputs);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].k, 500);
    }

    #[test]
    fn test_scan_not_ours() {
        let keys = GhostKeys::generate();
        let other_keys = GhostKeys::generate();

        // Payment to someone else using v2
        let (output_pubkey, ephemeral_pubkey, _) = other_keys
            .ghost_id()
            .derive_payment_address_v2_full(0)
            .unwrap();

        // We shouldn't find it
        let detector = PaymentDetector::new(&keys);
        let found = detector.scan_transaction(&ephemeral_pubkey, &[(output_pubkey, Some(100_000))]);

        assert!(found.is_empty());
    }

    #[test]
    fn test_quick_check() {
        let keys = GhostKeys::generate();
        let ghost_id = keys.ghost_id();

        // Create payment with k=0
        let (output_pubkey, ephemeral_pubkey, _) =
            ghost_id.derive_payment_address_v2_full(0).unwrap();

        let detector = PaymentDetector::new(&keys);

        // Our payment (k=0)
        assert!(detector.quick_check(&ephemeral_pubkey, &output_pubkey));

        // Someone else's
        let secp = Secp256k1::new();
        let (_, random) = secp.generate_keypair(&mut OsRng);
        assert!(!detector.quick_check(&ephemeral_pubkey, &random));
    }

    #[test]
    fn test_quick_check_misses_high_k() {
        let keys = GhostKeys::generate();
        let ghost_id = keys.ghost_id();

        // Create ephemeral key
        let secp = Secp256k1::new();
        let (ephemeral_secret, _) = secp.generate_keypair(&mut OsRng);

        // Create payment with k=5 (quick_check only checks k=0)
        let (output_pubkey, ephemeral_pubkey, _) = ghost_id
            .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 5)
            .unwrap();

        let detector = PaymentDetector::new(&keys);

        // quick_check should return false (it only checks k=0)
        assert!(!detector.quick_check(&ephemeral_pubkey, &output_pubkey));

        // But full scan should find it
        let found = detector.scan_transaction(&ephemeral_pubkey, &[(output_pubkey, Some(100_000))]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].k, 5);
    }

    #[test]
    fn test_batch_scanner() {
        let keys = GhostKeys::generate();
        let ghost_id = keys.ghost_id();

        // Create multiple transactions using v2
        let (out1, eph1, _) = ghost_id.derive_payment_address_v2_full(0).unwrap();
        let (out2, eph2, _) = ghost_id.derive_payment_address_v2_full(0).unwrap();

        let transactions = vec![
            (eph1, vec![(out1, Some(100_000))]),
            (eph2, vec![(out2, Some(200_000))]),
        ];

        let scanner = BatchScanner::new(4);
        let results = scanner.scan_batch(&keys, &transactions);

        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_batch_scanner_with_recovery_config() {
        let keys = GhostKeys::generate();
        let ghost_id = keys.ghost_id();

        // Create ephemeral key
        let secp = Secp256k1::new();
        let (ephemeral_secret, _) = secp.generate_keypair(&mut OsRng);

        // Create output with high k value
        let (out500, ephemeral, _) = ghost_id
            .derive_payment_address_v2_with_ephemeral(&ephemeral_secret, 500)
            .unwrap();

        let transactions = vec![(ephemeral, vec![(out500, Some(100_000))])];

        // Default scanner misses it
        let scanner_default = BatchScanner::new(4);
        let results = scanner_default.scan_batch(&keys, &transactions);
        assert!(results.is_empty());

        // Recovery scanner finds it
        let scanner_recovery = BatchScanner::with_config(4, ScanConfig::recovery());
        let results = scanner_recovery.scan_batch(&keys, &transactions);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1[0].k, 500);
    }
}
