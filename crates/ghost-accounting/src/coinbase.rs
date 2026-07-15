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
//| FILE: coinbase.rs                                                                                                    |
//|======================================================================================================================|

//! Coinbase transaction construction

use bitcoin::{
    absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Witness,
};
use ghost_common::constants::MAX_COINBASE_OUTPUTS;
use ghost_common::error::{GhostError, GhostResult};
use ghost_common::types::PayoutEntry;

/// Coinbase transaction builder
#[derive(Debug, Clone)]
pub struct CoinbaseBuilder {
    /// Block height
    block_height: u64,
    /// Block hash (for BIP34)
    block_hash: Option<[u8; 32]>,
    /// Extra nonce space
    extra_nonce_size: usize,
    /// Pool identifier in coinbase
    pool_tag: Vec<u8>,
}

impl CoinbaseBuilder {
    /// Create a new coinbase builder
    pub fn new(block_height: u64) -> Self {
        Self {
            block_height,
            block_hash: None,
            extra_nonce_size: 8,
            pool_tag: b"Ghost".to_vec(),
        }
    }

    /// Set block hash
    pub fn with_block_hash(mut self, hash: [u8; 32]) -> Self {
        self.block_hash = Some(hash);
        self
    }

    /// Set extra nonce size
    pub fn with_extra_nonce_size(mut self, size: usize) -> Self {
        self.extra_nonce_size = size;
        self
    }

    /// Set pool tag
    pub fn with_pool_tag(mut self, tag: impl Into<Vec<u8>>) -> Self {
        self.pool_tag = tag.into();
        self
    }

    /// Build coinbase script sig (BIP34 compliant)
    fn build_script_sig(&self) -> ScriptBuf {
        // BIP34: the height is pushed as a minimally-encoded CScriptNum — a SIGNED
        // little-endian integer. If the most-significant byte has its high bit set, a zero
        // sign byte must be appended, or the height decodes as NEGATIVE and the block is
        // rejected with `bad-cb-height`.
        //
        // Heights where this bites: 128..=255, 32768..=65535, 8_388_608.. — i.e. whenever the
        // top byte of the minimal encoding is >= 0x80. Mainnet is unaffected at present
        // (957_896 -> [0x48, 0x9D, 0x0E], top byte 0x0E) and this produces byte-identical
        // output for every height below 8_388_608, so the fix is inert on the live chain —
        // but a regtest/signet chain in the 128..=255 band produces blocks the node rejects.
        let le = self.block_height.to_le_bytes();
        let len = le
            .iter()
            .rposition(|&b| b != 0)
            .map(|i| i + 1)
            .unwrap_or(1);
        let mut height_bytes = le[..len].to_vec();
        if height_bytes.last().is_some_and(|&b| b & 0x80 != 0) {
            height_bytes.push(0x00);
        }

        let mut script_data = Vec::new();

        // Push height (variable length)
        script_data.push(height_bytes.len() as u8);
        script_data.extend_from_slice(&height_bytes);

        // Extra nonce placeholder
        script_data.extend(vec![0u8; self.extra_nonce_size]);

        // Pool tag
        if !self.pool_tag.is_empty() {
            script_data.extend_from_slice(&self.pool_tag);
        }

        ScriptBuf::from(script_data)
    }

    /// Build coinbase from raw entries
    pub fn build_from_entries(&self, entries: &[PayoutEntry]) -> GhostResult<Transaction> {
        if entries.len() > MAX_COINBASE_OUTPUTS {
            return Err(GhostError::TooManyOutputs {
                count: entries.len(),
                limit: MAX_COINBASE_OUTPUTS,
            });
        }

        let mut outputs = Vec::new();

        for entry in entries {
            let script = self.script_from_address(&entry.address)?;
            outputs.push(TxOut {
                value: Amount::from_sat(entry.amount),
                script_pubkey: script,
            });
        }

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: self.build_script_sig(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: outputs,
        };

        Ok(tx)
    }

    /// Convert address bytes to script pubkey
    ///
    /// Address can be:
    /// - Raw script pubkey bytes (for internal use)
    /// - Bech32/Bech32m encoded address string (P2WPKH, P2WSH only - P2TR rejected)
    ///
    /// # Quantum Safety
    ///
    /// P2TR addresses (bc1p...) are rejected for quantum safety.
    /// P2TR exposes public keys on-chain, making them vulnerable to
    /// quantum computer attacks while funds are locked.
    fn script_from_address(&self, address: &[u8]) -> GhostResult<ScriptBuf> {
        // First, try to parse as UTF-8 address string
        if let Ok(addr_str) = std::str::from_utf8(address) {
            // QUANTUM SAFETY: Reject P2TR addresses
            if addr_str.starts_with("bc1p")
                || addr_str.starts_with("tb1p")
                || addr_str.starts_with("bcrt1p")
            {
                return Err(GhostError::QuantumUnsafe(
                    "P2TR addresses (bc1p...) are quantum-vulnerable. Use P2WPKH (bc1q...) instead.".into()
                ));
            }

            // Try to parse as Bitcoin address
            if let Ok(addr) =
                addr_str.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            {
                // Return the script pubkey without network validation
                // (validation happens at transaction broadcast time)
                return Ok(addr.assume_checked().script_pubkey());
            }
        }

        // If raw script pubkey bytes, check for P2TR format
        // P2TR: 34 bytes, starts with OP_1 (0x51) + PUSH32 (0x20)
        if address.len() == 34 && address[0] == 0x51 && address[1] == 0x20 {
            return Err(GhostError::QuantumUnsafe(
                "P2TR script pubkeys are quantum-vulnerable. Use P2WSH instead.".into(),
            ));
        }

        // Defense-in-depth: reject oversized raw scripts
        // P2WSH (34 bytes) is the largest standard non-OP_RETURN scriptPubKey
        if address.len() > 34 {
            return Err(GhostError::InvalidInput(format!(
                "Raw script pubkey too large: {} bytes (max 34)",
                address.len()
            )));
        }

        Ok(ScriptBuf::from(address.to_vec()))
    }

    /// Calculate coinbase commitment for merkle root
    pub fn calculate_commitment(tx: &Transaction) -> [u8; 32] {
        use bitcoin::hashes::{sha256d, Hash};

        let serialized = bitcoin::consensus::serialize(tx);
        let hash = sha256d::Hash::hash(&serialized);
        hash.to_byte_array()
    }
}

/// Coinbase output allocation
#[derive(Debug, Clone)]
pub struct CoinbaseAllocation {
    /// Treasury output
    pub treasury: Option<(Vec<u8>, u64)>,
    /// TX fees output (to block builder)
    pub tx_fees: Option<(Vec<u8>, u64)>,
    /// Node reward outputs
    pub node_rewards: Vec<(Vec<u8>, u64)>,
    /// Miner outputs
    pub miners: Vec<(Vec<u8>, u64)>,
}

impl CoinbaseAllocation {
    /// Total output count
    pub fn output_count(&self) -> usize {
        let mut count = 0;
        if self.treasury.is_some() {
            count += 1;
        }
        if self.tx_fees.is_some() {
            count += 1;
        }
        count += self.node_rewards.len();
        count += self.miners.len();
        count
    }

    /// Total amount
    pub fn total_amount(&self) -> u64 {
        let mut total = 0u64;
        if let Some((_, amt)) = &self.treasury {
            total += amt;
        }
        if let Some((_, amt)) = &self.tx_fees {
            total += amt;
        }
        total += self.node_rewards.iter().map(|(_, amt)| amt).sum::<u64>();
        total += self.miners.iter().map(|(_, amt)| amt).sum::<u64>();
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP34 encodes the height as a CScriptNum — a SIGNED little-endian integer. When the
    /// most-significant byte has its high bit set, a zero sign byte is required, or the height
    /// decodes as negative and the node rejects the block with `bad-cb-height`.
    ///
    /// This was a live bug: a regtest chain at height 203 (0xCB) produced blocks ghostd
    /// refused. Mainnet is unaffected only because current heights encode with a top byte
    /// below 0x80 — it would have broken at height 8_388_608.
    #[test]
    fn bip34_height_is_a_signed_scriptnum() {
        // Reads the pushed height back out of the scriptSig: [len][height bytes...]
        fn pushed_height(height: u64) -> Vec<u8> {
            let script = CoinbaseBuilder::new(height).build_script_sig();
            let bytes = script.as_bytes();
            let len = bytes[0] as usize;
            bytes[1..1 + len].to_vec()
        }

        // High bit clear — no sign byte needed.
        assert_eq!(pushed_height(102), vec![0x66]);
        assert_eq!(pushed_height(127), vec![0x7f]);
        // Mainnet today: top byte 0x0E, unchanged by the fix.
        assert_eq!(pushed_height(957_896), vec![0xc8, 0x9d, 0x0e]);

        // High bit SET — a zero sign byte must be appended, or these read as negative.
        assert_eq!(pushed_height(128), vec![0x80, 0x00]);
        assert_eq!(pushed_height(203), vec![0xcb, 0x00]);
        assert_eq!(pushed_height(255), vec![0xff, 0x00]);
        assert_eq!(pushed_height(32_768), vec![0x00, 0x80, 0x00]);
        // The height mainnet would have broken at.
        assert_eq!(pushed_height(8_388_608), vec![0x00, 0x00, 0x80, 0x00]);

        // No encoding may ever end in a byte with the high bit set.
        for h in [1u64, 127, 128, 203, 255, 256, 32_768, 946_743, 957_896, 8_388_608] {
            let last = *pushed_height(h).last().expect("non-empty height push");
            assert_eq!(
                last & 0x80,
                0,
                "height {h} encodes as a negative CScriptNum — the node will reject the block"
            );
        }
    }

    #[test]
    fn test_coinbase_builder() {
        let builder = CoinbaseBuilder::new(100)
            .with_pool_tag(b"TestPool")
            .with_extra_nonce_size(8);

        let entries = vec![
            PayoutEntry {
                address: vec![0x00; 25], // P2PKH-like
                amount: 100_000,
                recipient_id: [0u8; 32],
                payout_type: ghost_common::types::PayoutType::Treasury,
            },
            PayoutEntry {
                address: vec![0x00; 25],
                amount: 200_000,
                recipient_id: [1u8; 32],
                payout_type: ghost_common::types::PayoutType::Mining,
            },
        ];

        let tx = builder.build_from_entries(&entries).unwrap();

        assert_eq!(tx.input.len(), 1);
        assert!(tx.input[0].previous_output.is_null());
        assert_eq!(tx.output.len(), 2);
    }

    #[test]
    fn test_output_limit() {
        let builder = CoinbaseBuilder::new(100);

        let entries: Vec<PayoutEntry> = (0..350)
            .map(|i| PayoutEntry {
                address: vec![i as u8; 25],
                amount: 1000,
                recipient_id: [i as u8; 32],
                payout_type: ghost_common::types::PayoutType::Mining,
            })
            .collect();

        let result = builder.build_from_entries(&entries);
        assert!(result.is_err());
    }

    // ── BIP34 height encoding tests ──────────────────────────────────────

    #[test]
    fn test_bip34_height_zero() {
        let builder = CoinbaseBuilder::new(0)
            .with_extra_nonce_size(0)
            .with_pool_tag(Vec::new());
        let script = builder.build_script_sig();
        let bytes = script.as_bytes();
        // Height 0: length byte = 1, then 0x00
        assert_eq!(bytes[0], 1, "height length byte should be 1 for height 0");
        assert_eq!(bytes[1], 0x00, "height 0 should encode as 0x00");
        assert_eq!(
            bytes.len(),
            2,
            "script should be exactly 2 bytes with no extras"
        );
    }

    #[test]
    fn test_bip34_height_500k() {
        let builder = CoinbaseBuilder::new(500_000)
            .with_extra_nonce_size(0)
            .with_pool_tag(Vec::new());
        let script = builder.build_script_sig();
        let bytes = script.as_bytes();
        // 500,000 = 0x07A120 → LE bytes: [0x20, 0xA1, 0x07]
        assert_eq!(bytes[0], 3, "height length byte should be 3 for 500,000");
        assert_eq!(bytes[1], 0x20);
        assert_eq!(bytes[2], 0xA1);
        assert_eq!(bytes[3], 0x07);
        assert_eq!(bytes.len(), 4);
    }

    #[test]
    fn test_bip34_height_max_u32() {
        let height: u64 = u32::MAX as u64; // 4,294,967,295
        let builder = CoinbaseBuilder::new(height)
            .with_extra_nonce_size(0)
            .with_pool_tag(Vec::new());
        let script = builder.build_script_sig();
        let bytes = script.as_bytes();
        // 0xFFFFFFFF → LE bytes [0xFF, 0xFF, 0xFF, 0xFF], whose top byte has the high bit set.
        // BIP34 heights are CScriptNums (signed), so a zero sign byte is required — without it
        // this decodes as a NEGATIVE height and the node rejects the block (`bad-cb-height`).
        // This test previously asserted the unsigned 4-byte form, codifying that bug.
        assert_eq!(
            bytes[0], 5,
            "u32::MAX needs a 5th sign byte to stay a positive CScriptNum"
        );
        assert_eq!(&bytes[1..6], &[0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        assert_eq!(bytes.len(), 6);
    }

    // ── P2TR quantum-safety rejection tests ──────────────────────────────

    #[test]
    fn test_p2tr_address_rejected() {
        let builder = CoinbaseBuilder::new(1);
        // Mainnet P2TR address (bc1p...)
        let addr = b"bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297";
        let result = builder.script_from_address(addr);
        assert!(result.is_err(), "P2TR mainnet address must be rejected");
        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("quantum") || err_str.contains("P2TR"),
            "Error should mention quantum safety or P2TR, got: {err_str}"
        );
    }

    #[test]
    fn test_p2tr_testnet_rejected() {
        let builder = CoinbaseBuilder::new(1);
        // Testnet P2TR address (tb1p...)
        let addr = b"tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c";
        let result = builder.script_from_address(addr);
        assert!(result.is_err(), "P2TR testnet address must be rejected");
        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("quantum") || err_str.contains("P2TR"),
            "Error should mention quantum safety or P2TR, got: {err_str}"
        );
    }

    #[test]
    fn test_p2tr_raw_script_rejected() {
        let builder = CoinbaseBuilder::new(1);
        // Raw witness v1 script: OP_1 (0x51) + PUSH32 (0x20) + 32 bytes
        let mut raw_p2tr = vec![0x51, 0x20];
        raw_p2tr.extend_from_slice(&[0xAB; 32]);
        assert_eq!(raw_p2tr.len(), 34);
        let result = builder.script_from_address(&raw_p2tr);
        assert!(result.is_err(), "Raw P2TR script pubkey must be rejected");
        let err = result.unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("quantum") || err_str.contains("P2TR"),
            "Error should mention quantum safety or P2TR, got: {err_str}"
        );
    }

    // ── CoinbaseAllocation tests ─────────────────────────────────────────

    #[test]
    fn test_allocation_output_count() {
        // Treasury (1) + 2 miners + 1 node = 4 outputs
        let alloc = CoinbaseAllocation {
            treasury: Some((vec![0x00; 25], 50_000)),
            tx_fees: None,
            node_rewards: vec![(vec![0x01; 25], 10_000)],
            miners: vec![(vec![0x02; 25], 20_000), (vec![0x03; 25], 20_000)],
        };
        assert_eq!(alloc.output_count(), 4);
    }

    #[test]
    fn test_allocation_total_amount() {
        let alloc = CoinbaseAllocation {
            treasury: Some((vec![0x00; 25], 50_000)),
            tx_fees: Some((vec![0x04; 25], 5_000)),
            node_rewards: vec![(vec![0x01; 25], 10_000), (vec![0x05; 25], 8_000)],
            miners: vec![(vec![0x02; 25], 20_000), (vec![0x03; 25], 7_000)],
        };
        let expected = 50_000 + 5_000 + 10_000 + 8_000 + 20_000 + 7_000;
        assert_eq!(alloc.total_amount(), expected);
        assert_eq!(alloc.total_amount(), 100_000);
    }
}
