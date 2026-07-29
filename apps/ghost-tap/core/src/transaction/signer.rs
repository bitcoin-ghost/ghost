//! Transaction signing
//!
//! Handles signing of Ghost transactions using secp256k1.

use super::{SignedTransaction, TransactionError, UnsignedTransaction};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Write a Bitcoin CompactSize/VarInt encoding of `n` into `buf`.
///
/// This matches the encoding used by Bitcoin Core for counts (input count,
/// output count, script lengths) in serialised transactions.
fn write_compact_size(buf: &mut Vec<u8>, n: usize) {
    if n < 0xFD {
        buf.push(n as u8);
    } else if n <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&(n as u64).to_le_bytes());
    }
}

/// Decode a Base58Check address and build the P2PKH scriptPubKey.
///
/// The script is: `OP_DUP OP_HASH160 <20-byte-pubkey-hash> OP_EQUALVERIFY OP_CHECKSIG`
fn address_to_script(address: &str) -> Result<Vec<u8>, TransactionError> {
    let decoded = bs58::decode(address)
        .into_vec()
        .map_err(|e| TransactionError::InvalidTransaction(format!("Bad Base58: {}", e)))?;

    // 1 byte version + 20 bytes hash + 4 bytes checksum = 25
    if decoded.len() != 25 {
        return Err(TransactionError::InvalidTransaction(format!(
            "Address decoded to {} bytes, expected 25",
            decoded.len()
        )));
    }

    // Verify checksum
    let payload = &decoded[..21];
    let checksum = &decoded[21..25];
    let hash = Sha256::digest(Sha256::digest(payload));
    if &hash[..4] != checksum {
        return Err(TransactionError::InvalidTransaction(
            "Address checksum mismatch".into(),
        ));
    }

    let pubkey_hash = &decoded[1..21];

    // Build P2PKH script
    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // Push 20 bytes
    script.extend_from_slice(pubkey_hash);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    Ok(script)
}

/// Build a P2PKH scriptPubKey directly from a compressed public key.
///
/// Performs Hash160 (SHA-256 then RIPEMD-160) on the pubkey bytes and
/// wraps the result in `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG`.
fn pubkey_to_p2pkh_script(pubkey: &PublicKey) -> Vec<u8> {
    use ripemd::Ripemd160;
    let pk_bytes = pubkey.serialize(); // 33 bytes compressed
    let sha = Sha256::digest(pk_bytes);
    let hash160: [u8; 20] = Ripemd160::digest(sha).into();

    let mut script = Vec::with_capacity(25);
    script.push(0x76); // OP_DUP
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // Push 20 bytes
    script.extend_from_slice(&hash160);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xac); // OP_CHECKSIG
    script
}

/// Transaction signer
///
/// Signs transactions using provided private keys.
pub struct TransactionSigner {
    secp: Secp256k1<secp256k1::All>,
}

impl TransactionSigner {
    /// Create a new transaction signer
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::new(),
        }
    }

    /// Sign an unsigned transaction
    ///
    /// # Arguments
    /// * `tx` - The unsigned transaction to sign
    /// * `get_key` - Callback to get the private key for each input's address_index
    ///
    /// # Returns
    /// A signed transaction ready for broadcast
    pub fn sign<F>(
        &self,
        tx: &UnsignedTransaction,
        mut get_key: F,
    ) -> Result<SignedTransaction, TransactionError>
    where
        F: FnMut(u32, u32) -> Result<Zeroizing<[u8; 32]>, TransactionError>,
    {
        // First pass: derive all private keys and public keys so we can
        // build the per-input P2PKH subscripts for sighash computation.
        let mut secret_keys = Vec::with_capacity(tx.inputs.len());
        let mut pubkeys = Vec::with_capacity(tx.inputs.len());
        let mut subscripts = Vec::with_capacity(tx.inputs.len());

        for input in &tx.inputs {
            let privkey_bytes = get_key(input.change, input.address_index)?;
            let secret_key = SecretKey::from_slice(&*privkey_bytes)
                .map_err(|e| TransactionError::SigningFailed(format!("Invalid key: {}", e)))?;
            let pubkey = PublicKey::from_secret_key(&self.secp, &secret_key);
            let script = pubkey_to_p2pkh_script(&pubkey);

            secret_keys.push(secret_key);
            pubkeys.push(pubkey);
            subscripts.push(script);
        }

        // Second pass: for each input, compute the sighash with that
        // input's subscript filled in (all others empty) and sign it.
        let mut signatures = Vec::with_capacity(tx.inputs.len());

        for (input_index, secret_key) in secret_keys.iter().enumerate().take(tx.inputs.len()) {
            let sighash = self.compute_tx_hash(tx, input_index, &subscripts)?;
            let message = Message::from_digest(sighash);
            let signature = self.secp.sign_ecdsa(&message, secret_key);
            signatures.push(signature);
        }

        // Build the signed transaction
        let signed = self.build_signed_tx(tx, &signatures, &pubkeys)?;

        Ok(signed)
    }

    /// Compute the sighash for a specific input using the standard Bitcoin
    /// legacy P2PKH sighash algorithm (SIGHASH_ALL).
    ///
    /// The preimage is:
    /// ```text
    /// version (4 bytes LE)
    /// input_count (compact size)
    /// for each input:
    ///   prev_txid (32 bytes, internal byte order)
    ///   prev_vout (4 bytes LE)
    ///   if this is the input being signed:
    ///     script_length (compact size of subscript)
    ///     subscript (the P2PKH scriptPubKey)
    ///   else:
    ///     0x00 (empty script)
    ///   sequence (4 bytes LE, 0xFFFFFFFF)
    /// output_count (compact size)
    /// for each output:
    ///   value (8 bytes LE)
    ///   script_length (compact size)
    ///   script (P2PKH scriptPubKey)
    /// locktime (4 bytes LE)
    /// sighash_type (4 bytes LE, 0x01000000 for SIGHASH_ALL)
    /// ```
    ///
    /// The result is the double-SHA256 of this preimage.
    fn compute_tx_hash(
        &self,
        tx: &UnsignedTransaction,
        input_index: usize,
        subscripts: &[Vec<u8>],
    ) -> Result<[u8; 32], TransactionError> {
        let mut data = Vec::new();

        // Version (4 bytes LE)
        data.extend_from_slice(&1u32.to_le_bytes());

        // Input count (compact size)
        write_compact_size(&mut data, tx.inputs.len());

        // Inputs
        for (i, input) in tx.inputs.iter().enumerate() {
            // Previous txid (32 bytes, internal byte order)
            let txid_bytes = hex::decode(&input.txid).map_err(|e| {
                TransactionError::InvalidTransaction(format!("Invalid txid: {}", e))
            })?;
            data.extend_from_slice(&txid_bytes);

            // Previous output index (4 bytes LE)
            data.extend_from_slice(&input.vout.to_le_bytes());

            if i == input_index {
                // Include the subscript (previous output's scriptPubKey)
                let subscript = &subscripts[i];
                write_compact_size(&mut data, subscript.len());
                data.extend_from_slice(subscript);
            } else {
                // Empty script for other inputs
                data.push(0x00);
            }

            // Sequence (4 bytes LE, 0xFFFFFFFF)
            data.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        }

        // Output count (compact size)
        write_compact_size(&mut data, tx.outputs.len());

        // Outputs — use P2PKH scriptPubKey
        for output in &tx.outputs {
            // Value (8 bytes LE)
            data.extend_from_slice(&output.amount.to_le_bytes());
            let script = address_to_script(&output.address)?;
            write_compact_size(&mut data, script.len());
            data.extend_from_slice(&script);
        }

        // Locktime (4 bytes LE)
        data.extend_from_slice(&0u32.to_le_bytes());

        // SIGHASH_ALL (4 bytes LE)
        data.extend_from_slice(&1u32.to_le_bytes());

        // Double SHA256
        let hash1 = Sha256::digest(&data);
        let hash2 = Sha256::digest(hash1);

        Ok(hash2.into())
    }

    /// Build the final signed transaction.
    ///
    /// Each input's scriptSig contains the DER-encoded ECDSA signature
    /// (with SIGHASH_ALL appended) followed by the 33-byte compressed
    /// public key. Outputs use proper P2PKH scriptPubKey.
    fn build_signed_tx(
        &self,
        tx: &UnsignedTransaction,
        signatures: &[Signature],
        pubkeys: &[PublicKey],
    ) -> Result<SignedTransaction, TransactionError> {
        let mut raw_tx = Vec::new();

        // Version (4 bytes)
        raw_tx.extend_from_slice(&1u32.to_le_bytes());

        // Number of inputs (compact size)
        write_compact_size(&mut raw_tx, tx.inputs.len());

        // Inputs with signatures + pubkeys
        for ((input, sig), pubkey) in tx.inputs.iter().zip(signatures.iter()).zip(pubkeys.iter()) {
            // Previous txid
            let txid_bytes = hex::decode(&input.txid).map_err(|e| {
                TransactionError::InvalidTransaction(format!("Invalid txid: {}", e))
            })?;
            raw_tx.extend_from_slice(&txid_bytes);

            // Previous output index
            raw_tx.extend_from_slice(&input.vout.to_le_bytes());

            // scriptSig: <sig_len> <DER sig + SIGHASH_ALL> <pubkey_len> <compressed pubkey>
            let sig_der = sig.serialize_der();
            let pk_bytes = pubkey.serialize(); // 33 bytes compressed
            let script_sig_len = 1 + sig_der.len() + 1 + 1 + pk_bytes.len();
            write_compact_size(&mut raw_tx, script_sig_len);
            // Push sig
            raw_tx.push((sig_der.len() + 1) as u8); // +1 for SIGHASH_ALL byte
            raw_tx.extend_from_slice(&sig_der);
            raw_tx.push(0x01); // SIGHASH_ALL
                               // Push pubkey
            raw_tx.push(pk_bytes.len() as u8);
            raw_tx.extend_from_slice(&pk_bytes);

            // Sequence (4 bytes LE, 0xFFFFFFFF)
            raw_tx.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        }

        // Number of outputs (compact size)
        write_compact_size(&mut raw_tx, tx.outputs.len());

        // Outputs with P2PKH scriptPubKey
        for output in &tx.outputs {
            raw_tx.extend_from_slice(&output.amount.to_le_bytes());
            let script = address_to_script(&output.address)?;
            write_compact_size(&mut raw_tx, script.len());
            raw_tx.extend_from_slice(&script);
        }

        // Locktime (4 bytes)
        raw_tx.extend_from_slice(&0u32.to_le_bytes());

        // Compute txid as double-SHA256 of the raw serialised transaction,
        // displayed in reversed byte order (Bitcoin standard).
        //
        // NOTE: This uses the legacy (pre-SegWit) txid calculation which
        // covers the full serialised transaction including scriptSig.
        // Legacy txids are inherently malleable because a third party can
        // re-encode the DER signature or public key push-data without
        // invalidating the signature, producing a different txid for the
        // same economic transaction.  This is acceptable for GhostTap
        // because: (a) the wallet does not chain unconfirmed transactions,
        // and (b) SegWit witness commitment is outside the scope of the
        // current P2PKH signing path.
        let txid_hash = Sha256::digest(Sha256::digest(&raw_tx));
        let txid = hex::encode(txid_hash.iter().rev().copied().collect::<Vec<_>>());

        Ok(SignedTransaction {
            raw_tx: hex::encode(&raw_tx),
            txid,
            size: raw_tx.len(),
            fee: tx.fee,
        })
    }

    /// Sign a message with a private key
    pub fn sign_message(
        &self,
        message: &[u8],
        privkey: &[u8; 32],
    ) -> Result<Vec<u8>, TransactionError> {
        let secret_key = SecretKey::from_slice(privkey)
            .map_err(|e| TransactionError::SigningFailed(format!("Invalid key: {}", e)))?;

        // Hash the message
        let hash = Sha256::digest(message);
        let msg = Message::from_digest(hash.into());

        let signature = self.secp.sign_ecdsa(&msg, &secret_key);
        Ok(signature.serialize_der().to_vec())
    }

    /// Verify a signature
    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        pubkey: &secp256k1::PublicKey,
    ) -> bool {
        let hash = Sha256::digest(message);
        let msg = Message::from_digest(hash.into());

        let sig = match Signature::from_der(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        self.secp.verify_ecdsa(&msg, &sig, pubkey).is_ok()
    }
}

impl Default for TransactionSigner {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify a signed transaction's signatures against the original unsigned
/// transaction.
///
/// Recomputes the per-input sighash from `unsigned_tx`, then parses the
/// signed raw bytes to extract each input's DER signature and compressed
/// public key, and verifies every ECDSA signature.
pub fn verify_transaction(
    signed: &SignedTransaction,
    unsigned: &UnsignedTransaction,
) -> Result<bool, TransactionError> {
    let raw = hex::decode(&signed.raw_tx)
        .map_err(|e| TransactionError::InvalidTransaction(format!("Invalid hex: {}", e)))?;

    if raw.len() < 10 {
        return Err(TransactionError::InvalidTransaction(
            "Transaction too short".into(),
        ));
    }

    let version = u32::from_le_bytes(raw[0..4].try_into().unwrap());
    if version != 1 {
        return Err(TransactionError::InvalidTransaction(format!(
            "Unknown version: {}",
            version
        )));
    }

    let signer = TransactionSigner::new();
    let secp = Secp256k1::verification_only();
    let mut pos = 4;

    let num_inputs = raw[pos] as usize;
    pos += 1;

    if num_inputs != unsigned.inputs.len() {
        return Err(TransactionError::InvalidTransaction(
            "Input count mismatch".into(),
        ));
    }

    // First pass: extract all pubkeys so we can build subscripts for
    // sighash computation.
    let mut input_positions = Vec::with_capacity(num_inputs);
    let mut extracted_sigs = Vec::with_capacity(num_inputs);
    let mut extracted_pks = Vec::with_capacity(num_inputs);

    let mut scan_pos = pos;
    for _ in 0..num_inputs {
        if scan_pos + 36 >= raw.len() {
            return Err(TransactionError::InvalidTransaction(
                "Truncated input".into(),
            ));
        }
        let input_start = scan_pos;
        scan_pos += 36; // txid (32) + vout (4)

        let script_sig_len = raw[scan_pos] as usize;
        scan_pos += 1;
        if scan_pos + script_sig_len > raw.len() {
            return Err(TransactionError::InvalidTransaction(
                "Truncated scriptSig".into(),
            ));
        }

        let script_start = scan_pos;

        // Parse DER sig (+ SIGHASH_ALL byte)
        let sig_push_len = raw[scan_pos] as usize;
        scan_pos += 1;
        if sig_push_len < 2 || scan_pos + sig_push_len > raw.len() {
            return Err(TransactionError::InvalidTransaction("Bad sig push".into()));
        }
        let der_bytes = &raw[scan_pos..scan_pos + sig_push_len - 1];
        scan_pos += sig_push_len;

        // Parse compressed pubkey (33 bytes)
        let pk_push_len = raw[scan_pos] as usize;
        scan_pos += 1;
        if pk_push_len != 33 || scan_pos + pk_push_len > raw.len() {
            return Err(TransactionError::InvalidTransaction(
                "Bad pubkey push".into(),
            ));
        }
        let pk_bytes = &raw[scan_pos..scan_pos + pk_push_len];
        scan_pos += pk_push_len;

        if scan_pos != script_start + script_sig_len {
            return Err(TransactionError::InvalidTransaction(
                "scriptSig length mismatch".into(),
            ));
        }

        // Skip sequence (4 bytes)
        if scan_pos + 4 > raw.len() {
            return Err(TransactionError::InvalidTransaction(
                "Truncated sequence".into(),
            ));
        }
        scan_pos += 4;

        let sig = Signature::from_der(der_bytes)
            .map_err(|_| TransactionError::InvalidTransaction("Invalid DER signature".into()))?;
        let pubkey = PublicKey::from_slice(pk_bytes)
            .map_err(|_| TransactionError::InvalidTransaction("Invalid public key".into()))?;

        input_positions.push(input_start);
        extracted_sigs.push(sig);
        extracted_pks.push(pubkey);
    }

    // Build subscripts from extracted public keys
    let subscripts: Vec<Vec<u8>> = extracted_pks.iter().map(pubkey_to_p2pkh_script).collect();

    // Verify each input's signature against its per-input sighash
    for i in 0..num_inputs {
        let sighash = signer.compute_tx_hash(unsigned, i, &subscripts)?;
        let message = Message::from_digest(sighash);

        if secp
            .verify_ecdsa(&message, &extracted_sigs[i], &extracted_pks[i])
            .is_err()
        {
            return Ok(false);
        }
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{TxInput, TxOutput};
    use crate::wallet::pubkey_to_address;

    fn valid_txid() -> String {
        "0000000000000000000000000000000000000000000000000000000000000001".to_string()
    }

    fn test_privkey() -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = 1; // minimal valid secp256k1 key
        k
    }

    /// Generate a real Base58Check P2PKH address from a private key.
    fn address_for_privkey(privkey: &[u8; 32]) -> String {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(privkey).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        pubkey_to_address(&pk)
    }

    fn test_address() -> String {
        address_for_privkey(&test_privkey())
    }

    fn simple_unsigned_tx() -> UnsignedTransaction {
        UnsignedTransaction {
            inputs: vec![TxInput {
                txid: valid_txid(),
                vout: 0,
                amount: 100000,
                address_index: 0,
                change: 0,
            }],
            outputs: vec![TxOutput {
                address: test_address(),
                amount: 90000,
            }],
            fee: 10000,
        }
    }

    #[test]
    fn test_signer_creation() {
        let signer = TransactionSigner::new();
        assert!(std::mem::size_of_val(&signer) > 0);
    }

    #[test]
    fn test_message_signing() {
        let signer = TransactionSigner::new();
        let privkey = test_privkey();
        let signature = signer.sign_message(b"Hello, Ghost Pay!", &privkey).unwrap();
        assert!(!signature.is_empty());
    }

    #[test]
    fn test_transaction_hash() {
        let signer = TransactionSigner::new();
        let tx = simple_unsigned_tx();

        // Build a subscript from the test key's pubkey for input 0.
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&test_privkey()).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let subscripts = vec![pubkey_to_p2pkh_script(&pk)];

        let hash = signer.compute_tx_hash(&tx, 0, &subscripts).unwrap();
        assert_eq!(hash.len(), 32);

        // Same transaction should produce same hash (deterministic)
        let hash2 = signer.compute_tx_hash(&tx, 0, &subscripts).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_sign_and_verify_message() {
        let signer = TransactionSigner::new();
        let privkey = test_privkey();
        let message = b"Test message for Ghost";

        let sig = signer.sign_message(message, &privkey).unwrap();

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&privkey).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret);

        assert!(signer.verify_signature(message, &sig, &pubkey));
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let signer = TransactionSigner::new();
        let privkey = test_privkey();

        let sig = signer.sign_message(b"correct message", &privkey).unwrap();

        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&privkey).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret);

        assert!(!signer.verify_signature(b"wrong message", &sig, &pubkey));
    }

    #[test]
    fn test_verify_wrong_pubkey_fails() {
        let signer = TransactionSigner::new();
        let privkey = test_privkey();

        let sig = signer.sign_message(b"message", &privkey).unwrap();

        // Different key
        let mut other_key = [0u8; 32];
        other_key[0] = 2;
        let secp = Secp256k1::new();
        let other_secret = SecretKey::from_slice(&other_key).unwrap();
        let other_pubkey = secp256k1::PublicKey::from_secret_key(&secp, &other_secret);

        assert!(!signer.verify_signature(b"message", &sig, &other_pubkey));
    }

    #[test]
    fn test_verify_invalid_signature_fails() {
        let signer = TransactionSigner::new();
        let privkey = test_privkey();
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&privkey).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret);

        assert!(!signer.verify_signature(b"msg", &[0xFF; 10], &pubkey));
    }

    #[test]
    fn test_sign_transaction() {
        let signer = TransactionSigner::new();
        let tx = simple_unsigned_tx();
        let privkey = test_privkey();

        let signed = signer
            .sign(&tx, |_change, _idx| Ok(Zeroizing::new(privkey)))
            .unwrap();

        assert!(!signed.raw_tx.is_empty());
        assert!(!signed.txid.is_empty());
        assert_eq!(signed.txid.len(), 64); // hex-encoded 32 bytes
        assert!(signed.size > 0);
        assert_eq!(signed.fee, 10000);
    }

    #[test]
    fn test_sign_transaction_multiple_inputs() {
        let signer = TransactionSigner::new();
        let tx = UnsignedTransaction {
            inputs: vec![
                TxInput {
                    txid: valid_txid(),
                    vout: 0,
                    amount: 50000,
                    address_index: 0,
                    change: 0,
                },
                TxInput {
                    txid: valid_txid(),
                    vout: 1,
                    amount: 60000,
                    address_index: 1,
                    change: 1,
                },
            ],
            outputs: vec![
                TxOutput {
                    address: test_address(),
                    amount: 80000,
                },
                TxOutput {
                    address: test_address(),
                    amount: 20000,
                },
            ],
            fee: 10000,
        };

        let privkey = test_privkey();
        let signed = signer
            .sign(&tx, |_change, _idx| Ok(Zeroizing::new(privkey)))
            .unwrap();

        assert!(!signed.raw_tx.is_empty());
        assert!(signed.size > 0);
    }

    #[test]
    fn test_sign_invalid_key_fails() {
        let signer = TransactionSigner::new();
        let tx = simple_unsigned_tx();

        let result = signer.sign(&tx, |_change, _idx| {
            Ok(Zeroizing::new([0u8; 32])) // zero key is invalid for secp256k1
        });

        assert!(matches!(result, Err(TransactionError::SigningFailed(_))));
    }

    #[test]
    fn test_sign_key_callback_error_propagates() {
        let signer = TransactionSigner::new();
        let tx = simple_unsigned_tx();

        let result = signer.sign(&tx, |_change, _idx| {
            Err(TransactionError::SigningFailed("key not found".into()))
        });

        assert!(matches!(result, Err(TransactionError::SigningFailed(_))));
    }

    #[test]
    fn test_different_transactions_different_hashes() {
        let signer = TransactionSigner::new();
        let tx1 = simple_unsigned_tx();
        let mut tx2 = simple_unsigned_tx();
        tx2.outputs[0].amount = 80000; // different amount

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&test_privkey()).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let subscripts = vec![pubkey_to_p2pkh_script(&pk)];

        let hash1 = signer.compute_tx_hash(&tx1, 0, &subscripts).unwrap();
        let hash2 = signer.compute_tx_hash(&tx2, 0, &subscripts).unwrap();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_verify_transaction_basic() {
        let signer = TransactionSigner::new();
        let tx = simple_unsigned_tx();
        let privkey = test_privkey();

        let signed = signer
            .sign(&tx, |_change, _idx| Ok(Zeroizing::new(privkey)))
            .unwrap();

        assert!(verify_transaction(&signed, &tx).unwrap());
    }

    #[test]
    fn test_verify_tampered_signature_rejected() {
        let signer = TransactionSigner::new();
        let tx = simple_unsigned_tx();
        let privkey = test_privkey();

        let mut signed = signer
            .sign(&tx, |_change, _idx| Ok(Zeroizing::new(privkey)))
            .unwrap();

        // Tamper with one byte in the signature region of the raw tx
        let mut raw_bytes = hex::decode(&signed.raw_tx).unwrap();
        // The DER sig starts after version(4) + input_count(1) + txid(32) + vout(4) + scriptSig_len(1) + sig_push_len(1) = byte 43
        if raw_bytes.len() > 44 {
            raw_bytes[44] ^= 0xFF; // flip a byte in the DER signature
        }
        signed.raw_tx = hex::encode(&raw_bytes);

        // Should either return Ok(false) or Err (invalid DER)
        // Err is equally acceptable — a tampered signature can fail DER parsing outright.
        if let Ok(valid) = verify_transaction(&signed, &tx) {
            assert!(!valid, "tampered signature must not verify");
        }
    }

    #[test]
    fn test_verify_transaction_too_short() {
        let dummy_unsigned = simple_unsigned_tx();
        let tx = SignedTransaction {
            raw_tx: hex::encode([0u8; 5]),
            txid: "abc".into(),
            size: 5,
            fee: 0,
        };
        assert!(matches!(
            verify_transaction(&tx, &dummy_unsigned),
            Err(TransactionError::InvalidTransaction(_))
        ));
    }

    #[test]
    fn test_verify_transaction_wrong_version() {
        let dummy_unsigned = simple_unsigned_tx();
        let mut raw = Vec::new();
        raw.extend_from_slice(&99u32.to_le_bytes()); // bad version
        raw.extend_from_slice(&[0u8; 10]);
        let tx = SignedTransaction {
            raw_tx: hex::encode(&raw),
            txid: "abc".into(),
            size: raw.len(),
            fee: 0,
        };
        assert!(matches!(
            verify_transaction(&tx, &dummy_unsigned),
            Err(TransactionError::InvalidTransaction(_))
        ));
    }

    #[test]
    fn test_verify_invalid_hex() {
        let dummy_unsigned = simple_unsigned_tx();
        let tx = SignedTransaction {
            raw_tx: "not_valid_hex!!!".into(),
            txid: "abc".into(),
            size: 0,
            fee: 0,
        };
        assert!(verify_transaction(&tx, &dummy_unsigned).is_err());
    }

    #[test]
    fn test_message_signing_deterministic() {
        let signer = TransactionSigner::new();
        let privkey = test_privkey();
        let msg = b"deterministic";

        let sig1 = signer.sign_message(msg, &privkey).unwrap();
        let sig2 = signer.sign_message(msg, &privkey).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_write_compact_size_small() {
        let mut buf = Vec::new();
        write_compact_size(&mut buf, 0);
        assert_eq!(buf, vec![0x00]);

        buf.clear();
        write_compact_size(&mut buf, 252);
        assert_eq!(buf, vec![0xFC]);
    }

    #[test]
    fn test_write_compact_size_medium() {
        let mut buf = Vec::new();
        write_compact_size(&mut buf, 253);
        assert_eq!(buf, vec![0xFD, 0xFD, 0x00]);

        buf.clear();
        write_compact_size(&mut buf, 0xFFFF);
        assert_eq!(buf, vec![0xFD, 0xFF, 0xFF]);
    }

    #[test]
    fn test_write_compact_size_large() {
        let mut buf = Vec::new();
        write_compact_size(&mut buf, 0x10000);
        assert_eq!(buf, vec![0xFE, 0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn test_verify_multi_input_transaction() {
        let signer = TransactionSigner::new();
        let tx = UnsignedTransaction {
            inputs: vec![
                TxInput {
                    txid: valid_txid(),
                    vout: 0,
                    amount: 50000,
                    address_index: 0,
                    change: 0,
                },
                TxInput {
                    txid: valid_txid(),
                    vout: 1,
                    amount: 60000,
                    address_index: 1,
                    change: 1,
                },
            ],
            outputs: vec![
                TxOutput {
                    address: test_address(),
                    amount: 80000,
                },
                TxOutput {
                    address: test_address(),
                    amount: 20000,
                },
            ],
            fee: 10000,
        };

        let privkey = test_privkey();
        let signed = signer
            .sign(&tx, |_change, _idx| Ok(Zeroizing::new(privkey)))
            .unwrap();

        assert!(verify_transaction(&signed, &tx).unwrap());
    }
}
