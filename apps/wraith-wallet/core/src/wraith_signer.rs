//! BIP-341 (Taproot key-path) witness signer for Wraith mix rounds.
//!
//! The wallet runs `WraithSessionClient::prepare_mix`, gets back a
//! `PreparedMix` with the assembled unsigned transaction and the
//! prevout for every input. To sign its own input, the wallet:
//!
//!   1. Walks BIP86 derivation indices `m/86'/531'/0'/0/N` until it
//!      finds one whose derived P2TR scriptPubKey matches
//!      `prepared.prevouts[prepared.input_index].scriptpubkey`.
//!      That's the key the input was received on.
//!
//!   2. Computes the BIP-341 SIGHASH_DEFAULT taproot sighash. This
//!      commits to the prevouts of EVERY input (not just the one
//!      we're signing) — that's why `prepare_mix` had to surface
//!      the full prevout slice.
//!
//!   3. Applies the BIP-341 tap tweak to the key (with no merkle
//!      root, per BIP86 — wallet uses pure key-path spends).
//!
//!   4. Schnorr-signs the sighash with the tweaked key. The witness
//!      for SIGHASH_DEFAULT is just the 64-byte signature — no
//!      appended sighash byte.
//!
//! Out of scope (deferred):
//!   - Non-taproot script types (P2WPKH, P2SH-P2WPKH, …). The light
//!     module only emits BIP86 P2TR addresses, so for v1 the
//!     wallet's mixing UTXOs are always P2TR. Adding P2WPKH means
//!     a parallel BIP84 derivation walk + BIP-143 sighash; future.
//!   - Hardware-wallet signers. The existing `signer::Signer` trait
//!     can sign Schnorr at a path; wiring it through this function
//!     in place of the direct keystore→secret-key conversion is
//!     mechanical, but future.
//!   - Address book / UTXO scanner integration. v1 callers tell us
//!     up-front the BIP86 index they used, OR we scan 0..MAX_SCAN.

use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{Network, ScriptBuf, Transaction, TxOut, Witness};

use crate::keystore::Keystore;
use crate::wraith::PreparedPrevOut;

/// Maximum BIP86 derivation index we'll scan for a matching
/// scriptPubKey when the caller doesn't specify the index up front.
/// Most wallets exhaust the first few indices in practice; 1024 is a
/// generous ceiling without making a wrong-wallet UTXO take a long
/// time to fail.
pub const DEFAULT_SCAN_INDEX_MAX: u32 = 1024;

#[derive(Debug, thiserror::Error)]
pub enum WraithSignerError {
    #[error("keystore: {0}")]
    Keystore(#[from] crate::keystore::KeystoreError),
    #[error("light: {0}")]
    Light(String),
    #[error(
        "no BIP86 key in m/86'/{coin_type}'/0'/0/0..{max} matches the input \
         scriptPubKey {scriptpubkey_hex}; either this UTXO is not from this \
         wallet, or its index is past --scan-max"
    )]
    KeyNotFound {
        scriptpubkey_hex: String,
        coin_type: u32,
        max: u32,
    },
    #[error("input_index {input_index} >= tx.input.len {input_count}")]
    InputIndexOutOfRange {
        input_index: usize,
        input_count: usize,
    },
    #[error(
        "prevouts.len {prevouts_count} != tx.input.len {input_count}; \
         coordinator should ship one prevout per input"
    )]
    PrevoutsCountMismatch {
        prevouts_count: usize,
        input_count: usize,
    },
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("bitcoin: {0}")]
    Bitcoin(String),
    #[error("secp256k1: {0}")]
    Secp(String),
}

/// Sign the wallet's input in a Wraith Lite round transaction, using
/// the BIP86 key whose derived scriptPubKey matches the input's
/// prevout. Returns a `Witness` ready to drop into the tx.
///
/// `scan_max` bounds the BIP86 index search; pass
/// `DEFAULT_SCAN_INDEX_MAX` for the default. If you know the index
/// up front, prefer `sign_taproot_key_path_at_index` to skip the
/// scan.
pub fn sign_taproot_key_path(
    keystore: &Keystore,
    network: Network,
    unsigned_tx: &Transaction,
    input_index: usize,
    prevouts: &[PreparedPrevOut],
    scan_max: u32,
) -> Result<Witness, WraithSignerError> {
    if input_index >= unsigned_tx.input.len() {
        return Err(WraithSignerError::InputIndexOutOfRange {
            input_index,
            input_count: unsigned_tx.input.len(),
        });
    }
    if prevouts.len() != unsigned_tx.input.len() {
        return Err(WraithSignerError::PrevoutsCountMismatch {
            prevouts_count: prevouts.len(),
            input_count: unsigned_tx.input.len(),
        });
    }

    let target_spk_hex = &prevouts[input_index].scriptpubkey_hex;
    let target_spk_bytes = hex::decode(target_spk_hex.trim())?;
    let target_spk = ScriptBuf::from_bytes(target_spk_bytes);

    // Scan BIP86 indices until we find a match. The light module's
    // derivation has to stay in sync with this; if you change the
    // path template here, mirror it in light::receive_address.
    let mut found: Option<u32> = None;
    for idx in 0..=scan_max {
        let derived_addr = crate::light::receive_address(keystore, idx, network)
            .map_err(|e| WraithSignerError::Light(e.to_string()))?;
        if derived_addr.script_pubkey() == target_spk {
            found = Some(idx);
            break;
        }
    }
    let idx = found.ok_or_else(|| WraithSignerError::KeyNotFound {
        scriptpubkey_hex: target_spk_hex.clone(),
        coin_type: crate::light::GHOST_COIN_TYPE,
        max: scan_max,
    })?;

    sign_taproot_key_path_at_index(keystore, network, unsigned_tx, input_index, prevouts, idx)
}

/// Same as `sign_taproot_key_path` but the BIP86 derivation index
/// is supplied by the caller — skips the scan. Use when the wallet's
/// UTXO scanner / address book already knows which key signed a
/// given UTXO.
pub fn sign_taproot_key_path_at_index(
    keystore: &Keystore,
    network: Network,
    unsigned_tx: &Transaction,
    input_index: usize,
    prevouts: &[PreparedPrevOut],
    bip86_index: u32,
) -> Result<Witness, WraithSignerError> {
    if input_index >= unsigned_tx.input.len() {
        return Err(WraithSignerError::InputIndexOutOfRange {
            input_index,
            input_count: unsigned_tx.input.len(),
        });
    }
    if prevouts.len() != unsigned_tx.input.len() {
        return Err(WraithSignerError::PrevoutsCountMismatch {
            prevouts_count: prevouts.len(),
            input_count: unsigned_tx.input.len(),
        });
    }

    // Sanity check: the derived address at this index must match the
    // input's scriptPubKey. Catches off-by-one in caller-supplied
    // indices early.
    let derived_addr = crate::light::receive_address(keystore, bip86_index, network)
        .map_err(|e| WraithSignerError::Light(e.to_string()))?;
    let target_spk_bytes = hex::decode(prevouts[input_index].scriptpubkey_hex.trim())?;
    let target_spk = ScriptBuf::from_bytes(target_spk_bytes);
    if derived_addr.script_pubkey() != target_spk {
        return Err(WraithSignerError::KeyNotFound {
            scriptpubkey_hex: prevouts[input_index].scriptpubkey_hex.clone(),
            coin_type: crate::light::GHOST_COIN_TYPE,
            max: bip86_index,
        });
    }

    // Derive raw secret key for that BIP86 path.
    let path = format!(
        "m/86'/{}'/0'/0/{}",
        crate::light::GHOST_COIN_TYPE,
        bip86_index
    );
    let xprv = keystore.derive_xprv(&path)?;
    let priv_bytes = xprv.private_key().to_bytes();
    let sk = SecretKey::from_slice(&priv_bytes)
        .map_err(|e| WraithSignerError::Secp(format!("from_slice: {e}")))?;

    // Build the Prevouts slice bitcoin::sighash needs.
    let mut prev_txouts: Vec<TxOut> = Vec::with_capacity(prevouts.len());
    for p in prevouts {
        let spk_bytes = hex::decode(p.scriptpubkey_hex.trim())?;
        prev_txouts.push(TxOut {
            value: bitcoin::Amount::from_sat(p.value_sats),
            script_pubkey: ScriptBuf::from_bytes(spk_bytes),
        });
    }
    let prevouts_slice = Prevouts::All(&prev_txouts);

    // Compute BIP-341 SIGHASH_DEFAULT.
    let mut cache = SighashCache::new(unsigned_tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(input_index, &prevouts_slice, TapSighashType::Default)
        .map_err(|e| WraithSignerError::Bitcoin(format!("taproot sighash: {e}")))?;

    // Tap-tweak the key (BIP86: no merkle root) and Schnorr-sign.
    let secp = Secp256k1::new();
    let untweaked = Keypair::from_secret_key(&secp, &sk);
    // bitcoin 0.32: use the convenience `tap_tweak` extension on
    // UntweakedKeypair. The trait lives on bitcoin::key.
    use bitcoin::key::TapTweak;
    let tweaked = untweaked.tap_tweak(&secp, None);
    use bitcoin::hashes::Hash as _;
    let msg = Message::from_digest(*sighash.as_byte_array());
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &tweaked.to_keypair());

    // For BIP-341 SIGHASH_DEFAULT the witness is JUST the 64-byte
    // signature — no sighash byte. Sighash bytes only appended for
    // non-DEFAULT types.
    let mut witness = Witness::new();
    witness.push(sig.as_ref());
    Ok(witness)
}

/// Prove control of the UTXO the wallet is registering, per BIP-322.
///
/// The coordinator refuses a registration without this (#699): everything
/// else it checks establishes what the coin *is*, and none of it
/// establishes whose it is. It verifies the proof against the scriptPubKey
/// the chain reports for the outpoint, so the signature has to come from
/// the key that really controls the coin — which is exactly the key this
/// scans for.
///
/// `challenge` must be `wraith_protocol::ownership_challenge(session_id,
/// txid, vout)`. Returns the signature base64-encoded as the BIP
/// specifies.
///
/// Only BIP86 key-path P2TR is covered, which is every address the light
/// module emits. A vault input spent through a script leaf would need a
/// script-path proof, which neither this nor the `bip322` crate does yet.
pub fn prove_ownership(
    keystore: &Keystore,
    network: Network,
    scriptpubkey_hex: &str,
    challenge: &str,
    scan_max: u32,
) -> Result<String, WraithSignerError> {
    let target_spk = ScriptBuf::from_bytes(hex::decode(scriptpubkey_hex.trim())?);

    let mut found: Option<(u32, bitcoin::Address)> = None;
    for idx in 0..=scan_max {
        let derived = crate::light::receive_address(keystore, idx, network)
            .map_err(|e| WraithSignerError::Light(e.to_string()))?;
        if derived.script_pubkey() == target_spk {
            found = Some((idx, derived));
            break;
        }
    }
    let (idx, address) = found.ok_or_else(|| WraithSignerError::KeyNotFound {
        scriptpubkey_hex: scriptpubkey_hex.to_string(),
        coin_type: crate::light::GHOST_COIN_TYPE,
        max: scan_max,
    })?;

    let path = format!("m/86'/{}'/0'/0/{}", crate::light::GHOST_COIN_TYPE, idx);
    let xprv = keystore.derive_xprv(&path)?;
    let sk = SecretKey::from_slice(&xprv.private_key().to_bytes())
        .map_err(|e| WraithSignerError::Secp(format!("from_slice: {e}")))?;
    // Untweaked: bip322 applies the BIP86 tap tweak itself when it signs
    // a key-path input, so handing it a pre-tweaked key would sign under
    // a key that is tweaked twice and verify against nothing.
    let private_key = bitcoin::PrivateKey::new(sk, network);

    let witness = bip322::sign_simple(&address, challenge.as_bytes(), &[private_key], None)
        .map_err(|e| WraithSignerError::Bitcoin(format!("bip322 sign: {e}")))?;

    use base64::Engine;
    use bitcoin::consensus::Encodable;
    let mut encoded = Vec::new();
    witness
        .consensus_encode(&mut encoded)
        .map_err(|e| WraithSignerError::Bitcoin(format!("witness encode: {e}")))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(encoded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::OutPoint;
    use bitcoin::{Address, ScriptBuf, Sequence, TxIn, TxOut, Witness as TxWitness};

    fn ks() -> Keystore {
        Keystore::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap()
    }

    /// Build a minimal valid-shape unsigned tx with one P2TR input
    /// (whose scriptPubKey we control via `prevout_spk`) and one
    /// dummy output.
    fn build_fixture_tx(prevout_spk: ScriptBuf) -> (Transaction, Vec<PreparedPrevOut>) {
        use bitcoin::hashes::Hash as _;
        let txin = TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0x11; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: TxWitness::new(),
        };
        let dummy_out = TxOut {
            value: bitcoin::Amount::from_sat(99_000),
            script_pubkey: prevout_spk.clone(),
        };
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![txin],
            output: vec![dummy_out],
        };
        let prevouts = vec![PreparedPrevOut {
            scriptpubkey_hex: hex::encode(prevout_spk.as_bytes()),
            value_sats: 100_000,
        }];
        (tx, prevouts)
    }

    #[test]
    fn sign_at_index_zero_produces_64_byte_witness() {
        let keystore = ks();
        let addr_idx0 = crate::light::receive_address(&keystore, 0, Network::Signet).unwrap();
        let spk = addr_idx0.script_pubkey();
        let (tx, prevouts) = build_fixture_tx(spk);
        let witness =
            sign_taproot_key_path_at_index(&keystore, Network::Signet, &tx, 0, &prevouts, 0)
                .expect("sign ok");
        assert_eq!(witness.len(), 1, "key-path witness has 1 stack item");
        let sig = witness.iter().next().expect("sig");
        assert_eq!(sig.len(), 64, "BIP-341 SIGHASH_DEFAULT sig is 64 bytes");
    }

    #[test]
    fn sign_with_scan_finds_the_right_index() {
        let keystore = ks();
        let addr_idx7 = crate::light::receive_address(&keystore, 7, Network::Signet).unwrap();
        let (tx, prevouts) = build_fixture_tx(addr_idx7.script_pubkey());
        let _ = sign_taproot_key_path(&keystore, Network::Signet, &tx, 0, &prevouts, 16)
            .expect("scan finds idx 7 within 16");
    }

    #[test]
    fn sign_returns_key_not_found_when_scriptpubkey_does_not_match_any_index() {
        let keystore = ks();
        // Different mnemonic → different keys → derived addresses
        // won't match.
        let other = Keystore::from_mnemonic(
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )
        .unwrap();
        let stranger_spk = crate::light::receive_address(&other, 0, Network::Signet)
            .unwrap()
            .script_pubkey();
        let (tx, prevouts) = build_fixture_tx(stranger_spk);
        let err = sign_taproot_key_path(&keystore, Network::Signet, &tx, 0, &prevouts, 16)
            .expect_err("should fail");
        match err {
            WraithSignerError::KeyNotFound { .. } => {}
            other => panic!("expected KeyNotFound; got {other:?}"),
        }
    }

    #[test]
    fn sign_verifies_against_secp_schnorr() {
        // Round-trip check: a fresh Schnorr verify against the tweaked
        // pubkey + the sighash we signed must succeed.
        use bitcoin::key::TapTweak;
        use bitcoin::secp256k1::{
            schnorr::Signature as SchnorrSig, Keypair, Message, XOnlyPublicKey,
        };

        let keystore = ks();
        let addr_idx0 = crate::light::receive_address(&keystore, 0, Network::Signet).unwrap();
        let spk = addr_idx0.script_pubkey();
        let (tx, prevouts) = build_fixture_tx(spk.clone());
        let witness =
            sign_taproot_key_path_at_index(&keystore, Network::Signet, &tx, 0, &prevouts, 0)
                .expect("sign ok");
        let sig_bytes: [u8; 64] = witness.iter().next().unwrap().try_into().expect("64 bytes");
        let sig = SchnorrSig::from_slice(&sig_bytes).unwrap();

        // Recompute the sighash + tweaked pubkey and verify.
        let mut prev_txouts: Vec<TxOut> = Vec::with_capacity(prevouts.len());
        for p in &prevouts {
            let spk_bytes = hex::decode(&p.scriptpubkey_hex).unwrap();
            prev_txouts.push(TxOut {
                value: bitcoin::Amount::from_sat(p.value_sats),
                script_pubkey: ScriptBuf::from_bytes(spk_bytes),
            });
        }
        let mut cache = SighashCache::new(&tx);
        let sighash = cache
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&prev_txouts),
                TapSighashType::Default,
            )
            .unwrap();
        use bitcoin::hashes::Hash as _;
        let msg = Message::from_digest(*sighash.as_byte_array());

        let path = format!("m/86'/{}'/0'/0/0", crate::light::GHOST_COIN_TYPE);
        let xprv = keystore.derive_xprv(&path).unwrap();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&xprv.private_key().to_bytes()).unwrap();
        let secp = Secp256k1::new();
        let untweaked = Keypair::from_secret_key(&secp, &sk);
        let tweaked = untweaked.tap_tweak(&secp, None);
        let xonly: XOnlyPublicKey = tweaked.to_keypair().x_only_public_key().0;

        secp.verify_schnorr(&sig, &msg, &xonly).expect("verify ok");
        let _ = Address::p2tr(
            &secp,
            untweaked.x_only_public_key().0,
            None,
            Network::Signet,
        );
    }
}
