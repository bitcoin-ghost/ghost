//! Light wallet — on-chain address derivation, UTXO tracking, send/receive.
//!
//! Phase 2 first slice: receive-address derivation via BIP86 (taproot).
//! UTXO tracking + send flow land in subsequent commits.
//!
//! Derivation path: `m/86'/531'/0'/0/N` where N is the receive-address index.
//! Coin type 531 is Ghost (matches the existing ghost-tap convention).

use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::{Address, Network};

use crate::keystore::{Keystore, KeystoreError};

/// BIP44 coin type for Bitcoin Ghost.
pub const GHOST_COIN_TYPE: u32 = 531;

#[derive(Debug, thiserror::Error)]
pub enum LightError {
    #[error(transparent)]
    Keystore(#[from] KeystoreError),
    #[error("bitcoin: {0}")]
    Bitcoin(String),
}

/// The plain wallet's receive chain: BIP86 account `0'`.
pub fn receive_path(index: u32) -> String {
    format!("m/86'/{}'/0'/0/{}", GHOST_COIN_TYPE, index)
}

/// A Ghost Lock owner key: account `1'`, kept off the plain wallet's account
/// so a Lock coin and a loose coin are never the same coin.
///
/// The Cash lane is a bare key-path output for this key, so an address derived
/// here is a Cash lane address — which is why the ordinary signer has to know
/// about this family. Cash spends with the owner's key alone, and if the
/// signer only walks the receive chain those coins cannot be spent at all.
pub fn lock_owner_path(index: u32) -> String {
    format!("m/86'/{}'/1'/0/{}", GHOST_COIN_TYPE, index)
}

/// Derive a fresh BIP86 (taproot) receive address at index `index`.
pub fn receive_address(
    keystore: &Keystore,
    index: u32,
    network: Network,
) -> Result<Address, LightError> {
    address_at(keystore, &receive_path(index), network)
}

/// The key-path address for a Lock owner key at `index` — i.e. its Cash lane.
pub fn lock_owner_address(
    keystore: &Keystore,
    index: u32,
    network: Network,
) -> Result<Address, LightError> {
    address_at(keystore, &lock_owner_path(index), network)
}

/// The BIP86 key-path address for one derivation path.
fn address_at(keystore: &Keystore, path: &str, network: Network) -> Result<Address, LightError> {
    let xprv = keystore.derive_xprv(path)?;

    // bip32 returns a 33-byte SEC1 compressed pubkey; for taproot we want the
    // 32-byte x-only form (drop the parity prefix byte).
    let pk_bytes = xprv.public_key().to_bytes();
    let internal = XOnlyPublicKey::from_slice(&pk_bytes[1..])
        .map_err(|e| LightError::Bitcoin(format!("xonly: {e}")))?;

    let secp = Secp256k1::verification_only();
    Ok(Address::p2tr(&secp, internal, None, network))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_address_is_deterministic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let ks = Keystore::from_mnemonic(mnemonic).unwrap();

        let a0 = receive_address(&ks, 0, Network::Signet).unwrap();
        let a0_again = receive_address(&ks, 0, Network::Signet).unwrap();
        assert_eq!(a0, a0_again);

        let a1 = receive_address(&ks, 1, Network::Signet).unwrap();
        assert_ne!(a0, a1);
    }

    #[test]
    fn signet_addresses_use_tb1p_prefix() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let ks = Keystore::from_mnemonic(mnemonic).unwrap();
        let addr = receive_address(&ks, 0, Network::Signet).unwrap();
        assert!(addr.to_string().starts_with("tb1p"), "got {addr}");
    }

    #[test]
    fn mainnet_addresses_use_bc1p_prefix() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let ks = Keystore::from_mnemonic(mnemonic).unwrap();
        let addr = receive_address(&ks, 0, Network::Bitcoin).unwrap();
        assert!(addr.to_string().starts_with("bc1p"), "got {addr}");
    }
}
