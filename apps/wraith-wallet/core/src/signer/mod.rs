//! Signer abstraction for the wallet.
//!
//! Defines a trait that hides the difference between an in-memory software
//! keystore and a future hardware wallet (Coldcard, Ledger, Trezor, …). All
//! signing-relevant code can hold a `&dyn Signer` and stay agnostic.
//!
//! ## Status (phase 13)
//!
//! 1. [`Signer`] is the per-signature-operation contract: pubkey at path,
//!    Schnorr sign of a 32-byte digest. Object-safe.
//! 2. [`SignerSetup`] is the once-per-wallet contract: get an xpub for
//!    enrolment, ask the device to display an address for verification.
//!    Hardware backings need this; software fakes it.
//! 3. [`SoftwareSigner`] implements both over an unlocked [`Keystore`].
//! 4. [`HardwareSignerStub`] is a placeholder that returns
//!    [`SignerError::Unsupported`] for everything — replaced by real
//!    vendor crates when they land.
//!
//! [`auth::xonly_pubkey_signer`](crate::auth::xonly_pubkey_signer),
//! [`auth::wallet_id_hex_signer`](crate::auth::wallet_id_hex_signer),
//! [`auth::sign_data_signer`](crate::auth::sign_data_signer) are the
//! Signer-aware GSP-auth helpers. The daemon currently calls the
//! keypair-based variants in `auth::*` because the `Keystore` is what
//! it has on hand; the trait is wired and tested so the swap is a
//! local refactor when a hardware vendor lands.
//!
//! ## Adding a hardware vendor
//!
//! 1. Create a crate `wraith-wallet-signer-<vendor>` (e.g.
//!    `wraith-wallet-signer-ledger`) that depends on the vendor's USB SDK
//!    and on `wraith-wallet-core` for the trait definitions.
//! 2. Implement [`Signer`] *and* [`SignerSetup`] on a struct that owns
//!    the device handle. The trait methods translate to APDU calls or
//!    similar. `info().interactive` should return `true` so the GUI
//!    knows to show a "confirm on device" banner.
//! 3. Add an optional dep + a feature flag in
//!    `apps/wraith-wallet/core/Cargo.toml`:
//!    ```toml
//!    [features]
//!    ledger = ["dep:wraith-wallet-signer-ledger"]
//!    [dependencies]
//!    wraith-wallet-signer-ledger = { version = "...", optional = true }
//!    ```
//! 4. Extend the daemon: store a tagged `BackingSigner` enum on the
//!    keystore-or-equivalent, and dispatch `signer_info_for_unlocked`
//!    accordingly. The IPC schema doesn't need to change — the
//!    [`SignerInfo`] -> `SignerInfoIpc` conversion already carries the
//!    vendor kind.
//! 5. Add a `Request::WalletEnrollHardware { vendor }` IPC variant for
//!    first-time enrolment. The daemon calls
//!    `vendor::scan_for_devices()` -> `SignerSetup::get_xpub_at()` to
//!    populate a hardware-backed keystore on disk that stores
//!    only the xpub + vendor metadata.

use bitcoin::secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey};

use crate::keystore::{Keystore, KeystoreError};

/// What the host knows about a signer at runtime — useful for the GUI to render
/// "Hardware (Ledger Nano X)" vs "Software (in-memory)".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerInfo {
    /// `"software"` for the in-memory keystore, vendor identifier (e.g.
    /// `"ledger"`, `"coldcard"`) for hardware.
    pub kind: String,
    /// Free-form human-readable identifier — model name, serial, etc.
    pub label: String,
    /// True if signing requires user approval on a separate device.
    pub interactive: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error(transparent)]
    Keystore(#[from] KeystoreError),
    #[error("secp error: {0}")]
    Secp(String),
    #[error("hardware error: {0}")]
    Hardware(String),
    #[error("operation not supported by this signer: {0}")]
    Unsupported(&'static str),
}

/// Capabilities every wallet signer must provide.
///
/// Object-safe (no generic methods, no `Self` in arg/return positions other
/// than `&self`) so callers can hold `Arc<dyn Signer>` or `&dyn Signer`.
pub trait Signer: Send + Sync {
    /// Static description of this signer (for UI / logs).
    fn info(&self) -> SignerInfo;

    /// 33-byte SEC1 compressed pubkey at the given BIP32 path.
    fn sec1_pubkey_at(&self, path: &str) -> Result<[u8; 33], SignerError>;

    /// 32-byte x-only pubkey at the given BIP32 path (for Schnorr / Taproot).
    fn xonly_pubkey_at(&self, path: &str) -> Result<[u8; 32], SignerError>;

    /// BIP-340 Schnorr-sign a 32-byte message digest with the key at `path`.
    /// Returns the 64-byte signature.
    fn sign_schnorr_at(
        &self,
        path: &str,
        message_digest: &[u8; 32],
    ) -> Result<[u8; 64], SignerError>;
}

/// Setup-time operations that don't fit `Signer` because they happen
/// once per wallet (or once per address verification) rather than per
/// signature.
///
/// A hardware backing's [`SignerSetup::display_address_at`] is what makes
/// "verify your address on the device screen" possible — without it,
/// receive flows on a HW wallet are blind. Software backings implement
/// it as a no-op since there's nothing to display on.
pub trait SignerSetup: Signer {
    /// Get the BIP32 xpub at `path`. Used during wallet enrolment to
    /// register the public side of a hardware-backed wallet without ever
    /// reading the seed.
    fn get_xpub_at(&self, path: &str) -> Result<String, SignerError>;

    /// Ask the device to display the address derived at `path` so the user
    /// can verify it on a trusted screen. Returns once the user confirms
    /// (or rejects) on-device. No-op for software backings — there's no
    /// trusted screen, so the wallet's own UI is already the source of
    /// truth.
    fn display_address_at(&self, path: &str) -> Result<(), SignerError>;
}

/// Software signer backed by an unlocked [`Keystore`].
///
/// Wraps the existing BIP32 derivation + Schnorr signing already in the
/// keystore, exposing them through the [`Signer`] trait. Holds a reference
/// to the keystore so the daemon can drop both together.
pub struct SoftwareSigner<'a> {
    keystore: &'a Keystore,
}

impl<'a> SoftwareSigner<'a> {
    pub fn new(keystore: &'a Keystore) -> Self {
        Self { keystore }
    }
}

impl<'a> Signer for SoftwareSigner<'a> {
    fn info(&self) -> SignerInfo {
        SignerInfo {
            kind: "software".into(),
            label: "in-memory keystore".into(),
            interactive: false,
        }
    }

    fn sec1_pubkey_at(&self, path: &str) -> Result<[u8; 33], SignerError> {
        let xprv = self.keystore.derive_xprv(path)?;
        Ok(xprv.public_key().to_bytes())
    }

    fn xonly_pubkey_at(&self, path: &str) -> Result<[u8; 32], SignerError> {
        let xprv = self.keystore.derive_xprv(path)?;
        let secp = Secp256k1::new();
        let sec1: [u8; 33] = xprv.public_key().to_bytes();
        // Drop parity byte for x-only.
        XOnlyPublicKey::from_slice(&sec1[1..])
            .map(|x| x.serialize())
            .or_else(|_| {
                // Fall back through Keypair for the rare case the parity bit needs flipping.
                let priv_bytes = xprv.to_bytes();
                let priv_slice: &[u8] = &priv_bytes[..];
                let kp = Keypair::from_seckey_slice(&secp, priv_slice)
                    .map_err(|e| SignerError::Secp(e.to_string()))?;
                Ok(kp.x_only_public_key().0.serialize())
            })
    }

    fn sign_schnorr_at(
        &self,
        path: &str,
        message_digest: &[u8; 32],
    ) -> Result<[u8; 64], SignerError> {
        let xprv = self.keystore.derive_xprv(path)?;
        let secp = Secp256k1::new();
        let priv_bytes = xprv.to_bytes();
        let priv_slice: &[u8] = &priv_bytes[..];
        let kp = Keypair::from_seckey_slice(&secp, priv_slice)
            .map_err(|e| SignerError::Secp(e.to_string()))?;
        let msg = Message::from_digest(*message_digest);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.as_ref());
        Ok(out)
    }
}

impl<'a> SignerSetup for SoftwareSigner<'a> {
    fn get_xpub_at(&self, path: &str) -> Result<String, SignerError> {
        let xprv = self.keystore.derive_xprv(path)?;
        // bip32::XPub serialises to a base58-checked string the same way
        // bitcoind / electrum print xpubs, so the value here is comparable
        // across implementations and copy-pasteable into other tooling.
        // Use the mainnet xpub prefix; clients can recompute for testnet
        // / regtest from the BIP32 path if needed.
        Ok(xprv.public_key().to_string(bip32::Prefix::XPUB))
    }

    fn display_address_at(&self, _path: &str) -> Result<(), SignerError> {
        // No-op: software backing has no trusted screen to display on.
        // The wallet's own UI is already the source of truth.
        Ok(())
    }
}

/// Placeholder hardware signer. Currently rejects every operation with
/// [`SignerError::Unsupported`]. Real vendor backends (Coldcard, Ledger,
/// Trezor, …) implement [`Signer`] in their own crates and are wired in
/// behind cargo features when they exist.
pub struct HardwareSignerStub {
    pub vendor: String,
    pub label: String,
}

impl Signer for HardwareSignerStub {
    fn info(&self) -> SignerInfo {
        SignerInfo {
            kind: self.vendor.clone(),
            label: self.label.clone(),
            interactive: true,
        }
    }

    fn sec1_pubkey_at(&self, _: &str) -> Result<[u8; 33], SignerError> {
        Err(SignerError::Unsupported(
            "hardware signer not yet implemented",
        ))
    }

    fn xonly_pubkey_at(&self, _: &str) -> Result<[u8; 32], SignerError> {
        Err(SignerError::Unsupported(
            "hardware signer not yet implemented",
        ))
    }

    fn sign_schnorr_at(&self, _: &str, _: &[u8; 32]) -> Result<[u8; 64], SignerError> {
        Err(SignerError::Unsupported(
            "hardware signer not yet implemented",
        ))
    }
}

impl SignerSetup for HardwareSignerStub {
    fn get_xpub_at(&self, _path: &str) -> Result<String, SignerError> {
        Err(SignerError::Unsupported(
            "hardware signer not yet implemented",
        ))
    }

    fn display_address_at(&self, _path: &str) -> Result<(), SignerError> {
        Err(SignerError::Unsupported(
            "hardware signer not yet implemented",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{schnorr::Signature, Secp256k1, XOnlyPublicKey};

    const VECTOR_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn software_signer_round_trips_sign_verify() {
        let ks = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
        let signer = SoftwareSigner::new(&ks);

        let path = "m/352'/0'/0'/2'";
        let xonly = signer.xonly_pubkey_at(path).unwrap();
        let digest = [0x42u8; 32];
        let sig = signer.sign_schnorr_at(path, &digest).unwrap();

        // Verify with the same secp the GSP server uses.
        let secp = Secp256k1::verification_only();
        let pk = XOnlyPublicKey::from_slice(&xonly).unwrap();
        let sig = Signature::from_slice(&sig).unwrap();
        let msg = Message::from_digest(digest);
        secp.verify_schnorr(&sig, &msg, &pk)
            .expect("software signer's Schnorr signature must verify");
    }

    #[test]
    fn software_signer_pubkey_paths_are_consistent() {
        let ks = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
        let signer = SoftwareSigner::new(&ks);

        let path = "m/86'/531'/0'/0/0";
        let sec1 = signer.sec1_pubkey_at(path).unwrap();
        let xonly = signer.xonly_pubkey_at(path).unwrap();
        // x-only = SEC1 with parity byte stripped (when parity is even) — the
        // signer's `xonly_pubkey_at` always returns the canonical form.
        // What we can always check: same path → bytes 1..33 of SEC1 match xonly
        // when parity is even (0x02), or differ when parity is odd (0x03).
        assert!(sec1[0] == 0x02 || sec1[0] == 0x03);
        if sec1[0] == 0x02 {
            assert_eq!(&sec1[1..], &xonly[..]);
        }
    }

    #[test]
    fn software_signer_info() {
        let ks = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
        let signer = SoftwareSigner::new(&ks);
        let info = signer.info();
        assert_eq!(info.kind, "software");
        assert!(!info.interactive);
    }

    #[test]
    fn hardware_stub_returns_unsupported() {
        let stub = HardwareSignerStub {
            vendor: "ledger".into(),
            label: "Nano X".into(),
        };
        assert_eq!(stub.info().kind, "ledger");
        assert!(stub.info().interactive);
        assert!(matches!(
            stub.sign_schnorr_at("m/0", &[0u8; 32]),
            Err(SignerError::Unsupported(_))
        ));
        assert!(matches!(
            stub.sec1_pubkey_at("m/0"),
            Err(SignerError::Unsupported(_))
        ));
    }

    #[test]
    fn signer_object_safe_via_dyn() {
        // Compile-time check: the trait is object-safe (`dyn Signer` works).
        let ks = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
        let signer = SoftwareSigner::new(&ks);
        let dyn_signer: &dyn Signer = &signer;
        let _ = dyn_signer.info();
    }

    #[test]
    fn software_signer_setup_xpub_round_trips() {
        let ks = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
        let signer = SoftwareSigner::new(&ks);
        let setup: &dyn SignerSetup = &signer;
        let xpub = setup.get_xpub_at("m/86'/531'/0'").unwrap();
        // Standard xpub envelopes start with "xpub" / "tpub" / "ypub" / etc.
        // and are 111 base58 characters. We don't pin the prefix (depends on
        // the keystore's network config) but length + base58-ness are fair.
        assert_eq!(xpub.len(), 111, "BIP32 xpub serialises to 111 b58 chars");
        assert!(
            xpub.chars().all(|c| c.is_ascii_alphanumeric()),
            "xpub must be base58-printable, got {xpub:?}"
        );
    }

    #[test]
    fn software_signer_display_address_is_noop() {
        let ks = Keystore::from_mnemonic(VECTOR_MNEMONIC).unwrap();
        let signer = SoftwareSigner::new(&ks);
        let setup: &dyn SignerSetup = &signer;
        // Software backing has no trusted screen — display_address_at must
        // succeed silently rather than fail with Unsupported. Hardware
        // backings will swap this for a "confirm on device" prompt.
        setup.display_address_at("m/86'/531'/0'/0/0").unwrap();
    }

    #[test]
    fn hardware_stub_setup_returns_unsupported() {
        let stub = HardwareSignerStub {
            vendor: "ledger".into(),
            label: "Nano X".into(),
        };
        let setup: &dyn SignerSetup = &stub;
        assert!(matches!(
            setup.get_xpub_at("m/86'/531'/0'"),
            Err(SignerError::Unsupported(_))
        ));
        assert!(matches!(
            setup.display_address_at("m/86'/531'/0'/0/0"),
            Err(SignerError::Unsupported(_))
        ));
    }
}
