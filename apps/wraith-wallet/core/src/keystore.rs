//! Encrypted keystore for the wallet's master seed.
//!
//! On-disk format (binary, single file):
//!
//! ```text
//! offset  bytes        meaning
//! ------  -----------  -------
//! 0       4            file version (LE u32, currently 1)
//! 4       32           Argon2id salt
//! 36      12           AES-256-GCM nonce
//! 48      ...          ciphertext (BIP39 mnemonic in UTF-8 + GCM tag)
//! ```
//!
//! KDF: Argon2id (m=64MiB, t=3, p=4) → 32-byte key.
//! AEAD: AES-256-GCM with the derived key.

use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use bip39::{Language, Mnemonic};
use rand::rngs::OsRng;

use crate::user_entropy::{mix_seed_entropy, UserEntropy};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use zeroize::{Zeroize, Zeroizing};

const FILE_VERSION: u32 = 1;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const HEADER_LEN: usize = 4 + SALT_LEN + NONCE_LEN;

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("kdf error: {0}")]
    Kdf(String),
    #[error("decryption failed (wrong passphrase or tampered file)")]
    Decrypt,
    #[error("invalid file format: {0}")]
    Format(String),
    #[error("bip39 error: {0}")]
    Bip39(String),
    #[error("bip32 derivation error: {0}")]
    Bip32(String),
    /// The OS random source could not be read. Fails closed: a wallet is
    /// never created, and a keystore is never written, from randomness we
    /// could not obtain (master spec §6A E-1/E-5).
    #[error("OS random source unavailable: {0}")]
    Rng(String),
}

/// In-memory unlocked wallet seed. Mnemonic is zeroized on drop.
pub struct Keystore {
    mnemonic: Zeroizing<String>,
}

impl Keystore {
    /// Generate a new wallet with a fresh 24-word BIP39 mnemonic.
    /// Returns the keystore and the mnemonic string (display once at create time).
    pub fn create() -> Result<(Self, String), KeystoreError> {
        Self::create_with_user_entropy(None)
    }

    /// Generate a new wallet, optionally mixing in entropy the user produced
    /// themselves (dice, coin flips).
    ///
    /// The OS source is always used and is always in the result. A user
    /// contribution is *mixed*, never substituted, so it can only raise the
    /// floor: an attacker must break the OS source and guess the rolls. A
    /// user who supplies nothing gets exactly the seed they would have got.
    ///
    /// Master spec §6A rule E-1 requires the OS CSPRNG for wallet seeds and
    /// forbids seeded PRNGs. It also once forbade user-supplied entropy
    /// outright; that was amended to permit mixing after the Coldcard
    /// incident, where a single silently-degraded source produced ~40-72 bit
    /// seeds for five years with nothing able to detect it. See
    /// [`crate::user_entropy`].
    pub fn create_with_user_entropy(
        user: Option<&UserEntropy>,
    ) -> Result<(Self, String), KeystoreError> {
        let user_digest = match user {
            Some(u) => Some(u.digest().map_err(|e| KeystoreError::Rng(e.to_string()))?),
            None => None,
        };
        Self::create_with_mixed_digest(user_digest.as_ref())
    }

    /// As [`create_with_user_entropy`](Self::create_with_user_entropy), but
    /// taking the already-reduced digest.
    ///
    /// This is what the daemon uses: the raw roll sequence never leaves the
    /// process that collected it, and the minimum-contribution floor is
    /// enforced there. That split is safe precisely because mixing is
    /// one-directional — a caller supplying a weak or attacker-chosen digest
    /// cannot drag the seed below the OS bytes, so the floor is a matter of
    /// not misleading the user rather than of security.
    pub fn create_with_mixed_digest(
        user_digest: Option<&[u8; 32]>,
    ) -> Result<(Self, String), KeystoreError> {
        let mut os_bytes = [0u8; 32]; // 256 bits → 24 words
        OsRng
            .try_fill_bytes(&mut os_bytes)
            .map_err(|e| KeystoreError::Rng(e.to_string()))?;

        let mut entropy = mix_seed_entropy(&os_bytes, user_digest);
        os_bytes.zeroize();

        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|e| KeystoreError::Bip39(e.to_string()))?;
        let words = mnemonic.to_string();
        entropy.zeroize();
        Ok((
            Self {
                mnemonic: Zeroizing::new(words.clone()),
            },
            words,
        ))
    }

    /// Reconstruct a keystore from an existing BIP39 mnemonic (recovery / import).
    pub fn from_mnemonic(mnemonic: &str) -> Result<Self, KeystoreError> {
        // Validate the mnemonic is well-formed.
        Mnemonic::parse_in(Language::English, mnemonic)
            .map_err(|e| KeystoreError::Bip39(e.to_string()))?;
        Ok(Self {
            mnemonic: Zeroizing::new(mnemonic.to_string()),
        })
    }

    /// Save the keystore to `path`, encrypted with `passphrase`.
    pub fn save(&self, path: &Path, passphrase: &SecretString) -> Result<(), KeystoreError> {
        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng
            .try_fill_bytes(&mut salt)
            .map_err(|e| KeystoreError::Rng(e.to_string()))?;
        OsRng
            .try_fill_bytes(&mut nonce_bytes)
            .map_err(|e| KeystoreError::Rng(e.to_string()))?;

        let key = derive_key(passphrase, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key.0)
            .map_err(|e| KeystoreError::Kdf(format!("cipher init: {e}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, self.mnemonic.as_bytes())
            .map_err(|_| KeystoreError::Decrypt)?;

        let mut buf = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        buf.extend_from_slice(&FILE_VERSION.to_le_bytes());
        buf.extend_from_slice(&salt);
        buf.extend_from_slice(&nonce_bytes);
        buf.extend_from_slice(&ciphertext);

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, &buf)?;
        // Restrict to user only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Load the keystore from `path` and decrypt with `passphrase`.
    pub fn load(path: &Path, passphrase: &SecretString) -> Result<Self, KeystoreError> {
        let bytes = std::fs::read(path)?;
        if bytes.len() < HEADER_LEN {
            return Err(KeystoreError::Format("file shorter than header".into()));
        }
        let version = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if version != FILE_VERSION {
            return Err(KeystoreError::Format(format!(
                "unsupported file version {version}"
            )));
        }
        let salt = &bytes[4..4 + SALT_LEN];
        let nonce_bytes = &bytes[4 + SALT_LEN..HEADER_LEN];
        let ciphertext = &bytes[HEADER_LEN..];

        let key = derive_key(passphrase, salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key.0)
            .map_err(|e| KeystoreError::Kdf(format!("cipher init: {e}")))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| KeystoreError::Decrypt)?;
        let mnemonic_str = String::from_utf8(plaintext)
            .map_err(|_| KeystoreError::Format("non-utf8 plaintext".into()))?;
        Ok(Self {
            mnemonic: Zeroizing::new(mnemonic_str),
        })
    }

    /// Return the mnemonic words. Avoid; use only when the user has explicitly
    /// asked to display the seed (recovery / backup).
    pub fn expose_mnemonic(&self) -> &str {
        self.mnemonic.as_str()
    }

    /// Compute the BIP39 seed (64 bytes). Caller is responsible for not leaking it.
    fn seed_bytes(&self) -> Result<Zeroizing<[u8; 64]>, KeystoreError> {
        let mnemonic = Mnemonic::parse_in(Language::English, self.mnemonic.as_str())
            .map_err(|e| KeystoreError::Bip39(e.to_string()))?;
        // Empty BIP39 passphrase. (BIP39 supports an additional passphrase
        // separate from the keystore-encryption passphrase; we don't use it.)
        Ok(Zeroizing::new(mnemonic.to_seed("")))
    }

    /// Master extended private key derived from the BIP39 seed.
    pub fn master_xprv(&self) -> Result<bip32::XPrv, KeystoreError> {
        let seed = self.seed_bytes()?;
        let seed_slice: &[u8] = &seed[..];
        bip32::XPrv::new(seed_slice).map_err(|e| KeystoreError::Bip32(e.to_string()))
    }

    /// Derive an extended private key at `path` (e.g. `"m/86'/531'/0'/0/0"`).
    pub fn derive_xprv(&self, path: &str) -> Result<bip32::XPrv, KeystoreError> {
        use bip32::DerivationPath;
        use std::str::FromStr;
        let parsed =
            DerivationPath::from_str(path).map_err(|e| KeystoreError::Bip32(e.to_string()))?;
        let mut xprv = self.master_xprv()?;
        for child_number in parsed.into_iter() {
            xprv = xprv
                .derive_child(child_number)
                .map_err(|e| KeystoreError::Bip32(e.to_string()))?;
        }
        Ok(xprv)
    }

    /// Derive `GhostKeys` (BIP-352 scan + spend) for this wallet.
    ///
    /// Paths match `ghost-light-wallet`'s canonical layout so wallets sharing a
    /// seed produce the same Ghost ID:
    ///   - scan:  `m/352'/0'/0'/0'`
    ///   - spend: `m/352'/0'/0'/1'`
    pub fn ghost_keys(&self) -> Result<ghost_keys::GhostKeys, KeystoreError> {
        let scan = self.derive_xprv("m/352'/0'/0'/0'")?;
        let spend = self.derive_xprv("m/352'/0'/0'/1'")?;
        let scan_bytes = scan.to_bytes();
        let spend_bytes = spend.to_bytes();
        ghost_keys::GhostKeys::from_bytes(&scan_bytes, &spend_bytes)
            .map_err(|e| KeystoreError::Bip32(format!("ghost_keys: {e}")))
    }

    /// Master fingerprint — the first 4 bytes of HASH160(master pubkey),
    /// rendered as 8 lowercase hex chars. Used as the leading
    /// element of BIP-380 descriptor key origins:
    /// `[<fingerprint>/<path>]xpub.../<children>` so a coordinator
    /// can prove which seed produced which xpub when assembling
    /// the multisig descriptor.
    pub fn master_fingerprint_hex(&self) -> Result<String, KeystoreError> {
        Ok(hex::encode(self.master_fingerprint_bytes()?))
    }

    /// Master fingerprint as the canonical 4 bytes — what BIP-32
    /// keys it. Same value as the leading element of every
    /// `bip32_derivation` entry a PSBT carries, so we can match
    /// against PSBT-supplied hints without parsing hex.
    pub fn master_fingerprint_bytes(&self) -> Result<[u8; 4], KeystoreError> {
        let master = self.master_xprv()?;
        let fp = master.public_key().fingerprint();
        let slice: &[u8] = fp.as_ref();
        let mut out = [0u8; 4];
        out.copy_from_slice(&slice[..4]);
        Ok(out)
    }

    /// Export the extended public key (xpub/tpub) at `path`,
    /// formatted for use as a BIP-380 descriptor key fragment.
    /// `path` is a BIP-32 derivation string with hardened markers
    /// (e.g. `"m/86'/0'/0'"` for a Bitcoin-mainnet taproot account
    /// suitable for `tr(multi_a(...))` multisig).
    ///
    /// `mainnet` selects the network prefix:
    ///   - `true`  → xpub (mainnet)
    ///   - `false` → tpub (testnet/signet/regtest)
    ///
    /// Returns the bare xpub string and a ready-to-paste descriptor
    /// fragment of the form
    /// `[<fingerprint>/<path-without-leading-m/>]xpub.../<0;1>/*`.
    /// The `<0;1>/*` suffix is the standard external/internal /
    /// address-index template understood by Sparrow / Bitcoin Core
    /// / miniscript. A coordinator drops this fragment into a
    /// wrapper like `wsh(sortedmulti(2, A, B, C))` or
    /// `tr(multi_a(2, A, B, C))` to assemble the multisig.
    pub fn export_xpub(&self, path: &str, mainnet: bool) -> Result<XpubExport, KeystoreError> {
        let xprv = self.derive_xprv(path)?;
        let xpub = xprv.public_key();
        let prefix = if mainnet {
            bip32::Prefix::XPUB
        } else {
            bip32::Prefix::TPUB
        };
        let xpub_str = xpub.to_string(prefix);
        let fp = self.master_fingerprint_hex()?;
        // Strip the leading "m/" or "m" so the path slots into a
        // `[fp/...]` fragment cleanly. Empty path (just "m") means
        // the master xpub itself; emit `[fp]` for that case.
        let trimmed = path.trim();
        let path_for_fragment = trimmed
            .strip_prefix("m/")
            .or_else(|| trimmed.strip_prefix("M/"))
            .unwrap_or(if trimmed == "m" || trimmed == "M" {
                ""
            } else {
                trimmed
            });
        let origin = if path_for_fragment.is_empty() {
            format!("[{fp}]")
        } else {
            format!("[{fp}/{path_for_fragment}]")
        };
        let fragment = format!("{origin}{xpub_str}/<0;1>/*");
        Ok(XpubExport {
            xpub: xpub_str.to_string(),
            master_fingerprint_hex: fp,
            path: path.to_string(),
            descriptor_key_fragment: fragment,
        })
    }
}

/// Result of `Keystore::export_xpub`.
///
/// Field choices match what every multisig coordinator UI asks for:
/// the xpub itself for visual confirmation, the master fingerprint
/// for cross-reference against a hardware wallet's "show
/// fingerprint" screen, the derivation path so the coordinator can
/// re-build the same descriptor, and the pre-assembled descriptor
/// key fragment so power users can skip the manual concatenation.
#[derive(Debug, Clone)]
pub struct XpubExport {
    pub xpub: String,
    pub master_fingerprint_hex: String,
    pub path: String,
    pub descriptor_key_fragment: String,
}

struct KdfKey([u8; KEY_LEN]);
impl Drop for KdfKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

fn derive_key(passphrase: &SecretString, salt: &[u8]) -> Result<KdfKey, KeystoreError> {
    let params = Params::new(64 * 1024, 3, 4, Some(KEY_LEN))
        .map_err(|e| KeystoreError::Kdf(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(passphrase.expose_secret().as_bytes(), salt, &mut key)
        .map_err(|e| KeystoreError::Kdf(e.to_string()))?;
    Ok(KdfKey(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn export_xpub_known_seed_emits_canonical_descriptor_fragment() {
        // The "abandon×11 about" mnemonic is the BIP-39 zero seed —
        // every Bitcoin-tooling test vector uses it, so the xpub at
        // m/86'/0'/0' is a published constant. Asserting the exact
        // string locks in our derivation and serialisation matching
        // Sparrow / Bitcoin Core's output.
        let ks = Keystore::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let exp = ks.export_xpub("m/86'/0'/0'", true).unwrap();
        // BIP-86 test vectors:
        //   master xprv fingerprint = 73c5da0a
        //   m/86'/0'/0' xpub        = xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ
        assert_eq!(exp.master_fingerprint_hex, "73c5da0a");
        assert_eq!(
            exp.xpub,
            "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"
        );
        assert_eq!(
            exp.descriptor_key_fragment,
            "[73c5da0a/86'/0'/0']xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/<0;1>/*"
        );
    }

    #[test]
    fn export_xpub_testnet_uses_tpub_prefix() {
        let ks = Keystore::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let exp = ks.export_xpub("m/48'/1'/0'/2'", false).unwrap();
        assert!(
            exp.xpub.starts_with("tpub"),
            "expected tpub prefix; got {}",
            exp.xpub
        );
        assert!(exp.descriptor_key_fragment.contains("tpub"));
        assert!(exp
            .descriptor_key_fragment
            .starts_with("[73c5da0a/48'/1'/0'/2']"));
    }

    #[test]
    fn export_xpub_master_path_emits_bare_origin() {
        let ks = Keystore::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let exp = ks.export_xpub("m", true).unwrap();
        // Path "m" → just the master xpub — origin should be the
        // bare fingerprint with no path.
        assert!(exp.descriptor_key_fragment.starts_with("[73c5da0a]xpub"));
    }

    #[test]
    fn create_save_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("k.bin");
        let pass = SecretString::new("correct horse battery staple".to_string());

        let (ks, mnemonic) = Keystore::create().unwrap();
        ks.save(&path, &pass).unwrap();

        let ks2 = Keystore::load(&path, &pass).unwrap();
        assert_eq!(ks.expose_mnemonic(), ks2.expose_mnemonic());
        assert_eq!(mnemonic, ks.expose_mnemonic());
        assert_eq!(mnemonic.split_whitespace().count(), 24);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("k.bin");
        let good = SecretString::new("good".to_string());
        let bad = SecretString::new("bad".to_string());

        let (ks, _) = Keystore::create().unwrap();
        ks.save(&path, &good).unwrap();
        match Keystore::load(&path, &bad) {
            Err(KeystoreError::Decrypt) => {}
            Err(other) => panic!("expected Decrypt error, got {other:?}"),
            Ok(_) => panic!("expected Decrypt error, got Ok"),
        }
    }

    #[test]
    fn ghost_keys_round_trip() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let ks = Keystore::from_mnemonic(mnemonic).unwrap();
        let gk1 = ks.ghost_keys().unwrap();
        let gk2 = ks.ghost_keys().unwrap();
        // Deterministic: same seed → same Ghost ID
        assert_eq!(gk1.scan_pubkey(), gk2.scan_pubkey());
        assert_eq!(gk1.spend_pubkey(), gk2.spend_pubkey());
        // Bech32 encoding is non-empty and starts with the expected HRP
        let id_str = gk1
            .ghost_id()
            .encode_for_network(ghost_keys::GhostNetwork::Signet)
            .unwrap();
        assert!(id_str.starts_with("sghost1"), "got {id_str}");
    }

    #[test]
    fn derivation_is_deterministic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let ks1 = Keystore::from_mnemonic(mnemonic).unwrap();
        let ks2 = Keystore::from_mnemonic(mnemonic).unwrap();

        let key1 = ks1.derive_xprv("m/86'/531'/0'/0/0").unwrap();
        let key2 = ks2.derive_xprv("m/86'/531'/0'/0/0").unwrap();
        assert_eq!(key1.to_bytes(), key2.to_bytes());

        let key3 = ks1.derive_xprv("m/86'/531'/0'/0/1").unwrap();
        assert_ne!(key1.to_bytes(), key3.to_bytes());
    }

    #[test]
    fn from_mnemonic_rejects_garbage() {
        match Keystore::from_mnemonic("not a real bip39 sentence") {
            Err(KeystoreError::Bip39(_)) => {}
            Err(other) => panic!("expected Bip39 error, got {other:?}"),
            Ok(_) => panic!("expected Bip39 error, got Ok"),
        }
    }

    #[test]
    fn wrong_version_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("k.bin");
        let pass = SecretString::new("p".to_string());

        let (ks, _) = Keystore::create().unwrap();
        ks.save(&path, &pass).unwrap();

        // Tamper with the version byte.
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[0] = 99;
        std::fs::write(&path, bytes).unwrap();

        match Keystore::load(&path, &pass) {
            Err(KeystoreError::Format(msg)) if msg.contains("unsupported file version") => {}
            Err(other) => panic!("expected Format error, got {other:?}"),
            Ok(_) => panic!("expected Format error, got Ok"),
        }
    }
}

#[cfg(test)]
mod user_entropy_tests {
    use super::*;
    use crate::user_entropy::UserEntropy;

    fn fifty_rolls() -> UserEntropy {
        let mut e = UserEntropy::new();
        for i in 0..50 {
            e.push_die((i % 6 + 1) as u8).unwrap();
        }
        e
    }

    #[test]
    fn a_wallet_can_be_created_with_user_entropy() {
        let (_ks, words) = Keystore::create_with_user_entropy(Some(&fifty_rolls())).unwrap();
        assert_eq!(words.split_whitespace().count(), 24);
    }

    #[test]
    fn identical_rolls_still_produce_different_wallets() {
        // The OS contribution is always mixed in, so a user who rolls the
        // same sequence twice — or copies someone else's — does not land on
        // the same seed. This is the property that makes mixing safe.
        let (_a, first) = Keystore::create_with_user_entropy(Some(&fifty_rolls())).unwrap();
        let (_b, second) = Keystore::create_with_user_entropy(Some(&fifty_rolls())).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn too_little_user_entropy_refuses_rather_than_quietly_accepting() {
        let mut e = UserEntropy::new();
        for _ in 0..5 {
            e.push_die(4).unwrap();
        }
        assert!(Keystore::create_with_user_entropy(Some(&e)).is_err());
    }

    #[test]
    fn supplying_none_is_still_a_full_strength_wallet() {
        let (_ks, words) = Keystore::create_with_user_entropy(None).unwrap();
        assert_eq!(words.split_whitespace().count(), 24);
        let (_ks2, words2) = Keystore::create().unwrap();
        assert_ne!(words, words2);
    }
}
