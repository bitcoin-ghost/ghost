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
//| FILE: ghost_id.rs                                                                                                    |
//|======================================================================================================================|

//! Ghost ID - Public identifier for receiving Ghost Pay payments
//!
//! A Ghost ID is the public component shared with senders. It contains
//! the scan pubkey and spend pubkey encoded in bech32 format.

use bech32::{Bech32m, Hrp};
use rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::derivation::{derive_payment_address_v2, derive_shared_secret};
use crate::error::GhostKeyError;
use crate::{GHOST_ID_HRP, GHOST_ID_HRP_REGTEST, GHOST_ID_HRP_SIGNET, GHOST_ID_HRP_TESTNET};
use zeroize::Zeroizing;

/// Network type for Ghost ID encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GhostNetwork {
    /// Bitcoin mainnet
    #[default]
    Mainnet,
    /// Bitcoin testnet
    Testnet,
    /// Bitcoin signet
    Signet,
    /// Bitcoin regtest
    Regtest,
}

impl GhostNetwork {
    /// Get the HRP for this network
    pub fn hrp(&self) -> &'static str {
        match self {
            GhostNetwork::Mainnet => GHOST_ID_HRP,
            GhostNetwork::Testnet => GHOST_ID_HRP_TESTNET,
            GhostNetwork::Signet => GHOST_ID_HRP_SIGNET,
            GhostNetwork::Regtest => GHOST_ID_HRP_REGTEST,
        }
    }

    /// Detect network from HRP string
    pub fn from_hrp(hrp: &str) -> Option<Self> {
        match hrp {
            GHOST_ID_HRP => Some(GhostNetwork::Mainnet),
            GHOST_ID_HRP_TESTNET => Some(GhostNetwork::Testnet),
            GHOST_ID_HRP_SIGNET => Some(GhostNetwork::Signet),
            GHOST_ID_HRP_REGTEST => Some(GhostNetwork::Regtest),
            _ => None,
        }
    }
}

/// Ghost ID - Public identifier for receiving payments
///
/// Contains scan_pubkey and spend_pubkey, encoded as bech32m.
/// Format: ghost1<bech32m_encoded_data>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhostId {
    scan_pubkey: PublicKey,
    spend_pubkey: PublicKey,
}

impl GhostId {
    /// Create a new Ghost ID from public keys
    pub fn new(scan_pubkey: PublicKey, spend_pubkey: PublicKey) -> Self {
        Self {
            scan_pubkey,
            spend_pubkey,
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(
        scan_bytes: &[u8; 33],
        spend_bytes: &[u8; 33],
    ) -> Result<Self, GhostKeyError> {
        let scan_pubkey = PublicKey::from_slice(scan_bytes)?;
        let spend_pubkey = PublicKey::from_slice(spend_bytes)?;
        Ok(Self::new(scan_pubkey, spend_pubkey))
    }

    /// Get the scan public key
    pub fn scan_pubkey(&self) -> &PublicKey {
        &self.scan_pubkey
    }

    /// Get the spend public key
    pub fn spend_pubkey(&self) -> &PublicKey {
        &self.spend_pubkey
    }

    /// Encode as bech32m string (mainnet by default)
    ///
    /// C-9 FIX: Returns Result instead of panicking on encoding failure.
    /// While bech32 encoding of valid public keys should never fail, we
    /// avoid panics for mainnet code to ensure graceful error handling.
    pub fn encode(&self) -> Result<String, GhostKeyError> {
        self.encode_for_network(GhostNetwork::Mainnet)
    }

    /// Encode as bech32m string for a specific network
    ///
    /// SECURITY: Different networks use different HRPs to prevent
    /// accidentally sending to wrong network addresses.
    ///
    /// C-9 FIX: Returns Result instead of panicking. While HRP parsing and
    /// bech32 encoding are theoretically infallible for valid inputs (HRPs are
    /// hardcoded valid constants, public keys serialize to valid bytes), we
    /// return errors to avoid panics in mainnet code.
    ///
    /// LOW-CRYPTO-3 SAFETY: The HRP constants ("ghost", "tghost", "sghost", "rghost")
    /// are compile-time string literals that satisfy all bech32 HRP requirements:
    /// - 1-83 ASCII characters
    /// - Only lowercase letters (a-z) and digits (0-9)
    /// - No leading/trailing whitespace
    ///
    /// Therefore Hrp::parse() cannot fail for these inputs. The error path exists
    /// only for defense-in-depth and to satisfy the type system.
    pub fn encode_for_network(&self, network: GhostNetwork) -> Result<String, GhostKeyError> {
        let hrp_str = network.hrp();
        let hrp = Hrp::parse(hrp_str).map_err(|e| {
            // LOW-CRYPTO-3: This error path is unreachable for our hardcoded HRP constants
            GhostKeyError::Bech32Error(format!(
                "HRP constant '{}' failed to parse (this should never happen): {}",
                hrp_str, e
            ))
        })?;

        // Concatenate scan and spend pubkeys (66 bytes total)
        let mut data = Vec::with_capacity(66);
        data.extend_from_slice(&self.scan_pubkey.serialize());
        data.extend_from_slice(&self.spend_pubkey.serialize());

        // LOW-CRYPTO-3 SAFETY: bech32 encoding cannot fail for valid inputs:
        // - HRP is validated above (always valid for our constants)
        // - Data is 66 bytes of valid public key serialization
        // - Bech32m has no length limit that would reject 66 bytes
        // The error path exists only for defense-in-depth.
        bech32::encode::<Bech32m>(hrp, &data).map_err(|e| {
            GhostKeyError::Bech32Error(format!(
                "Bech32 encoding of valid public keys failed (this should never happen): {}",
                e
            ))
        })
    }

    /// Decode from bech32m string (mainnet only)
    pub fn decode(s: &str) -> Result<Self, GhostKeyError> {
        Self::decode_for_network(s, GhostNetwork::Mainnet)
    }

    /// Decode from bech32m string for a specific network
    ///
    /// SECURITY: Validates that the HRP matches the expected network
    /// to prevent cross-network address confusion.
    pub fn decode_for_network(
        s: &str,
        expected_network: GhostNetwork,
    ) -> Result<Self, GhostKeyError> {
        let (hrp, data) =
            bech32::decode(s).map_err(|e| GhostKeyError::Bech32Error(e.to_string()))?;

        let expected_hrp = expected_network.hrp();
        if hrp.as_str() != expected_hrp {
            return Err(GhostKeyError::InvalidGhostId(format!(
                "Expected HRP '{}' for {:?}, got '{}'",
                expected_hrp,
                expected_network,
                hrp.as_str()
            )));
        }

        if data.len() != 66 {
            return Err(GhostKeyError::InvalidGhostId(format!(
                "Expected 66 bytes, got {}",
                data.len()
            )));
        }

        let scan_bytes: [u8; 33] = data[0..33]
            .try_into()
            .map_err(|_| GhostKeyError::InvalidGhostId("Invalid scan pubkey".to_string()))?;
        let spend_bytes: [u8; 33] = data[33..66]
            .try_into()
            .map_err(|_| GhostKeyError::InvalidGhostId("Invalid spend pubkey".to_string()))?;

        Self::from_bytes(&scan_bytes, &spend_bytes)
    }

    /// Decode from bech32m string and detect network from HRP
    ///
    /// Returns the GhostId and the detected network.
    pub fn decode_any_network(s: &str) -> Result<(Self, GhostNetwork), GhostKeyError> {
        let (hrp, data) =
            bech32::decode(s).map_err(|e| GhostKeyError::Bech32Error(e.to_string()))?;

        let network = GhostNetwork::from_hrp(hrp.as_str()).ok_or_else(|| {
            GhostKeyError::InvalidGhostId(format!(
                "Unknown network HRP '{}'. Valid HRPs: ghost, tghost, sghost, rghost",
                hrp.as_str()
            ))
        })?;

        if data.len() != 66 {
            return Err(GhostKeyError::InvalidGhostId(format!(
                "Expected 66 bytes, got {}",
                data.len()
            )));
        }

        let scan_bytes: [u8; 33] = data[0..33]
            .try_into()
            .map_err(|_| GhostKeyError::InvalidGhostId("Invalid scan pubkey".to_string()))?;
        let spend_bytes: [u8; 33] = data[33..66]
            .try_into()
            .map_err(|_| GhostKeyError::InvalidGhostId("Invalid spend pubkey".to_string()))?;

        let ghost_id = Self::from_bytes(&scan_bytes, &spend_bytes)?;
        Ok((ghost_id, network))
    }

    /// Derive a payment address for sending to this Ghost ID (v2 - position-independent)
    ///
    /// Uses counter-based k instead of output position, safe for shuffled outputs.
    ///
    /// # Arguments
    /// * `k` - Sequential counter for multiple outputs to same recipient (usually 0)
    ///
    /// # Returns
    /// (output_pubkey, ephemeral_pubkey) - The output key and ephemeral key to include in OP_RETURN
    pub fn derive_payment_address_v2(
        &self,
        k: u32,
    ) -> Result<(PublicKey, PublicKey), GhostKeyError> {
        let (output, ephemeral, _tweak) = self.derive_payment_address_v2_full(k)?;
        Ok((output, ephemeral))
    }

    /// Derive payment address with full details (v2 - position-independent)
    ///
    /// # Arguments
    /// * `k` - Sequential counter for multiple outputs to same recipient
    ///
    /// # Returns
    /// (output_pubkey, ephemeral_pubkey, tweak)
    ///
    /// M-17 FIX: Tweak is now returned as Zeroizing wrapper for automatic cleanup
    pub fn derive_payment_address_v2_full(
        &self,
        k: u32,
    ) -> Result<(PublicKey, PublicKey, Zeroizing<[u8; 32]>), GhostKeyError> {
        let secp = Secp256k1::new();

        // Generate ephemeral keypair
        let ephemeral_secret = SecretKey::new(&mut OsRng);
        let ephemeral_pubkey = PublicKey::from_secret_key(&secp, &ephemeral_secret);

        // Compute shared secret
        let shared_secret = derive_shared_secret(&ephemeral_secret, &self.scan_pubkey);

        // Derive output pubkey using v2 (position-independent)
        let (output_pubkey, tweak) =
            derive_payment_address_v2(&self.spend_pubkey, &shared_secret, k)?;

        Ok((output_pubkey, ephemeral_pubkey, tweak))
    }

    /// Derive payment address with a specific ephemeral secret (v2 - for testing/determinism)
    ///
    /// M-17 FIX: Tweak is now returned as Zeroizing wrapper for automatic cleanup
    pub fn derive_payment_address_v2_with_ephemeral(
        &self,
        ephemeral_secret: &SecretKey,
        k: u32,
    ) -> Result<(PublicKey, PublicKey, Zeroizing<[u8; 32]>), GhostKeyError> {
        let secp = Secp256k1::new();
        let ephemeral_pubkey = PublicKey::from_secret_key(&secp, ephemeral_secret);

        // Compute shared secret
        let shared_secret = derive_shared_secret(ephemeral_secret, &self.scan_pubkey);

        // Derive output pubkey using v2
        let (output_pubkey, tweak) =
            derive_payment_address_v2(&self.spend_pubkey, &shared_secret, k)?;

        Ok((output_pubkey, ephemeral_pubkey, tweak))
    }

    /// Export as raw bytes (66 bytes: scan || spend)
    pub fn to_bytes(&self) -> [u8; 66] {
        let mut bytes = [0u8; 66];
        bytes[0..33].copy_from_slice(&self.scan_pubkey.serialize());
        bytes[33..66].copy_from_slice(&self.spend_pubkey.serialize());
        bytes
    }
}

impl fmt::Display for GhostId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // C-9 FIX: encode() now returns Result, handle it gracefully
        // In practice this should never fail for valid GhostId instances
        match self.encode() {
            Ok(encoded) => write!(f, "{}", encoded),
            Err(_) => {
                // L-7: Fallback to truncated hex of the raw pubkey bytes instead
                // of exposing internal error details. This ensures Display never
                // panics and always produces a usable (if degraded) representation.
                let bytes = self.to_bytes();
                write!(f, "ghost-invalid:{}", hex::encode(&bytes[..16]))
            }
        }
    }
}

impl FromStr for GhostId {
    type Err = GhostKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::decode(s)
    }
}

/// Serializable Ghost ID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostIdExport {
    pub encoded: String,
}

impl TryFrom<&GhostId> for GhostIdExport {
    type Error = GhostKeyError;

    /// C-9 FIX: Changed from From to TryFrom since encode() now returns Result.
    fn try_from(id: &GhostId) -> Result<Self, Self::Error> {
        Ok(Self {
            encoded: id.encode()?,
        })
    }
}

impl TryFrom<GhostIdExport> for GhostId {
    type Error = GhostKeyError;

    fn try_from(export: GhostIdExport) -> Result<Self, Self::Error> {
        GhostId::decode(&export.encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode() {
        let secp = Secp256k1::new();
        let (_, scan_pubkey) = secp.generate_keypair(&mut OsRng);
        let (_, spend_pubkey) = secp.generate_keypair(&mut OsRng);

        let id = GhostId::new(scan_pubkey, spend_pubkey);
        let encoded = id
            .encode()
            .expect("C-9: encode should succeed for valid keys");

        assert!(encoded.starts_with("ghost1"));

        let decoded = GhostId::decode(&encoded).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn test_from_str() {
        let secp = Secp256k1::new();
        let (_, scan_pubkey) = secp.generate_keypair(&mut OsRng);
        let (_, spend_pubkey) = secp.generate_keypair(&mut OsRng);

        let id = GhostId::new(scan_pubkey, spend_pubkey);
        let encoded = id.to_string();

        // C-9: Display now gracefully handles encode errors, but for valid keys it should work
        assert!(!encoded.contains("encoding error"));

        let parsed: GhostId = encoded.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_derive_payment_address_v2() {
        let secp = Secp256k1::new();
        let (_, scan_pubkey) = secp.generate_keypair(&mut OsRng);
        let (_, spend_pubkey) = secp.generate_keypair(&mut OsRng);

        let id = GhostId::new(scan_pubkey, spend_pubkey);

        let (output, ephemeral) = id.derive_payment_address_v2(0).unwrap();

        // Output should be different from spend pubkey
        assert_ne!(output, spend_pubkey);

        // Different k values should produce different outputs
        let (output2, _) = id.derive_payment_address_v2(1).unwrap();
        assert_ne!(output, output2);

        // Ephemeral pubkey should be valid
        assert!(ephemeral.serialize().len() == 33);
    }

    #[test]
    fn test_derive_payment_address_v2_multiple_k() {
        let secp = Secp256k1::new();
        let (_, scan_pubkey) = secp.generate_keypair(&mut OsRng);
        let (_, spend_pubkey) = secp.generate_keypair(&mut OsRng);

        let id = GhostId::new(scan_pubkey, spend_pubkey);

        // Generate addresses for k=0, 1, 2
        let (addr0, _) = id.derive_payment_address_v2(0).unwrap();
        let (addr1, _) = id.derive_payment_address_v2(1).unwrap();
        let (addr2, _) = id.derive_payment_address_v2(2).unwrap();

        // All addresses should be unique
        assert_ne!(addr0, addr1);
        assert_ne!(addr1, addr2);
        assert_ne!(addr0, addr2);
    }

    #[test]
    fn test_to_bytes() {
        let secp = Secp256k1::new();
        let (_, scan_pubkey) = secp.generate_keypair(&mut OsRng);
        let (_, spend_pubkey) = secp.generate_keypair(&mut OsRng);

        let id = GhostId::new(scan_pubkey, spend_pubkey);
        let bytes = id.to_bytes();

        let scan_bytes: [u8; 33] = bytes[0..33].try_into().unwrap();
        let spend_bytes: [u8; 33] = bytes[33..66].try_into().unwrap();

        let id2 = GhostId::from_bytes(&scan_bytes, &spend_bytes).unwrap();
        assert_eq!(id, id2);
    }
}
