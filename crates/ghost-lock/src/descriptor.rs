//! A Lock described in public terms, so somebody else can rebuild it.
//!
//! # What an heir actually needs
//!
//! Four public keys and two heights. Nothing secret, nothing from the owner's
//! wallet, no file that has to survive alongside the coins — a piece of paper
//! and their own seed phrase.
//!
//! That works because the MuSig2 aggregates are a deterministic function of
//! the public keys, so a claimant derives them rather than being given them.
//! If they had to be handed over, inheritance would depend on the owner having
//! stored something extra somewhere their heir could find it, which is exactly
//! the condition inheritance exists to survive.
//!
//! # This is not a secret, and it is not nothing
//!
//! A descriptor reveals the Lock's addresses to anyone holding it, so it links
//! the lanes to each other and to whoever it was given to. It cannot move any
//! coin. Treat it as you would an xpub: not a key, but not a thing to publish.

use bitcoin::{Network, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

use crate::error::LockError;
use crate::lane::{Lane, SavingsPolicy};

/// A Lock in public terms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockDescriptor {
    /// Owner's x-only key, hex.
    pub owner_pubkey: String,
    /// Backup device's x-only key, hex.
    pub backup_pubkey: String,
    /// Heir's x-only key, hex.
    pub heir_pubkey: String,
    /// Wraith quorum's x-only key, hex.
    pub quorum_pubkey: String,
    /// Height the Lock was anchored at.
    pub anchor_height: u32,
    /// Absolute height the inheritance leaf matures at.
    pub inherit_height: u32,
}

fn key(label: &str, hexstr: &str) -> Result<XOnlyPublicKey, LockError> {
    use std::str::FromStr;
    XOnlyPublicKey::from_str(hexstr.trim())
        .map_err(|e| LockError::Policy(format!("{label} is not an x-only public key: {e}")))
}

impl LockDescriptor {
    /// The owner's key.
    pub fn owner(&self) -> Result<XOnlyPublicKey, LockError> {
        key("owner_pubkey", &self.owner_pubkey)
    }
    /// The backup device's key.
    pub fn backup(&self) -> Result<XOnlyPublicKey, LockError> {
        key("backup_pubkey", &self.backup_pubkey)
    }
    /// The heir's key.
    pub fn heir(&self) -> Result<XOnlyPublicKey, LockError> {
        key("heir_pubkey", &self.heir_pubkey)
    }
    /// The quorum's key.
    pub fn quorum(&self) -> Result<XOnlyPublicKey, LockError> {
        key("quorum_pubkey", &self.quorum_pubkey)
    }

    /// Rebuild the Savings lane.
    ///
    /// The only lane a claimant needs: backup recovery and inheritance are both
    /// Savings leaves. Spending and Investments have no non-owner claim.
    ///
    /// The aggregate is derived here rather than accepted, for the same reason
    /// the wallet derives it: a supplied aggregate that did not match its parts
    /// would rebuild a different lane, and the only symptom would be a control
    /// block that does not exist.
    pub fn savings_lane(&self, network: Network) -> Result<Lane, LockError> {
        let owner = self.owner()?;
        let backup = self.backup()?;
        let aggregate = crate::key_agg::aggregate(&[owner, backup])?;
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        SavingsPolicy {
            aggregate,
            owner,
            backup,
            heir: self.heir()?,
            inherit_height: self.inherit_height,
        }
        .build(&secp, self.anchor_height, network)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

    fn xo(b: u8) -> XOnlyPublicKey {
        let sk = SecretKey::from_slice(&[b; 32]).unwrap();
        Keypair::from_secret_key(&Secp256k1::new(), &sk)
            .x_only_public_key()
            .0
    }

    fn descriptor() -> LockDescriptor {
        LockDescriptor {
            owner_pubkey: hex::encode(xo(1).serialize()),
            backup_pubkey: hex::encode(xo(2).serialize()),
            heir_pubkey: hex::encode(xo(3).serialize()),
            quorum_pubkey: hex::encode(xo(4).serialize()),
            anchor_height: 900_000,
            inherit_height: 1_000_000,
        }
    }

    /// **The property inheritance depends on.**
    ///
    /// A descriptor built from public keys alone rebuilds the same lane the
    /// owner's wallet built. If it did not, an heir holding the right paper
    /// would derive an address with no coins in it.
    #[test]
    fn a_descriptor_rebuilds_the_owner_s_lane() {
        let d = descriptor();
        let from_descriptor = d.savings_lane(Network::Regtest).unwrap();

        // The same lane, built the way the wallet builds it.
        let owner = xo(1);
        let backup = xo(2);
        let direct = SavingsPolicy {
            aggregate: crate::key_agg::aggregate(&[owner, backup]).unwrap(),
            owner,
            backup,
            heir: xo(3),
            inherit_height: 1_000_000,
        }
        .build(&Secp256k1::verification_only(), 900_000, Network::Regtest)
        .unwrap();

        assert_eq!(from_descriptor.address, direct.address);
    }

    /// It travels as JSON, because it has to reach the heir somehow.
    #[test]
    fn a_descriptor_round_trips() {
        let d = descriptor();
        let wire = serde_json::to_string(&d).unwrap();
        let back: LockDescriptor = serde_json::from_str(&wire).unwrap();
        assert_eq!(back, d);
    }

    /// Which fields an heir must get exactly right, and which they need not.
    ///
    /// `inherit_height` is in the inheritance leaf, so it is part of the
    /// address: a wrong one derives a lane with no coins in it. `anchor_height`
    /// is not — the other two leaves are *relative* timelocks and carry no
    /// height, so the anchor only serves to check that inheritance is in the
    /// future when the Lock is built.
    ///
    /// Worth pinning because the two sit side by side in the descriptor and
    /// look equally load-bearing. They are not, and an heir chasing a mismatch
    /// should know which number to suspect.
    #[test]
    fn inherit_height_is_in_the_address_and_anchor_height_is_not() {
        let base = descriptor().savings_lane(Network::Regtest).unwrap();

        let mut later_anchor = descriptor();
        later_anchor.anchor_height = 900_001;
        assert_eq!(
            base.address,
            later_anchor.savings_lane(Network::Regtest).unwrap().address,
            "the anchor height is a build-time check, not part of the lane"
        );

        let mut later_inherit = descriptor();
        later_inherit.inherit_height = 1_000_001;
        assert_ne!(
            base.address,
            later_inherit
                .savings_lane(Network::Regtest)
                .unwrap()
                .address,
            "the inheritance height is in a leaf, so it is part of the address"
        );
    }

    /// Inheritance must be in the future, and the descriptor says so.
    #[test]
    fn inheritance_before_the_anchor_is_refused() {
        let mut d = descriptor();
        d.inherit_height = d.anchor_height - 1;
        assert!(
            d.savings_lane(Network::Regtest).is_err(),
            "a Lock whose inheritance has already matured is not a Lock"
        );
    }

    #[test]
    fn a_malformed_key_is_named() {
        let mut d = descriptor();
        d.heir_pubkey = "not a key".into();
        let err = d.savings_lane(Network::Regtest).expect_err("must refuse");
        assert!(format!("{err}").contains("heir_pubkey"), "{err}");
    }
}
