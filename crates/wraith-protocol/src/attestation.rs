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
//| FILE: attestation.rs                                                                                                 |
//|======================================================================================================================|

//! Spend attestations — what makes an instant payment final before it confirms.
//!
//! # The safety property, in one sentence
//!
//! **The quorum signs exactly once per coin, ever.**
//!
//! A hot-lane coin is a 2-of-2 between its owner and its quorum. On ordinary
//! Bitcoin a sender holds their own key and can sign a conflicting transaction
//! whenever they like, which is why accepting an unconfirmed payment is unsafe.
//! Here they physically cannot: any spend needs the quorum too, and the quorum
//! refuses a second signature over an outpoint it has already signed.
//!
//! So a recipient does not hold a promise. They hold a complete, valid
//! transaction plus a signed statement that no conflicting one can exist.
//!
//! # And if the quorum cheats
//!
//! Two attestations over the same outpoint naming different spending
//! transactions are a [`DoubleSignProof`] — self-proving, verifiable by anyone,
//! and requiring no trust in the party presenting it. It is the same shape as
//! the equivocation proofs the mesh already bans on.
//!
//! Note what this does *not* claim: it does not stop a corrupt quorum signing
//! twice. It makes doing so publicly provable and therefore expensive.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{
    schnorr::Signature, Keypair, Message, Secp256k1, Signing, Verification, XOnlyPublicKey,
};
use thiserror::Error;

/// Domain tag. Versioned, so a future change to the binding is a distinct
/// message that old signatures cannot be replayed into.
pub const ATTESTATION_TAG: &str = "wraith/attestation/v1";

/// Something went wrong verifying an attestation or a fraud proof.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AttestationError {
    /// The Schnorr signature did not verify against the quorum key.
    #[error("attestation signature is invalid")]
    BadSignature,

    /// A fraud proof was presented whose two halves do not conflict.
    #[error("not a conflict: both attestations name the same spending transaction")]
    NotAConflict,

    /// A fraud proof was presented over two different outpoints.
    #[error("not a conflict: the attestations cover different outpoints")]
    DifferentOutpoints,

    /// A fraud proof was presented signed by two different quorum keys.
    #[error("not a conflict: the attestations were signed by different keys")]
    DifferentSigners,
}

/// The exact bytes a quorum signs. Fixed-shape, so no field can be shifted into
/// another and produce a colliding message.
///
/// `tag_hash ‖ tag_hash ‖ outpoint_txid ‖ vout_be ‖ spending_txid`
///
/// The doubled tag hash is the BIP-340 tagged-hash convention.
pub fn attestation_message(
    outpoint_txid: &[u8; 32],
    vout: u32,
    spending_txid: &[u8; 32],
) -> Message {
    let tag = sha256::Hash::hash(ATTESTATION_TAG.as_bytes());
    let mut buf = Vec::with_capacity(32 * 2 + 32 + 4 + 32);
    buf.extend_from_slice(tag.as_byte_array());
    buf.extend_from_slice(tag.as_byte_array());
    buf.extend_from_slice(outpoint_txid);
    buf.extend_from_slice(&vout.to_be_bytes());
    buf.extend_from_slice(spending_txid);
    Message::from_digest(sha256::Hash::hash(&buf).to_byte_array())
}

/// A quorum's signed statement that it has spent an outpoint exactly once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpendAttestation {
    /// Txid of the coin being spent.
    pub outpoint_txid: [u8; 32],
    /// Output index of the coin being spent.
    pub vout: u32,
    /// Txid of the transaction the quorum co-signed.
    pub spending_txid: [u8; 32],
    /// The quorum's aggregate key.
    pub quorum_key: XOnlyPublicKey,
    /// Schnorr signature over [`attestation_message`].
    pub signature: Signature,
}

impl SpendAttestation {
    /// Produce an attestation. The caller is responsible for the once-per-coin
    /// rule — this function will happily sign a second one, which is exactly
    /// what [`DoubleSignProof`] exists to catch.
    pub fn create<C: Signing>(
        secp: &Secp256k1<C>,
        keypair: &Keypair,
        outpoint_txid: [u8; 32],
        vout: u32,
        spending_txid: [u8; 32],
    ) -> Self {
        let msg = attestation_message(&outpoint_txid, vout, &spending_txid);
        Self {
            outpoint_txid,
            vout,
            spending_txid,
            quorum_key: keypair.x_only_public_key().0,
            signature: secp.sign_schnorr_no_aux_rand(&msg, keypair),
        }
    }

    /// Verify the signature binds this outpoint to this spending transaction.
    pub fn verify<C: Verification>(&self, secp: &Secp256k1<C>) -> Result<(), AttestationError> {
        let msg = attestation_message(&self.outpoint_txid, self.vout, &self.spending_txid);
        secp.verify_schnorr(&self.signature, &msg, &self.quorum_key)
            .map_err(|_| AttestationError::BadSignature)
    }

    /// True when both attestations cover the same coin.
    pub fn same_outpoint(&self, other: &Self) -> bool {
        self.outpoint_txid == other.outpoint_txid && self.vout == other.vout
    }
}

/// Evidence that a quorum signed the same coin twice.
///
/// Verifiable by anyone, from the two attestations alone. No trust in whoever
/// presents it, and no access to the chain required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoubleSignProof {
    /// First attestation.
    pub a: SpendAttestation,
    /// Second attestation, over the same outpoint but a different transaction.
    pub b: SpendAttestation,
}

impl DoubleSignProof {
    /// Assemble a proof, checking it really is one.
    pub fn new(a: SpendAttestation, b: SpendAttestation) -> Result<Self, AttestationError> {
        if !a.same_outpoint(&b) {
            return Err(AttestationError::DifferentOutpoints);
        }
        if a.quorum_key != b.quorum_key {
            return Err(AttestationError::DifferentSigners);
        }
        if a.spending_txid == b.spending_txid {
            return Err(AttestationError::NotAConflict);
        }
        Ok(Self { a, b })
    }

    /// Verify both halves. A proof that verifies is grounds for a slash.
    pub fn verify<C: Verification>(&self, secp: &Secp256k1<C>) -> Result<(), AttestationError> {
        self.a.verify(secp)?;
        self.b.verify(secp)?;
        if !self.a.same_outpoint(&self.b) {
            return Err(AttestationError::DifferentOutpoints);
        }
        if self.a.quorum_key != self.b.quorum_key {
            return Err(AttestationError::DifferentSigners);
        }
        if self.a.spending_txid == self.b.spending_txid {
            return Err(AttestationError::NotAConflict);
        }
        Ok(())
    }

    /// The key that must be slashed.
    pub fn offender(&self) -> XOnlyPublicKey {
        self.a.quorum_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::SecretKey;

    fn kp(byte: u8) -> Keypair {
        let secp = Secp256k1::new();
        Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[byte; 32]).unwrap())
    }

    #[test]
    fn a_genuine_attestation_verifies() {
        let secp = Secp256k1::new();
        let a = SpendAttestation::create(&secp, &kp(1), [7u8; 32], 3, [9u8; 32]);
        assert_eq!(a.verify(&secp), Ok(()));
    }

    #[test]
    fn tampering_with_any_bound_field_invalidates_it() {
        let secp = Secp256k1::new();
        let good = SpendAttestation::create(&secp, &kp(1), [7u8; 32], 3, [9u8; 32]);

        let mut wrong_vout = good.clone();
        wrong_vout.vout = 4;
        assert_eq!(
            wrong_vout.verify(&secp),
            Err(AttestationError::BadSignature)
        );

        let mut wrong_tx = good.clone();
        wrong_tx.spending_txid = [10u8; 32];
        assert_eq!(wrong_tx.verify(&secp), Err(AttestationError::BadSignature));

        let mut wrong_outpoint = good.clone();
        wrong_outpoint.outpoint_txid = [8u8; 32];
        assert_eq!(
            wrong_outpoint.verify(&secp),
            Err(AttestationError::BadSignature)
        );
    }

    #[test]
    fn signing_the_same_coin_twice_is_a_verifiable_fraud_proof() {
        let secp = Secp256k1::new();
        let quorum = kp(1);
        let honest = SpendAttestation::create(&secp, &quorum, [7u8; 32], 3, [9u8; 32]);
        let cheat = SpendAttestation::create(&secp, &quorum, [7u8; 32], 3, [11u8; 32]);

        let proof = DoubleSignProof::new(honest, cheat).expect("this is a conflict");
        assert_eq!(proof.verify(&secp), Ok(()));
        assert_eq!(proof.offender(), quorum.x_only_public_key().0);
    }

    #[test]
    fn honest_behaviour_cannot_be_dressed_up_as_fraud() {
        let secp = Secp256k1::new();
        let quorum = kp(1);

        // Same coin, same transaction — a re-issued attestation, not a conflict.
        let a = SpendAttestation::create(&secp, &quorum, [7u8; 32], 3, [9u8; 32]);
        let b = SpendAttestation::create(&secp, &quorum, [7u8; 32], 3, [9u8; 32]);
        assert_eq!(
            DoubleSignProof::new(a, b),
            Err(AttestationError::NotAConflict)
        );

        // Two different coins — signing both is the entire job.
        let c = SpendAttestation::create(&secp, &quorum, [7u8; 32], 3, [9u8; 32]);
        let d = SpendAttestation::create(&secp, &quorum, [7u8; 32], 4, [11u8; 32]);
        assert_eq!(
            DoubleSignProof::new(c, d),
            Err(AttestationError::DifferentOutpoints)
        );

        // Two different quorums — neither equivocated.
        let e = SpendAttestation::create(&secp, &kp(1), [7u8; 32], 3, [9u8; 32]);
        let f = SpendAttestation::create(&secp, &kp(2), [7u8; 32], 3, [11u8; 32]);
        assert_eq!(
            DoubleSignProof::new(e, f),
            Err(AttestationError::DifferentSigners)
        );
    }

    #[test]
    fn a_forged_half_cannot_slash_an_innocent_quorum() {
        let secp = Secp256k1::new();
        let victim = kp(1);
        let real = SpendAttestation::create(&secp, &victim, [7u8; 32], 3, [9u8; 32]);

        // Attacker fabricates a second "attestation" with the victim's key.
        let attacker = kp(2);
        let mut forged = SpendAttestation::create(&secp, &attacker, [7u8; 32], 3, [11u8; 32]);
        forged.quorum_key = victim.x_only_public_key().0;

        let proof = DoubleSignProof::new(real, forged).expect("shape looks like a conflict");
        assert_eq!(
            proof.verify(&secp),
            Err(AttestationError::BadSignature),
            "a proof must not verify unless BOTH halves were really signed"
        );
    }

    #[test]
    fn the_domain_tag_prevents_cross_protocol_replay() {
        // The same outpoint and txid under a different tag is a different digest,
        // so an attestation signature can never be replayed as an ownership proof
        // or a transaction sighash.
        let m = attestation_message(&[7u8; 32], 3, &[9u8; 32]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&[7u8; 32]);
        buf.extend_from_slice(&3u32.to_be_bytes());
        buf.extend_from_slice(&[9u8; 32]);
        let untagged = Message::from_digest(sha256::Hash::hash(&buf).to_byte_array());
        assert_ne!(m, untagged, "the tag must change the digest");
    }
}
