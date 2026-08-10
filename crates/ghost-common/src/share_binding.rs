//! Proving a share was mined to the node that claims it.
//!
//! `ShareProof.received_by` is a claim, and `has_valid_received_by_signature` only proves the node
//! *named* in that field signed it — never that it was the node the work was mined to. So a peer
//! can lift a relayed share's header, re-sign it naming itself, and take the credit.
//!
//! Detecting that after the fact would need someone to notice two claims on one share and read an
//! alarm. This binds it instead, so a node decides alone, from data in hand:
//!
//! ```text
//!   header ──sha256d──▶ merkle root ◀──fold── merkle path ◀── coinbase ──▶ node tag
//! ```
//!
//! The coinbase commits to the node (the `GHNT` tag stamped at template build), the merkle path
//! commits the coinbase into the header's merkle root, and the header is what the miner actually
//! hashed. A stolen header is therefore provably someone else's work: re-attributing it needs a
//! different coinbase, which needs re-mining.
//!
//! ## Why a skeleton
//!
//! The coinbase varies between shares only in the extranonce, so carrying the whole thing per share
//! costs kilobytes for bytes of new information — at this pool's payee counts that is ~29 KB a
//! share, an order of magnitude worse than the traffic this programme exists to remove. A skeleton
//! is the invariant part of one job: everything either side of the extranonce, plus the merkle path.
//! Shares reference it by hash and carry only their own extranonce.
//!
//! Skeletons are **content-addressed**, so one fetched from an untrusted peer is verified by
//! rehashing it. No signature, no quorum, no trust.

use sha2::{Digest, Sha256};

/// Everything about a mining job's coinbase that does not change between shares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinbaseSkeleton {
    /// Serialized coinbase up to where the extranonce begins.
    pub coinbase_prefix: Vec<u8>,
    /// Serialized coinbase from where the extranonce ends.
    pub coinbase_suffix: Vec<u8>,
    /// Sibling hashes folding the coinbase txid up to the header's merkle root.
    ///
    /// The coinbase is always the leftmost leaf, so every sibling is on the right and the fold
    /// needs no direction bits.
    pub merkle_path: Vec<[u8; 32]>,
}

impl CoinbaseSkeleton {
    /// Content address: `sha256("CoinbaseSkeleton/v1" ‖ each field, length-prefixed)`.
    ///
    /// Lives here, beside the type, because **two programs must agree on it**: `pool_sv2` stamps
    /// the id onto every share it reports, and `ghost-pool` looks the skeleton up by that id. Two
    /// implementations of a content address is two chances for a share to reference a skeleton
    /// nobody can find.
    ///
    /// Content-addressed rather than keyed by job id so that jobs sharing an invariant part share
    /// one stored copy — which is what makes a ~29 KB outputs blob affordable — and so a skeleton
    /// received from elsewhere is verified by rehashing rather than trusted.
    pub fn id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"CoinbaseSkeleton/v1");
        h.update((self.coinbase_prefix.len() as u32).to_le_bytes());
        h.update(&self.coinbase_prefix);
        h.update((self.coinbase_suffix.len() as u32).to_le_bytes());
        h.update(&self.coinbase_suffix);
        h.update((self.merkle_path.len() as u32).to_le_bytes());
        for node in &self.merkle_path {
            h.update(node);
        }
        h.finalize().into()
    }
}

/// Why a share failed to prove it was mined to the node claiming it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingError {
    /// The header was not 80 bytes.
    MalformedHeader,
    /// The reconstructed coinbase did not fold to the merkle root the header commits to.
    ///
    /// The strong signal: the share was mined against a different coinbase than the one offered,
    /// which is what lifting someone else's header looks like.
    MerkleRootMismatch,
    /// The coinbase carries no node tag.
    NoNodeTag,
    /// The coinbase names a different node than the one claiming the share.
    WrongNode,
}

fn sha256d(bytes: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(bytes);
    Sha256::digest(first).into()
}

impl CoinbaseSkeleton {
    /// Content address: identity is the bytes, so a fetched skeleton is checked by rehashing.
    ///
    /// Domain-tagged and length-prefixed for the usual reason — without lengths, a prefix/suffix
    /// pair could be re-split to produce the same hash for different coinbases.
    pub fn skeleton_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"CoinbaseSkeleton/v1");
        h.update((self.coinbase_prefix.len() as u32).to_le_bytes());
        h.update(&self.coinbase_prefix);
        h.update((self.coinbase_suffix.len() as u32).to_le_bytes());
        h.update(&self.coinbase_suffix);
        h.update((self.merkle_path.len() as u32).to_le_bytes());
        for sibling in &self.merkle_path {
            h.update(sibling);
        }
        let first: [u8; 32] = h.finalize().into();
        Sha256::digest(first).into()
    }

    /// Rebuild the exact coinbase a share was mined against.
    pub fn coinbase_with(&self, extranonce: &[u8]) -> Vec<u8> {
        let mut tx = Vec::with_capacity(
            self.coinbase_prefix.len() + extranonce.len() + self.coinbase_suffix.len(),
        );
        tx.extend_from_slice(&self.coinbase_prefix);
        tx.extend_from_slice(extranonce);
        tx.extend_from_slice(&self.coinbase_suffix);
        tx
    }

    /// Fold a coinbase txid up to the merkle root.
    fn fold_to_root(&self, coinbase_txid: [u8; 32]) -> [u8; 32] {
        let mut acc = coinbase_txid;
        for sibling in &self.merkle_path {
            let mut pair = [0u8; 64];
            pair[..32].copy_from_slice(&acc);
            pair[32..].copy_from_slice(sibling);
            acc = sha256d(&pair);
        }
        acc
    }
}

/// The scriptSig lives at a fixed offset in a coinbase: version(4) + input count(1) +
/// prevout hash(32) + prevout index(4) + scriptSig length(1).
const SCRIPTSIG_LEN_OFFSET: usize = 4 + 1 + 32 + 4;

/// Read the scriptSig out of a serialized coinbase.
fn scriptsig_of(coinbase: &[u8]) -> Option<&[u8]> {
    let len = *coinbase.get(SCRIPTSIG_LEN_OFFSET)? as usize;
    let start = SCRIPTSIG_LEN_OFFSET + 1;
    coinbase.get(start..start.checked_add(len)?)
}

/// Prove a share was mined to `expected_node`, using only the data supplied.
///
/// No peers, no quorum, no clock. Every input is either in the share, in a skeleton the caller can
/// verify by rehashing, or a constant.
pub fn verify_share_node_binding(
    skeleton: &CoinbaseSkeleton,
    extranonce: &[u8],
    header80: &[u8],
    expected_node: &[u8; crate::coinbase_tags::NODE_ID_LEN],
) -> Result<(), BindingError> {
    if header80.len() != 80 {
        return Err(BindingError::MalformedHeader);
    }

    let coinbase = skeleton.coinbase_with(extranonce);
    let root = skeleton.fold_to_root(sha256d(&coinbase));

    // Bytes 36..68 of the header are the merkle root, in the same internal byte order sha256d
    // produces — so this compares like with like, with no reversal.
    if root != header80[36..68] {
        return Err(BindingError::MerkleRootMismatch);
    }

    let scriptsig = scriptsig_of(&coinbase).ok_or(BindingError::NoNodeTag)?;
    match crate::coinbase_tags::extract_node_tag(scriptsig) {
        None => Err(BindingError::NoNodeTag),
        Some(tag) if &tag != expected_node => Err(BindingError::WrongNode),
        Some(_) => Ok(()),
    }
}

/// Prove a share was mined to `node_id` **for a specific difficulty tier**, from the data supplied.
///
/// Identical in shape to [`verify_share_node_binding`], but the coinbase carries a tier-bound node
/// tag — `sha256(node_id ‖ tier_log2)[..20]` — instead of the plain `sha256(node_id)[..20]`. The
/// verifier recomputes that tag from the share's *stated* `(node_id, claimed_tier_log2)` and
/// requires it to match what the coinbase committed to.
///
/// This is the anti-post-hoc-claim property. The difficulty a share is credited is chosen BEFORE
/// the hash exists, because it lives in the coinbase that the header commits to. A share that
/// re-states a higher tier recomputes a different expected tag, which will not match the coinbase's
/// — a [`BindingError::WrongNode`]. A share that keeps the tag but alters the coinbase to carry a
/// different tier changes the coinbase txid, so it no longer folds to the header's merkle root — a
/// [`BindingError::MerkleRootMismatch`]. Either way the work would have to be re-mined.
///
/// This function proves only the *binding*: that the header was mined against a coinbase committing
/// to `(node_id, claimed_tier_log2)`. The separate obligation that the hash actually *achieves*
/// `2^claimed_tier_log2`, and the decision to credit exactly that tier, live in the accounting
/// layer (`DifficultyCalculator::verify_pow_preimage_tier`), because that is where PoW difficulty
/// is judged and where credit is assigned.
pub fn verify_share_tier_binding(
    skeleton: &CoinbaseSkeleton,
    extranonce: &[u8],
    header80: &[u8],
    node_id: &[u8],
    claimed_tier_log2: u32,
) -> Result<(), BindingError> {
    let expected = crate::coinbase_tags::node_commitment_for_tier(node_id, claimed_tier_log2);
    verify_share_node_binding(skeleton, extranonce, header80, &expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coinbase_tags::{encode_node_tag, encode_payout_tag};

    const HONEST: [u8; 20] = [0xA1; 20];
    const THIEF: [u8; 20] = [0xB2; 20];

    /// Build a coinbase skeleton whose scriptSig commits to `node`, shaped like a real one.
    fn skeleton_for(node: [u8; 20], path: Vec<[u8; 32]>) -> (CoinbaseSkeleton, Vec<u8>) {
        let extranonce = vec![0xEE; 20];

        // scriptSig: height push, payout tag, node tag, pool tag, then the extranonce.
        let mut scriptsig_head = vec![0x03, 0x40, 0x1f, 0x0e];
        scriptsig_head.extend_from_slice(&encode_payout_tag(&[0xC3; 16]));
        scriptsig_head.extend_from_slice(&encode_node_tag(&node));
        scriptsig_head.extend_from_slice(b"GHOST PublicPool");
        let scriptsig_len = scriptsig_head.len() + extranonce.len();

        let mut prefix = Vec::new();
        prefix.extend_from_slice(&2u32.to_le_bytes()); // version
        prefix.push(0x01); // input count
        prefix.extend_from_slice(&[0u8; 32]); // prevout hash
        prefix.extend_from_slice(&0xffffffffu32.to_le_bytes()); // prevout index
        prefix.push(scriptsig_len as u8);
        prefix.extend_from_slice(&scriptsig_head);

        let mut suffix = Vec::new();
        suffix.extend_from_slice(&0xffffffffu32.to_le_bytes()); // sequence
        suffix.push(0x00); // output count (irrelevant to the binding)
        suffix.extend_from_slice(&0u32.to_le_bytes()); // locktime

        (
            CoinbaseSkeleton {
                coinbase_prefix: prefix,
                coinbase_suffix: suffix,
                merkle_path: path,
            },
            extranonce,
        )
    }

    /// A header whose merkle root is the one this skeleton+extranonce actually produces.
    fn header_for(skeleton: &CoinbaseSkeleton, extranonce: &[u8]) -> Vec<u8> {
        let root = skeleton.fold_to_root(sha256d(&skeleton.coinbase_with(extranonce)));
        let mut header = vec![0u8; 80];
        header[36..68].copy_from_slice(&root);
        header
    }

    #[test]
    fn an_honest_share_verifies() {
        let (skeleton, extranonce) = skeleton_for(HONEST, vec![[0x11; 32], [0x22; 32]]);
        let header = header_for(&skeleton, &extranonce);
        assert_eq!(
            verify_share_node_binding(&skeleton, &extranonce, &header, &HONEST),
            Ok(())
        );
    }

    /// **The attack.** A thief lifts the honest node's header and claims it received the work.
    ///
    /// It cannot present the honest skeleton and claim to be the node — the coinbase names the
    /// honest one. Its only other option is a skeleton naming itself, which is the next test.
    #[test]
    fn a_thief_cannot_claim_a_share_mined_to_someone_else() {
        let (skeleton, extranonce) = skeleton_for(HONEST, vec![[0x11; 32]]);
        let header = header_for(&skeleton, &extranonce);

        assert_eq!(
            verify_share_node_binding(&skeleton, &extranonce, &header, &THIEF),
            Err(BindingError::WrongNode),
            "the coinbase names the honest node, so the thief's claim must fail"
        );
    }

    /// The thief's other move: substitute a coinbase naming itself. That changes the coinbase txid,
    /// so it no longer folds to the merkle root the stolen header commits to — the work would have
    /// to be re-mined.
    #[test]
    fn substituting_a_coinbase_breaks_the_stolen_header() {
        let (honest_skeleton, extranonce) = skeleton_for(HONEST, vec![[0x11; 32]]);
        let stolen_header = header_for(&honest_skeleton, &extranonce);

        let (thief_skeleton, thief_extranonce) = skeleton_for(THIEF, vec![[0x11; 32]]);

        assert_eq!(
            verify_share_node_binding(&thief_skeleton, &thief_extranonce, &stolen_header, &THIEF),
            Err(BindingError::MerkleRootMismatch),
            "a coinbase naming the thief cannot fold to the honest header's root"
        );
    }

    /// The extranonce is part of what the header commits to, so it cannot be swapped either.
    #[test]
    fn a_different_extranonce_breaks_the_binding() {
        let (skeleton, extranonce) = skeleton_for(HONEST, vec![[0x33; 32]]);
        let header = header_for(&skeleton, &extranonce);

        assert_eq!(
            verify_share_node_binding(&skeleton, &[0xAB; 20], &header, &HONEST),
            Err(BindingError::MerkleRootMismatch)
        );
    }

    /// A coinbase with no node tag is not bound to anyone and must not pass.
    #[test]
    fn an_untagged_coinbase_does_not_verify() {
        let extranonce = vec![0xEE; 20];
        let mut scriptsig_head = vec![0x03, 0x40, 0x1f, 0x0e];
        scriptsig_head.extend_from_slice(b"GHOST PublicPool");
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&2u32.to_le_bytes());
        prefix.push(0x01);
        prefix.extend_from_slice(&[0u8; 32]);
        prefix.extend_from_slice(&0xffffffffu32.to_le_bytes());
        prefix.push((scriptsig_head.len() + extranonce.len()) as u8);
        prefix.extend_from_slice(&scriptsig_head);

        let skeleton = CoinbaseSkeleton {
            coinbase_prefix: prefix,
            coinbase_suffix: vec![0xff, 0xff, 0xff, 0xff, 0x00, 0, 0, 0, 0],
            merkle_path: vec![],
        };
        let header = header_for(&skeleton, &extranonce);

        assert_eq!(
            verify_share_node_binding(&skeleton, &extranonce, &header, &HONEST),
            Err(BindingError::NoNodeTag)
        );
    }

    /// A solo coinbase has no other transactions, so the path is empty and the coinbase txid IS the
    /// merkle root. That case must work rather than being an accident of the loop.
    #[test]
    fn an_empty_merkle_path_verifies() {
        let (skeleton, extranonce) = skeleton_for(HONEST, vec![]);
        let header = header_for(&skeleton, &extranonce);
        assert_eq!(
            verify_share_node_binding(&skeleton, &extranonce, &header, &HONEST),
            Ok(())
        );
    }

    /// Content addressing is what makes fetching a skeleton from an untrusted peer safe, so any
    /// change to its bytes must change its hash.
    #[test]
    fn the_skeleton_hash_covers_every_field() {
        let (base, _) = skeleton_for(HONEST, vec![[0x11; 32]]);
        let h = base.skeleton_hash();

        let mut altered_prefix = base.clone();
        altered_prefix.coinbase_prefix.push(0x00);
        assert_ne!(h, altered_prefix.skeleton_hash(), "prefix not covered");

        let mut altered_suffix = base.clone();
        altered_suffix.coinbase_suffix.push(0x00);
        assert_ne!(h, altered_suffix.skeleton_hash(), "suffix not covered");

        let mut altered_path = base.clone();
        altered_path.merkle_path.push([0x99; 32]);
        assert_ne!(h, altered_path.skeleton_hash(), "merkle path not covered");
    }

    /// Length prefixing must stop a prefix/suffix pair being re-split into a different coinbase
    /// with the same hash.
    #[test]
    fn the_skeleton_hash_is_not_confusable_by_resplitting() {
        let a = CoinbaseSkeleton {
            coinbase_prefix: vec![1, 2, 3],
            coinbase_suffix: vec![4, 5],
            merkle_path: vec![],
        };
        let b = CoinbaseSkeleton {
            coinbase_prefix: vec![1, 2],
            coinbase_suffix: vec![3, 4, 5],
            merkle_path: vec![],
        };
        assert_ne!(a.skeleton_hash(), b.skeleton_hash());
    }

    #[test]
    fn a_malformed_header_is_rejected() {
        let (skeleton, extranonce) = skeleton_for(HONEST, vec![]);
        assert_eq!(
            verify_share_node_binding(&skeleton, &extranonce, &[0u8; 79], &HONEST),
            Err(BindingError::MalformedHeader)
        );
    }

    const NODE_ID_32: [u8; 32] = [0xC7; 32];

    /// A share whose coinbase commits to `sha256(node_id ‖ tier)` verifies when the verifier is
    /// told the same tier.
    #[test]
    fn a_tier_bound_share_verifies_at_its_own_tier() {
        let tier = 13u32;
        let commitment = crate::coinbase_tags::node_commitment_for_tier(&NODE_ID_32, tier);
        let (skeleton, extranonce) = skeleton_for(commitment, vec![[0x11; 32], [0x22; 32]]);
        let header = header_for(&skeleton, &extranonce);
        assert_eq!(
            verify_share_tier_binding(&skeleton, &extranonce, &header, &NODE_ID_32, tier),
            Ok(())
        );
    }

    /// **The attack this closes.** Re-stating a HIGHER tier after the hash is known recomputes a
    /// different expected tag, which the coinbase never committed to — so the claim is refuted. The
    /// only way to be credited a higher tier is to have committed to it before hashing.
    #[test]
    fn restating_a_higher_tier_after_the_fact_is_refuted() {
        let mined_tier = 13u32;
        let commitment = crate::coinbase_tags::node_commitment_for_tier(&NODE_ID_32, mined_tier);
        let (skeleton, extranonce) = skeleton_for(commitment, vec![[0x11; 32]]);
        let header = header_for(&skeleton, &extranonce);

        // Same header, same coinbase, but the sharer now claims a fatter tier.
        assert_eq!(
            verify_share_tier_binding(&skeleton, &extranonce, &header, &NODE_ID_32, mined_tier + 4),
            Err(BindingError::WrongNode),
            "a tier the coinbase never committed to must not verify"
        );
    }

    /// Rebuilding the coinbase to carry the fatter tier's tag changes the coinbase txid, so it no
    /// longer folds to the stolen header's merkle root — the work would have to be re-mined.
    #[test]
    fn rebuilding_the_coinbase_for_a_higher_tier_breaks_the_header() {
        let mined_tier = 13u32;
        let honest_commit = crate::coinbase_tags::node_commitment_for_tier(&NODE_ID_32, mined_tier);
        let (honest_skeleton, extranonce) = skeleton_for(honest_commit, vec![[0x11; 32]]);
        let stolen_header = header_for(&honest_skeleton, &extranonce);

        let fat_commit =
            crate::coinbase_tags::node_commitment_for_tier(&NODE_ID_32, mined_tier + 4);
        let (fat_skeleton, fat_extranonce) = skeleton_for(fat_commit, vec![[0x11; 32]]);

        assert_eq!(
            verify_share_tier_binding(
                &fat_skeleton,
                &fat_extranonce,
                &stolen_header,
                &NODE_ID_32,
                mined_tier + 4
            ),
            Err(BindingError::MerkleRootMismatch),
            "a coinbase carrying the fatter tier cannot fold to the honest header's root"
        );
    }

    /// A different node claiming a correctly-tiered share still fails: the tag folds node identity
    /// and tier together, so neither can be swapped alone.
    #[test]
    fn a_different_node_cannot_claim_a_tiered_share() {
        let tier = 13u32;
        let commitment = crate::coinbase_tags::node_commitment_for_tier(&NODE_ID_32, tier);
        let (skeleton, extranonce) = skeleton_for(commitment, vec![[0x11; 32]]);
        let header = header_for(&skeleton, &extranonce);

        let other_node = [0xEEu8; 32];
        assert_eq!(
            verify_share_tier_binding(&skeleton, &extranonce, &header, &other_node, tier),
            Err(BindingError::WrongNode)
        );
    }
}
