//! Spending a lane by its escape leaf — alone, after the delay.
//!
//! # The guarantee this is
//!
//! Every lane except Cash has a way out that needs nobody else:
//!
//! | Lane | Leaf | Who | After |
//! |---|---|---|---|
//! | Savings | owner recovery | you | ~14 months |
//! | Savings | backup recovery | your backup device | ~15 months |
//! | Spending | exit | you | ~7 days |
//! | Investments | recall | you | ~14 days |
//!
//! Those are single-signature spends. No quorum, no ceremony, no second
//! device — a key, a delay, and a transaction. That is what stops a silent
//! quorum from being the end of the money, and it is why Investments is
//! delegation with a bound rather than custody without one.
//!
//! Until this existed, funds in Spending or Investments were only recoverable
//! with the quorum's cooperation, which is the exact situation the leaves were
//! designed to survive.
//!
//! # Why the sequence number is not the caller's business
//!
//! A relative timelock is enforced by `OP_CHECKSEQUENCEVERIFY` against the
//! input's `nSequence`. Get it wrong and the node rejects the transaction as
//! non-final — or, worse, a caller "fixes" it by copying a number that happens
//! to pass while meaning something else. [`escape_sequence`] derives it from
//! the leaf, so the two cannot disagree.

use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{ControlBlock, LeafVersion, Signature as TaprootSignature};
use bitcoin::{
    secp256k1::{Keypair, Message, Secp256k1, SecretKey},
    ScriptBuf, Sequence, TapLeafHash, TapSighashType, Transaction, TxOut, Witness,
};

use crate::error::LockError;
use crate::lane::Lane;

/// The escape leaf the **owner** can spend, per lane.
///
/// Only the owner's routes are here. Savings' backup-recovery leaf belongs to
/// the backup device and its inheritance leaf to the heir; a wallet holding
/// the owner key cannot spend either, and offering them would be offering a
/// spend that cannot be produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerEscape {
    /// Savings, after ~14 months of silence.
    SavingsRecovery,
    /// Spending, after ~7 days without the quorum.
    SpendingExit,
    /// Investments, recalled after ~14 days.
    InvestmentsRecall,
}

impl OwnerEscape {
    /// How long the wait is, in blocks.
    pub fn blocks(self) -> u32 {
        match self {
            OwnerEscape::SavingsRecovery => crate::constants::OWNER_RECOVERY_BLOCKS,
            OwnerEscape::SpendingExit => crate::constants::SPENDING_EXIT_BLOCKS,
            OwnerEscape::InvestmentsRecall => crate::constants::INVESTMENTS_RECALL_BLOCKS,
        }
    }

    /// What to call it to a person.
    pub fn label(self) -> &'static str {
        match self {
            OwnerEscape::SavingsRecovery => "Savings recovery",
            OwnerEscape::SpendingExit => "Spending exit",
            OwnerEscape::InvestmentsRecall => "Investments recall",
        }
    }

    /// The leaf script, built the same way the lane built it.
    ///
    /// Derived rather than reconstructed by callers: a leaf that differs from
    /// the one in the tree by a single byte has no control block, and the only
    /// symptom is a spend that cannot be assembled.
    pub fn leaf(self, owner: &bitcoin::XOnlyPublicKey) -> Result<ScriptBuf, LockError> {
        crate::lane::relative_timelock_leaf(self.blocks(), owner)
    }
}

/// The `nSequence` an input must carry to satisfy a `blocks`-deep relative
/// timelock.
///
/// BIP-68: block-based, so the disable bit is clear and the type flag is unset.
pub fn escape_sequence(blocks: u32) -> Result<Sequence, LockError> {
    if blocks > crate::constants::CSV_MAX_BLOCKS {
        return Err(LockError::TimelockTooLong {
            blocks,
            max: crate::constants::CSV_MAX_BLOCKS,
        });
    }
    Ok(Sequence::from_height(blocks as u16))
}

/// The control block proving `leaf` belongs to `lane`'s tree.
fn control_block(lane: &Lane, leaf: &ScriptBuf) -> Result<ControlBlock, LockError> {
    lane.spend_info
        .control_block(&(leaf.clone(), LeafVersion::TapScript))
        .ok_or_else(|| {
            LockError::Policy(
                "that leaf is not in this lane's tree — the script and the lane disagree, \
                 so a spend built from them could never be valid"
                    .into(),
            )
        })
}

/// Sign one input's escape leaf and return the finished witness.
///
/// `prevouts` must cover **every** input: a Taproot sighash commits to all of
/// them, so a spend signed against a partial set is signed for a different
/// transaction than the one being broadcast.
///
/// Checks the input's `nSequence` against the leaf's delay before signing. A
/// mismatch is refused rather than signed, because the resulting transaction
/// is one a node rejects as non-final — and a signature on it is worse than no
/// signature, since it looks finished.
pub fn sign_escape(
    lane: &Lane,
    leaf: &ScriptBuf,
    blocks: u32,
    key: &SecretKey,
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
) -> Result<Witness, LockError> {
    if input_index >= tx.input.len() {
        return Err(LockError::Policy(format!(
            "input {input_index} does not exist: the transaction has {}",
            tx.input.len()
        )));
    }
    if prevouts.len() != tx.input.len() {
        return Err(LockError::Policy(format!(
            "{} prevouts for {} inputs: a Taproot sighash commits to every input, so \
             this would sign a different transaction than the one presented",
            prevouts.len(),
            tx.input.len()
        )));
    }

    let required = escape_sequence(blocks)?;
    let actual = tx.input[input_index].sequence;
    if actual != required {
        return Err(LockError::Policy(format!(
            "input {input_index} has nSequence {} but this leaf needs {} ({} blocks). \
             A node would reject the spend as non-final; signing it anyway would just \
             make a dead transaction look finished.",
            actual.0, required.0, blocks
        )));
    }

    let cb = control_block(lane, leaf)?;
    let leaf_hash = TapLeafHash::from_script(leaf, LeafVersion::TapScript);

    let mut cache = SighashCache::new(tx);
    let sighash = cache
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(prevouts),
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|e| LockError::Policy(format!("sighash: {e}")))?;

    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, key);

    // The leaf checks a plain x-only key, so BIP-340 signing applies directly —
    // no Taproot tweak. Tweaking here would produce a signature against a key
    // that is not the one in the script.
    //
    // Auxiliary randomness where it is available, because it costs nothing and
    // blunts fault and side-channel attacks on the signing device. Where it is
    // not, this falls back to deterministic BIP-340 rather than refusing:
    // that variant is explicitly permitted by the BIP and is cryptographically
    // sound, and this is the path a person takes when everything else has
    // failed. Refusing to sign an escape because the RNG is unavailable would
    // put a hole in the one guarantee that is supposed to have none.
    let msg = Message::from_digest(*sighash.as_ref());
    let mut aux = [0u8; 32];
    let sig = {
        use rand::RngCore;
        match rand::rngs::OsRng.try_fill_bytes(&mut aux) {
            Ok(()) => secp.sign_schnorr_with_aux_rand(&msg, &keypair, &aux),
            Err(_) => secp.sign_schnorr_no_aux_rand(&msg, &keypair),
        }
    };

    let mut witness = Witness::new();
    witness.push(
        TaprootSignature {
            signature: sig,
            sighash_type: TapSighashType::Default,
        }
        .to_vec(),
    );
    witness.push(leaf.as_bytes());
    witness.push(cb.serialize());
    Ok(witness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{INVESTMENTS_RECALL_BLOCKS, SPENDING_EXIT_BLOCKS};
    use crate::lane::{relative_timelock_leaf, InvestmentsPolicy, SpendingPolicy};
    use bitcoin::{
        absolute::LockTime, transaction::Version, Amount, Network, OutPoint, TxIn, Txid,
    };
    use std::str::FromStr;

    fn sk(b: u8) -> SecretKey {
        SecretKey::from_slice(&[b; 32]).unwrap()
    }
    fn xonly(s: &SecretKey) -> bitcoin::XOnlyPublicKey {
        Keypair::from_secret_key(&Secp256k1::new(), s)
            .x_only_public_key()
            .0
    }

    fn spending_lane(owner: &SecretKey) -> Lane {
        SpendingPolicy {
            aggregate: crate::key_agg::aggregate(&[xonly(owner), xonly(&sk(99))]).unwrap(),
            owner: xonly(owner),
        }
        .build(&Secp256k1::new(), Network::Regtest)
        .unwrap()
    }

    fn spend_of(lane: &Lane, seq: Sequence) -> (Transaction, Vec<TxOut>) {
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: lane.address.script_pubkey(),
        };
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(
                        "0000000000000000000000000000000000000000000000000000000000000003",
                    )
                    .unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: seq,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: lane.address.script_pubkey(),
            }],
        };
        (tx, vec![prevout])
    }

    /// The leaf this helper builds must be the one in the lane's tree.
    ///
    /// If it were not, there would be no control block and the escape would be
    /// unassemblable — the failure the helper exists to prevent.
    #[test]
    fn the_owner_escape_leaf_is_the_one_in_the_tree() {
        let owner = sk(81);
        let lane = spending_lane(&owner);
        let leaf = OwnerEscape::SpendingExit.leaf(&xonly(&owner)).unwrap();
        assert!(
            lane.spend_info
                .control_block(&(leaf, LeafVersion::TapScript))
                .is_some(),
            "the derived leaf must be in the lane's tree"
        );

        let inv_owner = sk(82);
        let inv = InvestmentsPolicy {
            quorum: xonly(&sk(97)),
            owner: xonly(&inv_owner),
        }
        .build(&Secp256k1::new(), Network::Regtest)
        .unwrap();
        let leaf = OwnerEscape::InvestmentsRecall
            .leaf(&xonly(&inv_owner))
            .unwrap();
        assert!(inv
            .spend_info
            .control_block(&(leaf, LeafVersion::TapScript))
            .is_some());
    }

    /// The delays are the constants, not numbers typed twice.
    #[test]
    fn each_escape_reports_its_own_delay() {
        assert_eq!(OwnerEscape::SpendingExit.blocks(), SPENDING_EXIT_BLOCKS);
        assert_eq!(
            OwnerEscape::InvestmentsRecall.blocks(),
            INVESTMENTS_RECALL_BLOCKS
        );
        assert_eq!(
            OwnerEscape::SavingsRecovery.blocks(),
            crate::constants::OWNER_RECOVERY_BLOCKS
        );
    }

    /// **The guarantee: the owner leaves alone.**
    #[test]
    fn the_owner_can_exit_spending_without_the_quorum() {
        let owner = sk(71);
        let lane = spending_lane(&owner);
        let leaf = relative_timelock_leaf(SPENDING_EXIT_BLOCKS, &xonly(&owner)).unwrap();
        let (tx, prevouts) = spend_of(&lane, escape_sequence(SPENDING_EXIT_BLOCKS).unwrap());

        let witness = sign_escape(
            &lane,
            &leaf,
            SPENDING_EXIT_BLOCKS,
            &owner,
            &tx,
            0,
            &prevouts,
        )
        .unwrap();

        // signature, script, control block.
        assert_eq!(witness.len(), 3);
        assert_eq!(witness.nth(1).unwrap(), leaf.as_bytes());
    }

    /// Investments is delegation with a bound, and this is the bound.
    #[test]
    fn the_owner_can_recall_investments() {
        let owner = sk(72);
        let lane = InvestmentsPolicy {
            quorum: xonly(&sk(98)),
            owner: xonly(&owner),
        }
        .build(&Secp256k1::new(), Network::Regtest)
        .unwrap();
        let leaf = relative_timelock_leaf(INVESTMENTS_RECALL_BLOCKS, &xonly(&owner)).unwrap();
        let (tx, prevouts) = spend_of(&lane, escape_sequence(INVESTMENTS_RECALL_BLOCKS).unwrap());

        let w = sign_escape(
            &lane,
            &leaf,
            INVESTMENTS_RECALL_BLOCKS,
            &owner,
            &tx,
            0,
            &prevouts,
        )
        .unwrap();
        assert_eq!(w.len(), 3);
    }

    /// A wrong nSequence is refused, not signed.
    ///
    /// The transaction would be rejected as non-final. Signing it anyway makes
    /// a dead spend look finished, which is the more expensive failure.
    #[test]
    fn a_sequence_that_does_not_satisfy_the_delay_is_refused() {
        let owner = sk(73);
        let lane = spending_lane(&owner);
        let leaf = relative_timelock_leaf(SPENDING_EXIT_BLOCKS, &xonly(&owner)).unwrap();
        let (tx, prevouts) = spend_of(&lane, Sequence::ENABLE_RBF_NO_LOCKTIME);

        let err = sign_escape(
            &lane,
            &leaf,
            SPENDING_EXIT_BLOCKS,
            &owner,
            &tx,
            0,
            &prevouts,
        )
        .expect_err("must refuse");
        assert!(format!("{err}").contains("non-final"), "{err}");
    }

    /// A leaf from a different lane has no control block here.
    #[test]
    fn a_leaf_from_another_lane_is_refused() {
        let owner = sk(74);
        let lane = spending_lane(&owner);
        // A leaf with the right shape but the wrong delay: not in this tree.
        let alien = relative_timelock_leaf(4_242, &xonly(&owner)).unwrap();
        let (tx, prevouts) = spend_of(&lane, escape_sequence(4_242).unwrap());

        let err =
            sign_escape(&lane, &alien, 4_242, &owner, &tx, 0, &prevouts).expect_err("must refuse");
        assert!(
            format!("{err}").contains("not in this lane's tree"),
            "{err}"
        );
    }

    /// A partial prevout set is refused: the sighash commits to all of them.
    #[test]
    fn a_partial_prevout_set_is_refused() {
        let owner = sk(75);
        let lane = spending_lane(&owner);
        let leaf = relative_timelock_leaf(SPENDING_EXIT_BLOCKS, &xonly(&owner)).unwrap();
        let (tx, _) = spend_of(&lane, escape_sequence(SPENDING_EXIT_BLOCKS).unwrap());

        let err = sign_escape(&lane, &leaf, SPENDING_EXIT_BLOCKS, &owner, &tx, 0, &[])
            .expect_err("must refuse");
        assert!(format!("{err}").contains("commits to every input"), "{err}");
    }

    /// BIP-68 block-based encoding, and the ceiling is enforced.
    #[test]
    fn the_sequence_is_the_block_count() {
        assert_eq!(escape_sequence(1_008).unwrap().0, 1_008);
        assert!(escape_sequence(crate::constants::CSV_MAX_BLOCKS + 1).is_err());
    }
}
