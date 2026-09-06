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
//| FILE: client_session.rs                                                                                               |
//|======================================================================================================================|

//! A joining client that cannot sign without having verified.
//!
//! [`crate::pre_sign`] gives a participant everything they need to check a round
//! before signing it. Nothing made them run it — a client could fetch the
//! transaction and sign, and every guarantee in that module would be words.
//!
//! This makes the omission unrepresentable. There is no path from a joined
//! session to a signature that does not pass through verification, because the
//! type that permits signing can only be produced by verifying.
//!
//! # And it must be the same transaction
//!
//! Verifying then signing is not enough on its own: a coordinator can serve one
//! transaction to `/round-tx` and a different one to sign. So the verified
//! session carries the txid it approved, and [`Verified::authorise`] refuses
//! anything else.
//!
//! That substitution is the cheapest attack available to a coordinator and the
//! hardest for a client author to remember to defend against, which is why it
//! belongs in the type rather than in a checklist.
//!
//! # Why this lives in the protocol crate
//!
//! A wallet joining over PSBT has no Lock, no quorum and no residency. It has
//! the transaction and these checks. Putting them in one client would mean the
//! second client re-derives them, and the second client is the one written by
//! someone who has not read this file.

use bitcoin::hashes::Hash;
use bitcoin::sighash::TapSighashType;
use bitcoin::{Transaction, Txid};

use crate::pre_sign::{check_before_signing, Expectation, RefuseToSign};
use crate::signature_scope::is_safe_for_round;

/// A client that has joined a round and not yet verified it.
#[derive(Debug, Clone)]
pub struct Joined {
    expectation: Expectation,
}

/// A client that has verified a specific transaction and may sign it.
///
/// Only obtainable from [`Joined::verify`].
#[derive(Debug, Clone)]
pub struct Verified {
    approved_txid: Txid,
    expectation: Expectation,
}

impl Joined {
    /// Join a round with what was agreed.
    pub fn new(expectation: Expectation) -> Self {
        Self { expectation }
    }

    /// What this client agreed to.
    pub fn expectation(&self) -> &Expectation {
        &self.expectation
    }

    /// Verify a coordinator's whole `/round-tx` response.
    ///
    /// This is the path a wallet should use. [`Self::verify`] leaves the
    /// anonymity analysis to the caller, and a caller that forgets it gets
    /// `SetUnverified` — correct, but only after the round trip. This does the
    /// recount itself, from the transaction and the prevouts the response
    /// already carries, so the check cannot be skipped by omission.
    ///
    /// `prevout_scripts` must be in `tx.input` order, as the endpoint serves
    /// them.
    pub fn verify_response(
        mut self,
        tx: &Transaction,
        prevout_scripts: &[Vec<u8>],
        claimed: Option<crate::anonymity_set::SetReport>,
    ) -> Result<Verified, Vec<RefuseToSign>> {
        // A response whose prevouts do not line up with its inputs cannot be
        // analysed, and guessing the alignment would produce a confident wrong
        // answer. Refuse instead — this is also the shape a coordinator would
        // serve if it were trying to make the recount come out differently.
        if prevout_scripts.len() != tx.input.len() {
            return Err(vec![RefuseToSign::SetUnverified {
                seats: tx.input.len(),
            }]);
        }

        let coins: Vec<crate::clustering::CoinFacts> = tx
            .input
            .iter()
            .zip(prevout_scripts.iter())
            .map(|(txin, script)| crate::clustering::CoinFacts {
                outpoint: crate::signing_ledger::OutPointKey {
                    txid: txin.previous_output.txid.to_byte_array(),
                    vout: txin.previous_output.vout,
                },
                script_pubkey: script.clone(),
            })
            .collect();

        self.expectation.set_report = Some(crate::anonymity_set::recount_from_inputs(&coins));
        self.expectation.claimed_set = claimed;
        self.verify(tx)
    }

    /// Verify a round transaction against an expectation the caller has already
    /// completed. Prefer [`Self::verify_response`], which fills in the
    /// anonymity analysis rather than trusting the caller to have done it.
    ///
    /// Returns every reason to refuse rather than the first, so a client can
    /// decide between retrying and walking away.
    pub fn verify(self, tx: &Transaction) -> Result<Verified, Vec<RefuseToSign>> {
        let refusals = check_before_signing(tx, &self.expectation);
        if refusals.is_empty() {
            Ok(Verified {
                approved_txid: tx.compute_txid(),
                expectation: self.expectation,
            })
        } else {
            Err(refusals)
        }
    }
}

/// Why a verified client still refused to authorise a signature.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthoriseError {
    /// A different transaction was presented than the one verified.
    #[error("asked to sign {presented} after verifying {approved} — a coordinator may serve one transaction and ask for a signature over another")]
    NotTheVerifiedTransaction {
        /// What was verified.
        approved: Txid,
        /// What was presented.
        presented: Txid,
    },

    /// The sighash would not commit to what was verified.
    #[error("sighash {sighash:?} does not commit to everything that was checked — verification would be void")]
    SighashVoidsVerification {
        /// The offending type.
        sighash: TapSighashType,
    },
}

impl Verified {
    /// The transaction this client approved.
    pub fn approved_txid(&self) -> Txid {
        self.approved_txid
    }

    /// What this client agreed to.
    pub fn expectation(&self) -> &Expectation {
        &self.expectation
    }

    /// Confirm a signature over `tx` with `sighash` is the one that was approved.
    ///
    /// Checks both that the transaction is the verified one and that the sighash
    /// commits to everything the verification covered. Signing `SIGHASH_NONE`
    /// over a transaction you carefully checked leaves the coordinator free to
    /// replace every output afterwards.
    pub fn authorise(
        &self,
        tx: &Transaction,
        sighash: TapSighashType,
    ) -> Result<(), AuthoriseError> {
        let presented = tx.compute_txid();
        if presented != self.approved_txid {
            return Err(AuthoriseError::NotTheVerifiedTransaction {
                approved: self.approved_txid,
                presented,
            });
        }
        if !is_safe_for_round(sighash) {
            return Err(AuthoriseError::SighashVoidsVerification { sighash });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        absolute::LockTime, hashes::Hash, transaction::Version, Amount, OutPoint, ScriptBuf,
        Sequence, TxIn, TxOut, Witness,
    };

    fn spk(tag: u8) -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0x51, 0x20, tag])
    }
    fn outpoint(tag: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([tag; 32]),
            vout: 0,
        }
    }

    fn honest_round() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: (1..=5u8)
                .map(|i| TxIn {
                    previous_output: outpoint(i),
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output: (1..=5u8)
                .map(|i| TxOut {
                    value: Amount::from_sat(100_000),
                    script_pubkey: spk(i + 10),
                })
                .chain(std::iter::once(TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: spk(99),
                }))
                .collect(),
        }
    }

    fn expectation() -> Expectation {
        Expectation {
            my_input: (outpoint(1).txid, 0),
            my_output_script: spk(11),
            my_output_sats: 100_000,
            total_input_sats: 505_000,
            max_fee_sats: 10_000,
            claimed_set: None,
            set_report: Some(crate::anonymity_set::SetReport {
                seats: 5,
                entities: 5,
                unverified: 0,
                payers: 5,
                discounts: Vec::new(),
            }),
            min_set: 5,
        }
    }

    #[test]
    fn an_honest_round_verifies_and_authorises() {
        let tx = honest_round();
        let v = Joined::new(expectation()).verify(&tx).expect("verifies");
        assert_eq!(v.approved_txid(), tx.compute_txid());
        assert_eq!(v.authorise(&tx, TapSighashType::Default), Ok(()));
    }

    #[test]
    fn a_dishonest_round_never_yields_a_signable_session() {
        // The point of the type-state: there is no way to obtain `Verified`
        // except by passing the checks, so "forgot to verify" is unrepresentable.
        let mut tx = honest_round();
        tx.output.retain(|o| o.script_pubkey != spk(11));
        let refusals = Joined::new(expectation()).verify(&tx).unwrap_err();
        assert!(refusals.contains(&RefuseToSign::MyOutputMissing {
            expected_sats: 100_000
        }));
    }

    #[test]
    fn a_substituted_transaction_is_refused() {
        // The cheapest attack a coordinator has: serve one transaction to
        // `/round-tx` and ask for a signature over another.
        let good = honest_round();
        let v = Joined::new(expectation()).verify(&good).expect("verifies");

        let mut swapped = honest_round();
        swapped.output[0].value = Amount::from_sat(1);
        assert!(matches!(
            v.authorise(&swapped, TapSighashType::Default),
            Err(AuthoriseError::NotTheVerifiedTransaction { .. })
        ));
    }

    #[test]
    fn a_sighash_that_voids_the_verification_is_refused() {
        // Verify carefully, then sign SIGHASH_NONE, and the coordinator may
        // replace every output afterwards. The checks were real; the signature
        // did not bind them.
        let tx = honest_round();
        let v = Joined::new(expectation()).verify(&tx).expect("verifies");
        for bad in [
            TapSighashType::None,
            TapSighashType::Single,
            TapSighashType::AllPlusAnyoneCanPay,
            TapSighashType::NonePlusAnyoneCanPay,
            TapSighashType::SinglePlusAnyoneCanPay,
        ] {
            assert!(
                matches!(
                    v.authorise(&tx, bad),
                    Err(AuthoriseError::SighashVoidsVerification { .. })
                ),
                "{bad:?} should void the verification"
            );
        }
        assert!(v.authorise(&tx, TapSighashType::All).is_ok());
    }

    #[test]
    fn verification_is_bound_to_the_transaction_not_to_the_expectation() {
        // Two rounds could satisfy the same expectation. Approving one must not
        // authorise the other.
        let a = honest_round();
        let mut b = honest_round();
        b.output.push(TxOut {
            value: Amount::from_sat(2_000),
            script_pubkey: spk(200),
        });

        let v = Joined::new(expectation()).verify(&a).expect("verifies");
        // `b` would also pass the checks — but it is not what was approved.
        assert!(Joined::new(expectation()).verify(&b).is_ok());
        assert!(matches!(
            v.authorise(&b, TapSighashType::Default),
            Err(AuthoriseError::NotTheVerifiedTransaction { .. })
        ));
    }
    /// Scripts for a round whose inputs are all independent.
    fn independent_scripts(tx: &Transaction) -> Vec<Vec<u8>> {
        (0..tx.input.len()).map(|i| vec![i as u8, 0xab]).collect()
    }

    #[test]
    fn verify_response_does_the_recount_itself() {
        // `verify` leaves the analysis to the caller, and a caller who forgets
        // gets `SetUnverified` only after the round trip. This path cannot be
        // skipped by omission.
        let tx = honest_round();
        let mut want = expectation();
        want.set_report = None; // deliberately not supplied
        want.min_set = 3;
        let scripts = independent_scripts(&tx);
        let joined = Joined::new(want);
        let verified = joined
            .verify_response(&tx, &scripts, None)
            .expect("independent inputs should verify");
        assert_eq!(verified.approved_txid(), tx.compute_txid());
        assert!(verified.expectation().set_report.is_some());
    }

    #[test]
    fn verify_response_refuses_an_over_claim_from_the_wire() {
        // The whole point of serving a figure: it can be contradicted.
        let tx = honest_round();
        let mut want = expectation();
        want.set_report = None;
        want.min_set = 1;
        let scripts = independent_scripts(&tx);
        let claimed = crate::anonymity_set::SetReport {
            seats: tx.input.len(),
            entities: 500,
            unverified: 0,
            payers: 500,
            discounts: Vec::new(),
        };
        let refusals = Joined::new(want)
            .verify_response(&tx, &scripts, Some(claimed))
            .expect_err("a 500-entity claim must not stand");
        assert!(
            refusals
                .iter()
                .any(|r| matches!(r, RefuseToSign::SetOverClaimed { claimed: 500, .. })),
            "{refusals:?}"
        );
    }

    #[test]
    fn a_round_of_siblings_fails_the_floor_through_the_wire_path() {
        // Every input from one funding transaction is one entity, however many
        // seats it fills. The recount has to see that without being told.
        let mut tx = honest_round();
        let common = tx.input[0].previous_output.txid;
        for (i, txin) in tx.input.iter_mut().enumerate() {
            txin.previous_output.txid = common;
            txin.previous_output.vout = i as u32;
        }
        let mut want = expectation();
        want.set_report = None;
        want.min_set = 5;
        let scripts = independent_scripts(&tx);
        let refusals = Joined::new(want)
            .verify_response(&tx, &scripts, None)
            .expect_err("one entity cannot clear a floor of five");
        assert!(
            refusals.iter().any(|r| matches!(
                r,
                RefuseToSign::SetTooSmall {
                    got: 1,
                    floor: 5,
                    ..
                }
            )),
            "{refusals:?}"
        );
    }

    #[test]
    fn mismatched_prevouts_are_refused_rather_than_guessed() {
        // Guessing the alignment produces a confident wrong answer, and this is
        // also the shape a coordinator would serve to bend the recount.
        let tx = honest_round();
        let short = vec![vec![1u8]; tx.input.len().saturating_sub(1)];
        let refusals = Joined::new(expectation())
            .verify_response(&tx, &short, None)
            .expect_err("misaligned prevouts must refuse");
        assert!(
            refusals
                .iter()
                .any(|r| matches!(r, RefuseToSign::SetUnverified { .. })),
            "{refusals:?}"
        );
    }
}
