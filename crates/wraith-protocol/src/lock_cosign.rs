//! The quorum's half of a Ghost Lock Spending spend.
//!
//! # What the quorum is actually for
//!
//! Spending's key path is MuSig2 of the owner and the quorum, so the quorum
//! cannot spend alone and cannot redirect: a different destination is a
//! different sighash, and the owner's partial signature would not combine with
//! it. That much is structural and needs no policy.
//!
//! What policy decides is whether the quorum co-signs **at all** — and that is
//! the entire security value of the arrangement. A quorum that signs whatever
//! it is asked adds nothing against somebody who has stolen the owner's key:
//! the thief simply asks, and the second factor waves them through. It would
//! leave only the downside, which is that the funds stop moving when the
//! service does.
//!
//! So refusal is not a bolt-on here. It is the feature.
//!
//! # The two rules
//!
//! **Never equivocate.** The quorum must not co-sign two different
//! transactions spending one coin. Doing so produces a valid double-sign proof
//! against it, which is the fraud the whole design promises cannot happen.
//! [`crate::signing_ledger`] already enforces this and is reused unchanged —
//! including its idempotency, because a retry is not an attack.
//!
//! **A ceiling.** Above a configured amount the quorum refuses and the owner
//! waits out the exit leaf instead. That is what makes the second factor worth
//! having: a stolen key buys an attacker the ceiling, not the balance, and the
//! owner keeps a route to the rest that needs nobody's cooperation.
//!
//! The ceiling is deliberately a number an operator sets rather than one this
//! module picks. There is no defensible default: it depends on what the lane
//! is for.

use bitcoin::XOnlyPublicKey;
use ghost_lock::airgap::{review, SigningRequest, SpendSummary};
use ghost_lock::signing::{NonceLedger, SigningSession};

use crate::signing_ledger::{Decision, LedgerError, OutPointKey, SignatureStore, SigningLedger};

/// What the quorum will and will not co-sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CosignPolicy {
    /// Largest single spend to co-sign, in satoshis.
    ///
    /// `None` means no ceiling, which makes the quorum a rubber stamp against
    /// a stolen owner key. Supported because some deployments genuinely want
    /// availability over that protection — but it is a choice, not a default
    /// somebody should arrive at by omission.
    pub max_spend_sats: Option<u64>,
}

/// Why the quorum said no.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum CosignRefusal {
    /// The spend is larger than the quorum will authorise.
    #[error(
        "this spend moves {spend_sats} sats and the quorum's ceiling is {ceiling_sats}; \
         it will not co-sign. The Spending exit leaf still gets you out alone after the delay."
    )]
    AboveCeiling {
        /// What the spend moves.
        spend_sats: u64,
        /// The configured ceiling.
        ceiling_sats: u64,
    },
    /// This coin is already committed to a different transaction.
    #[error("{0}")]
    WouldEquivocate(#[from] LedgerError),
    /// The request could not be read, so nothing about it is known.
    #[error("this request cannot be co-signed: {0}")]
    Unreadable(String),
}

/// A quorum's participation in one Lock spend.
///
/// Holds a secret nonce between the two rounds, so it is neither `Clone` nor
/// `Copy`.
pub struct CosignSession {
    session: SigningSession,
    /// What was approved, so round 2 cannot quietly complete something else.
    summary: SpendSummary,
    our_nonce: [u8; 66],
}

impl std::fmt::Debug for CosignSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CosignSession")
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

impl CosignSession {
    /// This party's public nonce, to send back.
    pub fn public_nonce(&self) -> [u8; 66] {
        self.our_nonce
    }

    /// What the quorum approved. Worth logging: it is the record of what this
    /// signature was for.
    pub fn summary(&self) -> &SpendSummary {
        &self.summary
    }

    /// Round 2. Produces the quorum's partial signature.
    ///
    /// Consumes the session, so one secret nonce can never sign twice.
    pub fn sign<N: NonceLedger>(
        self,
        nonces: &mut N,
        public_nonces: &[[u8; 66]],
    ) -> Result<[u8; 32], String> {
        self.session
            .sign(nonces, public_nonces)
            .map_err(|e| e.to_string())
    }
}

/// Decide whether to co-sign, and take round 1 if so.
///
/// The order matters. Policy is applied and the coin committed **before** a
/// nonce exists: a refusal must not consume one, or an attacker could exhaust
/// the quorum's willingness to sign by submitting spends it was always going
/// to reject.
///
/// `quorum_key` is this quorum's stable secret — stable because it is baked
/// into the Lock's address, unlike the ephemeral per-round keys the blind
/// signer uses.
#[allow(clippy::too_many_arguments)]
pub fn begin_cosign<S: SignatureStore>(
    request: &SigningRequest,
    network: bitcoin::Network,
    policy: CosignPolicy,
    coins: &mut SigningLedger<S>,
    quorum_key: &bitcoin::secp256k1::SecretKey,
    keys: &[XOnlyPublicKey],
    merkle_root: Option<bitcoin::TapNodeHash>,
) -> Result<CosignSession, CosignRefusal> {
    // Read the transaction first: every rule below is about what it does, and
    // a request that cannot be read is one the quorum knows nothing about.
    let (summary, message) =
        review(request, network).map_err(|e| CosignRefusal::Unreadable(e.to_string()))?;

    if let Some(ceiling) = policy.max_spend_sats {
        // The input's value, not the outputs': that is what leaves the lane,
        // and change coming back does not make a large spend a small one.
        if summary.input_sats > ceiling {
            return Err(CosignRefusal::AboveCeiling {
                spend_sats: summary.input_sats,
                ceiling_sats: ceiling,
            });
        }
    }

    // Commit the coin before signing. The ledger is idempotent, so a retry of
    // the same spend is allowed through; a *different* spend of the same coin
    // is refused, which is the equivocation guarantee.
    let coin = coin_key(request).map_err(CosignRefusal::Unreadable)?;
    let txid = spending_txid(request).map_err(CosignRefusal::Unreadable)?;
    match coins.authorise(coin, txid) {
        Ok(Decision::Sign) | Ok(Decision::AlreadyCommitted) => {}
        Err(e) => return Err(CosignRefusal::WouldEquivocate(e)),
    }

    let (session, commitment) = SigningSession::begin(keys, quorum_key, merkle_root, &message)
        .map_err(|e| CosignRefusal::Unreadable(e.to_string()))?;
    Ok(CosignSession {
        our_nonce: commitment.public_nonce,
        session,
        summary,
    })
}

/// The coin this request spends, as the ledger keys it.
fn coin_key(request: &SigningRequest) -> Result<OutPointKey, String> {
    let psbt = decode(request)?;
    let idx = request.input_index as usize;
    let input = psbt
        .unsigned_tx
        .input
        .get(idx)
        .ok_or_else(|| format!("input {idx} does not exist"))?;
    Ok(OutPointKey::new(
        input.previous_output.txid.to_raw_hash().to_byte_array(),
        input.previous_output.vout,
    ))
}

/// The transaction this request would complete.
fn spending_txid(request: &SigningRequest) -> Result<[u8; 32], String> {
    let psbt = decode(request)?;
    Ok(psbt
        .unsigned_tx
        .compute_txid()
        .to_raw_hash()
        .to_byte_array())
}

fn decode(request: &SigningRequest) -> Result<bitcoin::psbt::Psbt, String> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(request.psbt.trim())
        .map_err(|e| format!("psbt is not base64: {e}"))?;
    bitcoin::psbt::Psbt::deserialize(&raw).map_err(|e| format!("psbt: {e}"))
}

use bitcoin::hashes::Hash as _;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing_ledger::VolatileStore;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use bitcoin::{
        absolute::LockTime, psbt::Psbt, transaction::Version, Amount, Network, OutPoint, ScriptBuf,
        Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };
    use ghost_lock::lane::SpendingPolicy;
    use ghost_lock::signing::{combine, SigningSession, VolatileNonceLedger};
    use std::str::FromStr;

    fn sk(b: u8) -> SecretKey {
        SecretKey::from_slice(&[b; 32]).unwrap()
    }
    fn xo(s: &SecretKey) -> XOnlyPublicKey {
        Keypair::from_secret_key(&Secp256k1::new(), s)
            .x_only_public_key()
            .0
    }

    /// A Spending lane and a spend of it.
    fn fixture(
        input_sats: u64,
        vout: u32,
    ) -> (ghost_lock::lane::Lane, SecretKey, SecretKey, SigningRequest) {
        let owner = sk(91);
        let quorum = sk(92);
        let lane = SpendingPolicy {
            aggregate: ghost_lock::key_agg::aggregate(&[xo(&owner), xo(&quorum)]).unwrap(),
            owner: xo(&owner),
        }
        .build(&Secp256k1::new(), Network::Regtest)
        .unwrap();

        let prevout = TxOut {
            value: Amount::from_sat(input_sats),
            script_pubkey: lane.address.script_pubkey(),
        };
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(
                        "0000000000000000000000000000000000000000000000000000000000000004",
                    )
                    .unwrap(),
                    vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(input_sats - 1_000),
                script_pubkey: lane.address.script_pubkey(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(prevout);

        use base64::Engine as _;
        let req = SigningRequest {
            psbt: base64::engine::general_purpose::STANDARD.encode(psbt.serialize()),
            input_index: 0,
            keys: vec![
                hex::encode(xo(&owner).serialize()),
                hex::encode(xo(&quorum).serialize()),
            ],
            merkle_root: lane
                .spend_info
                .merkle_root()
                .map(|r| hex::encode(r.to_byte_array())),
        };
        (lane, owner, quorum, req)
    }

    /// **The whole point: the quorum completes what the owner started.**
    #[test]
    fn the_quorum_co_signs_and_the_lane_accepts_it() {
        let secp = Secp256k1::new();
        let (lane, owner, quorum, req) = fixture(100_000, 0);
        let keys = ghost_lock::airgap::keys(&req).unwrap();
        let root = ghost_lock::airgap::merkle_root(&req).unwrap();
        let (_, message) = review(&req, Network::Regtest).unwrap();

        let mut coins = SigningLedger::new(VolatileStore::default());
        let q = begin_cosign(
            &req,
            Network::Regtest,
            CosignPolicy::default(),
            &mut coins,
            &quorum,
            &keys,
            root,
        )
        .expect("the quorum agrees");

        let (owner_session, owner_commit) =
            SigningSession::begin(&keys, &owner, root, &message).unwrap();
        let mut nonces = vec![owner_commit.public_nonce, q.public_nonce()];
        nonces.sort_unstable();

        let mut qn = VolatileNonceLedger::default();
        let mut on = VolatileNonceLedger::default();
        let q_partial = q.sign(&mut qn, &nonces).expect("quorum round 2");
        let o_partial = owner_session.sign(&mut on, &nonces).expect("owner round 2");

        let sig = combine(&keys, root, &nonces, &[o_partial, q_partial], &message).unwrap();
        let out = lane.spend_info.output_key().to_x_only_public_key();
        secp.verify_schnorr(&sig, &Message::from_digest(message), &out)
            .expect("the lane must accept the pair's signature");
    }

    /// **A ceiling is what makes the quorum a second factor.**
    ///
    /// Without one a stolen owner key gets the balance, because the quorum
    /// simply agrees. With one it gets the ceiling, and the owner keeps the
    /// exit leaf for the rest.
    #[test]
    fn a_spend_above_the_ceiling_is_refused() {
        let (_, _, quorum, req) = fixture(500_000, 0);
        let keys = ghost_lock::airgap::keys(&req).unwrap();
        let root = ghost_lock::airgap::merkle_root(&req).unwrap();
        let mut coins = SigningLedger::new(VolatileStore::default());

        let err = begin_cosign(
            &req,
            Network::Regtest,
            CosignPolicy {
                max_spend_sats: Some(100_000),
            },
            &mut coins,
            &quorum,
            &keys,
            root,
        )
        .expect_err("above the ceiling");
        let msg = format!("{err}");
        assert!(msg.contains("500000"), "{msg}");
        assert!(
            msg.contains("exit leaf"),
            "a refusal must leave the owner a way out: {msg}"
        );
    }

    /// A refusal must not consume a nonce.
    ///
    /// Otherwise submitting spends the quorum was always going to reject would
    /// burn its willingness to sign — a denial of service dressed as a policy
    /// check.
    #[test]
    fn a_refused_spend_leaves_the_coin_uncommitted() {
        let (_, _, quorum, req) = fixture(500_000, 0);
        let keys = ghost_lock::airgap::keys(&req).unwrap();
        let root = ghost_lock::airgap::merkle_root(&req).unwrap();
        let mut coins = SigningLedger::new(VolatileStore::default());
        let policy = CosignPolicy {
            max_spend_sats: Some(100_000),
        };

        assert!(begin_cosign(
            &req,
            Network::Regtest,
            policy,
            &mut coins,
            &quorum,
            &keys,
            root
        )
        .is_err());

        // The same coin, now within a ceiling that allows it, must still work:
        // the refusal must not have committed anything.
        let ok = begin_cosign(
            &req,
            Network::Regtest,
            CosignPolicy {
                max_spend_sats: Some(1_000_000),
            },
            &mut coins,
            &quorum,
            &keys,
            root,
        );
        assert!(
            ok.is_ok(),
            "a rejected request must not have consumed the coin"
        );
    }

    /// **Never equivocate.** Two different spends of one coin is the fraud the
    /// design promises cannot happen.
    #[test]
    fn a_second_different_spend_of_one_coin_is_refused() {
        let (_, _, quorum, first) = fixture(100_000, 0);
        let keys = ghost_lock::airgap::keys(&first).unwrap();
        let root = ghost_lock::airgap::merkle_root(&first).unwrap();
        let mut coins = SigningLedger::new(VolatileStore::default());

        begin_cosign(
            &first,
            Network::Regtest,
            CosignPolicy::default(),
            &mut coins,
            &quorum,
            &keys,
            root,
        )
        .expect("first spend");

        // Same coin, different amount → different transaction.
        let (_, _, _, second) = fixture(100_000 - 500, 0);
        let err = begin_cosign(
            &second,
            Network::Regtest,
            CosignPolicy::default(),
            &mut coins,
            &quorum,
            &keys,
            root,
        )
        .expect_err("a second spend of one coin must be refused");
        assert!(format!("{err}").contains("equivocate"), "{err}");
        assert_eq!(coins.refusals(), 1, "the attempt must be counted");
    }

    /// Retrying the identical spend is a retry, not an attack.
    #[test]
    fn the_same_spend_twice_is_allowed() {
        let (_, _, quorum, req) = fixture(100_000, 0);
        let keys = ghost_lock::airgap::keys(&req).unwrap();
        let root = ghost_lock::airgap::merkle_root(&req).unwrap();
        let mut coins = SigningLedger::new(VolatileStore::default());

        for _ in 0..2 {
            begin_cosign(
                &req,
                Network::Regtest,
                CosignPolicy::default(),
                &mut coins,
                &quorum,
                &keys,
                root,
            )
            .expect("a retry of the same spend is not equivocation");
        }
        assert_eq!(coins.refusals(), 0);
    }
}
