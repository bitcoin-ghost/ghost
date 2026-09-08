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

/// A rolling total the quorum will not co-sign past.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VelocityLimit {
    /// Most the quorum will co-sign within one window.
    pub max_sats: u64,
    /// How long the window is, in seconds.
    pub window_secs: u64,
}

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
    /// Rolling total across a window.
    ///
    /// **A ceiling alone does not bound a theft.** Somebody holding the
    /// owner's key simply spends the ceiling ten times; the ceiling costs them
    /// ten transactions and ten fees and stops nothing. The window is what
    /// turns a speed bump into a wall, and a ceiling configured without one
    /// invites trusting protection that is not there.
    pub window: Option<VelocityLimit>,
}

/// What the quorum has already co-signed, and when.
///
/// # This must survive a restart
///
/// A window kept only in memory is bypassed by crashing the service: the total
/// resets and the next window starts empty. That is a cheaper attack than
/// stealing the key it is supposed to bound, so an implementation that forgets
/// is worse than no limit at all — it reports a protection it does not have.
pub trait SpendLog {
    /// Total co-signed at or after `since_secs`.
    fn total_since(&self, since_secs: u64) -> u64;
    /// Record a co-signature. Must be durable before it returns.
    fn record(&mut self, at_secs: u64, sats: u64) -> Result<(), String>;
}

/// An in-memory [`SpendLog`], for tests.
///
/// Named to be uncomfortable to type in production, because forgetting is the
/// exact failure the trait's contract is about.
#[derive(Debug, Default)]
pub struct VolatileSpendLog {
    entries: Vec<(u64, u64)>,
}

impl SpendLog for VolatileSpendLog {
    fn total_since(&self, since_secs: u64) -> u64 {
        self.entries
            .iter()
            .filter(|(at, _)| *at >= since_secs)
            .map(|(_, sats)| *sats)
            .sum()
    }
    fn record(&mut self, at_secs: u64, sats: u64) -> Result<(), String> {
        self.entries.push((at_secs, sats));
        Ok(())
    }
}

/// Whether this coordinator may co-sign Locks right now.
///
/// # Only one may
///
/// Every coordinator holding the quorum seed can derive the same key, which is
/// what makes failover work. But each keeps its own once-per-coin ledger, so
/// two of them serving at once can be asked to co-sign two *different* spends
/// of one coin — and both would agree, producing a valid double-sign proof
/// against the quorum. That is the fraud the design promises cannot happen,
/// reintroduced by redundancy.
///
/// So Lock co-signing is the Active coordinator's job alone. A Standby holding
/// the same seed must refuse, and refuse structurally rather than by
/// convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Serving. May co-sign.
    Active,
    /// Ready to take over, and must not co-sign until it has.
    Standby,
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
    /// The window's total would be exceeded.
    #[error(
        "this spend would take the last {window_secs}s to {would_total} sats and the \
         quorum's limit is {limit_sats}; it will not co-sign. Wait for the window to \
         clear, or use the Spending exit leaf."
    )]
    AboveWindow {
        /// What the total would become.
        would_total: u64,
        /// The configured limit.
        limit_sats: u64,
        /// The window's length.
        window_secs: u64,
    },
    /// This coordinator is not the one that co-signs.
    #[error(
        "this coordinator is on standby and does not co-sign Locks; only the active one \
         does, because two ledgers can be asked to sign two different spends of one coin"
    )]
    NotActive,
    /// The spend log could not be written, so the window is unknown.
    #[error("the spend log is unavailable ({0}); refusing rather than co-signing past a limit it cannot see")]
    LogUnavailable(String),
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
pub fn begin_cosign<S: SignatureStore, L: SpendLog>(
    request: &SigningRequest,
    network: bitcoin::Network,
    policy: CosignPolicy,
    role: Role,
    coins: &mut SigningLedger<S>,
    spends: &mut L,
    now_secs: u64,
    quorum_key: &bitcoin::secp256k1::SecretKey,
    keys: &[XOnlyPublicKey],
    merkle_root: Option<bitcoin::TapNodeHash>,
) -> Result<CosignSession, CosignRefusal> {
    // Before anything else. A standby that got as far as reading the request
    // is a standby that could get as far as signing it.
    if role != Role::Active {
        return Err(CosignRefusal::NotActive);
    }

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

    let coin = coin_key(request).map_err(CosignRefusal::Unreadable)?;
    let txid = spending_txid(request).map_err(CosignRefusal::Unreadable)?;

    // Is this the same transaction we already committed to? Asked before any
    // rule is applied, and answered without committing anything.
    //
    // A retry must skip the window entirely. Checking it first and committing
    // after looked right and was not: the window already holds this spend, so
    // the check counts it twice and refuses the retry. Committing first
    // instead would lock the coin to a transaction that was never signed.
    // Neither order works without knowing, so the ledger is asked.
    let is_retry = coins.is_committed_to(&coin, &txid);

    // The window is checked before the coin is committed, so a refused spend
    // leaves nothing behind.
    if let (false, Some(limit)) = (is_retry, policy.window) {
        let since = now_secs.saturating_sub(limit.window_secs);
        let would_total = spends.total_since(since).saturating_add(summary.input_sats);
        if would_total > limit.max_sats {
            return Err(CosignRefusal::AboveWindow {
                would_total,
                limit_sats: limit.max_sats,
                window_secs: limit.window_secs,
            });
        }
    }

    // Commit the coin before signing. The ledger is idempotent, so a retry of
    // the same spend is allowed through; a *different* spend of the same coin
    // is refused, which is the equivocation guarantee.
    let decision = match coins.authorise(coin, txid) {
        Ok(d) => d,
        Err(e) => return Err(CosignRefusal::WouldEquivocate(e)),
    };

    // Count the spend only when it is new. A retry of one transaction is one
    // spend, and charging the window twice for it would refuse honest retries
    // — turning a network hiccup into a lockout.
    if decision == Decision::Sign && policy.window.is_some() {
        spends
            .record(now_secs, summary.input_sats)
            .map_err(CosignRefusal::LogUnavailable)?;
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
            Role::Active,
            &mut coins,
            &mut VolatileSpendLog::default(),
            0,
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
                ..Default::default()
            },
            Role::Active,
            &mut coins,
            &mut VolatileSpendLog::default(),
            0,
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
            ..Default::default()
        };

        assert!(begin_cosign(
            &req,
            Network::Regtest,
            policy,
            Role::Active,
            &mut coins,
            &mut VolatileSpendLog::default(),
            0,
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
                ..Default::default()
            },
            Role::Active,
            &mut coins,
            &mut VolatileSpendLog::default(),
            0,
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
            Role::Active,
            &mut coins,
            &mut VolatileSpendLog::default(),
            0,
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
            Role::Active,
            &mut coins,
            &mut VolatileSpendLog::default(),
            0,
            &quorum,
            &keys,
            root,
        )
        .expect_err("a second spend of one coin must be refused");
        assert!(format!("{err}").contains("equivocate"), "{err}");
        assert_eq!(coins.refusals(), 1, "the attempt must be counted");
    }

    fn active(
        req: &SigningRequest,
        policy: CosignPolicy,
        coins: &mut SigningLedger<VolatileStore>,
        spends: &mut VolatileSpendLog,
        now: u64,
        quorum: &SecretKey,
    ) -> Result<CosignSession, CosignRefusal> {
        let keys = ghost_lock::airgap::keys(req).unwrap();
        let root = ghost_lock::airgap::merkle_root(req).unwrap();
        begin_cosign(
            req,
            Network::Regtest,
            policy,
            Role::Active,
            coins,
            spends,
            now,
            quorum,
            &keys,
            root,
        )
    }

    /// **A ceiling alone does not bound a theft.**
    ///
    /// Ten spends of the ceiling drain what one spend of ten times it could
    /// not. The window is what turns the speed bump into a wall, and this is
    /// the test that would fail if the window were only decorative.
    #[test]
    fn repeated_spends_under_the_ceiling_hit_the_window() {
        let (_, _, quorum, _) = fixture(100_000, 0);
        let policy = CosignPolicy {
            max_spend_sats: Some(100_000),
            window: Some(VelocityLimit {
                max_sats: 250_000,
                window_secs: 86_400,
            }),
        };
        let mut coins = SigningLedger::new(VolatileStore::default());
        let mut spends = VolatileSpendLog::default();

        // Each is under the ceiling; each is a different coin.
        for vout in 0..2u32 {
            let (_, _, _, req) = fixture(100_000, vout);
            active(&req, policy, &mut coins, &mut spends, 0, &quorum)
                .unwrap_or_else(|e| panic!("spend {vout} should pass: {e}"));
        }

        let (_, _, _, third) = fixture(100_000, 2);
        let err = active(&third, policy, &mut coins, &mut spends, 0, &quorum)
            .expect_err("the third spend crosses the window");
        let msg = format!("{err}");
        assert!(msg.contains("300000"), "{msg}");
        assert!(
            msg.contains("exit leaf"),
            "a refusal must leave the owner a way out: {msg}"
        );
    }

    /// The window rolls: once it has passed, spending resumes.
    #[test]
    fn the_window_clears_with_time() {
        let (_, _, quorum, _) = fixture(100_000, 0);
        let policy = CosignPolicy {
            max_spend_sats: None,
            window: Some(VelocityLimit {
                max_sats: 150_000,
                window_secs: 3_600,
            }),
        };
        let mut coins = SigningLedger::new(VolatileStore::default());
        let mut spends = VolatileSpendLog::default();

        let (_, _, _, a) = fixture(100_000, 0);
        active(&a, policy, &mut coins, &mut spends, 1_000, &quorum).expect("first");

        let (_, _, _, b) = fixture(100_000, 1);
        assert!(
            active(&b, policy, &mut coins, &mut spends, 1_500, &quorum).is_err(),
            "still inside the window"
        );
        assert!(
            active(&b, policy, &mut coins, &mut spends, 10_000, &quorum).is_ok(),
            "the window has rolled past the first spend"
        );
    }

    /// A retry must not be charged to the window twice.
    ///
    /// Otherwise a network hiccup turns into a lockout: the caller retries one
    /// spend and the quorum counts it as two.
    #[test]
    fn a_retry_is_charged_once() {
        let (_, _, quorum, req) = fixture(100_000, 0);
        let policy = CosignPolicy {
            max_spend_sats: None,
            window: Some(VelocityLimit {
                max_sats: 150_000,
                window_secs: 86_400,
            }),
        };
        let mut coins = SigningLedger::new(VolatileStore::default());
        let mut spends = VolatileSpendLog::default();

        for attempt in 0..3 {
            active(&req, policy, &mut coins, &mut spends, 0, &quorum)
                .unwrap_or_else(|e| panic!("retry {attempt} must be allowed: {e}"));
        }
        assert_eq!(
            spends.total_since(0),
            100_000,
            "one transaction is one spend, however many times it is asked for"
        );
    }

    /// A refused spend leaves the window untouched.
    #[test]
    fn a_refusal_does_not_consume_the_window() {
        let (_, _, quorum, req) = fixture(500_000, 0);
        let mut coins = SigningLedger::new(VolatileStore::default());
        let mut spends = VolatileSpendLog::default();

        assert!(active(
            &req,
            CosignPolicy {
                max_spend_sats: Some(100_000),
                window: Some(VelocityLimit {
                    max_sats: 10_000_000,
                    window_secs: 86_400
                }),
            },
            &mut coins,
            &mut spends,
            0,
            &quorum
        )
        .is_err());
        assert_eq!(spends.total_since(0), 0, "a refusal spends nothing");
    }

    /// **Only the active coordinator co-signs.**
    ///
    /// Two coordinators with the same seed and separate ledgers can be asked
    /// to sign two different spends of one coin, and both would agree — a
    /// double-sign proof against the quorum, reintroduced by redundancy.
    #[test]
    fn a_standby_refuses_before_it_reads_anything() {
        let (_, _, quorum, req) = fixture(100_000, 0);
        let keys = ghost_lock::airgap::keys(&req).unwrap();
        let root = ghost_lock::airgap::merkle_root(&req).unwrap();
        let mut coins = SigningLedger::new(VolatileStore::default());
        let mut spends = VolatileSpendLog::default();

        let err = begin_cosign(
            &req,
            Network::Regtest,
            CosignPolicy::default(),
            Role::Standby,
            &mut coins,
            &mut spends,
            0,
            &quorum,
            &keys,
            root,
        )
        .expect_err("a standby must not co-sign");
        assert!(format!("{err}").contains("standby"), "{err}");
        assert_eq!(
            spends.total_since(0),
            0,
            "a standby must not touch the window either"
        );
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
                Role::Active,
                &mut coins,
                &mut VolatileSpendLog::default(),
                0,
                &quorum,
                &keys,
                root,
            )
            .expect("a retry of the same spend is not equivocation");
        }
        assert_eq!(coins.refusals(), 0);
    }
}
