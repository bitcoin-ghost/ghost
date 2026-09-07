//! MuSig2 signing for a Lock's key path.
//!
//! # Aggregation needed no ceremony. This does.
//!
//! [`crate::key_agg`] builds the aggregate key alone, offline, from public keys
//! — BIP-327 key aggregation is a deterministic function and nobody needs to be
//! online for it. Spending by the key path is the opposite: two rounds of live
//! exchange, nonces first and partial signatures second.
//!
//! This module is the half that needs no transport. It produces the bytes a
//! party must send and consumes the bytes it receives; how they travel — to a
//! backup device over a cable, to the quorum over HTTP — is not decided here.
//!
//! # A nonce reused is a private key published
//!
//! This is the whole reason the module is shaped the way it is. Sign two
//! different messages with one MuSig2 secret nonce and the two partial
//! signatures are a pair of linear equations in one unknown. Anyone who sees
//! both recovers the signer's secret key. Not "weakens"; recovers.
//!
//! Three things stop that here, and they are deliberately layered, because the
//! first two only hold within one process:
//!
//! 1. **The message is bound at nonce creation.** [`SigningSession::begin`]
//!    takes the sighash and mixes it into the nonce. There is no method that
//!    signs a *different* message, so the dangerous operation is not something
//!    a caller can express.
//! 2. **Signing consumes the session.** [`SigningSession::sign`] takes `self`
//!    by value, so a second partial signature from one nonce is a compile
//!    error rather than a runtime check somebody can forget.
//! 3. **A ledger refuses a repeat across restarts.** The type system cannot
//!    see a process that died and came back, which is exactly when a naive
//!    implementation regenerates a nonce for a session it already signed. See
//!    [`NonceLedger`].
//!
//! Layer 3 is the one that needs real storage, and it is the one a test double
//! silently removes — hence the name [`VolatileNonceLedger`].

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::schnorr;
use bitcoin::{TapNodeHash, XOnlyPublicKey};

use crate::error::LockError;

/// Identifies one signing attempt: this Lock, this input, this sighash.
///
/// Derived from the message rather than chosen, so two parties agree on it
/// without negotiating, and so a caller cannot accidentally reuse an id across
/// two different spends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId([u8; 32]);

impl SessionId {
    /// The session a given sighash belongs to.
    pub fn for_message(message: &[u8; 32]) -> Self {
        SessionId(*message)
    }

    /// Raw bytes, for a ledger key or a wire field.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Remembers which sessions have had a secret nonce issued.
///
/// # The contract
///
/// [`claim`](NonceLedger::claim) must return `Ok` **at most once** for a given
/// [`SessionId`], and that fact must survive a crash between the claim and the
/// signature. An implementation that keeps this in memory satisfies the letter
/// of the trait and not its purpose: a daemon that restarts mid-round would
/// re-issue a nonce for a session it had already signed, and the two partial
/// signatures would publish the owner's key.
///
/// Write before returning `Ok`, and fsync. This is the same shape as the
/// once-per-coin rule the wallet enforces for rounds, and it fails the same
/// way when it is treated as bookkeeping.
pub trait NonceLedger {
    /// Reserve `id`. `Err` if it has been reserved before.
    fn claim(&mut self, id: &SessionId) -> Result<(), LockError>;
}

/// An in-memory [`NonceLedger`], for tests.
///
/// Named to be uncomfortable to type in production, because it is exactly the
/// implementation that looks like it works: correct for as long as the process
/// lives, and silently catastrophic across the restart it cannot see.
#[derive(Debug, Default)]
pub struct VolatileNonceLedger {
    claimed: std::collections::BTreeSet<SessionId>,
}

impl NonceLedger for VolatileNonceLedger {
    fn claim(&mut self, id: &SessionId) -> Result<(), LockError> {
        if !self.claimed.insert(*id) {
            return Err(LockError::Policy(format!(
                "a secret nonce was already issued for session {} — issuing a second \
                 one and signing with both publishes this key",
                hex::encode(id.as_bytes())
            )));
        }
        Ok(())
    }
}

/// What a party broadcasts in round 1.
#[derive(Debug, Clone)]
pub struct NonceCommitment {
    /// Which signing attempt this belongs to.
    pub session: SessionId,
    /// The party's public nonce, serialised.
    pub public_nonce: [u8; 66],
}

/// A party's in-progress signature. Round 1 done, round 2 pending.
///
/// Holds a secret nonce, so it is neither `Clone` nor `Copy`: duplicating it is
/// the one thing that must not be possible.
pub struct SigningSession {
    ctx: musig2::KeyAggContext,
    seckey: musig2::secp::Scalar,
    secnonce: musig2::SecNonce,
    message: [u8; 32],
    session: SessionId,
}

impl std::fmt::Debug for SigningSession {
    /// Deliberately opaque. A secret nonce that reaches a log is as spent as
    /// one that reaches a second signature.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningSession")
            .field("session", &hex::encode(self.session.as_bytes()))
            .finish_non_exhaustive()
    }
}

/// Lift an x-only key to its even-Y point, the way BIP-340 verification does.
///
/// Same convention as [`crate::key_agg`], and for the same reason: the two
/// modules must agree on what an `XOnlyPublicKey` means or they will build
/// different aggregates from one key set.
fn lift(key: &XOnlyPublicKey) -> Result<musig2::secp256k1::PublicKey, LockError> {
    let mut sec1 = [0u8; 33];
    sec1[0] = 0x02;
    sec1[1..].copy_from_slice(&key.serialize());
    musig2::secp256k1::PublicKey::from_slice(&sec1)
        .map_err(|e| LockError::Policy(format!("key is not a valid point: {e}")))
}

/// Build the aggregation context for a lane's key path.
///
/// The keys are sorted exactly as [`crate::key_agg::aggregate`] sorts them —
/// if these two ever disagreed, the wallet would sign under a key that is not
/// the one in the output, and the failure would surface as an invalid
/// signature with no indication of why.
///
/// `merkle_root` is the lane's script tree. A Taproot output commits to it, so
/// the key path spends with the **tweaked** aggregate; signing under the raw
/// aggregate produces a signature that does not verify against the address the
/// coins are actually in.
fn context(
    keys: &[XOnlyPublicKey],
    merkle_root: Option<TapNodeHash>,
) -> Result<musig2::KeyAggContext, LockError> {
    if keys.len() < 2 {
        return Err(LockError::Policy(format!(
            "MuSig2 signing needs at least two keys, got {}",
            keys.len()
        )));
    }
    let mut sorted: Vec<&XOnlyPublicKey> = keys.iter().collect();
    sorted.sort_unstable_by_key(|k| k.serialize());

    let mut pubkeys = Vec::with_capacity(sorted.len());
    for k in sorted {
        pubkeys.push(lift(k)?);
    }
    let ctx = musig2::KeyAggContext::new(pubkeys)
        .map_err(|e| LockError::Policy(format!("key aggregation failed: {e}")))?;

    match merkle_root {
        Some(root) => ctx
            .with_taproot_tweak(root.as_raw_hash().as_byte_array())
            .map_err(|e| LockError::Policy(format!("taproot tweak failed: {e}"))),
        None => ctx
            .with_unspendable_taproot_tweak()
            .map_err(|e| LockError::Policy(format!("taproot tweak failed: {e}"))),
    }
}

/// The x-only key a lane's key path actually verifies against.
///
/// This is the tweaked aggregate — the output key. Exposed so a caller can
/// check it equals the address it is about to spend from *before* a round
/// starts, rather than discovering the mismatch from a rejected signature.
pub fn output_key(
    keys: &[XOnlyPublicKey],
    merkle_root: Option<TapNodeHash>,
) -> Result<XOnlyPublicKey, LockError> {
    let ctx = context(keys, merkle_root)?;
    let agg: musig2::secp256k1::PublicKey = ctx.aggregated_pubkey();
    let (xonly, _parity) = agg.x_only_public_key();
    XOnlyPublicKey::from_slice(&xonly.serialize())
        .map_err(|e| LockError::Policy(format!("aggregate is not a valid x-only key: {e}")))
}

impl SigningSession {
    /// Round 1. Generate this party's secret nonce and the commitment to share.
    ///
    /// `message` is the sighash being signed and is bound into the nonce here.
    /// That binding is the point: this session can produce a signature over
    /// this message and no other.
    ///
    /// `ledger` is consulted before any nonce exists, so a session that has
    /// been signed before fails without generating one.
    pub fn begin<L: NonceLedger>(
        ledger: &mut L,
        keys: &[XOnlyPublicKey],
        own_seckey: &bitcoin::secp256k1::SecretKey,
        merkle_root: Option<TapNodeHash>,
        message: &[u8; 32],
    ) -> Result<(Self, NonceCommitment), LockError> {
        let session = SessionId::for_message(message);
        ledger.claim(&session)?;

        let ctx = context(keys, merkle_root)?;

        // Match the scalar to the point the group actually contains.
        //
        // `lift` takes every x-only key to its EVEN-Y point, as BIP-340
        // verification does. A secret key whose own point has odd Y is
        // therefore not a member of that group, and `sign_partial` rejects it
        // with "signing key is not a member of the group" — which is what
        // happens, because roughly half of all keys have odd Y.
        //
        // Negating the scalar gives the key for the even-Y point, which is the
        // same convention BIP-340 signing uses. This is not a workaround: it
        // is the counterpart of the lift, and omitting it makes the module
        // work for half the keys anybody tries.
        let (_, parity) = own_seckey.x_only_public_key(&bitcoin::secp256k1::Secp256k1::new());
        let normalised = match parity {
            bitcoin::secp256k1::Parity::Even => *own_seckey,
            bitcoin::secp256k1::Parity::Odd => own_seckey.negate(),
        };
        let seckey = musig2::secp::Scalar::from_slice(&normalised.secret_bytes())
            .map_err(|e| LockError::Policy(format!("signing key is not a valid scalar: {e}")))?;

        let mut seed = [0u8; 32];
        getrandom_seed(&mut seed)?;

        // `from_seckey` derives the party's point itself, so the nonce cannot
        // be bound to a pubkey that is not the signing key's — a mismatch
        // `sign_partial` would otherwise only catch at round 2.
        let secnonce = musig2::SecNonceBuilder::from_seckey(seed, seckey)
            .with_message(message)
            .build();

        let commitment = NonceCommitment {
            session,
            public_nonce: secnonce.public_nonce().serialize(),
        };
        Ok((
            SigningSession {
                ctx,
                seckey,
                secnonce,
                message: *message,
                session,
            },
            commitment,
        ))
    }

    /// The session this signature belongs to.
    pub fn session(&self) -> SessionId {
        self.session
    }

    /// Round 2. Combine the other parties' nonces and produce this party's
    /// partial signature.
    ///
    /// Takes `self` by value. The secret nonce is moved out and dropped with
    /// the session, so there is no way to sign twice with it — that is a
    /// compile error, not a check.
    pub fn sign(self, public_nonces: &[[u8; 66]]) -> Result<[u8; 32], LockError> {
        if public_nonces.is_empty() {
            return Err(LockError::Policy(
                "no public nonces: a MuSig2 signature needs every party's round-1 output".into(),
            ));
        }
        let mut nonces = Vec::with_capacity(public_nonces.len());
        for n in public_nonces {
            nonces.push(
                musig2::PubNonce::from_bytes(n)
                    .map_err(|e| LockError::Policy(format!("bad public nonce: {e}")))?,
            );
        }
        let agg = musig2::AggNonce::sum(&nonces);

        let partial: musig2::PartialSignature =
            musig2::sign_partial(&self.ctx, self.seckey, self.secnonce, &agg, self.message)
                .map_err(|e| LockError::Policy(format!("partial signature failed: {e}")))?;
        Ok(partial.serialize())
    }
}

/// Combine every party's partial signature into the final Schnorr signature.
///
/// Verifies as it aggregates: an invalid result is an error rather than a
/// signature that fails later, in a broadcast, with no indication of which
/// party produced the bad share.
pub fn combine(
    keys: &[XOnlyPublicKey],
    merkle_root: Option<TapNodeHash>,
    public_nonces: &[[u8; 66]],
    partials: &[[u8; 32]],
    message: &[u8; 32],
) -> Result<schnorr::Signature, LockError> {
    let ctx = context(keys, merkle_root)?;

    let mut nonces = Vec::with_capacity(public_nonces.len());
    for n in public_nonces {
        nonces.push(
            musig2::PubNonce::from_bytes(n)
                .map_err(|e| LockError::Policy(format!("bad public nonce: {e}")))?,
        );
    }
    let agg = musig2::AggNonce::sum(&nonces);

    let mut shares = Vec::with_capacity(partials.len());
    for p in partials {
        shares.push(
            musig2::PartialSignature::from_slice(p)
                .map_err(|e| LockError::Policy(format!("bad partial signature: {e}")))?,
        );
    }

    let sig: musig2::LiftedSignature =
        musig2::aggregate_partial_signatures(&ctx, &agg, shares, message)
            .map_err(|e| LockError::Policy(format!("aggregation failed: {e}")))?;

    schnorr::Signature::from_slice(&sig.serialize())
        .map_err(|e| LockError::Policy(format!("aggregate is not a Schnorr signature: {e}")))
}

/// Fill `buf` from the OS random source.
///
/// Split out so the failure is an error rather than a panic: a nonce seeded
/// from a degraded RNG is the same catastrophe as a reused one, so refusing to
/// produce one is the only safe response.
fn getrandom_seed(buf: &mut [u8; 32]) -> Result<(), LockError> {
    use rand::RngCore;
    rand::rngs::OsRng
        .try_fill_bytes(buf)
        .map_err(|e| LockError::Policy(format!("no secure randomness for a nonce seed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lane::SavingsPolicy;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use bitcoin::Network;

    fn sk(b: u8) -> SecretKey {
        SecretKey::from_slice(&[b.max(1); 32]).expect("valid scalar")
    }

    fn xonly(s: &SecretKey) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        Keypair::from_secret_key(&secp, s).x_only_public_key().0
    }

    /// The ledger's whole job, and the failure it exists to prevent.
    #[test]
    fn a_session_can_only_claim_a_nonce_once() {
        let mut ledger = VolatileNonceLedger::default();
        let id = SessionId::for_message(&[7u8; 32]);
        assert!(ledger.claim(&id).is_ok());
        let err = ledger
            .claim(&id)
            .expect_err("a second nonce for one session publishes the key");
        assert!(
            format!("{err}").contains("publishes this key"),
            "the refusal must say why it matters: {err}"
        );
    }

    /// A different message is a different session, so it claims cleanly.
    #[test]
    fn a_different_message_is_a_different_session() {
        let mut ledger = VolatileNonceLedger::default();
        assert!(ledger.claim(&SessionId::for_message(&[1u8; 32])).is_ok());
        assert!(ledger.claim(&SessionId::for_message(&[2u8; 32])).is_ok());
    }

    /// **The test that proves the tweak.**
    ///
    /// The key a lane's key path verifies against is the *tweaked* aggregate,
    /// not the raw one. If [`output_key`] and the lane disagreed, every
    /// key-path spend would produce a signature that fails against the address
    /// the coins are in — and it would fail at broadcast, far from the cause.
    #[test]
    fn the_signing_key_is_the_key_in_the_lane_s_address() {
        let secp = Secp256k1::new();
        let owner = sk(11);
        let backup = sk(12);
        let aggregate =
            crate::key_agg::aggregate(&[xonly(&owner), xonly(&backup)]).expect("aggregates");

        let lane = SavingsPolicy {
            aggregate,
            owner: xonly(&owner),
            backup: xonly(&backup),
            heir: xonly(&sk(13)),
            inherit_height: 1_000_000,
        }
        .build(&secp, 900_000, Network::Regtest)
        .expect("builds");

        let derived = output_key(
            &[xonly(&owner), xonly(&backup)],
            lane.spend_info.merkle_root(),
        )
        .expect("derives");

        assert_eq!(
            derived,
            lane.spend_info.output_key().to_x_only_public_key(),
            "the key we sign under must be the key the address commits to"
        );
    }

    /// End to end: two parties, two rounds, one signature that verifies
    /// against the lane's own output key.
    #[test]
    fn two_parties_sign_a_lane_s_key_path() {
        let secp = Secp256k1::new();
        let owner = sk(21);
        let backup = sk(22);
        let keys = [xonly(&owner), xonly(&backup)];
        let aggregate = crate::key_agg::aggregate(&keys).expect("aggregates");

        let lane = SavingsPolicy {
            aggregate,
            owner: keys[0],
            backup: keys[1],
            heir: xonly(&sk(23)),
            inherit_height: 1_000_000,
        }
        .build(&secp, 900_000, Network::Regtest)
        .expect("builds");
        let root = lane.spend_info.merkle_root();

        let message = [0x42u8; 32];

        // Each party keeps its own ledger — they are separate devices.
        let mut owner_ledger = VolatileNonceLedger::default();
        let mut backup_ledger = VolatileNonceLedger::default();

        // Round 1: nonces.
        let (owner_session, owner_commit) =
            SigningSession::begin(&mut owner_ledger, &keys, &owner, root, &message)
                .expect("owner round 1");
        let (backup_session, backup_commit) =
            SigningSession::begin(&mut backup_ledger, &keys, &backup, root, &message)
                .expect("backup round 1");

        assert_eq!(
            owner_commit.session, backup_commit.session,
            "both parties derive the same session id from the message, without negotiating"
        );

        let nonces = [owner_commit.public_nonce, backup_commit.public_nonce];

        // Round 2: partial signatures.
        let owner_partial = owner_session.sign(&nonces).expect("owner round 2");
        let backup_partial = backup_session.sign(&nonces).expect("backup round 2");

        let sig = combine(
            &keys,
            root,
            &nonces,
            &[owner_partial, backup_partial],
            &message,
        )
        .expect("combines");

        // The proof: BIP-340 verification against the address's own key.
        let out = lane.spend_info.output_key().to_x_only_public_key();
        secp.verify_schnorr(&sig, &Message::from_digest(message), &out)
            .expect("the signature must verify against the lane's output key");
    }

    /// Signing must work whatever the parity of a party's key.
    ///
    /// `lift` takes every x-only key to its even-Y point, so a signer whose own
    /// point has odd Y is not in the group unless its scalar is negated. This
    /// found a real bug: without the negation the module signed successfully
    /// for even-Y keys and failed with "signing key is not a member of the
    /// group" for odd-Y ones — roughly half of all keys, depending entirely on
    /// which fixtures a test happened to pick.
    ///
    /// So this test asserts on the parities it uses, rather than trusting that
    /// some fixture somewhere covers both.
    #[test]
    fn signing_works_for_both_key_parities() {
        use bitcoin::secp256k1::Parity;
        let secp = Secp256k1::new();

        // Find one key of each parity, so the case is covered on purpose.
        let mut even = None;
        let mut odd = None;
        for b in 1u8..=255 {
            let candidate = sk(b);
            match candidate.x_only_public_key(&secp).1 {
                Parity::Even if even.is_none() => even = Some(candidate),
                Parity::Odd if odd.is_none() => odd = Some(candidate),
                _ => {}
            }
            if even.is_some() && odd.is_some() {
                break;
            }
        }
        let even = even.expect("an even-Y key exists");
        let odd = odd.expect("an odd-Y key exists");
        assert_eq!(even.x_only_public_key(&secp).1, Parity::Even);
        assert_eq!(odd.x_only_public_key(&secp).1, Parity::Odd);

        let keys = [xonly(&even), xonly(&odd)];
        let message = [0x77u8; 32];

        let mut l1 = VolatileNonceLedger::default();
        let mut l2 = VolatileNonceLedger::default();
        let (s1, c1) = SigningSession::begin(&mut l1, &keys, &even, None, &message)
            .expect("even-Y party round 1");
        let (s2, c2) = SigningSession::begin(&mut l2, &keys, &odd, None, &message)
            .expect("odd-Y party round 1");

        let nonces = [c1.public_nonce, c2.public_nonce];
        let p1 = s1.sign(&nonces).expect("even-Y party round 2");
        let p2 = s2.sign(&nonces).expect("odd-Y party round 2");

        let sig = combine(&keys, None, &nonces, &[p1, p2], &message).expect("combines");
        let out = output_key(&keys, None).expect("derives");
        secp.verify_schnorr(&sig, &Message::from_digest(message), &out)
            .expect("a mixed-parity pair must produce a valid signature");
    }

    /// A partial signature from the wrong nonce set does not silently produce
    /// a bad signature — aggregation verifies and refuses.
    #[test]
    fn aggregation_refuses_a_mismatched_nonce_set() {
        let owner = sk(31);
        let backup = sk(32);
        let keys = [xonly(&owner), xonly(&backup)];
        let message = [0x55u8; 32];

        let mut l1 = VolatileNonceLedger::default();
        let mut l2 = VolatileNonceLedger::default();
        let (s1, c1) =
            SigningSession::begin(&mut l1, &keys, &owner, None, &message).expect("round 1");
        let (s2, c2) =
            SigningSession::begin(&mut l2, &keys, &backup, None, &message).expect("round 1");

        let nonces = [c1.public_nonce, c2.public_nonce];
        let p1 = s1.sign(&nonces).expect("round 2");
        let p2 = s2.sign(&nonces).expect("round 2");

        // Aggregate against only one of the two nonces: the aggregate nonce no
        // longer matches what either party signed under.
        let err = combine(&keys, None, &nonces[..1], &[p1, p2], &message)
            .expect_err("a mismatched nonce set must not aggregate");
        assert!(
            format!("{err}").contains("aggregation failed"),
            "got: {err}"
        );
    }
}
