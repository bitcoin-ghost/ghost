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
//| FILE: signing_ledger.rs                                                                                               |
//|======================================================================================================================|

//! The once-per-coin rule — where the instant-payment guarantee actually lives.
//!
//! [`crate::attestation`] gives a quorum the *shape* of a promise. This module
//! is the promise itself: **the quorum signs exactly once per coin, ever.**
//!
//! That single rule is what lets a recipient act before confirmation. A hot-lane
//! coin is a 2-of-2, so the sender cannot produce a conflicting transaction
//! alone; and if the quorum refuses a second signature, no conflicting
//! transaction can exist at all.
//!
//! Note where the guarantee is *not*. It is not cryptographic — nothing stops a
//! corrupt quorum signing twice, and [`crate::attestation::DoubleSignProof`]
//! exists precisely because that is possible. The guarantee is **state**, and
//! state has to be correct under retries, races and restarts.
//!
//! # Persistence is mandatory, unlike the ban list
//!
//! The coordinator's other stores are deliberately in-memory: a restart clears
//! outpoint bans, and that is fine because the worst case is a griefer getting
//! another go.
//!
//! **This store must not work that way.** If the ledger is lost on restart, a
//! coordinator will happily sign a second transaction for a coin it already
//! signed — which is not a degraded service, it is the exact fraud the whole
//! design promises cannot happen, executed accidentally by an honest operator.
//! A restart would mint a valid [`DoubleSignProof`] against a quorum that did
//! nothing wrong.
//!
//! So [`SignatureStore`] is a trait with a durability contract, and
//! [`VolatileStore`] is named to be uncomfortable to type in production.

use std::collections::HashMap;

use thiserror::Error;

/// A coin, as the ledger keys it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutPointKey {
    /// Txid of the coin being spent.
    pub txid: [u8; 32],
    /// Output index.
    pub vout: u32,
}

impl OutPointKey {
    /// Construct a key.
    pub fn new(txid: [u8; 32], vout: u32) -> Self {
        Self { txid, vout }
    }
}

/// Durable record of which coins this quorum has already signed for.
///
/// # Contract
///
/// An implementation **must** survive process restart. A volatile
/// implementation turns an ordinary restart into an accidental double-sign.
pub trait SignatureStore {
    /// The spending txid previously authorised for this coin, if any.
    fn signed_txid(&self, coin: &OutPointKey) -> Option<[u8; 32]>;

    /// Record an authorisation durably. Must not return until it is durable.
    fn record(&mut self, coin: OutPointKey, spending_txid: [u8; 32]);
}

/// In-memory store. **Tests and simulation only.**
///
/// Deliberately named so that finding it in a production path is obvious. See
/// the module docs for what using it would cost.
#[derive(Debug, Default)]
pub struct VolatileStore {
    seen: HashMap<OutPointKey, [u8; 32]>,
}

impl SignatureStore for VolatileStore {
    fn signed_txid(&self, coin: &OutPointKey) -> Option<[u8; 32]> {
        self.seen.get(coin).copied()
    }
    fn record(&mut self, coin: OutPointKey, spending_txid: [u8; 32]) {
        self.seen.insert(coin, spending_txid);
    }
}

/// Why an authorisation was refused.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LedgerError {
    /// This coin was already signed for a *different* transaction.
    ///
    /// Refusing here is the whole point. Signing anyway would produce a valid
    /// double-sign proof against this quorum.
    #[error("coin already signed for a different transaction; refusing to equivocate")]
    Conflict {
        /// The transaction this coin was already committed to.
        existing_txid: [u8; 32],
    },
}

/// What the caller should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Not seen before. Sign it, and the ledger has recorded the commitment.
    Sign,
    /// Already signed for exactly this transaction. Re-issue the existing
    /// attestation; do not produce a second signature.
    AlreadyCommitted,
}

/// Enforces the once-per-coin rule.
#[derive(Debug)]
pub struct SigningLedger<S: SignatureStore> {
    store: S,
    refusals: u64,
}

impl<S: SignatureStore> SigningLedger<S> {
    /// Wrap a durable store.
    pub fn new(store: S) -> Self {
        Self { store, refusals: 0 }
    }

    /// Decide whether this quorum may sign `spending_txid` for `coin`.
    ///
    /// Idempotent: asking twice for the same transaction is a retry, not an
    /// attack, and returns [`Decision::AlreadyCommitted`]. Asking for a
    /// *different* transaction is refused.
    ///
    /// The commitment is recorded **before** signing, not after. A crash
    /// between the two loses a payment; the other order loses the guarantee.
    pub fn authorise(
        &mut self,
        coin: OutPointKey,
        spending_txid: [u8; 32],
    ) -> Result<Decision, LedgerError> {
        match self.store.signed_txid(&coin) {
            Some(existing) if existing == spending_txid => Ok(Decision::AlreadyCommitted),
            Some(existing) => {
                self.refusals += 1;
                Err(LedgerError::Conflict {
                    existing_txid: existing,
                })
            }
            None => {
                self.store.record(coin, spending_txid);
                Ok(Decision::Sign)
            }
        }
    }

    /// How many equivocation attempts this ledger has refused.
    ///
    /// *A check whose failure produces no observable output is not a check.*
    /// This is the counter; the dashboard is its reader. A non-zero and rising
    /// value means someone is probing the guarantee.
    pub fn refusals(&self) -> u64 {
        self.refusals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coin(b: u8) -> OutPointKey {
        OutPointKey::new([b; 32], 0)
    }

    fn ledger() -> SigningLedger<VolatileStore> {
        SigningLedger::new(VolatileStore::default())
    }

    #[test]
    fn a_coin_is_signed_once() {
        let mut l = ledger();
        assert_eq!(l.authorise(coin(1), [9; 32]), Ok(Decision::Sign));
    }

    #[test]
    fn retrying_the_same_transaction_is_idempotent_not_a_second_signature() {
        // Networks drop packets. A retry must not mint a second signature, and
        // must not be mistaken for an attack either.
        let mut l = ledger();
        assert_eq!(l.authorise(coin(1), [9; 32]), Ok(Decision::Sign));
        assert_eq!(
            l.authorise(coin(1), [9; 32]),
            Ok(Decision::AlreadyCommitted)
        );
        assert_eq!(
            l.authorise(coin(1), [9; 32]),
            Ok(Decision::AlreadyCommitted)
        );
        assert_eq!(l.refusals(), 0, "a retry is not a refusal");
    }

    #[test]
    fn a_second_transaction_for_the_same_coin_is_refused_and_counted() {
        let mut l = ledger();
        l.authorise(coin(1), [9; 32]).unwrap();
        assert_eq!(
            l.authorise(coin(1), [11; 32]),
            Err(LedgerError::Conflict {
                existing_txid: [9; 32]
            })
        );
        assert_eq!(l.refusals(), 1, "the refusal must be observable");
    }

    #[test]
    fn different_coins_are_independent() {
        // Signing many different coins is the entire job.
        let mut l = ledger();
        for b in 1..=50u8 {
            assert_eq!(l.authorise(coin(b), [b; 32]), Ok(Decision::Sign));
        }
        assert_eq!(l.refusals(), 0);
    }

    #[test]
    fn the_same_txid_differs_by_vout() {
        // Two outputs of one transaction are two coins, not one.
        let mut l = ledger();
        assert_eq!(
            l.authorise(OutPointKey::new([7; 32], 0), [9; 32]),
            Ok(Decision::Sign)
        );
        assert_eq!(
            l.authorise(OutPointKey::new([7; 32], 1), [9; 32]),
            Ok(Decision::Sign)
        );
        assert_eq!(l.refusals(), 0);
    }

    #[test]
    fn repeated_equivocation_attempts_keep_being_refused() {
        // A prober must never wear the ledger down, and every attempt counts.
        let mut l = ledger();
        l.authorise(coin(1), [9; 32]).unwrap();
        for i in 1..=100u8 {
            assert!(l.authorise(coin(1), [i.wrapping_add(100); 32]).is_err());
        }
        assert_eq!(l.refusals(), 100);
        // The original commitment is unchanged.
        assert_eq!(
            l.authorise(coin(1), [9; 32]),
            Ok(Decision::AlreadyCommitted)
        );
    }

    #[test]
    fn losing_the_store_is_a_double_sign_vector() {
        // This test documents WHY `SignatureStore` has a durability contract.
        // It is not asserting desirable behaviour — it is pinning the failure
        // mode so nobody swaps in a volatile store thinking a restart is
        // merely a degraded service.
        let mut before = ledger();
        assert_eq!(before.authorise(coin(1), [9; 32]), Ok(Decision::Sign));

        // Simulate a restart with a store that did not persist.
        let mut after = ledger();
        assert_eq!(
            after.authorise(coin(1), [11; 32]),
            Ok(Decision::Sign),
            "a volatile store signs the same coin twice across a restart — \
             this is the fraud the design promises cannot happen, committed \
             accidentally by an honest operator"
        );
    }
}
