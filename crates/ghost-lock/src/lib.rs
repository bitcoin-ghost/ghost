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
//| FILE: lib.rs                                                                                                         |
//|======================================================================================================================|

//! Ghost Lock — Taproot custody policies for Bitcoin Ghost.
//!
//! A Lock is a **policy, not a coin**. Many UTXOs sit under one Lock, and the
//! identity is the policy rather than any address — which is what lets "bank
//! account" work as a mental model without lying about how Bitcoin works.
//!
//! Three lanes, escalating delegation:
//!
//! | Lane | Key path | The quorum |
//! |---|---|---|
//! | [`SavingsPolicy`] | `musig(owner, backup)` | has no part in it |
//! | [`SpendingPolicy`] | `musig(owner, quorum)` | can only complete what was pre-signed |
//! | [`InvestmentsPolicy`] | `quorum` | can spend alone — this lane is custody |
//!
//! # Why the key path matters
//!
//! Every lane spends through the key path in the normal case. A MuSig2 aggregate
//! is one 64-byte Schnorr signature over a bare 32-byte output key, which is
//! cryptographically indistinguishable from a single-signer spend. Nothing on
//! chain says a Lock exists, that it has a backup key, an heir, or a recovery
//! path — until the day someone actually uses one.
//!
//! # Entropy
//!
//! This crate takes public keys and never generates them. Callers must source
//! every secret from the OS CSPRNG: `Keystore::create` shipped with
//! `rand::thread_rng()` once and was fixed in `4d52543f0`. **MuSig2 nonce reuse
//! is key extraction, not a bug** — fresh entropy per session, and a refusal
//! path that alarms rather than reuses.

#![deny(missing_docs)]

pub mod compartment;
pub mod constants;
pub mod error;
pub mod lane;

pub use compartment::{Compartment, CompartmentError};
pub use constants::*;
pub use error::LockError;
pub use lane::{CashPolicy, InvestmentsPolicy, Lane, SavingsPolicy, SpendingPolicy};

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use bitcoin::Network;

    fn key(byte: u8) -> bitcoin::secp256k1::XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[byte; 32]).expect("valid scalar");
        sk.x_only_public_key(&secp).0
    }

    fn vault() -> SavingsPolicy {
        SavingsPolicy {
            aggregate: key(1),
            owner: key(2),
            backup: key(3),
            heir: key(4),
            inherit_height: 1_000_000,
        }
    }

    #[test]
    fn vault_builds_three_leaves_and_a_p2tr_address() {
        let secp = Secp256k1::verification_only();
        let lane = vault()
            .build(&secp, 900_000, Network::Regtest)
            .expect("builds");
        assert_eq!(
            lane.spend_info.script_map().len(),
            3,
            "vault has three leaves"
        );
        assert!(lane.address.script_pubkey().is_p2tr());
    }

    #[test]
    fn cash_has_no_script_path_at_all() {
        // The only lane with no leaves. A script path would be a way to move
        // the coin that is not the owner's key, and Cash has nothing to
        // delegate and nothing to escape from.
        let secp = Secp256k1::verification_only();
        let cash = CashPolicy { owner: key(2) }
            .build(&secp, Network::Regtest)
            .expect("builds");
        assert_eq!(cash.spend_info.script_map().len(), 0);
        assert!(cash.spend_info.merkle_root().is_none());
    }

    #[test]
    fn cash_is_not_the_same_address_as_the_private_lanes() {
        // Compartmenting is worthless if the compartments share an address.
        let secp = Secp256k1::verification_only();
        let cash = CashPolicy { owner: key(2) }
            .build(&secp, Network::Regtest)
            .expect("builds");
        let spending = SpendingPolicy {
            aggregate: key(1),
            owner: key(2),
        }
        .build(&secp, Network::Regtest)
        .expect("builds");
        assert_ne!(cash.address, spending.address);
    }

    #[test]
    fn hot_and_liquidity_have_exactly_one_leaf() {
        let secp = Secp256k1::verification_only();
        let hot = SpendingPolicy {
            aggregate: key(1),
            owner: key(2),
        }
        .build(&secp, Network::Regtest)
        .expect("builds");
        let liq = InvestmentsPolicy {
            quorum: key(5),
            owner: key(2),
        }
        .build(&secp, Network::Regtest)
        .expect("builds");
        assert_eq!(hot.spend_info.script_map().len(), 1);
        assert_eq!(liq.spend_info.script_map().len(), 1);
    }

    #[test]
    fn every_leaf_has_a_control_block() {
        let secp = Secp256k1::verification_only();
        let lane = vault()
            .build(&secp, 900_000, Network::Regtest)
            .expect("builds");
        for script in lane.spend_info.script_map().keys() {
            assert!(
                lane.spend_info.control_block(script).is_some(),
                "leaf is unspendable: no control block"
            );
        }
    }

    #[test]
    fn key_path_output_differs_from_the_internal_key() {
        // The output key is the internal key tweaked by the merkle root, so a
        // key-path spend reveals nothing about the tree hanging beneath it.
        let secp = Secp256k1::verification_only();
        let lane = vault()
            .build(&secp, 900_000, Network::Regtest)
            .expect("builds");
        assert_ne!(
            lane.spend_info.output_key().to_x_only_public_key(),
            lane.spend_info.internal_key(),
            "output key must be tweaked by the merkle root"
        );
        assert!(lane.spend_info.merkle_root().is_some());
    }

    #[test]
    fn inheritance_must_be_in_the_future() {
        let secp = Secp256k1::verification_only();
        let mut v = vault();
        v.inherit_height = 500;
        let err = v.build(&secp, 900_000, Network::Regtest).unwrap_err();
        assert!(matches!(err, LockError::InheritanceNotInFuture { .. }));
    }

    #[test]
    fn a_relative_timelock_beyond_the_ceiling_is_refused() {
        let err = lane::relative_timelock_leaf(CSV_MAX_BLOCKS + 1, &key(2)).unwrap_err();
        assert!(matches!(err, LockError::TimelockTooLong { .. }));
    }

    #[test]
    fn lanes_of_one_lock_are_distinct_addresses() {
        let secp = Secp256k1::verification_only();
        let v = vault().build(&secp, 900_000, Network::Regtest).unwrap();
        let h = SpendingPolicy {
            aggregate: key(1),
            owner: key(2),
        }
        .build(&secp, Network::Regtest)
        .unwrap();
        assert_ne!(v.address, h.address, "lanes must not share an address");
    }
}
