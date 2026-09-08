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
//| FILE: key_agg.rs                                                                                                    |
//|======================================================================================================================|

//! MuSig2 key aggregation for the Lock's key-path spends.
//!
//! # Aggregation is not a ceremony
//!
//! An earlier note in this project said the wallet could not compute the
//! aggregate keys alone, and that Lock creation therefore needed an interactive
//! ceremony. That was wrong, and the mistake was worth catching: **BIP-327 key
//! aggregation is a deterministic function of the public keys**. No rounds, no
//! nonces, no other party online.
//!
//! Interaction is needed only to *sign* — nonce exchange and partial signatures.
//! So a Lock can be created from the backup and quorum **public** keys today,
//! and spending it by the key path is the part that still needs the ceremony.
//!
//! # Not hand-rolled
//!
//! This delegates to the `musig2` crate rather than implementing key
//! aggregation here. Custody is the wrong place to practise cryptography, and
//! the key-aggregation coefficient — the part that stops a rogue-key attack — is
//! exactly the detail a from-scratch implementation gets subtly wrong.
//!
//! # Two versions of secp256k1, deliberately
//!
//! `musig2` uses `secp256k1 0.31`; this workspace is on `0.29` via `bitcoin
//! 0.32`. Both end up in the binary. `secp256k1-sys` namespaces its C symbols by
//! version precisely so this links, and it does.
//!
//! Keys cross the boundary as **canonical serialised bytes**, which is the only
//! representation both versions agree on. That conversion is contained to this
//! module: nothing else in the workspace should have to know there are two.
//!
//! The cost is build time and binary size. The alternative — upgrading the
//! workspace's `secp256k1` — means moving `bitcoin` too, which is a far wider
//! change than a Lock feature should carry.

use bitcoin::XOnlyPublicKey;

use crate::error::LockError;

/// Aggregate public keys into the single key a Taproot key path spends with.
///
/// # We sort; the library does not
///
/// BIP-327's `KeyAgg` is **order-dependent** — the aggregate of `[A, B]` differs
/// from `[B, A]`. Sorting is a separate step the BIP calls `KeySort`, which
/// callers apply themselves. An earlier version of this comment claimed
/// `musig2` sorted internally; it does not, and the order-independence test
/// caught it.
///
/// That detail is load-bearing. Each party computes this alone — the wallet with
/// its own key and the backup's, the backup with the same pair — and they must
/// arrive at the same answer without first agreeing who goes first. So the keys
/// are sorted by their serialised bytes here, before aggregation.
///
/// If this sort were ever removed, two honest parties would build **different**
/// Locks from the same keys and neither would be able to spend the other's.
///
/// Rejects a single key: aggregating one key is not multi-signature, and a
/// caller reaching this with one key has almost certainly lost the other
/// somewhere upstream. Failing here is cheaper than building a Lock whose
/// "2-of-2" lane is a single signer.
pub fn aggregate(keys: &[XOnlyPublicKey]) -> Result<XOnlyPublicKey, LockError> {
    if keys.len() < 2 {
        return Err(LockError::Policy(format!(
            "MuSig2 aggregation needs at least two keys, got {}; a lane aggregating \
             one key is single-sig wearing a 2-of-2 label",
            keys.len()
        )));
    }

    // Sorted before aggregation — see the note above. Sorting the x-only bytes
    // gives a total order both parties reach independently.
    let mut sorted: Vec<&XOnlyPublicKey> = keys.iter().collect();
    sorted.sort_unstable_by_key(|k| k.serialize());

    // Cross the version boundary as bytes. An x-only key is 32 bytes; MuSig2
    // works over full points, so each is lifted to its even-Y form — the same
    // convention BIP-340 uses when it verifies against an x-only key.
    let mut pubkeys: Vec<musig2::secp256k1::PublicKey> = Vec::with_capacity(sorted.len());
    for k in sorted {
        let mut sec1 = [0u8; 33];
        sec1[0] = 0x02; // even Y, matching BIP-340's lift_x
        sec1[1..].copy_from_slice(&k.serialize());
        let p = musig2::secp256k1::PublicKey::from_slice(&sec1)
            .map_err(|e| LockError::Policy(format!("key is not a valid point: {e}")))?;
        pubkeys.push(p);
    }

    let ctx = musig2::KeyAggContext::new(pubkeys)
        .map_err(|e| LockError::Policy(format!("key aggregation failed: {e}")))?;

    let agg: musig2::secp256k1::PublicKey = ctx.aggregated_pubkey();
    let (xonly, _parity) = agg.x_only_public_key();

    XOnlyPublicKey::from_slice(&xonly.serialize())
        .map_err(|e| LockError::Policy(format!("aggregate is not a valid x-only key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

    fn key(b: u8) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[b.max(1); 32]).unwrap();
        Keypair::from_secret_key(&secp, &sk).x_only_public_key().0
    }

    #[test]
    fn two_keys_aggregate_to_a_third_key() {
        let a = aggregate(&[key(1), key(2)]).expect("aggregates");
        assert_ne!(a, key(1));
        assert_ne!(a, key(2), "the aggregate must not be either input");
    }

    #[test]
    fn aggregation_is_order_independent() {
        // Each party computes this alone, so the two must match without first
        // agreeing who goes first.
        //
        // BIP-327's KeyAgg is order-DEPENDENT; the sort that makes this hold is
        // ours, not the library's. This test failed when that sort was missing,
        // which is exactly the failure it exists to catch: two honest parties
        // building different Locks from the same keys.
        assert_eq!(
            aggregate(&[key(1), key(2)]).unwrap(),
            aggregate(&[key(2), key(1)]).unwrap()
        );
        // And with three, where a partial sort would still pass a pair test.
        assert_eq!(
            aggregate(&[key(5), key(9), key(2)]).unwrap(),
            aggregate(&[key(2), key(5), key(9)]).unwrap()
        );
        assert_eq!(
            aggregate(&[key(9), key(2), key(5)]).unwrap(),
            aggregate(&[key(2), key(5), key(9)]).unwrap()
        );
    }

    #[test]
    fn aggregation_is_deterministic() {
        // No nonces, no rounds. Same inputs, same answer, every time — which is
        // what makes Lock creation possible without a ceremony.
        let a = aggregate(&[key(3), key(4)]).unwrap();
        let b = aggregate(&[key(3), key(4)]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_pairs_aggregate_differently() {
        // Savings uses owner+backup, Spending uses owner+quorum. If these
        // collided the two lanes would share a key path.
        let owner_backup = aggregate(&[key(1), key(2)]).unwrap();
        let owner_quorum = aggregate(&[key(1), key(3)]).unwrap();
        assert_ne!(owner_backup, owner_quorum);
    }

    #[test]
    fn a_single_key_is_refused() {
        // Aggregating one key is single-sig wearing a 2-of-2 label, and a caller
        // that got here has lost the other key somewhere upstream.
        let e = aggregate(&[key(1)]).expect_err("must refuse");
        assert!(format!("{e}").contains("at least two"), "{e}");
    }

    #[test]
    fn no_keys_is_refused() {
        assert!(aggregate(&[]).is_err());
    }

    #[test]
    fn three_keys_aggregate() {
        // Nothing here is limited to pairs, even though the Lock only uses them.
        let a = aggregate(&[key(1), key(2), key(3)]).unwrap();
        assert_ne!(a, aggregate(&[key(1), key(2)]).unwrap());
    }
}
