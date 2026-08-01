//! Judging a share's node binding once the evidence for it exists.
//!
//! A share proves which node it was mined for by committing to a coinbase that carries that node's
//! tag. The proof needs the coinbase skeleton, and the skeleton arrives once per job — so a share
//! can turn up before the thing that would justify it. That happens on a restart, and after any
//! delivery failure.
//!
//! Judging such a share once, on the one occasion its evidence happened to be missing, would turn a
//! transient gap into a permanent verdict. The share is recorded instead, and re-judged when the
//! skeleton lands. Nothing here needs an operator: the retry is driven by the same reconcile tick
//! that retries deferred settlements, and the work is proportional to the shares that can *now* be
//! judged rather than to the size of the backlog.
//!
//! Dark code: nothing wires this into a runtime path yet.

use std::sync::Arc;

use ghost_common::error::GhostResult;
use ghost_common::share_binding::{verify_share_node_binding, BindingError, CoinbaseSkeleton};
use ghost_storage::Database;
use tracing::{debug, info, warn};

/// Accept a skeleton announced by `pool_sv2`, if it proves itself.
///
/// **Verified by rehashing, never trusted.** The id is a content address, so a skeleton is stored
/// only under the id its own bytes produce. Without this check a peer could name any bytes it
/// liked under an identity that shares already point at, and every one of those shares would then
/// "verify" against a coinbase of the sender's choosing — which is the whole attack the binding
/// exists to prevent, reintroduced at the storage layer.
pub fn accept_skeleton(
    db: &Database,
    claimed_id: &str,
    coinbase_prefix: &str,
    coinbase_suffix: &str,
    merkle_path: &[String],
    height: u64,
) -> GhostResult<[u8; 32]> {
    let claimed = hex32(claimed_id).ok_or_else(|| {
        ghost_common::error::GhostError::Internal("skeleton id is not 32 bytes".into())
    })?;
    let prefix = hex::decode(coinbase_prefix)
        .map_err(|e| ghost_common::error::GhostError::Internal(format!("prefix: {e}")))?;
    let suffix = hex::decode(coinbase_suffix)
        .map_err(|e| ghost_common::error::GhostError::Internal(format!("suffix: {e}")))?;
    let mut path = Vec::with_capacity(merkle_path.len());
    for node in merkle_path {
        path.push(hex32(node).ok_or_else(|| {
            ghost_common::error::GhostError::Internal("merkle node is not 32 bytes".into())
        })?);
    }

    let built = CoinbaseSkeleton {
        coinbase_prefix: prefix,
        coinbase_suffix: suffix,
        merkle_path: path,
    };
    let actual = built.id();
    if actual != claimed {
        return Err(ghost_common::error::GhostError::Internal(
            "skeleton does not hash to the id it claims".into(),
        ));
    }

    db.store_skeleton(
        &actual,
        &built.coinbase_prefix,
        &built.coinbase_suffix,
        &built.merkle_path,
        height,
    )?;
    Ok(actual)
}

/// Parse a 32-byte hex string, or nothing.
///
/// `None` rather than a truncated or padded array: a wrong-width hash is not a hash, and coercing
/// one would have a share reference a skeleton that cannot exist.
pub fn hex32(s: &str) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(hex::decode(s).ok()?.as_slice()).ok()
}

/// Most bindings to re-judge in one pass.
///
/// Bounded so a large backlog cannot stall the tick it shares with settlement reconciliation. What
/// is left over is picked up next pass, and the count is reported, so a backlog that is not
/// draining is visible rather than inferred.
const MAX_RECHECK_PER_PASS: usize = 500;

/// What a pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecheckOutcome {
    /// Bindings that verified and are no longer waiting.
    pub confirmed: usize,
    /// Bindings that failed verification — the share was not mined for the node claiming it.
    ///
    /// Counted separately because this is the *finding*, not an error: the skeleton was present and
    /// the proof did not hold.
    pub refuted: usize,
    /// Still waiting on a skeleton after this pass.
    pub still_waiting: usize,
}

/// Re-judge every deferred binding whose skeleton is now held.
pub async fn recheck_bindings(db: &Arc<Database>) -> GhostResult<RecheckOutcome> {
    let mut outcome = RecheckOutcome::default();

    let ready = db.list_verifiable_bindings(MAX_RECHECK_PER_PASS)?;
    for (share_hash, skeleton_id, extranonce, header, expected_node) in ready {
        let Some((coinbase_prefix, coinbase_suffix, merkle_path)) =
            db.get_skeleton(&skeleton_id)?
        else {
            // The join said it was there. Losing it between the two reads is possible under
            // pruning, and is a reason to try again later rather than to judge without it.
            continue;
        };

        let skeleton = CoinbaseSkeleton {
            coinbase_prefix,
            coinbase_suffix,
            merkle_path,
        };

        match verify_share_node_binding(&skeleton, &extranonce, &header, &expected_node) {
            Ok(()) => {
                outcome.confirmed += 1;
                db.clear_deferred_binding(&share_hash)?;
                debug!(
                    share_hash,
                    "share binding verified once its coinbase skeleton arrived"
                );
            }
            Err(BindingError::MalformedHeader) => {
                // Nothing about waiting longer fixes an 80-byte header that is not 80 bytes. Clear
                // it rather than retrying forever; the share stays unattributed, which is the
                // honest outcome for a share whose own preimage is unusable.
                outcome.refuted += 1;
                db.clear_deferred_binding(&share_hash)?;
                warn!(
                    share_hash,
                    "deferred binding has an unusable header; dropping it"
                );
            }
            Err(e) => {
                // The skeleton was present and the proof did not hold. That is a finding about the
                // share, so it is resolved — not retried, which would only produce the same answer.
                outcome.refuted += 1;
                db.clear_deferred_binding(&share_hash)?;
                warn!(
                    share_hash,
                    error = ?e,
                    "share does NOT prove it was mined for the node claiming it"
                );
            }
        }
    }

    outcome.still_waiting = db.count_unverified_bindings()?;

    if outcome.confirmed > 0 || outcome.refuted > 0 {
        info!(
            confirmed = outcome.confirmed,
            refuted = outcome.refuted,
            still_waiting = outcome.still_waiting,
            "re-judged share bindings whose skeletons had arrived"
        );
    } else if outcome.still_waiting > 0 {
        // Said out loud, because a backlog that never drains means skeletons are not arriving —
        // and that is a transport fault, not a share problem.
        debug!(
            still_waiting = outcome.still_waiting,
            "share bindings are waiting on skeletons that have not arrived"
        );
    }

    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE: [u8; 20] = [0x5Au8; 20];

    /// A skeleton whose coinbase carries `NODE`'s tag, and a header committing to it.
    fn a_bound_share() -> (CoinbaseSkeleton, Vec<u8>, Vec<u8>) {
        let mut script_sig = vec![0x03, 0x40, 0x1f, 0x0e];
        script_sig.extend_from_slice(&ghost_common::coinbase_tags::encode_node_tag(&NODE));
        let extranonce = vec![9u8; 8];

        // Minimal non-witness coinbase: version, one input, script, sequence, no outputs, locktime.
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&2u32.to_le_bytes());
        prefix.push(1);
        prefix.extend_from_slice(&[0u8; 32]);
        prefix.extend_from_slice(&u32::MAX.to_le_bytes());
        prefix.push((script_sig.len() + extranonce.len()) as u8);
        prefix.extend_from_slice(&script_sig);

        let mut suffix = Vec::new();
        suffix.extend_from_slice(&u32::MAX.to_le_bytes());
        suffix.push(0);
        suffix.extend_from_slice(&0u32.to_le_bytes());

        let skeleton = CoinbaseSkeleton {
            coinbase_prefix: prefix,
            coinbase_suffix: suffix,
            merkle_path: vec![],
        };

        // Empty merkle path, so the root IS the coinbase txid. Computed here rather than through
        // the verifier's own internals, so the test does not assert a function against itself.
        let coinbase = skeleton.coinbase_with(&extranonce);
        let root = {
            use sha2::{Digest, Sha256};
            let once = Sha256::digest(&coinbase);
            let twice: [u8; 32] = Sha256::digest(once).into();
            twice
        };

        let mut header = vec![0u8; 80];
        header[4..36].copy_from_slice(&[0u8; 32]);
        header[36..68].copy_from_slice(&root);
        (skeleton, extranonce, header)
    }

    fn a_db() -> Arc<Database> {
        Arc::new(Database::in_memory().expect("db"))
    }

    /// **The healing property.** A share that arrived before its skeleton is judged when the
    /// skeleton lands — not left with the verdict it happened to get while the evidence was absent.
    #[tokio::test]
    async fn a_share_that_arrived_first_is_judged_when_its_skeleton_lands() {
        let db = a_db();
        let (skeleton, extranonce, header) = a_bound_share();
        let id = skeleton.id();

        db.defer_binding("share-1", &id, &extranonce, &header, &NODE)
            .expect("defer");

        // Nothing to judge yet, and the share is still waiting rather than resolved.
        let first = recheck_bindings(&db).await.expect("pass");
        assert_eq!(first.confirmed, 0);
        assert_eq!(first.still_waiting, 1);

        db.store_skeleton(
            &id,
            &skeleton.coinbase_prefix,
            &skeleton.coinbase_suffix,
            &skeleton.merkle_path,
            960_000,
        )
        .expect("store");

        let second = recheck_bindings(&db).await.expect("pass");
        assert_eq!(second.confirmed, 1, "the skeleton arrived; judge it now");
        assert_eq!(second.still_waiting, 0, "and stop waiting on it");
    }

    /// A share that really was not mined for this node is refuted and resolved — retrying would
    /// only produce the same answer, and leaving it queued would hide a genuine finding.
    #[tokio::test]
    async fn a_share_bound_to_another_node_is_refuted_not_retried() {
        let db = a_db();
        let (skeleton, extranonce, header) = a_bound_share();
        let id = skeleton.id();
        db.store_skeleton(
            &id,
            &skeleton.coinbase_prefix,
            &skeleton.coinbase_suffix,
            &skeleton.merkle_path,
            960_000,
        )
        .expect("store");

        // Same evidence, a different node claiming it.
        db.defer_binding("share-2", &id, &extranonce, &header, &[0xEEu8; 20])
            .expect("defer");

        let out = recheck_bindings(&db).await.expect("pass");
        assert_eq!(out.refuted, 1);
        assert_eq!(out.confirmed, 0);
        assert_eq!(
            out.still_waiting, 0,
            "a refuted binding is resolved, not left queued forever"
        );
    }

    /// Re-observing the same waiting share must not multiply it.
    #[tokio::test]
    async fn re_deferring_the_same_share_does_not_duplicate_it() {
        let db = a_db();
        let (skeleton, extranonce, header) = a_bound_share();
        let id = skeleton.id();
        for _ in 0..3 {
            db.defer_binding("share-3", &id, &extranonce, &header, &NODE)
                .expect("defer");
        }
        assert_eq!(db.count_unverified_bindings().expect("count"), 1);
    }

    /// An honest announcement is stored under the id its own bytes produce.
    #[test]
    fn an_honest_skeleton_is_accepted() {
        let db = a_db();
        let (skeleton, _, _) = a_bound_share();
        let id = skeleton.id();

        let stored = accept_skeleton(
            &db,
            &hex::encode(id),
            &hex::encode(&skeleton.coinbase_prefix),
            &hex::encode(&skeleton.coinbase_suffix),
            &skeleton
                .merkle_path
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>(),
            960_000,
        )
        .expect("should accept");
        assert_eq!(stored, id);
        assert!(db.get_skeleton(&id).expect("get").is_some());
    }

    /// **The trust-free property.** A peer cannot store bytes of its choosing under an id that
    /// shares already point at — which would make every one of those shares verify against a
    /// coinbase the sender picked, reintroducing the exact attack the binding prevents.
    #[test]
    fn a_skeleton_that_does_not_hash_to_its_claimed_id_is_refused() {
        let db = a_db();
        let (skeleton, _, _) = a_bound_share();
        let real_id = skeleton.id();

        let mut doctored = skeleton.coinbase_prefix.clone();
        doctored[10] ^= 0xFF; // change the coinbase, keep the claimed identity

        assert!(
            accept_skeleton(
                &db,
                &hex::encode(real_id),
                &hex::encode(&doctored),
                &hex::encode(&skeleton.coinbase_suffix),
                &skeleton
                    .merkle_path
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>(),
                960_000,
            )
            .is_err(),
            "bytes that do not hash to the claimed id must be refused"
        );
        assert!(
            db.get_skeleton(&real_id).expect("get").is_none(),
            "and nothing should have been stored"
        );
    }

    /// A malformed announcement is refused rather than stored half-parsed.
    #[test]
    fn a_malformed_skeleton_is_refused() {
        let db = a_db();
        assert!(accept_skeleton(&db, "notlongenough", "00", "01", &[], 1).is_err());
        assert!(accept_skeleton(&db, &hex::encode([1u8; 32]), "zz", "01", &[], 1).is_err());
    }

    /// A skeleton stored and read back must be the same skeleton — the merkle path is flattened
    /// into one blob, so an off-by-32 here would fold to a different root and refute everything.
    #[test]
    fn a_stored_skeleton_round_trips() {
        let db = a_db();
        let skeleton = CoinbaseSkeleton {
            coinbase_prefix: vec![1, 2, 3],
            coinbase_suffix: vec![4, 5],
            merkle_path: vec![[7u8; 32], [8u8; 32], [9u8; 32]],
        };
        let id = skeleton.id();
        db.store_skeleton(
            &id,
            &skeleton.coinbase_prefix,
            &skeleton.coinbase_suffix,
            &skeleton.merkle_path,
            1,
        )
        .expect("store");

        let (prefix, suffix, path) = db.get_skeleton(&id).expect("get").expect("present");
        assert_eq!(prefix, skeleton.coinbase_prefix);
        assert_eq!(suffix, skeleton.coinbase_suffix);
        assert_eq!(path, skeleton.merkle_path);
    }
}
