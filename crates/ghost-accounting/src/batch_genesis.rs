//! Where the share-batch chain starts.
//!
//! Every batch after this one is checked against its parent, so the first one cannot be — something
//! has to be adopted rather than verified. The only honest candidate is a **finalised
//! `PayoutLedgerCheckpoint`**: the fleet has already agreed those numbers under the existing
//! tolerance machinery, every node holds the identical adopted bytes, and its provenance is a vote
//! that happened rather than a claim made now.
//!
//! That is also the last use of tolerance. From `seq 1` onward, agreement is exact equality on a
//! recomputed state root, which is only safe because the state everyone starts from is the same
//! state — not merely a similar one.
//!
//! Genesis **converts** the checkpoint; it does not recompute it from local shares. Recomputing
//! would reintroduce exactly the divergence the checkpoint exists to have settled: eight nodes with
//! eight slightly different unpaid ledgers would derive eight slightly different genesis roots, and
//! the chain would fail to start for the same reason the old one failed to agree.
//!
//! Dark code: nothing wires this into a runtime path yet.

use std::collections::BTreeMap;

use ghost_common::share_batch::{compute_state_root, ShareBatch};

use crate::shares::WORK_SCALE;

/// Micro-work per whole share — the share-batch chain's fixed-point scale.
///
/// Kept here beside the conversion rather than imported from the ledger's SQL, because the point of
/// this module is that the two scales are different and the difference is handled once.
const MICRO_PER_WORK: u128 = 1_000_000;

/// How many checkpoint units make one micro-work.
///
/// The checkpoint quantises at `WORK_SCALE` (1e12) and the batch chain at 1e6, so the conversion is
/// a divide by 1e6. Derived rather than written out, so that changing either scale cannot leave a
/// hardcoded ratio quietly wrong.
const CHECKPOINT_UNITS_PER_MICRO: u128 = WORK_SCALE / MICRO_PER_WORK;

/// What the conversion had to throw away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GenesisRounding {
    /// Addresses whose balance lost a fraction of a micro-work.
    pub addresses_rounded: usize,
    /// Total checkpoint units discarded, across all addresses.
    ///
    /// Reported rather than swallowed. It is at most one micro-work per address — a millionth of a
    /// share — but "the opening balances are not exactly the checkpoint" is a fact the operator
    /// should be told once, not discover later as an unexplained drift.
    pub units_discarded: u128,
    /// Addresses dropped because their whole balance was below one micro-work.
    pub addresses_dropped: usize,
}

/// Build `seq 0` from a finalised checkpoint's adopted miner set.
///
/// `miner_payouts` is the checkpoint's own `(payout_address, WORK_SCALE-quantised work)` list,
/// adopted verbatim on finalise — so passing anything else defeats the purpose.
///
/// Truncating, never rounding up. Under-crediting by less than a millionth of a share is
/// immaterial; crediting work that was never proven is a different kind of thing, and the direction
/// of a rounding error is worth choosing deliberately even when the magnitude is not.
pub fn genesis_balances(
    miner_payouts: &[(String, u128)],
) -> (BTreeMap<String, i64>, GenesisRounding) {
    let mut balances: BTreeMap<String, i64> = BTreeMap::new();
    let mut rounding = GenesisRounding::default();

    for (address, scaled) in miner_payouts {
        let micro = scaled / CHECKPOINT_UNITS_PER_MICRO;
        let remainder = scaled % CHECKPOINT_UNITS_PER_MICRO;

        if remainder > 0 {
            rounding.addresses_rounded += 1;
            rounding.units_discarded += remainder;
        }
        if micro == 0 {
            rounding.addresses_dropped += 1;
            continue;
        }

        // Saturating rather than wrapping: a checkpoint balance beyond i64 micro-work is not
        // reachable by mining, but silently wrapping it to a negative balance would be.
        let micro = i64::try_from(micro).unwrap_or(i64::MAX);
        // The checkpoint's list should not repeat an address; summing rather than overwriting means
        // that if it ever does, the work is preserved instead of one entry being lost.
        let entry = balances.entry(address.clone()).or_insert(0);
        *entry = entry.saturating_add(micro);
    }

    (balances, rounding)
}

/// The genesis batch itself.
///
/// It carries no shares. The work is already in the opening balances, and re-listing the shares
/// behind it would invite a validator to re-derive numbers that were agreed by vote rather than by
/// arithmetic — the one thing genesis must not allow.
///
/// `prev_batch_hash` is the checkpoint hash, which makes the chain's first link point at the object
/// that authorises it. A genesis with a zero parent would be a chain anyone could start; this one
/// can only be started from a checkpoint the fleet finalised.
pub fn genesis_batch(
    checkpoint_hash: [u8; 32],
    cutoff_ts: i64,
    proposer: [u8; 32],
    miner_payouts: &[(String, u128)],
    node_shares: Vec<([u8; 32], i32)>,
) -> (ShareBatch, BTreeMap<String, i64>, GenesisRounding) {
    let (balances, rounding) = genesis_balances(miner_payouts);
    let state_root = compute_state_root(&balances, 0, cutoff_ts);

    let batch = ShareBatch {
        seq: 0,
        prev_batch_hash: checkpoint_hash,
        close_ts: cutoff_ts,
        proposer,
        shares: Vec::new(),
        settled_blocks: Vec::new(),
        node_shares,
        state_root,
        truncated: false,
        pending_count: 0,
        // Signed by the caller, which holds the key. Left empty here so this function stays pure.
        proposer_signature: Vec::new(),
    };

    (batch, balances, rounding)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint() -> Vec<(String, u128)> {
        vec![
            // 1.5 shares, exact.
            (
                "bc1qalice".to_string(),
                1_500_000 * CHECKPOINT_UNITS_PER_MICRO,
            ),
            // 2.25 shares, exact.
            (
                "bc1qbob".to_string(),
                2_250_000 * CHECKPOINT_UNITS_PER_MICRO,
            ),
        ]
    }

    /// The ratio must follow the two scales, not a number typed once and forgotten.
    #[test]
    fn the_conversion_ratio_follows_the_scales_it_bridges() {
        assert_eq!(CHECKPOINT_UNITS_PER_MICRO, WORK_SCALE / MICRO_PER_WORK);
        assert_eq!(CHECKPOINT_UNITS_PER_MICRO, 1_000_000);
    }

    #[test]
    fn exact_balances_convert_without_loss() {
        let (balances, rounding) = genesis_balances(&checkpoint());
        assert_eq!(balances.get("bc1qalice"), Some(&1_500_000));
        assert_eq!(balances.get("bc1qbob"), Some(&2_250_000));
        assert_eq!(rounding, GenesisRounding::default());
    }

    /// Sub-micro-work fractions are dropped, and the loss is **reported**. A conversion that
    /// quietly discards balance is how an unexplained drift starts.
    #[test]
    fn a_fraction_of_a_micro_work_is_dropped_and_counted() {
        let payouts = vec![(
            "bc1qalice".to_string(),
            1_500_000 * CHECKPOINT_UNITS_PER_MICRO + 999_999,
        )];
        let (balances, rounding) = genesis_balances(&payouts);
        assert_eq!(balances.get("bc1qalice"), Some(&1_500_000));
        assert_eq!(rounding.addresses_rounded, 1);
        assert_eq!(rounding.units_discarded, 999_999);
        assert_eq!(rounding.addresses_dropped, 0);
    }

    /// Truncation, not rounding up. Under-crediting by a millionth of a share is immaterial;
    /// crediting work nobody proved is a different kind of thing.
    #[test]
    fn the_conversion_never_credits_work_that_was_not_proven() {
        let payouts = vec![("bc1qalice".to_string(), CHECKPOINT_UNITS_PER_MICRO - 1)];
        let (balances, rounding) = genesis_balances(&payouts);
        assert!(
            balances.is_empty(),
            "just under one micro-work must not round up to one"
        );
        assert_eq!(rounding.addresses_dropped, 1);
    }

    /// Two nodes converting the same adopted checkpoint must reach the same root, whatever order
    /// the list arrives in — this is the property the whole chain is built on top of.
    #[test]
    fn genesis_is_identical_across_nodes() {
        let forwards = checkpoint();
        let mut backwards = checkpoint();
        backwards.reverse();

        let (a, ba, _) = genesis_batch([0x77; 32], 1_700_000_000, [1u8; 32], &forwards, vec![]);
        let (b, bb, _) = genesis_batch([0x77; 32], 1_700_000_000, [1u8; 32], &backwards, vec![]);

        assert_eq!(ba, bb);
        assert_eq!(a.state_root, b.state_root);
        assert_eq!(a.batch_hash(), b.batch_hash());
    }

    /// The first link points at the checkpoint that authorises it. A zero parent would be a chain
    /// anyone could start.
    #[test]
    fn genesis_is_anchored_to_its_checkpoint() {
        let (batch, _, _) =
            genesis_batch([0x77; 32], 1_700_000_000, [1u8; 32], &checkpoint(), vec![]);
        assert_eq!(batch.seq, 0);
        assert_eq!(batch.prev_batch_hash, [0x77; 32]);
        assert!(
            batch.shares.is_empty(),
            "the work is in the balances; re-listing shares invites re-derivation"
        );
    }

    /// A different checkpoint must give a different genesis, or the anchor is decorative.
    #[test]
    fn a_different_checkpoint_gives_a_different_genesis() {
        let (a, _, _) = genesis_batch([0x77; 32], 1_700_000_000, [1u8; 32], &checkpoint(), vec![]);
        let (b, _, _) = genesis_batch([0x88; 32], 1_700_000_000, [1u8; 32], &checkpoint(), vec![]);
        assert_ne!(a.batch_hash(), b.batch_hash());
    }

    /// A repeated address in the checkpoint must not lose work to an overwrite.
    #[test]
    fn a_repeated_address_sums_rather_than_overwrites() {
        let payouts = vec![
            ("bc1qalice".to_string(), CHECKPOINT_UNITS_PER_MICRO * 10),
            ("bc1qalice".to_string(), CHECKPOINT_UNITS_PER_MICRO * 5),
        ];
        let (balances, _) = genesis_balances(&payouts);
        assert_eq!(balances.get("bc1qalice"), Some(&15));
    }

    /// An empty checkpoint is a cold start, not a panic.
    #[test]
    fn an_empty_checkpoint_yields_an_empty_genesis() {
        let (batch, balances, rounding) = genesis_batch([0u8; 32], 0, [0u8; 32], &[], vec![]);
        assert!(balances.is_empty());
        assert_eq!(rounding, GenesisRounding::default());
        assert_eq!(batch.state_root, compute_state_root(&balances, 0, 0));
    }
}
