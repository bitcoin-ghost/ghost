//! Converting a ratified checkpoint into opening balances.
//!
//! Truncating, never rounding up: under-crediting by less than one micro-work is recoverable,
//! over-crediting is not. The rounding loss is returned rather than swallowed so a caller can
//! assert on it — a silent conversion loss is how an opening balance stops matching the ledger it
//! came from.
//!
//! Written for the share-batch chain's genesis, which is deleted. The conversion outlived it:
//! [`crate::shard_genesis`] reuses `genesis_balances` verbatim rather than re-spelling it, because
//! two spellings of one conversion drift apart and this one decides opening money.

use std::collections::BTreeMap;

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

    /// Two nodes converting the same adopted checkpoint must reach the same balances, whatever
    /// order the list arrives in. The shard's genesis table is built straight off this, so an
    /// order-dependent conversion would give two nodes different opening money.
    #[test]
    fn genesis_is_identical_across_nodes() {
        let forwards = checkpoint();
        let mut backwards = checkpoint();
        backwards.reverse();

        let (ba, ra) = genesis_balances(&forwards);
        let (bb, rb) = genesis_balances(&backwards);

        assert_eq!(ba, bb);
        assert_eq!(ra, rb);
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

    /// The real thing: the canonical payout the fleet had ratified at height 960,550, read from
    /// production on 2026-08-01.
    ///
    /// All 8 nodes held a **byte-identical** `canonical_payout` blob (one distinct SHA-256 across
    /// the fleet) and identical `ledger_root`s at 960,548–960,550. That is the property genesis
    /// depends on and it is worth pinned to a test rather than remembered: if this conversion ever
    /// stops producing the same balances from the same adopted bytes, the chain cannot start.
    ///
    /// Six payees, and the whole fleet loses **less than one micro-work** — a millionth of a share
    /// — to truncation across all of them.
    fn ratified_960550() -> Vec<(String, u128)> {
        vec![
            (
                "bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492".to_string(),
                56_331_582_763_867_633_090_560,
            ),
            (
                "bc1q9z23a6yl44nc83dwm996ntl6wphwcwt9k0q0ej".to_string(),
                2_793_514_555_167_149_129_728,
            ),
            (
                "bc1qhfgc0uj7wv03vmchxe2hn8lhtu6ey9zaf0nre2".to_string(),
                2_207_417_987_159_784_685_568,
            ),
            (
                "148WRjKfSSo911CYRLzeyYm1QKhy7kCXTN".to_string(),
                749_653_085_382_128_041_984,
            ),
            (
                "bc1pgfky40eg9nk5lqn54epltfvxyld5aaeed6j03n2knjh0x904eusskg48d7".to_string(),
                124_182_128_766_138_007_552,
            ),
            (
                "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h".to_string(),
                19_521_704_918_910_001_152,
            ),
        ]
    }

    #[test]
    fn the_real_ratified_checkpoint_converts_cleanly() {
        let (balances, rounding) = genesis_balances(&ratified_960550());

        assert_eq!(balances.len(), 6, "every payee must survive the conversion");
        assert_eq!(rounding.addresses_dropped, 0);
        assert_eq!(
            rounding.units_discarded, 956_544,
            "the entire fleet loses under one micro-work to truncation"
        );
        assert!(
            rounding.units_discarded < CHECKPOINT_UNITS_PER_MICRO,
            "less than a millionth of a share, in total, across every payee"
        );

        // The dominant payee holds ~90% of the ledger; a conversion bug there is the one that
        // would actually cost someone money.
        assert_eq!(
            balances.get("bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492"),
            Some(&56_331_582_763_867_633)
        );
    }

    /// The adopted per-address totals at height **961,642** — the CHOSEN genesis anchor.
    ///
    /// Operator selected 961,642 on 2026-08-09 in preference to the 960,550 candidate previewed on
    /// 08-01. Both are fleet-unanimous; 961,642 is ~1,100 blocks fresher, and every block between
    /// an anchor and the shadow run is work that has to reach the chain some other way. Picking the
    /// stale one would have made the gap eight days wide.
    ///
    /// Verified read-only across all 8 nodes on 2026-08-09:
    ///   - `ledger_root` at 961,642 = `0FE9BAC3023F624B99B087A9C7E6C4C8B5CD557225F0EA9EF9828608FEC0CAA9`
    ///     — ONE distinct value across the fleet
    ///   - `canonical_payout` 1,316 bytes, identical on all 8
    ///   - 5 miner payees, 8 node entries
    fn ratified_961642() -> Vec<(String, u128)> {
        vec![
            (
                "bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492".to_string(),
                52_157_533_139_126_865_362_944,
            ),
            (
                "bc1q9z23a6yl44nc83dwm996ntl6wphwcwt9k0q0ej".to_string(),
                2_503_874_639_417_892_143_104,
            ),
            (
                "bc1qhfgc0uj7wv03vmchxe2hn8lhtu6ey9zaf0nre2".to_string(),
                2_341_458_453_435_845_967_872,
            ),
            (
                "148WRjKfSSo911CYRLzeyYm1QKhy7kCXTN".to_string(),
                478_353_203_210_592_976_896,
            ),
            (
                "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h".to_string(),
                9_741_908_758_669_000_704,
            ),
        ]
    }

    /// The chosen anchor converts without losing a payee or a meaningful amount of work.
    #[test]
    fn the_chosen_961642_anchor_converts_cleanly() {
        let (balances, rounding) = genesis_balances(&ratified_961642());

        assert_eq!(balances.len(), 5, "every payee must survive the conversion");
        assert_eq!(
            rounding.addresses_dropped, 0,
            "no payee may be rounded out of existence"
        );
        // The real invariant is per-address, not fleet-wide: each payee truncates by at most one
        // micro-work, so the total is bounded by the payee count. The 960,550 test asserts a
        // fleet total under ONE micro-work, which held for that data by luck (six remainders that
        // happened to be small) and is not a law — 961,642 discards 2,451,520 units, ~2.45
        // micro-work across five payees, and is equally correct.
        //
        // 2.45 micro-work is 0.00000245 of a share. Immaterial in absolute terms; what matters is
        // that it truncates DOWN, so no address is ever credited work nobody proved.
        assert!(
            rounding.units_discarded
                < (ratified_961642().len() as u128) * CHECKPOINT_UNITS_PER_MICRO,
            "each payee may lose under one micro-work, so the total is bounded by the payee \
             count; lost {}",
            rounding.units_discarded
        );

        // Conservation: the opening balances must account for the ratified total, less only the
        // truncation remainder. A conversion that quietly loses balance is how an unexplained
        // drift begins, and at genesis there is nothing to reconcile it against afterwards.
        let opened: i128 = balances.values().map(|v| *v as i128).sum();
        let ratified: u128 = ratified_961642().iter().map(|(_, w)| *w).sum();
        let expected = (ratified - rounding.units_discarded) / CHECKPOINT_UNITS_PER_MICRO;
        assert_eq!(
            opened as u128, expected,
            "opening balances must equal the ratified total minus truncation"
        );
    }

    /// An empty checkpoint is a cold start, not a panic.
    #[test]
    fn an_empty_checkpoint_yields_an_empty_genesis() {
        let (balances, rounding) = genesis_balances(&[]);
        assert!(balances.is_empty());
        assert_eq!(rounding, GenesisRounding::default());
    }
}
