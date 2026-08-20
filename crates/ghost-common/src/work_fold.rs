//! The work fold: how a set of shares becomes a set of balances, deterministically.
//!
//! Every node must derive **byte-identical** numbers from the same shares, because agreement is by
//! exact equality — a validator recomputes the fold and compares roots. There is no tolerance to
//! absorb a disagreement, which is the point: the legacy path's tolerance existed precisely because
//! nodes could not agree, and removing the disagreement is what removes the need for it.
//!
//! So everything here is a pure function of its inputs, and the encodings are pinned by golden
//! vectors. Nothing in this module reads a clock, a database, or the network.
//!
//! Written for the share-batch chain (`share_batch.rs`), which is deleted. This half outlived it:
//! the share shard folds work exactly the same way, so `share_shard.rs`, `shard.rs`,
//! `shard_handler.rs` and `share_checks.rs` all call in here. ONE fold, or the shard and its
//! verifiers disagree about money.
//!
//! ⚠ `micro_work` quantisation must match the SQL the ledger uses — see its test.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::types::ShareProof;

/// Fixed-point scale for share work, matching the ledger's SQL exactly.
///
/// The existing payout path quantises with `CAST(ROUND(work * 1000000) AS INTEGER)`
/// (`get_top_unpaid_addresses`), and the shadow-run compares batch totals against that path, so any
/// difference here shows up as a false divergence.
const MICRO: f64 = 1_000_000.0;

/// Hard ceiling on a single share's creditable difficulty.
///
/// `micro_work` is `(canonical_json_f64(x) * 1e6).round() as i64`, and Rust's float-to-int cast
/// SATURATES — so without a ceiling, one share claiming `f64::MAX` difficulty is credited
/// `i64::MAX` micro-work and captures an entire balance in a single fold. The cast saturates at
/// `i64::MAX / 1e6 ≈ 9.22e12`; 1e12 keeps an order of magnitude of headroom below that (so the
/// JSON round-trip and the rounding can never tip a "legal" value over the edge), while sitting
/// about six orders of magnitude above the largest difficulty this pool's vardiff actually
/// assigns (farm tier peaks around 1e6) — no honest share is anywhere near it.
///
/// ⚠ This is a SATURATION guard, not the fix for the adaptive-claim attack: `difficulty` is still
/// a value the claiming side chooses post hoc, merely bounded and PoW-checked. The real fix is
/// the difficulty-tier commitment in the WP-1b tag, which is a separate, later change.
pub const MAX_CREDIT_DIFFICULTY: f64 = 1.0e12;

/// Whether a share's claimed difficulty may be credited at all.
///
/// One spelling of the predicate, shared by verification (where a violation is a terminal fault)
/// and by ingest (where such a share is refused before it can poison this node's own proposals).
/// Non-finite and non-positive values are excluded because `micro_work` maps NaN to 0 and an
/// infinity or a negative to a saturated or negative credit — all of them "numbers" no proof of
/// work can stand behind.
pub fn creditable_difficulty(difficulty: f64) -> bool {
    difficulty.is_finite() && difficulty > 0.0 && difficulty <= MAX_CREDIT_DIFFICULTY
}

/// Quantise a share's work to integer micro-work.
///
/// Two things make this reproducible across nodes:
///
/// 1. `canonical_json_f64` first. `work` is an `f64` gossiped as JSON, and serde's round-trip is not
///    guaranteed bit-exact — the signature encoding already commits to the post-round-trip value for
///    exactly this reason, so the fold must quantise the same value the signature covered.
/// 2. Integers after. Once quantised, accumulation is order-independent; summing `f64` is not, and
///    order-dependent arithmetic is how you get two honest nodes with different totals.
///
/// Rounds half-away-from-zero, which is what SQLite's `ROUND` does; Rust's `f64::round` agrees.
pub fn micro_work(work: f64) -> i64 {
    (crate::types::canonical_json_f64(work) * MICRO).round() as i64
}

/// Canonical order for the shares inside a batch: `(timestamp asc, share_hash asc)`.
///
/// `share_hash` is compared in **internal byte order** — the storage order since schema v41, with
/// the proof-of-work zeros at the back. Sorting display-order hex would order shares differently on
/// a node that happened to reverse them, and the batch hash covers this order, so the two nodes
/// would disagree about a batch neither of them built wrongly.
///
/// The pair is a total order because `share_hash` is unique.
pub fn canonical_cmp(a: &ShareProof, b: &ShareProof) -> Ordering {
    a.timestamp
        .cmp(&b.timestamp)
        .then_with(|| a.share_hash.cmp(&b.share_hash))
}

/// Sort shares into canonical order in place.
pub fn canonical_sort(shares: &mut [ShareProof]) {
    shares.sort_by(canonical_cmp);
}

/// A proposer's high-water mark: the canonical position of the last share it has had adopted.
///
/// Compared exactly as [`canonical_cmp`] compares shares — `(timestamp, share_hash)`
/// lexicographically, with `share_hash` in internal byte order — so "after the watermark" and
/// "later in canonical order" are the same statement.
pub type ShareWatermark = (u64, [u8; 32]);

/// Per-proposer high-water marks, part of the chain's adopted state.
///
/// This is the O(1) cross-batch replay guard: `verify_batch` requires every share in a batch to
/// sort STRICTLY after its proposer's watermark, and adoption advances the watermark to the
/// batch's last share. Combined with the strictly-increasing canonical order already enforced
/// WITHIN a batch, no share can appear in two adopted batches from the same proposer — without a
/// per-share index, which the schema deliberately does not have.
pub type ProposerWatermarks = BTreeMap<[u8; 32], ShareWatermark>;

/// Outcome of folding shares into the running balances.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FoldOutcome {
    /// Shares credited.
    pub credited: usize,
    /// Shares skipped because the proof carries no payout address.
    ///
    /// Counted rather than ignored: the existing ledger drops these silently through an INNER JOIN,
    /// and "work that exists but is attributed to nobody" is worth being able to see.
    pub unattributed: usize,
}

/// Fold a batch's shares into per-address running balances.
///
/// Keyed on the payout address carried by the proof, which is what payouts group by. Accumulation
/// is `saturating_add` over `i64` micro-work, mirroring the existing Rust fold so the shadow-run
/// compares like with like.
///
/// Credits `share.difficulty`, NOT `share.work`. `work` is a free field the claiming node signs
/// for itself and nothing ever checks it against anything; `difficulty` is the field the PoW
/// preimage check (`sbc_checks::pow_ok`) actually verifies the header against, so it is the only
/// number in the proof with work standing behind it. The live ingest path stamps the two fields
/// with the same value, so for honestly produced shares this changes nothing — it changes what a
/// dishonest claim can be worth. Verification rejects any share whose difficulty fails
/// [`creditable_difficulty`], so an adopted batch can never fold a saturating credit; see the
/// caveat on [`MAX_CREDIT_DIFFICULTY`] for what this does NOT fix.
///
/// Order-independent by construction: integer addition commutes, so a node that receives the same
/// shares in a different order reaches the same balances.
pub fn fold_shares(balances: &mut BTreeMap<String, i64>, shares: &[ShareProof]) -> FoldOutcome {
    let mut outcome = FoldOutcome::default();
    for share in shares {
        let Some(addr) = share.payout_address.as_ref().filter(|a| !a.is_empty()) else {
            outcome.unattributed += 1;
            continue;
        };
        let entry = balances.entry(addr.clone()).or_insert(0);
        *entry = entry.saturating_add(micro_work(share.difficulty));
        outcome.credited += 1;
    }
    outcome
}

/// Domain tag for the batch commitment. Same versioning rule as the state root — a batch hashed
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ShareProof;

    /// Deterministic PRNG. A fixed seed rather than a random one so a failure is reproducible from
    /// the test name alone — a shuffle test that fails one run in fifty and cannot be replayed is
    /// worse than no test.
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 11
        }
        fn shuffle<T>(&mut self, v: &mut [T]) {
            for i in (1..v.len()).rev() {
                let j = (self.next() as usize) % (i + 1);
                v.swap(i, j);
            }
        }
    }

    fn share(ts: u64, hash_byte: u8, addr: &str, work: f64) -> ShareProof {
        ShareProof {
            round_id: 1,
            miner_id: [hash_byte; 32],
            difficulty: work,
            work,
            share_hash: [hash_byte; 32],
            timestamp: ts,
            received_by: [0u8; 32],
            template_id: None,
            payout_address: Some(addr.to_string()),
            header: None,
            tier_log2: None,
            signature: None,
        }
    }

    fn sample_shares() -> Vec<ShareProof> {
        vec![
            share(100, 3, "bc1qalice", 1.5),
            share(100, 1, "bc1qbob", 2.25),
            share(99, 9, "bc1qalice", 0.125),
            share(101, 2, "bc1qcarol", 7.0),
            share(100, 2, "bc1qbob", 0.5),
        ]
    }

    /// Quantisation must match the SQL the ledger already uses, including the half-away-from-zero
    /// rounding, or the shadow-run reports divergence that is really just two spellings of the same
    /// number.
    #[test]
    fn micro_work_matches_the_sql_quantisation() {
        assert_eq!(micro_work(1.0), 1_000_000);
        assert_eq!(micro_work(0.000001), 1);
        assert_eq!(micro_work(0.0000004), 0);
        assert_eq!(micro_work(2.5e-6), 3, "half rounds away from zero");
        assert_eq!(micro_work(0.0), 0);
        assert_eq!(micro_work(1234.567891), 1_234_567_891);
    }

    /// Any arrival order must sort to the same sequence — the batch hash covers this order, so a
    /// disagreement here is a disagreement about the batch itself.
    #[test]
    fn canonical_order_is_independent_of_arrival_order() {
        let mut reference = sample_shares();
        canonical_sort(&mut reference);
        let reference: Vec<_> = reference
            .iter()
            .map(|s| (s.timestamp, s.share_hash))
            .collect();

        let mut rng = Lcg(0xC0FFEE);
        for _ in 0..200 {
            let mut shuffled = sample_shares();
            rng.shuffle(&mut shuffled);
            canonical_sort(&mut shuffled);
            let got: Vec<_> = shuffled
                .iter()
                .map(|s| (s.timestamp, s.share_hash))
                .collect();
            assert_eq!(got, reference, "sort is not order-independent");
        }
    }

    /// Ties on timestamp are broken by share_hash, so equal-timestamp shares cannot be ordered
    /// differently by two nodes.
    #[test]
    fn equal_timestamps_are_broken_by_share_hash() {
        let a = share(100, 1, "bc1q", 1.0);
        let b = share(100, 2, "bc1q", 1.0);
        assert_eq!(canonical_cmp(&a, &b), Ordering::Less);
        assert_eq!(canonical_cmp(&b, &a), Ordering::Greater);
    }

    /// The fold must commute: same shares, any order, same balances.
    #[test]
    fn fold_is_independent_of_order() {
        let mut reference = BTreeMap::new();
        fold_shares(&mut reference, &sample_shares());

        let mut rng = Lcg(0xBEEF);
        for _ in 0..200 {
            let mut shuffled = sample_shares();
            rng.shuffle(&mut shuffled);
            let mut got = BTreeMap::new();
            fold_shares(&mut got, &shuffled);
            assert_eq!(got, reference, "fold is not order-independent");
        }
    }

    /// Folding a batch in two halves must equal folding it whole — this is what lets a node apply
    /// batches one at a time and still arrive where a node that replayed them together arrives.
    #[test]
    fn fold_is_associative_across_batch_boundaries() {
        let all = sample_shares();
        let mut whole = BTreeMap::new();
        fold_shares(&mut whole, &all);

        let mut split = BTreeMap::new();
        let (a, b) = all.split_at(2);
        fold_shares(&mut split, a);
        fold_shares(&mut split, b);

        assert_eq!(whole, split);
    }

    /// Work with no payout address is counted, not silently dropped.
    #[test]
    fn unattributed_shares_are_counted() {
        let mut shares = sample_shares();
        shares.push(share(102, 44, "", 5.0));
        let mut s = share(103, 45, "x", 5.0);
        s.payout_address = None;
        shares.push(s);

        let mut balances = BTreeMap::new();
        let outcome = fold_shares(&mut balances, &shares);
        assert_eq!(outcome.credited, 5);
        assert_eq!(
            outcome.unattributed, 2,
            "empty and absent both count as unattributed"
        );
    }

    /// **The fold credits the PROVEN field.** `work` is a free field the claiming node signs for
    /// itself; `difficulty` is what the PoW preimage check verifies the header against. A fold
    /// that read `work` would credit whatever was claimed regardless of what was proven.
    #[test]
    fn the_fold_credits_difficulty_not_claimed_work() {
        let mut s = share(100, 1, "bc1qalice", 1.0);
        s.difficulty = 1.0;
        s.work = 999_999.0; // an inflated claim nothing verifies

        let mut balances = BTreeMap::new();
        fold_shares(&mut balances, &[s]);
        assert_eq!(
            balances.get("bc1qalice"),
            Some(&micro_work(1.0)),
            "credit must follow the PoW-verified difficulty, not the self-signed work claim"
        );
    }

    /// The saturation the credit cap exists to stop: one absurd difficulty is worth `i64::MAX`
    /// micro-work under the raw cast. The cap is the LAST value that cannot saturate with an
    /// order of magnitude to spare, and everything beyond or beneath the creditable range is
    /// refused.
    #[test]
    fn the_credit_cap_excludes_everything_that_could_saturate() {
        // The hazard is real: the raw cast saturates.
        assert_eq!(micro_work(f64::MAX), i64::MAX);
        assert_eq!(micro_work(1e19), i64::MAX);

        // The cap itself is safely representable...
        assert!(creditable_difficulty(MAX_CREDIT_DIFFICULTY));
        assert!(micro_work(MAX_CREDIT_DIFFICULTY) < i64::MAX / 9);

        // ...and everything unprovable or saturating is not creditable.
        for bad in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            0.0,
            -1.0,
            MAX_CREDIT_DIFFICULTY * 1.001,
            f64::MAX,
        ] {
            assert!(!creditable_difficulty(bad), "{bad} must not be creditable");
        }
        assert!(
            creditable_difficulty(1e-9),
            "tiny real difficulties stay creditable"
        );
        assert!(
            creditable_difficulty(1_000_000.0),
            "farm-tier vardiff stays creditable"
        );
    }
}
