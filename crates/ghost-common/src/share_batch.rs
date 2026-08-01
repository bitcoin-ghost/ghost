//! Share-batch chain: the deterministic core.
//!
//! Every node must derive **byte-identical** numbers from the same batch, because a batch is
//! accepted by exact equality — a validator recomputes the fold and compares roots. There is no
//! tolerance to absorb a disagreement, which is the point: today's tolerance exists precisely
//! because nodes could not agree, and removing the disagreement is what removes the need for it.
//!
//! So everything here is a pure function of its inputs, and the encodings are pinned by golden
//! vectors. Nothing in this module reads a clock, a database, or the network.
//!
//! Dark code: nothing wires this into a runtime path yet.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::types::ShareProof;

/// Domain tag for the running-state commitment. Bump the version on ANY encoding change — a root
/// computed under a different encoding is not comparable, and a silent change would split the fleet
/// rather than fail loudly.
const STATE_ROOT_DOMAIN: &[u8] = b"SbcStateRoot/v1";

/// Fixed-point scale for share work, matching the ledger's SQL exactly.
///
/// The existing payout path quantises with `CAST(ROUND(work * 1000000) AS INTEGER)`
/// (`get_top_unpaid_addresses`), and the shadow-run compares batch totals against that path, so any
/// difference here shows up as a false divergence.
const MICRO: f64 = 1_000_000.0;

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
        *entry = entry.saturating_add(micro_work(share.work));
        outcome.credited += 1;
    }
    outcome
}

/// Commit to the running state after a batch.
///
/// Follows the `compute_ledger_root` discipline already used for payout checkpoints: a domain tag,
/// then every field length-prefixed, then entries in a canonical order — so no two distinct states
/// can serialize to the same bytes by running fields together.
///
/// `BTreeMap` gives address-ascending iteration for free, which is the canonical order; taking a
/// `HashMap` here would reintroduce exactly the nondeterminism this function exists to remove.
pub fn compute_state_root(balances: &BTreeMap<String, i64>, seq: u64, close_ts: i64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(STATE_ROOT_DOMAIN);
    hasher.update(seq.to_le_bytes());
    hasher.update(close_ts.to_le_bytes());
    hasher.update((balances.len() as u32).to_le_bytes());
    for (addr, micro) in balances {
        hasher.update((addr.len() as u32).to_le_bytes());
        hasher.update(addr.as_bytes());
        hasher.update(micro.to_le_bytes());
    }
    hasher.finalize().into()
}

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

    /// Independently-derived state must be byte-identical. This is the property the whole batch
    /// design rests on: eight nodes, different arrival orders, one root.
    #[test]
    fn state_root_is_identical_across_simulated_nodes() {
        let mut rng = Lcg(0x5EED);
        let mut roots = Vec::new();
        for _ in 0..8 {
            let mut shares = sample_shares();
            rng.shuffle(&mut shares);
            let mut balances = BTreeMap::new();
            fold_shares(&mut balances, &shares);
            roots.push(compute_state_root(&balances, 500, 1_700_000_000));
        }
        assert!(
            roots.windows(2).all(|w| w[0] == w[1]),
            "simulated nodes derived different roots from the same shares"
        );
    }

    /// A one-micro-work difference must change the root. A commitment that misses small differences
    /// would let a divergence through exactly where it matters least visibly.
    #[test]
    fn state_root_detects_a_single_micro_work_difference() {
        let mut a = BTreeMap::new();
        fold_shares(&mut a, &sample_shares());
        let mut b = a.clone();
        *b.get_mut("bc1qalice").expect("alice present") += 1;

        assert_ne!(
            compute_state_root(&a, 1, 0),
            compute_state_root(&b, 1, 0),
            "root ignored a 1-micro-work change"
        );
    }

    /// seq and close_ts are bound, so the same balances at a different point in the chain commit
    /// differently.
    #[test]
    fn state_root_binds_seq_and_close_ts() {
        let mut balances = BTreeMap::new();
        fold_shares(&mut balances, &sample_shares());
        let base = compute_state_root(&balances, 1, 100);
        assert_ne!(base, compute_state_root(&balances, 2, 100), "seq not bound");
        assert_ne!(
            base,
            compute_state_root(&balances, 1, 101),
            "close_ts not bound"
        );
    }

    /// Length prefixes must make field boundaries unambiguous: two different address sets that
    /// would concatenate to the same bytes must still commit differently.
    #[test]
    fn state_root_is_not_confusable_by_running_fields_together() {
        let mut a = BTreeMap::new();
        a.insert("ab".to_string(), 1);
        a.insert("c".to_string(), 2);
        let mut b = BTreeMap::new();
        b.insert("a".to_string(), 1);
        b.insert("bc".to_string(), 2);

        assert_ne!(
            compute_state_root(&a, 1, 0),
            compute_state_root(&b, 1, 0),
            "address boundaries are ambiguous — length prefixing is not working"
        );
    }

    /// Golden vector, pinning `SbcStateRoot/v1` at the moment the encoding was defined.
    ///
    /// If this ever fails, the encoding changed. The fix is a domain-tag version bump plus a height
    /// gate so every node switches at the same block — **not** updating the expected value here.
    /// Editing the vector to match makes the test agree with whatever the code now does, which is
    /// the one thing it exists to prevent.
    #[test]
    fn state_root_golden_vector() {
        let mut balances = BTreeMap::new();
        fold_shares(&mut balances, &sample_shares());
        let root = compute_state_root(&balances, 500, 1_700_000_000);

        assert_eq!(
            hex::encode(root),
            "232e0aa5ea4d4af956a0e80a7535dac538d17e3245eb2416f5c39c06b365bb63",
            "state-root encoding changed — bump SbcStateRoot/v{{n}} and gate it, do not edit this \
             vector to match"
        );
    }
}
