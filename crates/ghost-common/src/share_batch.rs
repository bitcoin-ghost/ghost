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

/// Domain tag for the batch commitment. Same versioning rule as the state root — a batch hashed
/// under a different encoding is not comparable, so any change bumps the version and is gated.
const BATCH_HASH_DOMAIN: &[u8] = b"ShareBatch/v1";

/// One link in the share-batch chain.
///
/// The adopted chain **is** the share ledger. A batch is self-proving: every share in it carries
/// its own PoW and signature, so a validator checks validity rather than asking whether it happens
/// to hold the same shares. That is what lets agreement be verification instead of election.
///
/// `seq` is independent of block height. Share consensus runs on its own cadence and never waits on
/// a block — the whole point of the redesign is that a tip change *consumes* the latest agreed
/// batch rather than triggering agreement.
#[derive(Debug, Clone)]
pub struct ShareBatch {
    /// Position in the chain. Increments by one per adopted batch; unrelated to block height.
    pub seq: u64,
    /// Hash of the previous batch, making the chain a chain.
    pub prev_batch_hash: [u8; 32],
    /// When the proposer closed this batch. Advisory — a share's eligibility is decided by chain
    /// membership, not by landing inside a window.
    pub close_ts: i64,
    /// Who proposed it, per the deterministic round-robin.
    pub proposer: [u8; 32],
    /// The shares, in canonical order.
    pub shares: Vec<ShareProof>,
    /// Blocks whose settlements are folded into this batch's state.
    ///
    /// Block hashes only. An earlier design carried `(block_hash, proposal_hash)` pairs, but the
    /// coinbase now names the payout it pays, so the second half was redundant — every validator
    /// resolves it from its own chain. What the batch still has to say is *which* settlements are
    /// included, because nodes observe blocks at different moments relative to a batch close, and
    /// without a stated cut point two honest nodes fold different sets and their roots diverge.
    pub settled_blocks: Vec<[u8; 32]>,
    /// Qualified-node shares (the 5-4-3-2-1 snapshot) as of this batch.
    pub node_shares: Vec<([u8; 32], i32)>,
    /// Commitment to the running per-address balances after applying this batch.
    pub state_root: [u8; 32],
    /// Whether shares were deferred to the next batch for want of room.
    ///
    /// Carried so a peer can tell a full batch from a truncated one. Without it, "the proposer had
    /// nothing more" and "the proposer had more and could not fit it" look identical.
    pub truncated: bool,
    /// How many shares were deferred.
    pub pending_count: u32,
    /// The proposer's signature over [`ShareBatch::batch_hash`].
    pub proposer_signature: Vec<u8>,
}

impl ShareBatch {
    /// Commitment to everything in this batch except the signature over it.
    ///
    /// Shares are committed by their **canonical signing bytes**, not by their serialized form. The
    /// wire encoding is JSON and two nodes need not produce byte-identical JSON, so hashing the
    /// serialized proof would make the batch hash depend on an accident of serialization. The
    /// signing bytes are canonical by construction — they are what the GHOST-09 signature already
    /// covers — so both sides agree.
    ///
    /// The signature is excluded because it is *over* this hash; including it would be circular.
    pub fn batch_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(BATCH_HASH_DOMAIN);
        h.update(self.seq.to_le_bytes());
        h.update(self.prev_batch_hash);
        h.update(self.close_ts.to_le_bytes());
        h.update(self.proposer);

        h.update((self.shares.len() as u32).to_le_bytes());
        for share in &self.shares {
            let bytes = share.signing_bytes();
            h.update((bytes.len() as u32).to_le_bytes());
            h.update(&bytes);
        }

        h.update((self.settled_blocks.len() as u32).to_le_bytes());
        for block in &self.settled_blocks {
            h.update(block);
        }

        h.update((self.node_shares.len() as u32).to_le_bytes());
        for (node, shares) in &self.node_shares {
            h.update(node);
            h.update(shares.to_le_bytes());
        }

        h.update(self.state_root);
        h.update([self.truncated as u8]);
        h.update(self.pending_count.to_le_bytes());
        h.finalize().into()
    }

    /// Whether this batch follows `previous`.
    ///
    /// Checked rather than assumed: a batch whose parent is not the adopted head is not a
    /// disagreement about contents, it is a node looking at a different chain, and it should sync
    /// rather than vote.
    pub fn follows(&self, previous: &ShareBatch) -> bool {
        self.seq == previous.seq.saturating_add(1)
            && self.prev_batch_hash == previous.batch_hash()
            && self.close_ts > previous.close_ts
    }
}

/// How a batch was packed against a byte budget.
///
/// Not `PartialEq`: `ShareProof` deliberately is not, so compare packs by `share_hash` — which is
/// the identity that matters anyway.
#[derive(Debug, Clone)]
pub struct PackOutcome {
    /// Shares that fit, in canonical order.
    pub included: Vec<ShareProof>,
    /// Shares that did not fit, in canonical order. They are not lost — they are the head of the
    /// next batch.
    pub deferred: Vec<ShareProof>,
    /// Whether anything was deferred. Carried in the batch so a peer can tell a full batch from a
    /// truncated one; without it, "the proposer had nothing more" and "the proposer had more but
    /// could not fit it" look identical, which is the #558 failure repeated.
    pub truncated: bool,
}

/// Per-proof overhead when a batch is serialized as a JSON array: one separator.
const JSON_SEPARATOR_BYTES: usize = 1;

/// Pack shares into a batch that fits `budget_bytes`, deferring the rest.
///
/// Bounded on the SEND side deliberately. Message caps in this codebase are enforced on receive and
/// a violation is dropped at `debug!` — so an oversized batch would vanish silently and the chain
/// would stall with no error anywhere. A proposer that cannot build a legal batch should know it at
/// build time, which is what `truncated` reports.
///
/// Shares are taken in canonical order, so the split is deterministic: the same input and budget
/// produce the same batch on any node, and the deferred remainder is the natural head of the next
/// one. Nothing is dropped — `included` and `deferred` partition the input exactly.
///
/// The size estimate sums each proof's serialized length plus a separator. That slightly
/// under-counts the enclosing array's fixed overhead, so callers should leave headroom in
/// `budget_bytes` rather than passing the hard cap; `packed_size` exists to assert the real
/// encoded size in tests.
///
/// A single proof larger than the whole budget would otherwise wedge the chain forever — the same
/// share retried at the head of every batch. It is included alone instead, so the batch is
/// oversized and visibly wrong rather than silently stuck; the caller must treat an oversized
/// single-proof batch as a hard error.
pub fn pack_batch(shares: &[ShareProof], budget_bytes: usize) -> PackOutcome {
    let mut ordered = shares.to_vec();
    canonical_sort(&mut ordered);

    let mut used = 0usize;
    let mut split_at = 0usize;
    for (i, share) in ordered.iter().enumerate() {
        let size = serde_json::to_vec(share).map(|v| v.len()).unwrap_or(0) + JSON_SEPARATOR_BYTES;
        if i > 0 && used + size > budget_bytes {
            break;
        }
        used += size;
        split_at = i + 1;
    }

    let deferred = ordered.split_off(split_at);
    let truncated = !deferred.is_empty();
    PackOutcome {
        included: ordered,
        deferred,
        truncated,
    }
}

/// Actual serialized size of a packed share list, for asserting a pack really fits.
pub fn packed_size(shares: &[ShareProof]) -> usize {
    serde_json::to_vec(shares).map(|v| v.len()).unwrap_or(0)
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

    /// Nothing may be lost or duplicated at the truncation boundary. A share that is neither
    /// included nor deferred is work a miner did and will never be paid for.
    #[test]
    fn packing_partitions_the_input_exactly() {
        let shares = sample_shares();
        for budget in [0usize, 1, 200, 500, 900, 5_000, 100_000] {
            let out = pack_batch(&shares, budget);

            let mut seen: Vec<[u8; 32]> = out
                .included
                .iter()
                .chain(out.deferred.iter())
                .map(|s| s.share_hash)
                .collect();
            seen.sort();
            let mut expected: Vec<[u8; 32]> = shares.iter().map(|s| s.share_hash).collect();
            expected.sort();

            assert_eq!(
                seen, expected,
                "budget {budget}: packing lost or duplicated a share"
            );
        }
    }

    /// When everything fits, nothing is deferred and nothing claims truncation.
    #[test]
    fn a_batch_that_fits_is_not_marked_truncated() {
        let shares = sample_shares();
        let out = pack_batch(&shares, 1_000_000);
        assert_eq!(out.included.len(), shares.len());
        assert!(out.deferred.is_empty());
        assert!(!out.truncated);
    }

    /// A budget too small for even one proof must still make progress. Deferring everything would
    /// mean the same share heads every future batch and the chain never advances — so the first
    /// share goes in alone and the batch is visibly oversized instead of silently stuck.
    #[test]
    fn an_impossible_budget_still_makes_progress() {
        let shares = sample_shares();
        let out = pack_batch(&shares, 0);
        assert_eq!(
            out.included.len(),
            1,
            "a zero budget must still emit one share rather than wedging the chain"
        );
        assert!(out.truncated);
        assert_eq!(out.deferred.len(), shares.len() - 1);
    }

    /// The split must be canonical, so any node packing the same pending set picks the same batch.
    #[test]
    fn packing_is_deterministic_and_canonically_ordered() {
        let hashes =
            |v: &[ShareProof]| -> Vec<[u8; 32]> { v.iter().map(|s| s.share_hash).collect() };

        let mut rng = Lcg(0xFACADE);
        let reference = pack_batch(&sample_shares(), 700);
        let reference_included = hashes(&reference.included);
        let reference_deferred = hashes(&reference.deferred);

        for _ in 0..100 {
            let mut shuffled = sample_shares();
            rng.shuffle(&mut shuffled);
            let got = pack_batch(&shuffled, 700);
            assert_eq!(
                hashes(&got.included),
                reference_included,
                "packing depends on arrival order"
            );
            assert_eq!(hashes(&got.deferred), reference_deferred);
            assert_eq!(got.truncated, reference.truncated);
        }

        let mut sorted = reference.included.clone();
        canonical_sort(&mut sorted);
        assert_eq!(
            hashes(&reference.included),
            hashes(&sorted),
            "included list is not canonical"
        );
    }

    /// Deferred shares are the head of the next batch, so packing repeatedly must drain the pool
    /// and terminate rather than loop.
    #[test]
    fn repeated_packing_drains_the_pending_pool() {
        let mut pending = sample_shares();
        let mut batches = 0;
        let mut emitted = 0;
        while !pending.is_empty() {
            let out = pack_batch(&pending, 700);
            assert!(
                !out.included.is_empty(),
                "a batch must always make progress"
            );
            emitted += out.included.len();
            pending = out.deferred;
            batches += 1;
            assert!(batches < 100, "packing did not terminate");
        }
        assert_eq!(emitted, sample_shares().len());
    }

    /// The estimate must not under-count so badly that a "fitting" batch is actually oversized.
    /// Checked against the real encoded length with the headroom the doc comment asks callers for.
    #[test]
    fn a_packed_batch_fits_its_budget_when_actually_encoded() {
        let shares = sample_shares();
        for budget in [400usize, 700, 1_200, 5_000] {
            let out = pack_batch(&shares, budget);
            if out.included.len() > 1 {
                assert!(
                    packed_size(&out.included) <= budget + 64,
                    "budget {budget}: encoded {} exceeded the estimate by more than the \
                     documented headroom",
                    packed_size(&out.included)
                );
            }
        }
    }

    fn a_batch() -> ShareBatch {
        let mut shares = sample_shares();
        canonical_sort(&mut shares);
        let mut balances = BTreeMap::new();
        fold_shares(&mut balances, &shares);
        ShareBatch {
            seq: 500,
            prev_batch_hash: [0x11; 32],
            close_ts: 1_700_000_000,
            proposer: [0x22; 32],
            shares,
            settled_blocks: vec![[0x33; 32]],
            node_shares: vec![([0x44; 32], 15)],
            state_root: compute_state_root(&balances, 500, 1_700_000_000),
            truncated: false,
            pending_count: 0,
            proposer_signature: vec![0x55; 64],
        }
    }

    /// Every field must be covered, or a batch could be altered without changing its identity —
    /// and the identity is what a quorum signs.
    #[test]
    fn the_batch_hash_covers_every_field() {
        let base = a_batch();
        let h = base.batch_hash();

        let mut b = base.clone();
        b.seq += 1;
        assert_ne!(h, b.batch_hash(), "seq not covered");

        let mut b = base.clone();
        b.prev_batch_hash = [0x99; 32];
        assert_ne!(h, b.batch_hash(), "prev_batch_hash not covered");

        let mut b = base.clone();
        b.close_ts += 1;
        assert_ne!(h, b.batch_hash(), "close_ts not covered");

        let mut b = base.clone();
        b.proposer = [0x99; 32];
        assert_ne!(h, b.batch_hash(), "proposer not covered");

        let mut b = base.clone();
        b.shares.pop();
        assert_ne!(h, b.batch_hash(), "shares not covered");

        let mut b = base.clone();
        b.settled_blocks.push([0x77; 32]);
        assert_ne!(h, b.batch_hash(), "settled_blocks not covered");

        let mut b = base.clone();
        b.node_shares[0].1 = 14;
        assert_ne!(h, b.batch_hash(), "node_shares not covered");

        let mut b = base.clone();
        b.state_root = [0x99; 32];
        assert_ne!(h, b.batch_hash(), "state_root not covered");

        let mut b = base.clone();
        b.truncated = true;
        assert_ne!(h, b.batch_hash(), "truncated not covered");

        let mut b = base.clone();
        b.pending_count = 7;
        assert_ne!(h, b.batch_hash(), "pending_count not covered");
    }

    /// The signature is over the hash, so it cannot be inside it.
    #[test]
    fn the_batch_hash_excludes_the_signature() {
        let base = a_batch();
        let mut resigned = base.clone();
        resigned.proposer_signature = vec![0xEE; 64];
        assert_eq!(
            base.batch_hash(),
            resigned.batch_hash(),
            "including the signature would make signing it circular"
        );
    }

    /// Committing to shares by their canonical signing bytes rather than their serialized form:
    /// two nodes need not produce identical JSON, and a batch identity that depended on that would
    /// diverge for no reason.
    #[test]
    fn reordering_shares_changes_the_batch_hash() {
        let base = a_batch();
        let mut swapped = base.clone();
        swapped.shares.swap(0, 1);
        assert_ne!(
            base.batch_hash(),
            swapped.batch_hash(),
            "share order is part of the batch identity"
        );
    }

    /// Chaining is checked, not assumed. A batch whose parent is not our head means we are looking
    /// at a different chain and should sync, which is a different response from disagreeing.
    #[test]
    fn follows_requires_sequence_parent_and_forward_time() {
        let parent = a_batch();
        let mut child = a_batch();
        child.seq = parent.seq + 1;
        child.prev_batch_hash = parent.batch_hash();
        child.close_ts = parent.close_ts + 30;
        assert!(child.follows(&parent));

        let mut wrong_seq = child.clone();
        wrong_seq.seq = parent.seq + 2;
        assert!(!wrong_seq.follows(&parent), "a gap must not chain");

        let mut wrong_parent = child.clone();
        wrong_parent.prev_batch_hash = [0xAB; 32];
        assert!(
            !wrong_parent.follows(&parent),
            "a different parent must not chain"
        );

        let mut backwards = child.clone();
        backwards.close_ts = parent.close_ts - 1;
        assert!(!backwards.follows(&parent), "time must move forward");
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
