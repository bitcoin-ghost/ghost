//! A bounded negative cache for share proofs that can never become valid.
//!
//! #583: fourteen genuinely-bad shares produced sixty-seven rejections in ten minutes on one node,
//! and would have gone on producing them indefinitely. Rejecting them is correct — they claim more
//! work than their hash proves — but nothing recorded that the verdict was *final*, so backfill
//! kept requesting them, peers kept sending them, and every node kept spending a `sha256d` and a
//! log line on each redelivery, for ever.
//!
//! This remembers terminal verdicts so a proof that has already been judged unfixable is dropped at
//! ingest instead of re-entering verification.
//!
//! # Only terminal failures
//!
//! A failure is cacheable only if re-delivering the *same bytes* must produce the same verdict:
//!
//! - `hash_mismatch` — `sha256d(header) != share_hash`. Deterministic in the proof's own bytes.
//! - `below_difficulty` — the hash does not reach the claimed difficulty. Also deterministic.
//!
//! `missing_header` is **not** cacheable: a later delivery of the same share may carry the header
//! that this one lacked. That is a `Defer`, not a `Fault`, and it must stay retryable.
//!
//! # Why the key is not the share hash
//!
//! Keying on `share_hash` alone would be a poisoning vector. A hostile peer could take a legitimate
//! share, gossip it with an inflated difficulty, watch every node cache that hash as bad, and the
//! honest delivery would then be dropped without ever being checked — the attacker would be able to
//! suppress a competitor's work for the price of one forged message.
//!
//! So the key is a digest of exactly the inputs the verdict is a function of — the header, the
//! hash, and the claimed difficulty. Change any of them and it is a different claim that has not
//! been judged, and it gets verified on its merits. Redelivery of the identical bad proof hits;
//! a different claim about the same share does not.

use std::collections::{HashSet, VecDeque};

use parking_lot::Mutex;

/// Entries retained before the oldest is evicted.
///
/// Sized from measurement. The bad-share population a node encounters is **finite**: on vm5 the
/// distinct set grew to 598 and then stopped dead, after which new judgements fell to zero and
/// every further arrival was an already-known redelivery (1,343 in one five-minute window). The
/// backlog is historical — shares produced in bursts during vardiff retargets — so a node learns
/// it once and is then quiet. It is re-learned after each restart, since this cache is in memory.
///
/// 598 is the figure for one node over one pass. Producers with more history behind them will hold
/// more, and the whole point is to avoid re-verifying, so the capacity carries real headroom rather
/// than tracking the observed number. 256Ki keys is ~4 MB of key material against a process that
/// already works in the gigabytes.
///
/// An eviction is not a correctness problem — the proof simply gets verified once more — so this is
/// a throughput knob, not a safety one.
pub const DEFAULT_CAPACITY: usize = 262_144;

/// A digest of the bytes a terminal verdict is a function of.
pub type VerdictKey = [u8; 16];

/// Derive the cache key from exactly the inputs to the PoW verification.
///
/// Must stay in step with `DifficultyCalculator::verify_pow_preimage`: if that ever considers a
/// further input, it belongs in here too, or a proof could be cached under a verdict that no longer
/// follows from its key.
pub fn verdict_key(header80: &[u8; 80], share_hash: &[u8; 32], difficulty: f64) -> VerdictKey {
    use bitcoin::hashes::{sha256, Hash};
    let mut buf = Vec::with_capacity(80 + 32 + 8);
    buf.extend_from_slice(header80);
    buf.extend_from_slice(share_hash);
    // to_bits() so NaN and -0.0 are distinguished bit-exactly rather than by float comparison.
    buf.extend_from_slice(&difficulty.to_bits().to_be_bytes());
    let d = sha256::Hash::hash(&buf).to_byte_array();
    let mut k = [0u8; 16];
    k.copy_from_slice(&d[..16]);
    k
}

/// Bounded FIFO set of terminal verdicts.
pub struct TerminalRejectCache {
    capacity: usize,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    seen: HashSet<VerdictKey>,
    order: VecDeque<VerdictKey>,
}

impl TerminalRejectCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            inner: Mutex::new(Inner::default()),
        }
    }

    /// True if this exact claim has already been judged terminally invalid.
    pub fn contains(&self, key: &VerdictKey) -> bool {
        self.inner.lock().seen.contains(key)
    }

    /// Record a terminal verdict, evicting the oldest entry if full.
    pub fn insert(&self, key: VerdictKey) {
        let mut g = self.inner.lock();
        if !g.seen.insert(key) {
            return; // already known — do not re-queue, or one key could fill the window
        }
        g.order.push_back(key);
        while g.order.len() > self.capacity {
            if let Some(old) = g.order.pop_front() {
                g.seen.remove(&old);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for TerminalRejectCache {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(b: u8) -> [u8; 80] {
        [b; 80]
    }
    fn hash(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn a_repeated_identical_claim_hits() {
        let c = TerminalRejectCache::default();
        let k = verdict_key(&hdr(1), &hash(2), 1000.0);
        assert!(!c.contains(&k));
        c.insert(k);
        assert!(c.contains(&verdict_key(&hdr(1), &hash(2), 1000.0)));
    }

    // The poisoning guard. This is the reason the key is not just the share hash.
    #[test]
    fn a_different_difficulty_for_the_same_share_is_not_suppressed() {
        let c = TerminalRejectCache::default();
        // Hostile: real share, inflated difficulty. Gets judged terminal and cached.
        c.insert(verdict_key(&hdr(1), &hash(2), 999_999.0));
        // Honest delivery of the SAME share with its true difficulty must still be verified.
        assert!(
            !c.contains(&verdict_key(&hdr(1), &hash(2), 1000.0)),
            "an attacker must not be able to suppress a share by over-claiming it once"
        );
    }

    #[test]
    fn a_different_header_for_the_same_share_is_not_suppressed() {
        let c = TerminalRejectCache::default();
        c.insert(verdict_key(&hdr(9), &hash(2), 1000.0));
        assert!(!c.contains(&verdict_key(&hdr(1), &hash(2), 1000.0)));
    }

    #[test]
    fn it_stays_bounded_and_evicts_oldest_first() {
        let c = TerminalRejectCache::new(4);
        let keys: Vec<_> = (0..6u8)
            .map(|i| verdict_key(&hdr(i), &hash(i), 1.0))
            .collect();
        for k in &keys {
            c.insert(*k);
        }
        assert_eq!(c.len(), 4, "must not grow past capacity");
        assert!(!c.contains(&keys[0]), "oldest evicted");
        assert!(!c.contains(&keys[1]));
        assert!(c.contains(&keys[5]), "newest retained");
    }

    #[test]
    fn reinserting_a_known_key_does_not_consume_capacity() {
        let c = TerminalRejectCache::new(3);
        let hot = verdict_key(&hdr(1), &hash(1), 1.0);
        for _ in 0..50 {
            c.insert(hot);
        }
        // A share redelivered in a loop must not evict everything else — that is the exact
        // behaviour #583 exhibits.
        c.insert(verdict_key(&hdr(2), &hash(2), 1.0));
        c.insert(verdict_key(&hdr(3), &hash(3), 1.0));
        assert!(c.contains(&hot));
        assert_eq!(c.len(), 3);
    }

    #[test]
    fn nan_and_zero_difficulties_do_not_collide() {
        let a = verdict_key(&hdr(1), &hash(1), 0.0);
        let b = verdict_key(&hdr(1), &hash(1), -0.0);
        assert_ne!(a, b, "to_bits must distinguish these");
    }
}
