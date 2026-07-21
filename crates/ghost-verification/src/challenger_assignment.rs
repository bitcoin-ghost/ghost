//! Consensus-drawn challenger assignment (Surface A-2b).
//!
//! Node-reward qualification only trusts a `passed` verdict from a challenger
//! that was ASSIGNED to challenge that target this round. Assignment is a pure,
//! deterministic function of public, converged inputs — a shared block-hash
//! beacon (`seed`), the round height, and the converged candidate pool — so
//! every node recomputes the identical draw and a verdict from anyone who was
//! not drawn is simply ignored. No proof object travels with the verdict; the
//! challenger's existing signature proves authenticity, and this recompute
//! proves eligibility.
//!
//! ## Why this matters
//!
//! Without assignment, challenger selection is self-chosen: the "random" only
//! binds honest nodes, so a Sybil operator points all its fakes at its own
//! target and rubber-stamps `passed`, winning that target's LOCAL vote without a
//! global majority. Under assignment, neither the target nor a challenger can
//! steer who is drawn (the unpredictable `seed` and the target id are both
//! inputs), so the only way to control a target's challenger majority is to
//! control a majority of the network's distinct network positions — the
//! honest-majority floor, which is the best any permissionless system achieves.
//!
//! ## Subnet is the unit, not the identity
//!
//! The pool is deduplicated to one candidate per distinct `/24` subnet BEFORE
//! ranking, and candidates sharing the target's subnet (or with no known subnet)
//! are excluded. So minting many identities on one machine buys no extra draw
//! share — an attacker must field genuinely distinct network positions.
//!
//! This module is pure (no I/O) and fully unit-tested; callers supply the seed,
//! the converged pool, and the fan-out `k`.

use sha2::{Digest, Sha256};

/// Per-round, per-target number of assigned challengers (the draw fan-out). The
/// SAME value must be used at selection time (a node challenges the targets it is
/// drawn for) and at qualification time (a verdict counts only if its challenger
/// was drawn), or honest verdicts would be dropped. Sized with headroom above the
/// small-network floor; higher qualification floors are reached by accumulation
/// across the many rounds in the 7-day lookback window, not by one large round.
pub const ROUND_FANOUT_K: usize = 16;

/// Finality lag between a round and the block whose hash seeds it: a round at tip
/// height `H` is seeded by `blockhash(H - SEED_LAG)`, buried enough that a miner
/// cannot grind the tip to steer the draw. Canonical home for the value that
/// `ghost_pool::CHALLENGER_ASSIGNMENT_SEED_LAG` re-exports.
pub const SEED_LAG: u64 = 6;

/// Read-only accessor for L1 block hashes by height — the consensus beacon source.
/// The seed for a round is the block hash at `round_height - SEED_LAG`; every node
/// reads the same buried hash from its own chain, so the draw is identical
/// fleet-wide. (Must be the shared L1 chain, NOT a pool-local table which can be
/// gappy and diverge.)
pub trait BlockHashProvider: Send + Sync {
    /// The 32-byte block hash at `height`, or `None` if unavailable (node behind,
    /// height not yet buried, or lookup error) — in which case a verdict for that
    /// round cannot be assignment-verified and is simply not counted (fail-safe:
    /// never falsely counted, at worst a legitimate verdict qualifies slower).
    fn hash_at(&self, height: u64) -> Option<[u8; 32]>;
}

/// A candidate in the challenger draw: a node and the `/24` subnet it was
/// observed on. `subnet` is `None` when the node's network position is unknown
/// (it is then never drawn — it cannot prove a distinct position).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignmentCandidate {
    /// Hex-encoded node id.
    pub node_id: String,
    /// `/24` subnet prefix (`"a.b.c"`), or `None` if unknown/unparseable.
    pub subnet: Option<String>,
}

impl AssignmentCandidate {
    pub fn new(node_id: impl Into<String>, subnet: Option<String>) -> Self {
        Self {
            node_id: node_id.into(),
            subnet,
        }
    }
}

/// The per-candidate ranking score: `SHA256(seed ‖ round_height ‖ target ‖ candidate)`.
/// Returned as the raw 32-byte digest so callers rank by byte order.
fn score(
    seed: &[u8],
    round_height: u64,
    target_node_id: &str,
    candidate_node_id: &str,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(seed);
    h.update(round_height.to_le_bytes());
    h.update(target_node_id.as_bytes());
    h.update(candidate_node_id.as_bytes());
    h.finalize().into()
}

/// Reduce the pool to the eligible, subnet-deduplicated candidate set for
/// `target`: drop the target itself, drop candidates with no known subnet, drop
/// candidates sharing the target's subnet, and keep exactly one representative
/// per remaining distinct subnet (the lowest `node_id`, for determinism).
fn eligible_candidates<'a>(
    pool: &'a [AssignmentCandidate],
    target_node_id: &str,
) -> Vec<&'a AssignmentCandidate> {
    // The target's own subnet, if known — same-subnet peers are excluded.
    let target_subnet: Option<&str> = pool
        .iter()
        .find(|c| c.node_id == target_node_id)
        .and_then(|c| c.subnet.as_deref());

    // One representative per subnet: the candidate with the lowest node_id.
    // BTreeMap keeps this deterministic regardless of input ordering.
    use std::collections::BTreeMap;
    let mut by_subnet: BTreeMap<&str, &AssignmentCandidate> = BTreeMap::new();
    for c in pool {
        if c.node_id == target_node_id {
            continue;
        }
        let subnet = match c.subnet.as_deref() {
            Some(s) if !s.is_empty() => s,
            _ => continue, // unknown position → never drawn
        };
        if Some(subnet) == target_subnet {
            continue; // same subnet as the target → excluded
        }
        by_subnet
            .entry(subnet)
            .and_modify(|rep| {
                if c.node_id < rep.node_id {
                    *rep = c;
                }
            })
            .or_insert(c);
    }
    by_subnet.into_values().collect()
}

/// Deterministically draw the challengers assigned to `target_node_id` for the
/// round seeded by `seed` at `round_height`. Returns up to `k` node ids
/// (hex), sorted ascending for a stable, comparable result.
///
/// Same inputs → same output on every node.
pub fn assigned_challengers(
    seed: &[u8],
    round_height: u64,
    pool: &[AssignmentCandidate],
    target_node_id: &str,
    k: usize,
) -> Vec<String> {
    if k == 0 {
        return Vec::new();
    }
    let candidates = eligible_candidates(pool, target_node_id);

    // Rank by (score, node_id): the score is the draw; node_id breaks ties
    // deterministically so two candidates with an (astronomically unlikely)
    // score collision still order identically on every node.
    let mut ranked: Vec<(&AssignmentCandidate, [u8; 32])> = candidates
        .into_iter()
        .map(|c| {
            let s = score(seed, round_height, target_node_id, &c.node_id);
            (c, s)
        })
        .collect();
    ranked.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.node_id.cmp(&b.0.node_id)));

    let mut chosen: Vec<String> = ranked
        .into_iter()
        .take(k)
        .map(|(c, _)| c.node_id.clone())
        .collect();
    chosen.sort();
    chosen
}

/// Was `challenger_node_id` assigned to challenge `target_node_id` this round?
/// A verdict is only eligible to be counted when this is `true`.
pub fn is_assigned(
    seed: &[u8],
    round_height: u64,
    pool: &[AssignmentCandidate],
    target_node_id: &str,
    challenger_node_id: &str,
    k: usize,
) -> bool {
    assigned_challengers(seed, round_height, pool, target_node_id, k)
        .iter()
        .any(|c| c == challenger_node_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(id: &str, subnet: &str) -> AssignmentCandidate {
        AssignmentCandidate::new(id, Some(subnet.to_string()))
    }

    /// A pool of `n` nodes, each on its own distinct subnet `10.0.i.1`.
    fn distinct_pool(n: usize) -> Vec<AssignmentCandidate> {
        (0..n)
            .map(|i| cand(&format!("{:064x}", i), &format!("10.0.{}", i)))
            .collect()
    }

    const SEED_A: &[u8] = b"block-hash-seed-aaaaaaaaaaaaaaaa";
    const SEED_B: &[u8] = b"block-hash-seed-bbbbbbbbbbbbbbbb";

    /// Same inputs → byte-identical draw (the whole point: every node agrees).
    #[test]
    fn assignment_is_deterministic() {
        let pool = distinct_pool(20);
        let target = &pool[0].node_id.clone();
        let a = assigned_challengers(SEED_A, 100, &pool, target, 5);
        let b = assigned_challengers(SEED_A, 100, &pool, target, 5);
        assert_eq!(a, b);
        assert_eq!(a.len(), 5);
        // Input ordering must not matter.
        let mut shuffled = pool.clone();
        shuffled.reverse();
        let c = assigned_challengers(SEED_A, 100, &shuffled, target, 5);
        assert_eq!(a, c, "draw must not depend on pool ordering");
    }

    /// A different beacon seed reshuffles who is drawn.
    #[test]
    fn assignment_changes_with_seed() {
        let pool = distinct_pool(30);
        let target = &pool[0].node_id.clone();
        let a = assigned_challengers(SEED_A, 100, &pool, target, 5);
        let b = assigned_challengers(SEED_B, 100, &pool, target, 5);
        assert_ne!(a, b, "a fresh seed must re-roll the draw");
    }

    /// The draw for a target is a function of the pool + seed only — the target
    /// cannot steer it (there is no target-supplied input beyond its id).
    #[test]
    fn target_never_drawn_for_itself() {
        let pool = distinct_pool(15);
        for c in &pool {
            let drawn = assigned_challengers(SEED_A, 7, &pool, &c.node_id, 6);
            assert!(
                !drawn.contains(&c.node_id),
                "a node must never be assigned to challenge itself"
            );
        }
    }

    /// Extra identities on ONE subnet buy no extra draw share: at most one node
    /// from any subnet is ever assigned to a given target.
    #[test]
    fn subnet_dedup_caps_one_per_subnet() {
        // 5 honest distinct subnets + 50 attacker identities all on 10.9.9.
        let mut pool = distinct_pool(5);
        for i in 0..50 {
            pool.push(cand(&format!("{:064x}", 1000 + i), "10.9.9"));
        }
        let target = &pool[0].node_id.clone();
        // Ask for more than the number of distinct subnets.
        let drawn = assigned_challengers(SEED_A, 100, &pool, target, 20);
        // At most ONE assigned challenger can be on the attacker subnet.
        let on_attacker_subnet = drawn
            .iter()
            .filter(|id| {
                let n = u128::from_str_radix(id, 16).unwrap();
                n >= 1000
            })
            .count();
        assert!(
            on_attacker_subnet <= 1,
            "one subnet must contribute at most one assigned challenger, got {on_attacker_subnet}"
        );
    }

    /// A candidate on the SAME subnet as the target is excluded (likely same
    /// operator), and a candidate with no known subnet is never drawn.
    #[test]
    fn excludes_same_subnet_and_unknown() {
        let mut pool = vec![
            cand("t", "10.0.0"),                        // target
            cand("same", "10.0.0"),                     // same subnet as target → excluded
            AssignmentCandidate::new("nosubnet", None), // unknown → excluded
            cand("ok1", "10.0.1"),
            cand("ok2", "10.0.2"),
        ];
        pool.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        let drawn = assigned_challengers(SEED_A, 1, &pool, "t", 10);
        assert!(!drawn.contains(&"same".to_string()));
        assert!(!drawn.contains(&"nosubnet".to_string()));
        assert!(drawn.contains(&"ok1".to_string()));
        assert!(drawn.contains(&"ok2".to_string()));
        assert_eq!(
            drawn.len(),
            2,
            "only the two distinct-subnet peers are eligible"
        );
    }

    /// `is_assigned` agrees with membership of `assigned_challengers`.
    #[test]
    fn is_assigned_matches_the_draw() {
        let pool = distinct_pool(25);
        let target = &pool[0].node_id.clone();
        let k = 6;
        let drawn = assigned_challengers(SEED_A, 42, &pool, target, k);
        for c in &pool {
            let expect = drawn.contains(&c.node_id);
            let got = is_assigned(SEED_A, 42, &pool, target, &c.node_id, k);
            assert_eq!(expect, got, "is_assigned disagreed for {}", c.node_id);
        }
    }

    /// k larger than the eligible set returns everyone eligible, not a panic.
    #[test]
    fn k_exceeds_pool_returns_all_eligible() {
        let pool = distinct_pool(4); // target + 3 others
        let target = &pool[0].node_id.clone();
        let drawn = assigned_challengers(SEED_A, 1, &pool, target, 100);
        assert_eq!(
            drawn.len(),
            3,
            "only the 3 non-target distinct subnets are eligible"
        );
    }

    /// An attacker that stacks identities on a handful of subnets cannot occupy
    /// more assigned slots than it has distinct subnets — the core guarantee.
    #[test]
    fn attacker_draw_share_bounded_by_distinct_subnets() {
        // 10 honest subnets, attacker holds 3 subnets with 100 identities each.
        let mut pool = distinct_pool(10);
        for s in 0..3 {
            for i in 0..100 {
                pool.push(cand(
                    &format!("{:064x}", 100_000 + s * 1000 + i),
                    &format!("172.16.{}", s),
                ));
            }
        }
        // Average assigned attacker slots over many targets/rounds must never
        // exceed the attacker's 3 distinct subnets.
        let mut worst = 0usize;
        for round in 0..25u64 {
            for t in pool.iter().take(10) {
                let drawn = assigned_challengers(SEED_A, round, &pool, &t.node_id, 8);
                let atk = drawn
                    .iter()
                    .filter(|id| {
                        u128::from_str_radix(id, 16)
                            .map(|n| n >= 100_000)
                            .unwrap_or(false)
                    })
                    .count();
                worst = worst.max(atk);
            }
        }
        assert!(
            worst <= 3,
            "attacker occupied {worst} slots but holds only 3 subnets"
        );
    }
}
