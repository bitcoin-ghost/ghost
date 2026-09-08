//! Deterministic, publicly-verifiable coordinator election (sortition).
//!
//! This is increment 1 of the decentralised-coordinator design
//! (`tasks/plan_decentralised_coordinators.md`): the pure selection core, with
//! NO coupling to consensus, networking, or funds. Given three agreed inputs —
//! an unpredictable randomness `beacon`, the `epoch` number, and the
//! consensus-frozen `roster` of qualified node ids — it elects `n` coordinators
//! for that epoch.
//!
//! ## Properties (the whole point)
//!
//! - **No self-nomination.** A node's rank is `H(beacon ‖ epoch ‖ node_id)`. The
//!   node controls neither the beacon nor (cheaply) its own id, so it cannot
//!   grind itself into a seat. The network doesn't *vote for* candidates; it
//!   agrees on the beacon + roster, and the winners fall out deterministically.
//! - **Determinism.** Every node (and every wallet) computes the byte-identical
//!   result from the same inputs — so they agree on who coordinates without a
//!   second round of communication.
//! - **Public verifiability.** Anyone can recompute the election (`verify_election`)
//!   and the session→coordinator mapping (`shard_for`); there is no trusted
//!   tallier.
//! - **Fairness.** Ranks are uniform over the roster, so each qualified node is
//!   elected with probability ≈ `n / roster_len` per epoch.
//! - **Rotation.** A fresh `beacon`/`epoch` reshuffles the draw, so coordination
//!   rotates across the network over time.
//!
//! The *security* of the whole scheme rests on the beacon being **ungrindable**
//! (increment 2) — that is deliberately abstracted out here: this module treats
//! the beacon as a given 32-byte value and is correct for any such value.

use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// A node identifier eligible to coordinate — matches `ghost_common::types::NodeId`
/// (32-byte node id), kept local so `wraith-protocol` stays free of a consensus
/// dependency. Callers pass the qualified-node roster as these ids.
pub type CoordinatorNodeId = [u8; 32];

/// Domain separators so a sortition hash can never collide with a shard hash or
/// any other hash in the system. Versioned for forward changes.
const DOMAIN_RANK: &[u8] = b"ghost/wraith/coordinator-sortition/rank/v1";
const DOMAIN_SHARD: &[u8] = b"ghost/wraith/coordinator-sortition/shard/v1";

/// One elected coordinator for an epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectedCoordinator {
    /// The elected node's id.
    pub node_id: CoordinatorNodeId,
    /// The sortition hash that won it the seat (lower = higher priority). Carried
    /// so verifiers and observers can see *why* this node was chosen.
    pub rank: [u8; 32],
    /// Seat index `0..n`, in ascending-rank order. Sessions are sharded across
    /// seats via [`shard_for`], so the seat is this coordinator's shard.
    pub seat: u32,
}

/// The sortition rank of a single node for a given beacon+epoch:
/// `SHA256(DOMAIN_RANK ‖ beacon ‖ epoch_le ‖ node_id)`. Lower ranks win.
pub fn rank_of(beacon: &[u8; 32], epoch: u64, node_id: &CoordinatorNodeId) -> [u8; 32] {
    rank_of_for_tier(beacon, epoch, "", node_id)
}

/// The sortition rank of a node **for one tier**:
/// `SHA256(DOMAIN_RANK ‖ beacon ‖ epoch_le ‖ tier_len ‖ tier ‖ node_id)`.
/// Lower ranks win.
///
/// # Why the tier is in the hash
///
/// Callers walk the ordering from the top until a coordinator accepts, which
/// concentrates traffic on whoever is first. Concentration is good for
/// anonymity — a larger set — but it makes being first worth a great deal, and
/// a single ordering would make one node first for *every* denomination at once.
///
/// Mixing the tier in gives each denomination an independent ordering, so
/// winning one buys one. It keeps walk-until-filled intact and spreads the prize
/// without reintroducing a seat count to disagree about.
///
/// The tier is length-prefixed so `"1m" ‖ "sats"` cannot collide with
/// `"1msats" ‖ ""`.
pub fn rank_of_for_tier(
    beacon: &[u8; 32],
    epoch: u64,
    tier_id: &str,
    node_id: &CoordinatorNodeId,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_RANK);
    h.update(beacon);
    h.update(epoch.to_le_bytes());
    h.update((tier_id.len() as u64).to_le_bytes());
    h.update(tier_id.as_bytes());
    h.update(node_id);
    h.finalize().into()
}

/// The full preference order of coordinators for one tier, best first.
///
/// # Why an ordering rather than a seat count
///
/// `coordinator_for_tier` used to compute a seat count from mesh-summed demand
/// and then `shard_for(key) mod seats`. Two nodes disagreeing on that count sent
/// the same tier to *different* nodes even when their elected sets were
/// identical — the ranking never differed, only the modulus did.
///
/// There is no count here to disagree about. A caller walks this list and takes
/// the first coordinator that is reachable and not full, so demand fills the
/// list organically and an unreachable node costs one step rather than a split.
///
/// Returns every eligible node, not a truncated set: the tail is the failover
/// path, and truncating it would reintroduce a length to disagree about.
pub fn coordinator_order_for_tier(
    beacon: &[u8; 32],
    epoch: u64,
    tier_id: &str,
    roster: &[CoordinatorNodeId],
) -> Vec<ElectedCoordinator> {
    let mut seen = HashSet::with_capacity(roster.len());
    let mut ranked: Vec<([u8; 32], CoordinatorNodeId)> = roster
        .iter()
        .filter(|id| seen.insert(**id))
        .map(|id| (rank_of_for_tier(beacon, epoch, tier_id, id), *id))
        .collect();
    ranked.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    ranked
        .into_iter()
        .enumerate()
        .map(|(seat, (rank, node_id))| ElectedCoordinator {
            node_id,
            rank,
            seat: seat as u32,
        })
        .collect()
}

/// Elect `n` coordinators from `roster` for `epoch` under `beacon`.
///
/// Ranks every (deduplicated) roster member, sorts ascending by `(rank, node_id)`
/// — node_id only as a tie-break, astronomically unlikely with 256-bit ranks —
/// and returns the lowest `n`, each tagged with its seat `0..n`. Returns fewer
/// than `n` (all of them) when the roster is smaller, and an empty vec for an
/// empty roster or `n == 0`. A duplicated id in `roster` is counted once (a node
/// cannot hold two seats).
pub fn elect_coordinators(
    beacon: &[u8; 32],
    epoch: u64,
    roster: &[CoordinatorNodeId],
    n: usize,
) -> Vec<ElectedCoordinator> {
    if n == 0 || roster.is_empty() {
        return Vec::new();
    }
    let mut seen: HashSet<CoordinatorNodeId> = HashSet::with_capacity(roster.len());
    let mut ranked: Vec<([u8; 32], CoordinatorNodeId)> = roster
        .iter()
        .filter(|id| seen.insert(**id))
        .map(|id| (rank_of(beacon, epoch, id), *id))
        .collect();
    // Total order: by rank, then node_id. Deterministic on every node.
    ranked.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    ranked
        .into_iter()
        .take(n)
        .enumerate()
        .map(|(seat, (rank, node_id))| ElectedCoordinator {
            node_id,
            rank,
            seat: seat as u32,
        })
        .collect()
}

/// Deterministically map a session to one of `seats` elected coordinators, so a
/// wallet and every node independently agree which coordinator owns the session:
/// `SHA256(DOMAIN_SHARD ‖ session_id)[..8] mod seats`. Returns 0 when `seats <= 1`.
pub fn shard_for(session_id: &[u8; 32], seats: usize) -> u32 {
    if seats <= 1 {
        return 0;
    }
    let mut h = Sha256::new();
    h.update(DOMAIN_SHARD);
    h.update(session_id);
    let d = h.finalize();
    let v = u64::from_le_bytes(d[..8].try_into().expect("32-byte digest has 8 bytes"));
    (v % seats as u64) as u32
}

/// Recompute the election and check a claimed result matches exactly. The audit
/// path: anyone with the same agreed inputs confirms a published coordinator set
/// was elected honestly.
pub fn verify_election(
    beacon: &[u8; 32],
    epoch: u64,
    roster: &[CoordinatorNodeId],
    n: usize,
    claimed: &[ElectedCoordinator],
) -> bool {
    elect_coordinators(beacon, epoch, roster, n) == claimed
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a deterministic roster of `k` distinct node ids.
    fn roster(k: u8) -> Vec<CoordinatorNodeId> {
        (0..k)
            .map(|i| {
                let mut id = [0u8; 32];
                id[0] = i;
                id[31] = i.wrapping_mul(7).wrapping_add(1);
                id
            })
            .collect()
    }

    fn beacon(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn determinism_same_inputs_same_output() {
        let r = roster(20);
        let a = elect_coordinators(&beacon(1), 42, &r, 4);
        let b = elect_coordinators(&beacon(1), 42, &r, 4);
        assert_eq!(a, b, "election must be byte-identical across calls");
        assert_eq!(a.len(), 4);
        // seats are 0..n in order
        for (i, e) in a.iter().enumerate() {
            assert_eq!(e.seat, i as u32);
        }
        // strictly ascending ranks
        assert!(a.windows(2).all(|w| w[0].rank <= w[1].rank));
    }

    #[test]
    fn no_self_nomination_node_cannot_force_a_win() {
        // A fixed node either wins or not depending purely on the beacon, which
        // it does not control. Across many beacons its win-rate ≈ n/roster, and
        // it is NOT always elected — so it cannot nominate itself in.
        let r = roster(20);
        let target = r[7];
        let mut wins = 0;
        let trials = 4000u64;
        for e in 0..trials {
            // vary the beacon each trial (stand-in for the per-epoch beacon)
            let elected = elect_coordinators(&beacon((e % 251) as u8 + 1), e, &r, 4);
            if elected.iter().any(|c| c.node_id == target) {
                wins += 1;
            }
        }
        // Expected ≈ trials * 4/20 = 20%. Assert it's clearly bounded away from
        // both 0% (could never win) and 100% (always wins / self-nominated).
        let pct = (wins as f64) / (trials as f64);
        assert!(
            pct > 0.10 && pct < 0.32,
            "win-rate {pct:.3} should sit near 0.20 — never guaranteed, never impossible"
        );
    }

    #[test]
    fn fairness_uniform_over_epochs() {
        // Over many epochs every roster member is elected ≈ equally.
        let r = roster(20);
        let n = 4usize;
        let trials = 8000u64;
        let mut counts = vec![0u64; r.len()];
        for e in 0..trials {
            for c in elect_coordinators(&beacon(9), e, &r, n) {
                let idx = r.iter().position(|x| *x == c.node_id).unwrap();
                counts[idx] += 1;
            }
        }
        let expected = (trials as f64) * (n as f64) / (r.len() as f64); // = 1600
        for (i, &c) in counts.iter().enumerate() {
            let dev = (c as f64 - expected).abs() / expected;
            assert!(
                dev < 0.15,
                "node {i} elected {c} times, expected ~{expected:.0} (dev {dev:.3})"
            );
        }
    }

    #[test]
    fn n_exceeds_roster_elects_all_no_panic() {
        let r = roster(3);
        let e = elect_coordinators(&beacon(2), 1, &r, 10);
        assert_eq!(e.len(), 3, "cannot elect more than the roster");
        let ids: HashSet<_> = e.iter().map(|c| c.node_id).collect();
        assert_eq!(ids.len(), 3, "all distinct");
    }

    #[test]
    fn empty_roster_and_zero_n() {
        assert!(elect_coordinators(&beacon(1), 1, &[], 4).is_empty());
        assert!(elect_coordinators(&beacon(1), 1, &roster(5), 0).is_empty());
    }

    #[test]
    fn duplicate_ids_counted_once() {
        let mut r = roster(5);
        r.push(r[2]); // duplicate
        r.push(r[2]);
        let e = elect_coordinators(&beacon(3), 7, &r, 5);
        let ids: HashSet<_> = e.iter().map(|c| c.node_id).collect();
        assert_eq!(ids.len(), e.len(), "no node holds two seats");
        assert_eq!(e.len(), 5, "5 distinct after dedup");
    }

    #[test]
    fn rotation_changes_the_draw() {
        let r = roster(20);
        let a: Vec<_> = elect_coordinators(&beacon(5), 100, &r, 4)
            .into_iter()
            .map(|c| c.node_id)
            .collect();
        let b: Vec<_> = elect_coordinators(&beacon(5), 101, &r, 4)
            .into_iter()
            .map(|c| c.node_id)
            .collect();
        assert_ne!(a, b, "a fresh epoch should reshuffle the coordinator set");
    }

    #[test]
    fn shard_for_is_deterministic_and_bounded() {
        let s = [0x5a; 32];
        assert_eq!(shard_for(&s, 4), shard_for(&s, 4), "deterministic");
        assert!(shard_for(&s, 4) < 4, "in range");
        assert_eq!(shard_for(&s, 1), 0);
        assert_eq!(shard_for(&s, 0), 0);
    }

    #[test]
    fn shard_for_distributes_evenly() {
        let seats = 5usize;
        let trials = 5000u32;
        let mut buckets = vec![0u32; seats];
        for i in 0..trials {
            let mut sid = [0u8; 32];
            sid[..4].copy_from_slice(&i.to_le_bytes());
            buckets[shard_for(&sid, seats) as usize] += 1;
        }
        let expected = (trials as f64) / (seats as f64);
        for (k, &c) in buckets.iter().enumerate() {
            let dev = (c as f64 - expected).abs() / expected;
            assert!(
                dev < 0.12,
                "seat {k} got {c}, expected ~{expected:.0} (dev {dev:.3})"
            );
        }
    }

    #[test]
    fn verify_election_accepts_valid_rejects_tampered() {
        let r = roster(12);
        let (b, e, n) = (beacon(4), 55u64, 3usize);
        let valid = elect_coordinators(&b, e, &r, n);
        assert!(
            verify_election(&b, e, &r, n, &valid),
            "honest result verifies"
        );

        // tamper: swap in a non-elected node
        let mut t1 = valid.clone();
        t1[0].node_id = r[11];
        assert!(
            !verify_election(&b, e, &r, n, &t1),
            "substituted node rejected"
        );

        // tamper: reorder seats
        let mut t2 = valid.clone();
        t2.swap(0, 1);
        assert!(
            !verify_election(&b, e, &r, n, &t2),
            "reordered seats rejected"
        );

        // tamper: forged rank
        let mut t3 = valid.clone();
        t3[1].rank = [0u8; 32];
        assert!(!verify_election(&b, e, &r, n, &t3), "forged rank rejected");

        // wrong beacon → different election → claimed (old) no longer verifies
        assert!(
            !verify_election(&beacon(99), e, &r, n, &valid),
            "beacon-bound"
        );
    }
    #[test]
    fn tiers_of_the_same_length_still_get_different_orderings() {
        // Every other tier fixture here has a distinct name length, so the
        // length prefix alone separated them and a mutation blanking the tier
        // BYTES survived the whole suite. These two are both nine characters,
        // so only the content can tell them apart.
        let roster: Vec<CoordinatorNodeId> = (1..=12u8).map(|i| [i; 32]).collect();
        let b = [5u8; 32];
        assert_eq!(
            "100k_sats".len(),
            "500k_sats".len(),
            "fixture must be same-length"
        );
        let a = coordinator_order_for_tier(&b, 3, "100k_sats", &roster);
        let c = coordinator_order_for_tier(&b, 3, "500k_sats", &roster);
        assert_ne!(
            a.iter().map(|x| x.node_id).collect::<Vec<_>>(),
            c.iter().map(|x| x.node_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_tier_content_binds_not_just_its_length() {
        let n = [4u8; 32];
        let b = [2u8; 32];
        assert_ne!(
            rank_of_for_tier(&b, 1, "aaaa", &n),
            rank_of_for_tier(&b, 1, "bbbb", &n),
            "same length, different content — the bytes must bind"
        );
    }

    #[test]
    fn each_tier_gets_its_own_ordering() {
        // Walking from the top concentrates traffic on whoever is first. One
        // ordering would make a single node first for every denomination at
        // once; per-tier orderings mean winning one buys one.
        let roster: Vec<CoordinatorNodeId> = (1..=12u8).map(|i| [i; 32]).collect();
        let b = [5u8; 32];
        let a_first = coordinator_order_for_tier(&b, 3, "100k_sats", &roster)[0].node_id;
        let b_first = coordinator_order_for_tier(&b, 3, "1m_sats", &roster)[0].node_id;
        let c_first = coordinator_order_for_tier(&b, 3, "10k_sats", &roster)[0].node_id;
        assert!(
            !(a_first == b_first && b_first == c_first),
            "one node must not lead every tier"
        );
    }

    #[test]
    fn the_ordering_carries_every_node_so_the_tail_is_the_failover() {
        // Truncating would reintroduce a length for two nodes to disagree
        // about, which is the bug this replaced.
        let roster: Vec<CoordinatorNodeId> = (1..=9u8).map(|i| [i; 32]).collect();
        let order = coordinator_order_for_tier(&[1u8; 32], 4, "100k_sats", &roster);
        assert_eq!(order.len(), roster.len());
        let seats: Vec<u32> = order.iter().map(|c| c.seat).collect();
        assert_eq!(seats, (0..roster.len() as u32).collect::<Vec<_>>());
    }

    #[test]
    fn two_nodes_with_the_same_roster_walk_the_same_order() {
        // The agreement property, and it needs no count to be agreed.
        let roster: Vec<CoordinatorNodeId> = (1..=8u8).map(|i| [i; 32]).collect();
        let mut shuffled = roster.clone();
        shuffled.reverse();
        let a = coordinator_order_for_tier(&[9u8; 32], 2, "1m_sats", &roster);
        let b = coordinator_order_for_tier(&[9u8; 32], 2, "1m_sats", &shuffled);
        assert_eq!(a, b);
    }

    #[test]
    fn a_duplicated_node_takes_one_place_in_the_order() {
        let dup = vec![[1u8; 32], [2u8; 32], [1u8; 32], [3u8; 32]];
        let order = coordinator_order_for_tier(&[7u8; 32], 1, "100k_sats", &dup);
        assert_eq!(order.len(), 3);
    }

    #[test]
    fn the_tier_is_length_prefixed_so_names_cannot_collide() {
        // "1m" + "sats" must not hash the same as "1msats" + "".
        let n = [4u8; 32];
        let b = [2u8; 32];
        assert_ne!(
            rank_of_for_tier(&b, 1, "1m", &n),
            rank_of_for_tier(&b, 1, "1msats", &n)
        );
    }

    #[test]
    fn the_untiered_rank_is_the_empty_tier() {
        // `rank_of` is kept for callers with no tier in hand, and must stay
        // consistent with the tiered form rather than being a second scheme.
        let n = [6u8; 32];
        let b = [3u8; 32];
        assert_eq!(rank_of(&b, 5, &n), rank_of_for_tier(&b, 5, "", &n));
    }
}
