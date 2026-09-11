//! Deterministic, publicly-verifiable coordinator election (sortition).
//!
//! The pure selection core of the decentralised-coordinator design
//! (`tasks/plan_decentralised_coordinators.md`), with NO coupling to consensus,
//! networking, or funds. Given three agreed inputs — an unpredictable `beacon`,
//! the `epoch` number, and the `roster` of eligible node ids — it names a
//! leader for every denomination, and the order a wallet falls back through.
//!
//! ## Properties (the whole point)
//!
//! - **No self-nomination.** A node's rank for a tier is
//!   `H(beacon ‖ epoch ‖ tier ‖ node_id)`. The node controls neither the beacon
//!   nor (cheaply) its own id, so it cannot grind itself into a lead. The
//!   network doesn't *vote for* candidates; it agrees on the beacon + roster,
//!   and the leaders fall out deterministically.
//! - **Determinism.** Every node (and every wallet) computes the byte-identical
//!   result from the same inputs — so they agree on who coordinates without a
//!   second round of communication.
//! - **Public verifiability.** Anyone can recompute [`tier_leaders`]; there is
//!   no trusted tallier.
//! - **Evenness.** Every tier has a *different* leader whenever the roster is at
//!   least as large as the tier list, and every node is equally likely to lead
//!   every tier. Opting in means being called on — see [`tier_leaders`].
//! - **Rotation.** A fresh `beacon`/`epoch` reshuffles the draw, so coordination
//!   rotates across the network over time.
//!
//! ## Why there is no seat count
//!
//! This used to elect `n` coordinators into seats and send each tier to
//! `shard(tier, epoch) mod n`. With `n` sized from session demand — zero on
//! mainnet — that was one seat, so a single node carried every denomination for
//! a whole day while every other opted-in node sat idle. And `n` was one more
//! number nodes had to agree on: two nodes with identical rosters but different
//! demand snapshots sent the same tier to different coordinators.
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

/// Domain separator so a sortition hash can never collide with any other hash
/// in the system. Versioned for forward changes.
const DOMAIN_RANK: &[u8] = b"ghost/wraith/coordinator-sortition/rank/v1";

/// One place in a tier's ranking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectedCoordinator {
    /// The node's id.
    pub node_id: CoordinatorNodeId,
    /// The sortition hash that placed it (lower = higher priority). Carried so
    /// verifiers and observers can see *why* this node is where it is.
    pub rank: [u8; 32],
    /// Position `0..n` in the tier's ranking, in ascending-rank order.
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

/// Who coordinates one denomination for an epoch.
///
/// `order[0]` leads it. The rest is where its wallets go if the leader does not
/// answer, walked in this order by every wallet, so a dead leader's cohort moves
/// as one body to the same next node instead of scattering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierLeadership {
    /// The tier's stable id (`LiteTier::id`).
    pub tier_id: String,
    /// Leader first, then the failover path. Holds every roster node.
    pub order: Vec<CoordinatorNodeId>,
}

impl TierLeadership {
    /// The node that leads this tier. `None` only for an empty roster.
    pub fn leader(&self) -> Option<&CoordinatorNodeId> {
        self.order.first()
    }
}

/// Every tier's leader and failover order for `epoch`, one entry per tier in
/// the order `tiers` gives them.
///
/// # Different leaders, not merely independent ones
///
/// Each tier has its own ranking ([`coordinator_order_for_tier`]). Taking each
/// ranking's top node independently would let one node lead several tiers while
/// others lead none — with eight nodes and four tiers, all four leaders differ
/// in only ~41% of epochs. So tiers are filled in turn, each by the
/// best-ranked node **not already leading one**.
///
/// That changes nothing about fairness. Ranks are independent and uniform and
/// the rule never looks at who a node is, so every node is equally likely to
/// lead every tier; what it removes is the doubling-up. With `n ≥ tiers`, every
/// epoch has `tiers` different leaders; with fewer nodes than tiers every node
/// leads, and some lead more than one.
///
/// # The failover order
///
/// The leader, then the rest of the tier's own ranking. The next node is often
/// another tier's leader; its load grows, which is the right trade against
/// sending wallets to a node nobody else would pick.
///
/// Deduplicates the roster; an empty roster yields empty orders.
pub fn tier_leaders(
    beacon: &[u8; 32],
    epoch: u64,
    tiers: &[&str],
    roster: &[CoordinatorNodeId],
) -> Vec<TierLeadership> {
    let mut leading: HashSet<CoordinatorNodeId> = HashSet::with_capacity(tiers.len());
    tiers
        .iter()
        .map(|tier_id| {
            let ranked: Vec<CoordinatorNodeId> =
                coordinator_order_for_tier(beacon, epoch, tier_id, roster)
                    .into_iter()
                    .map(|c| c.node_id)
                    .collect();
            // Once every node leads something, doubling up is unavoidable; the
            // tier then goes to its own top-ranked node.
            let pick = ranked
                .iter()
                .position(|id| !leading.contains(id))
                .unwrap_or(0);
            let mut order = ranked;
            if !order.is_empty() {
                let leader = order.remove(pick);
                leading.insert(leader);
                order.insert(0, leader);
            }
            TierLeadership {
                tier_id: (*tier_id).to_string(),
                order,
            }
        })
        .collect()
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

    const TIERS: [&str; 4] = ["100k_sats", "1m_sats", "10m_sats", "100m_sats"];

    fn leaders(b: &[u8; 32], epoch: u64, r: &[CoordinatorNodeId]) -> Vec<CoordinatorNodeId> {
        tier_leaders(b, epoch, &TIERS, r)
            .iter()
            .map(|t| *t.leader().expect("non-empty roster"))
            .collect()
    }

    #[test]
    fn determinism_same_inputs_same_output() {
        let r = roster(20);
        let a = tier_leaders(&beacon(1), 42, &TIERS, &r);
        let b = tier_leaders(&beacon(1), 42, &TIERS, &r);
        assert_eq!(a, b, "the draw must be byte-identical across calls");
        assert_eq!(a.len(), TIERS.len());
        for (t, want) in a.iter().zip(TIERS) {
            assert_eq!(t.tier_id, want, "one entry per tier, in the order given");
        }
    }

    #[test]
    fn two_nodes_with_the_roster_in_different_orders_agree() {
        let r = roster(8);
        let mut shuffled = r.clone();
        shuffled.reverse();
        assert_eq!(
            tier_leaders(&beacon(3), 9, &TIERS, &r),
            tier_leaders(&beacon(3), 9, &TIERS, &shuffled)
        );
    }

    #[test]
    fn every_tier_has_a_different_leader_when_there_are_enough_nodes() {
        // Independent top picks would double up in ~59% of epochs at 8 nodes.
        for e in 0..2000u64 {
            let l = leaders(&beacon((e % 251) as u8), e, &roster(8));
            let distinct: HashSet<_> = l.iter().collect();
            assert_eq!(distinct.len(), TIERS.len(), "epoch {e}: {l:?}");
        }
    }

    /// The property the operator asked for: unbiased, and even. Every node
    /// leads every tier about equally often, so every opted-in node is called on
    /// and has the same chance at the tier that pays most.
    #[test]
    fn every_node_leads_every_tier_equally_often() {
        let r = roster(8);
        let trials = 16_000u64;
        let mut counts = vec![[0u64; 4]; r.len()];
        for e in 0..trials {
            for (t, leader) in leaders(&beacon(9), e, &r).iter().enumerate() {
                let idx = r.iter().position(|x| x == leader).unwrap();
                counts[idx][t] += 1;
            }
        }
        let expected = trials as f64 / r.len() as f64; // 2000 per (node, tier)
        for (i, per_tier) in counts.iter().enumerate() {
            for (t, &c) in per_tier.iter().enumerate() {
                let dev = (c as f64 - expected).abs() / expected;
                assert!(
                    dev < 0.10,
                    "node {i} led {} {c} times, expected ~{expected:.0} (dev {dev:.3})",
                    TIERS[t]
                );
            }
        }
    }

    #[test]
    fn no_self_nomination_node_cannot_force_a_win() {
        // A fixed node leads or not depending purely on the beacon, which it
        // does not control: never guaranteed, never impossible.
        let r = roster(20);
        let target = r[7];
        let trials = 4000u64;
        let wins = (0..trials)
            .filter(|&e| leaders(&beacon((e % 251) as u8 + 1), e, &r).contains(&target))
            .count();
        // Expected ≈ 4/20 = 20%.
        let pct = wins as f64 / trials as f64;
        assert!(
            pct > 0.10 && pct < 0.32,
            "lead-rate {pct:.3} should sit near 0.20"
        );
    }

    #[test]
    fn rotation_changes_the_draw() {
        let r = roster(20);
        assert_ne!(
            leaders(&beacon(5), 100, &r),
            leaders(&beacon(5), 101, &r),
            "a fresh epoch should reshuffle the leaders"
        );
    }

    #[test]
    fn fewer_nodes_than_tiers_still_covers_every_tier() {
        let r = roster(2);
        let l = leaders(&beacon(2), 1, &r);
        assert_eq!(l.len(), TIERS.len(), "no tier is left without a leader");
        let distinct: HashSet<_> = l.iter().collect();
        assert_eq!(distinct.len(), 2, "both nodes are called on");
    }

    #[test]
    fn the_order_is_the_leader_then_the_tiers_own_ranking() {
        let r = roster(9);
        let b = beacon(4);
        for t in tier_leaders(&b, 55, &TIERS, &r) {
            let ranking: Vec<_> = coordinator_order_for_tier(&b, 55, &t.tier_id, &r)
                .into_iter()
                .map(|c| c.node_id)
                .collect();
            let leader = *t.leader().unwrap();
            let rest: Vec<_> = ranking.iter().copied().filter(|id| *id != leader).collect();
            assert_eq!(
                t.order[1..],
                rest[..],
                "{}: failover keeps rank order",
                t.tier_id
            );
            assert_eq!(
                t.order.len(),
                r.len(),
                "every node is somewhere in the path"
            );
        }
    }

    #[test]
    fn empty_roster_leads_nothing() {
        for t in tier_leaders(&beacon(1), 1, &TIERS, &[]) {
            assert!(t.order.is_empty());
            assert!(t.leader().is_none());
        }
    }

    #[test]
    fn duplicate_ids_counted_once() {
        let mut r = roster(5);
        r.push(r[2]);
        r.push(r[2]);
        for t in tier_leaders(&beacon(3), 7, &TIERS, &r) {
            let ids: HashSet<_> = t.order.iter().collect();
            assert_eq!(ids.len(), t.order.len(), "no node appears twice");
            assert_eq!(t.order.len(), 5);
        }
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
