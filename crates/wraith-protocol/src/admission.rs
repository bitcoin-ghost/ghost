//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: admission.rs                                                                                                   |
//|======================================================================================================================|

//! Seat admission — pricing and detecting Sybil rounds.
//!
//! # The attack
//!
//! An adversary fills a round with their own seats. They get every coin back,
//! so it costs only fees — roughly 500 sats a seat, about 14,000 sats to
//! dominate a 30-seat round. They then know their own outputs and subtract
//! them, and a victim who believed they had a set of thirty actually had two.
//!
//! Wasabi and Whirlpool both live with this. It **cannot be prevented** in a
//! permissionless round, only made expensive and made visible. Anyone who
//! writes "Sybil-proof" in this file is wrong.
//!
//! # The three levers here
//!
//! - **Aging.** A seat must have been confirmed for a while. Sybils then need
//!   capital *parked*, not merely cycled, which turns a per-round fee into an
//!   opportunity cost proportional to how long they want to keep attacking.
//! - **Diversity.** No two seats in a round may share an ancestry cluster.
//!   Splitting a hoard into forty outputs no longer buys forty seats.
//! - **Dispersion.** A coordinator must not reassemble the same peer set. A
//!   victim repeatedly rounded with the same crowd is being farmed.
//!
//! A fourth lever is not code: **publish the measurement**. [`dominance`] is
//! the number a dashboard shows, because one entity supplying most seats is
//! visible over time and invisible in any single round.
//!
//! # What this module cannot do
//!
//! It does not identify clusters. `cluster` is supplied by the caller from
//! chain analysis (common-input heuristics, known-address tagging), and is only
//! as good as that analysis. A Sybil who funds each seat from genuinely
//! unrelated coins defeats the diversity check entirely — aging and dispersion
//! are what remain.

use std::collections::{HashMap, HashSet};

use crate::signing_ledger::OutPointKey;

/// A seat offered to a round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatCandidate {
    /// The coin being offered.
    pub coin: OutPointKey,
    /// Block height at which it confirmed.
    pub confirmed_height: u32,
    /// Caller-supplied ancestry cluster. `None` means analysis found no link,
    /// which is treated as its own singleton cluster.
    pub cluster: Option<u64>,
}

/// Why a seat was turned away. Every variant is a counter with a reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rejection {
    /// Confirmed too recently — capital was cycled, not parked.
    TooYoung {
        /// How many blocks it has.
        age: u32,
        /// How many it needs.
        required: u32,
    },
    /// Its ancestry cluster already holds the maximum seats in this round.
    ClusterSaturated {
        /// The cluster in question.
        cluster: u64,
    },
}

/// Admission rules.
#[derive(Debug, Clone, Copy)]
pub struct AdmissionPolicy {
    /// Minimum confirmations before a coin may take a seat.
    pub min_age_blocks: u32,
    /// Maximum seats one ancestry cluster may hold in a single round.
    pub max_seats_per_cluster: usize,
}

impl Default for AdmissionPolicy {
    /// Deliberately conservative defaults; both are open parameters in the
    /// build plan and want tuning against real fill rates before launch.
    ///
    /// `min_age_blocks` of 144 is roughly a day — long enough that attacking
    /// continuously means parking capital, short enough that an ordinary user
    /// who entered yesterday can pay today.
    fn default() -> Self {
        Self {
            min_age_blocks: 144,
            max_seats_per_cluster: 2,
        }
    }
}

/// The outcome of applying [`AdmissionPolicy`] to a set of offers.
#[derive(Debug, Clone, Default)]
pub struct Admission {
    /// Seats accepted, in offer order.
    pub admitted: Vec<SeatCandidate>,
    /// Seats turned away, with the reason.
    pub rejected: Vec<(SeatCandidate, Rejection)>,
}

impl Admission {
    /// Count of each rejection kind — the numbers a dashboard reads.
    pub fn rejection_counts(&self) -> HashMap<std::mem::Discriminant<Rejection>, usize> {
        let mut m = HashMap::new();
        for (_, r) in &self.rejected {
            *m.entry(std::mem::discriminant(r)).or_insert(0) += 1;
        }
        m
    }
}

/// Apply the policy to a round's offered seats.
///
/// Offers are considered in order, so a caller that wants fairness should
/// shuffle before calling — first-come is otherwise an advantage a Sybil can
/// buy with low latency.
pub fn admit(offers: &[SeatCandidate], tip_height: u32, policy: AdmissionPolicy) -> Admission {
    let mut out = Admission::default();
    let mut per_cluster: HashMap<u64, usize> = HashMap::new();

    for c in offers {
        let age = tip_height.saturating_sub(c.confirmed_height);
        if age < policy.min_age_blocks {
            out.rejected.push((
                c.clone(),
                Rejection::TooYoung {
                    age,
                    required: policy.min_age_blocks,
                },
            ));
            continue;
        }
        if let Some(cluster) = c.cluster {
            let n = per_cluster.entry(cluster).or_insert(0);
            if *n >= policy.max_seats_per_cluster {
                out.rejected
                    .push((c.clone(), Rejection::ClusterSaturated { cluster }));
                continue;
            }
            *n += 1;
        }
        out.admitted.push(c.clone());
    }
    out
}

/// The largest share of a round's seats held by any one cluster, 0.0..=1.0.
///
/// **Publish this.** A single round tells you nothing — a legitimate user can
/// hold two seats. A rising trend across many rounds is what a Sybil looks
/// like, and it is only visible if somebody is plotting it.
pub fn dominance(admitted: &[SeatCandidate]) -> f64 {
    if admitted.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<u64, usize> = HashMap::new();
    let mut unclustered = 0usize;
    for c in admitted {
        match c.cluster {
            Some(k) => *counts.entry(k).or_insert(0) += 1,
            None => unclustered += 1,
        }
    }
    // An unclustered seat is its own singleton, so it can never dominate.
    let biggest = counts
        .values()
        .copied()
        .max()
        .unwrap_or(0)
        .max(usize::from(unclustered > 0));
    biggest as f64 / admitted.len() as f64
}

/// Refuses to reassemble a peer set that overlaps a recent one too closely.
///
/// A victim repeatedly rounded with the same crowd is being farmed, and no
/// per-round check can see it — only history can.
#[derive(Debug)]
pub struct DispersionGuard {
    recent: Vec<HashSet<OutPointKey>>,
    memory: usize,
    max_overlap: f64,
    refusals: u64,
}

impl DispersionGuard {
    /// `memory` past rounds are remembered; a proposed set sharing more than
    /// `max_overlap` of its members with any of them is refused.
    pub fn new(memory: usize, max_overlap: f64) -> Self {
        Self {
            recent: Vec::new(),
            memory,
            max_overlap,
            refusals: 0,
        }
    }

    /// May this peer set be assembled?
    pub fn allows(&mut self, proposed: &[SeatCandidate]) -> bool {
        let set: HashSet<OutPointKey> = proposed.iter().map(|c| c.coin).collect();
        if set.is_empty() {
            return true;
        }
        for past in &self.recent {
            let shared = set.intersection(past).count() as f64;
            if shared / set.len() as f64 > self.max_overlap {
                self.refusals += 1;
                return false;
            }
        }
        true
    }

    /// Record an assembled set.
    pub fn record(&mut self, assembled: &[SeatCandidate]) {
        self.recent.push(assembled.iter().map(|c| c.coin).collect());
        if self.recent.len() > self.memory {
            self.recent.remove(0);
        }
    }

    /// How many proposed sets were refused as too repetitive.
    pub fn refusals(&self) -> u64 {
        self.refusals
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seat(b: u8, height: u32, cluster: Option<u64>) -> SeatCandidate {
        SeatCandidate {
            coin: OutPointKey::new([b; 32], 0),
            confirmed_height: height,
            cluster,
        }
    }

    #[test]
    fn freshly_confirmed_coins_are_turned_away() {
        let p = AdmissionPolicy::default();
        let a = admit(&[seat(1, 1_000, None)], 1_010, p);
        assert!(a.admitted.is_empty());
        assert!(matches!(
            a.rejected[0].1,
            Rejection::TooYoung {
                age: 10,
                required: 144
            }
        ));
    }

    #[test]
    fn an_aged_coin_is_admitted() {
        let p = AdmissionPolicy::default();
        let a = admit(&[seat(1, 1_000, None)], 1_200, p);
        assert_eq!(a.admitted.len(), 1);
    }

    #[test]
    fn splitting_a_hoard_no_longer_buys_a_round() {
        // Forty seats, all one cluster: the whole point of the attack.
        let p = AdmissionPolicy::default();
        let offers: Vec<_> = (1..=40u8).map(|b| seat(b, 1_000, Some(7))).collect();
        let a = admit(&offers, 1_200, p);
        assert_eq!(
            a.admitted.len(),
            2,
            "one cluster may hold at most two seats"
        );
        assert_eq!(a.rejected.len(), 38);
        assert!(a
            .rejected
            .iter()
            .all(|(_, r)| matches!(r, Rejection::ClusterSaturated { .. })));
    }

    #[test]
    fn unrelated_participants_are_unaffected() {
        let p = AdmissionPolicy::default();
        let offers: Vec<_> = (1..=30u8)
            .map(|b| seat(b, 1_000, Some(u64::from(b))))
            .collect();
        let a = admit(&offers, 1_200, p);
        assert_eq!(
            a.admitted.len(),
            30,
            "the policy must not punish honest rounds"
        );
        assert!(a.rejected.is_empty());
    }

    #[test]
    fn dominance_reports_the_biggest_share() {
        let mixed: Vec<_> = (1..=10u8)
            .map(|b| seat(b, 1_000, Some(if b <= 6 { 1 } else { u64::from(b) })))
            .collect();
        assert!(
            (dominance(&mixed) - 0.6).abs() < 1e-9,
            "6 of 10 seats is one cluster"
        );

        let clean: Vec<_> = (1..=10u8)
            .map(|b| seat(b, 1_000, Some(u64::from(b))))
            .collect();
        assert!((dominance(&clean) - 0.1).abs() < 1e-9);
        assert_eq!(dominance(&[]), 0.0);
    }

    #[test]
    fn an_unclustered_seat_never_counts_as_dominant() {
        // `None` means analysis found no link, not that they are all the same
        // person. Treating them as one cluster would flag every honest round.
        let all_unknown: Vec<_> = (1..=10u8).map(|b| seat(b, 1_000, None)).collect();
        assert!((dominance(&all_unknown) - 0.1).abs() < 1e-9);
    }

    #[test]
    fn the_same_crowd_is_not_reassembled() {
        let mut g = DispersionGuard::new(4, 0.5);
        let crowd: Vec<_> = (1..=10u8).map(|b| seat(b, 1_000, None)).collect();
        assert!(g.allows(&crowd));
        g.record(&crowd);
        assert!(
            !g.allows(&crowd),
            "farming a victim with one crowd must be refused"
        );
        assert_eq!(g.refusals(), 1);
    }

    #[test]
    fn a_mostly_new_crowd_is_allowed() {
        let mut g = DispersionGuard::new(4, 0.5);
        let first: Vec<_> = (1..=10u8).map(|b| seat(b, 1_000, None)).collect();
        g.record(&first);
        // 4 of 10 shared — under the threshold.
        let second: Vec<_> = (1..=10u8)
            .map(|b| seat(if b <= 4 { b } else { b + 40 }, 1_000, None))
            .collect();
        assert!(g.allows(&second));
        assert_eq!(g.refusals(), 0);
    }

    #[test]
    fn dispersion_memory_is_bounded() {
        let mut g = DispersionGuard::new(2, 0.5);
        let crowd: Vec<_> = (1..=10u8).map(|b| seat(b, 1_000, None)).collect();
        g.record(&crowd);
        for i in 0..3u8 {
            let other: Vec<_> = (1..=10u8)
                .map(|b| seat(b + 50 + i * 10, 1_000, None))
                .collect();
            g.record(&other);
        }
        assert!(
            g.allows(&crowd),
            "the original crowd has aged out of memory"
        );
    }
}
