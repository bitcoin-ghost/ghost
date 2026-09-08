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
//| FILE: anonymity_set.rs                                                                                               |
//|======================================================================================================================|

//! The number shown to the user, and why it is not the seat count.
//!
//! Every mixer on the market reports how many participants were in the round.
//! That number is wrong whenever one party holds several seats, which is
//! precisely the case the number is supposed to warn about. A round of fifty
//! where one entity supplied forty-nine seats offers an anonymity set of **two**,
//! and reporting fifty is not a rounding error — it is the single most
//! misleading thing a mixer can tell somebody.
//!
//! So the headline figure here counts **entities**, not seats.
//!
//! # Evidence, and the absence of it
//!
//! Inputs fall into three cases, and conflating the last two is where honesty
//! usually fails:
//!
//! | Evidence | Treatment |
//! |---|---|
//! | Positively linked (shared ancestry cluster, same LP identity) | merged into one entity |
//! | Positively distinct (different LP identities) | separate entities |
//! | No evidence either way | separate entities, **and counted as unverified** |
//!
//! Treating "no evidence" as linked would report 1 for every round and be
//! useless. Treating it as distinct without saying so would quietly present an
//! assumption as a measurement. So it counts, and it is declared: the report
//! carries how much of the set rests on the absence of evidence rather than on
//! its presence.
//!
//! # This never rounds in the user's favour
//!
//! Where a judgement could go either way it goes against the reported number.
//! A set that is smaller than stated is a lie the user acts on; a set larger
//! than stated costs them nothing.
//!
//! # The participant can run this themselves
//!
//! Everything here is derived from public chain data plus the round's own
//! contents. Nothing requires trusting the coordinator, which matters because
//! **a malicious coordinator can lie about the anonymity set but cannot lie
//! about the chain.** Verifying locally removes the coordinator from the trust
//! path for the one number the user is relying on.

use std::collections::{HashMap, HashSet};

use crate::admission::SeatCandidate;

/// What a seat is doing in the round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Making a real payment. The best cover there is, because they behave
    /// exactly like the user being protected.
    Payer,
    /// Here only to mix.
    Mixer,
    /// Supplying liquidity, identified by LP id.
    ///
    /// Identified deliberately: an LP sells a service rather than buying
    /// privacy, so it may be named where a user may not. Two seats from one LP
    /// are one entity.
    LiquidityProvider(u64),
}

/// One seat in a round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seat {
    /// The coin offered.
    pub candidate: SeatCandidate,
    /// What this seat is doing.
    pub role: Role,
}

/// Why two or more seats collapsed into one entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Discount {
    /// Seats whose coins share an ancestry cluster.
    SharedAncestry {
        /// The cluster.
        cluster: u64,
        /// How many seats it covered.
        seats: usize,
    },
    /// Seats from one liquidity provider.
    SameProvider {
        /// The LP.
        lp: u64,
        /// How many seats it held.
        seats: usize,
    },
}

/// What the user is told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetReport {
    /// Seats in the round — what a naive mixer would report.
    pub seats: usize,
    /// Distinct entities. **This is the anonymity set.**
    pub entities: usize,
    /// Entities whose distinctness rests on no evidence being found, rather
    /// than on evidence of distinctness. Always `<= entities`.
    pub unverified: usize,
    /// Real payments among the entities. Cover that behaves like the user,
    /// because it is doing the same thing the user is doing.
    pub payers: usize,
    /// Why seats collapsed. Empty when nothing did.
    pub discounts: Vec<Discount>,
}

impl SetReport {
    /// Seats that collapsed into another entity.
    pub fn discounted(&self) -> usize {
        self.seats.saturating_sub(self.entities)
    }

    /// Whether the round meets a required set size.
    ///
    /// Judged on [`Self::entities`], never on seats — checking seats would pass
    /// exactly the rounds this module exists to catch.
    pub fn meets(&self, required: usize) -> bool {
        self.entities >= required
    }
}

/// Minimal union-find. Small sets, so the simple version is the right one.
struct Union {
    parent: Vec<usize>,
}

impl Union {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
        }
    }
    fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            self.parent[x] = self.parent[self.parent[x]];
            x = self.parent[x];
        }
        x
    }
    fn union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            self.parent[rb] = ra;
        }
    }
}

/// Count the entities in a round.
///
/// Merges seats sharing an ancestry cluster, and seats belonging to one
/// liquidity provider. A seat with neither signal is its own entity and is
/// counted as unverified.
pub fn assess(seats: &[Seat]) -> SetReport {
    if seats.is_empty() {
        return SetReport {
            seats: 0,
            entities: 0,
            unverified: 0,
            payers: 0,
            discounts: Vec::new(),
        };
    }

    let mut uf = Union::new(seats.len());

    // Merge on shared ancestry. `None` is explicitly NOT a cluster — treating
    // every unanalysed coin as one group would collapse the set to 1.
    let mut by_cluster: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, s) in seats.iter().enumerate() {
        if let Some(c) = s.candidate.cluster {
            by_cluster.entry(c).or_default().push(i);
        }
    }
    // Merge on LP identity. One provider holding several seats is one entity,
    // whatever its coins' ancestry looks like.
    let mut by_lp: HashMap<u64, Vec<usize>> = HashMap::new();
    for (i, s) in seats.iter().enumerate() {
        if let Role::LiquidityProvider(lp) = s.role {
            by_lp.entry(lp).or_default().push(i);
        }
    }

    for group in by_cluster.values().chain(by_lp.values()) {
        for w in group.windows(2) {
            uf.union(w[0], w[1]);
        }
    }

    let mut roots: HashSet<usize> = HashSet::new();
    for i in 0..seats.len() {
        roots.insert(uf.find(i));
    }
    let entities = roots.len();

    // An entity is unverified when nothing positively distinguished it: no
    // ancestry cluster and no LP identity. Counted per entity, not per seat.
    let mut unverified_roots: HashSet<usize> = HashSet::new();
    for (i, s) in seats.iter().enumerate() {
        let has_evidence =
            s.candidate.cluster.is_some() || matches!(s.role, Role::LiquidityProvider(_));
        if !has_evidence {
            unverified_roots.insert(uf.find(i));
        }
    }

    // Payers counted per entity too — one payer holding three seats is one
    // piece of cover, not three.
    let mut payer_roots: HashSet<usize> = HashSet::new();
    for (i, s) in seats.iter().enumerate() {
        if s.role == Role::Payer {
            payer_roots.insert(uf.find(i));
        }
    }

    let mut discounts: Vec<Discount> = Vec::new();
    for (cluster, group) in &by_cluster {
        if group.len() > 1 {
            discounts.push(Discount::SharedAncestry {
                cluster: *cluster,
                seats: group.len(),
            });
        }
    }
    for (lp, group) in &by_lp {
        if group.len() > 1 {
            discounts.push(Discount::SameProvider {
                lp: *lp,
                seats: group.len(),
            });
        }
    }
    // Deterministic ordering, so two nodes rendering the same round agree.
    discounts.sort_by_key(|d| match d {
        Discount::SharedAncestry { cluster, .. } => (0u8, *cluster),
        Discount::SameProvider { lp, .. } => (1u8, *lp),
    });

    SetReport {
        seats: seats.len(),
        entities,
        unverified: unverified_roots.len(),
        payers: payer_roots.len(),
        discounts,
    }
}

/// The coordinator claimed a larger set than the chain supports.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("coordinator claims an anonymity set of {claimed}, but only {counted} distinct entities are visible in the round's own inputs")]
pub struct OverClaimed {
    /// What the coordinator said.
    pub claimed: usize,
    /// What the participant counted for itself.
    pub counted: usize,
}

/// Recount a round's entities from its inputs alone, as a participant can.
///
/// Takes `(outpoint, scriptPubKey)` per input — both available from the round
/// transaction and its prevouts, so this needs nothing the coordinator has to
/// be believed about.
///
/// Roles are unknown to a participant, so every seat is counted as a payer.
/// That means the result is an **upper bound**: the coordinator additionally
/// merges seats belonging to one liquidity provider, which can only make its
/// honest figure smaller than this one.
pub fn recount_from_inputs(coins: &[crate::clustering::CoinFacts]) -> SetReport {
    let clusters = crate::clustering::cluster_coins(coins);
    let seats: Vec<Seat> = coins
        .iter()
        .zip(clusters.iter())
        .map(|(c, cluster)| Seat {
            candidate: SeatCandidate {
                coin: c.outpoint,
                confirmed_height: 0,
                cluster: *cluster,
            },
            role: Role::Payer,
        })
        .collect();
    assess(&seats)
}

/// Check a coordinator's claim against an independent recount.
///
/// # The asymmetry is the whole design
///
/// Only **over**-claiming is a refusal. A coordinator reporting *fewer* entities
/// than the participant counts is being conservative — it can see liquidity
/// provider identities the participant cannot, and merging those correctly
/// lowers the figure. Refusing that would punish the honest behaviour.
///
/// Claiming *more* than the round's own inputs support cannot be conservatism.
/// The participant's count is an upper bound, so exceeding it means the claim is
/// not derivable from the chain at all.
///
/// # What this catches, and what it does not
///
/// It catches gross over-claiming — fifty asserted where the coins show three —
/// which is the failure that matters, because it is the one a user acts on.
///
/// It cannot verify the coordinator's liquidity-provider merging, because the
/// participant cannot see which seats belong to which provider. A coordinator
/// under-reporting to hide something would pass. That is the weaker direction
/// and it is not the direction that misleads a user into signing.
pub fn verify_claim(claimed: &SetReport, independent: &SetReport) -> Result<(), OverClaimed> {
    if claimed.entities > independent.entities {
        return Err(OverClaimed {
            claimed: claimed.entities,
            counted: independent.entities,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing_ledger::OutPointKey;

    fn seat(id: u8, cluster: Option<u64>, role: Role) -> Seat {
        Seat {
            candidate: SeatCandidate {
                coin: OutPointKey {
                    txid: [id; 32],
                    vout: 0,
                },
                confirmed_height: 1_000,
                cluster,
            },
            role,
        }
    }

    fn facts(txid: u8, vout: u32, script: &[u8]) -> crate::clustering::CoinFacts {
        crate::clustering::CoinFacts {
            outpoint: OutPointKey {
                txid: [txid; 32],
                vout,
            },
            script_pubkey: script.to_vec(),
        }
    }

    #[test]
    fn a_participant_recounts_the_round_from_its_own_inputs() {
        // Everything here comes from the round transaction and its prevouts, so
        // the coordinator does not have to be believed about any of it.
        let coins = vec![
            facts(1, 0, &[1]),
            facts(2, 0, &[2]),
            facts(3, 0, &[3]),
            facts(9, 0, &[9]),
            facts(9, 1, &[10]), // sibling of the previous one
        ];
        let r = recount_from_inputs(&coins);
        assert_eq!(r.seats, 5);
        assert_eq!(r.entities, 4, "the two siblings are one entity");
    }

    #[test]
    fn claiming_more_than_the_coins_support_is_refused() {
        // The failure that matters: a number the user acts on that the chain
        // does not support.
        let coins: Vec<crate::clustering::CoinFacts> =
            (0..20u32).map(|v| facts(7, v, &[v as u8])).collect();
        let independent = recount_from_inputs(&coins);
        assert_eq!(independent.entities, 1, "all twenty share a funding tx");

        let claimed = SetReport {
            seats: 20,
            entities: 20,
            unverified: 0,
            payers: 20,
            discounts: Vec::new(),
        };
        assert_eq!(
            verify_claim(&claimed, &independent),
            Err(OverClaimed {
                claimed: 20,
                counted: 1
            })
        );
    }

    #[test]
    fn claiming_fewer_is_accepted_because_it_is_conservatism() {
        // The coordinator sees liquidity-provider identities a participant
        // cannot, and merging those correctly lowers the figure. Refusing that
        // would punish the honest behaviour.
        let coins = vec![facts(1, 0, &[1]), facts(2, 0, &[2]), facts(3, 0, &[3])];
        let independent = recount_from_inputs(&coins);
        assert_eq!(independent.entities, 3);

        let claimed = SetReport {
            seats: 3,
            entities: 2,
            unverified: 0,
            payers: 1,
            discounts: Vec::new(),
        };
        assert!(verify_claim(&claimed, &independent).is_ok());
    }

    #[test]
    fn an_exact_match_is_accepted() {
        let coins = vec![facts(1, 0, &[1]), facts(2, 0, &[2])];
        let independent = recount_from_inputs(&coins);
        let claimed = independent.clone();
        assert!(verify_claim(&claimed, &independent).is_ok());
    }

    #[test]
    fn the_over_claim_error_carries_both_numbers() {
        // A user shown only "refused" cannot tell a bug from a lie.
        let msg = OverClaimed {
            claimed: 50,
            counted: 3,
        }
        .to_string();
        assert!(msg.contains("50") && msg.contains('3'), "{msg}");
    }

    #[test]
    fn the_headline_is_entities_not_seats() {
        // The case the whole module exists for: fifty seats, one entity behind
        // forty-nine of them. Reporting fifty here is the most misleading thing
        // a mixer can say.
        let mut seats = vec![seat(0, None, Role::Mixer)];
        for i in 1..50u8 {
            seats.push(seat(i, None, Role::LiquidityProvider(7)));
        }
        let r = assess(&seats);
        assert_eq!(r.seats, 50);
        assert_eq!(r.entities, 2, "one LP plus the victim");
        assert_eq!(r.discounted(), 48);
    }

    #[test]
    fn shared_ancestry_collapses_seats() {
        let seats = vec![
            seat(1, Some(9), Role::Mixer),
            seat(2, Some(9), Role::Mixer),
            seat(3, Some(9), Role::Mixer),
            seat(4, Some(4), Role::Payer),
        ];
        let r = assess(&seats);
        assert_eq!(r.entities, 2);
        assert!(r.discounts.contains(&Discount::SharedAncestry {
            cluster: 9,
            seats: 3
        }));
    }

    #[test]
    fn an_unanalysed_coin_is_its_own_entity_not_one_big_group() {
        // Treating `None` as a shared cluster would report 1 for every round
        // and be useless rather than cautious.
        let seats: Vec<Seat> = (0..5u8).map(|i| seat(i, None, Role::Payer)).collect();
        let r = assess(&seats);
        assert_eq!(r.entities, 5);
    }

    #[test]
    fn distinctness_without_evidence_is_declared_as_such() {
        // Counting it silently would present an assumption as a measurement.
        let seats = vec![
            seat(1, None, Role::Mixer),
            seat(2, None, Role::Payer),
            seat(3, Some(3), Role::Payer),
            seat(4, None, Role::LiquidityProvider(1)),
        ];
        let r = assess(&seats);
        assert_eq!(r.entities, 4);
        // Two carry no evidence at all; the clustered one and the LP do.
        assert_eq!(r.unverified, 2);
        assert!(r.unverified <= r.entities);
    }

    #[test]
    fn two_seats_from_one_provider_are_one_entity() {
        // The 1-input-per-LP rule makes this rare, and the count must still be
        // right when the rule is not enforced upstream.
        let seats = vec![
            seat(1, None, Role::LiquidityProvider(3)),
            seat(2, None, Role::LiquidityProvider(3)),
            seat(3, None, Role::LiquidityProvider(8)),
            seat(4, None, Role::Mixer),
        ];
        let r = assess(&seats);
        assert_eq!(r.entities, 3);
        assert!(r
            .discounts
            .contains(&Discount::SameProvider { lp: 3, seats: 2 }));
    }

    #[test]
    fn ancestry_and_provider_evidence_merge_transitively() {
        // Seats 1-2 share a cluster; 2-3 share an LP. All three are one entity,
        // and missing that would over-report by treating the two signals
        // independently.
        let seats = vec![
            seat(1, Some(5), Role::LiquidityProvider(1)),
            seat(2, Some(5), Role::LiquidityProvider(2)),
            seat(3, None, Role::LiquidityProvider(2)),
            seat(4, None, Role::Payer),
        ];
        let r = assess(&seats);
        assert_eq!(r.entities, 2);
    }

    #[test]
    fn payers_are_counted_per_entity_not_per_seat() {
        // One payer with three rungs is one piece of cover.
        let seats = vec![
            seat(1, Some(2), Role::Payer),
            seat(2, Some(2), Role::Payer),
            seat(3, Some(2), Role::Payer),
            seat(4, Some(7), Role::Payer),
        ];
        let r = assess(&seats);
        assert_eq!(r.payers, 2);
        assert_eq!(r.entities, 2);
    }

    #[test]
    fn the_floor_is_judged_on_entities_so_a_padded_round_fails_it() {
        // Checking seats would pass exactly the rounds this module catches.
        let mut seats = vec![seat(0, None, Role::Mixer)];
        for i in 1..20u8 {
            seats.push(seat(i, Some(1), Role::Mixer));
        }
        let r = assess(&seats);
        assert_eq!(r.seats, 20);
        assert!(
            !r.meets(5),
            "20 seats, 2 entities — must not pass a floor of 5"
        );
        assert!(r.meets(2));
    }

    #[test]
    fn discount_order_is_deterministic() {
        // Two nodes rendering the same round must produce the same text.
        let seats = vec![
            seat(1, Some(9), Role::LiquidityProvider(4)),
            seat(2, Some(9), Role::LiquidityProvider(4)),
            seat(3, Some(2), Role::Mixer),
            seat(4, Some(2), Role::Mixer),
        ];
        let a = assess(&seats);
        let mut reversed = seats.clone();
        reversed.reverse();
        let b = assess(&reversed);
        assert_eq!(a.discounts, b.discounts);
        assert_eq!(a.entities, b.entities);
    }

    #[test]
    fn an_empty_round_reports_nothing_rather_than_one() {
        let r = assess(&[]);
        assert_eq!(r.entities, 0);
        assert!(!r.meets(1));
    }
}
