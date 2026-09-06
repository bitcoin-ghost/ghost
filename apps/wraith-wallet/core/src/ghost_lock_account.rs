//! A Ghost Lock as the wallet holds it: four lanes and one balance.
//!
//! `crates/ghost-lock` builds the Taproot output for a single lane. This turns
//! four of them into the thing a person has — one account, four compartments,
//! and a total.
//!
//! # Not `ghost-locks`
//!
//! `wraith-wallet-core` also depends on `ghost-locks` (plural), which is Ghost
//! Pay's P2WSH lock and is what `LockEntry` and the wallet's Locks screen render
//! today. This is the replacement, and the two coexist until Phase 0 demolition.
//! Nothing here touches the old model, deliberately — attaching the new design
//! to the one being demolished would make the demolition harder.
//!
//! # The lanes are not interchangeable, and the wallet must not pretend they are
//!
//! Each lane makes a different promise, and the difference is the point of
//! having four:
//!
//! | Lane | Normal spend | If the quorum goes silent | Private? |
//! |---|---|---|---|
//! | Savings | you + backup | you alone, after ~14 months | yes |
//! | Spending | you + quorum | you alone, after ~7 days | yes |
//! | Cash | you alone | n/a — no quorum involved | **no** |
//! | Investments | **quorum alone** | you recall, after ~14 days | yes |
//!
//! **Investments is the exception and the wallet has to say so.** It is the one
//! lane where the quorum can move funds without the owner — that is what lets an
//! LP supply liquidity on demand while the owner is offline, and it is a
//! genuinely different risk from the other three. A balance screen that shows
//! four numbers in the same weight misrepresents it.

use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::{Network, XOnlyPublicKey};

use ghost_lock::{CashPolicy, InvestmentsPolicy, Lane, LockError, SavingsPolicy, SpendingPolicy};

/// Which compartment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneKind {
    Savings,
    Spending,
    Cash,
    Investments,
}

impl LaneKind {
    /// Every lane, in the order a person reads them: coldest first.
    pub const ALL: [LaneKind; 4] = [
        LaneKind::Savings,
        LaneKind::Spending,
        LaneKind::Cash,
        LaneKind::Investments,
    ];

    /// The name a user sees.
    pub fn label(self) -> &'static str {
        match self {
            LaneKind::Savings => "Savings",
            LaneKind::Spending => "Spending",
            LaneKind::Cash => "Cash",
            LaneKind::Investments => "Investments",
        }
    }

    /// Whether the quorum can move this lane's funds **without** the owner.
    ///
    /// True only for Investments. A UI that does not surface this shows a
    /// custodial balance beside three non-custodial ones and lets the reader
    /// assume they are alike.
    pub fn quorum_can_spend_alone(self) -> bool {
        matches!(self, LaneKind::Investments)
    }

    /// Whether coins here can enter a Wraith round.
    ///
    /// False for Cash: it is already public, so mixing it gains nothing and
    /// re-links whatever it is mixed with. Enforced in
    /// `ghost_lock::compartment`; repeated here so a caller building a UI does
    /// not have to reach for the rule.
    pub fn round_eligible(self) -> bool {
        !matches!(self, LaneKind::Cash)
    }
}

/// The keys a Lock is built from.
#[derive(Debug, Clone, Copy)]
pub struct LockKeys {
    /// Owner's key.
    pub owner: XOnlyPublicKey,
    /// Backup device's key.
    pub backup: XOnlyPublicKey,
    /// Heir's key, for the inheritance leaf.
    pub heir: XOnlyPublicKey,
    /// MuSig2 aggregate of owner and backup, for the Savings key path.
    pub owner_backup_aggregate: XOnlyPublicKey,
    /// MuSig2 aggregate of owner and quorum, for the Spending key path.
    pub owner_quorum_aggregate: XOnlyPublicKey,
    /// The Wraith quorum's key.
    pub quorum: XOnlyPublicKey,
}

/// One built lane: its address and what it promises.
#[derive(Debug, Clone)]
pub struct BuiltLane {
    pub kind: LaneKind,
    pub lane: Lane,
}

/// A Ghost Lock: four lanes under one set of keys.
#[derive(Debug, Clone)]
pub struct GhostLockAccount {
    pub lanes: Vec<BuiltLane>,
}

impl GhostLockAccount {
    /// Build all four lanes.
    ///
    /// All four or none: a Lock missing a lane is not a Lock, and returning a
    /// partial one would leave the wallet showing three compartments while
    /// funds could still arrive at the fourth's address.
    pub fn build<C: Verification>(
        secp: &Secp256k1<C>,
        keys: &LockKeys,
        network: Network,
        anchor_height: u32,
        inherit_height: u32,
    ) -> Result<Self, LockError> {
        let savings = SavingsPolicy {
            aggregate: keys.owner_backup_aggregate,
            owner: keys.owner,
            backup: keys.backup,
            heir: keys.heir,
            inherit_height,
        }
        .build(secp, anchor_height, network)?;

        let spending = SpendingPolicy {
            aggregate: keys.owner_quorum_aggregate,
            owner: keys.owner,
        }
        .build(secp, network)?;

        let cash = CashPolicy { owner: keys.owner }.build(secp, network)?;

        let investments = InvestmentsPolicy {
            quorum: keys.quorum,
            owner: keys.owner,
        }
        .build(secp, network)?;

        Ok(Self {
            lanes: vec![
                BuiltLane {
                    kind: LaneKind::Savings,
                    lane: savings,
                },
                BuiltLane {
                    kind: LaneKind::Spending,
                    lane: spending,
                },
                BuiltLane {
                    kind: LaneKind::Cash,
                    lane: cash,
                },
                BuiltLane {
                    kind: LaneKind::Investments,
                    lane: investments,
                },
            ],
        })
    }

    /// The lane of a given kind.
    pub fn lane(&self, kind: LaneKind) -> Option<&BuiltLane> {
        self.lanes.iter().find(|l| l.kind == kind)
    }
}

/// A lane's balance, as shown.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LaneBalance {
    pub kind: LaneKind,
    pub label: String,
    pub address: String,
    pub balance_sats: u64,
    /// True only for Investments. Carried per lane rather than left for the UI
    /// to infer, so every client shows the same warning.
    pub quorum_can_spend_alone: bool,
    /// Whether these coins may enter a round.
    pub round_eligible: bool,
}

/// Every lane's balance, plus the combined total.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LockBalances {
    pub lanes: Vec<LaneBalance>,
    /// The whole Lock. What a person means by "how much have I got".
    pub total_sats: u64,
    /// Of the total, how much the quorum could move without the owner.
    ///
    /// Reported alongside the total rather than folded into it: a single figure
    /// that silently mixes custodial and non-custodial funds tells the reader
    /// less than two figures do.
    pub custodial_sats: u64,
}

/// Sum a Lock's lanes.
///
/// Saturating, because a total shown to a person must never wrap into a small
/// number. Where arithmetic actually moves coins the checked form is used
/// instead.
pub fn balances(account: &GhostLockAccount, per_lane_sats: &[(LaneKind, u64)]) -> LockBalances {
    let mut lanes = Vec::with_capacity(account.lanes.len());
    let mut total: u64 = 0;
    let mut custodial: u64 = 0;

    for built in &account.lanes {
        let sats = per_lane_sats
            .iter()
            .filter(|(k, _)| *k == built.kind)
            .fold(0u64, |acc, (_, v)| acc.saturating_add(*v));
        total = total.saturating_add(sats);
        if built.kind.quorum_can_spend_alone() {
            custodial = custodial.saturating_add(sats);
        }
        lanes.push(LaneBalance {
            kind: built.kind,
            label: built.kind.label().to_string(),
            address: built.lane.address.to_string(),
            balance_sats: sats,
            quorum_can_spend_alone: built.kind.quorum_can_spend_alone(),
            round_eligible: built.kind.round_eligible(),
        });
    }

    LockBalances {
        lanes,
        total_sats: total,
        custodial_sats: custodial,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, SecretKey};

    fn key(b: u8) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[b.max(1); 32]).unwrap();
        Keypair::from_secret_key(&secp, &sk).x_only_public_key().0
    }

    fn keys() -> LockKeys {
        LockKeys {
            owner: key(1),
            backup: key(2),
            heir: key(3),
            owner_backup_aggregate: key(4),
            owner_quorum_aggregate: key(5),
            quorum: key(6),
        }
    }

    fn account() -> GhostLockAccount {
        let secp = Secp256k1::verification_only();
        // Anchor at the current tip; inheritance well beyond it.
        GhostLockAccount::build(&secp, &keys(), Network::Regtest, 900_000, 1_000_000).unwrap()
    }

    #[test]
    fn a_lock_has_all_four_lanes_at_distinct_addresses() {
        // Compartments that share an address are not compartments.
        let a = account();
        assert_eq!(a.lanes.len(), 4);
        let mut addrs: Vec<String> = a.lanes.iter().map(|l| l.lane.address.to_string()).collect();
        addrs.sort();
        addrs.dedup();
        assert_eq!(addrs.len(), 4, "each lane needs its own address");
    }

    #[test]
    fn only_investments_is_custodial() {
        // The lane where the quorum spends alone. A UI that misses this shows a
        // custodial balance beside three non-custodial ones.
        for k in LaneKind::ALL {
            assert_eq!(
                k.quorum_can_spend_alone(),
                k == LaneKind::Investments,
                "{k:?}"
            );
        }
    }

    #[test]
    fn cash_is_the_only_lane_barred_from_rounds() {
        for k in LaneKind::ALL {
            assert_eq!(k.round_eligible(), k != LaneKind::Cash, "{k:?}");
        }
    }

    #[test]
    fn the_total_is_every_lane_including_cash() {
        // "How much have I got" means all of it. Excluding Cash because it is
        // not private would answer a different question than the one asked.
        let a = account();
        let b = balances(
            &a,
            &[
                (LaneKind::Savings, 1_000_000),
                (LaneKind::Spending, 200_000),
                (LaneKind::Cash, 50_000),
                (LaneKind::Investments, 40_000),
            ],
        );
        assert_eq!(b.total_sats, 1_290_000);
        assert_eq!(b.lanes.len(), 4);
    }

    #[test]
    fn the_custodial_share_is_reported_separately() {
        // Folding it into the total would tell the reader less: they could not
        // see how much of their money somebody else can move.
        let a = account();
        let b = balances(
            &a,
            &[
                (LaneKind::Savings, 1_000_000),
                (LaneKind::Investments, 40_000),
            ],
        );
        assert_eq!(b.total_sats, 1_040_000);
        assert_eq!(b.custodial_sats, 40_000);
    }

    #[test]
    fn a_lane_with_no_coins_is_still_listed() {
        // An empty lane must not vanish: it has an address funds can arrive at,
        // and a person needs to see it exists.
        let a = account();
        let b = balances(&a, &[(LaneKind::Spending, 5)]);
        assert_eq!(b.lanes.len(), 4);
        assert_eq!(b.total_sats, 5);
        for l in &b.lanes {
            assert!(!l.address.is_empty());
        }
    }

    #[test]
    fn several_utxos_in_one_lane_sum() {
        let a = account();
        let b = balances(
            &a,
            &[
                (LaneKind::Cash, 1_000),
                (LaneKind::Cash, 2_000),
                (LaneKind::Cash, 3_000),
            ],
        );
        assert_eq!(b.total_sats, 6_000);
    }

    #[test]
    fn the_total_saturates_rather_than_wrapping() {
        // A balance shown to a person must never wrap into a small number.
        let a = account();
        let b = balances(
            &a,
            &[
                (LaneKind::Savings, u64::MAX),
                (LaneKind::Spending, u64::MAX),
            ],
        );
        assert_eq!(b.total_sats, u64::MAX);
    }

    #[test]
    fn lanes_are_ordered_coldest_first() {
        // The order a person reads them in, and the order risk increases.
        let a = account();
        let kinds: Vec<LaneKind> = a.lanes.iter().map(|l| l.kind).collect();
        assert_eq!(kinds, LaneKind::ALL.to_vec());
    }
}
