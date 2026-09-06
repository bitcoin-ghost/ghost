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
//| FILE: standing_order.rs                                                                                              |
//|======================================================================================================================|

//! The standing order — a year of spending money, presigned.
//!
//! At each annual rollover the vault splits a budget into rungs that mature
//! monthly. The phone can spend a matured rung alone; the vault behind them
//! needs both devices. Said to a user it is simply **a standing order from
//! savings to your current account**, and that framing is accurate.
//!
//! It is also what makes a fourteen-month recovery survivable: lose the backup
//! device and you keep drawing income the whole time the clock runs.
//!
//! # Exposure is cumulative, not monthly
//!
//! The tempting sentence is "a compromised phone reaches one month's money".
//! That is false, and the difference matters to anyone deciding how much to
//! schedule. Unspent rungs **accumulate** — a phone stolen in month nine
//! reaches every rung matured since the rollover that has not been spent.
//!
//! [`StandingOrder::exposure_at`] reports the true figure, and the wallet's job
//! is to keep it low by sweeping matured rungs into the hot lane promptly rather
//! than by scheduling less.
//!
//! Discretionary rungs are the answer to the other half: without them a manual
//! top-up needs both devices, which is exactly the errand this exists to avoid.
//! They mature immediately and are deliberately a small share of the budget.

use crate::ladder::Ladder;

/// Blocks in an average month: 144 per day over 30.44 days.
pub const BLOCKS_PER_MONTH: u32 = 4_383;

/// Why a rung is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RungKind {
    /// Matures on its month.
    Monthly,
    /// Available from the rollover, for unplanned spending.
    Discretionary,
}

/// One presigned rung and when the phone may spend it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduledRung {
    /// Value. Always a ladder rung.
    pub value_sats: u64,
    /// Absolute height from which the phone may spend it alone.
    pub matures_at: u32,
    /// Monthly or discretionary.
    pub kind: RungKind,
}

/// A year of presigned spending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandingOrder {
    rungs: Vec<ScheduledRung>,
    anchor_height: u32,
}

impl StandingOrder {
    /// Split `budget_sats` into twelve monthly tranches plus a discretionary
    /// reserve, all quantised onto the ladder.
    ///
    /// `discretionary_sats` is available from the rollover. Keep it modest: it
    /// is the part a stolen phone reaches on day one.
    pub fn plan(
        ladder: &Ladder,
        budget_sats: u64,
        discretionary_sats: u64,
        anchor_height: u32,
    ) -> Self {
        let mut rungs = Vec::new();

        let discretionary = ladder.quantise(discretionary_sats.min(budget_sats));
        if discretionary >= ladder.floor() {
            for v in ladder.decompose(discretionary).unwrap_or_default() {
                rungs.push(ScheduledRung {
                    value_sats: v,
                    matures_at: anchor_height,
                    kind: RungKind::Discretionary,
                });
            }
        }

        let monthly_budget = budget_sats.saturating_sub(discretionary);
        let per_month = ladder.quantise(monthly_budget / 12);
        if per_month >= ladder.floor() {
            for month in 1..=12u32 {
                for v in ladder.decompose(per_month).unwrap_or_default() {
                    rungs.push(ScheduledRung {
                        value_sats: v,
                        matures_at: anchor_height + month * BLOCKS_PER_MONTH,
                        kind: RungKind::Monthly,
                    });
                }
            }
        }

        Self {
            rungs,
            anchor_height,
        }
    }

    /// Every rung, matured or not.
    pub fn rungs(&self) -> &[ScheduledRung] {
        &self.rungs
    }

    /// Rungs the phone may spend alone at `height`.
    pub fn spendable_at(&self, height: u32) -> Vec<ScheduledRung> {
        self.rungs
            .iter()
            .copied()
            .filter(|r| r.matures_at <= height)
            .collect()
    }

    /// What a compromised phone reaches at `height`, assuming nothing was swept.
    ///
    /// **Cumulative, not monthly.** This is the number to show a user choosing a
    /// budget, and the reason the wallet should sweep matured rungs promptly.
    pub fn exposure_at(&self, height: u32) -> u64 {
        self.spendable_at(height).iter().map(|r| r.value_sats).sum()
    }

    /// Exposure if matured rungs are swept into the hot lane as they arrive.
    ///
    /// The realistic figure for a wallet that does its job: at most one month's
    /// tranche plus whatever discretionary reserve remains.
    pub fn exposure_if_swept(&self, height: u32) -> u64 {
        let discretionary: u64 = self
            .rungs
            .iter()
            .filter(|r| r.kind == RungKind::Discretionary)
            .map(|r| r.value_sats)
            .sum();
        let newest_month = self
            .rungs
            .iter()
            .filter(|r| r.kind == RungKind::Monthly && r.matures_at <= height)
            .map(|r| r.matures_at)
            .max();
        let month_tranche: u64 = match newest_month {
            Some(h) => self
                .rungs
                .iter()
                .filter(|r| r.kind == RungKind::Monthly && r.matures_at == h)
                .map(|r| r.value_sats)
                .sum(),
            None => 0,
        };
        discretionary + month_tranche
    }

    /// Total scheduled across the year.
    pub fn total(&self) -> u64 {
        self.rungs.iter().map(|r| r.value_sats).sum()
    }

    /// Height at which the schedule runs dry and a rollover is required.
    pub fn exhausted_at(&self) -> u32 {
        self.rungs
            .iter()
            .map(|r| r.matures_at)
            .max()
            .unwrap_or(self.anchor_height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ANCHOR: u32 = 900_000;

    fn order() -> StandingOrder {
        // £-ish: 1.2M sats a year, 100k of it discretionary.
        StandingOrder::plan(&Ladder::standard(), 1_200_000, 100_000, ANCHOR)
    }

    #[test]
    fn every_scheduled_value_is_a_rung() {
        let l = Ladder::standard();
        for r in order().rungs() {
            assert!(
                l.rungs().contains(&r.value_sats),
                "{} is not a rung",
                r.value_sats
            );
        }
    }

    #[test]
    fn nothing_but_the_discretionary_reserve_is_available_on_day_one() {
        let o = order();
        let day_one = o.spendable_at(ANCHOR);
        assert!(
            day_one.iter().all(|r| r.kind == RungKind::Discretionary),
            "a monthly rung matured early"
        );
        assert_eq!(o.exposure_at(ANCHOR), 100_000);
    }

    #[test]
    fn exposure_accumulates_and_is_not_one_month() {
        // The sentence "a stolen phone reaches one month's money" is false, and
        // this is the test that keeps it from being written down.
        let o = order();
        let m1 = o.exposure_at(ANCHOR + BLOCKS_PER_MONTH);
        let m6 = o.exposure_at(ANCHOR + 6 * BLOCKS_PER_MONTH);
        let m12 = o.exposure_at(ANCHOR + 12 * BLOCKS_PER_MONTH);
        assert!(m6 > m1, "unspent rungs accumulate");
        assert!(m12 > m6);
        assert_eq!(m12, o.total(), "by year end everything has matured");
    }

    #[test]
    fn sweeping_bounds_exposure_to_a_single_tranche() {
        // What the wallet doing its job actually buys.
        let o = order();
        let unswept = o.exposure_at(ANCHOR + 9 * BLOCKS_PER_MONTH);
        let swept = o.exposure_if_swept(ANCHOR + 9 * BLOCKS_PER_MONTH);
        assert!(
            swept < unswept / 2,
            "sweeping should cut exposure sharply: {swept} vs {unswept}"
        );
    }

    #[test]
    fn a_rung_is_never_spendable_before_its_month() {
        let o = order();
        for r in o.rungs() {
            assert!(
                o.spendable_at(r.matures_at.saturating_sub(1))
                    .iter()
                    .all(|s| *s != *r),
                "rung maturing at {} was spendable a block early",
                r.matures_at
            );
            assert!(o.spendable_at(r.matures_at).contains(r));
        }
    }

    #[test]
    fn the_schedule_runs_dry_after_twelve_months() {
        let o = order();
        assert_eq!(o.exhausted_at(), ANCHOR + 12 * BLOCKS_PER_MONTH);
    }

    #[test]
    fn a_budget_below_the_floor_schedules_nothing_rather_than_dust() {
        let o = StandingOrder::plan(&Ladder::standard(), 500, 0, ANCHOR);
        assert!(o.rungs().is_empty(), "sub-floor budgets must not mint dust");
        assert_eq!(o.total(), 0);
    }

    #[test]
    fn discretionary_never_exceeds_the_budget() {
        // A caller asking for more discretionary than exists must not create
        // money that was never scheduled.
        let o = StandingOrder::plan(&Ladder::standard(), 100_000, 500_000, ANCHOR);
        assert!(
            o.total() <= 100_000,
            "scheduled {} against a 100k budget",
            o.total()
        );
    }
}
