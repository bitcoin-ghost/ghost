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
//| FILE: consolidation.rs                                                                                             |
//|======================================================================================================================|

//! Consolidation — the wallet behaviour that quietly undoes everything else.
//!
//! A recipient is paid in rungs: 137,000 sats arrives as five separate coins.
//! Every wallet in existence will, given the chance, tidy those into one UTXO —
//! to reduce fees, to simplify the balance, because that is what wallets do.
//!
//! Doing so publishes the payment. Spending all five together announces their
//! sum, which is the amount the round went to some trouble to hide, and it links
//! the five coins to one owner permanently.
//!
//! Nothing upstream can prevent this. The round is long since confirmed; the
//! ladder did its job; the coordinator never knew. It is undone afterwards, by
//! the recipient's own wallet, doing something reasonable.
//!
//! # Two distinct harms
//!
//! - **Revealing an amount.** Spending several coins from *one* payment
//!   discloses at least their sum. Spending all of them discloses it exactly.
//! - **Linking payments.** Spending coins from *different* payments proves one
//!   owner received both — merging two anonymity sets into one identity.
//!
//! The second is worse and less obvious: each payment may be perfectly private
//! on its own, and the link is created entirely by the spend.
//!
//! # This has to be a refusal
//!
//! A warning that still lets the spend through is worth nothing here, because
//! the default is the dangerous behaviour and defaults are what run at 3am on a
//! background thread.

use std::collections::{BTreeMap, BTreeSet};

/// Which payment a coin arrived in. Wallet-local; never published.
pub type PaymentId = u64;

/// A coin the wallet holds, with the provenance needed to spend it safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldCoin {
    /// Value in satoshis.
    pub value_sats: u64,
    /// The payment this arrived in.
    pub received_in: PaymentId,
}

/// What a proposed spend would disclose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsolidationRisk {
    /// Several coins from one payment, disclosing at least their sum.
    RevealsPaymentAmount {
        /// Which payment.
        payment: PaymentId,
        /// Coins from it being spent.
        spent: usize,
        /// Coins from it held in total.
        held: usize,
        /// The sum being disclosed.
        disclosed_sats: u64,
        /// Whether this is the exact amount rather than a lower bound.
        exact: bool,
    },
    /// Coins from different payments, proving common ownership.
    LinksPayments {
        /// The payments being linked.
        payments: Vec<PaymentId>,
    },
}

/// Assess a proposed input set against everything the wallet holds.
///
/// `spending` must be a subset of `held`. Returns every risk, worst first —
/// linkage before disclosure, because linkage cannot be undone by later
/// behaviour and an amount can at least be muddied.
pub fn assess(held: &[HeldCoin], spending: &[HeldCoin]) -> Vec<ConsolidationRisk> {
    let mut risks = Vec::new();

    let payments: BTreeSet<PaymentId> = spending.iter().map(|c| c.received_in).collect();
    if payments.len() > 1 {
        risks.push(ConsolidationRisk::LinksPayments {
            payments: payments.iter().copied().collect(),
        });
    }

    let mut by_payment: BTreeMap<PaymentId, Vec<u64>> = BTreeMap::new();
    for c in spending {
        by_payment
            .entry(c.received_in)
            .or_default()
            .push(c.value_sats);
    }
    for (payment, values) in by_payment {
        if values.len() < 2 {
            continue;
        }
        let held_count = held.iter().filter(|c| c.received_in == payment).count();
        risks.push(ConsolidationRisk::RevealsPaymentAmount {
            payment,
            spent: values.len(),
            held: held_count,
            disclosed_sats: values.iter().sum(),
            exact: values.len() == held_count,
        });
    }

    risks
}

/// Whether a spend is safe to make without asking.
///
/// Anything a wallet does on a schedule — fee consolidation, dust sweeping,
/// balance tidying — must pass this before it runs unattended.
pub fn is_safe_unattended(held: &[HeldCoin], spending: &[HeldCoin]) -> bool {
    assess(held, spending).is_empty()
}

/// Choose coins for a payment while disclosing as little as possible.
///
/// Prefers a single coin that covers the target. Failing that, takes coins from
/// **one** payment rather than several — disclosing an amount is the lesser
/// harm, and linking payments is the one that cannot be walked back.
///
/// Returns `None` when no single payment can cover the target: at that point the
/// choice is the user's, not the wallet's.
pub fn select_least_disclosing(held: &[HeldCoin], target_sats: u64) -> Option<Vec<HeldCoin>> {
    // A single sufficient coin discloses nothing.
    let mut singles: Vec<&HeldCoin> = held
        .iter()
        .filter(|c| c.value_sats >= target_sats)
        .collect();
    singles.sort_by_key(|c| c.value_sats);
    if let Some(c) = singles.first() {
        return Some(vec![**c]);
    }

    // Otherwise the smallest set from a single payment that covers it.
    let mut by_payment: BTreeMap<PaymentId, Vec<HeldCoin>> = BTreeMap::new();
    for c in held {
        by_payment.entry(c.received_in).or_default().push(*c);
    }
    let mut best: Option<Vec<HeldCoin>> = None;
    for (_, mut coins) in by_payment {
        coins.sort_by_key(|c| std::cmp::Reverse(c.value_sats));
        let mut take = Vec::new();
        let mut sum = 0u64;
        for c in coins {
            if sum >= target_sats {
                break;
            }
            sum += c.value_sats;
            take.push(c);
        }
        if sum >= target_sats && best.as_ref().is_none_or(|b| take.len() < b.len()) {
            best = Some(take);
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coin(value: u64, payment: PaymentId) -> HeldCoin {
        HeldCoin {
            value_sats: value,
            received_in: payment,
        }
    }

    /// A recipient paid 137,000 in one round, and 89,000 in another.
    fn wallet() -> Vec<HeldCoin> {
        vec![
            coin(100_000, 1),
            coin(20_000, 1),
            coin(10_000, 1),
            coin(5_000, 1),
            coin(2_000, 1),
            coin(50_000, 2),
            coin(20_000, 2),
            coin(10_000, 2),
            coin(5_000, 2),
            coin(2_000, 2),
            coin(2_000, 2),
        ]
    }

    #[test]
    fn spending_one_coin_discloses_nothing() {
        let w = wallet();
        assert!(is_safe_unattended(&w, &[coin(100_000, 1)]));
    }

    #[test]
    fn the_overnight_tidy_up_is_refused() {
        // The scheduled consolidation every wallet performs by default: sweep
        // everything into one UTXO. It links both payments AND publishes both
        // amounts exactly.
        let w = wallet();
        let risks = assess(&w, &w);
        assert!(!is_safe_unattended(&w, &w));
        assert!(matches!(risks[0], ConsolidationRisk::LinksPayments { .. }));
        assert!(risks.iter().any(|r| matches!(
            r,
            ConsolidationRisk::RevealsPaymentAmount {
                disclosed_sats: 137_000,
                exact: true,
                ..
            }
        )));
    }

    #[test]
    fn spending_a_whole_payment_discloses_its_exact_amount() {
        let w = wallet();
        let all_of_one: Vec<HeldCoin> = w.iter().filter(|c| c.received_in == 1).copied().collect();
        let risks = assess(&w, &all_of_one);
        assert_eq!(
            risks,
            vec![ConsolidationRisk::RevealsPaymentAmount {
                payment: 1,
                spent: 5,
                held: 5,
                disclosed_sats: 137_000,
                exact: true,
            }]
        );
    }

    #[test]
    fn spending_part_of_a_payment_discloses_a_lower_bound() {
        let w = wallet();
        let some = vec![coin(100_000, 1), coin(20_000, 1)];
        let risks = assess(&w, &some);
        assert!(matches!(
            risks[0],
            ConsolidationRisk::RevealsPaymentAmount {
                disclosed_sats: 120_000,
                exact: false,
                ..
            }
        ));
    }

    #[test]
    fn linking_two_payments_is_reported_first() {
        // Linkage is the worse harm and cannot be undone by later behaviour,
        // so it must not be buried under amount disclosures.
        let w = wallet();
        let mixed = vec![coin(100_000, 1), coin(50_000, 2)];
        let risks = assess(&w, &mixed);
        assert!(matches!(risks[0], ConsolidationRisk::LinksPayments { .. }));
    }

    #[test]
    fn a_single_sufficient_coin_is_preferred() {
        let w = wallet();
        let chosen = select_least_disclosing(&w, 40_000).expect("covers");
        assert_eq!(chosen.len(), 1, "one coin discloses nothing");
        assert_eq!(chosen[0].value_sats, 50_000, "and the smallest that fits");
        assert!(is_safe_unattended(&w, &chosen));
    }

    #[test]
    fn otherwise_it_stays_within_one_payment() {
        let w = wallet();
        // Nothing single covers 130k, so it must not reach across payments.
        let chosen = select_least_disclosing(&w, 130_000).expect("covers");
        let payments: BTreeSet<PaymentId> = chosen.iter().map(|c| c.received_in).collect();
        assert_eq!(payments.len(), 1, "linking payments is the worse harm");
        let risks = assess(&w, &chosen);
        assert!(!risks
            .iter()
            .any(|r| matches!(r, ConsolidationRisk::LinksPayments { .. })));
    }

    #[test]
    fn an_amount_no_single_payment_covers_is_the_users_call() {
        let w = wallet();
        // More than either payment holds: the wallet must not silently link
        // them to make it work.
        assert!(select_least_disclosing(&w, 200_000).is_none());
    }
}
