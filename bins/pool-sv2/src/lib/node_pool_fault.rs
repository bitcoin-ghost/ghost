//! Test-only faults in the canonical coinbase, for the regtest harness's hostile node
//! (`scripts/regtest-node-pool`). Compiled only with the `np-fault-injection` feature, which no
//! release build enables; without it this module does not exist.
//!
//! `GHOST_NP_FAULT` picks the fault, read once:
//! - `wrong-treasury`: the first output pays a script that is not the treasury's.
//! - `fee-skim`: 100,000 sats move from the treasury to the finder, so treasury plus miners fall
//!   below the subsidy.
//! - `payee-order`: the first two miner outputs swap places: the right payees and amounts, out of
//!   rule order. A job with fewer than two miner outputs is left as it is.
//! - `no-root`: the `GHNP` ledger commitment output is left out.
//! - `overpay`: 50,000 sats move from the treasury to the first miner output, so one payee is paid
//!   more than the ledger owes it while treasury plus miners still make the subsidy.
//!
//! Anything else, or unset, changes nothing.

use std::sync::OnceLock;

use ghost_common::canonical_payout::CoinbaseOutput;
use tracing::warn;

/// What a fee-skimming node takes from each coinbase.
pub const SKIM_SATS: u64 = 100_000;

/// What an overpaying node adds to its first payee.
pub const OVERPAY_SATS: u64 = 50_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    WrongTreasury,
    FeeSkim,
    PayeeOrder,
    NoRoot,
    Overpay,
}

fn fault() -> Fault {
    static FAULT: OnceLock<Fault> = OnceLock::new();
    *FAULT.get_or_init(|| {
        let f = parse(std::env::var("GHOST_NP_FAULT").ok().as_deref());
        if f != Fault::None {
            warn!(fault = ?f, "NODE_POOL_FAULT: this pool_sv2 builds HOSTILE coinbases (test build)");
        }
        f
    })
}

fn parse(v: Option<&str>) -> Fault {
    match v {
        Some("wrong-treasury") => Fault::WrongTreasury,
        Some("fee-skim") => Fault::FeeSkim,
        Some("payee-order") => Fault::PayeeOrder,
        Some("no-root") => Fault::NoRoot,
        Some("overpay") => Fault::Overpay,
        _ => Fault::None,
    }
}

/// The script a wrong-treasury node pays instead of the treasury.
pub fn hostile_treasury() -> Vec<u8> {
    let mut s = vec![0x51, 0x20];
    s.extend_from_slice(&[0x66; 32]);
    s
}

/// Apply the configured fault to a job's full output list (treasury, miners, optional finder,
/// the `GHNP` commitment, the witness commitment), `finder` being the fee script.
pub fn apply(outs: Vec<CoinbaseOutput>, finder: &[u8]) -> Vec<CoinbaseOutput> {
    apply_fault(fault(), outs, finder)
}

fn apply_fault(f: Fault, mut outs: Vec<CoinbaseOutput>, finder: &[u8]) -> Vec<CoinbaseOutput> {
    if outs.len() < 3 {
        return outs;
    }
    // Miner outputs: after the treasury, up to the finder (if any) before the commitments.
    let commit = outs.len() - 2;
    let miners_end = if commit > 1 && outs[commit - 1].1 == finder {
        commit - 1
    } else {
        commit
    };
    match f {
        Fault::None => {}
        Fault::WrongTreasury => outs[0].1 = hostile_treasury(),
        Fault::PayeeOrder => {
            if miners_end >= 3 {
                outs.swap(1, 2);
            }
        }
        Fault::NoRoot => {
            outs.remove(commit);
        }
        Fault::Overpay => {
            if miners_end >= 2 {
                let more = outs[0].0.min(OVERPAY_SATS);
                outs[0].0 -= more;
                outs[1].0 += more;
            }
        }
        Fault::FeeSkim => {
            let skim = outs[0].0.min(SKIM_SATS);
            outs[0].0 -= skim;
            let at = outs.len() - 2;
            if outs[at - 1].1 == finder {
                outs[at - 1].0 += skim;
            } else {
                outs.insert(at, (skim, finder.to_vec()));
            }
        }
    }
    outs
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Treasury, two miners, the finder, the commitments.
    fn two_miners() -> Vec<CoinbaseOutput> {
        vec![
            (1_000_000, vec![0x51]),
            (5_000, vec![0x52]),
            (7_000, vec![0x54]),
            (3, vec![0x53]),
            (0, vec![0x6a, 0x01]),
            (0, vec![0x6a, 0x02]),
        ]
    }

    #[test]
    fn the_phase_3_faults_change_only_what_they_name() {
        let f = [0x53];
        let o = apply_fault(Fault::PayeeOrder, two_miners(), &f);
        assert_eq!(
            (o[1].clone(), o[2].clone()),
            (two_miners()[2].clone(), two_miners()[1].clone())
        );
        assert_eq!(o[3..], two_miners()[3..]);
        // One miner output, or none: nothing to reorder, so the job stays honest.
        assert_eq!(apply_fault(Fault::PayeeOrder, outs(), &f), outs());
        let mut one = two_miners();
        one.remove(2);
        assert_eq!(apply_fault(Fault::PayeeOrder, one.clone(), &f), one);

        let o = apply_fault(Fault::NoRoot, two_miners(), &f);
        assert_eq!(o.len(), 5);
        assert_eq!(o[..4], two_miners()[..4]);
        assert_eq!(o[4], (0, vec![0x6a, 0x02]));

        let o = apply_fault(Fault::Overpay, two_miners(), &f);
        assert_eq!(o[0].0, 1_000_000 - OVERPAY_SATS);
        assert_eq!(o[1], (5_000 + OVERPAY_SATS, vec![0x52]));
        assert_eq!(o[2..], two_miners()[2..]);
        let sum = |v: &[CoinbaseOutput]| v.iter().map(|x| x.0).sum::<u64>();
        assert_eq!(sum(&o), sum(&two_miners()));
        // No miner output: nobody to overpay.
        let bare = vec![
            two_miners()[0].clone(),
            two_miners()[4].clone(),
            two_miners()[5].clone(),
        ];
        assert_eq!(apply_fault(Fault::Overpay, bare.clone(), &f), bare);
    }

    fn outs() -> Vec<CoinbaseOutput> {
        vec![
            (1_000_000, vec![0x51]),
            (5_000_000, vec![0x52]),
            (0, vec![0x6a, 0x01]),
            (0, vec![0x6a, 0x02]),
        ]
    }

    #[test]
    fn faults_change_only_what_they_name() {
        assert_eq!(apply_fault(Fault::None, outs(), &[0x53]), outs());
        let w = apply_fault(Fault::WrongTreasury, outs(), &[0x53]);
        assert_eq!(w[0], (1_000_000, hostile_treasury()));
        assert_eq!(w[1..], outs()[1..]);
        let s = apply_fault(Fault::FeeSkim, outs(), &[0x53]);
        assert_eq!(s.len(), 5);
        assert_eq!(s[0].0, 1_000_000 - SKIM_SATS);
        assert_eq!(s[2], (SKIM_SATS, vec![0x53]));
        assert_eq!(s.iter().map(|o| o.0).sum::<u64>(), 6_000_000);
        assert_eq!(parse(Some("fee-skim")), Fault::FeeSkim);
        assert_eq!(parse(Some("payee-order")), Fault::PayeeOrder);
        assert_eq!(parse(Some("no-root")), Fault::NoRoot);
        assert_eq!(parse(Some("overpay")), Fault::Overpay);
        assert_eq!(parse(Some("other")), Fault::None);
        assert_eq!(parse(None), Fault::None);
    }
}
