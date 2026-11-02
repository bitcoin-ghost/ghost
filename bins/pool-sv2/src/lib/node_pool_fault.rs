//! Test-only faults in the canonical coinbase, for the regtest harness's hostile node
//! (`scripts/regtest-node-pool`). Compiled only with the `np-fault-injection` feature, which no
//! release build enables; without it this module does not exist.
//!
//! `GHOST_NP_FAULT` picks the fault, read once:
//! - `wrong-treasury`: the first output pays a script that is not the treasury's.
//! - `fee-skim`: 100,000 sats move from the treasury to the finder, so treasury plus miners fall
//!   below the subsidy.
//!
//! Anything else, or unset, changes nothing.

use std::sync::OnceLock;

use ghost_common::canonical_payout::CoinbaseOutput;
use tracing::warn;

/// What a fee-skimming node takes from each coinbase.
pub const SKIM_SATS: u64 = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    None,
    WrongTreasury,
    FeeSkim,
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
    match f {
        Fault::None => {}
        Fault::WrongTreasury => outs[0].1 = hostile_treasury(),
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
        assert_eq!(parse(Some("other")), Fault::None);
        assert_eq!(parse(None), Fault::None);
    }
}
