//! The solo check of one job: does its coinbase pay the miner and the treasury, and nothing else.
//!
//! A Ghost Solo coinbase pays the treasury exactly `subsidy / 200`, then the miner's own payout
//! script everything else (`subsidy - subsidy / 200 + fees`), then at most a witness commitment
//! ([`ghost_common::solo::check_solo_outputs`]). The height, and with it the subsidy, is read from
//! the coinbase's own BIP34 push. The auditor cannot know the template's fees, so it checks that
//! everything above the treasury's cut goes to the miner and reports the fees that implies.

use bitcoin::Transaction;
use serde::Serialize;

use ghost_common::coinbase_tags::bip34_height_from;
use ghost_common::solo::{check_solo_outputs, CoinbaseOutput, SoloNetwork};

use crate::job::Job;

/// The outcome of one job's check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// The coinbase follows the solo rule for this miner.
    Pass,
    /// It does not.
    Fail,
    /// It could not be judged (an SV2 standard job no extended job could rebuild).
    Unchecked,
}

/// One job, judged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JobReport {
    /// The job id the node gave it (`std-`/`ext-` prefixed over SV2).
    pub job_id: String,
    /// `pass`, `fail` or `unchecked`.
    pub verdict: Verdict,
    /// Why it failed, in plain words.
    pub reason: Option<String>,
    /// The block height the coinbase commits (BIP34).
    pub height: Option<u64>,
    /// Sats to the treasury.
    pub treasury_sats: Option<u64>,
    /// Sats to the miner.
    pub miner_sats: Option<u64>,
    /// The fees the miner's output implies.
    pub fees_sats: Option<u64>,
    /// The coinbase's size, bytes.
    pub coinbase_bytes: usize,
}

impl JobReport {
    /// A job that fails for `why`.
    pub fn fail(
        job_id: &str,
        coinbase_bytes: usize,
        height: Option<u64>,
        why: String,
    ) -> JobReport {
        Self::not_passed(Verdict::Fail, job_id, coinbase_bytes, height, why)
    }

    /// A job that could not be judged, for `why`.
    pub fn unchecked(job_id: &str, why: String) -> JobReport {
        Self::not_passed(Verdict::Unchecked, job_id, 0, None, why)
    }

    fn not_passed(
        verdict: Verdict,
        job_id: &str,
        coinbase_bytes: usize,
        height: Option<u64>,
        why: String,
    ) -> JobReport {
        JobReport {
            job_id: job_id.to_string(),
            verdict,
            reason: Some(why),
            height,
            treasury_sats: None,
            miner_sats: None,
            fees_sats: None,
            coinbase_bytes,
        }
    }
}

/// The outputs of a coinbase as `(sats, script)`.
pub fn outputs_of(tx: &Transaction) -> Vec<CoinbaseOutput> {
    tx.output
        .iter()
        .map(|o| (o.value.to_sat(), o.script_pubkey.to_bytes()))
        .collect()
}

/// Judge one coinbase for the miner paid by `payee` on `network`.
pub fn audit_coinbase(
    job_id: &str,
    coinbase: &Transaction,
    coinbase_bytes: usize,
    payee: &[u8],
    network: SoloNetwork,
) -> JobReport {
    let Some(input) = coinbase.input.first() else {
        return JobReport::fail(
            job_id,
            coinbase_bytes,
            None,
            "the coinbase has no input".into(),
        );
    };
    let Some((height, _)) = bip34_height_from(input.script_sig.as_bytes()) else {
        return JobReport::fail(
            job_id,
            coinbase_bytes,
            None,
            "the coinbase scriptSig carries no BIP34 height".into(),
        );
    };
    let Ok(h) = u32::try_from(height) else {
        return JobReport::fail(
            job_id,
            coinbase_bytes,
            Some(height),
            "the BIP34 height is out of range".into(),
        );
    };
    match check_solo_outputs(&outputs_of(coinbase), h, network.halving(), payee, None) {
        Ok(p) => JobReport {
            job_id: job_id.to_string(),
            verdict: Verdict::Pass,
            reason: None,
            height: Some(height),
            treasury_sats: Some(p.treasury),
            miner_sats: Some(p.miner),
            fees_sats: Some(p.fees),
            coinbase_bytes,
        },
        Err(e) => JobReport::fail(job_id, coinbase_bytes, Some(height), e),
    }
}

/// Judge one job for the miner paid by `payee` on `network`.
pub fn audit_job(job: &Job, payee: &[u8], network: SoloNetwork) -> JobReport {
    audit_coinbase(
        &job.job_id,
        &job.coinbase,
        job.coinbase_bytes,
        payee,
        network,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};
    use ghost_common::coinbase_tags::bip34_height_push;
    use ghost_common::solo::{solo_outputs, Halving};

    const PAYEE: [u8; 22] = [
        0x00, 0x14, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    ];

    fn coinbase(height: u64, outs: &[CoinbaseOutput]) -> Transaction {
        let mut sig = bip34_height_push(height);
        sig.extend([0x04, 1, 2, 3, 4]);
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(sig),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: outs
                .iter()
                .map(|(v, s)| TxOut {
                    value: Amount::from_sat(*v),
                    script_pubkey: ScriptBuf::from_bytes(s.clone()),
                })
                .collect(),
        }
    }

    #[test]
    fn a_solo_coinbase_passes_and_reports_its_split() {
        let [t, m] = solo_outputs(960_000, Halving::MAINNET, 5_000, &PAYEE);
        let tx = coinbase(960_000, &[t, m]);
        let r = audit_coinbase("j", &tx, 200, &PAYEE, SoloNetwork::Mainnet);
        assert_eq!(r.verdict, Verdict::Pass, "{r:?}");
        assert_eq!(r.treasury_sats, Some(1_562_500));
        assert_eq!(r.miner_sats, Some(312_500_000 - 1_562_500 + 5_000));
        assert_eq!(r.fees_sats, Some(5_000));
        assert_eq!(r.height, Some(960_000));
    }

    #[test]
    fn a_short_treasury_another_payee_or_the_wrong_network_fails() {
        let [t, m] = solo_outputs(960_000, Halving::MAINNET, 0, &PAYEE);
        let short = coinbase(960_000, &[(t.0 - 1, t.1.clone()), (m.0 + 1, m.1.clone())]);
        let r = audit_coinbase("j", &short, 200, &PAYEE, SoloNetwork::Mainnet);
        assert_eq!(r.verdict, Verdict::Fail);
        assert!(r.reason.unwrap().contains("treasury"));
        let mut other = PAYEE;
        other[3] = 0;
        let tx = coinbase(960_000, &[t.clone(), m.clone()]);
        assert_eq!(
            audit_coinbase("j", &tx, 200, &other, SoloNetwork::Mainnet).verdict,
            Verdict::Fail
        );
        // Regtest has halved many times by height 960,000: the subsidy differs.
        assert_eq!(
            audit_coinbase("j", &tx, 200, &PAYEE, SoloNetwork::Regtest).verdict,
            Verdict::Fail
        );
    }
}
