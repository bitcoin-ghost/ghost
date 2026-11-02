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
//| FILE: check.rs                                                                                                       |
//|======================================================================================================================|

//! The checks: does this job pay the canonical coinbase, and does its tag credit this miner?
//!
//! A job passes when all of these hold, in this order (the first that fails names the verdict;
//! the names are [`crate::check::FailReason`]'s):
//!
//! 1. The coinbase is a coinbase with a scriptSig of 2 to 100 bytes, and its BIP34 height is one
//!    above its `prev_hash`'s (`MalformedCoinbase`, `WrongHeight`).
//! 2. Its `GHNT` tag opens to this miner's payout script: some stamp the node discloses
//!    (`node_id`, `parent_anchor`, `batch_root`), with some tier and slot class, hashes to the tag
//!    together with the miner's own script, and the `GHPP` slot carries that stamp's
//!    `parent_anchor[..16]` (`TagNotBinding`). The tag is a 20-byte hash, so a node cannot find
//!    a stamp that opens it to the miner unless the job really credits the miner.
//! 3. The committed tier is one the miner's shares meet at the difficulty the node set
//!    (`TierAboveDifficulty`); a tier above it voids the miner's network shares.
//! 4. The outputs are exactly the canonical outputs for that height, parent anchor and slot class
//!    on the share chain the auditor synced itself (`share_commit::check_outputs`). When they are
//!    not, the difference is named: `WrongTreasury`, `WrongSlotClass`, `RelabelledPayee`,
//!    `InflatedBalance`, `FeeSkim`, `WrongLedgerRoot`, or `OutputsNotCanonical` for anything
//!    else.
//!
//! A job the auditor cannot judge (its `prev_hash` or parent anchor is not known yet) is
//! UNCHECKED, never PASS.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::Transaction;
use serde::Serialize;
use sha2::{Digest, Sha256};

use ghost_common::canonical_payout::{
    build_outputs, ledger_root_of, subsidy, table_root, CoinbaseOutput, Table,
};
use ghost_common::coinbase_tags::{extract_node_tag, extract_payout_tag};
use ghost_common::node_pool_constants::{
    PARENT_ANCHOR_TAG_LEN, SHARE_TAG_DOMAIN, SHARE_TAG_LEN, SLOT_CLASSES,
    TREASURY_SCRIPT_PLACEHOLDER, T_NET_FLOOR,
};
use ghost_common::share_commit::check_outputs;
use ghost_np_relay::wire::JobStamps;

use crate::job::{display_hex, Job};

/// What the auditor needs from the share chain and Bitcoin, obtained by the auditor itself.
#[async_trait]
pub trait ShareChainData: Send + Sync {
    /// Height of Bitcoin block `hash` (internal byte order), if known.
    async fn block_height(&self, hash: &[u8; 32]) -> Option<u32>;
    /// The table a job of height `h` on Bitcoin block `prev`, built on anchor `parent`, must pay.
    /// `None` while the parent anchor or a Bitcoin block on the way is not held.
    async fn table(&self, parent: &[u8; 32], h: u32, prev: &[u8; 32]) -> Option<Arc<Table>>;
}

/// The overall verdict on one job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    /// Every check passed.
    Pass,
    /// A check failed; see the reason.
    Fail,
    /// The job could not be judged yet. Not a pass.
    Unchecked,
}

/// Why a job failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailReason {
    /// Not a coinbase, a scriptSig outside 2..=100 bytes, no `GHPP` slot, or outputs that do
    /// not end in the ledger and witness commitments.
    MalformedCoinbase,
    /// The BIP34 height is not one above the job's `prev_hash`.
    WrongHeight,
    /// The share tag does not commit to the miner's payout script: the job credits someone else,
    /// or the node will not disclose what it commits to.
    TagNotBinding,
    /// The tag commits a tier above the difficulty the node set: the miner's shares fail it.
    TierAboveDifficulty,
    /// The first output does not pay the treasury script.
    WrongTreasury,
    /// The treasury and miners get less than the subsidy: value moved to the finder or
    /// elsewhere.
    FeeSkim,
    /// A payee the ledger owes is replaced by another script carrying its amount.
    RelabelledPayee,
    /// A script is paid more than the ledger owes it, or paid when the ledger owes it nothing.
    InflatedBalance,
    /// The outputs are canonical, but for another slot class than the tag commits.
    WrongSlotClass,
    /// Payees and amounts are canonical but the `GHNP` output commits another table.
    WrongLedgerRoot,
    /// Any other difference from the canonical outputs (order, a dropped payee, the treasury
    /// overpaid, a zero-value finder).
    OutputsNotCanonical,
    /// An SV2 standard job, which shows only its merkle root: no canonical coinbase crediting
    /// the miner, under any stamp the node discloses, slot class or tier, rebuilt from the node's
    /// own extended job on the same template, hashes to it ([`crate::sv2::rebuild_standard`]).
    /// Which part is wrong (tag, outputs) cannot be told from a hash.
    StandardJobNotCanonical,
}

impl FailReason {
    /// A short plain-words label.
    pub fn label(self) -> &'static str {
        match self {
            FailReason::MalformedCoinbase => "malformed coinbase",
            FailReason::WrongHeight => "wrong height",
            FailReason::TagNotBinding => "tag not committing to you",
            FailReason::TierAboveDifficulty => "tier above your difficulty",
            FailReason::WrongTreasury => "wrong treasury",
            FailReason::FeeSkim => "skimmed from the outputs",
            FailReason::RelabelledPayee => "relabelled payee",
            FailReason::InflatedBalance => "inflated balance",
            FailReason::WrongSlotClass => "wrong slot class",
            FailReason::WrongLedgerRoot => "wrong ledger root",
            FailReason::OutputsNotCanonical => "outputs not canonical",
            FailReason::StandardJobNotCanonical => "standard job not canonical",
        }
    }
}

/// The verdict on one job, with what was read from it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct JobReport {
    /// The node's job id.
    pub job_id: String,
    /// PASS, FAIL or UNCHECKED.
    pub verdict: Verdict,
    /// Why it failed, for a FAIL.
    pub reason: Option<FailReason>,
    /// What was found, in words.
    pub detail: String,
    /// Job height, once known.
    pub height: Option<u32>,
    /// `prev_hash`, display byte order.
    pub prev_hash: String,
    /// The parent anchor the tag opened with, hex.
    pub parent_anchor: Option<String>,
    /// The slot class the tag commits.
    pub slot_class: Option<u16>,
    /// The tier the tag commits.
    pub tier: Option<u8>,
    /// Outputs in the coinbase.
    pub outputs: usize,
    /// Coinbase size in bytes.
    pub coinbase_bytes: usize,
}

/// What a tag opened to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenedTag {
    /// The node id.
    pub node_id: [u8; 32],
    /// The anchor the job builds on.
    pub parent_anchor: [u8; 32],
    /// Its batch root.
    pub batch_root: [u8; 32],
    /// The committed tier.
    pub tier: u8,
    /// The committed slot class.
    pub slot_class: u16,
}

/// Find the stamp, tier and slot class under which `tag` commits to `payee`. Only stamps whose
/// `parent_anchor` starts with `parent_prefix` (the `GHPP` slot) are tried; every tier and every
/// slot class is, since both are cheap to enumerate (256 x 6 hashes a stamp).
pub fn open_tag(
    tag: &[u8; SHARE_TAG_LEN],
    parent_prefix: &[u8; PARENT_ANCHOR_TAG_LEN],
    payee: &[u8],
    stamps: &JobStamps,
) -> Option<OpenedTag> {
    let payee_hash: [u8; 32] = Sha256::digest(payee).into();
    for s in stamps
        .recent
        .iter()
        .filter(|s| &s.parent_anchor[..PARENT_ANCHOR_TAG_LEN] == parent_prefix)
    {
        for tier in 0..=u8::MAX {
            for class in SLOT_CLASSES {
                let mut h = Sha256::new();
                h.update(SHARE_TAG_DOMAIN);
                h.update(stamps.node_id);
                h.update([tier]);
                h.update(class.to_le_bytes());
                h.update(payee_hash);
                h.update(s.parent_anchor);
                h.update(s.batch_root);
                let d: [u8; 32] = h.finalize().into();
                if &d[..SHARE_TAG_LEN] == tag {
                    return Some(OpenedTag {
                        node_id: stamps.node_id,
                        parent_anchor: s.parent_anchor,
                        batch_root: s.batch_root,
                        tier,
                        slot_class: class,
                    });
                }
            }
        }
    }
    None
}

fn short(script: &[u8]) -> String {
    let h = hex::encode(script);
    if h.len() > 20 {
        format!("{}…", &h[..20])
    } else {
        h
    }
}

fn is_witness_commitment(s: &[u8]) -> bool {
    s.len() == 38 && s.starts_with(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed])
}

/// Compare a coinbase's outputs with the canonical ones for `slot_class` and name the
/// difference. `Ok` exactly when `share_commit::check_outputs` accepts them.
pub fn classify_outputs(
    coinbase: &Transaction,
    table: &Table,
    h: u32,
    slot_class: u16,
) -> Result<(), (FailReason, String)> {
    let actual: Vec<CoinbaseOutput> = coinbase
        .output
        .iter()
        .map(|o| (o.value.to_sat(), o.script_pubkey.to_bytes()))
        .collect();
    let n = actual.len();
    if n < 3 || !is_witness_commitment(&actual[n - 1].1) {
        return Err((
            FailReason::MalformedCoinbase,
            "the last output is not a witness commitment".into(),
        ));
    }
    let Some(root) = ledger_root_of(&actual) else {
        return Err((
            FailReason::MalformedCoinbase,
            "no GHNP ledger commitment before the witness commitment".into(),
        ));
    };
    if actual[0].1 != TREASURY_SCRIPT_PLACEHOLDER {
        return Err((
            FailReason::WrongTreasury,
            format!(
                "the first output pays {}, not the treasury {}",
                hex::encode(&actual[0].1),
                hex::encode(TREASURY_SCRIPT_PLACEHOLDER)
            ),
        ));
    }
    if check_outputs(coinbase, table, h, slot_class as usize).is_ok() {
        return Ok(());
    }
    if let Some(c) = SLOT_CLASSES
        .iter()
        .find(|c| **c != slot_class && check_outputs(coinbase, table, h, **c as usize).is_ok())
    {
        return Err((
            FailReason::WrongSlotClass,
            format!(
                "the tag commits {slot_class} miner outputs but the coinbase is canonical for {c}"
            ),
        ));
    }
    let pay = build_outputs(h, table, slot_class as usize)
        .map_err(|e| (FailReason::OutputsNotCanonical, format!("payout rule: {e}")))?;
    let body = &actual[1..n - 2];
    // The finder is laid out last. An unowed script there is read as the finder, so a payee
    // dropped or added in the middle is still named for what it is.
    let finder_last = body
        .last()
        .is_some_and(|(_, s)| !pay.outputs.iter().any(|(o, _)| o == s));
    let (miners, finder) = if finder_last || body.len() > pay.outputs.len() {
        (&body[..body.len() - 1], body.last())
    } else {
        (body, None)
    };
    let mut paid: BTreeMap<&[u8], u64> = BTreeMap::new();
    for (v, s) in miners {
        if paid.insert(s.as_slice(), *v).is_some() {
            return Err((
                FailReason::OutputsNotCanonical,
                format!("{} is paid twice", short(s)),
            ));
        }
    }
    let owed: BTreeMap<&[u8], u64> = pay
        .outputs
        .iter()
        .map(|(s, v)| (s.as_slice(), *v))
        .collect();
    let missing: Vec<(&[u8], u64)> = owed
        .iter()
        .filter(|(s, _)| !paid.contains_key(*s))
        .map(|(s, v)| (*s, *v))
        .collect();
    let extra: Vec<(&[u8], u64)> = paid
        .iter()
        .filter(|(s, _)| !owed.contains_key(*s))
        .map(|(s, v)| (*s, *v))
        .collect();
    for (e, v) in &extra {
        if let Some((m, _)) = missing.iter().find(|(_, mv)| mv == v) {
            return Err((
                FailReason::RelabelledPayee,
                format!(
                    "pays {} {v} sats where the ledger owes that output to {}",
                    short(e),
                    short(m)
                ),
            ));
        }
    }
    if let Some((e, v)) = extra.first() {
        return Err((
            FailReason::InflatedBalance,
            format!(
                "pays {} {v} sats; the canonical outputs pay it nothing",
                short(e)
            ),
        ));
    }
    if let Some((s, a, w)) = paid
        .iter()
        .filter_map(|(s, a)| owed.get(s).map(|w| (s, a, w)))
        .find(|(_, a, w)| a > w)
    {
        return Err((
            FailReason::InflatedBalance,
            format!("pays {} {a} sats; canonical is {w}", short(s)),
        ));
    }
    let s = subsidy(h);
    let core = actual[0].0 + miners.iter().map(|(v, _)| *v).sum::<u64>();
    if core < s {
        let to = finder.map_or("nowhere in the outputs".to_string(), |f| short(&f.1));
        return Err((
            FailReason::FeeSkim,
            format!(
                "the treasury and miners get {core} of the {s}-sat subsidy; {} sats go to {to}",
                s - core
            ),
        ));
    }
    if let Some((m, v)) = missing.first() {
        return Err((
            FailReason::OutputsNotCanonical,
            format!("drops {} (owed {v} sats in this block)", short(m)),
        ));
    }
    if actual[0].0 != pay.treasury {
        return Err((
            FailReason::OutputsNotCanonical,
            format!(
                "the treasury gets {} sats; canonical is {}",
                actual[0].0, pay.treasury
            ),
        ));
    }
    let order_ok = miners
        .iter()
        .map(|(_, s)| s.as_slice())
        .eq(pay.outputs.iter().map(|(s, _)| s.as_slice()));
    if !order_ok {
        return Err((
            FailReason::OutputsNotCanonical,
            "the miner outputs are not in rule order".into(),
        ));
    }
    if finder.is_some_and(|f| f.0 == 0) {
        return Err((
            FailReason::OutputsNotCanonical,
            "a zero-value finder output".into(),
        ));
    }
    let want = table_root(table);
    if root != want {
        return Err((
            FailReason::WrongLedgerRoot,
            format!(
                "commits ledger root {}; the table's is {}",
                hex::encode(root),
                hex::encode(want)
            ),
        ));
    }
    Err((
        FailReason::OutputsNotCanonical,
        "the outputs are not the canonical outputs".into(),
    ))
}

/// The tier a miner's shares meet at difficulty `d`: `floor(log2 d)`, with a hair of slack for
/// a tier target's difficulty printed as a float just below its power of two.
fn tier_at(d: f64) -> f64 {
    (d.max(1.0) * (1.0 + 1e-9)).log2().floor()
}

/// Judge one job. `stamps` is what the node disclosed (`None`: it would not say).
pub async fn audit_job(
    job: &Job,
    payee: &[u8],
    stamps: Option<&JobStamps>,
    data: &dyn ShareChainData,
) -> JobReport {
    let mut r = JobReport {
        job_id: job.job_id.clone(),
        verdict: Verdict::Unchecked,
        reason: None,
        detail: String::new(),
        height: None,
        prev_hash: display_hex(&job.prev_hash),
        parent_anchor: None,
        slot_class: None,
        tier: None,
        outputs: job.coinbase.output.len(),
        coinbase_bytes: job.coinbase_bytes,
    };
    let fail = |mut r: JobReport, why: FailReason, detail: String| {
        r.verdict = Verdict::Fail;
        r.reason = Some(why);
        r.detail = detail;
        r
    };
    let cb = &job.coinbase;
    if !cb.is_coinbase() || cb.input.len() != 1 {
        return fail(
            r,
            FailReason::MalformedCoinbase,
            "not a coinbase transaction".into(),
        );
    }
    let sig = cb.input[0].script_sig.as_bytes();
    if !(2..=100).contains(&sig.len()) {
        return fail(
            r,
            FailReason::MalformedCoinbase,
            format!("a {}-byte scriptSig (2 to 100 allowed)", sig.len()),
        );
    }
    let Some(prev_height) = data.block_height(&job.prev_hash).await else {
        r.detail = "the job's prev_hash is not a Bitcoin block this auditor knows yet".into();
        return r;
    };
    let h = prev_height + 1;
    r.height = Some(h);
    let bip34 = bitcoin::script::Builder::new()
        .push_int(h as i64)
        .into_bytes();
    if !sig.starts_with(&bip34) {
        return fail(
            r,
            FailReason::WrongHeight,
            format!("the scriptSig does not start with height {h} (prev_hash is at {prev_height})"),
        );
    }
    let Some(prefix) = extract_payout_tag(sig) else {
        return fail(
            r,
            FailReason::MalformedCoinbase,
            "no GHPP parent-anchor slot in the scriptSig".into(),
        );
    };
    let Some(tag) = extract_node_tag(sig) else {
        return fail(
            r,
            FailReason::TagNotBinding,
            "no GHNT share tag in the scriptSig".into(),
        );
    };
    let Some(stamps) = stamps else {
        return fail(
            r,
            FailReason::TagNotBinding,
            "the node does not disclose its job stamps, so nothing shows the tag credits you"
                .into(),
        );
    };
    let Some(open) = open_tag(&tag, &prefix, payee, stamps) else {
        return fail(
            r,
            FailReason::TagNotBinding,
            format!(
                "the tag {} does not commit to your payout script {} under any of the node's {} \
                 recent stamps: this job's shares credit someone else",
                hex::encode(tag),
                hex::encode(payee),
                stamps.recent.len()
            ),
        );
    };
    r.parent_anchor = Some(hex::encode(open.parent_anchor));
    r.slot_class = Some(open.slot_class);
    r.tier = Some(open.tier);
    if let Some(d) = job.difficulty {
        let meets = tier_at(d);
        if (open.tier as f64) > meets && open.tier > T_NET_FLOOR {
            return fail(
                r,
                FailReason::TierAboveDifficulty,
                format!(
                    "the tag commits tier {} but your difficulty {d} only meets tier {meets}: \
                     your network shares would fail it",
                    open.tier
                ),
            );
        }
    }
    let Some(table) = data.table(&open.parent_anchor, h, &job.prev_hash).await else {
        r.detail = format!(
            "the share chain this auditor synced does not hold anchor {} (or a Bitcoin block \
             below the job) yet",
            hex::encode(open.parent_anchor)
        );
        return r;
    };
    match classify_outputs(cb, &table, h, open.slot_class) {
        Ok(()) => {
            r.verdict = Verdict::Pass;
            r.detail = format!(
                "pays the canonical coinbase for {} miner outputs at height {h} and credits you",
                open.slot_class
            );
            r
        }
        Err((why, detail)) => fail(r, why, detail),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};
    use ghost_common::canonical_payout::{coinbase_outputs, Balance};
    use ghost_common::coinbase_tags::{encode_node_tag, encode_payout_tag};
    use ghost_common::node_pool_constants::FACE_PER_SAT;
    use ghost_common::share_commit::ShareTagPreimage;
    use ghost_np_relay::relay::JobAnchor;
    use std::collections::HashMap;

    pub const H: u32 = 974_500;
    const PREV: [u8; 32] = [0x55; 32];

    pub fn p2tr(tag: &str) -> Vec<u8> {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&Sha256::digest(tag.as_bytes()));
        s
    }

    pub fn table() -> Table {
        (0..30u32)
            .map(|i| {
                let b = Balance {
                    owed: (2_000 + 100 * i as i128) * FACE_PER_SAT,
                    queue_since: Some(900_000 + i),
                };
                (p2tr(&format!("m{i}")), b)
            })
            .collect()
    }

    pub struct MemData {
        pub heights: HashMap<[u8; 32], u32>,
        pub table: Option<Arc<Table>>,
    }

    #[async_trait]
    impl ShareChainData for MemData {
        async fn block_height(&self, hash: &[u8; 32]) -> Option<u32> {
            self.heights.get(hash).copied()
        }
        async fn table(&self, _: &[u8; 32], _: u32, _: &[u8; 32]) -> Option<Arc<Table>> {
            self.table.clone()
        }
    }

    /// A job being built; tests change one field.
    struct Fx {
        table: Table,
        payee: Vec<u8>,
        stamps: JobStamps,
        tag: ShareTagPreimage,
        finder_value: u64,
        outputs: Option<Vec<CoinbaseOutput>>,
        bip34: u32,
        difficulty: Option<f64>,
    }

    impl Fx {
        fn new() -> Fx {
            let stamp = JobAnchor {
                parent_anchor: [2; 32],
                batch_root: [3; 32],
            };
            let stamps = JobStamps {
                node_id: [1; 32],
                recent: vec![
                    JobAnchor {
                        parent_anchor: [9; 32],
                        batch_root: [9; 32],
                    },
                    stamp,
                ],
            };
            Fx {
                table: table(),
                payee: p2tr("me"),
                tag: ShareTagPreimage {
                    node_id: [1; 32],
                    tier: 12,
                    slot_class: 9,
                    payee_script: p2tr("me"),
                    parent_anchor: stamp.parent_anchor,
                    batch_root: stamp.batch_root,
                },
                stamps,
                finder_value: 50_000,
                outputs: None,
                bip34: H,
                difficulty: Some(4096.0),
            }
        }

        fn honest_outputs(&self) -> Vec<CoinbaseOutput> {
            self.outputs_on(&self.table, self.tag.slot_class)
        }

        fn outputs_on(&self, t: &Table, class: u16) -> Vec<CoinbaseOutput> {
            coinbase_outputs(
                H,
                t,
                class as usize,
                &p2tr("finder"),
                self.finder_value,
                &[7; 32],
            )
            .unwrap()
            .0
        }

        fn job(&self) -> Job {
            let mut sig = bitcoin::script::Builder::new()
                .push_int(self.bip34 as i64)
                .into_bytes();
            sig.extend(encode_payout_tag(&self.tag.parent_anchor_tag()));
            sig.extend(encode_node_tag(&self.tag.tag()));
            sig.extend([0x08, 0, 0, 0, 0, 0, 0, 0, 0]);
            let coinbase = Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::from_bytes(sig),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                }],
                output: self
                    .outputs
                    .clone()
                    .unwrap_or_else(|| self.honest_outputs())
                    .into_iter()
                    .map(|(v, s)| TxOut {
                        value: Amount::from_sat(v),
                        script_pubkey: ScriptBuf::from_bytes(s),
                    })
                    .collect(),
            };
            Job {
                job_id: "1".into(),
                prev_hash: PREV,
                coinbase_bytes: bitcoin::consensus::serialize(&coinbase).len(),
                coinbase,
                merkle_branch: vec![],
                version: 0x2000_0000,
                bits: 0x1702_1be5,
                time: 1_800_000_000,
                difficulty: self.difficulty,
            }
        }

        fn data(&self) -> MemData {
            MemData {
                heights: [(PREV, H - 1)].into_iter().collect(),
                table: Some(Arc::new(self.table.clone())),
            }
        }

        async fn judge(&self) -> JobReport {
            audit_job(&self.job(), &self.payee, Some(&self.stamps), &self.data()).await
        }

        async fn reason(&self) -> Option<FailReason> {
            let r = self.judge().await;
            assert_eq!(
                r.verdict == Verdict::Fail,
                r.reason.is_some(),
                "{}",
                r.detail
            );
            r.reason
        }
    }

    #[tokio::test]
    async fn honest_jobs_pass_for_every_class_with_and_without_a_finder() {
        for class in SLOT_CLASSES {
            for finder in [0u64, 1, 50_000] {
                let mut f = Fx::new();
                f.tag.slot_class = class;
                f.finder_value = finder;
                let r = f.judge().await;
                assert_eq!(r.verdict, Verdict::Pass, "class {class}: {}", r.detail);
                assert_eq!(r.slot_class, Some(class));
                assert_eq!(r.tier, Some(12));
                assert_eq!(r.height, Some(H));
                assert_eq!(r.parent_anchor, Some(hex::encode([2u8; 32])));
            }
        }
        // An empty table: the treasury takes the subsidy, and that is canonical too.
        let mut f = Fx::new();
        f.table = Table::new();
        assert_eq!(f.judge().await.verdict, Verdict::Pass);
    }

    #[test]
    fn the_tag_opens_only_to_its_own_payee_and_stamp() {
        let f = Fx::new();
        let tag = f.tag.tag();
        let prefix = f.tag.parent_anchor_tag();
        let o = open_tag(&tag, &prefix, &f.payee, &f.stamps).expect("opens");
        assert_eq!((o.tier, o.slot_class, o.batch_root), (12, 9, [3; 32]));
        assert!(open_tag(&tag, &prefix, &p2tr("thief"), &f.stamps).is_none());
        assert!(open_tag(&tag, &[9; 16], &f.payee, &f.stamps).is_none());
        let mut other = f.stamps.clone();
        other.node_id = [8; 32];
        assert!(open_tag(&tag, &prefix, &f.payee, &other).is_none());
        other = f.stamps.clone();
        other.recent.pop();
        assert!(open_tag(&tag, &prefix, &f.payee, &other).is_none());
    }

    #[tokio::test]
    async fn a_tag_crediting_someone_else_is_named() {
        let mut f = Fx::new();
        f.tag.payee_script = p2tr("the node");
        assert_eq!(f.reason().await, Some(FailReason::TagNotBinding));
        // No stamps disclosed: nothing shows the tag credits the miner.
        let f = Fx::new();
        let r = audit_job(&f.job(), &f.payee, None, &f.data()).await;
        assert_eq!(r.reason, Some(FailReason::TagNotBinding));
    }

    #[tokio::test]
    async fn a_tier_above_the_difficulty_is_named() {
        let mut f = Fx::new();
        f.tag.tier = 20;
        f.difficulty = Some(65_536.0);
        assert_eq!(f.reason().await, Some(FailReason::TierAboveDifficulty));
        f.difficulty = Some(1_048_576.0);
        assert_eq!(f.reason().await, None);
        f.difficulty = Some(1_048_575.999_999);
        assert_eq!(
            f.reason().await,
            None,
            "a float just below the power of two"
        );
        // The floor tier is committed whatever the difficulty; T_net is at least the floor.
        let mut f = Fx::new();
        f.tag.tier = T_NET_FLOOR;
        f.difficulty = Some(1.0);
        assert_eq!(f.reason().await, None);
    }

    #[tokio::test]
    async fn each_hostile_coinbase_gets_its_named_failure() {
        type Mutation = Box<dyn Fn(&Fx, &mut Vec<CoinbaseOutput>)>;
        let n_out = |o: &Vec<CoinbaseOutput>| o.len();
        let cases: Vec<(&str, Mutation, FailReason)> = vec![
            (
                "wrong treasury",
                Box::new(|_, o| o[0].1 = p2tr("not the treasury")),
                FailReason::WrongTreasury,
            ),
            (
                "fee skim from a miner",
                Box::new(move |_, o| {
                    let f = n_out(o) - 3;
                    o[1].0 -= 500;
                    o[f].0 += 500;
                }),
                FailReason::FeeSkim,
            ),
            (
                "fee skim from the treasury",
                Box::new(move |_, o| {
                    let f = n_out(o) - 3;
                    o[0].0 -= 5_000;
                    o[f].0 += 500;
                }),
                FailReason::FeeSkim,
            ),
            (
                "relabelled payee",
                Box::new(|_, o| o[2].1 = p2tr("the node")),
                FailReason::RelabelledPayee,
            ),
            (
                "inflated miner",
                Box::new(|_, o| {
                    o[1].0 += 5_000;
                    o[0].0 -= 5_000;
                }),
                FailReason::InflatedBalance,
            ),
            (
                "inflated balance in the node's table",
                Box::new(|f, o| {
                    let mut t = f.table.clone();
                    t.insert(
                        p2tr("the node"),
                        Balance {
                            owed: 9_000_000 * FACE_PER_SAT,
                            queue_since: Some(950_000),
                        },
                    );
                    *o = f.outputs_on(&t, f.tag.slot_class);
                }),
                FailReason::InflatedBalance,
            ),
            (
                "wrong slot class",
                Box::new(|f, o| *o = f.outputs_on(&f.table, 3)),
                FailReason::WrongSlotClass,
            ),
            (
                "wrong ledger root",
                Box::new(move |_, o| {
                    let c = n_out(o) - 2;
                    o[c].1[10] ^= 1;
                }),
                FailReason::WrongLedgerRoot,
            ),
            (
                "reordered miners",
                Box::new(|_, o| o.swap(1, 2)),
                FailReason::OutputsNotCanonical,
            ),
            (
                "dropped payee to the treasury",
                Box::new(|_, o| {
                    let v = o.remove(1).0;
                    o[0].0 += v;
                }),
                FailReason::OutputsNotCanonical,
            ),
            (
                "no witness commitment",
                Box::new(|_, o| {
                    o.pop();
                }),
                FailReason::MalformedCoinbase,
            ),
        ];
        for (name, mutate, want) in cases {
            let mut f = Fx::new();
            let mut o = f.honest_outputs();
            mutate(&f, &mut o);
            f.outputs = Some(o);
            let r = f.judge().await;
            assert_eq!(r.reason, Some(want), "{name}: {}", r.detail);
            assert_eq!(r.verdict, Verdict::Fail, "{name}");
        }
    }

    #[tokio::test]
    async fn a_wrong_height_fails_and_unknown_data_is_unchecked() {
        let mut f = Fx::new();
        f.bip34 = H + 1;
        assert_eq!(f.reason().await, Some(FailReason::WrongHeight));

        let f = Fx::new();
        let mut d = f.data();
        d.heights.clear();
        let r = audit_job(&f.job(), &f.payee, Some(&f.stamps), &d).await;
        assert_eq!((r.verdict, r.reason), (Verdict::Unchecked, None));
        let mut d = f.data();
        d.table = None;
        let r = audit_job(&f.job(), &f.payee, Some(&f.stamps), &d).await;
        assert_eq!((r.verdict, r.reason), (Verdict::Unchecked, None));
        assert_eq!(
            r.slot_class,
            Some(9),
            "the tag opened before the table was asked for"
        );
    }

    #[test]
    fn reason_codes_are_stable() {
        let codes: Vec<String> = [
            FailReason::MalformedCoinbase,
            FailReason::WrongHeight,
            FailReason::TagNotBinding,
            FailReason::TierAboveDifficulty,
            FailReason::WrongTreasury,
            FailReason::FeeSkim,
            FailReason::RelabelledPayee,
            FailReason::InflatedBalance,
            FailReason::WrongSlotClass,
            FailReason::WrongLedgerRoot,
            FailReason::OutputsNotCanonical,
            FailReason::StandardJobNotCanonical,
        ]
        .iter()
        .map(|r| {
            serde_json::to_value(r)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
        assert_eq!(
            codes,
            [
                "malformed_coinbase",
                "wrong_height",
                "tag_not_binding",
                "tier_above_difficulty",
                "wrong_treasury",
                "fee_skim",
                "relabelled_payee",
                "inflated_balance",
                "wrong_slot_class",
                "wrong_ledger_root",
                "outputs_not_canonical",
                "standard_job_not_canonical"
            ]
        );
        assert_eq!(
            serde_json::to_value(Verdict::Unchecked).unwrap(),
            "UNCHECKED"
        );
    }
}
