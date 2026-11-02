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
//| FILE: share_commit.rs                                                                                                |
//|======================================================================================================================|

//! Share commitment and the pure share checks of spec 2.1.
//!
//! A node-pool share commits, in its coinbase scriptSig's `GHNT` push, to
//!
//! ```text
//! tag = sha256("GhostShare/v2" || node_id || tier || slot_class || sha256(payee_script)
//!              || parent_anchor || batch_root)[..20]
//! ```
//!
//! and its coinbase pays exactly the canonical outputs of the ledger snapshot it was built on.
//! [`verify_share`](crate::share_commit::verify_share) checks rules 1 to 5 from the share alone plus the chain-dependent facts the
//! caller resolves first and passes in as [`ShareContext`](crate::share_commit::ShareContext): the network tier, the including
//! anchor's `btc_height`, the height of the header's `prev_hash`, the expected bits, the time
//! bounds and the snapshot table. Rule 6 (ancestry) lives in `anchor_chain`.
//!
//! Pure: no I/O, no clock. Nothing here is wired into the running node.

use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::{CompactTarget, Transaction};
use sha2::{Digest, Sha256};

use crate::canonical_payout::{
    build_outputs, coinbase_outputs, share_face, Halving, PayoutError, Retirement, Table,
};
use crate::coinbase_tags::{extract_node_tag, extract_payout_tag};
use crate::node_pool_constants::{
    PARENT_ANCHOR_TAG_LEN, SHARE_HEIGHT_WINDOW, SHARE_TAG_DOMAIN, SHARE_TAG_LEN, SLOT_CLASSES,
};
use crate::node_pool_u256::U256;

/// The four payee script classes the ledger accepts (spec 2.1). P2PKH is excluded: each output
/// costs 4 sigops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayeeScriptClass {
    /// `OP_HASH160 <20> OP_EQUAL`, 23 bytes.
    P2sh,
    /// `OP_0 <20>`, 22 bytes.
    P2wpkh,
    /// `OP_0 <32>`, 34 bytes.
    P2wsh,
    /// `OP_1 <32>`, 34 bytes.
    P2tr,
}

/// Longest accepted payee script, in bytes (P2WSH and P2TR).
pub const MAX_PAYEE_SCRIPT_LEN: usize = 34;

/// The class of a payee script, or `None` if the ledger refuses it. Exact template match, as the
/// reference's `script_ok`.
pub fn payee_script_class(s: &[u8]) -> Option<PayeeScriptClass> {
    match (s.len(), s.first(), s.get(1)) {
        (23, Some(0xa9), Some(0x14)) if s[22] == 0x87 => Some(PayeeScriptClass::P2sh),
        (22, Some(0x00), Some(0x14)) => Some(PayeeScriptClass::P2wpkh),
        (34, Some(0x00), Some(0x20)) => Some(PayeeScriptClass::P2wsh),
        (34, Some(0x51), Some(0x20)) => Some(PayeeScriptClass::P2tr),
        _ => None,
    }
}

/// Whether `n` miner outputs is one of the slot classes.
pub fn is_slot_class(n: u16) -> bool {
    SLOT_CLASSES.contains(&n)
}

/// The preimage of a share tag: everything a job commits to before it is hashed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareTagPreimage {
    /// The node the share was mined to.
    pub node_id: [u8; 32],
    /// Committed tier, `log2` of the share difficulty.
    pub tier: u8,
    /// Miner outputs this job carries: one of [`SLOT_CLASSES`].
    pub slot_class: u16,
    /// The script the share credits.
    pub payee_script: Vec<u8>,
    /// The anchor the job was built on.
    pub parent_anchor: [u8; 32],
    /// Root of the batch of shares this job would lock in if it became an anchor.
    pub batch_root: [u8; 32],
}

impl ShareTagPreimage {
    /// `sha256("GhostShare/v2" || node_id || tier u8 || slot_class u16 LE || sha256(payee_script)
    /// || parent_anchor || batch_root)[..20]`. Every field is fixed width, so no length prefixes.
    pub fn tag(&self) -> [u8; SHARE_TAG_LEN] {
        let mut h = Sha256::new();
        h.update(SHARE_TAG_DOMAIN);
        h.update(self.node_id);
        h.update([self.tier]);
        h.update(self.slot_class.to_le_bytes());
        h.update(Sha256::digest(&self.payee_script));
        h.update(self.parent_anchor);
        h.update(self.batch_root);
        let d: [u8; 32] = h.finalize().into();
        let mut out = [0u8; SHARE_TAG_LEN];
        out.copy_from_slice(&d[..SHARE_TAG_LEN]);
        out
    }

    /// The bytes carried in the `GHPP` payout-tag slot: `parent_anchor[..16]`.
    pub fn parent_anchor_tag(&self) -> [u8; PARENT_ANCHOR_TAG_LEN] {
        let mut out = [0u8; PARENT_ANCHOR_TAG_LEN];
        out.copy_from_slice(&self.parent_anchor[..PARENT_ANCHOR_TAG_LEN]);
        out
    }
}

/// The difficulty-1 target, `0xFFFF * 2^208`: tier 0 on mainnet and signet.
pub fn diff1_target() -> U256 {
    U256::from_u128(0xFFFF)
        .checked_shl(208)
        .expect("0xFFFF << 208 fits 256 bits")
}

/// Target of tier `t` from base target `base`: `base >> t`.
pub fn tier_target(base: U256, t: u8) -> U256 {
    base.shr_floor(t as u32)
}

/// Whether a hash, in Bitcoin's internal byte order, meets tier `t`.
pub fn hash_meets_tier(hash: &[u8; 32], base: U256, t: u8) -> bool {
    U256::from_le_bytes(*hash) <= tier_target(base, t)
}

fn sha256d(b: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(b)).into()
}

/// Fold a coinbase txid up a merkle branch. The coinbase is the leftmost leaf, so every sibling
/// is on the right.
pub fn fold_coinbase_branch(txid: [u8; 32], branch: &[[u8; 32]]) -> [u8; 32] {
    branch.iter().fold(txid, |acc, sib| {
        let mut pair = [0u8; 64];
        pair[..32].copy_from_slice(&acc);
        pair[32..].copy_from_slice(sib);
        sha256d(&pair)
    })
}

/// Domain separator of a batch root.
pub const BATCH_ROOT_DOMAIN: &[u8] = b"GhostBatch/v1";

fn batch_leaf(id: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(id);
    h.finalize().into()
}

fn batch_node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// Largest power of two strictly below `n` (`n >= 2`).
fn split_point(n: usize) -> usize {
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// RFC 6962 merkle tree hash over share ids, in order: `leaf = sha256(0x00 || id)`,
/// `node = sha256(0x01 || left || right)`, split at the largest power of two below `n`, so an odd
/// node is carried up, never duplicated. Empty: 32 zero bytes.
fn batch_merkle(ids: &[[u8; 32]]) -> [u8; 32] {
    match ids.len() {
        0 => [0; 32],
        1 => batch_leaf(&ids[0]),
        n => {
            let k = split_point(n);
            batch_node(&batch_merkle(&ids[..k]), &batch_merkle(&ids[k..]))
        }
    }
}

/// The `batch_root` a job commits: `sha256("GhostBatch/v1" || n as u32 LE || merkle(ids))`, with
/// `merkle` the RFC 6962 tree over the share ids (each share's header hash, internal byte order)
/// in batch order. The count is committed so no two lists share a root, and the tree gives a
/// share's owner a log-size proof that an anchor included it ([`batch_proof`]).
pub fn batch_root(ids: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(BATCH_ROOT_DOMAIN);
    h.update((ids.len() as u32).to_le_bytes());
    h.update(batch_merkle(ids));
    h.finalize().into()
}

/// Audit path for `ids[index]`, leaf to root (RFC 6962). `None` if out of range.
pub fn batch_proof(ids: &[[u8; 32]], index: usize) -> Option<Vec<[u8; 32]>> {
    if index >= ids.len() {
        return None;
    }
    let mut path = Vec::new();
    let (mut lo, mut hi, mut i) = (0, ids.len(), index);
    let mut frames = Vec::new();
    while hi - lo > 1 {
        let k = split_point(hi - lo);
        if i < k {
            frames.push(batch_merkle(&ids[lo + k..hi]));
            hi = lo + k;
        } else {
            frames.push(batch_merkle(&ids[lo..lo + k]));
            lo += k;
            i -= k;
        }
    }
    while let Some(f) = frames.pop() {
        path.push(f);
    }
    Some(path)
}

/// Check that `id` sits at `index` of an `n`-share batch with root `root`, by its audit path.
pub fn verify_batch_proof(
    root: &[u8; 32],
    id: &[u8; 32],
    index: usize,
    n: usize,
    path: &[[u8; 32]],
) -> bool {
    if index >= n {
        return false;
    }
    // Walk down to record which side each level takes, then fold up.
    let (mut lo, mut hi, mut i) = (0usize, n, index);
    let mut left_side = Vec::new();
    while hi - lo > 1 {
        let k = split_point(hi - lo);
        if i < k {
            left_side.push(true);
            hi = lo + k;
        } else {
            left_side.push(false);
            lo += k;
            i -= k;
        }
    }
    if left_side.len() != path.len() {
        return false;
    }
    let mut acc = batch_leaf(id);
    for (is_left, sib) in left_side.iter().rev().zip(path) {
        acc = if *is_left {
            batch_node(&acc, sib)
        } else {
            batch_node(sib, &acc)
        };
    }
    let mut h = Sha256::new();
    h.update(BATCH_ROOT_DOMAIN);
    h.update((n as u32).to_le_bytes());
    h.update(acc);
    let want: [u8; 32] = h.finalize().into();
    &want == root
}

/// The share as received.
#[derive(Debug, Clone, Copy)]
pub struct ShareSubmission<'a> {
    /// The share's block header.
    pub header: &'a Header,
    /// The full coinbase transaction the header commits to.
    pub coinbase: &'a Transaction,
    /// Merkle branch from the coinbase txid to the header's merkle root.
    pub merkle_branch: &'a [[u8; 32]],
    /// The tag preimage the share claims.
    pub tag: &'a ShareTagPreimage,
}

/// Chain-dependent facts, resolved by the caller against the INCLUDING anchor's ancestry and the
/// Bitcoin header chain before calling [`verify_share`].
#[derive(Debug, Clone, Copy)]
pub struct ShareContext<'a> {
    /// The network tier `T_net` the share must meet.
    pub t_net: u8,
    /// Tier 0 target: [`diff1_target`] on mainnet and signet.
    pub tier_base: U256,
    /// The including anchor's `btc_height`.
    pub anchor_btc_height: u32,
    /// Height of the header's `prev_hash` in the Bitcoin header chain (the caller refuses an
    /// unknown header first). The share's job height is this plus one.
    pub prev_block_height: u32,
    /// The bits Bitcoin requires on top of `prev_hash`.
    pub expected_bits: CompactTarget,
    /// Median time past of `prev_hash`; the header time must exceed it.
    pub median_time_past: u32,
    /// Latest acceptable header time.
    pub max_time: u32,
    /// The snapshot `S(H)` with retirements through `H - 1` applied: what the coinbase must pay.
    pub table: &'a Table,
    /// The network's subsidy schedule.
    pub halving: Halving,
}

/// A share that passed rules 1 to 5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedShare {
    /// Job height `H`.
    pub job_height: u32,
    /// Tier credited: `max(T_net, committed tier)`.
    pub credited_tier: u8,
    /// Face units credited to the payee.
    pub face: u128,
    /// What the coinbase would retire if it became a block.
    pub retired: Vec<Retirement>,
}

/// Why a share failed. A failed share earns nothing, and an anchor including one is invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShareError {
    /// Rule 1: the hash does not meet `max(T_net, committed tier)`.
    #[error("insufficient work")]
    InsufficientWork,
    /// Rule 2: the coinbase does not fold to the header's merkle root.
    #[error("coinbase does not fold to the merkle root")]
    MerkleRootMismatch,
    /// Rule 3: no `GHNT` share tag in the scriptSig.
    #[error("no share tag")]
    MissingTag,
    /// Rule 3: the tag does not recompute from the claimed preimage.
    #[error("share tag does not match its preimage")]
    TagMismatch,
    /// Rule 3: the payee script is not P2SH, P2WPKH, P2WSH or P2TR.
    #[error("payee script class refused")]
    PayeeScript,
    /// Rule 3: the committed slot class is not one of the classes.
    #[error("unknown slot class {0}")]
    SlotClass(u16),
    /// Rule 4: the outputs are not the canonical outputs plus finder and commitments.
    #[error("coinbase outputs are not canonical")]
    OutputsMismatch,
    /// Rule 4: the payout arithmetic refused the snapshot.
    #[error("payout: {0}")]
    Payout(PayoutError),
    /// Rule 5: not a coinbase, or a scriptSig outside 2..=100 bytes.
    #[error("malformed coinbase")]
    MalformedCoinbase,
    /// Rule 5: the scriptSig does not start with the BIP34 height `H`.
    #[error("BIP34 height mismatch")]
    Bip34Height,
    /// Rule 5 (layout): the `GHPP` slot does not carry `parent_anchor[..16]`.
    #[error("payout-tag slot does not carry the parent anchor")]
    ParentAnchorTag,
    /// Rule 5: header bits differ from the required bits.
    #[error("wrong bits")]
    Bits,
    /// Rule 5: header time outside (median time past, max time].
    #[error("header time out of range")]
    Time,
    /// Rule 5: `H < anchor btc_height - 12`.
    #[error("job height {job} below the including anchor's window (btc_height {anchor})")]
    TooOld {
        /// The share's job height.
        job: u32,
        /// The including anchor's `btc_height`.
        anchor: u32,
    },
    /// Rule 5: `H` is in another subsidy era than the including anchor.
    #[error("job height in another subsidy era")]
    Era,
}

impl From<PayoutError> for ShareError {
    fn from(e: PayoutError) -> Self {
        ShareError::Payout(e)
    }
}

/// Era of the including anchor: its job height is `btc_height + 1`, since `btc_height` is the
/// Bitcoin tip its job saw.
fn same_era(job_height: u32, anchor_btc_height: u32, halving: Halving) -> bool {
    halving.era(job_height) == halving.era(anchor_btc_height.saturating_add(1))
}

/// Rules 1 to 5 of spec 2.1, in that order. Returns the credit the share earns.
pub fn verify_share(
    share: &ShareSubmission<'_>,
    ctx: &ShareContext<'_>,
) -> Result<VerifiedShare, ShareError> {
    let ShareSubmission {
        header,
        coinbase,
        merkle_branch,
        tag,
    } = *share;
    let job_height = ctx.prev_block_height.saturating_add(1);

    // 1. PoW meets max(T_net, committed tier).
    let credited_tier = ctx.t_net.max(tag.tier);
    let hash = header.block_hash().to_byte_array();
    if !hash_meets_tier(&hash, ctx.tier_base, credited_tier) {
        return Err(ShareError::InsufficientWork);
    }

    // 2. The coinbase folds to the header's merkle root.
    let txid = coinbase.compute_txid().to_byte_array();
    if fold_coinbase_branch(txid, merkle_branch) != header.merkle_root.to_byte_array() {
        return Err(ShareError::MerkleRootMismatch);
    }

    // 3. The tag recomputes from its preimage, and the preimage is admissible.
    if !coinbase.is_coinbase() || coinbase.input.len() != 1 {
        return Err(ShareError::MalformedCoinbase);
    }
    let script_sig = coinbase.input[0].script_sig.as_bytes();
    if !(2..=100).contains(&script_sig.len()) {
        return Err(ShareError::MalformedCoinbase);
    }
    let committed = extract_node_tag(script_sig).ok_or(ShareError::MissingTag)?;
    if committed != tag.tag() {
        return Err(ShareError::TagMismatch);
    }
    if payee_script_class(&tag.payee_script).is_none() {
        return Err(ShareError::PayeeScript);
    }
    if !is_slot_class(tag.slot_class) {
        return Err(ShareError::SlotClass(tag.slot_class));
    }

    // 4. Outputs are the canonical outputs plus finder and commitments.
    let retired = check_outputs(
        coinbase,
        ctx.table,
        job_height,
        ctx.halving,
        tag.slot_class as usize,
    )?;

    // 5. BIP34 height, layout tag, bits, time, and the job height window.
    let bip34 = bitcoin::script::Builder::new()
        .push_int(job_height as i64)
        .into_bytes();
    if !script_sig.starts_with(&bip34) {
        return Err(ShareError::Bip34Height);
    }
    if extract_payout_tag(script_sig) != Some(tag.parent_anchor_tag()) {
        return Err(ShareError::ParentAnchorTag);
    }
    if header.bits != ctx.expected_bits {
        return Err(ShareError::Bits);
    }
    if header.time <= ctx.median_time_past || header.time > ctx.max_time {
        return Err(ShareError::Time);
    }
    if job_height.saturating_add(SHARE_HEIGHT_WINDOW) < ctx.anchor_btc_height {
        return Err(ShareError::TooOld {
            job: job_height,
            anchor: ctx.anchor_btc_height,
        });
    }
    if !same_era(job_height, ctx.anchor_btc_height, ctx.halving) {
        return Err(ShareError::Era);
    }

    let face = share_face(
        credited_tier as u32,
        header.bits.to_consensus(),
        job_height,
        ctx.halving,
    )?;
    Ok(VerifiedShare {
        job_height,
        credited_tier,
        face,
        retired,
    })
}

/// Rule 4: the coinbase outputs are exactly treasury, canonical miners, an optional non-zero
/// finder, the ledger commitment and a witness commitment. Returns the retirements.
pub fn check_outputs(
    coinbase: &Transaction,
    table: &Table,
    job_height: u32,
    halving: Halving,
    slots: usize,
) -> Result<Vec<Retirement>, ShareError> {
    let actual: Vec<(u64, Vec<u8>)> = coinbase
        .output
        .iter()
        .map(|o| (o.value.to_sat(), o.script_pubkey.to_bytes()))
        .collect();
    let canonical = 1 + build_outputs(job_height, halving, table, slots)?
        .outputs
        .len();
    let finder = match actual.len().checked_sub(canonical + 2) {
        Some(0) => None,
        Some(1) => Some(&actual[canonical]),
        _ => return Err(ShareError::OutputsMismatch),
    };
    if finder.is_some_and(|f| f.0 == 0) {
        return Err(ShareError::OutputsMismatch);
    }
    let witness = &actual[actual.len() - 1].1;
    let commitment: [u8; 32] = match witness.strip_prefix(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed][..])
    {
        Some(c) if c.len() == 32 => c.try_into().expect("32 bytes"),
        _ => return Err(ShareError::OutputsMismatch),
    };
    let (finder_script, finder_value) = finder.map_or((&[][..], 0), |f| (&f.1[..], f.0));
    let (want, retired) = coinbase_outputs(
        job_height,
        halving,
        table,
        slots,
        finder_script,
        finder_value,
        &commitment,
    )?;
    if want != actual {
        return Err(ShareError::OutputsMismatch);
    }
    Ok(retired)
}

/// Settlement's match (spec 2.3): whether a mined coinbase at height `job_height` pays the
/// canonical outputs of `table` for any slot class. The class is committed only inside the share
/// tag's hash, which the chain alone cannot open, so every class is tried; outputs that are
/// canonical for some class retire exactly what they paid, whichever class it was. Returns the
/// class and the retirements of the first class that matches.
pub fn settle_outputs(
    coinbase: &Transaction,
    table: &Table,
    job_height: u32,
    halving: Halving,
) -> Option<(u16, Vec<Retirement>)> {
    SLOT_CLASSES.iter().find_map(|c| {
        check_outputs(coinbase, table, job_height, halving, *c as usize)
            .ok()
            .map(|r| (*c, r))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_payout::Balance;
    use crate::coinbase_tags::{encode_node_tag, encode_payout_tag};
    use crate::node_pool_constants::FACE_PER_SAT;
    use bitcoin::absolute::LockTime;
    use bitcoin::block::Version;
    use bitcoin::hash_types::TxMerkleNode;
    use bitcoin::{Amount, BlockHash, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    const H: u32 = 974_500;
    const BITS: u32 = 0x1702_1be5;

    fn p2tr(tag: &str) -> Vec<u8> {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&Sha256::digest(tag.as_bytes()));
        s
    }

    fn table() -> Table {
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

    /// A share being built; tests change one field, then `mine()`.
    struct Fixture {
        height: u32,
        tag: ShareTagPreimage,
        table: Table,
        finder_value: u64,
        branch: Vec<[u8; 32]>,
        script_sig_tag: Option<[u8; 20]>,
        parent_tag: [u8; 16],
        outputs: Option<Vec<(u64, Vec<u8>)>>,
        bip34_height: u32,
        halving: Halving,
    }

    impl Fixture {
        fn new(height: u32) -> Fixture {
            let tag = ShareTagPreimage {
                node_id: [1; 32],
                tier: 2,
                slot_class: 9,
                payee_script: p2tr("payee"),
                parent_anchor: [2; 32],
                batch_root: [3; 32],
            };
            Fixture {
                height,
                parent_tag: tag.parent_anchor_tag(),
                tag,
                table: table(),
                finder_value: 50_000,
                branch: vec![[7; 32], [8; 32]],
                script_sig_tag: None,
                outputs: None,
                bip34_height: height,
                halving: Halving::MAINNET,
            }
        }

        fn outputs(&self) -> Vec<(u64, Vec<u8>)> {
            self.outputs.clone().unwrap_or_else(|| {
                let slots = self.tag.slot_class as usize;
                let (o, _) = coinbase_outputs(
                    self.height,
                    self.halving,
                    &self.table,
                    slots,
                    &p2tr("finder"),
                    self.finder_value,
                    &[9; 32],
                )
                .unwrap();
                o
            })
        }

        fn mine(&self) -> (Header, Transaction) {
            let mut sig = bitcoin::script::Builder::new()
                .push_int(self.bip34_height as i64)
                .into_bytes();
            sig.extend(encode_payout_tag(&self.parent_tag));
            sig.extend(encode_node_tag(
                &self.script_sig_tag.unwrap_or(self.tag.tag()),
            ));
            sig.extend([0x08, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE]);
            let tx = Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint::null(),
                    script_sig: ScriptBuf::from_bytes(sig),
                    sequence: Sequence::MAX,
                    witness: Witness::from_slice(&[[0u8; 32]]),
                }],
                output: self
                    .outputs()
                    .into_iter()
                    .map(|(v, s)| TxOut {
                        value: Amount::from_sat(v),
                        script_pubkey: ScriptBuf::from_bytes(s),
                    })
                    .collect(),
            };
            let root = fold_coinbase_branch(tx.compute_txid().to_byte_array(), &self.branch);
            let mut header = Header {
                version: Version::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::from_byte_array([5; 32]),
                merkle_root: TxMerkleNode::from_byte_array(root),
                time: 1_800_000_000,
                bits: CompactTarget::from_consensus(BITS),
                nonce: 0,
            };
            // Test base 2^255: tier 4 needs a hash below 2^251, one try in 32.
            while !hash_meets_tier(&header.block_hash().to_byte_array(), base(), 4) {
                header.nonce += 1;
            }
            (header, tx)
        }

        fn ctx(&self) -> ShareContext<'_> {
            ShareContext {
                t_net: 3,
                tier_base: base(),
                anchor_btc_height: self.height - 1,
                prev_block_height: self.height - 1,
                expected_bits: CompactTarget::from_consensus(BITS),
                median_time_past: 1_799_999_000,
                max_time: 1_800_007_200,
                table: &self.table,
                halving: self.halving,
            }
        }

        fn verify(&self) -> Result<VerifiedShare, ShareError> {
            let (header, tx) = self.mine();
            self.verify_with(&header, &tx, &self.ctx())
        }

        fn verify_with(
            &self,
            header: &Header,
            tx: &Transaction,
            ctx: &ShareContext<'_>,
        ) -> Result<VerifiedShare, ShareError> {
            let sub = ShareSubmission {
                header,
                coinbase: tx,
                merkle_branch: &self.branch,
                tag: &self.tag,
            };
            verify_share(&sub, ctx)
        }
    }

    type Mutation = Box<dyn Fn(&mut Vec<(u64, Vec<u8>)>)>;

    fn base() -> U256 {
        U256::pow2(255).unwrap()
    }

    #[test]
    fn tag_golden_vector() {
        let t = ShareTagPreimage {
            node_id: [1; 32],
            tier: 12,
            slot_class: 44,
            payee_script: p2tr("payee"),
            parent_anchor: [2; 32],
            batch_root: [3; 32],
        };
        // Independently computed: sha256(b"GhostShare/v2" + ...)[:20] in Python.
        assert_eq!(
            hex::encode(t.tag()),
            "cea99e9ab97af1b27124c515758451a1c88b3922"
        );
        let mut other = t.clone();
        other.tier = 13;
        assert_ne!(other.tag(), t.tag());
    }

    #[test]
    fn batch_root_vectors_and_proofs() {
        let ids: Vec<[u8; 32]> = (0..7u8).map(|i| [i; 32]).collect();
        // Independently computed in Python (hashlib, RFC 6962 split).
        assert_eq!(
            hex::encode(batch_root(&[])),
            "fb467fde239aa2ba036944e6dd1787401b8d021fbeb3e203f53f04d18242bfb5"
        );
        assert_eq!(
            hex::encode(batch_root(&ids[..3])),
            "44b2da39f74705013e5f276f3e5c12a60f54a247d072e77f910c7fa555b7b734"
        );
        assert_eq!(
            hex::encode(batch_root(&ids)),
            "2afb3fb79e90289de1b2731929f37487a47f8b0117e77ec86ebdbb2ec7cda47c"
        );
        assert_ne!(batch_root(&ids[..2]), batch_root(&[ids[1], ids[0]]));
        assert_ne!(
            batch_root(&ids[..3]),
            batch_root(&[ids[0], ids[1], ids[2], ids[2]])
        );
        for n in 1..=ids.len() {
            let root = batch_root(&ids[..n]);
            for i in 0..n {
                let p = batch_proof(&ids[..n], i).unwrap();
                assert!(verify_batch_proof(&root, &ids[i], i, n, &p), "n {n} i {i}");
                assert!(!verify_batch_proof(&root, &[9; 32], i, n, &p));
                if n > 1 {
                    assert!(!verify_batch_proof(&root, &ids[i], (i + 1) % n, n, &p));
                }
            }
            assert!(batch_proof(&ids[..n], n).is_none());
        }
    }

    #[test]
    fn payee_script_classes() {
        let p2sh = [&[0xa9, 0x14][..], &[0; 20], &[0x87]].concat();
        assert_eq!(payee_script_class(&p2sh), Some(PayeeScriptClass::P2sh));
        let p2wpkh = [&[0x00, 0x14][..], &[0; 20]].concat();
        assert_eq!(payee_script_class(&p2wpkh), Some(PayeeScriptClass::P2wpkh));
        let p2wsh = [&[0x00, 0x20][..], &[0; 32]].concat();
        assert_eq!(payee_script_class(&p2wsh), Some(PayeeScriptClass::P2wsh));
        assert_eq!(payee_script_class(&p2tr("x")), Some(PayeeScriptClass::P2tr));
        let p2pkh = [&[0x76, 0xa9, 0x14][..], &[0; 20], &[0x88, 0xac]].concat();
        assert_eq!(payee_script_class(&p2pkh), None);
        assert_eq!(payee_script_class(&p2tr("x")[..33]), None);
        assert_eq!(payee_script_class(&[&p2sh[..22], &[0x88]].concat()), None);
        assert_eq!(payee_script_class(&[0x52, 0x20].repeat(17)), None);
        assert_eq!(payee_script_class(&[]), None);
        assert!(SLOT_CLASSES.iter().all(|c| is_slot_class(*c)) && !is_slot_class(10));
    }

    #[test]
    fn tier_targets_follow_difficulty_one() {
        let d1 = diff1_target();
        assert_eq!(d1.to_be_bytes()[4..6], [0xFF, 0xFF]);
        assert_eq!(tier_target(d1, 10), d1.shr_floor(10));
        let mut h = d1.to_be_bytes();
        h.reverse(); // internal byte order
        assert!(hash_meets_tier(&h, d1, 0));
        assert!(!hash_meets_tier(&h, d1, 1));
    }

    #[test]
    fn an_honest_share_verifies_and_earns_its_face() {
        let f = Fixture::new(H);
        let v = f.verify().unwrap();
        assert_eq!(v.job_height, H);
        assert_eq!(v.credited_tier, 3, "max(T_net 3, committed 2)");
        assert_eq!(v.face, share_face(3, BITS, H, Halving::MAINNET).unwrap());
        let want = build_outputs(H, Halving::MAINNET, &f.table, 9)
            .unwrap()
            .retired;
        assert_eq!(v.retired, want);
        // Without a finder output too.
        let mut f = Fixture::new(H);
        f.finder_value = 0;
        assert!(f.verify().is_ok());
    }

    #[test]
    fn committed_tier_above_t_net_must_be_met() {
        let mut f = Fixture::new(H);
        f.tag.tier = 60;
        assert_eq!(f.verify(), Err(ShareError::InsufficientWork));
        let f = Fixture::new(H);
        let (header, tx) = f.mine();
        let mut ctx = f.ctx();
        ctx.t_net = 60;
        assert_eq!(
            f.verify_with(&header, &tx, &ctx),
            Err(ShareError::InsufficientWork)
        );
    }

    #[test]
    fn a_coinbase_that_does_not_fold_is_refused() {
        let f = Fixture::new(H);
        let (header, tx) = f.mine();
        let mut g = Fixture::new(H);
        g.branch = vec![[7; 32]];
        assert_eq!(
            g.verify_with(&header, &tx, &f.ctx()),
            Err(ShareError::MerkleRootMismatch)
        );
    }

    #[test]
    fn tag_and_preimage_must_agree() {
        let mut f = Fixture::new(H);
        f.script_sig_tag = Some([0xAB; 20]);
        assert_eq!(f.verify(), Err(ShareError::TagMismatch));
        // Relabel: same coinbase, a different payee claimed.
        let f = Fixture::new(H);
        let (header, tx) = f.mine();
        let mut thief = Fixture::new(H);
        thief.tag.payee_script = p2tr("thief");
        assert_eq!(
            thief.verify_with(&header, &tx, &f.ctx()),
            Err(ShareError::TagMismatch)
        );
        let mut f = Fixture::new(H);
        f.tag.payee_script = [&[0x76, 0xa9, 0x14][..], &[0; 20], &[0x88, 0xac]].concat();
        assert_eq!(f.verify(), Err(ShareError::PayeeScript));
        let mut f = Fixture::new(H);
        f.tag.slot_class = 10;
        assert_eq!(f.verify(), Err(ShareError::SlotClass(10)));
    }

    #[test]
    fn outputs_must_be_canonical() {
        let base = Fixture::new(H).outputs();
        let cases: Vec<Mutation> = vec![
            Box::new(|o| o[1].0 += 1),                       // inflated miner
            Box::new(|o| o.swap(1, 2)),                      // reordered miners
            Box::new(|o| o[0].0 -= 1),                       // treasury skim
            Box::new(|o| o[0].1 = p2tr("not the treasury")), // wrong treasury
            Box::new(|o| o[1].1 = p2tr("relabel")),          // relabelled payee
            Box::new(|o| o[10].0 = 0),                       // zero-value finder kept
            Box::new(|o| {
                o.pop();
            }), // no witness commitment
            Box::new(|o| o[11].1[10] ^= 1),                  // wrong table root
            Box::new(|o| o.insert(1, (1_000, p2tr("extra")))), // extra payee
            Box::new(|o| o.truncate(2)),                     // truncated
        ];
        for (i, mutate) in cases.iter().enumerate() {
            let mut f = Fixture::new(H);
            let mut o = base.clone();
            mutate(&mut o);
            f.outputs = Some(o);
            assert_eq!(f.verify(), Err(ShareError::OutputsMismatch), "case {i}");
        }
        // The same outputs judged against a different snapshot.
        let f = Fixture::new(H);
        let (header, tx) = f.mine();
        let mut other = f.table.clone();
        other.insert(
            p2tr("late"),
            Balance {
                owed: 9_000 * FACE_PER_SAT,
                queue_since: Some(1),
            },
        );
        let mut ctx = f.ctx();
        ctx.table = &other;
        assert_eq!(
            f.verify_with(&header, &tx, &ctx),
            Err(ShareError::OutputsMismatch)
        );
    }

    #[test]
    fn header_and_scriptsig_rules() {
        let mut f = Fixture::new(H);
        f.bip34_height = H + 1;
        assert_eq!(f.verify(), Err(ShareError::Bip34Height));
        let mut f = Fixture::new(H);
        f.parent_tag = [0xCC; 16];
        assert_eq!(f.verify(), Err(ShareError::ParentAnchorTag));

        let f = Fixture::new(H);
        let (header, tx) = f.mine();
        let mut ctx = f.ctx();
        ctx.expected_bits = CompactTarget::from_consensus(BITS + 1);
        assert_eq!(f.verify_with(&header, &tx, &ctx), Err(ShareError::Bits));
        let mut ctx = f.ctx();
        ctx.median_time_past = header.time;
        assert_eq!(f.verify_with(&header, &tx, &ctx), Err(ShareError::Time));
        let mut ctx = f.ctx();
        ctx.max_time = header.time - 1;
        assert_eq!(f.verify_with(&header, &tx, &ctx), Err(ShareError::Time));
    }

    #[test]
    fn job_height_window_and_era() {
        let f = Fixture::new(H);
        let (header, tx) = f.mine();
        let mut ctx = f.ctx();
        ctx.anchor_btc_height = H + 12;
        assert!(
            f.verify_with(&header, &tx, &ctx).is_ok(),
            "H >= btc_height - 12"
        );
        ctx.anchor_btc_height = H + 13;
        let err = f.verify_with(&header, &tx, &ctx);
        assert_eq!(
            err,
            Err(ShareError::TooOld {
                job: H,
                anchor: H + 13
            })
        );

        // A share from the last era-4 job, included by an anchor whose job is in era 5.
        let last = 1_049_999;
        let f = Fixture::new(last);
        let (header, tx) = f.mine();
        let mut ctx = f.ctx();
        ctx.anchor_btc_height = last - 1;
        assert!(f.verify_with(&header, &tx, &ctx).is_ok());
        ctx.anchor_btc_height = last;
        assert_eq!(f.verify_with(&header, &tx, &ctx), Err(ShareError::Era));
    }

    /// Regtest halves every 150 blocks: a share's face and coinbase follow regtest's subsidy, and
    /// the era guard splits at 150, not 210,000.
    #[test]
    fn regtest_shares_price_and_split_eras_on_regtest_halvings() {
        let mut f = Fixture::new(149);
        f.halving = Halving::REGTEST;
        let (header, tx) = f.mine();
        let mut ctx = f.ctx();
        ctx.anchor_btc_height = 147;
        let v = f.verify_with(&header, &tx, &ctx).expect("same regtest era");
        assert_eq!(v.face, share_face(3, BITS, 149, Halving::REGTEST).unwrap());
        ctx.anchor_btc_height = 149;
        assert_eq!(f.verify_with(&header, &tx, &ctx), Err(ShareError::Era));

        // At 150 the coinbase pays regtest's 25 BTC; one paying mainnet's 50 is not canonical.
        let mut f = Fixture::new(150);
        f.halving = Halving::REGTEST;
        let (header, tx) = f.mine();
        let mut ctx = f.ctx();
        ctx.anchor_btc_height = 150;
        let v = f.verify_with(&header, &tx, &ctx).expect("regtest era 1");
        assert_eq!(
            v.face * 2,
            share_face(3, BITS, 149, Halving::REGTEST).unwrap()
        );
        let paid: u64 = tx.output[..tx.output.len() - 3]
            .iter()
            .map(|o| o.value.to_sat())
            .sum();
        assert_eq!(paid, 2_500_000_000, "treasury plus miners");
        let mainnet = Fixture::new(150);
        let (header, tx) = mainnet.mine();
        assert_eq!(
            mainnet.verify_with(&header, &tx, &ctx),
            Err(ShareError::OutputsMismatch)
        );
    }

    #[test]
    fn settlement_matches_any_class_and_reads_provisional_retirements() {
        use crate::canonical_payout::{ledger_root_of, provisional_retirements, table_root};
        for (class, finder) in [(9u16, 50_000u64), (44, 0), (3, 1)] {
            let mut f = Fixture::new(H);
            f.tag.slot_class = class;
            f.finder_value = finder;
            let (_, tx) = f.mine();
            let outs: Vec<(u64, Vec<u8>)> = tx
                .output
                .iter()
                .map(|o| (o.value.to_sat(), o.script_pubkey.to_bytes()))
                .collect();
            let (got_class, retired) =
                settle_outputs(&tx, &f.table, H, Halving::MAINNET).expect("canonical");
            // Classes are tried smallest first; 30 balances make 3, 9 and 44 all differ.
            let want = check_outputs(&tx, &f.table, H, Halving::MAINNET, class as usize).unwrap();
            assert_eq!(retired, want, "class {class}");
            assert_eq!(got_class, class);
            assert_eq!(ledger_root_of(&outs), Some(table_root(&f.table)));
            assert_eq!(
                provisional_retirements(H, Halving::MAINNET, &outs),
                Some(want),
                "class {class}"
            );
            // Another table: no class matches.
            let mut other = f.table.clone();
            other.pop_first();
            assert_eq!(settle_outputs(&tx, &other, H, Halving::MAINNET), None);
        }
    }

    #[test]
    fn provisional_retirements_refuse_a_coinbase_of_another_shape() {
        use crate::canonical_payout::provisional_retirements;
        use crate::node_pool_constants::TREASURY_SCRIPT_PLACEHOLDER;
        let f = Fixture::new(H);
        let good = f.outputs();
        let mut no_commitment = good.clone();
        no_commitment.remove(no_commitment.len() - 2);
        assert_eq!(
            provisional_retirements(H, Halving::MAINNET, &no_commitment),
            None
        );
        let mut wrong_treasury = good.clone();
        wrong_treasury[0].1 = p2tr("someone");
        assert_eq!(
            provisional_retirements(H, Halving::MAINNET, &wrong_treasury),
            None
        );
        let mut two_finders = good.clone();
        two_finders.insert(good.len() - 2, (5, p2tr("x")));
        assert_eq!(
            provisional_retirements(H, Halving::MAINNET, &two_finders),
            None
        );
        let mut short = good.clone();
        short[1].0 -= 1;
        assert_eq!(
            provisional_retirements(H, Halving::MAINNET, &short),
            None,
            "does not sum to the subsidy"
        );
        let treasury_only = vec![
            (
                crate::canonical_payout::subsidy(H, Halving::MAINNET),
                TREASURY_SCRIPT_PLACEHOLDER.to_vec(),
            ),
            good[good.len() - 2].clone(),
            good[good.len() - 1].clone(),
        ];
        assert_eq!(
            provisional_retirements(H, Halving::MAINNET, &treasury_only),
            Some(vec![])
        );
    }
}
