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
//| FILE: canonical_payout.rs                                                                                            |
//|======================================================================================================================|

//! Canonical payout: the node pool's ledger arithmetic and output selection.
//!
//! An exact port of `docs/node-pool-reference/refimpl_v3.py`, the normative reference (spec 2.3).
//! The vector test at the bottom of this file matches every vector in `test_vectors_v3.json`
//! byte for byte. Where the reference and anything else disagree, the reference wins.
//!
//! The rule, in face units of `2^-32` sat:
//!
//! ```text
//! S = subsidy(H); Rm = S - S/200
//! owed[a]  = sum(face) - sum(retired)      table at cut(H) = H - 20, retired through tip H - 1
//! eligible = owed >= 1,000 sats
//! N = miner outputs of the slot class; O = ceil(N/2) oldest, L = N - O largest
//! top      = the largest eligible balance, by (owed desc, script asc): the remainder absorber
//! oldest   = eligible except top, by (queue_since asc, owed desc, script asc), first O
//! largest  = [top] + rest of eligible by (owed desc, script asc), first L in all
//! pay everyone selected except top, oldest first: pay = min(owed, Rm left); stop when Rm left < 1,000
//! then top: pay = min(owed_top, Rm left) if that is >= 1,000 sats
//! retired = pay, exactly;  treasury = S/200 + (Rm - sum(pay))
//! ```
//!
//! Pure: no I/O, no clock, no floats. Nothing here is wired into the running node.
//!
//! Balances are `i128` face units. The total Bitcoin supply is below `2^83` face units, so `i128`
//! holds any real balance with room to spare; an `i64` would cap at 21.47 BTC, which is why the
//! spec forbids storing balances as SQLite integers. A balance may be negative: a retirement
//! computed on another fork's table can exceed this fork's owed (the reference allows it too).

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::node_pool_constants::{
    FACE_PER_SAT, HALVING_INTERVAL, INITIAL_SUBSIDY_SATS, LEDGER_COMMITMENT_MAGIC, MIN_PAYOUT_SATS,
    PAYOUT_FLOOR_FACE, SNAPSHOT_CUT_LAG, TREASURY_DIVISOR, TREASURY_SCRIPT_PLACEHOLDER,
};
use crate::node_pool_u256::U256;

/// A payee output script. The ledger keys on script bytes, never on address strings.
pub type Script = Vec<u8>;

/// One ledger row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Balance {
    /// Owed, in face units (`2^-32` sat).
    pub owed: i128,
    /// The credit height at which `owed` last crossed the 1,000-sat floor; `None` below it.
    pub queue_since: Option<u32>,
}

/// The balance table, ordered by script bytes (the reference's `sorted(state)` order).
pub type Table = BTreeMap<Script, Balance>;

/// One coinbase output: `(value in sats, script)`.
pub type CoinbaseOutput = (u64, Script);

/// One retirement: `(script, face units)`.
pub type Retirement = (Script, i128);

/// One entry of an undo log: the row as it was before a change (`None` = absent).
pub type UndoEntry = (Script, Option<Balance>);

/// Why the payout arithmetic refused its input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayoutError {
    /// Fewer than two miner outputs: the rule needs room for one oldest and one largest.
    #[error("slot count {0} is below 2")]
    InvalidSlots(usize),
    /// An eligible balance had no `queue_since`; the table is corrupt.
    #[error("eligible balance with no queue_since")]
    EligibleWithoutQueueSince,
    /// A value left the range the reference allows (`U256` in `share_face`, `i128` balances).
    #[error("arithmetic overflow")]
    Overflow,
}

/// What one block pays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payout {
    /// Treasury output value: `S/200` plus any change.
    pub treasury: u64,
    /// Miner outputs in pay order: oldest, largest without top, then top last.
    pub outputs: Vec<(Script, u64)>,
    /// Face units each paid script is retired by: `pay * 2^32`, exactly.
    pub retired: Vec<(Script, i128)>,
    /// `Rm` left unpaid, sent to the treasury.
    pub change: u64,
    /// Size of the oldest list selected.
    pub n_oldest: usize,
    /// Size of the largest list selected, top included.
    pub n_largest: usize,
    /// `min(outputs, oldest)`, as the reference reports it.
    pub paid_oldest: usize,
    /// What top was paid (0 if unpaid).
    pub paid_top: u64,
    /// Top was paid, but less than it is owed.
    pub top_partial: bool,
}

/// Bitcoin block subsidy at height `h`, in sats.
pub fn subsidy(h: u32) -> u64 {
    let n = h / HALVING_INTERVAL;
    if n >= 64 {
        0
    } else {
        INITIAL_SUBSIDY_SATS >> n
    }
}

/// `(treasury base, miner pool Rm)` at height `h`.
pub fn split(h: u32) -> (u64, u64) {
    let s = subsidy(h);
    let t = s / TREASURY_DIVISOR;
    (t, s - t)
}

/// `cut(H) = H - 20`, or `None` below height 20.
pub fn cut(h: u32) -> Option<u32> {
    h.checked_sub(SNAPSHOT_CUT_LAG)
}

/// `(O oldest, L largest)` with `O = ceil(N/2)`.
pub fn split_slots(n: usize) -> (usize, usize) {
    let o = n.div_ceil(2);
    (o, n - o)
}

/// Face of one share: `floor(2^tier * Rm_h * T * 2^32 / (0xFFFF * 2^208))`.
///
/// `T` is decoded from the share's own header `nbits` exactly as the reference does (mantissa
/// `nbits & 0x007FFFFF`, the sign bit ignored); `h` is the share's job height. The product is
/// carried in 256 bits; a result that leaves 256 bits, or does not fit a balance, is an error.
pub fn share_face(tier_log2: u32, nbits: u32, h: u32) -> Result<u128, PayoutError> {
    let (_, rm) = split(h);
    let exp = (nbits >> 24) as i64;
    let mant = (nbits & 0x007F_FFFF) as u128;
    let num = U256::mul_u128(rm as u128, mant)
        .checked_shl(tier_log2)
        .ok_or(PayoutError::Overflow)?;
    let s = 32 + 8 * (exp - 3) - 208;
    let r = if s >= 0 {
        num.checked_shl(s as u32)
            .ok_or(PayoutError::Overflow)?
            .div_u64(0xFFFF)
    } else {
        // floor(num / (0xFFFF << k)) == floor(floor(num / 2^k) / 0xFFFF) for non-negative integers.
        num.shr_floor((-s).min(256) as u32).div_u64(0xFFFF)
    };
    r.to_u128()
        .filter(|v| *v <= i128::MAX as u128)
        .ok_or(PayoutError::Overflow)
}

/// A selected payee: script and owed face units.
pub type Pick<'a> = (&'a Script, i128);

/// `(oldest, largest)`: `largest[0]` is top, the remainder absorber.
pub fn select(table: &Table, slots: usize) -> Result<(Vec<Pick<'_>>, Vec<Pick<'_>>), PayoutError> {
    if slots < 2 {
        return Err(PayoutError::InvalidSlots(slots));
    }
    let (o, l) = split_slots(slots);
    let mut el: Vec<(&Script, i128, u32)> = Vec::new();
    for (a, b) in table {
        if b.owed >= PAYOUT_FLOOR_FACE {
            let q = b
                .queue_since
                .ok_or(PayoutError::EligibleWithoutQueueSince)?;
            el.push((a, b.owed, q));
        }
    }
    if el.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut by_size = el.clone();
    by_size.sort_by(|x, y| y.1.cmp(&x.1).then_with(|| x.0.cmp(y.0)));
    let top = by_size[0];
    let mut by_age: Vec<_> = el.into_iter().filter(|x| x.0 != top.0).collect();
    by_age.sort_by(|x, y| {
        x.2.cmp(&y.2)
            .then_with(|| y.1.cmp(&x.1))
            .then_with(|| x.0.cmp(y.0))
    });
    by_age.truncate(o);
    let oldest: Vec<Pick<'_>> = by_age.iter().map(|x| (x.0, x.1)).collect();
    let in_oldest: BTreeSet<&Script> = oldest.iter().map(|p| p.0).collect();
    let mut largest: Vec<Pick<'_>> = vec![(top.0, top.1)];
    largest.extend(
        by_size[1..]
            .iter()
            .filter(|x| !in_oldest.contains(x.0))
            .take(l - 1)
            .map(|x| (x.0, x.1)),
    );
    Ok((oldest, largest))
}

/// What block `h` pays from `table` with `slots` miner outputs. Reads nothing but its arguments.
pub fn build_outputs(h: u32, table: &Table, slots: usize) -> Result<Payout, PayoutError> {
    let (tre, rm) = split(h);
    let (old, big) = select(table, slots)?;
    let mut left = rm;
    let mut outputs: Vec<(Script, u64)> = Vec::new();
    let others = big.get(1..).unwrap_or(&[]);
    for (a, owed) in old.iter().chain(others) {
        if left < MIN_PAYOUT_SATS {
            break;
        }
        let p = sats_of(*owed).min(left);
        left -= p;
        outputs.push(((*a).clone(), p));
    }
    let mut paid_top = 0u64;
    if let Some((a, owed)) = big.first() {
        let p = sats_of(*owed).min(left);
        if p >= MIN_PAYOUT_SATS {
            left -= p;
            outputs.push(((*a).clone(), p));
            paid_top = p;
        }
    }
    let retired = outputs
        .iter()
        .map(|(a, p)| (a.clone(), *p as i128 * FACE_PER_SAT))
        .collect();
    let top_partial = big
        .first()
        .is_some_and(|(_, owed)| 0 < paid_top && paid_top < sats_of(*owed));
    Ok(Payout {
        treasury: tre + left,
        paid_oldest: outputs.len().min(old.len()),
        outputs,
        retired,
        change: left,
        n_oldest: old.len(),
        n_largest: big.len(),
        paid_top,
        top_partial,
    })
}

/// Whole sats of a non-negative face amount, saturating at `u64::MAX` (above any `Rm`).
fn sats_of(face: i128) -> u64 {
    u64::try_from(face.max(0) / FACE_PER_SAT).unwrap_or(u64::MAX)
}

/// Add a batch of credits of share height `c`. Returns an undo log.
///
/// `queue_since` is set to `c` when a balance crosses the floor and cleared when it falls below.
pub fn apply_credits(
    table: &mut Table,
    deltas: &BTreeMap<Script, i128>,
    c: u32,
) -> Result<Vec<UndoEntry>, PayoutError> {
    let mut undo = Vec::with_capacity(deltas.len());
    for (a, d) in deltas {
        let v = table.get(a).copied();
        let (o, mut q) = v.map_or((0, None), |b| (b.owed, b.queue_since));
        let o = o.checked_add(*d).ok_or(PayoutError::Overflow)?;
        if q.is_none() && o >= PAYOUT_FLOOR_FACE {
            q = Some(c);
        } else if q.is_some() && o < PAYOUT_FLOOR_FACE {
            q = None;
        }
        undo.push((a.clone(), v));
        table.insert(
            a.clone(),
            Balance {
                owed: o,
                queue_since: q,
            },
        );
    }
    Ok(undo)
}

/// Apply a block's retirements. Returns an undo log. Only a balance falling below the floor clears
/// `queue_since`. A script absent from the table (a retirement computed on another fork's table)
/// goes negative.
pub fn apply_block(
    table: &mut Table,
    retired: &[(Script, i128)],
) -> Result<Vec<UndoEntry>, PayoutError> {
    let mut undo = Vec::with_capacity(retired.len());
    for (a, r) in retired {
        let v = table.get(a).copied();
        let (o, q) = v.map_or((0, None), |b| (b.owed, b.queue_since));
        let o = o.checked_sub(*r).ok_or(PayoutError::Overflow)?;
        undo.push((a.clone(), v));
        table.insert(
            a.clone(),
            Balance {
                owed: o,
                queue_since: if o < PAYOUT_FLOOR_FACE { None } else { q },
            },
        );
    }
    Ok(undo)
}

/// Exact inverse of [`apply_credits`] / [`apply_block`], for reorgs.
pub fn revert(table: &mut Table, undo: Vec<UndoEntry>) {
    for (a, v) in undo.into_iter().rev() {
        match v {
            None => {
                table.remove(&a);
            }
            Some(b) => {
                table.insert(a, b);
            }
        }
    }
}

/// The table block `h` is built on: credits of share height `<= cut(h)` and retirements of blocks
/// below `h`, from one chain's history. Fold order per table height `P` ascending: the credits of
/// share height `P - 20` (pinned at `P`), then block `P` if `P < h`.
pub fn table_for(
    h: u32,
    credits: &BTreeMap<u32, BTreeMap<Script, i128>>,
    blocks: &BTreeMap<u32, Vec<(Script, i128)>>,
) -> Result<Table, PayoutError> {
    table_for_from(Table::new(), h, credits, blocks)
}

/// [`table_for`] folded onto a starting table `base` instead of an empty one: the genesis table a
/// node pool starts from (plan, Phase 4), or a checkpointed table below every height folded here.
pub fn table_for_from(
    base: Table,
    h: u32,
    credits: &BTreeMap<u32, BTreeMap<Script, i128>>,
    blocks: &BTreeMap<u32, Vec<(Script, i128)>>,
) -> Result<Table, PayoutError> {
    let mut keys: Vec<u64> = credits
        .keys()
        .map(|c| *c as u64 + SNAPSHOT_CUT_LAG as u64)
        .chain(blocks.keys().map(|b| *b as u64))
        .filter(|p| *p <= h as u64)
        .collect();
    keys.sort_unstable();
    keys.dedup();
    let mut t = base;
    for p in keys {
        if let Some(c) = p.checked_sub(SNAPSHOT_CUT_LAG as u64) {
            if let Some(d) = credits.get(&(c as u32)) {
                apply_credits(&mut t, d, c as u32)?;
            }
        }
        if p < h as u64 {
            if let Some(r) = blocks.get(&(p as u32)) {
                apply_block(&mut t, r)?;
            }
        }
    }
    Ok(t)
}

/// Canonical table digest. For each row in script order:
/// `len(script) as u16 BE || script || owed as 32-byte two's complement BE || queue_since as u32 BE`
/// (`0xFFFFFFFF` for none).
pub fn table_root(table: &Table) -> [u8; 32] {
    let mut m = Sha256::new();
    for (a, b) in table {
        m.update((a.len() as u16).to_be_bytes());
        m.update(a);
        let fill = if b.owed < 0 { 0xFF } else { 0x00 };
        m.update([fill; 16]);
        m.update(b.owed.to_be_bytes());
        m.update(b.queue_since.unwrap_or(0xFFFF_FFFF).to_be_bytes());
    }
    m.finalize().into()
}

/// The ledger commitment output script: `OP_RETURN PUSH36 "GHNP" || root`.
pub fn commitment_script(root: &[u8; 32]) -> Script {
    let mut s = vec![0x6a, 0x24];
    s.extend_from_slice(LEDGER_COMMITMENT_MAGIC);
    s.extend_from_slice(root);
    s
}

/// The segwit witness commitment script: `OP_RETURN PUSH36 0xaa21a9ed || commitment`.
pub fn witness_script(wtxid_commitment: &[u8; 32]) -> Script {
    let mut s = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    s.extend_from_slice(wtxid_commitment);
    s
}

/// The full fixed coinbase output layout: treasury, miners in pay order, finder, ledger commitment,
/// witness commitment. A zero-value finder output is omitted; the finder is positional and retires
/// nothing. Returns `(value, script)` pairs and the retirements.
pub fn coinbase_outputs(
    h: u32,
    table: &Table,
    slots: usize,
    finder_script: &[u8],
    finder_value: u64,
    witness_commitment: &[u8; 32],
) -> Result<(Vec<CoinbaseOutput>, Vec<Retirement>), PayoutError> {
    let pay = build_outputs(h, table, slots)?;
    let mut o = Vec::with_capacity(pay.outputs.len() + 4);
    o.push((pay.treasury, TREASURY_SCRIPT_PLACEHOLDER.to_vec()));
    o.extend(pay.outputs.into_iter().map(|(a, p)| (p, a)));
    if finder_value > 0 {
        o.push((finder_value, finder_script.to_vec()));
    }
    o.push((0, commitment_script(&table_root(table))));
    o.push((0, witness_script(witness_commitment)));
    Ok((o, pay.retired))
}

fn varint_len(n: usize) -> usize {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        _ => 5,
    }
}

/// Serialized size of an output section: count varint plus each `value || script` entry.
pub fn outputs_bytes(o: &[(u64, Script)]) -> usize {
    varint_len(o.len())
        + o.iter()
            .map(|(_, s)| 8 + varint_len(s.len()) + s.len())
            .sum::<usize>()
}

/// The reference's output digest: `sha256` over `value u64 LE || len u8 || script` per output.
pub fn outputs_digest(o: &[(u64, Script)]) -> [u8; 32] {
    let mut m = Sha256::new();
    for (v, s) in o {
        m.update(v.to_le_bytes());
        m.update([s.len() as u8]);
        m.update(s);
    }
    m.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_pool_constants::SLOT_CLASSES;
    use serde_json::Value;

    const ONE: i128 = FACE_PER_SAT;
    const FLOOR: i128 = PAYOUT_FLOOR_FACE;
    const H: u32 = 974_500;
    const VECTORS: &str = include_str!("../../../docs/node-pool-reference/test_vectors_v3.json");

    fn sha(b: &[u8]) -> [u8; 32] {
        Sha256::digest(b).into()
    }

    fn p2tr(tag: &str) -> Script {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&sha(tag.as_bytes()));
        s
    }

    fn p2wpkh(tag: &str) -> Script {
        let mut s = vec![0x00, 0x14];
        s.extend_from_slice(&sha(tag.as_bytes())[..20]);
        s
    }

    fn be(b: &[u8]) -> i128 {
        b.iter().fold(0i128, |acc, x| (acc << 8) | *x as i128)
    }

    /// The reference's `st()`: queue_since forced to none below the floor.
    fn st(rows: &[(&str, i128, u32)]) -> Table {
        rows.iter()
            .map(|(t, o, q)| {
                let b = Balance {
                    owed: *o,
                    queue_since: (*o >= FLOOR).then_some(*q),
                };
                (p2tr(t), b)
            })
            .collect()
    }

    /// The reference's portable `gen(seed, n)` generator.
    fn gen(seed: u32, n: u32) -> Table {
        let mut t = Table::new();
        for i in 0..n {
            let b = sha(format!("g{seed}/{i}").as_bytes());
            let e = (b[0] % 8) as u32;
            let row = if e == 0 {
                Balance {
                    owed: be(&b[1..9]) % FLOOR,
                    queue_since: None,
                }
            } else {
                let sat = 1000 + be(&b[1..9]) % (1000i128 << (2 * e));
                Balance {
                    owed: sat * ONE + be(&b[9..13]),
                    queue_since: Some(900_000 + (be(&b[13..15]) % 5000) as u32),
                }
            };
            t.insert(p2tr(&format!("{seed}/{i}")), row);
        }
        t
    }

    /// The reference's `flat(n, sats)` generator.
    fn flat(n: u32, sats: i128) -> Table {
        (0..n)
            .map(|i| {
                let b = Balance {
                    owed: sats * ONE,
                    queue_since: Some(900_000 + i / 450),
                };
                (p2tr(&format!("flat{i}")), b)
            })
            .collect()
    }

    /// The 503/504-output tables: 400 small and 300 large balances.
    fn golden_50x(script_fn: fn(&str) -> Script, nm: &str) -> Table {
        let mut t = Table::new();
        for i in 0..400u32 {
            let b = Balance {
                owed: (5000 + i as i128) * ONE,
                queue_since: Some(900_000 + i / 450),
            };
            t.insert(script_fn(&format!("g{nm}{i}")), b);
        }
        for i in 0..300u32 {
            let b = Balance {
                owed: (600_000 + i as i128) * ONE,
                queue_since: Some(900_100),
            };
            t.insert(script_fn(&format!("top{nm}{i}")), b);
        }
        t
    }

    fn snap() -> Table {
        let mut t = Table::new();
        for i in 0..1500u32 {
            let b = Balance {
                owed: (3000 + (i as i128 * 37) % 9000) * ONE,
                queue_since: Some(900_000 + i / 300),
            };
            t.insert(p2tr(&format!("s{i}")), b);
        }
        for i in 0..20u32 {
            let b = Balance {
                owed: (40_000_000 + i as i128) * ONE,
                queue_since: Some(900_010),
            };
            t.insert(p2tr(&format!("sw{i}")), b);
        }
        t
    }

    fn reorg_pre() -> Table {
        (0..800u32)
            .map(|i| {
                let b = Balance {
                    owed: (3000 + i as i128) * ONE,
                    queue_since: Some(900_000 + i),
                };
                (p2tr(&format!("o{i}")), b)
            })
            .collect()
    }

    /// Port of the reference's `check_invariants`.
    fn check_invariants(h: u32, table: &Table, res: &Payout, slots: usize) {
        let (t, rm) = split(h);
        let outs = &res.outputs;
        let paid: u64 = outs.iter().map(|(_, p)| p).sum();
        assert_eq!(res.treasury + paid, t + rm, "treasury + miners != subsidy");
        assert!(res.treasury == t + (rm - paid) && res.treasury >= t);
        let uniq: BTreeSet<_> = outs.iter().map(|(a, _)| a).collect();
        assert!(outs.len() <= slots && uniq.len() == outs.len());
        assert!(
            outs.iter().all(|(_, p)| *p >= MIN_PAYOUT_SATS),
            "output below 1,000"
        );
        assert!(
            outs.iter().all(|(a, p)| *p as i128 * ONE <= table[a].owed),
            "paid more than owed"
        );
        let want: Vec<_> = outs
            .iter()
            .map(|(a, p)| (a.clone(), *p as i128 * ONE))
            .collect();
        assert_eq!(res.retired, want, "retired != pay");
        let full: Vec<bool> = outs
            .iter()
            .map(|(a, p)| *p as i128 == table[a].owed / ONE)
            .collect();
        if !full.is_empty() {
            assert!(
                full[..full.len() - 1].iter().all(|f| *f),
                "partial payee not last"
            );
        }
        let (old, big) = select(table, slots).unwrap();
        let sel: Vec<&Script> = old
            .iter()
            .chain(big.get(1..).unwrap_or(&[]))
            .map(|p| p.0)
            .collect();
        let top_paid = !outs.is_empty() && !big.is_empty() && &outs[outs.len() - 1].0 == big[0].0;
        let rest = if top_paid {
            &outs[..outs.len() - 1]
        } else {
            &outs[..]
        };
        let rest_scripts: Vec<&Script> = rest.iter().map(|(a, _)| a).collect();
        assert_eq!(rest_scripts, sel[..rest.len()].to_vec(), "not in pay order");
        if rest.len() < sel.len() || (!big.is_empty() && !top_paid) {
            assert!(rm - paid < MIN_PAYOUT_SATS, "stopped with >= 1,000 left");
        }
        if !big.is_empty() && rest.len() == sel.len() && !top_paid {
            let rest_paid: u64 = rest.iter().map(|(_, p)| p).sum();
            assert!(
                rm - rest_paid < MIN_PAYOUT_SATS,
                "top unpaid with >= 1,000 left"
            );
        }
        if res.change >= MIN_PAYOUT_SATS {
            assert!(full.iter().all(|f| *f) && outs.len() == old.len() + big.len());
        }
        let mut el: BTreeMap<&Script, Balance> = table
            .iter()
            .filter(|(_, b)| b.owed >= FLOOR)
            .map(|(a, b)| (a, *b))
            .collect();
        if !el.is_empty() {
            let want_top = el
                .iter()
                .min_by(|x, y| y.1.owed.cmp(&x.1.owed).then_with(|| x.0.cmp(y.0)))
                .map(|(a, _)| *a)
                .unwrap();
            assert_eq!(big[0].0, want_top, "top is not the largest eligible");
            el.remove(want_top);
        }
        let (o, l) = split_slots(slots);
        if !big.is_empty() {
            assert_eq!(old.len(), o.min(el.len()));
            assert_eq!(big.len() - 1, (l - 1).min(el.len() - old.len()));
        } else {
            assert!(old.is_empty());
        }
        if !old.is_empty() && el.len() > old.len() {
            let key = |a: &Script, b: &Balance| (b.queue_since.unwrap(), -b.owed, a.clone());
            let worst = old.iter().map(|p| key(p.0, &table[p.0])).max().unwrap();
            let old_set: BTreeSet<&Script> = old.iter().map(|p| p.0).collect();
            for (a, b) in &el {
                if !old_set.contains(a) {
                    assert!(key(a, b) > worst, "oldest are not the oldest");
                }
            }
        }
    }

    /// The reference's vector digest: `sha256(json.dumps([treasury, outputs, retired]))`.
    fn digest(p: &Payout) -> String {
        let outs: Vec<String> = p
            .outputs
            .iter()
            .map(|(a, v)| format!("[\"{}\", {}]", hex::encode(a), v))
            .collect();
        let ret: Vec<String> = p
            .retired
            .iter()
            .map(|(a, r)| format!("[\"{}\", \"{}\"]", hex::encode(a), r))
            .collect();
        let s = format!(
            "[{}, [{}], [{}]]",
            p.treasury,
            outs.join(", "),
            ret.join(", ")
        );
        hex::encode(sha(s.as_bytes()))
    }

    fn pairs(v: &Value) -> Vec<(String, u64)> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|e| (e[0].as_str().unwrap().to_string(), e[1].as_u64().unwrap()))
            .collect()
    }

    fn hex_pairs(o: &[(Script, u64)]) -> Vec<(String, u64)> {
        o.iter().map(|(a, p)| (hex::encode(a), *p)).collect()
    }

    fn parse_table(v: &serde_json::Map<String, Value>) -> Table {
        v.iter()
            .map(|(a, row)| {
                let b = Balance {
                    owed: row[0].as_str().unwrap().parse().unwrap(),
                    queue_since: row[1].as_u64().map(|q| q as u32),
                };
                (hex::decode(a).unwrap(), b)
            })
            .collect()
    }

    /// The input table of a vector, rebuilt from its literal rows or its generator.
    fn input_for(v: &Value) -> Table {
        let name = v["name"].as_str().unwrap();
        match &v["input"] {
            Value::Object(m) => parse_table(m),
            Value::String(g) => match g.as_str() {
                "gen(7, 900)" => gen(7, 900),
                "gen(5, 600)" => gen(5, 600),
                "gen(6, 600)" => gen(6, 600),
                "flat(23000, 18000)" => flat(23_000, 18_000),
                "see main(): snap" => snap(),
                "snap after block 1" => {
                    let mut s = snap();
                    let r1 = build_outputs(H, &s, 500).unwrap();
                    apply_block(&mut s, &r1.retired).unwrap();
                    s
                }
                "800 x (p2tr('o'+i), (3000+i) sats, 900000+i)" => reorg_pre(),
                _ if name.contains("P2TR") => golden_50x(p2tr, "t"),
                _ if name.contains("P2WPKH") => golden_50x(p2wpkh, "w"),
                other => panic!("unknown generator {other}"),
            },
            other => panic!("bad input {other}"),
        }
    }

    #[test]
    fn every_reference_vector_matches() {
        let doc: Value = serde_json::from_str(VECTORS).unwrap();
        let c = &doc["constants"];
        assert_eq!(c["MIN_PAY"].as_u64(), Some(MIN_PAYOUT_SATS));
        assert_eq!(c["CUT_LAG"].as_u64(), Some(SNAPSHOT_CUT_LAG as u64));
        assert_eq!(c["TREASURY_DIV"].as_u64(), Some(TREASURY_DIVISOR));
        let classes: Vec<u64> = (0..6)
            .map(|i| c["SLOT_CLASSES"][i.to_string()].as_u64().unwrap())
            .collect();
        assert_eq!(classes, SLOT_CLASSES.map(|x| x as u64).to_vec());
        for k in SLOT_CLASSES {
            let ol = &c["OLDEST_LARGEST"][k.to_string()];
            let want = (
                ol[0].as_u64().unwrap() as usize,
                ol[1].as_u64().unwrap() as usize,
            );
            assert_eq!(split_slots(k as usize), want);
        }

        let vectors = doc["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 37);
        let mut matched = 0;
        for v in vectors {
            let name = v["name"].as_str().unwrap();
            let h = v["height"].as_u64().unwrap() as u32;
            let slots = v["slots"].as_u64().unwrap() as usize;
            let table = input_for(v);
            assert_eq!(table.len() as u64, v["n_input"].as_u64().unwrap(), "{name}");
            let p = build_outputs(h, &table, slots).unwrap();
            check_invariants(h, &table, &p, slots);
            let miner_total: u64 = p.outputs.iter().map(|(_, x)| x).sum();
            assert_eq!(p.treasury, v["treasury"].as_u64().unwrap(), "{name}");
            assert_eq!(p.change, v["change"].as_u64().unwrap(), "{name}");
            assert_eq!(
                p.outputs.len() as u64,
                v["n_miner_outputs"].as_u64().unwrap()
            );
            assert_eq!(p.n_oldest as u64, v["n_oldest_selected"].as_u64().unwrap());
            assert_eq!(
                p.n_largest as u64,
                v["n_largest_selected"].as_u64().unwrap()
            );
            assert_eq!(miner_total, v["miner_total"].as_u64().unwrap(), "{name}");
            assert_eq!(
                hex::encode(table_root(&table)),
                v["table_root"].as_str().unwrap()
            );
            assert_eq!(digest(&p), v["digest"].as_str().unwrap(), "{name}");
            if let Some(o) = v.get("outputs") {
                assert_eq!(hex_pairs(&p.outputs), pairs(o), "{name}");
            } else {
                assert_eq!(hex_pairs(&p.outputs[..3]), pairs(&v["first_outputs"]));
                let last = &p.outputs[p.outputs.len() - 1..];
                assert_eq!(hex_pairs(last), pairs(&v["last_output"]), "{name}");
            }
            if let Some(n) = v.get("coinbase_outputs") {
                let (sf, finder): (fn(&str) -> Script, u64) = (
                    if name.contains("P2TR") { p2tr } else { p2wpkh },
                    if name.contains("finder 0") {
                        0
                    } else {
                        123_456
                    },
                );
                let (o, ret) =
                    coinbase_outputs(h, &table, slots, &sf("finder"), finder, &[0; 32]).unwrap();
                assert_eq!(o.len() as u64, n.as_u64().unwrap(), "{name}");
                assert_eq!(ret, p.retired);
                assert_eq!(o.iter().map(|x| x.0).sum::<u64>(), subsidy(h) + finder);
                let bytes = v["output_section_bytes"].as_u64().unwrap();
                assert_eq!(outputs_bytes(&o) as u64, bytes);
                let d = v["output_digest"].as_str().unwrap();
                assert_eq!(hex::encode(outputs_digest(&o)), d);
            }
            if let Some(r) = v.get("snapshot_root") {
                assert_eq!(hex::encode(table_root(&snap())), r.as_str().unwrap());
            }
            if let Some(r) = v.get("root_before") {
                let mut pre = reorg_pre();
                assert_eq!(hex::encode(table_root(&pre)), r.as_str().unwrap());
                let a = build_outputs(H, &pre, 500).unwrap();
                let undo = apply_block(&mut pre, &a.retired).unwrap();
                let ra = v["root_after_A"].as_str().unwrap();
                assert_eq!(hex::encode(table_root(&pre)), ra);
                revert(&mut pre, undo);
                let ru = v["root_after_undo"].as_str().unwrap();
                assert_eq!(hex::encode(table_root(&pre)), ru);
                assert_eq!(pre, reorg_pre());
            }
            matched += 1;
        }
        assert_eq!(matched, 37);
    }

    #[test]
    fn cut_vectors_rebuild_from_table_for() {
        let doc: Value = serde_json::from_str(VECTORS).unwrap();
        let vs = doc["vectors"].as_array().unwrap();
        let first = vs
            .iter()
            .find(|v| v["name"].as_str().unwrap().starts_with("cut: block H "));
        let second = vs
            .iter()
            .find(|v| v["name"].as_str().unwrap().starts_with("cut: block H+1"));
        let (first, second) = (first.unwrap(), second.unwrap());
        let mut credits: BTreeMap<u32, BTreeMap<Script, i128>> = BTreeMap::new();
        for (k, d) in first["credits"].as_object().unwrap() {
            let rows = d.as_object().unwrap().iter().map(|(a, x)| {
                (
                    hex::decode(a).unwrap(),
                    x.as_str().unwrap().parse().unwrap(),
                )
            });
            credits.insert(k.parse().unwrap(), rows.collect());
        }
        let t_h = table_for(H, &credits, &BTreeMap::new()).unwrap();
        assert_eq!(t_h, parse_table(first["input"].as_object().unwrap()));
        let blocks = BTreeMap::from([(H, build_outputs(H, &t_h, 9).unwrap().retired)]);
        let t_h1 = table_for(H + 1, &credits, &blocks).unwrap();
        assert_eq!(t_h1, parse_table(second["input"].as_object().unwrap()));
        assert_eq!(
            t_h1[&p2tr("late")],
            Balance {
                owed: 9_000 * ONE,
                queue_since: Some(H - 19)
            }
        );
        assert_eq!(
            t_h1[&p2tr("m")],
            Balance {
                owed: 0,
                queue_since: None
            }
        );
    }

    #[test]
    fn share_face_goldens() {
        let doc: Value = serde_json::from_str(VECTORS).unwrap();
        let f = &doc["share_face"];
        let nb = 0x1702_1be5u32;
        assert_eq!(f["nbits"].as_str(), Some("0x17021be5"));
        let s = |x: u128| x.to_string();
        assert_eq!(
            s(share_face(10, nb, H).unwrap()),
            f["face"].as_str().unwrap()
        );
        assert_eq!(s(share_face(10, nb, H).unwrap()), "10246338");
        assert_eq!(
            s(share_face(40, nb, H).unwrap()),
            f["tier40"].as_str().unwrap()
        );
        let after = share_face(10, nb, 1_050_000).unwrap();
        assert_eq!(s(after), f["after_halving"].as_str().unwrap());
        assert_eq!(share_face(10, nb, 1_049_999).unwrap(), 2 * after);
        // A product that leaves 256 bits is refused, not wrapped.
        assert_eq!(share_face(250, 0x2000_ffff, H), Err(PayoutError::Overflow));
    }

    #[test]
    fn reference_arithmetic_constants() {
        assert_eq!(split(H), (1_562_500, 310_937_500));
        assert_eq!(split(1_050_000), (781_250, 155_468_750));
        assert_eq!(cut(H), Some(H - 20));
        assert_eq!(cut(19), None);
        assert_eq!(subsidy(64 * HALVING_INTERVAL), 0);
        let mut want = p2tr("placeholder treasury, compiled constant, see plan section 5");
        assert_eq!(
            TREASURY_SCRIPT_PLACEHOLDER.to_vec(),
            std::mem::take(&mut want)
        );
        assert_eq!(select(&Table::new(), 1), Err(PayoutError::InvalidSlots(1)));
        let corrupt = BTreeMap::from([(
            p2tr("x"),
            Balance {
                owed: FLOOR,
                queue_since: None,
            },
        )]);
        assert_eq!(
            select(&corrupt, 9),
            Err(PayoutError::EligibleWithoutQueueSince)
        );
    }

    #[test]
    fn floor_crossing_and_partial_payments() {
        let mut q = Table::new();
        apply_credits(&mut q, &BTreeMap::from([(p2tr("x"), FLOOR - 1)]), 10).unwrap();
        assert_eq!(
            q[&p2tr("x")],
            Balance {
                owed: FLOOR - 1,
                queue_since: None
            }
        );
        apply_credits(&mut q, &BTreeMap::from([(p2tr("x"), 1)]), 11).unwrap();
        assert_eq!(
            q[&p2tr("x")],
            Balance {
                owed: FLOOR,
                queue_since: Some(11)
            }
        );

        // A partial payment keeps its queue place; a full one clears it.
        let rows: Vec<(String, i128, u32)> = (0..5)
            .map(|i| (format!("q{i}"), 100_000_000 * ONE + i as i128, 10 + i))
            .chain((0..4).map(|i| (format!("l{i}"), 900_000_000 * ONE, 50)))
            .collect();
        let refs: Vec<(&str, i128, u32)> =
            rows.iter().map(|(a, o, q)| (a.as_str(), *o, *q)).collect();
        let mid = st(&refs);
        let res = build_outputs(H, &mid, 9).unwrap();
        let paid: Vec<u64> = res.outputs.iter().map(|x| x.1).collect();
        assert_eq!(
            paid,
            vec![100_000_000, 100_000_000, 100_000_000, 10_937_500]
        );
        let mut after = mid.clone();
        apply_block(&mut after, &res.retired).unwrap();
        let q3 = mid[&p2tr("q3")].owed - 10_937_500 * ONE;
        assert_eq!(
            after[&p2tr("q3")],
            Balance {
                owed: q3,
                queue_since: Some(13)
            }
        );
        assert_eq!(
            after[&p2tr("q0")],
            Balance {
                owed: 0,
                queue_since: None
            }
        );

        // The sub-sat remainder of a fully paid balance stays owed and its queue clears.
        let mut frac = st(&[("f", 7_777 * ONE + ONE - 1, 3)]);
        let res = build_outputs(H, &frac, 9).unwrap();
        apply_block(&mut frac, &res.retired).unwrap();
        assert_eq!(res.outputs, vec![(p2tr("f"), 7_777)]);
        assert_eq!(
            frac[&p2tr("f")],
            Balance {
                owed: ONE - 1,
                queue_since: None
            }
        );
    }

    #[test]
    fn finder_is_positional_and_fees_touch_only_finder_and_witness() {
        let mut s = Table::new();
        for i in 0..400u32 {
            let b = Balance {
                owed: (5000 + i as i128) * ONE,
                queue_since: Some(900_000),
            };
            s.insert(p2tr(&format!("fee{i}")), b);
        }
        for i in 0..300u32 {
            let b = Balance {
                owed: (600_000 + i as i128) * ONE,
                queue_since: Some(900_100),
            };
            s.insert(p2tr(&format!("feetop{i}")), b);
        }
        let (a, _) = coinbase_outputs(H, &s, 500, &p2tr("nodeA"), 1_000_000, &[1; 32]).unwrap();
        let (b, _) = coinbase_outputs(H, &s, 500, &p2tr("nodeB"), 40_000_000, &[2; 32]).unwrap();
        assert_eq!(a.len(), 504);
        assert_eq!(a[..501], b[..501]);
        assert_eq!(a[502], b[502]);
        assert_ne!(a[501], b[501]);
        assert_ne!(a[503], b[503]);

        let sf = BTreeMap::from([
            (
                p2tr("nodeA"),
                Balance {
                    owed: 5000 * ONE,
                    queue_since: Some(900_000),
                },
            ),
            (
                p2tr("other"),
                Balance {
                    owed: 6000 * ONE,
                    queue_since: Some(900_000),
                },
            ),
        ]);
        let (o, ret) = coinbase_outputs(H, &sf, 500, &p2tr("nodeA"), 9_999, &[0; 32]).unwrap();
        assert_eq!(o.iter().filter(|x| x.1 == p2tr("nodeA")).count(), 2);
        assert_eq!(ret.iter().filter(|x| x.0 == p2tr("nodeA")).count(), 1);
    }

    /// splitmix64: a tiny deterministic generator for the property tests.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// Multi-block fuzz from the reference: nobody is ever paid more than owed, every block obeys
    /// the invariants, and no balance goes negative on one chain.
    #[test]
    fn property_multi_block_never_overpays() {
        for seed in 0..8u32 {
            let mut o = gen(100 + seed, 400);
            let mut h = H;
            for blk in 0..25usize {
                let sl = SLOT_CLASSES[(seed as usize + blk) % 6] as usize;
                let res = build_outputs(h, &o, sl).unwrap();
                check_invariants(h, &o, &res, sl);
                apply_block(&mut o, &res.retired).unwrap();
                assert!(o.values().all(|b| b.owed >= 0), "negative balance");
                h += 144;
                let credit: BTreeMap<Script, i128> =
                    o.keys().map(|a| (a.clone(), ONE * 400)).collect();
                apply_credits(&mut o, &credit, h - SNAPSHOT_CUT_LAG).unwrap();
            }
        }
    }

    /// Port of the reference's `replay_equivalence`: random credits, blocks and reorgs. A table kept
    /// with undo logs must always equal a fold of the surviving history, `queue_since` included.
    #[test]
    fn property_undo_equals_fold() {
        for seed in 0..12u64 {
            let mut r = Rng(seed);
            let addrs: Vec<Script> = (0..120).map(|i| p2tr(&format!("r{seed}/{i}"))).collect();
            let mut live = Table::new();
            let mut hist: Vec<(bool, Vec<Retirement>, u32)> = Vec::new();
            let mut undos: Vec<Vec<UndoEntry>> = Vec::new();
            for (step, h) in (0..300).zip(H..) {
                let c = r.below(100);
                if c < 8 && !undos.is_empty() {
                    let d = 1 + r.below(undos.len().min(3) as u64) as usize;
                    for _ in 0..d {
                        revert(&mut live, undos.pop().unwrap());
                        hist.pop();
                    }
                } else if c < 45 {
                    let n = 1 + r.below(40);
                    let b: BTreeMap<Script, i128> = (0..n)
                        .map(|_| {
                            let a = addrs[r.below(addrs.len() as u64) as usize].clone();
                            (a, (1 + r.below(4_000_000)) as i128 * ONE / 1000)
                        })
                        .collect();
                    undos.push(apply_credits(&mut live, &b, h).unwrap());
                    hist.push((true, b.into_iter().collect(), h));
                } else if !live.is_empty() {
                    let sl = SLOT_CLASSES[r.below(6) as usize] as usize;
                    let res = build_outputs(h, &live, sl).unwrap();
                    check_invariants(h, &live, &res, sl);
                    undos.push(apply_block(&mut live, &res.retired).unwrap());
                    hist.push((false, res.retired, h));
                }
                if step % 25 == 0 {
                    let mut s = Table::new();
                    for (credit, rows, hh) in &hist {
                        if *credit {
                            let d: BTreeMap<Script, i128> = rows.iter().cloned().collect();
                            apply_credits(&mut s, &d, *hh).unwrap();
                        } else {
                            apply_block(&mut s, rows).unwrap();
                        }
                    }
                    assert_eq!(s, live, "undo path differs from fold");
                    assert_eq!(table_root(&s), table_root(&live));
                    for b in live.values() {
                        assert_eq!(b.queue_since.is_some(), b.owed >= FLOOR);
                        assert!(b.owed >= 0, "negative balance on one chain");
                    }
                }
            }
        }
    }

    #[test]
    fn negative_balances_hash_as_twos_complement() {
        let t = BTreeMap::from([(
            vec![0xAB],
            Balance {
                owed: -5,
                queue_since: None,
            },
        )]);
        let mut m = Sha256::new();
        m.update([0, 1, 0xAB]);
        let mut owed = [0xFF; 32];
        owed[31] = 0xFB;
        m.update(owed);
        m.update([0xFF; 4]);
        let want: [u8; 32] = m.finalize().into();
        assert_eq!(table_root(&t), want);
    }
}
