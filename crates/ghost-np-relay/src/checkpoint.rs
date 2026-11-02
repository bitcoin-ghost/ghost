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
//| FILE: checkpoint.rs                                                                                                  |
//|======================================================================================================================|

//! Ledger checkpoints (W2.13): the snapshot state folded at a deep anchor.
//!
//! Every snapshot table is the genesis table with the credits of the snapshot anchor's ancestry
//! and the retirements of the share's Bitcoin ancestry folded on, in height order
//! (`canonical_payout::table_for_from`). A checkpoint at anchor `C` folds that prefix once:
//!
//! - `base`: the table at fold height `F = btc_height(C) + 1`: the genesis table with every
//!   credit of `C`'s ancestry of job height `c` with `c + 20 <= F`, and every retirement of a
//!   pool block below `F`.
//! - `residual`: the credits of `C`'s ancestry still above the fold (`c + 20 > F`).
//! - `checks`: block checks already decided for pool blocks just above the fold, whose own
//!   tables reach below `C` and cannot be computed once it is pruned.
//!
//! Every table on an anchor descending from `C` is then `table_for_from(base, h, residual + the
//! credits above C, retirements at or above F)`, the same fold in the same order. `F` is chosen so
//! the fold is the same for every includer descending from `C`: no credit of a descendant is
//! folded (a descendant's shares have job height at least `btc_height(C) - 12`), and the anchor a
//! pool block below `F` was built on is either `C`'s ancestor or on no descendant's ancestry.
//!
//! The encoding is versioned and carries the genesis anchor; the digest is
//! `sha256("GhostNP/checkpoint/v1" || payload)`.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use ghost_common::anchor_chain::AnchorHash;
use ghost_common::canonical_payout::{Balance, Retirement, Script, Table};
use ghost_common::node_pool_u256::U256;

/// Credits by job height and payee.
pub type CreditMap = BTreeMap<u32, BTreeMap<Script, i128>>;

/// A decided block check: `(block hash, anchor, what it retires if it matched)`.
pub type BlockCheck = ([u8; 32], AnchorHash, Option<Vec<Retirement>>);

const MAGIC: &[u8; 4] = b"GHCP";
const VERSION: u8 = 1;
const DOMAIN: &[u8] = b"GhostNP/checkpoint/v1";

/// Folded ledger state at an anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// The share chain's genesis anchor.
    pub genesis: AnchorHash,
    /// The anchor folded at.
    pub anchor: AnchorHash,
    /// Its anchor height.
    pub height: u32,
    /// Its `btc_height`.
    pub btc_height: u32,
    /// Its cumulative work.
    pub work: U256,
    /// The fold height `F`.
    pub fold_height: u32,
    /// The table at `F`.
    pub base: Table,
    /// Credits of the ancestry above the fold.
    pub residual: CreditMap,
    /// Decided checks of pool blocks just above the fold.
    pub checks: Vec<BlockCheck>,
}

/// Why a payload did not decode.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("checkpoint payload: {0}")]
pub struct DecodeError(String);

impl Checkpoint {
    /// The virtual checkpoint at genesis: the genesis table, nothing folded.
    pub fn genesis(genesis: AnchorHash, btc_height: u32, work: U256, table: Table) -> Checkpoint {
        Checkpoint {
            genesis,
            anchor: genesis,
            height: 0,
            btc_height,
            work,
            fold_height: btc_height + 1,
            base: table,
            residual: CreditMap::new(),
            checks: Vec::new(),
        }
    }

    /// The payload bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(MAGIC);
        p.push(VERSION);
        p.extend_from_slice(&self.genesis);
        p.extend_from_slice(&self.anchor);
        p.extend_from_slice(&self.height.to_le_bytes());
        p.extend_from_slice(&self.btc_height.to_le_bytes());
        p.extend_from_slice(&self.work.to_be_bytes());
        p.extend_from_slice(&self.fold_height.to_le_bytes());
        p.extend_from_slice(&(self.base.len() as u32).to_le_bytes());
        for (s, b) in &self.base {
            put_script(&mut p, s);
            p.extend_from_slice(&b.owed.to_be_bytes());
            p.extend_from_slice(&b.queue_since.unwrap_or(u32::MAX).to_be_bytes());
        }
        p.extend_from_slice(&(self.residual.len() as u32).to_le_bytes());
        for (h, m) in &self.residual {
            p.extend_from_slice(&h.to_le_bytes());
            put_amounts(&mut p, m.iter());
        }
        p.extend_from_slice(&(self.checks.len() as u32).to_le_bytes());
        for (b, a, r) in &self.checks {
            p.extend_from_slice(b);
            p.extend_from_slice(a);
            match r {
                None => p.push(0),
                Some(r) => {
                    p.push(1);
                    put_amounts(&mut p, r.iter().map(|(s, v)| (s, v)));
                }
            }
        }
        p
    }

    /// From payload bytes. Refuses anything malformed, including trailing bytes.
    pub fn decode(b: &[u8]) -> Result<Checkpoint, DecodeError> {
        let mut r = R(b);
        if r.take(4)? != MAGIC || r.take(1)?[0] != VERSION {
            return Err(DecodeError("magic or version".into()));
        }
        let genesis = r.a32()?;
        let anchor = r.a32()?;
        let height = r.u32()?;
        let btc_height = r.u32()?;
        let work = U256::from_be_bytes(r.a32()?);
        let fold_height = r.u32()?;
        let mut base = Table::new();
        for _ in 0..r.count()? {
            let s = r.script()?;
            let owed = r.i128()?;
            let q = u32::from_be_bytes(r.take(4)?.try_into().expect("4"));
            base.insert(
                s,
                Balance {
                    owed,
                    queue_since: (q != u32::MAX).then_some(q),
                },
            );
        }
        let mut residual = CreditMap::new();
        for _ in 0..r.count()? {
            let h = r.u32()?;
            residual.insert(h, r.amounts()?.into_iter().collect());
        }
        let mut checks = Vec::new();
        for _ in 0..r.count()? {
            let bh = r.a32()?;
            let a = r.a32()?;
            let ret = match r.take(1)?[0] {
                0 => None,
                1 => Some(r.amounts()?),
                _ => return Err(DecodeError("check flag".into())),
            };
            checks.push((bh, a, ret));
        }
        if !r.0.is_empty() {
            return Err(DecodeError("trailing bytes".into()));
        }
        Ok(Checkpoint {
            genesis,
            anchor,
            height,
            btc_height,
            work,
            fold_height,
            base,
            residual,
            checks,
        })
    }
}

/// The digest a payload must have.
pub fn digest(payload: &[u8]) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update(DOMAIN);
    s.update(payload);
    s.finalize().into()
}

fn put_script(p: &mut Vec<u8>, s: &[u8]) {
    p.extend_from_slice(&(s.len() as u16).to_le_bytes());
    p.extend_from_slice(s);
}

fn put_amounts<'a>(p: &mut Vec<u8>, it: impl ExactSizeIterator<Item = (&'a Script, &'a i128)>) {
    p.extend_from_slice(&(it.len() as u32).to_le_bytes());
    for (s, v) in it {
        put_script(p, s);
        p.extend_from_slice(&v.to_be_bytes());
    }
}

struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.0.len() < n {
            return Err(DecodeError("truncated".into()));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4")))
    }

    /// A count, bounded by the bytes left so a corrupt count cannot allocate.
    fn count(&mut self) -> Result<usize, DecodeError> {
        let n = self.u32()? as usize;
        if n > self.0.len() {
            return Err(DecodeError("count beyond the payload".into()));
        }
        Ok(n)
    }

    fn a32(&mut self) -> Result<[u8; 32], DecodeError> {
        Ok(self.take(32)?.try_into().expect("32"))
    }

    fn i128(&mut self) -> Result<i128, DecodeError> {
        Ok(i128::from_be_bytes(self.take(16)?.try_into().expect("16")))
    }

    fn script(&mut self) -> Result<Script, DecodeError> {
        let n = u16::from_le_bytes(self.take(2)?.try_into().expect("2")) as usize;
        Ok(self.take(n)?.to_vec())
    }

    fn amounts(&mut self) -> Result<Vec<(Script, i128)>, DecodeError> {
        (0..self.count()?)
            .map(|_| Ok((self.script()?, self.i128()?)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Checkpoint {
        let mut base = Table::new();
        base.insert(
            vec![0x51, 0x20, 1],
            Balance {
                owed: -5,
                queue_since: None,
            },
        );
        base.insert(
            vec![0x51, 0x20, 2],
            Balance {
                owed: i128::MAX,
                queue_since: Some(1_001),
            },
        );
        let mut residual = CreditMap::new();
        residual.insert(1_010, [(vec![1u8], 7i128)].into_iter().collect());
        Checkpoint {
            genesis: [1; 32],
            anchor: [2; 32],
            height: 9,
            btc_height: 1_030,
            work: U256::pow2(30).unwrap(),
            fold_height: 1_031,
            base,
            residual,
            checks: vec![
                ([3; 32], [4; 32], None),
                ([5; 32], [6; 32], Some(vec![(vec![9u8], 1 << 40)])),
            ],
        }
    }

    #[test]
    fn checkpoints_round_trip_and_refuse_damage() {
        let c = sample();
        let p = c.encode();
        assert_eq!(Checkpoint::decode(&p), Ok(c));
        for cut in [0, 5, p.len() - 1] {
            assert!(Checkpoint::decode(&p[..cut]).is_err());
        }
        let mut long = p.clone();
        long.push(0);
        assert!(Checkpoint::decode(&long).is_err());
        // A flipped byte changes the digest even where it still decodes.
        let mut flipped = p.clone();
        flipped[80] ^= 1;
        assert_ne!(digest(&flipped), digest(&p));
        // A huge count is refused before it allocates.
        let mut big = p.clone();
        let at = 4 + 1 + 32 + 32 + 4 + 4 + 32 + 4;
        big[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Checkpoint::decode(&big).is_err());
    }
}
