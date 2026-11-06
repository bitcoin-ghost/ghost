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
//| FILE: node_pool_views.rs                                                                                             |
//|======================================================================================================================|

//! Read-only views over the node pool tables for the ledger and status API (W2.11).
//!
//! Nothing here writes. The queries read what the relay ([`crate::node_pool_store`]) and
//! settlement journalled: a payee's shares as batches carry them, the retirements of applied
//! blocks, and the applied events themselves. Whether a share was credited on this node's best
//! chain is the caller's question, answered with [`Database::np_ledger_event_applied`](crate::database::Database::np_ledger_event_applied) on the
//! share's credit event key (the relay's `credit_event_key`), because the key is the relay's
//! definition, not storage's.
//!
//! **The genesis table.** `np_ledger` holds only what the share chain changed: it starts empty,
//! and settlement folds it onto the imported genesis table (`np_genesis`, migration v65). So a
//! payee's balance is its genesis row folded with its ledger events
//! ([`Database::np_payee_balance`](crate::database::Database::np_payee_balance), through the
//! pure core's `apply_credits` and `apply_block`, never a re-implementation), and the balance
//! before each event is the journalled one plus its genesis amount (owed is additive; only
//! `queue_since` needs the fold).

use rusqlite::{params, OptionalExtension};

use std::collections::BTreeMap;

use ghost_common::anchor_chain::{AnchorHash, ShareId};
use ghost_common::canonical_payout::{apply_block, apply_credits, Balance, Retirement, Table};
use ghost_common::error::{GhostError, GhostResult};

use crate::address_key::blob32;
use crate::database::Database;
use crate::node_pool_store::{face_from_blob, NpLedgerEventKind};

fn db_err(e: rusqlite::Error) -> GhostError {
    GhostError::Database(e.to_string())
}

fn u32_col(v: i64, what: &str) -> GhostResult<u32> {
    u32::try_from(v).map_err(|_| GhostError::Database(format!("{what} {v} is not a u32")))
}

fn limit(n: usize) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// One share paying a payee, as one batch carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpPayeeShare {
    /// The share.
    pub share_id: ShareId,
    /// The anchor whose batch carries it.
    pub anchor_hash: AnchorHash,
    /// That anchor's `btc_height`.
    pub anchor_btc_height: u32,
    /// When this node received the batch, unix seconds.
    pub received_at: i64,
    /// The share's job height.
    pub job_height: u32,
    /// The tier it was credited at under that anchor.
    pub credited_tier: u8,
    /// Face units it earned under that anchor.
    pub face: i128,
}

/// One retirement of a payee by an applied block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpPayeeRetirement {
    /// The block.
    pub block_hash: [u8; 32],
    /// Its Bitcoin height.
    pub height: u32,
    /// Face units retired: what the block paid, times `2^32`.
    pub amount: i128,
    /// When settlement applied it, unix seconds.
    pub applied_at: i64,
}

/// One applied pool block with what it retired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpAppliedBlock {
    /// The block.
    pub block_hash: [u8; 32],
    /// Its Bitcoin height.
    pub height: u32,
    /// When settlement applied it, unix seconds.
    pub applied_at: i64,
    /// Its retirements in coinbase pay order.
    pub retirements: Vec<Retirement>,
}

/// One change to a payee's balance, from the ledger journals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpPayeeLedgerEvent {
    /// The event's order on this node's chain.
    pub seq: i64,
    /// A credit or a block.
    pub kind: NpLedgerEventKind,
    /// A credit's job height, or a block's height.
    pub height: u32,
    /// When this node applied it, unix seconds.
    pub applied_at: i64,
    /// Face units credited, or retired (positive either way).
    pub amount: i128,
    /// The balance just before it, face units.
    pub prior_owed: i128,
    /// The block, for a block.
    pub block_hash: Option<[u8; 32]>,
    /// The Bitcoin time of the event: a block's own header time, or for a credit at job height
    /// `h` the header time of a block at `h - 1` (the tip it was mined on). `None` when this
    /// node's archive has no such header.
    pub chain_time: Option<u32>,
}

fn header_time(h: Option<Vec<u8>>) -> Option<u32> {
    let h = h?;
    let b: [u8; 4] = h.get(68..72)?.try_into().ok()?;
    Some(u32::from_le_bytes(b))
}

impl Database {
    /// `script`'s balance: its imported genesis row (if any) with every applied credit and
    /// retirement of it folded on, in applied order, by the pure core's `apply_credits` and
    /// `apply_block`. `None` if it has neither a genesis row nor a ledger row. With no genesis
    /// row this is the stored ledger row ([`Database::np_balance`]), read directly.
    pub fn np_payee_balance(&self, script: &[u8]) -> GhostResult<Option<Balance>> {
        let Some(g) = self.np_genesis_balance(script)? else {
            return self.np_balance(script);
        };
        type Row = (i64, i64, Vec<u8>);
        let rows: Vec<Row> = self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT kind, height, amount FROM ( \
                       SELECT e.seq, c.position, e.kind, e.height, c.amount \
                       FROM np_ledger_events e \
                       JOIN np_credits c ON c.event_key = e.event_key \
                       WHERE e.kind = 0 AND c.script = ?1 \
                       UNION ALL \
                       SELECT e.seq, r.position, e.kind, e.height, r.amount \
                       FROM np_ledger_events e \
                       JOIN np_retirements r ON r.block_hash = e.event_key \
                       WHERE e.kind = 1 AND r.script = ?1 \
                     ) ORDER BY seq, position",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map(params![script], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .map_err(db_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_err);
            rows
        })?;
        let arith = |e: ghost_common::canonical_payout::PayoutError| {
            GhostError::PayoutCalculation(e.to_string())
        };
        let mut t = Table::new();
        t.insert(script.to_vec(), g.balance);
        for (kind, h, amount) in rows {
            let amount = face_from_blob(&amount)?;
            let h = u32_col(h, "np ledger event height")?;
            match kind {
                0 => {
                    let d: BTreeMap<_, _> = [(script.to_vec(), amount)].into();
                    apply_credits(&mut t, &d, h).map_err(arith)?;
                }
                1 => {
                    apply_block(&mut t, &[(script.to_vec(), amount)]).map_err(arith)?;
                }
                k => {
                    return Err(GhostError::Database(format!(
                        "np ledger event kind {k} is unknown"
                    )))
                }
            }
        }
        Ok(t.remove(script))
    }

    /// Every change to `script`'s balance at height `min_height` or above, in the order this
    /// node applied them (at most `limit_n`, the newest kept). Credits come from `np_credits`,
    /// blocks from `np_retirements`; both carry the balance they replaced, so the balance after
    /// each event is exact. That balance includes `script`'s genesis row: the journals record
    /// the share chain's own table, which starts empty, so its genesis amount is added.
    pub fn np_payee_ledger_events(
        &self,
        script: &[u8],
        min_height: u32,
        limit_n: usize,
    ) -> GhostResult<Vec<NpPayeeLedgerEvent>> {
        type Row = (
            i64,
            i64,
            i64,
            i64,
            Vec<u8>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        );
        let rows: Vec<Row> = self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT * FROM ( \
                       SELECT e.seq, e.kind, e.height, e.applied_at, c.amount, c.prior_owed, \
                              NULL AS block_hash, \
                              (SELECT header FROM np_btc_blocks WHERE height = e.height - 1 \
                               LIMIT 1) AS header \
                       FROM np_ledger_events e \
                       JOIN np_credits c ON c.event_key = e.event_key \
                       WHERE e.kind = 0 AND e.height >= ?2 AND c.script = ?1 \
                       UNION ALL \
                       SELECT e.seq, e.kind, e.height, e.applied_at, r.amount, r.prior_owed, \
                              r.block_hash, \
                              (SELECT header FROM np_btc_blocks WHERE hash = r.block_hash) \
                       FROM np_ledger_events e \
                       JOIN np_retirements r ON r.block_hash = e.event_key \
                       WHERE e.kind = 1 AND e.height >= ?2 AND r.script = ?1 \
                     ) ORDER BY seq DESC LIMIT ?3",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map(
                    params![script, i64::from(min_height), limit(limit_n)],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                            r.get(6)?,
                            r.get(7)?,
                        ))
                    },
                )
                .map_err(db_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_err);
            rows
        })?;
        let genesis = self
            .np_genesis_balance(script)?
            .map_or(0, |g| g.balance.owed);
        let mut out = rows
            .into_iter()
            .map(|(seq, kind, h, at, amount, prior, block, header)| {
                let kind = match kind {
                    0 => NpLedgerEventKind::Credit,
                    1 => NpLedgerEventKind::Block,
                    k => {
                        return Err(GhostError::Database(format!(
                            "np ledger event kind {k} is unknown"
                        )))
                    }
                };
                Ok(NpPayeeLedgerEvent {
                    seq,
                    kind,
                    height: u32_col(h, "np ledger event height")?,
                    applied_at: at,
                    amount: face_from_blob(&amount)?,
                    prior_owed: genesis
                        + prior
                            .as_deref()
                            .map(face_from_blob)
                            .transpose()?
                            .unwrap_or(0),
                    block_hash: block.map(|b| blob32(b, "np block hash")).transpose()?,
                    chain_time: header_time(header),
                })
            })
            .collect::<GhostResult<Vec<_>>>()?;
        out.reverse();
        Ok(out)
    }

    /// The latest `limit` batch memberships of shares paying `script`, newest batch first. A
    /// share carried by several batches (a losing anchor's, then the winner's) appears once per
    /// batch; only the batch whose credit event is applied credited it.
    pub fn np_payee_shares(&self, script: &[u8], limit_n: usize) -> GhostResult<Vec<NpPayeeShare>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT s.share_id, bs.anchor_hash, b.btc_height, b.received_at, s.job_height, \
                            bs.credited_tier, bs.face \
                     FROM np_shares s \
                     JOIN np_batch_shares bs ON bs.share_id = s.share_id \
                     JOIN np_batches b ON b.anchor_hash = bs.anchor_hash \
                     WHERE s.payee_script = ?1 \
                     ORDER BY b.received_at DESC, b.btc_height DESC, bs.position DESC \
                     LIMIT ?2",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map(params![script, limit(limit_n)], |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, i64>(5)?,
                        r.get::<_, Vec<u8>>(6)?,
                    ))
                })
                .map_err(db_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_err)?;
            rows.into_iter()
                .map(|(id, a, bh, at, jh, tier, face)| {
                    Ok(NpPayeeShare {
                        share_id: blob32(id, "np share id")?,
                        anchor_hash: blob32(a, "np batch anchor")?,
                        anchor_btc_height: u32_col(bh, "np batch btc height")?,
                        received_at: at,
                        job_height: u32_col(jh, "np share job height")?,
                        credited_tier: u8::try_from(tier).map_err(|_| {
                            GhostError::Database(format!("np credited tier {tier} is not a u8"))
                        })?,
                        face: face_from_blob(&face)?,
                    })
                })
                .collect()
        })
    }

    /// Whether the ledger event `(kind, key)` is applied on this node's chain.
    pub fn np_ledger_event_applied(
        &self,
        kind: NpLedgerEventKind,
        key: &[u8; 32],
    ) -> GhostResult<bool> {
        let code: i64 = match kind {
            NpLedgerEventKind::Credit => 0,
            NpLedgerEventKind::Block => 1,
        };
        self.with_connection(|conn| {
            conn.query_row(
                "SELECT 1 FROM np_ledger_events WHERE kind = ?1 AND event_key = ?2",
                params![code, key.as_slice()],
                |_| Ok(()),
            )
            .optional()
            .map(|r| r.is_some())
            .map_err(db_err)
        })
    }

    /// The latest `limit` retirements of `script` by applied blocks, highest block first.
    pub fn np_payee_retirements(
        &self,
        script: &[u8],
        limit_n: usize,
    ) -> GhostResult<Vec<NpPayeeRetirement>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT r.block_hash, r.height, r.amount, e.applied_at \
                     FROM np_retirements r \
                     JOIN np_ledger_events e ON e.kind = 1 AND e.event_key = r.block_hash \
                     WHERE r.script = ?1 \
                     ORDER BY r.height DESC, r.position \
                     LIMIT ?2",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map(params![script, limit(limit_n)], |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                })
                .map_err(db_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_err)?;
            rows.into_iter()
                .map(|(b, h, a, at)| {
                    Ok(NpPayeeRetirement {
                        block_hash: blob32(b, "np block hash")?,
                        height: u32_col(h, "np retirement height")?,
                        amount: face_from_blob(&a)?,
                        applied_at: at,
                    })
                })
                .collect()
        })
    }

    /// The latest `limit` applied pool blocks, highest first, with their retirements.
    pub fn np_recent_blocks(&self, limit_n: usize) -> GhostResult<Vec<NpAppliedBlock>> {
        let heads = self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT event_key, height, applied_at FROM np_ledger_events WHERE kind = 1 \
                     ORDER BY height DESC LIMIT ?1",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map(params![limit(limit_n)], |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                })
                .map_err(db_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_err)?;
            rows.into_iter()
                .map(|(k, h, at)| {
                    Ok((
                        blob32(k, "np block hash")?,
                        u32_col(h, "np block height")?,
                        at,
                    ))
                })
                .collect::<GhostResult<Vec<_>>>()
        })?;
        heads
            .into_iter()
            .map(|(block_hash, height, applied_at)| {
                Ok(NpAppliedBlock {
                    block_hash,
                    height,
                    applied_at,
                    retirements: self.np_block_retirements(&block_hash)?.unwrap_or_default(),
                })
            })
            .collect()
    }

    /// Face units credited to every payee by shares of credit height `min_height` or above, on
    /// the applied credit events: the pool's whole credited work over that span. At the share
    /// face rate, this divided by `Rm * 2^32` is how many blocks that work was expected to find.
    pub fn np_credited_face_from(&self, min_height: u32) -> GhostResult<i128> {
        self.with_connection(|conn| {
            let mut st = conn
                .prepare_cached("SELECT amount FROM np_credits WHERE credit_height >= ?1")
                .map_err(db_err)?;
            let rows = st
                .query_map(params![min_height], |r| r.get::<_, Vec<u8>>(0))
                .map_err(db_err)?;
            let mut sum: i128 = 0;
            for blob in rows {
                let v = face_from_blob(&blob.map_err(db_err)?)?;
                sum = sum
                    .checked_add(v)
                    .ok_or_else(|| GhostError::Database("credited face overflows i128".into()))?;
            }
            Ok(sum)
        })
    }

    /// Pool blocks applied to the ledger: every pool block on this node's best Bitcoin chain
    /// since the genesis anchor (an undone block is not counted).
    pub fn np_pool_blocks(&self) -> GhostResult<u64> {
        self.with_connection(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM np_ledger_events WHERE kind = 1",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n.max(0) as u64)
            .map_err(db_err)
        })
    }

    /// Payees with a balance row: in the imported genesis table, the share chain's ledger, or
    /// both (counted once).
    pub fn np_ledger_rows(&self) -> GhostResult<u64> {
        self.with_connection(|conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM (SELECT script FROM np_ledger \
                 UNION SELECT script FROM np_genesis)",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n.max(0) as u64)
            .map_err(db_err)
        })
    }

    /// Every balance summed, face units: the imported genesis table plus the share chain's own
    /// table. Owed is additive (module docs), so the sum of every payee's folded balance is the
    /// sum of the two tables, read without folding any one payee.
    pub fn np_total_owed(&self) -> GhostResult<i128> {
        self.with_connection(|conn| {
            let mut sum: i128 = 0;
            for sql in ["SELECT owed FROM np_ledger", "SELECT owed FROM np_genesis"] {
                let mut st = conn.prepare_cached(sql).map_err(db_err)?;
                let rows = st
                    .query_map([], |r| r.get::<_, Vec<u8>>(0))
                    .map_err(db_err)?;
                for blob in rows {
                    sum = sum
                        .checked_add(face_from_blob(&blob.map_err(db_err)?)?)
                        .ok_or_else(|| GhostError::Database("total owed overflows i128".into()))?;
                }
            }
            Ok(sum)
        })
    }

    /// Shares batches carry at job height `min_job_height` or above, counted per anchor, job
    /// height and credited tier. Whether an anchor's credits at a job height were applied on this
    /// node's best chain is the caller's question (the module docs say why); each group is one
    /// credit event's shares at one tier. Only batches at Bitcoin height `min_batch_btc_height`
    /// or above are read: a batch never carries a share whose job is above its own anchor's.
    pub fn np_batched_share_tiers(
        &self,
        min_job_height: u32,
        min_batch_btc_height: u32,
    ) -> GhostResult<Vec<NpShareTierCount>> {
        self.with_connection(|conn| {
            let mut st = conn
                .prepare_cached(
                    "SELECT bs.anchor_hash, s.job_height, bs.credited_tier, COUNT(*) \
                     FROM np_batches b \
                     JOIN np_batch_shares bs ON bs.anchor_hash = b.anchor_hash \
                     JOIN np_shares s ON s.share_id = bs.share_id \
                     WHERE b.btc_height >= ?2 AND s.job_height >= ?1 \
                     GROUP BY bs.anchor_hash, s.job_height, bs.credited_tier",
                )
                .map_err(db_err)?;
            let rows = st
                .query_map(params![min_job_height, min_batch_btc_height], |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                })
                .map_err(db_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_err)?;
            rows.into_iter()
                .map(|(a, jh, tier, n)| {
                    Ok(NpShareTierCount {
                        anchor_hash: blob32(a, "np batch anchor")?,
                        job_height: u32_col(jh, "np share job height")?,
                        credited_tier: u8::try_from(tier).map_err(|_| {
                            GhostError::Database(format!("np credited tier {tier} is not a u8"))
                        })?,
                        shares: u64::try_from(n).unwrap_or(0),
                    })
                })
                .collect()
        })
    }
}

/// Shares one anchor's batch carries at one job height and credited tier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpShareTierCount {
    /// The anchor whose batch carries them.
    pub anchor_hash: AnchorHash,
    /// Their job height.
    pub job_height: u32,
    /// The tier they were credited at under that anchor.
    pub credited_tier: u8,
    /// How many.
    pub shares: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_pool_store::{NpAnchorRecord, NpBatchShare, NpShareRecord};
    use ghost_common::canonical_payout::Script;
    use ghost_common::node_pool_constants::FACE_PER_SAT;
    use ghost_common::node_pool_u256::U256;
    use ghost_common::share_commit::ShareTagPreimage;
    use std::collections::BTreeMap;

    fn payee(b: u8) -> Script {
        let mut s = vec![0x00, 0x14];
        s.extend_from_slice(&[b; 20]);
        s
    }

    fn anchor(db: &Database, hash: u8, btc_height: u32, at: i64) {
        db.np_insert_anchor(&NpAnchorRecord {
            hash: [hash; 32],
            parent: Some([0xEE; 32]),
            height: 1,
            t_net: 10,
            btc_height,
            cum_work: U256::pow2(18).expect("work"),
            batch_root: [hash; 32],
            received_at: at,
        })
        .expect("anchor");
    }

    fn member(seed: u8, who: u8, face: u128) -> NpBatchShare {
        let mut header = [seed; 80];
        header[0] = 0x20;
        NpBatchShare {
            share: NpShareRecord {
                share_id: {
                    use sha2::{Digest, Sha256};
                    Sha256::digest(Sha256::digest(header)).into()
                },
                header,
                coinbase: vec![1, 2, 3],
                merkle_branch: vec![],
                tag: ShareTagPreimage {
                    node_id: [9; 32],
                    tier: 10,
                    slot_class: 9,
                    payee_script: payee(who),
                    parent_anchor: [0xEE; 32],
                    batch_root: [0; 32],
                },
                job_height: 500 + seed as u32,
            },
            credited_tier: 10,
            face,
        }
    }

    #[test]
    fn payee_views_read_shares_retirements_and_blocks() {
        let db = Database::in_memory().unwrap();
        anchor(&db, 1, 600, 100);
        anchor(&db, 2, 601, 200);
        db.np_insert_batch(&[1; 32], &[member(10, 7, 5), member(11, 8, 6)], 100)
            .unwrap();
        db.np_insert_batch(&[2; 32], &[member(12, 7, 9)], 200)
            .unwrap();

        let shares = db.np_payee_shares(&payee(7), 10).unwrap();
        assert_eq!(shares.len(), 2);
        assert_eq!(
            shares[0].share_id,
            member(12, 7, 9).share.share_id,
            "newest batch first"
        );
        assert_eq!(shares[0].anchor_btc_height, 601);
        assert_eq!(shares[0].face, 9);
        assert_eq!(shares[1].job_height, 510);
        assert_eq!(db.np_payee_shares(&payee(7), 1).unwrap().len(), 1);
        assert!(db.np_payee_shares(&payee(99), 10).unwrap().is_empty());

        let key = [0x33; 32];
        assert!(!db
            .np_ledger_event_applied(NpLedgerEventKind::Credit, &key)
            .unwrap());
        let mut deltas = BTreeMap::new();
        deltas.insert(payee(7), 5_000 * FACE_PER_SAT);
        db.np_apply_credits(&key, 510, &deltas, 300).unwrap();
        assert!(db
            .np_ledger_event_applied(NpLedgerEventKind::Credit, &key)
            .unwrap());
        assert!(!db
            .np_ledger_event_applied(NpLedgerEventKind::Block, &key)
            .unwrap());
        assert_eq!(db.np_ledger_rows().unwrap(), 1);

        db.np_apply_block(&[0xB1; 32], 700, &[(payee(7), 2_000 * FACE_PER_SAT)], 400)
            .unwrap();
        db.np_apply_block(&[0xB2; 32], 701, &[(payee(7), 1_000 * FACE_PER_SAT)], 500)
            .unwrap();
        let paid = db.np_payee_retirements(&payee(7), 10).unwrap();
        assert_eq!(paid.len(), 2);
        assert_eq!((paid[0].height, paid[0].block_hash), (701, [0xB2; 32]));
        assert_eq!(paid[1].amount, 2_000 * FACE_PER_SAT);
        assert_eq!(paid[1].applied_at, 400);
        assert_eq!(db.np_pool_blocks().unwrap(), 2);
        let blocks = db.np_recent_blocks(1).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].height, 701);
        assert_eq!(
            blocks[0].retirements,
            vec![(payee(7), 1_000 * FACE_PER_SAT)]
        );

        db.np_undo_block(&[0xB2; 32]).unwrap();
        assert_eq!(db.np_payee_retirements(&payee(7), 10).unwrap().len(), 1);
        assert_eq!(
            db.np_pool_blocks().unwrap(),
            1,
            "an undone block is not counted"
        );
        assert_eq!(db.np_recent_blocks(5).unwrap().len(), 1);
    }

    fn btc_block(db: &Database, height: u32, time: u32) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut header = [0u8; 80];
        header[0] = 0x20;
        header[36..40].copy_from_slice(&height.to_le_bytes());
        header[68..72].copy_from_slice(&time.to_le_bytes());
        let hash: [u8; 32] = Sha256::digest(Sha256::digest(header)).into();
        db.np_put_btc_block(&crate::node_pool_store::NpBtcBlock {
            hash,
            height,
            header,
            coinbase: None,
            received_at: 1,
        })
        .unwrap();
        hash
    }

    #[test]
    fn a_payees_ledger_events_carry_the_balance_before_each() {
        let db = Database::in_memory().unwrap();
        btc_block(&db, 509, 1_700_000_000);
        let paid_block = btc_block(&db, 700, 1_700_100_000);
        let mut deltas = BTreeMap::new();
        deltas.insert(payee(7), 3_000 * FACE_PER_SAT);
        deltas.insert(payee(8), 9 * FACE_PER_SAT);
        db.np_apply_credits(&[0x31; 32], 510, &deltas, 300).unwrap();
        let mut deltas = BTreeMap::new();
        deltas.insert(payee(7), 500 * FACE_PER_SAT + 7);
        db.np_apply_credits(&[0x32; 32], 520, &deltas, 310).unwrap();
        db.np_apply_block(&paid_block, 700, &[(payee(7), 2_000 * FACE_PER_SAT)], 400)
            .unwrap();

        let ev = db.np_payee_ledger_events(&payee(7), 0, 100).unwrap();
        assert_eq!(ev.len(), 3);
        assert!(ev.windows(2).all(|w| w[0].seq < w[1].seq), "applied order");
        assert_eq!(ev[0].kind, NpLedgerEventKind::Credit);
        assert_eq!((ev[0].prior_owed, ev[0].amount), (0, 3_000 * FACE_PER_SAT));
        assert_eq!(ev[0].chain_time, Some(1_700_000_000), "header of h - 1");
        assert_eq!(ev[1].prior_owed, 3_000 * FACE_PER_SAT);
        assert_eq!(ev[1].chain_time, None, "no header at 519");
        assert_eq!(ev[2].kind, NpLedgerEventKind::Block);
        assert_eq!(ev[2].prior_owed, 3_500 * FACE_PER_SAT + 7);
        assert_eq!(ev[2].amount, 2_000 * FACE_PER_SAT);
        assert_eq!(ev[2].block_hash, Some(paid_block));
        assert_eq!(
            ev[2].chain_time,
            Some(1_700_100_000),
            "the block's own header"
        );
        assert_eq!(ev[2].applied_at, 400);

        // Height floor and the newest-kept limit.
        assert_eq!(
            db.np_payee_ledger_events(&payee(7), 515, 100)
                .unwrap()
                .len(),
            2
        );
        let last = db.np_payee_ledger_events(&payee(7), 0, 1).unwrap();
        assert_eq!(last.len(), 1);
        assert_eq!(last[0].kind, NpLedgerEventKind::Block);
        assert_eq!(
            db.np_payee_ledger_events(&payee(8), 0, 100).unwrap().len(),
            1
        );

        // A reorg undoes the block: its event goes with it.
        db.np_undo_block(&paid_block).unwrap();
        assert_eq!(
            db.np_payee_ledger_events(&payee(7), 0, 100).unwrap().len(),
            2
        );
    }

    /// A store with an imported genesis table: payee 7 carried over below the floor, payee 9
    /// above it, payee 8 not at all.
    fn with_genesis() -> (Database, Table) {
        use crate::node_pool_genesis::NpGenesisMeta;
        use ghost_common::canonical_payout::table_root;
        let db = Database::in_memory().unwrap();
        let mut g = Table::new();
        g.insert(
            payee(7),
            Balance {
                owed: 900 * FACE_PER_SAT,
                queue_since: None,
            },
        );
        g.insert(
            payee(9),
            Balance {
                owed: 5_000 * FACE_PER_SAT + 3,
                queue_since: Some(400),
            },
        );
        db.np_import_genesis(
            &g,
            &NpGenesisMeta {
                export_digest: [7; 32],
                network: "regtest".into(),
                export_height: 400,
                queue_since: 400,
                row_count: 2,
                table_root: table_root(&g),
                imported_at: 1,
            },
        )
        .unwrap();
        (db, g)
    }

    #[test]
    fn a_payees_balance_folds_its_genesis_row_with_the_share_chains_events() {
        use ghost_common::canonical_payout::table_for_from;
        let (db, g) = with_genesis();
        btc_block(&db, 400, 1_699_000_000);
        let mut d1 = BTreeMap::new();
        d1.insert(payee(7), 200 * FACE_PER_SAT);
        d1.insert(payee(8), 50 * FACE_PER_SAT);
        db.np_apply_credits(&[0x31; 32], 510, &d1, 300).unwrap();
        let mut d2 = BTreeMap::new();
        d2.insert(payee(9), 7);
        db.np_apply_credits(&[0x32; 32], 520, &d2, 310).unwrap();
        let paid = vec![
            (payee(9), 5_000 * FACE_PER_SAT),
            (payee(7), 100 * FACE_PER_SAT),
        ];
        db.np_apply_block(&[0xB1; 32], 700, &paid, 400).unwrap();

        // The same events folded onto the genesis table by the pure core.
        let credits: BTreeMap<u32, BTreeMap<Vec<u8>, i128>> = [(510, d1), (520, d2)].into();
        let blocks: BTreeMap<u32, Vec<(Vec<u8>, i128)>> = [(700, paid)].into();
        let want = table_for_from(g, 10_000, &credits, &blocks).unwrap();
        for p in [7, 8, 9] {
            assert_eq!(
                db.np_payee_balance(&payee(p)).unwrap().as_ref(),
                want.get(&payee(p)),
                "payee {p}"
            );
        }
        // Payee 7 crossed the floor only with its genesis amount: the share chain's own row
        // (200 sats credited, 100 paid) never did.
        let seven = db.np_payee_balance(&payee(7)).unwrap().unwrap();
        assert_eq!(seven.owed, 1_000 * FACE_PER_SAT);
        assert_eq!(seven.queue_since, Some(510));
        assert_eq!(db.np_balance(&payee(7)).unwrap().unwrap().queue_since, None);
        // Payee 9 was paid its carried-over balance down to 10 units: off the queue.
        assert_eq!(
            db.np_payee_balance(&payee(9)).unwrap(),
            Some(Balance {
                owed: 10,
                queue_since: None
            })
        );
        // No genesis row: the stored ledger row.
        assert_eq!(
            db.np_payee_balance(&payee(8)).unwrap(),
            db.np_balance(&payee(8)).unwrap()
        );
        assert_eq!(db.np_payee_balance(&payee(99)).unwrap(), None);
        // 7, 8 and 9 hold rows; 7 and 9 are in both tables.
        assert_eq!(db.np_ledger_rows().unwrap(), 3);

        // A carried-over payee with no events yet: its genesis row.
        let (db, g) = with_genesis();
        assert_eq!(
            db.np_payee_balance(&payee(9)).unwrap().as_ref(),
            g.get(&payee(9))
        );
        assert_eq!(db.np_ledger_rows().unwrap(), 2);
    }

    #[test]
    fn ledger_events_carry_the_balance_with_the_genesis_amount() {
        let (db, _) = with_genesis();
        let mut d = BTreeMap::new();
        d.insert(payee(7), 200 * FACE_PER_SAT);
        db.np_apply_credits(&[0x31; 32], 510, &d, 300).unwrap();
        db.np_apply_block(&[0xB1; 32], 700, &[(payee(7), 1_000 * FACE_PER_SAT)], 400)
            .unwrap();
        let ev = db.np_payee_ledger_events(&payee(7), 0, 100).unwrap();
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[0].prior_owed, 900 * FACE_PER_SAT, "the genesis amount");
        assert_eq!(ev[1].prior_owed, 1_100 * FACE_PER_SAT);
        assert_eq!(
            ev[1].prior_owed - ev[1].amount,
            db.np_payee_balance(&payee(7)).unwrap().unwrap().owed,
            "the last event ends at the balance"
        );
    }

    #[test]
    fn total_owed_is_every_payees_folded_balance_summed() {
        let (db, _) = with_genesis();
        assert_eq!(
            db.np_total_owed().unwrap(),
            5_900 * FACE_PER_SAT + 3,
            "the genesis table alone"
        );
        let mut d = BTreeMap::new();
        d.insert(payee(7), 200 * FACE_PER_SAT);
        d.insert(payee(8), 50 * FACE_PER_SAT);
        db.np_apply_credits(&[0x31; 32], 510, &d, 300).unwrap();
        db.np_apply_block(&[0xB1; 32], 700, &[(payee(9), 5_000 * FACE_PER_SAT)], 400)
            .unwrap();
        let folded: i128 = [7, 8, 9]
            .iter()
            .map(|p| db.np_payee_balance(&payee(*p)).unwrap().map_or(0, |b| b.owed))
            .sum();
        assert_eq!(db.np_total_owed().unwrap(), folded);
        assert_eq!(folded, 1_150 * FACE_PER_SAT + 3);
        assert_eq!(Database::in_memory().unwrap().np_total_owed().unwrap(), 0);
    }

    #[test]
    fn batched_share_tiers_group_by_anchor_job_height_and_tier() {
        let db = Database::in_memory().unwrap();
        anchor(&db, 1, 509, 100);
        anchor(&db, 2, 512, 200);
        // Job heights 510, 511 (anchor 1) and 512, 512 again and 511 (anchor 2).
        let mut deep = member(2, 7, 5);
        deep.credited_tier = 12;
        db.np_insert_batch(&[1; 32], &[member(10, 7, 5), member(11, 8, 6)], 100)
            .unwrap();
        db.np_insert_batch(&[2; 32], &[member(12, 7, 9), deep, member(11, 8, 6)], 200)
            .unwrap();
        // `deep` is seed 2: job height 502, below the floor asked for.
        let mut g = db.np_batched_share_tiers(510, 0).unwrap();
        g.sort_by_key(|x| (x.anchor_hash, x.job_height));
        let flat: Vec<_> = g
            .iter()
            .map(|x| (x.anchor_hash[0], x.job_height, x.credited_tier, x.shares))
            .collect();
        assert_eq!(
            flat,
            vec![(1, 510, 10, 1), (1, 511, 10, 1), (2, 511, 10, 1), (2, 512, 10, 1)]
        );
        let all = db.np_batched_share_tiers(0, 0).unwrap();
        assert!(all.iter().any(|x| x.credited_tier == 12 && x.job_height == 502));
        // The batch floor skips anchor 1's batch.
        assert!(db
            .np_batched_share_tiers(510, 510)
            .unwrap()
            .iter()
            .all(|x| x.anchor_hash == [2; 32]));
    }
}
