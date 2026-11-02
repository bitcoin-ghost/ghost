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

use rusqlite::{params, OptionalExtension};

use ghost_common::anchor_chain::{AnchorHash, ShareId};
use ghost_common::canonical_payout::Retirement;
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

impl Database {
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

    /// Rows in the materialised balance table.
    pub fn np_ledger_rows(&self) -> GhostResult<u64> {
        self.with_connection(|conn| {
            conn.query_row("SELECT COUNT(*) FROM np_ledger", [], |r| r.get::<_, i64>(0))
                .map(|n| n.max(0) as u64)
                .map_err(db_err)
        })
    }
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
        let blocks = db.np_recent_blocks(1).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].height, 701);
        assert_eq!(
            blocks[0].retirements,
            vec![(payee(7), 1_000 * FACE_PER_SAT)]
        );

        db.np_undo_block(&[0xB2; 32]).unwrap();
        assert_eq!(db.np_payee_retirements(&payee(7), 10).unwrap().len(), 1);
        assert_eq!(db.np_recent_blocks(5).unwrap().len(), 1);
    }
}
