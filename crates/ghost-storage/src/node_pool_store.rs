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
//| FILE: node_pool_store.rs                                                                                             |
//|======================================================================================================================|

//! Node pool storage (W2.4, migration v63): the typed API over the `np_*` tables.
//!
//! - **Anchors** and **batches** with their **shares**: enough to rebuild the
//!   [`AnchorChain`](ghost_common::anchor_chain::AnchorChain) on restart, re-run
//!   `share_commit::verify_share` on any held share, and recompute the table.
//! - **The ledger**: the materialised balance table, changed only through journalled events (a
//!   credit event or a block's retirements). The arithmetic is the pure core's own
//!   [`apply_credits`], [`apply_block`] and [`revert`]: this module loads the rows an event
//!   touches, runs them through those functions, and writes the result with the undo log in the
//!   same transaction. Undo is last-in first-out, so it restores every row exactly.
//! - **Pinned snapshot roots** per cut height and **per-miner sensing** results.
//!
//! Face-unit amounts are 32-byte two's complement big-endian blobs, as `table_root` hashes them:
//! balances can pass `i64` (about 21.47 BTC in `2^-32` sat) and can go negative.
//!
//! Every insert that may meet an existing row is `INSERT OR IGNORE` followed by an explicit read
//! of the row: a duplicate that matches is [`InsertOutcome::AlreadyPresent`], a duplicate that
//! differs is an error, and an insert that was ignored for any other reason (OR IGNORE also
//! swallows CHECK and NOT NULL failures) is an error. Nothing here discards a database error.
//!
//! The relay (`ghost-np-relay`) applies credits; settlement applies and undoes blocks.

use std::collections::BTreeMap;

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use ghost_common::anchor_chain::{AnchorHash, ShareId};
use ghost_common::canonical_payout::{
    apply_block, apply_credits, revert, table_for, Balance, Retirement, Script, Table, UndoEntry,
};
use ghost_common::error::{GhostError, GhostResult};
use ghost_common::node_pool_u256::U256;
use ghost_common::share_commit::ShareTagPreimage;

use crate::address_key::blob32;
use crate::database::Database;

/// What an idempotent insert or apply did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// The row (or event) is new and was written.
    Inserted,
    /// An identical row (or event) was already held; nothing changed.
    AlreadyPresent,
}

/// One anchor header as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpAnchorRecord {
    /// The anchor's header hash.
    pub hash: AnchorHash,
    /// The `parent_anchor` its job committed; `None` only for genesis.
    pub parent: Option<AnchorHash>,
    /// Anchors between genesis and this one (genesis is 0).
    pub height: u32,
    /// `T_net` in force for it; it met `t_net + 8`.
    pub t_net: u8,
    /// The Bitcoin tip height its job saw.
    pub btc_height: u32,
    /// Cumulative anchor work, genesis to here.
    pub cum_work: U256,
    /// The `batch_root` its job committed.
    pub batch_root: [u8; 32],
    /// When this node received it, unix seconds.
    pub received_at: i64,
}

/// A share as stored: everything `share_commit::verify_share` reads from the share itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpShareRecord {
    /// `sha256d(header)`, Bitcoin's internal byte order.
    pub share_id: ShareId,
    /// The 80-byte block header.
    pub header: [u8; 80],
    /// The raw coinbase transaction.
    pub coinbase: Vec<u8>,
    /// Merkle branch from the coinbase txid to the header's merkle root.
    pub merkle_branch: Vec<[u8; 32]>,
    /// The tag preimage the share claims.
    pub tag: ShareTagPreimage,
    /// Job height: the height of the header's `prev_hash`, plus one.
    pub job_height: u32,
}

/// A share as one batch carries it, with what it earned under that batch's anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpBatchShare {
    /// The share.
    pub share: NpShareRecord,
    /// `max(T_net, committed tier)` under the including anchor.
    pub credited_tier: u8,
    /// Face units credited.
    pub face: u128,
}

/// An anchor's batch as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpBatch {
    /// The anchor that locks the batch in.
    pub anchor_hash: AnchorHash,
    /// The anchor's committed `batch_root`.
    pub batch_root: [u8; 32],
    /// The anchor's `btc_height`.
    pub btc_height: u32,
    /// When this node received it, unix seconds.
    pub received_at: i64,
    /// The shares, in batch order.
    pub shares: Vec<NpBatchShare>,
}

/// What [`Database::np_prune_batches_below`] removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NpPruneReport {
    /// Batches removed.
    pub batches: usize,
    /// Batch membership rows removed.
    pub batch_shares: usize,
    /// Shares removed because no remaining batch carries them.
    pub shares: usize,
}

/// The two kinds of ledger event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NpLedgerEventKind {
    /// Credits, keyed by the anchor whose batch earned them.
    Credit,
    /// A block's retirements, keyed by the block hash.
    Block,
}

impl NpLedgerEventKind {
    fn code(self) -> i64 {
        match self {
            NpLedgerEventKind::Credit => 0,
            NpLedgerEventKind::Block => 1,
        }
    }

    fn from_code(c: i64) -> GhostResult<Self> {
        match c {
            0 => Ok(NpLedgerEventKind::Credit),
            1 => Ok(NpLedgerEventKind::Block),
            _ => Err(GhostError::Database(format!(
                "np ledger event kind {c} is unknown"
            ))),
        }
    }

    fn journal(self) -> &'static str {
        match self {
            NpLedgerEventKind::Credit => "np_credits",
            NpLedgerEventKind::Block => "np_retirements",
        }
    }

    fn key_column(self) -> &'static str {
        match self {
            NpLedgerEventKind::Credit => "event_key",
            NpLedgerEventKind::Block => "block_hash",
        }
    }
}

/// One applied ledger event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NpLedgerEvent {
    /// Application order; undo runs from the highest.
    pub seq: i64,
    /// Credit or block.
    pub kind: NpLedgerEventKind,
    /// The anchor hash (credit) or block hash (block).
    pub key: [u8; 32],
    /// Credit height (credit) or Bitcoin height (block).
    pub height: u32,
    /// When it was applied, unix seconds.
    pub applied_at: i64,
}

/// A pinned snapshot table root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NpSnapshotRoot {
    /// `cut(H)`.
    pub cut_height: u32,
    /// The snapshot anchor `S(H)` the table was taken on.
    pub anchor_hash: AnchorHash,
    /// `canonical_payout::table_root` of that table.
    pub table_root: [u8; 32],
    /// Rows in that table.
    pub row_count: u64,
    /// When it was pinned, unix seconds.
    pub pinned_at: i64,
}

/// The latest coinbase-size sensing result for one miner and user agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpMinerSensing {
    /// The miner's payee script.
    pub miner_script: Script,
    /// The user agent it connected with.
    pub user_agent: String,
    /// The highest slot class it returned valid shares on, if any.
    pub highest_pass_class: Option<u16>,
    /// The slot class it failed on, if any.
    pub failed_class: Option<u16>,
    /// When, unix seconds.
    pub sensed_at: i64,
}

/// An archived Bitcoin block (W2.13): its header and, above the archive floor, its coinbase with
/// the merkle branch that binds it to the header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpBtcBlock {
    /// `sha256d(header)`, internal byte order.
    pub hash: [u8; 32],
    /// The block's height.
    pub height: u32,
    /// The 80-byte header. Its bytes 4..36 are the parent's hash.
    pub header: [u8; 80],
    /// The coinbase, non-witness serialization, and the merkle branch from its txid to the
    /// header's merkle root, if held.
    pub coinbase: Option<(Vec<u8>, Vec<[u8; 32]>)>,
    /// When this node archived it, unix seconds.
    pub received_at: i64,
}

/// A stored ledger checkpoint (W2.13). The payload is the relay's encoding; `digest` is what it
/// must hash to, so corruption is detected rather than trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpCheckpoint {
    /// The anchor the state is folded at.
    pub anchor_hash: AnchorHash,
    /// Its anchor height.
    pub height: u32,
    /// Its `btc_height`.
    pub btc_height: u32,
    /// The encoded state.
    pub payload: Vec<u8>,
    /// The digest the payload must have.
    pub digest: [u8; 32],
    /// When it was written, unix seconds.
    pub created_at: i64,
}

/// A stored checkpoint's identity without its payload ([`Database::np_checkpoint_heads`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpCheckpointHead {
    /// The anchor the state is folded at.
    pub anchor_hash: AnchorHash,
    /// Its anchor height.
    pub height: u32,
    /// Its `btc_height`.
    pub btc_height: u32,
    /// The digest the payload must have.
    pub digest: [u8; 32],
    /// When it was written, unix seconds.
    pub created_at: i64,
}

fn db_err(e: rusqlite::Error) -> GhostError {
    GhostError::Database(e.to_string())
}

/// `v` as 32-byte two's complement big-endian: the `table_root` encoding.
pub fn face_to_blob(v: i128) -> [u8; 32] {
    let mut out = [if v < 0 { 0xFF } else { 0x00 }; 32];
    out[16..].copy_from_slice(&v.to_be_bytes());
    out
}

/// Inverse of [`face_to_blob`]. Refuses a blob that is not 32 bytes or whose value leaves `i128`
/// (the upper 16 bytes are not the sign extension of the lower 16).
pub fn face_from_blob(b: &[u8]) -> GhostResult<i128> {
    let b: [u8; 32] = b
        .try_into()
        .map_err(|_| GhostError::Database(format!("face blob is {} bytes, not 32", b.len())))?;
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&b[16..]);
    let v = i128::from_be_bytes(lo);
    let fill = if v < 0 { 0xFF } else { 0x00 };
    if b[..16].iter().any(|x| *x != fill) {
        return Err(GhostError::Database(
            "face blob value is outside i128".to_string(),
        ));
    }
    Ok(v)
}

fn face_u128_to_blob(v: u128) -> GhostResult<[u8; 32]> {
    let v = i128::try_from(v)
        .map_err(|_| GhostError::Database(format!("face {v} exceeds i128::MAX")))?;
    Ok(face_to_blob(v))
}

fn face_u128_from_blob(b: &[u8]) -> GhostResult<u128> {
    let v = face_from_blob(b)?;
    u128::try_from(v).map_err(|_| GhostError::Database(format!("stored face {v} is negative")))
}

fn u32_col(v: i64, what: &str) -> GhostResult<u32> {
    u32::try_from(v).map_err(|_| GhostError::Database(format!("{what} {v} is not a u32")))
}

fn u8_col(v: i64, what: &str) -> GhostResult<u8> {
    u8::try_from(v).map_err(|_| GhostError::Database(format!("{what} {v} is not a u8")))
}

fn u16_col(v: i64, what: &str) -> GhostResult<u16> {
    u16::try_from(v).map_err(|_| GhostError::Database(format!("{what} {v} is not a u16")))
}

fn sha256d(b: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(b)).into()
}

fn branch_to_blob(branch: &[[u8; 32]]) -> Vec<u8> {
    branch.iter().flatten().copied().collect()
}

fn branch_from_blob(b: &[u8]) -> GhostResult<Vec<[u8; 32]>> {
    let (chunks, rest) = b.as_chunks::<32>();
    if !rest.is_empty() {
        return Err(GhostError::Database(format!(
            "merkle branch blob is {} bytes, not a multiple of 32",
            b.len()
        )));
    }
    Ok(chunks.to_vec())
}

/// Did the last statement on `conn` write a row?
fn wrote(conn: &Connection) -> bool {
    conn.changes() > 0
}

// ---------------------------------------------------------------------------------------------
// Anchors
// ---------------------------------------------------------------------------------------------

const ANCHOR_COLS: &str = "hash, parent, height, t_net, btc_height, cum_work, batch_root, \
                           received_at";

fn anchor_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawAnchor> {
    Ok(RawAnchor {
        hash: r.get(0)?,
        parent: r.get(1)?,
        height: r.get(2)?,
        t_net: r.get(3)?,
        btc_height: r.get(4)?,
        cum_work: r.get(5)?,
        batch_root: r.get(6)?,
        received_at: r.get(7)?,
    })
}

struct RawAnchor {
    hash: Vec<u8>,
    parent: Option<Vec<u8>>,
    height: i64,
    t_net: i64,
    btc_height: i64,
    cum_work: Vec<u8>,
    batch_root: Vec<u8>,
    received_at: i64,
}

impl RawAnchor {
    fn decode(self) -> GhostResult<NpAnchorRecord> {
        Ok(NpAnchorRecord {
            hash: blob32(self.hash, "np anchor hash")?,
            parent: self
                .parent
                .map(|p| blob32(p, "np anchor parent"))
                .transpose()?,
            height: u32_col(self.height, "np anchor height")?,
            t_net: u8_col(self.t_net, "np anchor t_net")?,
            btc_height: u32_col(self.btc_height, "np anchor btc_height")?,
            cum_work: U256::from_be_bytes(blob32(self.cum_work, "np anchor cum_work")?),
            batch_root: blob32(self.batch_root, "np anchor batch_root")?,
            received_at: self.received_at,
        })
    }
}

fn get_anchor_conn(conn: &Connection, hash: &AnchorHash) -> GhostResult<Option<NpAnchorRecord>> {
    conn.query_row(
        &format!("SELECT {ANCHOR_COLS} FROM np_anchors WHERE hash = ?1"),
        params![hash.to_vec()],
        anchor_from_row,
    )
    .optional()
    .map_err(db_err)?
    .map(RawAnchor::decode)
    .transpose()
}

/// The fields that define an anchor, without `received_at`: a later copy of the same anchor
/// received at another time is the same anchor.
fn same_anchor(a: &NpAnchorRecord, b: &NpAnchorRecord) -> bool {
    (
        a.hash,
        a.parent,
        a.height,
        a.t_net,
        a.btc_height,
        a.cum_work,
        a.batch_root,
    ) == (
        b.hash,
        b.parent,
        b.height,
        b.t_net,
        b.btc_height,
        b.cum_work,
        b.batch_root,
    )
}

// ---------------------------------------------------------------------------------------------
// Shares and batches
// ---------------------------------------------------------------------------------------------

fn insert_share_conn(conn: &Connection, s: &NpShareRecord) -> GhostResult<()> {
    if sha256d(&s.header) != s.share_id {
        return Err(GhostError::Database(format!(
            "np share {} is not sha256d of its header",
            hex::encode(s.share_id)
        )));
    }
    conn.execute(
        "INSERT OR IGNORE INTO np_shares (share_id, header, coinbase, merkle_branch, node_id, \
         tier, slot_class, payee_script, parent_anchor, batch_root, job_height) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            s.share_id.to_vec(),
            s.header.to_vec(),
            s.coinbase,
            branch_to_blob(&s.merkle_branch),
            s.tag.node_id.to_vec(),
            s.tag.tier as i64,
            s.tag.slot_class as i64,
            s.tag.payee_script,
            s.tag.parent_anchor.to_vec(),
            s.tag.batch_root.to_vec(),
            s.job_height as i64,
        ],
    )
    .map_err(db_err)?;
    // Inserted or not, the row must now be exactly this share.
    match get_share_conn(conn, &s.share_id)? {
        Some(held) if held == *s => Ok(()),
        Some(_) => Err(GhostError::Database(format!(
            "np share {} is already held with different contents",
            hex::encode(s.share_id)
        ))),
        None => Err(GhostError::Database(format!(
            "np share {} was not stored (insert ignored, no row present)",
            hex::encode(s.share_id)
        ))),
    }
}

fn get_share_conn(conn: &Connection, id: &ShareId) -> GhostResult<Option<NpShareRecord>> {
    type Raw = (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
    );
    let raw: Option<Raw> = conn
        .query_row(
            "SELECT header, coinbase, merkle_branch, node_id, tier, slot_class, payee_script, \
             parent_anchor, batch_root, job_height FROM np_shares WHERE share_id = ?1",
            params![id.to_vec()],
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
                    r.get(8)?,
                    r.get(9)?,
                ))
            },
        )
        .optional()
        .map_err(db_err)?;
    let Some((header, coinbase, branch, node_id, tier, slot, payee, parent, root, job)) = raw
    else {
        return Ok(None);
    };
    let header: [u8; 80] = header
        .as_slice()
        .try_into()
        .map_err(|_| GhostError::Database("np share header is not 80 bytes".to_string()))?;
    Ok(Some(NpShareRecord {
        share_id: *id,
        header,
        coinbase,
        merkle_branch: branch_from_blob(&branch)?,
        tag: ShareTagPreimage {
            node_id: blob32(node_id, "np share node_id")?,
            tier: u8_col(tier, "np share tier")?,
            slot_class: u16_col(slot, "np share slot_class")?,
            payee_script: payee,
            parent_anchor: blob32(parent, "np share parent_anchor")?,
            batch_root: blob32(root, "np share batch_root")?,
        },
        job_height: u32_col(job, "np share job_height")?,
    }))
}

/// `(share_id, credited_tier, face)` per position, in batch order.
fn batch_members_conn(
    conn: &Connection,
    anchor: &AnchorHash,
) -> GhostResult<Vec<(ShareId, u8, u128)>> {
    let mut stmt = conn
        .prepare(
            "SELECT position, share_id, credited_tier, face FROM np_batch_shares \
             WHERE anchor_hash = ?1 ORDER BY position",
        )
        .map_err(db_err)?;
    let rows = stmt
        .query_map(params![anchor.to_vec()], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(db_err)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_err)?;
    rows.into_iter()
        .enumerate()
        .map(|(i, (pos, id, tier, face))| {
            if pos != i as i64 {
                return Err(GhostError::Database(format!(
                    "np batch {} has a gap at position {i}",
                    hex::encode(anchor)
                )));
            }
            Ok((
                blob32(id, "np batch share_id")?,
                u8_col(tier, "np batch credited_tier")?,
                face_u128_from_blob(&face)?,
            ))
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------------------------

fn get_balance_conn(conn: &Connection, script: &[u8]) -> GhostResult<Option<Balance>> {
    let raw: Option<(Vec<u8>, Option<i64>)> = conn
        .query_row(
            "SELECT owed, queue_since FROM np_ledger WHERE script = ?1",
            params![script],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(db_err)?;
    raw.map(|(owed, q)| {
        Ok(Balance {
            owed: face_from_blob(&owed)?,
            queue_since: q.map(|q| u32_col(q, "np ledger queue_since")).transpose()?,
        })
    })
    .transpose()
}

/// Write `script`'s row as `b`, or delete it for `None`.
fn put_balance_conn(conn: &Connection, script: &[u8], b: Option<&Balance>) -> GhostResult<()> {
    match b {
        Some(b) => conn
            .execute(
                "INSERT INTO np_ledger (script, owed, queue_since) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(script) DO UPDATE SET owed = excluded.owed, \
                 queue_since = excluded.queue_since",
                params![
                    script,
                    face_to_blob(b.owed).to_vec(),
                    b.queue_since.map(|q| q as i64)
                ],
            )
            .map_err(db_err)?,
        None => conn
            .execute("DELETE FROM np_ledger WHERE script = ?1", params![script])
            .map_err(db_err)?,
    };
    Ok(())
}

/// The current rows of `scripts`, as a partial table.
fn load_rows_conn<'a>(
    conn: &Connection,
    scripts: impl IntoIterator<Item = &'a Script>,
) -> GhostResult<Table> {
    let mut t = Table::new();
    for s in scripts {
        if t.contains_key(s) {
            continue;
        }
        if let Some(b) = get_balance_conn(conn, s)? {
            t.insert(s.clone(), b);
        }
    }
    Ok(t)
}

fn get_event_conn(
    conn: &Connection,
    kind: NpLedgerEventKind,
    key: &[u8; 32],
) -> GhostResult<Option<NpLedgerEvent>> {
    let raw: Option<(i64, i64, i64)> = conn
        .query_row(
            "SELECT seq, height, applied_at FROM np_ledger_events WHERE kind = ?1 AND \
             event_key = ?2",
            params![kind.code(), key.to_vec()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(db_err)?;
    raw.map(|(seq, h, at)| {
        Ok(NpLedgerEvent {
            seq,
            kind,
            key: *key,
            height: u32_col(h, "np ledger event height")?,
            applied_at: at,
        })
    })
    .transpose()
}

fn last_event_conn(conn: &Connection) -> GhostResult<Option<NpLedgerEvent>> {
    let raw: Option<(i64, i64, Vec<u8>, i64, i64)> = conn
        .query_row(
            "SELECT seq, kind, event_key, height, applied_at FROM np_ledger_events \
             ORDER BY seq DESC LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()
        .map_err(db_err)?;
    raw.map(|(seq, kind, key, h, at)| {
        Ok(NpLedgerEvent {
            seq,
            kind: NpLedgerEventKind::from_code(kind)?,
            key: blob32(key, "np ledger event key")?,
            height: u32_col(h, "np ledger event height")?,
            applied_at: at,
        })
    })
    .transpose()
}

/// The `(script, amount)` entries of an event's journal, in order.
fn journal_entries_conn(
    conn: &Connection,
    kind: NpLedgerEventKind,
    key: &[u8; 32],
) -> GhostResult<Vec<(Script, i128)>> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT script, amount FROM {} WHERE {} = ?1 ORDER BY position",
            kind.journal(),
            kind.key_column()
        ))
        .map_err(db_err)?;
    let rows = stmt
        .query_map(params![key.to_vec()], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
        })
        .map_err(db_err)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_err)?;
    rows.into_iter()
        .map(|(s, a)| Ok((s, face_from_blob(&a)?)))
        .collect()
}

/// The undo log of an event, in application order.
fn journal_undo_conn(
    conn: &Connection,
    kind: NpLedgerEventKind,
    key: &[u8; 32],
) -> GhostResult<Vec<UndoEntry>> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT script, prior_present, prior_owed, prior_queue_since FROM {} \
             WHERE {} = ?1 ORDER BY position",
            kind.journal(),
            kind.key_column()
        ))
        .map_err(db_err)?;
    let rows = stmt
        .query_map(params![key.to_vec()], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Option<Vec<u8>>>(2)?,
                r.get::<_, Option<i64>>(3)?,
            ))
        })
        .map_err(db_err)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(db_err)?;
    rows.into_iter()
        .map(|(s, present, owed, q)| {
            let prior = match (present, owed) {
                (0, None) => None,
                (1, Some(o)) => Some(Balance {
                    owed: face_from_blob(&o)?,
                    queue_since: q.map(|q| u32_col(q, "np prior queue_since")).transpose()?,
                }),
                _ => {
                    return Err(GhostError::Database(format!(
                        "{} row for {} has an inconsistent prior",
                        kind.journal(),
                        hex::encode(&s)
                    )))
                }
            };
            Ok((s, prior))
        })
        .collect()
}

/// Apply one ledger event: run `f` (the pure core's arithmetic) over the touched rows, write the
/// rows, the event and its journal. Idempotent on an identical event; refuses a different one
/// under the same key.
fn apply_event_conn(
    conn: &Connection,
    kind: NpLedgerEventKind,
    key: &[u8; 32],
    height: u32,
    entries: &[(Script, i128)],
    applied_at: i64,
    f: impl FnOnce(&mut Table) -> GhostResult<Vec<UndoEntry>>,
) -> GhostResult<InsertOutcome> {
    if let Some(held) = get_event_conn(conn, kind, key)? {
        let held_entries = journal_entries_conn(conn, kind, key)?;
        return if held.height == height && held_entries == entries {
            Ok(InsertOutcome::AlreadyPresent)
        } else {
            Err(GhostError::Database(format!(
                "np ledger event {} is already applied with different contents",
                hex::encode(key)
            )))
        };
    }
    if kind == NpLedgerEventKind::Block {
        let other: Option<Vec<u8>> = conn
            .query_row(
                "SELECT event_key FROM np_ledger_events WHERE kind = 1 AND height = ?1",
                params![height as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;
        if let Some(other) = other {
            return Err(GhostError::Database(format!(
                "block {} at height {height} is applied; undo it before applying {}",
                hex::encode(other),
                hex::encode(key)
            )));
        }
    }

    let mut rows = load_rows_conn(conn, entries.iter().map(|(s, _)| s))?;
    let undo = f(&mut rows)?;
    if undo.len() != entries.len() {
        return Err(GhostError::Database(format!(
            "np ledger event {}: {} undo entries for {} changes",
            hex::encode(key),
            undo.len(),
            entries.len()
        )));
    }

    conn.execute(
        "INSERT INTO np_ledger_events (kind, event_key, height, applied_at) \
         VALUES (?1, ?2, ?3, ?4)",
        params![kind.code(), key.to_vec(), height as i64, applied_at],
    )
    .map_err(db_err)?;
    let sql = format!(
        "INSERT INTO {} ({}, position, {}, script, amount, prior_present, prior_owed, \
         prior_queue_since) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        kind.journal(),
        kind.key_column(),
        match kind {
            NpLedgerEventKind::Credit => "credit_height",
            NpLedgerEventKind::Block => "height",
        }
    );
    for (i, ((script, amount), (undo_script, prior))) in entries.iter().zip(&undo).enumerate() {
        if script != undo_script {
            return Err(GhostError::Database(
                "np ledger undo log out of order with its changes".to_string(),
            ));
        }
        conn.execute(
            &sql,
            params![
                key.to_vec(),
                i as i64,
                height as i64,
                script,
                face_to_blob(*amount).to_vec(),
                prior.is_some() as i64,
                prior.map(|b| face_to_blob(b.owed).to_vec()),
                prior.and_then(|b| b.queue_since).map(|q| q as i64),
            ],
        )
        .map_err(db_err)?;
    }
    for (script, b) in &rows {
        put_balance_conn(conn, script, Some(b))?;
    }
    Ok(InsertOutcome::Inserted)
}

/// Undo the most recent ledger event, which must be `(kind, key)`.
fn undo_event_conn(conn: &Connection, kind: NpLedgerEventKind, key: &[u8; 32]) -> GhostResult<()> {
    let ev = get_event_conn(conn, kind, key)?.ok_or_else(|| {
        GhostError::Database(format!(
            "np ledger event {} is not applied",
            hex::encode(key)
        ))
    })?;
    let last = last_event_conn(conn)?
        .ok_or_else(|| GhostError::Database("np ledger has no events to undo".to_string()))?;
    if last.seq != ev.seq {
        return Err(GhostError::Database(format!(
            "np ledger event {} is not the latest (seq {} applied after it); undo is last-in \
             first-out",
            hex::encode(key),
            last.seq
        )));
    }
    let undo = journal_undo_conn(conn, kind, key)?;
    let scripts: Vec<Script> = undo.iter().map(|(s, _)| s.clone()).collect();
    let mut rows = load_rows_conn(conn, scripts.iter())?;
    revert(&mut rows, undo);
    for s in &scripts {
        put_balance_conn(conn, s, rows.get(s))?;
    }
    conn.execute(
        &format!(
            "DELETE FROM {} WHERE {} = ?1",
            kind.journal(),
            kind.key_column()
        ),
        params![key.to_vec()],
    )
    .map_err(db_err)?;
    conn.execute(
        "DELETE FROM np_ledger_events WHERE seq = ?1",
        params![ev.seq],
    )
    .map_err(db_err)?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Bitcoin block archive
// ---------------------------------------------------------------------------------------------

struct RawBtcBlock {
    hash: Vec<u8>,
    height: i64,
    header: Vec<u8>,
    coinbase: Option<Vec<u8>>,
    branch: Option<Vec<u8>>,
    received_at: i64,
}

fn btc_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawBtcBlock> {
    Ok(RawBtcBlock {
        hash: r.get(0)?,
        height: r.get(1)?,
        header: r.get(2)?,
        coinbase: r.get(3)?,
        branch: r.get(4)?,
        received_at: r.get(5)?,
    })
}

impl RawBtcBlock {
    fn decode(self) -> GhostResult<NpBtcBlock> {
        let header: [u8; 80] = self
            .header
            .as_slice()
            .try_into()
            .map_err(|_| GhostError::Database("np btc header is not 80 bytes".to_string()))?;
        let coinbase = match (self.coinbase, self.branch) {
            (Some(c), Some(b)) => Some((c, branch_from_blob(&b)?)),
            (None, None) => None,
            _ => {
                return Err(GhostError::Database(
                    "np btc block holds a coinbase without its branch".to_string(),
                ))
            }
        };
        Ok(NpBtcBlock {
            hash: blob32(self.hash, "np btc hash")?,
            height: u32_col(self.height, "np btc height")?,
            header,
            coinbase,
            received_at: self.received_at,
        })
    }
}

fn get_btc_block_conn(conn: &Connection, hash: &[u8; 32]) -> GhostResult<Option<NpBtcBlock>> {
    conn.query_row(
        "SELECT hash, height, header, coinbase, branch, received_at FROM np_btc_blocks \
         WHERE hash = ?1",
        params![hash.to_vec()],
        btc_row,
    )
    .optional()
    .map_err(db_err)?
    .map(RawBtcBlock::decode)
    .transpose()
}

impl Database {
    // -----------------------------------------------------------------------------------------
    // Anchors
    // -----------------------------------------------------------------------------------------

    /// Store an anchor header. Idempotent: the same anchor again (whatever its `received_at`)
    /// is [`InsertOutcome::AlreadyPresent`]; a different anchor under the same hash is an error.
    pub fn np_insert_anchor(&self, a: &NpAnchorRecord) -> GhostResult<InsertOutcome> {
        self.transaction(|tx| {
            tx.execute(
                &format!(
                    "INSERT OR IGNORE INTO np_anchors ({ANCHOR_COLS}) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
                ),
                params![
                    a.hash.to_vec(),
                    a.parent.map(|p| p.to_vec()),
                    a.height as i64,
                    a.t_net as i64,
                    a.btc_height as i64,
                    a.cum_work.to_be_bytes().to_vec(),
                    a.batch_root.to_vec(),
                    a.received_at,
                ],
            )
            .map_err(db_err)?;
            let inserted = wrote(tx);
            match get_anchor_conn(tx, &a.hash)? {
                Some(held) if same_anchor(&held, a) => Ok(if inserted {
                    InsertOutcome::Inserted
                } else {
                    InsertOutcome::AlreadyPresent
                }),
                Some(_) => Err(GhostError::Database(format!(
                    "np anchor {} is already held with different contents",
                    hex::encode(a.hash)
                ))),
                None => Err(GhostError::Database(format!(
                    "np anchor {} was not stored (insert ignored, no row present)",
                    hex::encode(a.hash)
                ))),
            }
        })
    }

    /// One anchor, if held.
    pub fn np_get_anchor(&self, hash: &AnchorHash) -> GhostResult<Option<NpAnchorRecord>> {
        self.with_connection(|conn| get_anchor_conn(conn, hash))
    }

    /// Every held anchor, parents before children (by anchor height, then hash): the order to
    /// replay them into an `AnchorChain` on restart.
    pub fn np_load_anchors(&self) -> GhostResult<Vec<NpAnchorRecord>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(&format!(
                    "SELECT {ANCHOR_COLS} FROM np_anchors ORDER BY height, hash"
                ))
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], anchor_from_row)
                .map_err(db_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_err)?;
            rows.into_iter().map(RawAnchor::decode).collect()
        })
    }

    // -----------------------------------------------------------------------------------------
    // Batches
    // -----------------------------------------------------------------------------------------

    /// Store an anchor's batch and its shares, in one transaction. The anchor must be held; the
    /// batch takes its committed `batch_root` and `btc_height`. Each share must hash to its
    /// `share_id`. Shares already held from another batch are reused, and must match.
    ///
    /// Idempotent: the same batch again is [`InsertOutcome::AlreadyPresent`]; a different share
    /// list for the same anchor is an error. That the list matches `batch_root`, and that each
    /// share passes its checks, is the caller's job (W2.5).
    pub fn np_insert_batch(
        &self,
        anchor_hash: &AnchorHash,
        shares: &[NpBatchShare],
        received_at: i64,
    ) -> GhostResult<InsertOutcome> {
        let wanted: Vec<(ShareId, u8, u128)> = shares
            .iter()
            .map(|s| (s.share.share_id, s.credited_tier, s.face))
            .collect();
        let faces = shares
            .iter()
            .map(|s| face_u128_to_blob(s.face))
            .collect::<GhostResult<Vec<_>>>()?;
        self.transaction(|tx| {
            let anchor = get_anchor_conn(tx, anchor_hash)?.ok_or_else(|| {
                GhostError::Database(format!(
                    "np batch for unknown anchor {}",
                    hex::encode(anchor_hash)
                ))
            })?;
            tx.execute(
                "INSERT OR IGNORE INTO np_batches (anchor_hash, batch_root, share_count, \
                 btc_height, received_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    anchor_hash.to_vec(),
                    anchor.batch_root.to_vec(),
                    shares.len() as i64,
                    anchor.btc_height as i64,
                    received_at,
                ],
            )
            .map_err(db_err)?;
            if !wrote(tx) {
                let held: Option<i64> = tx
                    .query_row(
                        "SELECT share_count FROM np_batches WHERE anchor_hash = ?1",
                        params![anchor_hash.to_vec()],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(db_err)?;
                if held.is_none() {
                    return Err(GhostError::Database(format!(
                        "np batch {} was not stored (insert ignored, no row present)",
                        hex::encode(anchor_hash)
                    )));
                }
                let held_members = batch_members_conn(tx, anchor_hash)?;
                if held != Some(shares.len() as i64) || held_members != wanted {
                    return Err(GhostError::Database(format!(
                        "np batch {} is already held with a different share list",
                        hex::encode(anchor_hash)
                    )));
                }
                for s in shares {
                    if get_share_conn(tx, &s.share.share_id)?.as_ref() != Some(&s.share) {
                        return Err(GhostError::Database(format!(
                            "np batch {}: share {} differs from the held copy",
                            hex::encode(anchor_hash),
                            hex::encode(s.share.share_id)
                        )));
                    }
                }
                return Ok(InsertOutcome::AlreadyPresent);
            }
            for (i, (s, face)) in shares.iter().zip(&faces).enumerate() {
                insert_share_conn(tx, &s.share)?;
                // A fresh batch in this transaction: a conflict here is a duplicate share in the
                // list, and the plain INSERT surfaces it as an error that rolls the batch back.
                tx.execute(
                    "INSERT INTO np_batch_shares (anchor_hash, position, share_id, \
                     credited_tier, face) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        anchor_hash.to_vec(),
                        i as i64,
                        s.share.share_id.to_vec(),
                        s.credited_tier as i64,
                        face.to_vec(),
                    ],
                )
                .map_err(db_err)?;
            }
            Ok(InsertOutcome::Inserted)
        })
    }

    /// Whether `anchor_hash`'s batch is held.
    pub fn np_has_batch(&self, anchor_hash: &AnchorHash) -> GhostResult<bool> {
        self.with_connection(|conn| {
            conn.query_row(
                "SELECT 1 FROM np_batches WHERE anchor_hash = ?1",
                params![anchor_hash.to_vec()],
                |_| Ok(()),
            )
            .optional()
            .map(|o| o.is_some())
            .map_err(db_err)
        })
    }

    /// An anchor's batch with its shares in order, if held.
    pub fn np_get_batch(&self, anchor_hash: &AnchorHash) -> GhostResult<Option<NpBatch>> {
        self.with_connection(|conn| {
            let raw: Option<(Vec<u8>, i64, i64, i64)> = conn
                .query_row(
                    "SELECT batch_root, share_count, btc_height, received_at FROM np_batches \
                     WHERE anchor_hash = ?1",
                    params![anchor_hash.to_vec()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()
                .map_err(db_err)?;
            let Some((root, count, btc_height, received_at)) = raw else {
                return Ok(None);
            };
            let members = batch_members_conn(conn, anchor_hash)?;
            if members.len() as i64 != count {
                return Err(GhostError::Database(format!(
                    "np batch {} holds {} shares, recorded {count}",
                    hex::encode(anchor_hash),
                    members.len()
                )));
            }
            let mut shares = Vec::with_capacity(members.len());
            for (id, credited_tier, face) in members {
                let share = get_share_conn(conn, &id)?.ok_or_else(|| {
                    GhostError::Database(format!("np share {} is missing", hex::encode(id)))
                })?;
                shares.push(NpBatchShare {
                    share,
                    credited_tier,
                    face,
                });
            }
            Ok(Some(NpBatch {
                anchor_hash: *anchor_hash,
                batch_root: blob32(root, "np batch batch_root")?,
                btc_height: u32_col(btc_height, "np batch btc_height")?,
                received_at,
                shares,
            }))
        })
    }

    /// Store one share outside any batch: an anchor's own share, which no batch of its own can
    /// carry (its job committed the batch before it was hashed). Idempotent; a different share
    /// under the same id is an error. Pruning keeps any share that is an anchor's own.
    pub fn np_insert_share(&self, s: &NpShareRecord) -> GhostResult<()> {
        self.transaction(|tx| insert_share_conn(tx, s))
    }

    /// One share, if held.
    pub fn np_get_share(&self, share_id: &ShareId) -> GhostResult<Option<NpShareRecord>> {
        self.with_connection(|conn| get_share_conn(conn, share_id))
    }

    /// Remove every batch whose anchor's `btc_height` is below `retention_height`, and every
    /// share no remaining batch carries and no anchor owns. Anchor headers, the ledger and its journals are kept.
    /// One transaction. Frees pages to SQLite's free list only: no VACUUM.
    pub fn np_prune_batches_below(&self, retention_height: u32) -> GhostResult<NpPruneReport> {
        self.transaction(|tx| {
            let h = retention_height as i64;
            let ids: Vec<Vec<u8>> = {
                let mut stmt = tx
                    .prepare(
                        "SELECT DISTINCT bs.share_id FROM np_batch_shares bs \
                         JOIN np_batches b ON b.anchor_hash = bs.anchor_hash \
                         WHERE b.btc_height < ?1",
                    )
                    .map_err(db_err)?;
                let rows = stmt
                    .query_map(params![h], |r| r.get(0))
                    .map_err(db_err)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(db_err)?;
                rows
            };
            let batch_shares = tx
                .execute(
                    "DELETE FROM np_batch_shares WHERE anchor_hash IN \
                     (SELECT anchor_hash FROM np_batches WHERE btc_height < ?1)",
                    params![h],
                )
                .map_err(db_err)?;
            let batches = tx
                .execute("DELETE FROM np_batches WHERE btc_height < ?1", params![h])
                .map_err(db_err)?;
            let mut shares = 0;
            for id in ids {
                shares += tx
                    .execute(
                        "DELETE FROM np_shares WHERE share_id = ?1 AND NOT EXISTS \
                         (SELECT 1 FROM np_batch_shares WHERE share_id = ?1) AND NOT EXISTS \
                         (SELECT 1 FROM np_anchors WHERE hash = ?1)",
                        params![id],
                    )
                    .map_err(db_err)?;
            }
            Ok(NpPruneReport {
                batches,
                batch_shares,
                shares,
            })
        })
    }

    // -----------------------------------------------------------------------------------------
    // Ledger
    // -----------------------------------------------------------------------------------------

    /// Apply one credit event atomically: `deltas` credited at share height `credit_height`
    /// through the pure core's `apply_credits`, keyed by `event_key` (the anchor whose batch
    /// earned them). Idempotent on an identical event; a different event under the same key is
    /// an error.
    ///
    /// The materialised table equals `canonical_payout::table_for` only if events are applied in
    /// that function's fold order; choosing the order is the caller's (W2.7).
    pub fn np_apply_credits(
        &self,
        event_key: &AnchorHash,
        credit_height: u32,
        deltas: &BTreeMap<Script, i128>,
        applied_at: i64,
    ) -> GhostResult<InsertOutcome> {
        let entries: Vec<(Script, i128)> = deltas.iter().map(|(s, d)| (s.clone(), *d)).collect();
        self.transaction(|tx| {
            apply_event_conn(
                tx,
                NpLedgerEventKind::Credit,
                event_key,
                credit_height,
                &entries,
                applied_at,
                |t| {
                    apply_credits(t, deltas, credit_height)
                        .map_err(|e| GhostError::PayoutCalculation(e.to_string()))
                },
            )
        })
    }

    /// Undo a credit event. It must be the most recent ledger event.
    pub fn np_undo_credits(&self, event_key: &AnchorHash) -> GhostResult<()> {
        self.transaction(|tx| undo_event_conn(tx, NpLedgerEventKind::Credit, event_key))
    }

    /// Apply a block's retirements atomically, in coinbase pay order, through the pure core's
    /// `apply_block`, and record them per block for reorg undo. Idempotent on an identical block;
    /// refuses a different block under the same hash, or a second block at a height whose block
    /// has not been undone.
    pub fn np_apply_block(
        &self,
        block_hash: &[u8; 32],
        height: u32,
        retired: &[Retirement],
        applied_at: i64,
    ) -> GhostResult<InsertOutcome> {
        self.transaction(|tx| {
            apply_event_conn(
                tx,
                NpLedgerEventKind::Block,
                block_hash,
                height,
                retired,
                applied_at,
                |t| {
                    apply_block(t, retired)
                        .map_err(|e| GhostError::PayoutCalculation(e.to_string()))
                },
            )
        })
    }

    /// Undo a block's retirements, restoring every touched row exactly. It must be the most
    /// recent ledger event: a reorg undoes blocks (and anything applied after them) newest first.
    pub fn np_undo_block(&self, block_hash: &[u8; 32]) -> GhostResult<()> {
        self.transaction(|tx| undo_event_conn(tx, NpLedgerEventKind::Block, block_hash))
    }

    /// Undo a block's retirements wherever it sits in the event log (settlement: a Bitcoin reorg,
    /// or a provisional block that turned out not to match). Every event applied after it is
    /// undone first, newest first, and re-applied in its original order afterwards, all in one
    /// transaction, so the result is exactly the log without the block.
    pub fn np_undo_block_anywhere(&self, block_hash: &[u8; 32]) -> GhostResult<()> {
        self.transaction(|tx| {
            let target =
                get_event_conn(tx, NpLedgerEventKind::Block, block_hash)?.ok_or_else(|| {
                    GhostError::Database(format!(
                        "np block {} is not applied",
                        hex::encode(block_hash)
                    ))
                })?;
            let mut above = Vec::new();
            while let Some(ev) = last_event_conn(tx)? {
                if ev.seq == target.seq {
                    break;
                }
                let entries = journal_entries_conn(tx, ev.kind, &ev.key)?;
                undo_event_conn(tx, ev.kind, &ev.key)?;
                above.push((ev, entries));
            }
            undo_event_conn(tx, NpLedgerEventKind::Block, block_hash)?;
            for (ev, entries) in above.into_iter().rev() {
                match ev.kind {
                    NpLedgerEventKind::Credit => {
                        let deltas: BTreeMap<Script, i128> = entries.iter().cloned().collect();
                        apply_event_conn(
                            tx,
                            ev.kind,
                            &ev.key,
                            ev.height,
                            &entries,
                            ev.applied_at,
                            |t| {
                                apply_credits(t, &deltas, ev.height)
                                    .map_err(|e| GhostError::PayoutCalculation(e.to_string()))
                            },
                        )?;
                    }
                    NpLedgerEventKind::Block => {
                        apply_event_conn(
                            tx,
                            ev.kind,
                            &ev.key,
                            ev.height,
                            &entries,
                            ev.applied_at,
                            |t| {
                                apply_block(t, &entries)
                                    .map_err(|e| GhostError::PayoutCalculation(e.to_string()))
                            },
                        )?;
                    }
                }
            }
            Ok(())
        })
    }

    /// Every applied block as `(height, block hash)`, by height.
    pub fn np_applied_blocks(&self) -> GhostResult<Vec<(u32, [u8; 32])>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT height, event_key FROM np_ledger_events WHERE kind = 1 \
                     ORDER BY height",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)))
                .map_err(db_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_err)?;
            rows.into_iter()
                .map(|(h, k)| Ok((u32_col(h, "np block height")?, blob32(k, "np block hash")?)))
                .collect()
        })
    }

    /// A block's recorded retirements in pay order, if the block is applied.
    pub fn np_block_retirements(
        &self,
        block_hash: &[u8; 32],
    ) -> GhostResult<Option<Vec<Retirement>>> {
        self.with_connection(|conn| {
            if get_event_conn(conn, NpLedgerEventKind::Block, block_hash)?.is_none() {
                return Ok(None);
            }
            journal_entries_conn(conn, NpLedgerEventKind::Block, block_hash).map(Some)
        })
    }

    /// The most recently applied ledger event, if any.
    pub fn np_last_ledger_event(&self) -> GhostResult<Option<NpLedgerEvent>> {
        self.with_connection(last_event_conn)
    }

    /// One payee's materialised balance, if it has a row.
    pub fn np_balance(&self, script: &[u8]) -> GhostResult<Option<Balance>> {
        self.with_connection(|conn| get_balance_conn(conn, script))
    }

    /// The whole materialised table.
    pub fn np_ledger_table(&self) -> GhostResult<Table> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare("SELECT script, owed, queue_since FROM np_ledger")
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Option<i64>>(2)?,
                    ))
                })
                .map_err(db_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_err)?;
            rows.into_iter()
                .map(|(s, o, q)| {
                    Ok((
                        s,
                        Balance {
                            owed: face_from_blob(&o)?,
                            queue_since: q
                                .map(|q| u32_col(q, "np ledger queue_since"))
                                .transpose()?,
                        },
                    ))
                })
                .collect()
        })
    }

    /// The table block `h` is built on: credits of share height `<= cut(h)` and the retirements
    /// of blocks below `h`, folded from the applied journals by the pure core's `table_for`.
    pub fn np_table_for_block(&self, h: u32) -> GhostResult<Table> {
        let (credits, blocks) = self.with_connection(|conn| {
            let mut credits: BTreeMap<u32, BTreeMap<Script, i128>> = BTreeMap::new();
            let mut stmt = conn
                .prepare("SELECT credit_height, script, amount FROM np_credits")
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                })
                .map_err(db_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_err)?;
            for (c, s, a) in rows {
                let slot = credits
                    .entry(u32_col(c, "np credit height")?)
                    .or_default()
                    .entry(s)
                    .or_insert(0);
                *slot = slot.checked_add(face_from_blob(&a)?).ok_or_else(|| {
                    GhostError::PayoutCalculation("credit sum overflow".to_string())
                })?;
            }
            let mut blocks: BTreeMap<u32, Vec<Retirement>> = BTreeMap::new();
            let mut stmt = conn
                .prepare(
                    "SELECT height, script, amount FROM np_retirements ORDER BY height, position",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                })
                .map_err(db_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_err)?;
            for (b, s, a) in rows {
                blocks
                    .entry(u32_col(b, "np retirement height")?)
                    .or_default()
                    .push((s, face_from_blob(&a)?));
            }
            Ok((credits, blocks))
        })?;
        table_for(h, &credits, &blocks).map_err(|e| GhostError::PayoutCalculation(e.to_string()))
    }

    // -----------------------------------------------------------------------------------------
    // Snapshot roots
    // -----------------------------------------------------------------------------------------

    /// Pin a snapshot root for `(cut_height, anchor_hash)`. Idempotent on the same root and row
    /// count; a different root for the same snapshot is an error (the table is a pure function
    /// of the anchor's ancestry, so two roots mean a fault).
    pub fn np_pin_snapshot(&self, s: &NpSnapshotRoot) -> GhostResult<InsertOutcome> {
        let row_count = i64::try_from(s.row_count)
            .map_err(|_| GhostError::Database("snapshot row count exceeds i64".to_string()))?;
        self.transaction(|tx| {
            tx.execute(
                "INSERT OR IGNORE INTO np_snapshot_roots (cut_height, anchor_hash, table_root, \
                 row_count, pinned_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    s.cut_height as i64,
                    s.anchor_hash.to_vec(),
                    s.table_root.to_vec(),
                    row_count,
                    s.pinned_at
                ],
            )
            .map_err(db_err)?;
            let inserted = wrote(tx);
            let held: Option<(Vec<u8>, i64)> = tx
                .query_row(
                    "SELECT table_root, row_count FROM np_snapshot_roots \
                     WHERE cut_height = ?1 AND anchor_hash = ?2",
                    params![s.cut_height as i64, s.anchor_hash.to_vec()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(db_err)?;
            match held {
                Some((root, n)) if root == s.table_root && n == row_count => Ok(if inserted {
                    InsertOutcome::Inserted
                } else {
                    InsertOutcome::AlreadyPresent
                }),
                Some(_) => Err(GhostError::Database(format!(
                    "snapshot at cut {} on anchor {} is pinned with a different root",
                    s.cut_height,
                    hex::encode(s.anchor_hash)
                ))),
                None => Err(GhostError::Database(format!(
                    "snapshot at cut {} was not stored (insert ignored, no row present)",
                    s.cut_height
                ))),
            }
        })
    }

    /// Every snapshot root pinned at `cut_height` (one per snapshot anchor held).
    pub fn np_snapshot_roots_at(&self, cut_height: u32) -> GhostResult<Vec<NpSnapshotRoot>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT anchor_hash, table_root, row_count, pinned_at FROM np_snapshot_roots \
                     WHERE cut_height = ?1 ORDER BY anchor_hash",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map(params![cut_height as i64], |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                })
                .map_err(db_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_err)?;
            rows.into_iter()
                .map(|(a, root, n, at)| {
                    Ok(NpSnapshotRoot {
                        cut_height,
                        anchor_hash: blob32(a, "np snapshot anchor")?,
                        table_root: blob32(root, "np snapshot root")?,
                        row_count: u64::try_from(n).map_err(|_| {
                            GhostError::Database(format!("snapshot row count {n} is negative"))
                        })?,
                        pinned_at: at,
                    })
                })
                .collect()
        })
    }

    // -----------------------------------------------------------------------------------------
    // Bitcoin block archive (W2.13)
    // -----------------------------------------------------------------------------------------

    /// Archive a Bitcoin block. The header must hash to `hash`. Idempotent; a block already held
    /// without its coinbase gains it; a different header or coinbase under the same hash is an
    /// error. Checking the header's work and the coinbase's merkle branch is the caller's.
    pub fn np_put_btc_block(&self, b: &NpBtcBlock) -> GhostResult<InsertOutcome> {
        if sha256d(&b.header) != b.hash {
            return Err(GhostError::Database(format!(
                "np btc block {} is not sha256d of its header",
                hex::encode(b.hash)
            )));
        }
        let (cb, br) = match &b.coinbase {
            Some((c, br)) => (Some(c.clone()), Some(branch_to_blob(br))),
            None => (None, None),
        };
        self.transaction(|tx| {
            tx.execute(
                "INSERT OR IGNORE INTO np_btc_blocks (hash, prev, height, header, coinbase, \
                 branch, received_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    b.hash.to_vec(),
                    b.header[4..36].to_vec(),
                    b.height as i64,
                    b.header.to_vec(),
                    cb,
                    br,
                    b.received_at
                ],
            )
            .map_err(db_err)?;
            if wrote(tx) {
                return Ok(InsertOutcome::Inserted);
            }
            let held = get_btc_block_conn(tx, &b.hash)?.ok_or_else(|| {
                GhostError::Database(format!(
                    "np btc block {} was not stored (insert ignored, no row present)",
                    hex::encode(b.hash)
                ))
            })?;
            if held.header != b.header || held.height != b.height {
                return Err(GhostError::Database(format!(
                    "np btc block {} is already held with a different header",
                    hex::encode(b.hash)
                )));
            }
            match (&held.coinbase, &b.coinbase) {
                (Some(h), Some(n)) if h != n => Err(GhostError::Database(format!(
                    "np btc block {} is already held with a different coinbase",
                    hex::encode(b.hash)
                ))),
                (None, Some(_)) => {
                    tx.execute(
                        "UPDATE np_btc_blocks SET coinbase = ?2, branch = ?3 WHERE hash = ?1",
                        params![b.hash.to_vec(), cb, br],
                    )
                    .map_err(db_err)?;
                    Ok(InsertOutcome::Inserted)
                }
                _ => Ok(InsertOutcome::AlreadyPresent),
            }
        })
    }

    /// One archived block, if held.
    pub fn np_get_btc_block(&self, hash: &[u8; 32]) -> GhostResult<Option<NpBtcBlock>> {
        self.with_connection(|conn| get_btc_block_conn(conn, hash))
    }

    /// Every archived block, by height.
    pub fn np_load_btc_blocks(&self) -> GhostResult<Vec<NpBtcBlock>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT hash, height, header, coinbase, branch, received_at FROM \
                     np_btc_blocks ORDER BY height, hash",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], btc_row)
                .map_err(db_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_err)?;
            rows.into_iter().map(RawBtcBlock::decode).collect()
        })
    }

    // -----------------------------------------------------------------------------------------
    // Checkpoints (W2.13)
    // -----------------------------------------------------------------------------------------

    /// Store a checkpoint, replacing any at the same anchor.
    pub fn np_put_checkpoint(&self, c: &NpCheckpoint) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO np_checkpoints (anchor_hash, height, btc_height, payload, digest, \
                 created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT(anchor_hash) DO UPDATE \
                 SET height = excluded.height, btc_height = excluded.btc_height, \
                 payload = excluded.payload, digest = excluded.digest, \
                 created_at = excluded.created_at",
                params![
                    c.anchor_hash.to_vec(),
                    c.height as i64,
                    c.btc_height as i64,
                    c.payload,
                    c.digest.to_vec(),
                    c.created_at
                ],
            )
            .map_err(db_err)?;
            if !wrote(conn) {
                return Err(GhostError::Database(
                    "np checkpoint was not stored".to_string(),
                ));
            }
            Ok(())
        })
    }

    /// Every stored checkpoint, newest (highest anchor) first.
    pub fn np_load_checkpoints(&self) -> GhostResult<Vec<NpCheckpoint>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT anchor_hash, height, btc_height, payload, digest, created_at FROM \
                     np_checkpoints ORDER BY height DESC, anchor_hash",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                        r.get::<_, Vec<u8>>(4)?,
                        r.get::<_, i64>(5)?,
                    ))
                })
                .map_err(db_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_err)?;
            rows.into_iter()
                .map(|(a, h, b, payload, d, at)| {
                    Ok(NpCheckpoint {
                        anchor_hash: blob32(a, "np checkpoint anchor")?,
                        height: u32_col(h, "np checkpoint height")?,
                        btc_height: u32_col(b, "np checkpoint btc_height")?,
                        payload,
                        digest: blob32(d, "np checkpoint digest")?,
                        created_at: at,
                    })
                })
                .collect()
        })
    }

    /// Every stored checkpoint without its payload, newest (highest anchor) first: what a status
    /// page shows, without reading the folded state.
    pub fn np_checkpoint_heads(&self) -> GhostResult<Vec<NpCheckpointHead>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT anchor_hash, height, btc_height, digest, created_at FROM \
                     np_checkpoints ORDER BY height DESC, anchor_hash",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                        r.get::<_, i64>(4)?,
                    ))
                })
                .map_err(db_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_err)?;
            rows.into_iter()
                .map(|(a, h, b, d, at)| {
                    Ok(NpCheckpointHead {
                        anchor_hash: blob32(a, "np checkpoint anchor")?,
                        height: u32_col(h, "np checkpoint height")?,
                        btc_height: u32_col(b, "np checkpoint btc_height")?,
                        digest: blob32(d, "np checkpoint digest")?,
                        created_at: at,
                    })
                })
                .collect()
        })
    }

    /// Remove the checkpoint at `anchor_hash`, if any.
    pub fn np_delete_checkpoint(&self, anchor_hash: &AnchorHash) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "DELETE FROM np_checkpoints WHERE anchor_hash = ?1",
                params![anchor_hash.to_vec()],
            )
            .map_err(db_err)?;
            Ok(())
        })
    }

    // -----------------------------------------------------------------------------------------
    // Sensing
    // -----------------------------------------------------------------------------------------

    /// Record the latest sensing result for a miner and user agent, replacing the earlier one.
    pub fn np_record_sensing(&self, s: &NpMinerSensing) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO np_miner_sensing (miner_script, user_agent, highest_pass_class, \
                 failed_class, sensed_at) VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(miner_script, user_agent) DO UPDATE SET \
                 highest_pass_class = excluded.highest_pass_class, \
                 failed_class = excluded.failed_class, sensed_at = excluded.sensed_at",
                params![
                    s.miner_script,
                    s.user_agent,
                    s.highest_pass_class.map(|c| c as i64),
                    s.failed_class.map(|c| c as i64),
                    s.sensed_at
                ],
            )
            .map_err(db_err)?;
            if !wrote(conn) {
                return Err(GhostError::Database(
                    "np sensing result was not stored".to_string(),
                ));
            }
            Ok(())
        })
    }

    /// Every sensing result held for a miner, one per user agent.
    pub fn np_sensing_for(&self, miner_script: &[u8]) -> GhostResult<Vec<NpMinerSensing>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT user_agent, highest_pass_class, failed_class, sensed_at \
                     FROM np_miner_sensing WHERE miner_script = ?1 ORDER BY user_agent",
                )
                .map_err(db_err)?;
            let rows = stmt
                .query_map(params![miner_script], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<i64>>(1)?,
                        r.get::<_, Option<i64>>(2)?,
                        r.get::<_, i64>(3)?,
                    ))
                })
                .map_err(db_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_err)?;
            rows.into_iter()
                .map(|(ua, pass, fail, at)| {
                    Ok(NpMinerSensing {
                        miner_script: miner_script.to_vec(),
                        user_agent: ua,
                        highest_pass_class: pass
                            .map(|c| u16_col(c, "np sensing pass class"))
                            .transpose()?,
                        failed_class: fail
                            .map(|c| u16_col(c, "np sensing failed class"))
                            .transpose()?,
                        sensed_at: at,
                    })
                })
                .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::canonical_payout::table_root;
    use ghost_common::node_pool_constants::FACE_PER_SAT;

    fn db() -> Database {
        Database::in_memory().expect("in-memory db")
    }

    fn h(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn script(b: u8) -> Script {
        let mut s = vec![0x00, 0x14];
        s.extend_from_slice(&[b; 20]);
        s
    }

    fn anchor(hash: u8, parent: Option<u8>, height: u32, btc_height: u32) -> NpAnchorRecord {
        NpAnchorRecord {
            hash: h(hash),
            parent: parent.map(h),
            height,
            t_net: 10,
            btc_height,
            cum_work: U256::pow2(18 + height).expect("work"),
            batch_root: [hash ^ 0x5A; 32],
            received_at: 1_700_000_000,
        }
    }

    fn share(seed: u8) -> NpShareRecord {
        let mut header = [seed; 80];
        header[0] = 0x20;
        NpShareRecord {
            share_id: sha256d(&header),
            header,
            coinbase: vec![0x01, seed, 0x02, seed, seed],
            merkle_branch: vec![[seed; 32], [seed.wrapping_add(1); 32]],
            tag: ShareTagPreimage {
                node_id: [seed; 32],
                tier: 12,
                slot_class: 44,
                payee_script: script(seed),
                parent_anchor: h(1),
                batch_root: [seed ^ 0xFF; 32],
            },
            job_height: 900_000 + seed as u32,
        }
    }

    fn member(seed: u8, face: u128) -> NpBatchShare {
        NpBatchShare {
            share: share(seed),
            credited_tier: 12,
            face,
        }
    }

    fn count(db: &Database, table: &str) -> i64 {
        db.with_connection(|c| {
            c.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .map_err(db_err)
        })
        .expect("count")
    }

    /// 30 BTC in face units: above `i64::MAX` (about 21.47 BTC).
    const BIG: i128 = 3_000_000_000 * FACE_PER_SAT;

    // -- blobs ---------------------------------------------------------------------------------

    #[test]
    fn face_blobs_round_trip_past_i64_and_below_zero() {
        assert!(
            BIG > i64::MAX as i128,
            "the test value must exceed an SQLite INTEGER"
        );
        for v in [
            0,
            1,
            -1,
            BIG,
            -BIG,
            i64::MAX as i128 + 1,
            i64::MIN as i128 - 1,
            i128::MAX,
            i128::MIN,
        ] {
            let b = face_to_blob(v);
            assert_eq!(face_from_blob(&b).expect("decode"), v, "value {v}");
        }
        // The encoding is table_root's: sign-extended big-endian.
        assert_eq!(face_to_blob(-1), [0xFF; 32]);
        assert_eq!(face_to_blob(1)[31], 1);
        assert!(face_to_blob(1)[..31].iter().all(|b| *b == 0));
    }

    #[test]
    fn face_blob_outside_i128_or_wrong_length_is_refused() {
        let mut b = face_to_blob(5);
        b[0] = 1;
        assert!(face_from_blob(&b).is_err());
        let mut b = face_to_blob(-5);
        b[3] = 0;
        assert!(face_from_blob(&b).is_err());
        assert!(face_from_blob(&[0u8; 31]).is_err());
        assert!(face_from_blob(&[0u8; 33]).is_err());
        assert!(face_u128_to_blob(u128::MAX).is_err());
    }

    /// Why every `INSERT OR IGNORE` here is followed by a read: OR IGNORE also swallows CHECK
    /// failures, returning success with no row written.
    #[test]
    fn insert_or_ignore_swallows_a_check_failure() {
        let db = db();
        db.with_connection(|c| {
            c.execute(
                "INSERT OR IGNORE INTO np_snapshot_roots (cut_height, anchor_hash, table_root, \
                 row_count, pinned_at) VALUES (1, ?1, ?2, 0, 0)",
                params![vec![0u8; 31], vec![0u8; 32]],
            )
            .map_err(db_err)?;
            assert_eq!(c.changes(), 0);
            Ok(())
        })
        .expect("OR IGNORE returns Ok on a CHECK failure");
        assert_eq!(count(&db, "np_snapshot_roots"), 0);
    }

    // -- anchors -------------------------------------------------------------------------------

    #[test]
    fn anchors_round_trip_and_insert_idempotently() {
        let db = db();
        let g = anchor(1, None, 0, 100);
        let a = anchor(2, Some(1), 1, 100);
        let mut big = anchor(3, Some(2), 2, 101);
        big.cum_work = U256::pow2(255).expect("2^255");

        assert_eq!(db.np_insert_anchor(&big).unwrap(), InsertOutcome::Inserted);
        assert_eq!(db.np_insert_anchor(&a).unwrap(), InsertOutcome::Inserted);
        assert_eq!(db.np_insert_anchor(&g).unwrap(), InsertOutcome::Inserted);

        let mut later = a.clone();
        later.received_at += 600;
        assert_eq!(
            db.np_insert_anchor(&later).unwrap(),
            InsertOutcome::AlreadyPresent,
            "a later copy of the same anchor is the same anchor"
        );
        assert_eq!(db.np_get_anchor(&a.hash).unwrap(), Some(a.clone()));
        assert_eq!(db.np_get_anchor(&big.hash).unwrap(), Some(big.clone()));
        assert_eq!(db.np_get_anchor(&h(9)).unwrap(), None);

        let loaded = db.np_load_anchors().unwrap();
        assert_eq!(loaded, vec![g, a.clone(), big], "parents before children");

        let mut forged = a.clone();
        forged.btc_height = 99;
        let err = db.np_insert_anchor(&forged).unwrap_err();
        assert!(err.to_string().contains("different contents"), "{err}");
        assert_eq!(db.np_get_anchor(&a.hash).unwrap(), Some(a));
    }

    // -- batches -------------------------------------------------------------------------------

    #[test]
    fn batches_round_trip_and_insert_idempotently() {
        let db = db();
        db.np_insert_anchor(&anchor(1, None, 0, 100)).unwrap();
        let shares = vec![
            member(10, 5),
            member(11, u64::MAX as u128 * 7),
            member(12, 0),
        ];
        assert!(!db.np_has_batch(&h(1)).unwrap());
        assert_eq!(
            db.np_insert_batch(&h(1), &shares, 1_700_000_001).unwrap(),
            InsertOutcome::Inserted
        );
        assert!(db.np_has_batch(&h(1)).unwrap());

        let got = db.np_get_batch(&h(1)).unwrap().expect("held");
        assert_eq!(got.anchor_hash, h(1));
        assert_eq!(got.batch_root, anchor(1, None, 0, 100).batch_root);
        assert_eq!(got.btc_height, 100);
        assert_eq!(got.received_at, 1_700_000_001);
        assert_eq!(got.shares, shares);
        assert_eq!(
            db.np_get_share(&share(11).share_id).unwrap(),
            Some(share(11))
        );

        assert_eq!(
            db.np_insert_batch(&h(1), &shares, 1_700_000_999).unwrap(),
            InsertOutcome::AlreadyPresent
        );
        let reordered = vec![
            member(11, u64::MAX as u128 * 7),
            member(10, 5),
            member(12, 0),
        ];
        assert!(db.np_insert_batch(&h(1), &reordered, 0).is_err());
        let shorter = vec![member(10, 5)];
        assert!(db.np_insert_batch(&h(1), &shorter, 0).is_err());
        assert_eq!(
            db.np_get_batch(&h(1)).unwrap().expect("held").shares,
            shares
        );
        assert_eq!(count(&db, "np_shares"), 3);
    }

    #[test]
    fn a_bad_batch_is_refused_whole() {
        let db = db();
        db.np_insert_anchor(&anchor(1, None, 0, 100)).unwrap();

        assert!(
            db.np_insert_batch(&h(7), &[member(10, 1)], 0).is_err(),
            "unknown anchor"
        );

        let mut bad = member(11, 1);
        bad.share.header[5] ^= 1;
        let err = db
            .np_insert_batch(&h(1), &[member(10, 1), bad], 0)
            .unwrap_err();
        assert!(err.to_string().contains("sha256d"), "{err}");

        let err = db
            .np_insert_batch(&h(1), &[member(10, 1), member(10, 1)], 0)
            .unwrap_err();
        assert!(err.to_string().contains("UNIQUE"), "{err}");

        // A share held with other contents under the same id is refused, not overwritten.
        db.np_insert_anchor(&anchor(2, Some(1), 1, 100)).unwrap();
        db.np_insert_batch(&h(2), &[member(20, 1)], 0).unwrap();
        let mut altered = member(20, 1);
        altered.share.coinbase.push(0);
        db.np_insert_anchor(&anchor(3, Some(1), 1, 100)).unwrap();
        let err = db.np_insert_batch(&h(3), &[altered], 0).unwrap_err();
        assert!(err.to_string().contains("different contents"), "{err}");

        for a in [1, 3] {
            assert!(!db.np_has_batch(&h(a)).unwrap(), "anchor {a}: nothing kept");
        }
        assert_eq!(count(&db, "np_shares"), 1);
        assert_eq!(count(&db, "np_batch_shares"), 1);
        assert_eq!(
            db.np_get_share(&share(20).share_id).unwrap(),
            Some(share(20))
        );
    }

    #[test]
    fn prune_drops_old_batches_and_orphaned_shares_only() {
        let db = db();
        db.np_insert_anchor(&anchor(1, None, 0, 100)).unwrap();
        db.np_insert_anchor(&anchor(2, Some(1), 1, 120)).unwrap();
        db.np_insert_anchor(&anchor(3, Some(2), 2, 200)).unwrap();
        // Share 11 sits on a losing fork's batch and is re-included by anchor 3.
        db.np_insert_batch(&h(1), &[member(10, 1)], 0).unwrap();
        db.np_insert_batch(&h(2), &[member(11, 1), member(12, 1)], 0)
            .unwrap();
        db.np_insert_batch(&h(3), &[member(11, 1), member(13, 1)], 0)
            .unwrap();

        let r = db.np_prune_batches_below(150).unwrap();
        assert_eq!(
            r,
            NpPruneReport {
                batches: 2,
                batch_shares: 3,
                shares: 2
            }
        );
        assert!(!db.np_has_batch(&h(1)).unwrap());
        assert!(!db.np_has_batch(&h(2)).unwrap());
        assert_eq!(
            db.np_get_batch(&h(3)).unwrap().expect("kept").shares,
            vec![member(11, 1), member(13, 1)]
        );
        assert_eq!(db.np_get_share(&share(10).share_id).unwrap(), None);
        assert_eq!(db.np_get_share(&share(12).share_id).unwrap(), None);
        assert_eq!(db.np_load_anchors().unwrap().len(), 3, "headers are kept");

        assert_eq!(
            db.np_prune_batches_below(150).unwrap(),
            NpPruneReport::default()
        );
    }

    #[test]
    fn an_anchors_own_share_is_stored_alone_and_survives_pruning() {
        let db = db();
        db.np_insert_anchor(&anchor(1, None, 0, 100)).unwrap();
        // Share 30 is an anchor's own share, later included in anchor 1's (old) batch.
        let own = share(30);
        db.np_insert_share(&own).unwrap();
        db.np_insert_share(&own).unwrap();
        let mut altered = own.clone();
        altered.coinbase.push(0);
        assert!(db.np_insert_share(&altered).is_err());
        let mut rec = anchor(2, Some(1), 1, 100);
        rec.hash = own.share_id;
        db.np_insert_anchor(&rec).unwrap();
        db.np_insert_batch(&h(1), &[member(30, 1), member(31, 1)], 0)
            .unwrap();
        let r = db.np_prune_batches_below(150).unwrap();
        assert_eq!((r.batches, r.shares), (1, 1));
        assert_eq!(db.np_get_share(&own.share_id).unwrap(), Some(own));
        assert_eq!(db.np_get_share(&share(31).share_id).unwrap(), None);
    }

    // -- ledger --------------------------------------------------------------------------------

    fn credits(rows: &[(u8, i128)]) -> BTreeMap<Script, i128> {
        rows.iter().map(|(s, d)| (script(*s), *d)).collect()
    }

    #[test]
    fn reorg_undo_restores_balances_exactly() {
        let db = db();
        db.np_apply_credits(
            &h(1),
            100,
            &credits(&[(1, BIG), (2, 5_000 * FACE_PER_SAT), (3, 7)]),
            0,
        )
        .unwrap();
        let before = db.np_ledger_table().unwrap();
        assert_eq!(before.len(), 3);
        assert_eq!(
            before[&script(1)].owed,
            BIG,
            "a balance above 21.47 BTC survives storage"
        );
        assert_eq!(before[&script(1)].queue_since, Some(100));
        assert_eq!(before[&script(3)].queue_since, None, "below the floor");

        // Block A pays 1 in part, 2 in full, and retires an unknown payee (another fork's table).
        let retired: Vec<Retirement> = vec![
            (script(2), 5_000 * FACE_PER_SAT),
            (script(1), 1_000_000 * FACE_PER_SAT),
            (script(9), 2_000 * FACE_PER_SAT),
        ];
        assert_eq!(
            db.np_apply_block(&h(0xA0), 121, &retired, 0).unwrap(),
            InsertOutcome::Inserted
        );
        let after = db.np_ledger_table().unwrap();
        let mut expect = before.clone();
        apply_block(&mut expect, &retired).unwrap();
        assert_eq!(after, expect, "the stored arithmetic is the pure core's");
        assert_eq!(
            after[&script(9)].owed,
            -2_000 * FACE_PER_SAT,
            "negative balances survive"
        );
        assert_eq!(
            after[&script(2)].queue_since,
            None,
            "paid to zero leaves the queue"
        );
        assert_eq!(
            db.np_block_retirements(&h(0xA0)).unwrap(),
            Some(retired.clone())
        );

        // A second block at 121 is refused while A stands.
        let err = db
            .np_apply_block(&h(0xB0), 121, &retired[..1], 0)
            .unwrap_err();
        assert!(err.to_string().contains("undo it"), "{err}");

        // Reorg: undo A, apply B.
        db.np_undo_block(&h(0xA0)).unwrap();
        let undone = db.np_ledger_table().unwrap();
        assert_eq!(
            undone, before,
            "undo restores every row, including absent ones"
        );
        assert_eq!(table_root(&undone), table_root(&before));
        assert_eq!(db.np_block_retirements(&h(0xA0)).unwrap(), None);
        assert_eq!(count(&db, "np_retirements"), 0);
        db.np_apply_block(&h(0xB0), 121, &retired[..1], 0).unwrap();
        assert_eq!(db.np_balance(&script(2)).unwrap().expect("row").owed, 0);
        assert_eq!(db.np_balance(&script(9)).unwrap(), None);
    }

    #[test]
    fn undo_is_last_in_first_out() {
        let db = db();
        db.np_apply_credits(&h(1), 100, &credits(&[(1, 2_000 * FACE_PER_SAT)]), 0)
            .unwrap();
        db.np_apply_block(&h(0xA0), 121, &[(script(1), 1_500 * FACE_PER_SAT)], 0)
            .unwrap();
        db.np_apply_credits(&h(2), 101, &credits(&[(1, 3_000 * FACE_PER_SAT)]), 0)
            .unwrap();
        let top = db.np_ledger_table().unwrap();

        let err = db.np_undo_block(&h(0xA0)).unwrap_err();
        assert!(err.to_string().contains("last-in first-out"), "{err}");
        assert_eq!(
            db.np_ledger_table().unwrap(),
            top,
            "a refused undo changes nothing"
        );
        assert!(db.np_undo_block(&h(0xEE)).is_err(), "not applied");

        let last = db.np_last_ledger_event().unwrap().expect("event");
        assert_eq!(
            (last.kind, last.key, last.height),
            (NpLedgerEventKind::Credit, h(2), 101)
        );
        db.np_undo_credits(&h(2)).unwrap();
        db.np_undo_block(&h(0xA0)).unwrap();
        db.np_undo_credits(&h(1)).unwrap();
        assert!(db.np_ledger_table().unwrap().is_empty());
        assert_eq!(db.np_last_ledger_event().unwrap(), None);
        for t in [
            "np_ledger_events",
            "np_credits",
            "np_retirements",
            "np_ledger",
        ] {
            assert_eq!(count(&db, t), 0, "{t}");
        }
    }

    #[test]
    fn a_block_under_later_events_undoes_as_if_it_never_happened() {
        let replay = |with_block: bool| {
            let db = db();
            db.np_apply_credits(&h(1), 100, &credits(&[(1, 2_000 * FACE_PER_SAT)]), 0)
                .unwrap();
            if with_block {
                db.np_apply_block(&h(0xA0), 121, &[(script(1), 1_500 * FACE_PER_SAT)], 0)
                    .unwrap();
            }
            db.np_apply_credits(&h(2), 101, &credits(&[(1, 3_000 * FACE_PER_SAT)]), 0)
                .unwrap();
            db.np_apply_block(&h(0xB0), 122, &[(script(1), 2_000 * FACE_PER_SAT)], 0)
                .unwrap();
            db.np_apply_credits(&h(3), 102, &credits(&[(2, 4_000 * FACE_PER_SAT)]), 0)
                .unwrap();
            db
        };
        let db = replay(true);
        assert_eq!(
            db.np_applied_blocks().unwrap(),
            vec![(121, h(0xA0)), (122, h(0xB0))]
        );
        db.np_undo_block_anywhere(&h(0xA0)).unwrap();
        let without = replay(false);
        assert_eq!(
            db.np_ledger_table().unwrap(),
            without.np_ledger_table().unwrap()
        );
        assert_eq!(db.np_applied_blocks().unwrap(), vec![(122, h(0xB0))]);
        assert_eq!(
            db.np_block_retirements(&h(0xB0)).unwrap(),
            Some(vec![(script(1), 2_000 * FACE_PER_SAT)])
        );
        assert_eq!(
            db.np_table_for_block(200).unwrap(),
            without.np_table_for_block(200).unwrap()
        );
        // The re-applied events keep their order: the last is still credit 3, and LIFO undo
        // still works from it.
        let last = db.np_last_ledger_event().unwrap().unwrap();
        assert_eq!((last.kind, last.key), (NpLedgerEventKind::Credit, h(3)));
        db.np_undo_credits(&h(3)).unwrap();
        db.np_undo_block(&h(0xB0)).unwrap();
        assert!(db.np_undo_block_anywhere(&h(0xA0)).is_err(), "not applied");
    }

    #[test]
    fn ledger_events_apply_idempotently() {
        let db = db();
        let c = credits(&[(1, BIG), (2, -3)]);
        assert_eq!(
            db.np_apply_credits(&h(1), 100, &c, 0).unwrap(),
            InsertOutcome::Inserted
        );
        let t = db.np_ledger_table().unwrap();
        assert_eq!(
            db.np_apply_credits(&h(1), 100, &c, 99).unwrap(),
            InsertOutcome::AlreadyPresent
        );
        assert_eq!(
            db.np_ledger_table().unwrap(),
            t,
            "a retry does not credit twice"
        );
        assert!(
            db.np_apply_credits(&h(1), 101, &c, 0).is_err(),
            "other height, same key"
        );
        assert!(
            db.np_apply_credits(&h(1), 100, &credits(&[(1, BIG)]), 0)
                .is_err(),
            "other credits, same key"
        );

        let r = vec![(script(1), FACE_PER_SAT)];
        db.np_apply_block(&h(0xA0), 130, &r, 0).unwrap();
        let t = db.np_ledger_table().unwrap();
        assert_eq!(
            db.np_apply_block(&h(0xA0), 130, &r, 5).unwrap(),
            InsertOutcome::AlreadyPresent
        );
        assert_eq!(db.np_ledger_table().unwrap(), t);
        assert!(db
            .np_apply_block(&h(0xA0), 130, &[(script(1), 2)], 0)
            .is_err());
        assert_eq!(db.np_ledger_table().unwrap(), t);
    }

    #[test]
    fn a_failed_apply_rolls_back_whole() {
        let db = db();
        db.np_apply_credits(&h(1), 100, &credits(&[(1, i128::MAX)]), 0)
            .unwrap();
        let t = db.np_ledger_table().unwrap();
        // Credit 2 is fine, credit 1 overflows: neither may land, nor the event.
        let err = db
            .np_apply_credits(&h(2), 101, &credits(&[(1, 1), (2, 5)]), 0)
            .unwrap_err();
        assert!(matches!(err, GhostError::PayoutCalculation(_)), "{err}");
        assert_eq!(db.np_ledger_table().unwrap(), t);
        assert_eq!(count(&db, "np_ledger_events"), 1);
        assert_eq!(count(&db, "np_credits"), 1);
    }

    #[test]
    fn table_for_block_matches_the_pure_fold() {
        let db = db();
        let mut cmap: BTreeMap<u32, BTreeMap<Script, i128>> = BTreeMap::new();
        let mut bmap: BTreeMap<u32, Vec<Retirement>> = BTreeMap::new();
        let f = FACE_PER_SAT;
        // Fold order: credits of share height c land at table height c + 20, block P after them.
        type Step = (u32, Option<BTreeMap<Script, i128>>, Option<Vec<Retirement>>);
        let plan: Vec<Step> = vec![
            (100, Some(credits(&[(1, BIG), (2, 1_200 * f)])), None),
            (101, Some(credits(&[(2, 400 * f), (3, 999 * f)])), None),
            (102, Some(credits(&[(3, 2 * f), (4, 50_000 * f)])), None),
            (
                121,
                None,
                Some(vec![(script(1), 310_937_500 * f), (script(2), 1_200 * f)]),
            ),
            (
                122,
                None,
                Some(vec![(script(2), 400 * f), (script(4), 50_000 * f)]),
            ),
        ];
        for (i, (hgt, c, b)) in plan.into_iter().enumerate() {
            if let Some(c) = c {
                db.np_apply_credits(&h(i as u8), hgt, &c, 0).unwrap();
                cmap.insert(hgt, c);
            }
            if let Some(b) = b {
                db.np_apply_block(&h(0x80 + i as u8), hgt, &b, 0).unwrap();
                bmap.insert(hgt, b);
            }
        }
        for hgt in [100, 120, 121, 122, 123, 200] {
            let pure = table_for(hgt, &cmap, &bmap).unwrap();
            let stored = db.np_table_for_block(hgt).unwrap();
            assert_eq!(stored, pure, "table for block {hgt}");
        }
        // Every credit is cut in and every block is below 200, so the fold is the materialised
        // table.
        assert_eq!(
            db.np_table_for_block(200).unwrap(),
            db.np_ledger_table().unwrap()
        );
        assert!(db.np_table_for_block(119).unwrap().is_empty());
    }

    // -- snapshots and sensing -----------------------------------------------------------------

    #[test]
    fn snapshot_roots_pin_idempotently() {
        let db = db();
        let s = NpSnapshotRoot {
            cut_height: 974_480,
            anchor_hash: h(3),
            table_root: h(0xCC),
            row_count: 12_345,
            pinned_at: 1,
        };
        assert_eq!(db.np_pin_snapshot(&s).unwrap(), InsertOutcome::Inserted);
        let mut again = s;
        again.pinned_at = 2;
        assert_eq!(
            db.np_pin_snapshot(&again).unwrap(),
            InsertOutcome::AlreadyPresent
        );
        let mut other_fork = s;
        other_fork.anchor_hash = h(4);
        other_fork.table_root = h(0xDD);
        assert_eq!(
            db.np_pin_snapshot(&other_fork).unwrap(),
            InsertOutcome::Inserted
        );
        let mut conflict = s;
        conflict.table_root = h(0xEE);
        assert!(db.np_pin_snapshot(&conflict).is_err());

        assert_eq!(
            db.np_snapshot_roots_at(974_480).unwrap(),
            vec![s, other_fork]
        );
        assert!(db.np_snapshot_roots_at(974_481).unwrap().is_empty());
    }

    #[test]
    fn sensing_keeps_the_latest_result_per_user_agent() {
        let db = db();
        let m = script(1);
        let first = NpMinerSensing {
            miner_script: m.clone(),
            user_agent: "bmminer/2.0.0".to_string(),
            highest_pass_class: Some(9),
            failed_class: None,
            sensed_at: 10,
        };
        db.np_record_sensing(&first).unwrap();
        let later = NpMinerSensing {
            highest_pass_class: Some(44),
            failed_class: Some(143),
            sensed_at: 20,
            ..first.clone()
        };
        db.np_record_sensing(&later).unwrap();
        let other = NpMinerSensing {
            user_agent: "bitaxe/BM1370/v2.4.0".to_string(),
            highest_pass_class: None,
            failed_class: Some(3),
            ..first.clone()
        };
        db.np_record_sensing(&other).unwrap();
        assert_eq!(db.np_sensing_for(&m).unwrap(), vec![other, later]);
        assert!(db.np_sensing_for(&script(2)).unwrap().is_empty());
    }

    // -- migration from v62 --------------------------------------------------------------------

    fn temp_db_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ghost-np-{tag}-{}-{:?}.db",
            std::process::id(),
            std::thread::current().id()
        ))
    }

    fn remove_db_files(path: &std::path::Path) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    /// Turn a head database back into v62: drop the v63 objects and stamp the version.
    fn rewind_to_v62(conn: &Connection) {
        let names: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'np\\_%' ESCAPE '\\'")
                .unwrap();
            stmt.query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        };
        assert_eq!(
            names.len(),
            12,
            "v63 and v64 create twelve tables: {names:?}"
        );
        conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
        for n in names {
            conn.execute_batch(&format!("DROP TABLE {n};")).unwrap();
        }
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA user_version = 62;")
            .unwrap();
        let left: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE tbl_name LIKE 'np\\_%' ESCAPE '\\'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(left, 0, "a v62 database holds no np_ object");
    }

    /// A v62 database on disk, with data in an existing table, opened by this binary: v63 runs,
    /// the old row survives untouched, and the new tables work through the real open path (WAL).
    #[test]
    fn a_v62_database_on_disk_migrates_to_v63() {
        let path = temp_db_path("v62");
        remove_db_files(&path);
        {
            let db = Database::open(&path).expect("create");
            drop(db);
            let conn = Connection::open(&path).unwrap();
            rewind_to_v62(&conn);
            conn.execute(
                "INSERT INTO shard_settled (address_hash, address_enc, settled_micro, last_height) \
                 VALUES (?1, 'enc', 42, 974000)",
                params![vec![7u8; 32]],
            )
            .unwrap();
            let v: u32 = conn
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
            assert_eq!(v, 62);
        }

        let db = Database::open(&path).expect("reopen migrates");
        let (v, mode): (u32, String) = db
            .with_connection(|c| {
                Ok((
                    c.query_row("PRAGMA user_version", [], |r| r.get(0))
                        .map_err(db_err)?,
                    c.query_row("PRAGMA journal_mode", [], |r| r.get(0))
                        .map_err(db_err)?,
                ))
            })
            .unwrap();
        assert_eq!(v, 64);
        assert_eq!(mode, "wal");
        let kept: (i64, i64) = db
            .with_connection(|c| {
                c.query_row(
                    "SELECT settled_micro, last_height FROM shard_settled",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(db_err)
            })
            .unwrap();
        assert_eq!(kept, (42, 974_000), "existing rows are untouched");

        db.np_insert_anchor(&anchor(1, None, 0, 100)).unwrap();
        db.np_apply_credits(&h(1), 100, &credits(&[(1, BIG)]), 0)
            .unwrap();
        drop(db);

        let db = Database::open(&path).expect("reopen at head");
        assert_eq!(db.np_balance(&script(1)).unwrap().expect("row").owed, BIG);
        assert_eq!(db.np_load_anchors().unwrap(), vec![anchor(1, None, 0, 100)]);
        drop(db);
        remove_db_files(&path);
    }

    /// The same rehearsal on an SQLCipher database: `sqlcipher_export` does not carry
    /// `user_version`, so the version must be read back through the encrypted open path.
    #[test]
    fn an_encrypted_v62_database_migrates_to_v63() {
        let path = temp_db_path("v62-enc");
        remove_db_files(&path);
        let key = [0x42u8; 32];
        {
            drop(Database::open_encrypted(&path, &key).expect("create"));
            let conn = Connection::open(&path).unwrap();
            conn.pragma_update(None, "key", format!("x'{}'", hex::encode(key)))
                .unwrap();
            rewind_to_v62(&conn);
        }
        let db = Database::open_encrypted(&path, &key).expect("reopen migrates");
        let v: u32 = db
            .with_connection(|c| {
                c.query_row("PRAGMA user_version", [], |r| r.get(0))
                    .map_err(db_err)
            })
            .unwrap();
        assert_eq!(v, 64);
        db.np_apply_block(&h(0xA0), 121, &[(script(1), BIG)], 0)
            .unwrap();
        assert_eq!(db.np_balance(&script(1)).unwrap().expect("row").owed, -BIG);
        drop(db);
        remove_db_files(&path);
    }

    /// The archive keeps a block's header and coinbase, upgrades a header-only row, and refuses
    /// a different block under the same hash.
    #[test]
    fn btc_blocks_round_trip_and_upgrade() {
        let db = db();
        let mut header = [7u8; 80];
        header[4..36].copy_from_slice(&[9; 32]);
        let hash = sha256d(&header);
        let bare = NpBtcBlock {
            hash,
            height: 1_001,
            header,
            coinbase: None,
            received_at: 5,
        };
        assert_eq!(db.np_put_btc_block(&bare).unwrap(), InsertOutcome::Inserted);
        assert_eq!(
            db.np_put_btc_block(&bare).unwrap(),
            InsertOutcome::AlreadyPresent
        );
        let full = NpBtcBlock {
            coinbase: Some((vec![1, 2, 3], vec![[4; 32]])),
            ..bare.clone()
        };
        assert_eq!(db.np_put_btc_block(&full).unwrap(), InsertOutcome::Inserted);
        assert_eq!(db.np_get_btc_block(&hash).unwrap(), Some(full.clone()));
        assert_eq!(
            db.np_put_btc_block(&bare).unwrap(),
            InsertOutcome::AlreadyPresent,
            "a header-only copy never strips a held coinbase"
        );
        let other = NpBtcBlock {
            coinbase: Some((vec![1, 2], vec![])),
            ..bare.clone()
        };
        assert!(db.np_put_btc_block(&other).is_err());
        let mut forged = bare.clone();
        forged.hash = [0; 32];
        assert!(db.np_put_btc_block(&forged).is_err(), "hash must match");
        assert_eq!(db.np_load_btc_blocks().unwrap(), vec![full]);
    }

    /// Checkpoints are stored newest first, replaced at the same anchor, and deleted on request.
    #[test]
    fn checkpoints_round_trip() {
        let db = db();
        let c = |a: u8, height: u32| NpCheckpoint {
            anchor_hash: h(a),
            height,
            btc_height: 1_000 + height,
            payload: vec![a; 3],
            digest: h(a ^ 0xFF),
            created_at: 1,
        };
        db.np_put_checkpoint(&c(1, 10)).unwrap();
        db.np_put_checkpoint(&c(2, 20)).unwrap();
        let mut again = c(1, 10);
        again.payload = vec![0];
        db.np_put_checkpoint(&again).unwrap();
        assert_eq!(db.np_load_checkpoints().unwrap(), vec![c(2, 20), again]);
        let heads = db.np_checkpoint_heads().unwrap();
        assert_eq!(
            heads
                .iter()
                .map(|x| (x.anchor_hash, x.height, x.btc_height, x.digest))
                .collect::<Vec<_>>(),
            vec![
                (h(2), 20, 1_020, h(2 ^ 0xFF)),
                (h(1), 10, 1_010, h(1 ^ 0xFF))
            ]
        );
        db.np_delete_checkpoint(&h(2)).unwrap();
        assert_eq!(db.np_load_checkpoints().unwrap().len(), 1);
    }
}
