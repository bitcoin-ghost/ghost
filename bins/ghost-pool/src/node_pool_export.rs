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
//| FILE: node_pool_export.rs                                                                                            |
//|======================================================================================================================|

//! Node-pool flag-day export: the miners' ledger and the MPC ceremony lineage, read-only.
//!
//! At the node-pool cutover every node runs this against its own database. The new binary
//! imports the ledger half as its genesis table, pinned by the digest printed here, and the
//! old tables are dropped. See `docs/LEDGER_EXPORT.md` for the file formats.
//!
//! - **Source.** One finalised payout-ledger checkpoint, at an EXACT height. A row exists in
//!   `payout_ledger_checkpoints` only once the fleet has finalised it (`payout_checkpoint.rs`,
//!   `maybe_finalize`), so "finalised" here means "the row exists and carries its adopted
//!   `canonical_payout` bytes". Never at-or-before: a node missing the height must refuse, not
//!   export an older checkpoint that no other node will match.
//! - **Root.** The checkpoint's stored `ledger_root` is recomputed from the exported set with
//!   [`crate::payout::compute_ledger_root`]. Since the #606 median gate the stored root is the
//!   proposer's and the adopted list is a median, so they can differ; the export refuses that
//!   unless told otherwise. Fleet unanimity is a separate check: all nodes must print the same
//!   digest (which covers `canonical_payout_sha256`).
//! - **Rate.** Work converts to `2^-32` sat units at a rate the operator must pass. Nothing here
//!   picks one. Each miner is floored; the remainder is reported exactly.
//! - **Read-only.** The database is opened `SQLITE_OPEN_READ_ONLY` with `query_only`, and all
//!   reads run in one read transaction, so a running node's writes cannot interleave.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use rusqlite::{types::ValueRef, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// `format` field of the ledger JSON.
pub const LEDGER_FORMAT: &str = "ghost-ledger-export/v1";
/// Domain tag at the start of the canonical ledger bytes.
pub const LEDGER_MAGIC: &[u8] = b"GhostLedgerExport/v1";
/// `format` field of the MPC lineage JSON.
pub const MPC_FORMAT: &str = "ghost-mpc-lineage/v1";
/// Node-pool balances are in units of `2^-32` sat.
pub const FACE_UNITS_PER_SAT: u128 = 1 << 32;
/// The MPC tables archived before the cutover drops them.
pub const MPC_TABLES: [&str; 4] = [
    "mpc_ceremony",
    "mpc_contributions",
    "mpc_verification_votes",
    "mpc_params_files",
];

/// Output file names inside the export directory.
pub const LEDGER_BIN: &str = "ledger-export.bin";
/// Human-auditable ledger JSON.
pub const LEDGER_JSON: &str = "ledger-export.json";
/// MPC lineage JSON.
pub const MPC_JSON: &str = "mpc-lineage.json";
/// `sha256sum -c` file covering the three above.
pub const SUMS_FILE: &str = "SHA256SUMS";

/// Checkpoint work units per whole unit of work at `height`.
///
/// Below [`crate::CHECKPOINT_FROM_SHARD_HEIGHT`] the checkpoint carried the legacy ledger's
/// `WORK_SCALE`-quantised work (1e12 per unit). At and above it, `select_shard_miner_work`
/// fills it with the shard's micro-work (1e6 per unit). The rate is per whole unit, so the
/// export divides by this to stay correct either side of the gate.
pub fn work_units_per_work(height: u64) -> u128 {
    if height >= crate::CHECKPOINT_FROM_SHARD_HEIGHT {
        1_000_000
    } else {
        ghost_accounting::shares::WORK_SCALE
    }
}

/// Why an export was refused. Every variant writes nothing.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// No rate was given. The rate is a published decision and is never defaulted.
    #[error(
        "no sats-per-work rate given: pass --np-export-sats-per-work as an exact rational \
         (e.g. 3/1000000 or 0.000003); the export never picks a rate"
    )]
    MissingRate,
    /// The rate does not parse, is zero, or overflows.
    #[error("bad sats-per-work rate {input:?}: {detail}")]
    BadRate {
        /// What was passed.
        input: String,
        /// Why it was refused.
        detail: String,
    },
    /// No finalised checkpoint is held at exactly this height.
    #[error(
        "no finalised payout checkpoint at height {0} in this database: only finalised \
         checkpoints are stored, and the export never falls back to an older one"
    )]
    NotFinalised(u64),
    /// The database was migrated to the node pool (schema v65 or later, stored negated), so its
    /// old tables are gone. The export reads the pre-cutover database, or its `.pre-v65` copy.
    #[error(
        "this database was migrated to the node pool (user_version {0}, schema v65 or later): its \
         payout tables were dropped. Export from the old database, or from the `<db>.pre-v65` \
         copy migration v65 took, never from a migrated one"
    )]
    Migrated(i64),
    /// The row predates adopt-on-finalise and carries no adopted lists.
    #[error("checkpoint at height {0} has no canonical_payout (a pre-adopt-on-finalise row)")]
    NoCanonical(u64),
    /// The adopted bytes do not decode as `(miner_payouts, node_shares)`.
    #[error("checkpoint at height {height}: canonical_payout does not decode: {detail}")]
    Undecodable {
        /// Checkpoint height.
        height: u64,
        /// Decoder message.
        detail: String,
    },
    /// The checkpoint owes nobody.
    #[error(
        "checkpoint at height {0} carries no miner payouts; refusing to export an empty ledger"
    )]
    NoPayees(u64),
    /// The stored `ledger_root` does not recompute from the adopted lists.
    #[error(
        "checkpoint at height {height}: stored ledger_root {stored} does not recompute from the \
         adopted lists ({adopted}). Since #606 the stored root is the proposer's and the lists are \
         the fleet median; pick a height where they agree, or pass \
         --np-export-allow-root-mismatch to export anyway"
    )]
    RootMismatch {
        /// Checkpoint height.
        height: u64,
        /// Stored root, hex.
        stored: String,
        /// Root of the adopted lists, hex.
        adopted: String,
    },
    /// A payout address does not parse for the chosen network.
    #[error("payout address {address:?} is not a valid address on {network}: {detail}")]
    BadAddress {
        /// The address.
        address: String,
        /// Network the export was run for.
        network: String,
        /// Parser message.
        detail: String,
    },
    /// The same address appears twice in one checkpoint.
    #[error("payout address {0:?} appears more than once in the checkpoint")]
    DuplicateAddress(String),
    /// Arithmetic left `u128` / `i128`.
    #[error("arithmetic overflow: {0}")]
    Overflow(String),
    /// Database error.
    #[error("database: {0}")]
    Db(String),
    /// File-system error.
    #[error("io: {0}")]
    Io(String),
    /// An output file already exists. The export never overwrites.
    #[error("{0} already exists; the export never overwrites a previous one")]
    OutputExists(PathBuf),
}

impl From<rusqlite::Error> for ExportError {
    fn from(e: rusqlite::Error) -> Self {
        ExportError::Db(e.to_string())
    }
}

impl From<std::io::Error> for ExportError {
    fn from(e: std::io::Error) -> Self {
        ExportError::Io(e.to_string())
    }
}

type Result<T> = std::result::Result<T, ExportError>;

// ── Exact arithmetic ──────────────────────────────────────────────────────────────────────

/// `a * b` as a 256-bit `(hi, lo)` pair.
fn mul_wide(a: u128, b: u128) -> (u128, u128) {
    const M: u128 = u64::MAX as u128;
    let (a1, a0) = (a >> 64, a & M);
    let (b1, b0) = (b >> 64, b & M);
    let lo_lo = a0 * b0;
    let hi_lo = a1 * b0;
    let lo_hi = a0 * b1;
    let hi_hi = a1 * b1;
    let cross = (lo_lo >> 64) + (hi_lo & M) + (lo_hi & M);
    let lo = (cross << 64) | (lo_lo & M);
    let hi = hi_hi + (hi_lo >> 64) + (lo_hi >> 64) + (cross >> 64);
    (hi, lo)
}

/// `floor(a * b * 2^32 / d)` and its remainder, exactly. Errors if the quotient leaves `u128`.
fn mul_shift_div(a: u128, b: u128, d: u128) -> Result<(u128, u128)> {
    if d == 0 {
        return Err(ExportError::Overflow("division by zero".into()));
    }
    let (hi, lo) = mul_wide(a, b);
    if hi >> 96 != 0 {
        return Err(ExportError::Overflow(format!(
            "{a} * {b} * 2^32 exceeds 256 bits"
        )));
    }
    let (hi, lo) = ((hi << 32) | (lo >> 96), lo << 32);
    if hi >= d {
        return Err(ExportError::Overflow(format!(
            "{a} * {b} * 2^32 / {d} exceeds u128"
        )));
    }
    // Restoring long division of (hi, lo) by d; hi < d keeps the quotient within 128 bits.
    let mut rem = hi;
    let mut q: u128 = 0;
    for i in (0..128).rev() {
        let carry = rem >> 127;
        rem = (rem << 1) | ((lo >> i) & 1);
        q <<= 1;
        if carry == 1 || rem >= d {
            rem = rem.wrapping_sub(d);
            q |= 1;
        }
    }
    Ok((q, rem))
}

fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// The conversion rate in sats per whole unit of work, as a reduced fraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    /// Numerator, > 0.
    pub num: u128,
    /// Denominator, > 0.
    pub den: u128,
}

/// Parse the rate: `N`, `N/D` or a decimal `I.F`, all exact. `None` is [`ExportError::MissingRate`].
///
/// The result is reduced, so `1/2`, `2/4` and `0.5` are the same rate and give the same digest.
pub fn parse_rate(input: Option<&str>) -> Result<Rate> {
    let s = input.ok_or(ExportError::MissingRate)?.trim();
    let bad = |detail: &str| ExportError::BadRate {
        input: s.to_string(),
        detail: detail.to_string(),
    };
    let digits = |t: &str| -> Result<u128> {
        if t.is_empty() || !t.bytes().all(|c| c.is_ascii_digit()) {
            return Err(bad("expected digits"));
        }
        t.parse::<u128>().map_err(|_| bad("number exceeds u128"))
    };
    let (num, den) = if let Some((n, d)) = s.split_once('/') {
        (digits(n.trim())?, digits(d.trim())?)
    } else if let Some((i, f)) = s.split_once('.') {
        let scale = 10u128
            .checked_pow(u32::try_from(f.len()).map_err(|_| bad("too many decimals"))?)
            .ok_or_else(|| bad("too many decimals"))?;
        let i = if i.is_empty() { 0 } else { digits(i)? };
        let f = digits(f)?;
        let n = i
            .checked_mul(scale)
            .and_then(|x| x.checked_add(f))
            .ok_or_else(|| bad("number exceeds u128"))?;
        (n, scale)
    } else {
        (digits(s)?, 1)
    };
    if den == 0 {
        return Err(bad("denominator is zero"));
    }
    if num == 0 {
        return Err(bad("rate is zero"));
    }
    let g = gcd(num, den);
    Ok(Rate {
        num: num / g,
        den: den / g,
    })
}

// ── The export object ────────────────────────────────────────────────────────────────────

mod u128_str {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// The checkpoint the ledger was taken from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointInfo {
    /// Checkpoint height.
    pub height: u64,
    /// Checkpoint cutoff timestamp (an input to `ledger_root`).
    pub cutoff_ts: i64,
    /// The `ledger_root` stored with the checkpoint, hex.
    pub ledger_root: String,
    /// `compute_ledger_root` over the exported lists, hex.
    pub adopted_root: String,
    /// Whether the two roots are equal.
    pub ledger_root_recomputes: bool,
    /// SHA-256 of the stored `canonical_payout` bytes, as `shard-anchor-rehearsal.sh` hashes them.
    pub canonical_payout_sha256: String,
    /// The qualified-node set from the same checkpoint (an input to `ledger_root`), by node id.
    pub node_shares: Vec<NodeShare>,
}

/// One qualified node in the checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeShare {
    /// Node id, hex.
    pub node_id: String,
    /// Its 5-4-3-2-1 capability shares.
    pub shares: i32,
}

/// The conversion rate as written into the export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateInfo {
    /// Sats per whole unit of work, numerator.
    #[serde(with = "u128_str")]
    pub sats_per_work_num: u128,
    /// Sats per whole unit of work, denominator.
    #[serde(with = "u128_str")]
    pub sats_per_work_den: u128,
    /// Checkpoint work units per whole unit of work (1e6 from the shard gate on, 1e12 before).
    #[serde(with = "u128_str")]
    pub work_units_per_work: u128,
    /// Always `2^32`.
    #[serde(with = "u128_str")]
    pub face_units_per_sat: u128,
}

/// One miner's row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinerRow {
    /// Payout address exactly as the checkpoint keys it.
    pub address: String,
    /// Its scriptPubKey, hex.
    pub script_hex: String,
    /// Owed work in checkpoint units, exactly as adopted.
    #[serde(with = "u128_str")]
    pub work: u128,
    /// `floor(work * rate * 2^32 / work_units_per_work)`, in `2^-32` sat.
    #[serde(with = "u128_str")]
    pub face_units: u128,
}

/// One genesis-table row: the import's input, keyed by script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableRow {
    /// Payee scriptPubKey, hex.
    pub script_hex: String,
    /// Sum of the floored `face_units` of every miner row with this script.
    #[serde(with = "u128_str")]
    pub face_units: u128,
}

/// Totals and the rounding report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    /// Sum of `work`.
    #[serde(with = "u128_str")]
    pub work: u128,
    /// Sum of floored `face_units`: what the genesis table owes.
    #[serde(with = "u128_str")]
    pub face_units: u128,
    /// Whole `2^-32`-sat units lost to per-miner flooring.
    #[serde(with = "u128_str")]
    pub remainder_face_units: u128,
    /// Fractional part of the remainder, numerator.
    #[serde(with = "u128_str")]
    pub remainder_frac_num: u128,
    /// Fractional part of the remainder, denominator.
    #[serde(with = "u128_str")]
    pub remainder_frac_den: u128,
    /// `floor(total work * rate * 2^32 / work_units_per_work)`, which equals
    /// `face_units + remainder_face_units`.
    #[serde(with = "u128_str")]
    pub face_units_of_total_work: u128,
}

/// Facts read from this node that are not part of the digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observed {
    /// Checkpoint proposer, hex, as stored.
    pub proposer_id: String,
    /// Active node count, as stored.
    pub active_node_count: u32,
    /// `max(rounds.block_height)` on this node at export time, if any.
    pub tip_height_seen: Option<u64>,
    /// Length of the stored `canonical_payout` blob.
    pub canonical_payout_len: usize,
}

/// The whole ledger export, as written to `ledger-export.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerExport {
    /// [`LEDGER_FORMAT`].
    pub format: String,
    /// SHA-256 of [`canonical_bytes`], hex. Not itself part of the bytes.
    pub digest_sha256: String,
    /// Network the addresses were parsed for (`bitcoin`, `signet`, ...).
    pub network: String,
    /// Source checkpoint.
    pub checkpoint: CheckpointInfo,
    /// Conversion rate.
    pub rate: RateInfo,
    /// Miner rows, by `(script, address)` ascending.
    pub miners: Vec<MinerRow>,
    /// Genesis table, by script ascending.
    pub genesis_table: Vec<TableRow>,
    /// Totals and rounding.
    pub totals: Totals,
    /// Not in the digest.
    pub observed: Observed,
    /// Not in the digest.
    pub warnings: Vec<String>,
    /// Not in the digest. Checkpoint rows deleted because the node pool cannot pay their
    /// script (decided 2026-11-03), with their owed work, so a stranger can still recompute
    /// the checkpoint's `ledger_root` from `miners` plus these.
    #[serde(default)]
    pub deleted: Vec<DeletedRow>,
}

/// A checkpoint row the export deleted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletedRow {
    /// Payout address exactly as the checkpoint keys it.
    pub address: String,
    /// Owed work in checkpoint units, exactly as adopted.
    #[serde(with = "u128_str")]
    pub work: u128,
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    let v = hex::decode(s).map_err(|e| ExportError::Undecodable {
        height: 0,
        detail: format!("{what}: {e}"),
    })?;
    v.try_into().map_err(|_| ExportError::Undecodable {
        height: 0,
        detail: format!("{what}: not 32 bytes"),
    })
}

fn put_bytes16(out: &mut Vec<u8>, b: &[u8]) -> Result<()> {
    let n = u16::try_from(b.len())
        .map_err(|_| ExportError::Overflow(format!("field of {} bytes", b.len())))?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

fn put_count(out: &mut Vec<u8>, n: usize) -> Result<()> {
    let n = u32::try_from(n).map_err(|_| ExportError::Overflow(format!("count {n}")))?;
    out.extend_from_slice(&n.to_be_bytes());
    Ok(())
}

/// The canonical bytes the digest is taken over. Big-endian throughout; see
/// `docs/LEDGER_EXPORT.md` for the layout. A pure function of the JSON's digest fields, so
/// anyone holding `ledger-export.json` can rebuild `ledger-export.bin` and check the digest.
pub fn canonical_bytes(e: &LedgerExport) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(LEDGER_MAGIC);
    put_bytes16(&mut out, e.network.as_bytes())?;
    let c = &e.checkpoint;
    out.extend_from_slice(&c.height.to_be_bytes());
    out.extend_from_slice(&c.cutoff_ts.to_be_bytes());
    out.extend_from_slice(&hex32(&c.ledger_root, "ledger_root")?);
    out.extend_from_slice(&hex32(&c.adopted_root, "adopted_root")?);
    out.extend_from_slice(&hex32(
        &c.canonical_payout_sha256,
        "canonical_payout_sha256",
    )?);
    put_count(&mut out, c.node_shares.len())?;
    for n in &c.node_shares {
        out.extend_from_slice(&hex32(&n.node_id, "node_id")?);
        out.extend_from_slice(&n.shares.to_be_bytes());
    }
    let r = &e.rate;
    out.extend_from_slice(&r.sats_per_work_num.to_be_bytes());
    out.extend_from_slice(&r.sats_per_work_den.to_be_bytes());
    out.extend_from_slice(&r.work_units_per_work.to_be_bytes());
    out.extend_from_slice(&r.face_units_per_sat.to_be_bytes());
    put_count(&mut out, e.miners.len())?;
    for m in &e.miners {
        put_bytes16(&mut out, m.address.as_bytes())?;
        let script = hex::decode(&m.script_hex).map_err(|err| ExportError::Undecodable {
            height: c.height,
            detail: format!("script_hex: {err}"),
        })?;
        put_bytes16(&mut out, &script)?;
        out.extend_from_slice(&m.work.to_be_bytes());
        out.extend_from_slice(&m.face_units.to_be_bytes());
    }
    put_count(&mut out, e.genesis_table.len())?;
    for t in &e.genesis_table {
        let script = hex::decode(&t.script_hex).map_err(|err| ExportError::Undecodable {
            height: c.height,
            detail: format!("script_hex: {err}"),
        })?;
        put_bytes16(&mut out, &script)?;
        out.extend_from_slice(&t.face_units.to_be_bytes());
    }
    let t = &e.totals;
    for v in [
        t.work,
        t.face_units,
        t.remainder_face_units,
        t.remainder_frac_num,
        t.remainder_frac_den,
        t.face_units_of_total_work,
    ] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    Ok(out)
}

/// The adopted lists exactly as `upsert_payout_ledger_checkpoint` stores them.
type Adopted = (Vec<(String, u128)>, Vec<([u8; 32], i32)>);

/// Open `path` read-only. Refuses a missing file rather than letting SQLite create one.
pub fn open_read_only(path: &Path) -> Result<Connection> {
    if !path.is_file() {
        return Err(ExportError::Db(format!(
            "{} is not a database file",
            path.display()
        )));
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.pragma_update(None, "query_only", true)?;
    // A running node may hold a write lock briefly; wait rather than fail.
    conn.busy_timeout(std::time::Duration::from_secs(30))?;
    Ok(conn)
}

/// Build the ledger export from a finalised checkpoint at exactly `height`.
pub fn build_ledger_export(
    conn: &Connection,
    height: u64,
    rate: Rate,
    network: bitcoin::Network,
    allow_root_mismatch: bool,
) -> Result<LedgerExport> {
    let h = i64::try_from(height).map_err(|_| ExportError::NotFinalised(height))?;
    // From v65 the node pool stores its schema version negated (so older binaries refuse the
    // database at open); this export opens the file raw, so it checks for itself.
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 0 {
        return Err(ExportError::Migrated(version));
    }
    let has_table: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'payout_ledger_checkpoints'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !has_table {
        return Err(ExportError::NotFinalised(height));
    }
    let row = conn
        .query_row(
            "SELECT cutoff_ts, ledger_root, proposer_id, active_node_count, canonical_payout \
             FROM payout_ledger_checkpoints WHERE height = ?1",
            [h],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Option<Vec<u8>>>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((cutoff_ts, root_blob, proposer_id, active_node_count, canonical)) = row else {
        return Err(ExportError::NotFinalised(height));
    };
    let ledger_root: [u8; 32] =
        root_blob
            .as_slice()
            .try_into()
            .map_err(|_| ExportError::Undecodable {
                height,
                detail: format!("ledger_root is {} bytes", root_blob.len()),
            })?;
    let canonical = match canonical {
        Some(b) if !b.is_empty() => b,
        _ => return Err(ExportError::NoCanonical(height)),
    };
    let (miner_payouts, node_shares): Adopted =
        serde_json::from_slice(&canonical).map_err(|e| ExportError::Undecodable {
            height,
            detail: e.to_string(),
        })?;
    if miner_payouts.is_empty() {
        return Err(ExportError::NoPayees(height));
    }

    let adopted_root =
        crate::payout::compute_ledger_root(&miner_payouts, &node_shares, cutoff_ts, height);
    let recomputes = adopted_root == ledger_root;
    if !recomputes && !allow_root_mismatch {
        return Err(ExportError::RootMismatch {
            height,
            stored: hex::encode(ledger_root),
            adopted: hex::encode(adopted_root),
        });
    }

    let units = work_units_per_work(height);
    let divisor = rate
        .den
        .checked_mul(units)
        .ok_or_else(|| ExportError::Overflow("rate denominator * work units".into()))?;

    let mut seen = std::collections::HashSet::new();
    let mut miners = Vec::with_capacity(miner_payouts.len());
    let mut total_work: u128 = 0;
    let mut total_face: u128 = 0;
    let (mut rem_whole, mut rem_frac): (u128, u128) = (0, 0);
    let mut dropped: Vec<(String, u128)> = Vec::new();
    for (address, work) in &miner_payouts {
        if !seen.insert(address.as_str()) {
            return Err(ExportError::DuplicateAddress(address.clone()));
        }
        let bad = |detail: String| ExportError::BadAddress {
            address: address.clone(),
            network: network.to_string(),
            detail,
        };
        let script_buf = bitcoin::Address::from_str(address)
            .map_err(|e| bad(e.to_string()))?
            .require_network(network)
            .map_err(|e| bad(e.to_string()))?
            .script_pubkey();
        // The node pool pays only P2SH, P2WPKH, P2WSH and P2TR, and its import refuses any
        // other row. Decided 2026-11-03: such a balance is deleted from the export, not
        // carried. Every node drops the same rows from the same checkpoint, so digests agree.
        if !(script_buf.is_p2sh()
            || script_buf.is_p2wpkh()
            || script_buf.is_p2wsh()
            || script_buf.is_p2tr())
        {
            dropped.push((address.clone(), *work));
            continue;
        }
        let script = script_buf.to_bytes();
        let (face, rem) = mul_shift_div(*work, rate.num, divisor)?;
        if face > i128::MAX as u128 {
            return Err(ExportError::Overflow(format!(
                "{address}: face {face} exceeds i128"
            )));
        }
        total_work = total_work
            .checked_add(*work)
            .ok_or_else(|| ExportError::Overflow("total work".into()))?;
        total_face = total_face
            .checked_add(face)
            .ok_or_else(|| ExportError::Overflow("total face".into()))?;
        // rem_frac + rem, carried into whole units without overflowing.
        if rem >= divisor - rem_frac {
            rem_frac = rem - (divisor - rem_frac);
            rem_whole += 1;
        } else {
            rem_frac += rem;
        }
        miners.push(MinerRow {
            address: address.clone(),
            script_hex: hex::encode(&script),
            work: *work,
            face_units: face,
        });
    }
    // Canonical order: script bytes ascending, then address. Lower-case hex of equal-length
    // prefixes sorts like the bytes, but scripts differ in length, so compare the bytes.
    miners.sort_by_cached_key(|m| {
        (
            hex::decode(&m.script_hex).unwrap_or_default(),
            m.address.clone(),
        )
    });

    let (face_of_total, _) = mul_shift_div(total_work, rate.num, divisor)?;
    if face_of_total != total_face + rem_whole {
        return Err(ExportError::Overflow(format!(
            "rounding check failed: floor(total) {face_of_total} != {total_face} + {rem_whole}"
        )));
    }

    let mut table: BTreeMap<Vec<u8>, u128> = BTreeMap::new();
    for m in &miners {
        let script = hex::decode(&m.script_hex).unwrap_or_default();
        let slot = table.entry(script).or_insert(0);
        *slot = slot
            .checked_add(m.face_units)
            .ok_or_else(|| ExportError::Overflow("table row".into()))?;
    }
    let genesis_table: Vec<TableRow> = table
        .into_iter()
        .map(|(s, f)| TableRow {
            script_hex: hex::encode(s),
            face_units: f,
        })
        .collect();

    let mut nodes: Vec<NodeShare> = node_shares
        .iter()
        .map(|(id, s)| NodeShare {
            node_id: hex::encode(id),
            shares: *s,
        })
        .collect();
    nodes.sort_by(|a, b| a.node_id.cmp(&b.node_id).then(a.shares.cmp(&b.shares)));

    let tip_height_seen: Option<u64> = conn
        .query_row("SELECT max(block_height) FROM rounds", [], |r| {
            r.get::<_, Option<i64>>(0)
        })
        .ok()
        .flatten()
        .and_then(|v| u64::try_from(v).ok());

    let mut warnings = Vec::new();
    for (address, work) in &dropped {
        warnings.push(format!(
            "deleted {address} (owed work {work}): not a node pool payee class (P2SH, P2WPKH, \
             P2WSH, P2TR); this balance is not exported"
        ));
    }
    if !recomputes {
        warnings.push(format!(
            "ledger_root does not recompute from the adopted lists (stored {}, adopted {}); \
             exported anyway because --np-export-allow-root-mismatch was given",
            hex::encode(ledger_root),
            hex::encode(adopted_root)
        ));
    }
    if height >= crate::CHECKPOINT_FROM_SHARD_HEIGHT
        && miner_payouts.len() >= ghost_common::constants::MAX_MINER_OUTPUTS
    {
        warnings.push(format!(
            "the checkpoint holds {} miners, the MAX_MINER_OUTPUTS cap: select_shard_miner_work \
             truncates there, so balances below the top {} are NOT in this checkpoint",
            miner_payouts.len(),
            ghost_common::constants::MAX_MINER_OUTPUTS
        ));
    }
    if height < crate::CHECKPOINT_FROM_SHARD_HEIGHT {
        warnings.push(format!(
            "height {height} is below CHECKPOINT_FROM_SHARD_HEIGHT ({}): this checkpoint came from \
             the legacy ledger, capped and dust-filtered, in 1e12 units per work",
            crate::CHECKPOINT_FROM_SHARD_HEIGHT
        ));
    }
    if let Some(tip) = tip_height_seen {
        if tip < height {
            warnings.push(format!(
                "this node's highest round is {tip}, below the checkpoint height {height}"
            ));
        }
    }

    let mut export = LedgerExport {
        format: LEDGER_FORMAT.to_string(),
        digest_sha256: String::new(),
        network: network.to_string(),
        checkpoint: CheckpointInfo {
            height,
            cutoff_ts,
            ledger_root: hex::encode(ledger_root),
            adopted_root: hex::encode(adopted_root),
            ledger_root_recomputes: recomputes,
            canonical_payout_sha256: hex::encode(Sha256::digest(&canonical)),
            node_shares: nodes,
        },
        rate: RateInfo {
            sats_per_work_num: rate.num,
            sats_per_work_den: rate.den,
            work_units_per_work: units,
            face_units_per_sat: FACE_UNITS_PER_SAT,
        },
        miners,
        genesis_table,
        totals: Totals {
            work: total_work,
            face_units: total_face,
            remainder_face_units: rem_whole,
            remainder_frac_num: rem_frac,
            remainder_frac_den: divisor,
            face_units_of_total_work: face_of_total,
        },
        observed: Observed {
            proposer_id,
            active_node_count: u32::try_from(active_node_count).unwrap_or(u32::MAX),
            tip_height_seen,
            canonical_payout_len: canonical.len(),
        },
        warnings,
        deleted: dropped
            .iter()
            .map(|(address, work)| DeletedRow {
                address: address.clone(),
                work: *work,
            })
            .collect(),
    };
    export.digest_sha256 = hex::encode(Sha256::digest(canonical_bytes(&export)?));
    Ok(export)
}

// ── MPC lineage ──────────────────────────────────────────────────────────────────────────

fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Dump [`MPC_TABLES`] as pretty JSON bytes: every column, every row, rows ordered by all
/// columns in declared order. Blobs are `{"blob_hex": ...}`. A missing table is recorded as
/// `"present": false`. Deterministic: the same rows give the same bytes.
pub fn dump_mpc_lineage(conn: &Connection) -> Result<Vec<u8>> {
    use serde_json::{json, Map, Value};
    let mut tables = Map::new();
    for name in MPC_TABLES {
        let present = conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [name],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !present {
            tables.insert(
                name.to_string(),
                json!({ "present": false, "columns": [], "rows": [] }),
            );
            continue;
        }
        let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", quote_ident(name)))?;
        let columns: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<std::result::Result<_, _>>()?;
        let order: Vec<String> = (1..=columns.len()).map(|i| i.to_string()).collect();
        let sql = format!(
            "SELECT * FROM {} ORDER BY {}",
            quote_ident(name),
            order.join(", ")
        );
        let mut stmt = conn.prepare(&sql)?;
        let n = columns.len();
        let mut rows_out = Vec::new();
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let mut row = Vec::with_capacity(n);
            for i in 0..n {
                row.push(match r.get_ref(i)? {
                    ValueRef::Null => Value::Null,
                    ValueRef::Integer(v) => Value::from(v),
                    ValueRef::Real(v) => serde_json::Number::from_f64(v)
                        .map(Value::Number)
                        .unwrap_or(Value::Null),
                    ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).into_owned()),
                    ValueRef::Blob(b) => json!({ "blob_hex": hex::encode(b) }),
                });
            }
            rows_out.push(Value::Array(row));
        }
        tables.insert(
            name.to_string(),
            json!({ "present": true, "columns": columns, "rows": rows_out }),
        );
    }
    let doc = json!({ "format": MPC_FORMAT, "tables": Value::Object(tables) });
    let mut bytes = serde_json::to_vec_pretty(&doc).map_err(|e| ExportError::Io(e.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

// ── Driver ───────────────────────────────────────────────────────────────────────────────

/// What `ghost-mining --np-export` was asked to do.
#[derive(Debug, Clone)]
pub struct ExportOptions {
    /// The node's `ghost.db`.
    pub db_path: PathBuf,
    /// Directory the four files are written into (created if missing; files never overwritten).
    pub out_dir: PathBuf,
    /// Exact checkpoint height.
    pub height: u64,
    /// The rate as typed; `None` is refused.
    pub sats_per_work: Option<String>,
    /// Network the payout addresses belong to.
    pub network: bitcoin::Network,
    /// Export even when the stored `ledger_root` does not recompute.
    pub allow_root_mismatch: bool,
}

/// What was written.
#[derive(Debug, Clone)]
pub struct ExportSummary {
    /// The ledger export (also in `ledger-export.json`).
    pub ledger: LedgerExport,
    /// SHA-256 of `mpc-lineage.json`, hex.
    pub mpc_digest_sha256: String,
    /// Files written.
    pub files: Vec<PathBuf>,
}

/// Read, build, then write. Nothing is written unless every check passed.
pub fn run(opts: &ExportOptions) -> Result<ExportSummary> {
    let rate = parse_rate(opts.sats_per_work.as_deref())?;
    let mut conn = open_read_only(&opts.db_path)?;
    // One read transaction: the ledger and the MPC dump see the same snapshot.
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
    let ledger = build_ledger_export(
        &tx,
        opts.height,
        rate,
        opts.network,
        opts.allow_root_mismatch,
    )?;
    let mpc = dump_mpc_lineage(&tx)?;
    drop(tx);
    drop(conn);

    let bin = canonical_bytes(&ledger)?;
    let mut json =
        serde_json::to_vec_pretty(&ledger).map_err(|e| ExportError::Io(e.to_string()))?;
    json.push(b'\n');
    let mpc_digest = hex::encode(Sha256::digest(&mpc));
    let sums = format!(
        "{}  {LEDGER_BIN}\n{}  {LEDGER_JSON}\n{}  {MPC_JSON}\n",
        ledger.digest_sha256,
        hex::encode(Sha256::digest(&json)),
        mpc_digest
    );

    std::fs::create_dir_all(&opts.out_dir)?;
    let outputs = [
        (LEDGER_BIN, bin.as_slice()),
        (LEDGER_JSON, json.as_slice()),
        (MPC_JSON, mpc.as_slice()),
        (SUMS_FILE, sums.as_bytes()),
    ];
    for (name, _) in &outputs {
        let p = opts.out_dir.join(name);
        if p.exists() {
            return Err(ExportError::OutputExists(p));
        }
    }
    let mut files = Vec::new();
    for (name, bytes) in outputs {
        let p = opts.out_dir.join(name);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::AlreadyExists => ExportError::OutputExists(p.clone()),
                _ => ExportError::Io(format!("{}: {e}", p.display())),
            })?;
        f.write_all(bytes)?;
        f.sync_all()?;
        files.push(p);
    }
    Ok(ExportSummary {
        ledger,
        mpc_digest_sha256: mpc_digest,
        files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_storage::{Database, PayoutLedgerCheckpointRecord};

    /// Above the shard gate, so work is micro-work (1e6 per unit).
    const H: u64 = 970_000;
    const CUTOFF: i64 = 1_790_000_000;

    fn miners() -> Vec<(String, u128)> {
        vec![
            (
                "bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492".to_string(),
                62_143_408_528,
            ),
            (
                "bc1qhfgc0uj7wv03vmchxe2hn8lhtu6ey9zaf0nre2".to_string(),
                2_827_976_214,
            ),
            (
                "148WRjKfSSo911CYRLzeyYm1QKhy7kCXTN".to_string(),
                532_541_467,
            ),
            (
                "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h".to_string(),
                9_741_908,
            ),
        ]
    }

    fn nodes() -> Vec<([u8; 32], i32)> {
        vec![([0x58; 32], 6), ([0x0e; 32], 10), ([0xfb; 32], 10)]
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        db_path: PathBuf,
        root: PathBuf,
    }

    /// A real, fully migrated ghost.db (WAL mode, as on the fleet) holding one finalised
    /// checkpoint at `H` whose stored root matches its lists, one at `H + 1` whose stored root
    /// does not (the post-#606 median case), one pre-adopt row at `H + 2` with no
    /// canonical_payout, and some MPC lineage.
    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("ghost.db");
        {
            let db = Database::open(&db_path).unwrap();
            let m = miners();
            let n = nodes();
            db.upsert_payout_ledger_checkpoint(&PayoutLedgerCheckpointRecord {
                height: H,
                cutoff_ts: CUTOFF,
                ledger_root: crate::payout::compute_ledger_root(&m, &n, CUTOFF, H),
                proposer_id: hex::encode([0x58; 32]),
                active_node_count: 8,
                miner_payouts: m.clone(),
                node_shares: n.clone(),
            })
            .unwrap();
            // The median moved one address: the stored (proposer's) root no longer recomputes.
            let mut med = m.clone();
            med[0].1 -= 1;
            db.upsert_payout_ledger_checkpoint(&PayoutLedgerCheckpointRecord {
                height: H + 1,
                cutoff_ts: CUTOFF + 600,
                ledger_root: crate::payout::compute_ledger_root(&m, &n, CUTOFF + 600, H + 1),
                proposer_id: hex::encode([0x58; 32]),
                active_node_count: 8,
                miner_payouts: med,
                node_shares: n,
            })
            .unwrap();
            db.with_connection(|c| {
                c.execute_batch(
                    "INSERT INTO payout_ledger_checkpoints \
                       (height, cutoff_ts, ledger_root, proposer_id, active_node_count) \
                       VALUES (970002, 1790001200, zeroblob(32), 'aa', 8);
                     INSERT INTO mpc_ceremony (id, contribution_count, current_params_hash, \
                       is_ossified, updated_at) VALUES (1, 2, x'0102', 0, 1700000000);
                     INSERT INTO mpc_contributions VALUES \
                       (2, 'bb', x'01', x'02', x'ff', 1, 1700000002), \
                       (1, 'aa', x'00', x'01', x'ee', 1, 1700000001);
                     INSERT INTO mpc_verification_votes VALUES (1, 'bb', 1, x'aa', 1700000003);
                     INSERT INTO mpc_params_files VALUES (x'02', '/p/2.bin', 10, 2, 1700000004);",
                )
                .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))
            })
            .unwrap();
        }
        let root = dir.path().to_path_buf();
        Fixture {
            _dir: dir,
            db_path,
            root,
        }
    }

    fn opts(f: &Fixture, out: &str, height: u64, rate: Option<&str>) -> ExportOptions {
        ExportOptions {
            db_path: f.db_path.clone(),
            out_dir: f.root.join(out),
            height,
            sats_per_work: rate.map(str::to_string),
            network: bitcoin::Network::Bitcoin,
            allow_root_mismatch: false,
        }
    }

    fn sha_files(dir: &Path) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| {
                let p = e.unwrap().path();
                let name = p.file_name().unwrap().to_string_lossy().into_owned();
                (
                    name,
                    hex::encode(Sha256::digest(std::fs::read(&p).unwrap())),
                )
            })
            .collect();
        v.sort();
        v
    }

    #[test]
    fn same_db_twice_gives_identical_files_and_digests() {
        let f = fixture();
        let a = run(&opts(&f, "a", H, Some("3/1000"))).unwrap();
        let b = run(&opts(&f, "b", H, Some("3/1000"))).unwrap();
        assert_eq!(a.ledger.digest_sha256, b.ledger.digest_sha256);
        assert_eq!(a.mpc_digest_sha256, b.mpc_digest_sha256);
        assert_eq!(sha_files(&f.root.join("a")), sha_files(&f.root.join("b")));
        // An equal rate written differently is the same export.
        let c = run(&opts(&f, "c", H, Some("0.003"))).unwrap();
        assert_eq!(a.ledger.digest_sha256, c.ledger.digest_sha256);
        // A different rate is not.
        let d = run(&opts(&f, "d", H, Some("3/999"))).unwrap();
        assert_ne!(a.ledger.digest_sha256, d.ledger.digest_sha256);
    }

    /// The stranger's check, from the published files alone: the digest rebuilds from the JSON,
    /// the bin hashes to it, and the exported set recomputes to the fleet's `ledger_root`.
    #[test]
    fn exported_set_recomputes_to_the_checkpoint_ledger_root() {
        let f = fixture();
        let s = run(&opts(&f, "out", H, Some("1/1000000"))).unwrap();
        let json = std::fs::read(f.root.join("out").join(LEDGER_JSON)).unwrap();
        let parsed: LedgerExport = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed, s.ledger);

        let bin = std::fs::read(f.root.join("out").join(LEDGER_BIN)).unwrap();
        assert_eq!(canonical_bytes(&parsed).unwrap(), bin);
        assert_eq!(hex::encode(Sha256::digest(&bin)), parsed.digest_sha256);

        // The exported rows plus the deleted ones are the checkpoint's whole list.
        let m: Vec<(String, u128)> = miners()
            .into_iter()
            .filter(|(a, w)| {
                parsed
                    .miners
                    .iter()
                    .any(|r| &r.address == a && r.work == *w)
                    || parsed
                        .deleted
                        .iter()
                        .any(|r| &r.address == a && r.work == *w)
            })
            .collect();
        assert_eq!(m.len(), miners().len());
        let n: Vec<([u8; 32], i32)> = parsed
            .checkpoint
            .node_shares
            .iter()
            .map(|x| (hex32(&x.node_id, "node").unwrap(), x.shares))
            .collect();
        let root = crate::payout::compute_ledger_root(
            &m,
            &n,
            parsed.checkpoint.cutoff_ts,
            parsed.checkpoint.height,
        );
        assert_eq!(hex::encode(root), parsed.checkpoint.ledger_root);
        assert!(parsed.checkpoint.ledger_root_recomputes);
        assert_eq!(
            parsed.checkpoint.adopted_root,
            parsed.checkpoint.ledger_root
        );
        // And the blob digest matches what shard-anchor-rehearsal.sh compares across nodes.
        let blob = serde_json::to_vec(&(&miners(), &nodes())).unwrap();
        assert_eq!(
            parsed.checkpoint.canonical_payout_sha256,
            hex::encode(Sha256::digest(blob))
        );
        // Every exported address carries its script. The P2PKH balance is deleted (2026-11-03):
        // not exported, not in the table, named in the warnings.
        assert!(parsed
            .miners
            .iter()
            .any(|r| r.script_hex.starts_with("0014")));
        assert!(!parsed
            .miners
            .iter()
            .any(|r| r.script_hex.starts_with("76a914")));
        assert!(!parsed
            .genesis_table
            .iter()
            .any(|r| r.script_hex.starts_with("76a914")));
        assert_eq!(parsed.miners.len(), miners().len() - 1);
        assert!(parsed
            .warnings
            .iter()
            .any(|w| w.contains("deleted 148WRjKfSSo911CYRLzeyYm1QKhy7kCXTN")));
    }

    #[test]
    fn rounding_floors_per_miner_and_reports_the_remainder_exactly() {
        let f = fixture();
        // 1/3 sat per work; micro-work units, so face = floor(work * 2^32 / 3_000_000).
        let s = run(&opts(&f, "out", H, Some("1/3"))).unwrap();
        let l = &s.ledger;
        let d: u128 = 3_000_000;
        assert_eq!(l.totals.remainder_frac_den, d);
        let mut rem_sum: u128 = 0;
        for r in &l.miners {
            let exact = r.work * FACE_UNITS_PER_SAT;
            assert_eq!(r.face_units, exact / d, "{}", r.address);
            rem_sum += exact % d;
        }
        assert_eq!(l.totals.remainder_face_units, rem_sum / d);
        assert_eq!(l.totals.remainder_frac_num, rem_sum % d);
        // Totals cover the exported rows only; the P2PKH row is deleted.
        let total_work: u128 = miners()
            .iter()
            .filter(|(a, _)| !a.starts_with('1'))
            .map(|(_, w)| w)
            .sum();
        assert_eq!(l.totals.work, total_work);
        assert_eq!(
            l.totals.face_units_of_total_work,
            total_work * FACE_UNITS_PER_SAT / d
        );
        assert_eq!(
            l.totals.face_units_of_total_work,
            l.totals.face_units + l.totals.remainder_face_units
        );
        // Hand-checked: 9_741_908 * 2^32 = 41_841_176_260_640_768; / 3e6 = 13_947_058_753 r 1_640_768.
        let small = l.miners.iter().find(|r| r.work == 9_741_908).unwrap();
        assert_eq!(small.face_units, 13_947_058_753);
        // The genesis table is the per-script sum of the floors.
        let table_total: u128 = l.genesis_table.iter().map(|t| t.face_units).sum();
        assert_eq!(table_total, l.totals.face_units);
        // Four checkpoint rows, the P2PKH one deleted.
        assert_eq!(l.genesis_table.len(), 3);
    }

    #[test]
    fn refuses_a_height_that_is_not_finalised() {
        let f = fixture();
        let err = run(&opts(&f, "out", H - 1, Some("1"))).unwrap_err();
        assert!(
            matches!(err, ExportError::NotFinalised(h) if h == H - 1),
            "{err}"
        );
        // A pre-adopt-on-finalise row carries no adopted lists: also refused.
        let err = run(&opts(&f, "out", H + 2, Some("1"))).unwrap_err();
        assert!(matches!(err, ExportError::NoCanonical(_)), "{err}");
        assert!(!f.root.join("out").exists(), "a refusal writes nothing");
    }

    #[test]
    fn refuses_without_a_rate() {
        let f = fixture();
        let err = run(&opts(&f, "out", H, None)).unwrap_err();
        assert!(matches!(err, ExportError::MissingRate), "{err}");
        assert!(!f.root.join("out").exists(), "a refusal writes nothing");
        for bad in ["", "0", "0/5", "1/0", "-1", "abc", "1.2.3", "1e-6"] {
            assert!(parse_rate(Some(bad)).is_err(), "{bad:?} must be refused");
        }
        assert_eq!(parse_rate(Some("2/4")).unwrap(), Rate { num: 1, den: 2 });
        assert_eq!(parse_rate(Some("0.50")).unwrap(), Rate { num: 1, den: 2 });
        assert_eq!(parse_rate(Some(".5")).unwrap(), Rate { num: 1, den: 2 });
        assert_eq!(parse_rate(Some("7")).unwrap(), Rate { num: 7, den: 1 });
    }

    #[test]
    fn refuses_a_root_that_does_not_recompute_unless_allowed() {
        let f = fixture();
        let err = run(&opts(&f, "out", H + 1, Some("1"))).unwrap_err();
        assert!(matches!(err, ExportError::RootMismatch { .. }), "{err}");
        let mut o = opts(&f, "out", H + 1, Some("1"));
        o.allow_root_mismatch = true;
        let s = run(&o).unwrap();
        assert!(!s.ledger.checkpoint.ledger_root_recomputes);
        assert!(s
            .ledger
            .warnings
            .iter()
            .any(|w| w.contains("does not recompute")));
    }

    #[test]
    fn refuses_addresses_from_another_network_and_never_overwrites() {
        let f = fixture();
        let mut o = opts(&f, "out", H, Some("1"));
        o.network = bitcoin::Network::Signet;
        let err = run(&o).unwrap_err();
        assert!(matches!(err, ExportError::BadAddress { .. }), "{err}");

        run(&opts(&f, "out", H, Some("1"))).unwrap();
        let err = run(&opts(&f, "out", H, Some("1"))).unwrap_err();
        assert!(matches!(err, ExportError::OutputExists(_)), "{err}");
    }

    /// A database migrated by the node pool's v65 (version stored negated, payout tables
    /// dropped) is refused by name, not as a missing checkpoint.
    #[test]
    fn refuses_a_database_migrated_by_v65_by_name() {
        let f = fixture();
        {
            let c = rusqlite::Connection::open(&f.db_path).unwrap();
            c.execute_batch("DROP TABLE payout_ledger_checkpoints; PRAGMA user_version = -65;")
                .unwrap();
        }
        let err = run(&opts(&f, "out", H, Some("1"))).unwrap_err();
        assert!(matches!(err, ExportError::Migrated(-65)), "{err}");
        assert!(err.to_string().contains(".pre-v65"), "{err}");
        assert!(!f.root.join("out").join(LEDGER_BIN).exists());
    }

    #[test]
    fn the_database_is_never_written() {
        let f = fixture();
        let before = std::fs::read(&f.db_path).unwrap();
        run(&opts(&f, "out", H, Some("1/3"))).unwrap();
        let _ = run(&opts(&f, "out2", H - 1, Some("1/3")));
        assert_eq!(
            Sha256::digest(std::fs::read(&f.db_path).unwrap()),
            Sha256::digest(&before),
            "ghost.db changed"
        );
        // The connection itself refuses writes.
        let conn = open_read_only(&f.db_path).unwrap();
        assert!(conn
            .execute("DELETE FROM payout_ledger_checkpoints", [])
            .is_err());
        // A missing file is refused rather than created.
        let missing = f.root.join("nope.db");
        assert!(open_read_only(&missing).is_err());
        assert!(!missing.exists());
    }

    #[test]
    fn mpc_lineage_dumps_every_table_in_a_stable_order() {
        let f = fixture();
        let s = run(&opts(&f, "out", H, Some("1"))).unwrap();
        let bytes = std::fs::read(f.root.join("out").join(MPC_JSON)).unwrap();
        assert_eq!(hex::encode(Sha256::digest(&bytes)), s.mpc_digest_sha256);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["format"], MPC_FORMAT);
        for t in MPC_TABLES {
            assert_eq!(v["tables"][t]["present"], true, "{t}");
        }
        let contrib = &v["tables"]["mpc_contributions"]["rows"];
        assert_eq!(contrib.as_array().unwrap().len(), 2);
        // Inserted 2 then 1; dumped 1 then 2.
        assert_eq!(contrib[0][0], 1);
        assert_eq!(contrib[0][4]["blob_hex"], "ee");
        assert_eq!(v["tables"]["mpc_params_files"]["rows"][0][1], "/p/2.bin");
        let sums = std::fs::read_to_string(f.root.join("out").join(SUMS_FILE)).unwrap();
        assert!(sums.contains(&format!("{}  {MPC_JSON}", s.mpc_digest_sha256)));
        assert!(sums.contains(&format!("{}  {LEDGER_BIN}", s.ledger.digest_sha256)));
    }

    #[test]
    fn wide_arithmetic_is_exact() {
        // Agrees with plain u128 where that does not overflow.
        for (a, b, d) in [
            (0u128, 5u128, 7u128),
            (1, 1, 1),
            (123_456_789, 987_654_321, 1_000_003),
            (u64::MAX as u128, 3, 11),
        ] {
            let exact = a * b * FACE_UNITS_PER_SAT;
            assert_eq!(mul_shift_div(a, b, d).unwrap(), (exact / d, exact % d));
        }
        // Past u128 in the middle: (2^100 * 2^60 * 2^32) / 2^100 = 2^92.
        let (q, r) = mul_shift_div(1 << 100, 1 << 60, 1 << 100).unwrap();
        assert_eq!((q, r), (1 << 92, 0));
        // Divisor with the top bit set exercises the carry path.
        let d = (1u128 << 127) + 12345;
        let (q, r) = mul_shift_div(1 << 120, 1 << 100, d).unwrap();
        let (hi, lo) = mul_wide(q, d);
        // q * d + r == 2^252 exactly.
        let (lo2, c) = lo.overflowing_add(r);
        assert_eq!((hi + c as u128, lo2), (1 << 124, 0));
        assert!(r < d);
        // A quotient past u128 is refused, not wrapped.
        assert!(mul_shift_div(u128::MAX, u128::MAX >> 40, 1).is_err());
    }
}
