//|======================================================================================================================|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: node_pool_genesis_import.rs                                                                                    |
//|======================================================================================================================|

//! The genesis import (plan Phase 4, migration v65): load the cutover's ledger export into the
//! relay's store as the share chain's genesis table, offline, before the relay first runs.
//!
//! ```text
//! pool_sv2 -c pool-config.toml --np-import-genesis DIR --np-export-digest HEX [--np-verify-genesis]
//! ```
//!
//! `DIR` holds `ledger-export.bin` and `ledger-export.json` as `ghost-mining --np-export` writes
//! them (`docs/LEDGER_EXPORT.md` on `feat/ledger-export`). The store and the network are the
//! ones `[node_pool.relay]` names (`db_path`, `network`), so the import cannot land in a store
//! the pool does not run on. pool_sv2 owns that store and is the only process that opens it,
//! which is why the import is a pool_sv2 flag and not a separate tool.
//!
//! **Rules**, every one refusing with nothing written:
//!
//! 1. `sha256(ledger-export.bin)` must equal `--np-export-digest`, the digest the fleet compared
//!    and published. The JSON's `digest_sha256` must equal it too.
//! 2. The binary must start with `GhostLedgerExport/v1`, its network and its height (the stable
//!    prefix of the format), and must end with the genesis table exactly as the JSON lists it
//!    followed by the 96-byte totals block. The rows are therefore covered by the digest; nothing
//!    between the prefix and the rows (the source checkpoint, the rate, the miner list) is read,
//!    so the import does not depend on which source the export was taken from.
//! 3. The JSON's network must equal the binary's, and both must be the network `[node_pool.relay]`
//!    runs (`bitcoin` and `mainnet` are the same network).
//! 4. Rows strictly ascending by script, no empty script, every amount at most `i128::MAX` face
//!    units. Units are taken as they are: the export already converted work to `2^-32` sat.
//! 5. **`queue_since`**: every row owed at least the payout floor
//!    ([`PAYOUT_FLOOR_FACE`]) gets `queue_since = H`, the export's height (the freeze height);
//!    rows below the floor get none. Derived, not a parameter: every node importing the same
//!    digest builds the same table and the same `table_root`, with nothing to mistype. The old
//!    balances therefore queue ahead of anything credited on the share chain, which starts above
//!    the freeze, and among themselves by amount, then script (the pay order's tie-break).
//! 6. The store must hold no genesis table yet and an empty ledger (no anchors, batches,
//!    credits, retirements, checkpoints or snapshot roots): the import runs once, before the
//!    relay first runs on the store.
//! 7. If a digest is pinned (`[node_pool.relay] genesis_table_digest`, or mainnet's compiled
//!    start), the table's `table_root` must equal it.
//!
//! It prints the `table_root`: the value to pin as `genesis_table_digest` (W2.8) and, for
//! mainnet, in `node_pool_network::MAINNET_START`. The relay checks the stored table against
//! the pin at every start ([`crate::node_pool_relay::start_with_parts`]).
//!
//! `--np-verify-genesis` writes nothing: it rebuilds the table from the export, checks it
//! against the store's (export digest, rows, `table_root`) and prints the same root. It can be
//! run any number of times, on any node, to confirm the store holds the published table.

use std::path::{Path, PathBuf};

use ghost_common::{
    canonical_payout::{table_root, Balance, Table},
    node_pool_constants::PAYOUT_FLOOR_FACE,
    node_pool_network::{NodePoolNetwork, MAINNET_START},
};
use ghost_storage::{node_pool_genesis::NpGenesisMeta, Database};
use sha2::{Digest, Sha256};

use crate::node_pool_relay::NodePoolRelayConfig;

/// The export binary's magic, its first bytes.
pub const LEDGER_MAGIC: &[u8] = b"GhostLedgerExport/v1";

/// The export binary's file name in the export directory.
pub const EXPORT_BIN: &str = "ledger-export.bin";

/// The export JSON's file name in the export directory.
pub const EXPORT_JSON: &str = "ledger-export.json";

/// Bytes after the genesis rows: six `u128` totals.
const TOTALS_LEN: usize = 6 * 16;

/// What the import reads from the JSON: only what it needs, so the rest of the format can change.
#[derive(serde::Deserialize)]
struct ExportJson {
    digest_sha256: String,
    network: String,
    genesis_table: Vec<ExportRow>,
}

#[derive(serde::Deserialize)]
struct ExportRow {
    script_hex: String,
    face_units: String,
}

/// An export, checked and turned into a genesis table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisExport {
    /// sha256 of `ledger-export.bin`.
    pub digest: [u8; 32],
    /// The network as the export names it.
    pub network_name: String,
    /// That network.
    pub network: NodePoolNetwork,
    /// The export's height: the freeze height.
    pub height: u64,
    /// The `queue_since` given to rows at or above the floor (= `height`).
    pub queue_since: u32,
    /// The genesis table.
    pub table: Table,
    /// Its `table_root`.
    pub table_root: [u8; 32],
}

fn take<'a>(b: &'a [u8], at: &mut usize, n: usize, what: &str) -> Result<&'a [u8], String> {
    let end = at
        .checked_add(n)
        .filter(|e| *e <= b.len())
        .ok_or_else(|| format!("{EXPORT_BIN} ends inside {what}"))?;
    let s = &b[*at..end];
    *at = end;
    Ok(s)
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s.trim()).map_err(|e| format!("{what}: {e}"))?;
    v.try_into().map_err(|_| format!("{what}: not 32 bytes"))
}

/// The rows as the binary encodes them: `u32 n`, then per row `u16 len || script || u128 face`.
fn encode_rows(rows: &[(Vec<u8>, u128)]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let n = u32::try_from(rows.len()).map_err(|_| "too many genesis rows".to_string())?;
    out.extend_from_slice(&n.to_be_bytes());
    for (s, f) in rows {
        let len = u16::try_from(s.len()).map_err(|_| format!("script of {} bytes", s.len()))?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(s);
        out.extend_from_slice(&f.to_be_bytes());
    }
    Ok(out)
}

/// Build the genesis table from the export's rows: rule 4 and the `queue_since` rule (5).
pub fn genesis_table(rows: &[(Vec<u8>, u128)], queue_since: u32) -> Result<Table, String> {
    let mut t = Table::new();
    let mut prev: Option<&Vec<u8>> = None;
    for (script, face) in rows {
        if script.is_empty() {
            return Err("a genesis row has an empty script".to_string());
        }
        if prev.is_some_and(|p| p >= script) {
            return Err(format!(
                "genesis rows are not strictly ascending by script at {}",
                hex::encode(script)
            ));
        }
        prev = Some(script);
        let owed = i128::try_from(*face).map_err(|_| {
            format!(
                "{} owes {face} face units, above i128::MAX",
                hex::encode(script)
            )
        })?;
        t.insert(
            script.clone(),
            Balance {
                owed,
                queue_since: (owed >= PAYOUT_FLOOR_FACE).then_some(queue_since),
            },
        );
    }
    Ok(t)
}

/// Check an export against `expected` (rules 1-5) and build its table.
pub fn parse_export(bin: &[u8], json: &[u8], expected: &[u8; 32]) -> Result<GenesisExport, String> {
    let digest: [u8; 32] = Sha256::digest(bin).into();
    if &digest != expected {
        return Err(format!(
            "{EXPORT_BIN} has sha256 {}, not the expected {}: this is not the published export",
            hex::encode(digest),
            hex::encode(expected)
        ));
    }
    let j: ExportJson =
        serde_json::from_slice(json).map_err(|e| format!("{EXPORT_JSON} does not parse: {e}"))?;
    if &hex32(&j.digest_sha256, "digest_sha256")? != expected {
        return Err(format!(
            "{EXPORT_JSON} names digest {}, not the expected {}: the two files are not one export",
            j.digest_sha256.trim(),
            hex::encode(expected)
        ));
    }

    let mut at = 0usize;
    if take(bin, &mut at, LEDGER_MAGIC.len(), "the magic")? != LEDGER_MAGIC {
        return Err(format!(
            "{EXPORT_BIN} does not start with GhostLedgerExport/v1"
        ));
    }
    let len = u16::from_be_bytes(
        take(bin, &mut at, 2, "the network")?
            .try_into()
            .unwrap_or([0; 2]),
    );
    let network_name = std::str::from_utf8(take(bin, &mut at, len as usize, "the network")?)
        .map_err(|_| format!("{EXPORT_BIN}: the network is not UTF-8"))?
        .to_string();
    let height = u64::from_be_bytes(
        take(bin, &mut at, 8, "the height")?
            .try_into()
            .unwrap_or([0; 8]),
    );
    if j.network != network_name {
        return Err(format!(
            "{EXPORT_JSON} says network {:?} and {EXPORT_BIN} says {network_name:?}",
            j.network
        ));
    }
    let network = NodePoolNetwork::parse(&network_name).map_err(|e| format!("the export's {e}"))?;
    let queue_since = u32::try_from(height)
        .map_err(|_| format!("the export's height {height} does not fit a Bitcoin height"))?;

    let mut rows = Vec::with_capacity(j.genesis_table.len());
    for r in &j.genesis_table {
        let script = hex::decode(r.script_hex.trim())
            .map_err(|e| format!("genesis row script_hex {:?}: {e}", r.script_hex))?;
        let face: u128 = r
            .face_units
            .trim()
            .parse()
            .map_err(|e| format!("genesis row face_units {:?}: {e}", r.face_units))?;
        rows.push((script, face));
    }
    let enc = encode_rows(&rows)?;
    let tail = enc.len() + TOTALS_LEN;
    if bin.len() < at + tail || bin[bin.len() - tail..bin.len() - TOTALS_LEN] != enc[..] {
        return Err(format!(
            "the genesis table in {EXPORT_JSON} ({} rows) is not the one in {EXPORT_BIN}: the \
             JSON's rows must be exactly the rows the digest covers",
            rows.len()
        ));
    }
    let table = genesis_table(&rows, queue_since)?;
    Ok(GenesisExport {
        digest,
        network_name,
        network,
        height,
        queue_since,
        table_root: table_root(&table),
        table,
    })
}

/// Read and check the export in `dir`.
pub fn read_export(dir: &Path, expected: &[u8; 32]) -> Result<GenesisExport, String> {
    let read = |name: &str| {
        let p = dir.join(name);
        std::fs::read(&p).map_err(|e| format!("cannot read {}: {e}", p.display()))
    };
    parse_export(&read(EXPORT_BIN)?, &read(EXPORT_JSON)?, expected)
}

/// The digest a node would hold this table to: the configured pin, else mainnet's compiled one.
fn pinned(cfg: &NodePoolRelayConfig, network: NodePoolNetwork) -> Result<Option<[u8; 32]>, String> {
    if let Some(d) = cfg
        .genesis_table_digest
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
    {
        return hex32(d, "node_pool.relay.genesis_table_digest").map(Some);
    }
    Ok(match network {
        NodePoolNetwork::Mainnet => MAINNET_START.and_then(|s| s.genesis_table_digest),
        _ => None,
    })
}

/// What an import or a verification did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSummary {
    /// The store.
    pub db_path: PathBuf,
    /// The checked export.
    pub export: GenesisExport,
    /// `true` for `--np-verify-genesis` (nothing written).
    pub verified_only: bool,
}

impl ImportSummary {
    /// The lines printed on success; the last names the value to pin.
    pub fn lines(&self) -> Vec<String> {
        let e = &self.export;
        let total: i128 = e.table.values().map(|b| b.owed).sum();
        vec![
            format!(
                "NODE_POOL_GENESIS_{}: store={} network={} export_digest={} export_height={} \
                 rows={} owed_face_units={} queue_since={} table_root={}",
                if self.verified_only {
                    "VERIFIED"
                } else {
                    "IMPORTED"
                },
                self.db_path.display(),
                e.network,
                hex::encode(e.digest),
                e.height,
                e.table.len(),
                total,
                e.queue_since,
                hex::encode(e.table_root),
            ),
            format!(
                "pin it: [node_pool.relay] genesis_table_digest = \"{}\"",
                hex::encode(e.table_root)
            ),
        ]
    }
}

/// Import (or, with `verify_only`, verify) the export in `dir` into `cfg`'s store.
pub fn run(
    cfg: &NodePoolRelayConfig,
    dir: &Path,
    expected: &[u8; 32],
    verify_only: bool,
    now: i64,
) -> Result<ImportSummary, String> {
    let export = read_export(dir, expected)?;
    let network = cfg.network()?;
    if export.network != network {
        return Err(format!(
            "the export is for {} ({}) and this node's share chain runs on {network}",
            export.network, export.network_name
        ));
    }
    if let Some(pin) = pinned(cfg, network)? {
        if pin != export.table_root {
            return Err(format!(
                "the export's genesis table has table_root {}, and this node pins {}: the relay \
                 would refuse it",
                hex::encode(export.table_root),
                hex::encode(pin)
            ));
        }
    }
    let summary = |verified_only| ImportSummary {
        db_path: cfg.db_path.clone(),
        export: export.clone(),
        verified_only,
    };

    if verify_only {
        if !cfg.db_path.exists() {
            return Err(format!("no store at {}", cfg.db_path.display()));
        }
        let db = Database::open(&cfg.db_path).map_err(|e| format!("relay store: {e}"))?;
        let meta = db
            .np_genesis_meta()
            .map_err(|e| format!("relay store: {e}"))?
            .ok_or_else(|| format!("{} holds no genesis table", cfg.db_path.display()))?;
        let stored = db
            .np_genesis_table()
            .map_err(|e| format!("relay store: {e}"))?;
        if meta.export_digest != export.digest {
            return Err(format!(
                "the store's genesis table came from export {}, not {}",
                hex::encode(meta.export_digest),
                hex::encode(export.digest)
            ));
        }
        if stored != export.table || meta.table_root != export.table_root {
            return Err(format!(
                "the store's genesis table (root {}) differs from the export's (root {})",
                hex::encode(meta.table_root),
                hex::encode(export.table_root)
            ));
        }
        return Ok(summary(true));
    }

    let db = Database::open(&cfg.db_path).map_err(|e| format!("relay store: {e}"))?;
    let meta = NpGenesisMeta {
        export_digest: export.digest,
        network: export.network_name.clone(),
        export_height: export.height,
        queue_since: export.queue_since,
        row_count: export.table.len() as u64,
        table_root: export.table_root,
        imported_at: now,
    };
    db.np_import_genesis(&export.table, &meta)
        .map_err(|e| format!("genesis import refused: {e}"))?;
    let back = db
        .np_genesis_table()
        .map_err(|e| format!("relay store: {e}"))?;
    if table_root(&back) != export.table_root {
        return Err("the stored genesis table does not read back as written".to_string());
    }
    Ok(summary(false))
}

#[cfg(test)]
#[path = "node_pool_genesis_import_tests.rs"]
mod tests;
