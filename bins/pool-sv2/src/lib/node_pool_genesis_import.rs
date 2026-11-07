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
//! **Rules**, every one refusing with nothing written: the export checks of
//! [`ghost_common::node_pool_genesis_export`] (digest, layout, rows, `queue_since` at the
//! export's height for every row at or above the floor), shared with `ghost-audit` so the two
//! cannot build different tables from one export, and then:
//!
//! 1. The export's network must be the network `[node_pool.relay]` runs (`bitcoin` and `mainnet`
//!    are the same network).
//! 2. The store must hold no genesis table yet and an empty ledger (no anchors, batches,
//!    credits, retirements, checkpoints or snapshot roots): the import runs once, before the
//!    relay first runs on the store.
//! 3. If a digest is pinned (`[node_pool.relay] genesis_table_digest`, or mainnet's compiled
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
    canonical_payout::table_root,
    node_pool_genesis_export::{hex32, read_export, GenesisExport},
    node_pool_network::{NodePoolNetwork, MAINNET_START},
};
use ghost_storage::{node_pool_genesis::NpGenesisMeta, Database};

use crate::node_pool_relay::NodePoolRelayConfig;

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
