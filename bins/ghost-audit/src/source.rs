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
//| FILE: source.rs                                                                                                      |
//|======================================================================================================================|

//! Where the auditor's share-chain data comes from: its own relay node, never the audited node.
//!
//! [`crate::source::start_share_chain`] opens a store in the auditor's data
//! directory and runs a `ghost-np-relay` node exactly as pool_sv2 runs one, minus the pool: it
//! dials the relay peers the miner names, syncs anchors, batches and shares from them (W2.13:
//! `GetHeaders`, `GetBatch`, `GetShares`, `GetBtcBlocks`), checks every share against its
//! including anchor's ancestry, and settles pool blocks from the miner's own Bitcoin node. It
//! trusts nothing a peer says: a peer that lies is refused like any other node refuses it. The
//! tables a job is judged against are then
//! [`ghost_np_relay::relay::Relay::block_table_on`] on this relay, for the job's own `prev_hash`.
//!
//! Why not ask the audited node, or a node named as trusted, for the table? The audited node is
//! the party being checked, and a table from it proves nothing. A trusted node would move the
//! trust rather than remove it. The peers only supply data; the auditor's own relay judges it.
//! Bitcoin blocks come from the miner's Bitcoin node over RPC, as on any node: header heights,
//! and the coinbases settlement reads.
//!
//! **The genesis table.** Every table folds onto the cutover's genesis table, so the auditor's
//! relay must start from the same one the network does, or every job it judges is judged against
//! other balances. [`crate::source::auditor_genesis`] gives it that table: from the published
//! ledger export (`--genesis-export DIR --export-digest HEX`), checked by
//! [`ghost_common::node_pool_genesis_export`], the same checks pool_sv2's import runs, and
//! imported into the auditor's store on first use (`np_import_genesis`, so later runs need no
//! export); or from the table already in its store. Its `table_root` must then equal the
//! network's pinned digest (`--genesis-table-digest`, or mainnet's compiled one), or nothing is
//! audited, probed or listed. Only regtest may run unpinned.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot, watch};

use ghost_common::canonical_payout::{table_root, Table};
use ghost_common::node_pool_genesis_export::read_export;
use ghost_common::node_pool_network::NodePoolNetwork;
use ghost_common::node_pool_u256::U256;
use ghost_common::rpc::BitcoinRpc;
use ghost_np_relay::archive::BtcArchive;
use ghost_np_relay::headers::{HeaderOracle, RpcHeaderOracle};
use ghost_np_relay::net::{spawn_with_settlement, NetConfig, RelayHandle, TableRequest};
use ghost_np_relay::relay::{Genesis, Relay, RelayParams, RelayStatus};
use ghost_np_relay::settlement::{BlockSource, RpcBlockSource, SettledView, Settlement};
use ghost_storage::node_pool_genesis::NpGenesisMeta;
use ghost_storage::Database;

use crate::check::ShareChainData;

/// How long a table request may take before it counts as not answered.
const TABLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The published ledger export the genesis table is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSource {
    /// The directory holding `ledger-export.bin` and `ledger-export.json`.
    pub dir: PathBuf,
    /// The published sha256 of `ledger-export.bin`.
    pub digest: [u8; 32],
}

/// Where the auditor's genesis table comes from and what it must hash to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisSource {
    /// The share chain's network: the export must be for it.
    pub network: NodePoolNetwork,
    /// The export, if given. Without one, the table already in the store (empty if none).
    pub export: Option<ExportSource>,
    /// The network's pinned genesis table digest (`table_root`). `None` only on regtest.
    pub pinned: Option<[u8; 32]>,
}

/// The auditor's share-chain settings: the same genesis and Bitcoin RPC a node uses.
#[derive(Debug, Clone)]
pub struct ChainConfig {
    /// Where the auditor's relay store lives.
    pub data_dir: PathBuf,
    /// The genesis balance table's source and pin.
    pub genesis_table: GenesisSource,
    /// The genesis anchor, internal byte order.
    pub genesis_anchor: [u8; 32],
    /// Its `btc_height`.
    pub genesis_height: u32,
    /// `T_net` at genesis.
    pub genesis_tier: u8,
    /// Tier 0 target.
    pub tier_base: U256,
    /// Relay peers to sync from.
    pub relay_peers: Vec<SocketAddr>,
    /// Bitcoin RPC host.
    pub rpc_host: String,
    /// Bitcoin RPC port.
    pub rpc_port: u16,
    /// Bitcoin RPC user.
    pub rpc_user: String,
    /// Bitcoin RPC password.
    pub rpc_password: String,
}

/// Share-chain data from a running relay node.
pub struct RelayChain {
    tables: mpsc::Sender<TableRequest>,
    status: watch::Receiver<RelayStatus>,
    blocks: Arc<dyn BlockSource>,
    task: tokio::task::JoinHandle<()>,
}

impl RelayChain {
    /// Wrap a running relay and the Bitcoin source its settlement reads.
    pub fn from_handle(handle: RelayHandle, blocks: Arc<dyn BlockSource>) -> RelayChain {
        RelayChain {
            tables: handle.tables,
            status: handle.status,
            blocks,
            task: handle.task,
        }
    }

    /// The relay's status: best anchor, height, peers.
    pub fn status(&self) -> RelayStatus {
        *self.status.borrow()
    }
}

impl Drop for RelayChain {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[async_trait]
impl ShareChainData for RelayChain {
    async fn block_height(&self, hash: &[u8; 32]) -> Option<u32> {
        self.blocks.block(hash).await.map(|b| b.height)
    }

    async fn table(&self, parent: &[u8; 32], h: u32, prev: &[u8; 32]) -> Option<Arc<Table>> {
        let (reply, rx) = oneshot::channel();
        self.tables
            .send(TableRequest {
                parent: *parent,
                height: h,
                prev: Some(*prev),
                reply,
            })
            .await
            .ok()?;
        tokio::time::timeout(TABLE_TIMEOUT, rx).await.ok()?.ok()?
    }
}

/// The genesis table the auditor's relay starts from, refusing anything the network's pin does
/// not match.
///
/// With an export: it is read and checked ([`read_export`]), must be for `src.network`, and is
/// imported into `db` if the store holds no genesis table yet (refused, by the store, once the
/// relay has run on it); a store that already holds one must hold this export's. Without one:
/// the store's table, empty if nothing was ever imported. Then its `table_root` must equal
/// `src.pinned`; with no pin (regtest only) any table is taken.
pub fn auditor_genesis(db: &Database, src: &GenesisSource, now: i64) -> Result<Table, String> {
    let store = |e: ghost_common::error::GhostError| format!("auditor store: {e}");
    let held = db.np_genesis_meta().map_err(store)?;
    let table = match &src.export {
        Some(x) => {
            let e = read_export(&x.dir, &x.digest)?;
            if e.network != src.network {
                return Err(format!(
                    "the export at {} is for {} ({}), and this audit runs on {}",
                    x.dir.display(),
                    e.network,
                    e.network_name,
                    src.network
                ));
            }
            match held {
                Some(m) if m.export_digest != e.digest || m.table_root != e.table_root => {
                    return Err(format!(
                        "the auditor's store holds the genesis table of export {} (table_root \
                         {}), not of {} (table_root {}): use another --data-dir, or move the \
                         store aside",
                        hex::encode(m.export_digest),
                        hex::encode(m.table_root),
                        hex::encode(e.digest),
                        hex::encode(e.table_root)
                    ));
                }
                Some(_) => {}
                None => {
                    let meta = NpGenesisMeta {
                        export_digest: e.digest,
                        network: e.network_name.clone(),
                        export_height: e.height,
                        queue_since: e.queue_since,
                        row_count: e.table.len() as u64,
                        table_root: e.table_root,
                        imported_at: now,
                    };
                    db.np_import_genesis(&e.table, &meta).map_err(|err| {
                        format!(
                            "the auditor's store cannot take the genesis table: {err}. It has \
                             already run on another one; use another --data-dir, or move the \
                             store aside"
                        )
                    })?;
                }
            }
            let stored = db.np_genesis_table().map_err(store)?;
            if stored != e.table {
                return Err("the auditor's stored genesis table differs from the export's".into());
            }
            stored
        }
        None => db.np_genesis_table().map_err(store)?,
    };
    let root = table_root(&table);
    match src.pinned {
        Some(pin) if pin != root => Err(format!(
            "refusing to audit: the auditor's genesis table has table_root {} ({} rows) and {} \
             pins {}. Its tables would not be the network's, so every verdict would be wrong. \
             Pass the network's published export with --genesis-export and --export-digest, or \
             check the pinned digest",
            hex::encode(root),
            table.len(),
            src.network,
            hex::encode(pin)
        )),
        Some(_) => Ok(table),
        None if src.network == NodePoolNetwork::Regtest => Ok(table),
        None => Err(format!(
            "no genesis table digest is pinned for {}: pass --genesis-table-digest (the \
             network's published table_root)",
            src.network
        )),
    }
}

/// Open the auditor's store and start its relay node: outbound only, no pool, syncing from
/// `cfg.relay_peers` and settling from the Bitcoin node at `cfg.rpc_*`.
pub async fn start_share_chain(cfg: &ChainConfig) -> Result<RelayChain, String> {
    let rpc = || {
        BitcoinRpc::new(
            &cfg.rpc_host,
            cfg.rpc_port,
            &cfg.rpc_user,
            &cfg.rpc_password,
        )
        .map_err(|e| format!("bitcoin rpc: {e}"))
    };
    let oracle: Arc<dyn HeaderOracle> = Arc::new(RpcHeaderOracle::new(rpc()?));
    let blocks: Arc<dyn BlockSource> = Arc::new(RpcBlockSource::new(rpc()?));
    let db = open_store(cfg)?;
    let archive = BtcArchive::open(db.clone()).map_err(|e| format!("bitcoin archive: {e}"))?;
    start_share_chain_on(cfg, db, archive, oracle, blocks, NetConfig::default()).await
}

/// The auditor's store in `cfg.data_dir`, created if absent.
pub fn open_store(cfg: &ChainConfig) -> Result<Arc<Database>, String> {
    std::fs::create_dir_all(&cfg.data_dir)
        .map_err(|e| format!("data dir {}: {e}", cfg.data_dir.display()))?;
    Database::open(cfg.data_dir.join("ghost-audit.db"))
        .map(Arc::new)
        .map_err(|e| format!("auditor store: {e}"))
}

/// [`start_share_chain`] on a given store, archive, header oracle, block source and network
/// settings (`net`'s listen address, peers, user agent and node id are the auditor's own): the
/// genesis table is loaded and held to the pin ([`auditor_genesis`]) before the relay is built.
pub async fn start_share_chain_on(
    cfg: &ChainConfig,
    db: Arc<Database>,
    archive: Arc<BtcArchive>,
    oracle: Arc<dyn HeaderOracle>,
    blocks: Arc<dyn BlockSource>,
    net: NetConfig,
) -> Result<RelayChain, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let table = auditor_genesis(&db, &cfg.genesis_table, now)?;
    let genesis = Genesis {
        hash: cfg.genesis_anchor,
        btc_height: cfg.genesis_height,
        tier: cfg.genesis_tier,
        table,
    };
    let view = SettledView::load(&db).map_err(|e| format!("settlement view: {e}"))?;
    let relay = Relay::open(
        RelayParams::new(genesis, cfg.tier_base),
        db.clone(),
        archive,
    )
    .map_err(|e| format!("relay: {e}"))?;
    let settlement = Settlement::new(db, view, cfg.genesis_height);
    let net = NetConfig {
        listen: None,
        peers: cfg.relay_peers.clone(),
        user_agent: format!("ghost-audit/{}", env!("CARGO_PKG_VERSION")),
        node_id: None,
        advert: None,
        ..net
    };
    let handle = spawn_with_settlement(
        relay,
        net,
        oracle,
        Arc::new(|_| {}),
        Some((settlement, blocks.clone())),
    )
    .await
    .map_err(|e| format!("relay: {e}"))?;
    Ok(RelayChain::from_handle(handle, blocks))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::node_pool_constants::FACE_PER_SAT;
    use ghost_common::node_pool_genesis_export::{sample_export, EXPORT_BIN, EXPORT_JSON};

    /// An export directory, removed on drop.
    struct Dir(PathBuf);

    impl Dir {
        fn with(tag: &str, network: &str, rows: &[(Vec<u8>, u128)]) -> (Dir, ExportSource) {
            let p = std::env::temp_dir().join(format!(
                "ghost-audit-genesis-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&p).unwrap();
            let (bin, json, digest) = sample_export(network, 900, rows, rows);
            std::fs::write(p.join(EXPORT_BIN), bin).unwrap();
            std::fs::write(p.join(EXPORT_JSON), json).unwrap();
            let src = ExportSource {
                dir: p.clone(),
                digest,
            };
            (Dir(p), src)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn rows(extra: u128) -> Vec<(Vec<u8>, u128)> {
        vec![
            (vec![0x00, 0x14, 1], 4_000 * FACE_PER_SAT as u128 + extra),
            (vec![0x51, 0x20, 2], 300 * FACE_PER_SAT as u128),
        ]
    }

    fn source(export: Option<ExportSource>, pinned: Option<[u8; 32]>) -> GenesisSource {
        GenesisSource {
            network: NodePoolNetwork::Regtest,
            export,
            pinned,
        }
    }

    fn root_of(x: &ExportSource) -> [u8; 32] {
        read_export(&x.dir, &x.digest).unwrap().table_root
    }

    #[test]
    fn the_export_is_imported_once_and_the_store_serves_later_runs() {
        let (_d, x) = Dir::with("once", "regtest", &rows(0));
        let pin = root_of(&x);
        let db = Database::in_memory().unwrap();
        let t = auditor_genesis(&db, &source(Some(x.clone()), Some(pin)), 5).unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!(table_root(&t), pin);
        let m = db.np_genesis_meta().unwrap().unwrap();
        assert_eq!(
            (m.export_digest, m.table_root, m.imported_at),
            (x.digest, pin, 5)
        );
        // Again with the export: the stored one is checked, not re-imported.
        assert_eq!(
            auditor_genesis(&db, &source(Some(x), Some(pin)), 6).unwrap(),
            t
        );
        // Without it: the store's table, held to the pin.
        assert_eq!(
            auditor_genesis(&db, &source(None, Some(pin)), 7).unwrap(),
            t
        );
    }

    #[test]
    fn a_genesis_that_is_not_the_networks_pinned_one_is_refused() {
        let (_a, honest) = Dir::with("honest", "regtest", &rows(0));
        let (_b, other) = Dir::with("other", "regtest", &rows(1));
        let pin = root_of(&honest);

        // Another export than the network's.
        let db = Database::in_memory().unwrap();
        let e = auditor_genesis(&db, &source(Some(other.clone()), Some(pin)), 1).unwrap_err();
        assert!(
            e.contains("refusing to audit") && e.contains(&hex::encode(pin)),
            "{e}"
        );

        // No export at all: the empty table is not the pinned one.
        let db = Database::in_memory().unwrap();
        let e = auditor_genesis(&db, &source(None, Some(pin)), 1).unwrap_err();
        assert!(
            e.contains("refusing to audit") && e.contains("(0 rows)"),
            "{e}"
        );

        // A store holding one export does not take another.
        let db = Database::in_memory().unwrap();
        auditor_genesis(&db, &source(Some(honest.clone()), Some(pin)), 1).unwrap();
        let e = auditor_genesis(&db, &source(Some(other.clone()), Some(root_of(&other))), 1)
            .unwrap_err();
        assert!(e.contains("holds the genesis table of export"), "{e}");

        // A wrong export digest, and an export for another network.
        let mut bad = honest.clone();
        bad.digest[0] ^= 1;
        let db = Database::in_memory().unwrap();
        let e = auditor_genesis(&db, &source(Some(bad), Some(pin)), 1).unwrap_err();
        assert!(e.contains("not the published export"), "{e}");
        let (_c, signet) = Dir::with("signet", "signet", &rows(0));
        let e = auditor_genesis(&db, &source(Some(signet), Some(pin)), 1).unwrap_err();
        assert!(e.contains("this audit runs on regtest"), "{e}");
        assert!(db.np_genesis_meta().unwrap().is_none(), "nothing imported");
    }

    #[test]
    fn only_regtest_runs_without_a_pin() {
        let db = Database::in_memory().unwrap();
        assert!(auditor_genesis(&db, &source(None, None), 1)
            .unwrap()
            .is_empty());
        for network in [NodePoolNetwork::Signet, NodePoolNetwork::Mainnet] {
            let src = GenesisSource {
                network,
                export: None,
                pinned: None,
            };
            let e = auditor_genesis(&db, &src, 1).unwrap_err();
            assert!(e.contains("no genesis table digest is pinned"), "{e}");
        }
    }

    #[test]
    fn a_store_that_has_run_on_another_genesis_cannot_take_the_export() {
        let (_d, x) = Dir::with("used", "regtest", &rows(0));
        let db = Database::in_memory().unwrap();
        db.np_apply_block(&[0xA0; 32], 121, &[(vec![0x51], 1)], 0)
            .unwrap();
        let e = auditor_genesis(&db, &source(Some(x.clone()), Some(root_of(&x))), 1).unwrap_err();
        assert!(e.contains("already run on another one"), "{e}");
    }
}
