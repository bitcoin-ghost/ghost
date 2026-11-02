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
//! [`start_share_chain`](crate::source::start_share_chain) opens a store in the auditor's data
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

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, oneshot, watch};

use ghost_common::canonical_payout::Table;
use ghost_common::node_pool_u256::U256;
use ghost_common::rpc::BitcoinRpc;
use ghost_np_relay::archive::BtcArchive;
use ghost_np_relay::headers::{HeaderOracle, RpcHeaderOracle};
use ghost_np_relay::net::{spawn_with_settlement, NetConfig, RelayHandle, TableRequest};
use ghost_np_relay::relay::{Genesis, Relay, RelayParams, RelayStatus};
use ghost_np_relay::settlement::{BlockSource, RpcBlockSource, SettledView, Settlement};
use ghost_storage::Database;

use crate::check::ShareChainData;

/// How long a table request may take before it counts as not answered.
const TABLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The auditor's share-chain settings: the same genesis and Bitcoin RPC a node uses.
#[derive(Debug, Clone)]
pub struct ChainConfig {
    /// Where the auditor's relay store lives.
    pub data_dir: PathBuf,
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

/// Open the auditor's store and start its relay node: outbound only, no pool, syncing from
/// `cfg.relay_peers` and settling from the Bitcoin node at `cfg.rpc_*`.
pub async fn start_share_chain(cfg: &ChainConfig) -> Result<RelayChain, String> {
    std::fs::create_dir_all(&cfg.data_dir)
        .map_err(|e| format!("data dir {}: {e}", cfg.data_dir.display()))?;
    let db = Arc::new(
        Database::open(cfg.data_dir.join("ghost-audit.db"))
            .map_err(|e| format!("auditor store: {e}"))?,
    );
    let genesis = Genesis {
        hash: cfg.genesis_anchor,
        btc_height: cfg.genesis_height,
        tier: cfg.genesis_tier,
        // The cutover's imported genesis table (plan, Phase 4) is not published yet; pool_sv2
        // starts from the empty table too.
        table: Default::default(),
    };
    let view = SettledView::load(&db).map_err(|e| format!("settlement view: {e}"))?;
    let archive = BtcArchive::open(db.clone()).map_err(|e| format!("bitcoin archive: {e}"))?;
    let relay = Relay::open(
        RelayParams::new(genesis, cfg.tier_base),
        db.clone(),
        archive,
    )
    .map_err(|e| format!("relay: {e}"))?;
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
    let settlement = Settlement::new(db, view, cfg.genesis_height);
    let net = NetConfig {
        listen: None,
        peers: cfg.relay_peers.clone(),
        user_agent: format!("ghost-audit/{}", env!("CARGO_PKG_VERSION")),
        node_id: None,
        ..NetConfig::default()
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
