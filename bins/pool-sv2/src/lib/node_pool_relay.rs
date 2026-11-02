//! `[node_pool.relay]`: run the share-chain relay (W2.5) and settlement (W2.7) inside pool_sv2.
//!
//! pool_sv2 owns both ends the relay needs: the shares miners submit, and the
//! [`AnchorDriver`](crate::node_pool::AnchorDriver) that re-stamps every channel's jobs. So the
//! relay runs here, with its own store file. Every accepted share whose hash meets the lowest
//! network tier is offered to it ([`crate::node_pool::NodePool::offer_share`]); the relay keeps
//! those at `T_net` and turns one at `T_net + 8` on a published job into an anchor. Every new best
//! tip, and the 30 s re-batch, is published back to the driver at once.
//!
//! Settlement runs in the same task over the same store: it follows the local Bitcoin node's
//! best chain over RPC, retires what pool blocks paid into the stored ledger, and archives every
//! block it reads in the relay's Bitcoin archive. Every table a share is checked against and every
//! job pays subtracts the pool blocks on its own Bitcoin ancestry, read from that archive (W2.13).
//! The job builder asks the task for its tables ([`crate::node_pool::NodePool::fetch_table`]).
//!
//! Share-chain sync (W2.13) needs nothing configured: a node behind its peers fetches headers,
//! batches and stale Bitcoin blocks from them. `checkpoint_depth` and `prune` set retention.

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use ghost_common::{node_pool_u256::U256, rpc::BitcoinRpc, share_commit::diff1_target};
use ghost_np_relay::{
    archive::BtcArchive,
    headers::{HeaderOracle, RpcHeaderOracle},
    net::{spawn_with_settlement, NetConfig, RelayHandle},
    relay::{Genesis, Relay, RelayParams},
    settlement::{BlockSource, RpcBlockSource, SettledView, Settlement},
};
use ghost_storage::Database;
use tracing::warn;

use crate::node_pool::{AnchorUpdate, NodePool};

/// The relay's settings.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodePoolRelayConfig {
    /// Where to accept peers, e.g. `0.0.0.0:8566`. Absent: outbound only.
    #[serde(default)]
    pub listen: Option<SocketAddr>,
    /// The port peers should dial, when it differs from `listen`'s.
    #[serde(default)]
    pub advertise_port: Option<u16>,
    /// Peers to dial, `host:port`. More are learned from them.
    #[serde(default)]
    pub peers: Vec<String>,
    /// The relay's own store (anchors, batches, shares, ledger).
    pub db_path: PathBuf,
    /// The genesis anchor, 64 hex characters, internal byte order.
    pub genesis_anchor: String,
    /// The genesis anchor's `btc_height`.
    pub genesis_btc_height: u32,
    /// `T_net` at genesis. Defaults to the floor.
    #[serde(default)]
    pub genesis_tier: Option<u8>,
    /// Tier 0 target, 64 hex characters, big-endian. Defaults to the difficulty-1 target; regtest
    /// needs an easier one.
    #[serde(default)]
    pub tier_base: Option<String>,
    /// The local Bitcoin node's RPC, for share headers.
    pub rpc_host: String,
    /// RPC port.
    pub rpc_port: u16,
    /// RPC user.
    pub rpc_user: String,
    /// RPC password.
    pub rpc_password: String,
    /// Fold a ledger checkpoint this many Bitcoin blocks below the share-chain tip (0: never;
    /// otherwise at least 40). Defaults to 288.
    #[serde(default)]
    pub checkpoint_depth: Option<u32>,
    /// Delete stored batches below the older of the two kept checkpoints. Off by default: an
    /// archive node, which can serve a fresh node's sync from genesis.
    #[serde(default)]
    pub prune: bool,
}

/// The `genesis_anchor` an installer writes for a network whose share-chain genesis has not been
/// published yet. A node refuses to start on it rather than guess a genesis: a guessed one is a
/// share chain of its own, which no other node would ever join.
pub const GENESIS_UNSET: &str = "UNSET";

impl NodePoolRelayConfig {
    /// The genesis anchor, refused when it is the [`GENESIS_UNSET`] placeholder, all zeros, or
    /// not 32 bytes of hex. Checked at startup before anything else, so the refusal names the fix.
    pub fn genesis_hash(&self) -> Result<[u8; 32], String> {
        let g = self.genesis_anchor.trim();
        if g.is_empty() || g.eq_ignore_ascii_case(GENESIS_UNSET) {
            return Err(format!(
                "node_pool.relay.genesis_anchor is {GENESIS_UNSET}: the share-chain genesis for \
                 this network has not been published, and this node will not guess one. Set \
                 genesis_anchor (64 hex characters) and genesis_btc_height in [node_pool.relay] \
                 of the pool_sv2 config to the published values, or re-run the installer with \
                 --genesis-anchor and --genesis-height"
            ));
        }
        let h = hex32(g, "node_pool.relay.genesis_anchor")?;
        if h == [0u8; 32] {
            return Err(
                "node_pool.relay.genesis_anchor is all zeros, which is not a genesis".to_string(),
            );
        }
        Ok(h)
    }
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s.trim()).map_err(|e| format!("{what}: {e}"))?;
    v.try_into().map_err(|_| format!("{what}: not 32 bytes"))
}

/// Open the store and start the relay, publishing to `np`'s anchor driver and taking its
/// offered shares.
pub async fn start(cfg: &NodePoolRelayConfig, np: &NodePool) -> Result<RelayHandle, String> {
    let tier_base = match &cfg.tier_base {
        Some(h) => U256::from_be_bytes(hex32(h, "tier_base")?),
        None => diff1_target(),
    };
    let genesis = Genesis {
        hash: cfg.genesis_hash()?,
        btc_height: cfg.genesis_btc_height,
        tier: cfg
            .genesis_tier
            .unwrap_or(ghost_common::node_pool_constants::T_NET_FLOOR),
        // The imported genesis table is the cutover's (plan, Phase 4); until then, empty.
        table: Default::default(),
    };
    let genesis_btc_height = genesis.btc_height;
    let db = Arc::new(Database::open(&cfg.db_path).map_err(|e| format!("relay store: {e}"))?);
    let view = SettledView::load(&db).map_err(|e| format!("settlement view: {e}"))?;
    let archive = BtcArchive::open(db.clone()).map_err(|e| format!("bitcoin archive: {e}"))?;
    let mut params = RelayParams::new(genesis, tier_base);
    if let Some(d) = cfg.checkpoint_depth {
        params.checkpoint_depth = d;
    }
    params.prune = cfg.prune;
    let relay = Relay::open(params, db.clone(), archive).map_err(|e| format!("relay: {e}"))?;
    let rpc = || {
        BitcoinRpc::new(
            &cfg.rpc_host,
            cfg.rpc_port,
            &cfg.rpc_user,
            &cfg.rpc_password,
        )
        .map_err(|e| format!("relay rpc: {e}"))
    };
    let oracle: Arc<dyn HeaderOracle> = Arc::new(RpcHeaderOracle::new(rpc()?));
    let blocks: Arc<dyn BlockSource> = Arc::new(RpcBlockSource::new(rpc()?));
    let settlement = Settlement::new(db, view, genesis_btc_height);
    let mut peers = Vec::new();
    for p in &cfg.peers {
        match tokio::net::lookup_host(p.as_str()).await {
            Ok(mut addrs) => peers.extend(addrs.next()),
            Err(e) => warn!("NODE_POOL_RELAY: peer {p} does not resolve: {e}"),
        }
    }
    let net = NetConfig {
        listen: cfg.listen,
        advertise_port: cfg.advertise_port,
        peers,
        ..NetConfig::default()
    };
    let driver = np.anchor_driver();
    let handle = spawn_with_settlement(
        relay,
        net,
        oracle,
        Arc::new(move |j| {
            driver.publish(AnchorUpdate {
                parent_anchor: j.parent_anchor,
                batch_root: j.batch_root,
            })
        }),
        Some((settlement, blocks)),
    )
    .await
    .map_err(|e| format!("relay listen: {e}"))?;
    np.set_relay_sink(handle.local.clone(), tier_base);
    np.set_table_source(handle.tables.clone());
    warn!(
        listen = ?handle.listen_addr,
        "NODE_POOL_RELAY: the share-chain relay is RUNNING"
    );
    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodePoolConfig;

    const GENESIS: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    fn parse(toml: &str) -> Result<NodePoolConfig, ext_config::ConfigError> {
        ext_config::Config::builder()
            .add_source(ext_config::File::from_str(
                toml,
                ext_config::FileFormat::Toml,
            ))
            .build()?
            .try_deserialize()
    }

    fn relay_toml(db: &std::path::Path, extra: &str) -> String {
        format!(
            "fee_address = \"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\"\n[relay]\nlisten = \"127.0.0.1:0\"\npeers = [\"127.0.0.1:1\"]\ndb_path = {:?}\n\
             genesis_anchor = \"{GENESIS}\"\ngenesis_btc_height = 974400\nrpc_host = \
             \"127.0.0.1\"\nrpc_port = 1\nrpc_user = \"u\"\nrpc_password = \"p\"\n{extra}",
            db.display().to_string()
        )
    }

    #[test]
    fn the_relay_section_parses_and_refuses_unknown_keys() {
        let db = std::path::Path::new("/tmp/np.db");
        let c = parse(&relay_toml(db, "")).unwrap();
        let r = c.relay.expect("relay section");
        assert_eq!(r.genesis_btc_height, 974_400);
        assert_eq!(r.peers, vec!["127.0.0.1:1".to_string()]);
        assert!(r.tier_base.is_none() && r.genesis_tier.is_none());
        assert!(
            r.checkpoint_depth.is_none() && !r.prune,
            "archive node by default"
        );
        let r = parse(&relay_toml(db, "checkpoint_depth = 500\nprune = true\n"))
            .unwrap()
            .relay
            .unwrap();
        assert_eq!((r.checkpoint_depth, r.prune), (Some(500), true));
        assert!(parse(&relay_toml(db, "nonsense = 1\n")).is_err());
        assert!(parse("").is_err(), "fee_address is required");
        let bare = parse("fee_address = \"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\"").unwrap();
        assert!(bare.relay.is_none());
    }

    #[tokio::test]
    async fn a_started_relay_publishes_its_tip_to_the_anchor_driver() {
        let dir = std::env::temp_dir().join(format!("np-relay-start-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = parse(&relay_toml(&dir.join("relay.db"), ""))
            .unwrap()
            .relay
            .unwrap();
        let np = NodePool::from_parts([0x7A; 32], vec![0x51, 0x20], 60.0, 20);
        let mut bad = cfg.clone();
        bad.genesis_anchor = "zz".into();
        assert!(start(&bad, &np).await.is_err());
        let h = start(&cfg, &np).await.unwrap();
        let mut rx = np.subscribe();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            rx.wait_for(|u| u.is_some()),
        )
        .await
        .expect("published")
        .unwrap();
        let u = np.anchor_driver().current().unwrap();
        assert_eq!(u.parent_anchor, hex32(GENESIS, "g").unwrap());
        assert_eq!(u.batch_root, ghost_common::share_commit::batch_root(&[]));
        h.task.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unset_genesis_is_refused_by_name() {
        let db = std::path::Path::new("/tmp/np.db");
        let mut r = parse(&relay_toml(db, "")).unwrap().relay.unwrap();
        assert_eq!(r.genesis_hash().unwrap(), [0xee; 32]);
        for bad in [GENESIS_UNSET, "unset", " ", ""] {
            r.genesis_anchor = bad.into();
            let e = r.genesis_hash().unwrap_err();
            assert!(e.contains("has not been published"), "{bad:?}: {e}");
        }
        r.genesis_anchor = "00".repeat(32);
        assert!(r.genesis_hash().unwrap_err().contains("all zeros"));
        r.genesis_anchor = "ab".repeat(31);
        assert!(r.genesis_hash().unwrap_err().contains("not 32 bytes"));
    }
}
