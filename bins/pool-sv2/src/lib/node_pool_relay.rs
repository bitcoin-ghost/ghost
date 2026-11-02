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
//! best chain over RPC, retires what pool blocks paid, and is the relay's retirement hook, so
//! every table a share is checked against and every job pays subtracts what was paid. The job
//! builder asks the task for its tables ([`crate::node_pool::NodePool::fetch_table`]).
//!
//! **Where the share chain starts (W2.8)** is per network ([`ghost_common::node_pool_network`]):
//! `network` names it, and [`NodePoolRelayConfig::network_start`] resolves the genesis anchor, its
//! height and the pinned genesis table digest, refusing what it cannot vouch for. The effective
//! values are logged once when the relay starts ([`start_log_line`]).

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use ghost_common::{
    canonical_payout::Table,
    node_pool_network::{
        regtest_default_genesis, CompiledStart, NetworkStart, NodePoolNetwork, StartSource,
        MAINNET_START, REGTEST_GENESIS_HEIGHT,
    },
    node_pool_u256::U256,
    rpc::BitcoinRpc,
    share_commit::diff1_target,
};
use ghost_np_relay::{
    headers::{HeaderOracle, RpcHeaderOracle},
    net::{spawn_with_settlement, NetConfig, RelayHandle},
    relay::{Genesis, Relay, RelayParams, RelayStatus},
    settlement::{BlockSource, RpcBlockSource, SettledView, Settlement, SettlementStatus},
};
use ghost_storage::Database;
use tokio::sync::watch;
use tracing::warn;

use crate::node_pool::{AnchorUpdate, NodePool};

/// The relay's settings.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodePoolRelayConfig {
    /// The network this share chain runs on: `mainnet`, `signet` or `regtest`. Absent means
    /// mainnet, the strictest: its start is compiled in, so an unlabelled node cannot be talked
    /// onto a configured genesis.
    #[serde(default)]
    pub network: Option<String>,
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
    /// The pinned digest of the genesis balance table (`canonical_payout::table_root`), 64 hex.
    /// When set, the relay refuses to start on a genesis table with any other digest. Mainnet's
    /// is compiled in with its start.
    #[serde(default)]
    pub genesis_table_digest: Option<String>,
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

impl NodePoolRelayConfig {
    /// The configured network; absent is mainnet.
    pub fn network(&self) -> Result<NodePoolNetwork, String> {
        match &self.network {
            Some(n) => NodePoolNetwork::parse(n).map_err(|e| format!("node_pool.relay.{e}")),
            None => Ok(NodePoolNetwork::Mainnet),
        }
    }

    fn genesis_is_unset(&self) -> bool {
        let g = self.genesis_anchor.trim();
        g.is_empty() || g.eq_ignore_ascii_case(GENESIS_UNSET)
    }

    fn pinned_digest(&self) -> Result<Option<[u8; 32]>, String> {
        self.genesis_table_digest
            .as_deref()
            .map(str::trim)
            .filter(|d| !d.is_empty())
            .map(|d| hex32(d, "node_pool.relay.genesis_table_digest"))
            .transpose()
    }

    /// Where this node's share chain starts, or why it will not start:
    /// - **mainnet**: the compiled [`MAINNET_START`]. While it is unset, an `UNSET` genesis is
    ///   refused by name ([`NodePoolRelayConfig::genesis_hash`]) and any configured genesis is
    ///   refused too. Once set, a configured genesis must equal it, and `tier_base` must be absent
    ///   (mainnet's tier 0 is difficulty 1).
    /// - **signet**: the configured genesis, required.
    /// - **regtest**: the configured genesis, or regtest's default when it is `UNSET` or empty.
    pub fn network_start(&self) -> Result<NetworkStart, String> {
        self.network_start_with(MAINNET_START)
    }

    /// [`NodePoolRelayConfig::network_start`] with mainnet's compiled start given, for tests.
    pub fn network_start_with(
        &self,
        mainnet: Option<CompiledStart>,
    ) -> Result<NetworkStart, String> {
        let network = self.network()?;
        let pinned = self.pinned_digest()?;
        let start = |anchor, height, pinned, source| NetworkStart {
            network,
            genesis_anchor: anchor,
            genesis_btc_height: height,
            pinned_table_digest: pinned,
            source,
        };
        match network {
            NodePoolNetwork::Mainnet => {
                if self.tier_base.is_some() {
                    return Err(
                        "node_pool.relay.tier_base is set on mainnet, whose tier 0 is \
                     the difficulty-1 target: remove it"
                            .to_string(),
                    );
                }
                let Some(c) = mainnet else {
                    // The installer's placeholder: refused by its own message.
                    self.genesis_hash()?;
                    return Err(format!(
                        "node_pool.relay.genesis_anchor is set to {} on mainnet, but mainnet's \
                         share-chain start is compiled into pool_sv2 and this build has none: the \
                         flag day is not set. A configured genesis is not accepted on mainnet; \
                         set genesis_anchor = \"{GENESIS_UNSET}\" and run a release that carries \
                         the published start",
                        self.genesis_anchor.trim()
                    ));
                };
                if !self.genesis_is_unset()
                    && (self.genesis_hash()? != c.genesis_anchor
                        || self.genesis_btc_height != c.genesis_btc_height)
                {
                    return Err(format!(
                        "node_pool.relay.genesis_anchor {} at height {} is not mainnet's \
                         compiled start ({} at height {}): remove it from the config or set it \
                         to {GENESIS_UNSET}",
                        self.genesis_anchor.trim(),
                        self.genesis_btc_height,
                        hex::encode(c.genesis_anchor),
                        c.genesis_btc_height
                    ));
                }
                if pinned.is_some() && pinned != c.genesis_table_digest {
                    return Err(
                        "node_pool.relay.genesis_table_digest differs from mainnet's compiled \
                         digest: remove it from the config"
                            .to_string(),
                    );
                }
                Ok(start(
                    c.genesis_anchor,
                    c.genesis_btc_height,
                    c.genesis_table_digest,
                    StartSource::Compiled,
                ))
            }
            NodePoolNetwork::Signet => Ok(start(
                self.genesis_hash()?,
                self.genesis_btc_height,
                pinned,
                StartSource::Config,
            )),
            NodePoolNetwork::Regtest if self.genesis_is_unset() => {
                if self.genesis_btc_height != REGTEST_GENESIS_HEIGHT {
                    return Err(format!(
                        "node_pool.relay.genesis_btc_height is {} with regtest's default genesis \
                         anchor, whose height is {REGTEST_GENESIS_HEIGHT}: set both or neither",
                        self.genesis_btc_height
                    ));
                }
                Ok(start(
                    regtest_default_genesis(),
                    REGTEST_GENESIS_HEIGHT,
                    pinned,
                    StartSource::Default,
                ))
            }
            NodePoolNetwork::Regtest => Ok(start(
                self.genesis_hash()?,
                self.genesis_btc_height,
                pinned,
                StartSource::Config,
            )),
        }
    }
}

/// The start-up line: every value the share chain starts from, once.
pub fn start_log_line(
    start: &NetworkStart,
    table_digest: &[u8; 32],
    table_rows: usize,
    genesis_tier: u8,
    tier_base: &U256,
) -> String {
    format!(
        "NODE_POOL_START: network={} genesis_anchor={} genesis_btc_height={} source={} \
         genesis_table_digest={} genesis_table_rows={} pinned_digest={} genesis_tier={} \
         tier_base={}",
        start.network,
        hex::encode(start.genesis_anchor),
        start.genesis_btc_height,
        start.source.as_str(),
        hex::encode(table_digest),
        table_rows,
        start
            .pinned_table_digest
            .map_or_else(|| "none".to_string(), hex::encode),
        genesis_tier,
        hex::encode(tier_base.to_be_bytes()),
    )
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s.trim()).map_err(|e| format!("{what}: {e}"))?;
    v.try_into().map_err(|_| format!("{what}: not 32 bytes"))
}

/// What the ledger and status API ([`crate::node_pool_api`]) reads from a running relay.
#[derive(Clone)]
pub struct RelayParts {
    /// The relay's store.
    pub db: Arc<Database>,
    /// Where the share chain starts.
    pub start: NetworkStart,
    /// `T_net` at genesis.
    pub genesis_tier: u8,
    /// The digest of the genesis table it runs on.
    pub genesis_table_digest: [u8; 32],
    /// The relay core's status.
    pub status: watch::Receiver<RelayStatus>,
    /// Settlement's progress.
    pub settlement: watch::Receiver<SettlementStatus>,
}

/// Open the store and start the relay, publishing to `np`'s anchor driver and taking its
/// offered shares.
pub async fn start(cfg: &NodePoolRelayConfig, np: &NodePool) -> Result<RelayHandle, String> {
    start_with_parts(cfg, np).await.map(|(h, _)| h)
}

/// [`start`], also returning what the API reads.
pub async fn start_with_parts(
    cfg: &NodePoolRelayConfig,
    np: &NodePool,
) -> Result<(RelayHandle, RelayParts), String> {
    let net_start = cfg.network_start()?;
    let tier_base = match &cfg.tier_base {
        Some(h) => U256::from_be_bytes(hex32(h, "tier_base")?),
        None => diff1_target(),
    };
    // The imported genesis table is the cutover's (plan, Phase 4, migration v64); until then,
    // empty. Its digest is checked against the pinned one before anything is opened.
    let table = Table::new();
    let table_digest = net_start.check_table(&table)?;
    let genesis_tier = cfg
        .genesis_tier
        .unwrap_or(ghost_common::node_pool_constants::T_NET_FLOOR);
    warn!(
        "{}",
        start_log_line(
            &net_start,
            &table_digest,
            table.len(),
            genesis_tier,
            &tier_base
        )
    );
    let genesis = Genesis {
        hash: net_start.genesis_anchor,
        btc_height: net_start.genesis_btc_height,
        tier: genesis_tier,
        table,
    };
    let genesis_btc_height = genesis.btc_height;
    let db = Arc::new(Database::open(&cfg.db_path).map_err(|e| format!("relay store: {e}"))?);
    let view = SettledView::load(&db).map_err(|e| format!("settlement view: {e}"))?;
    let relay = Relay::open(
        RelayParams::new(genesis, tier_base),
        db.clone(),
        Box::new(view.clone()),
    )
    .map_err(|e| format!("relay: {e}"))?;
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
    let settlement = Settlement::new(db.clone(), view, genesis_btc_height);
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
    let parts = RelayParts {
        db,
        start: net_start,
        genesis_tier,
        genesis_table_digest: table_digest,
        status: handle.status.clone(),
        settlement: handle.settlement.clone(),
    };
    Ok((handle, parts))
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
            "fee_address = \"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\"\n[relay]\nnetwork = \"regtest\"\nlisten = \"127.0.0.1:0\"\npeers = [\"127.0.0.1:1\"]\ndb_path = {:?}\n\
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

    fn relay_cfg(network: Option<&str>, genesis: &str, height: u32) -> NodePoolRelayConfig {
        let mut r = parse(&relay_toml(std::path::Path::new("/tmp/np.db"), ""))
            .unwrap()
            .relay
            .unwrap();
        r.network = network.map(str::to_string);
        r.genesis_anchor = genesis.to_string();
        r.genesis_btc_height = height;
        r
    }

    #[test]
    fn mainnet_refuses_while_its_start_is_not_compiled_in() {
        assert!(MAINNET_START.is_none(), "these cases cover the unset build");
        // An absent network is mainnet.
        for net in [None, Some("mainnet")] {
            let e = relay_cfg(net, GENESIS_UNSET, 0)
                .network_start()
                .unwrap_err();
            assert!(e.contains("has not been published"), "{net:?}: {e}");
            let e = relay_cfg(net, GENESIS, 974_400)
                .network_start()
                .unwrap_err();
            assert!(e.contains("compiled into pool_sv2"), "{net:?}: {e}");
            assert!(e.contains("flag day is not set"), "{e}");
        }
    }

    #[test]
    fn mainnet_runs_only_on_its_compiled_start() {
        let c = CompiledStart {
            genesis_anchor: [0xAB; 32],
            genesis_btc_height: 975_000,
            genesis_table_digest: Some([0xCD; 32]),
        };
        let s = relay_cfg(Some("mainnet"), GENESIS_UNSET, 0)
            .network_start_with(Some(c))
            .unwrap();
        assert_eq!(
            (
                s.genesis_anchor,
                s.genesis_btc_height,
                s.pinned_table_digest
            ),
            ([0xAB; 32], 975_000, Some([0xCD; 32]))
        );
        assert_eq!(s.source, StartSource::Compiled);
        let same = relay_cfg(Some("mainnet"), &"ab".repeat(32), 975_000);
        assert_eq!(same.network_start_with(Some(c)).unwrap(), s);
        let e = relay_cfg(Some("mainnet"), GENESIS, 975_000)
            .network_start_with(Some(c))
            .unwrap_err();
        assert!(e.contains("is not mainnet's compiled start"), "{e}");
        let e = relay_cfg(Some("mainnet"), &"ab".repeat(32), 1)
            .network_start_with(Some(c))
            .unwrap_err();
        assert!(e.contains("is not mainnet's compiled start"), "{e}");
        let mut eased = relay_cfg(Some("mainnet"), GENESIS_UNSET, 0);
        eased.tier_base = Some("7f".repeat(32));
        assert!(eased
            .network_start_with(Some(c))
            .unwrap_err()
            .contains("tier_base"));
        let mut other_digest = relay_cfg(Some("mainnet"), GENESIS_UNSET, 0);
        other_digest.genesis_table_digest = Some("ee".repeat(32));
        assert!(other_digest
            .network_start_with(Some(c))
            .unwrap_err()
            .contains("compiled digest"));
    }

    #[test]
    fn signet_needs_a_configured_genesis_and_regtest_has_a_default() {
        let e = relay_cfg(Some("signet"), GENESIS_UNSET, 0)
            .network_start()
            .unwrap_err();
        assert!(e.contains("has not been published"), "{e}");
        let s = relay_cfg(Some("signet"), GENESIS, 200)
            .network_start()
            .unwrap();
        assert_eq!(
            (s.genesis_anchor, s.genesis_btc_height, s.source),
            ([0xee; 32], 200, StartSource::Config)
        );

        for unset in [GENESIS_UNSET, ""] {
            let s = relay_cfg(Some("regtest"), unset, 0)
                .network_start()
                .unwrap();
            assert_eq!(s.genesis_anchor, regtest_default_genesis());
            assert_eq!(s.genesis_btc_height, 0);
            assert_eq!(s.source, StartSource::Default);
        }
        let e = relay_cfg(Some("regtest"), GENESIS_UNSET, 5)
            .network_start()
            .unwrap_err();
        assert!(e.contains("set both or neither"), "{e}");
        let s = relay_cfg(Some("regtest"), GENESIS, 3)
            .network_start()
            .unwrap();
        assert_eq!(
            (s.genesis_anchor, s.source),
            ([0xee; 32], StartSource::Config)
        );
        let e = relay_cfg(Some("testnet"), GENESIS, 3)
            .network_start()
            .unwrap_err();
        assert!(e.contains("node_pool.relay.network"), "{e}");
    }

    #[tokio::test]
    async fn a_pinned_genesis_table_digest_must_match() {
        let dir = std::env::temp_dir().join(format!("np-relay-digest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut cfg = parse(&relay_toml(&dir.join("relay.db"), ""))
            .unwrap()
            .relay
            .unwrap();
        let np = NodePool::from_parts([0x7A; 32], vec![0x51, 0x20], 60.0, 20);
        cfg.genesis_table_digest = Some("12".repeat(32));
        let Err(e) = start(&cfg, &np).await else {
            panic!("a mismatched digest must refuse")
        };
        assert!(e.contains("differs from the pinned"), "{e}");
        assert!(
            !dir.join("relay.db").exists(),
            "refused before the store opens"
        );
        cfg.genesis_table_digest = Some(hex::encode(
            ghost_common::node_pool_network::genesis_table_digest(&Table::new()),
        ));
        let (h, parts) = start_with_parts(&cfg, &np).await.unwrap();
        assert_eq!(
            parts.start.pinned_table_digest,
            Some(parts.genesis_table_digest)
        );
        assert_eq!(parts.start.network, NodePoolNetwork::Regtest);
        h.task.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_start_up_line_names_every_start_value() {
        let s = relay_cfg(Some("regtest"), GENESIS_UNSET, 0)
            .network_start()
            .unwrap();
        let line = start_log_line(&s, &[0x42; 32], 0, 10, &diff1_target());
        for want in [
            "network=regtest".to_string(),
            format!("genesis_anchor={}", hex::encode(regtest_default_genesis())),
            "genesis_btc_height=0".to_string(),
            "source=default".to_string(),
            format!("genesis_table_digest={}", "42".repeat(32)),
            "genesis_table_rows=0".to_string(),
            "pinned_digest=none".to_string(),
            "genesis_tier=10".to_string(),
            format!("tier_base={}", hex::encode(diff1_target().to_be_bytes())),
        ] {
            assert!(line.contains(&want), "{want} missing from {line}");
        }
    }
}
