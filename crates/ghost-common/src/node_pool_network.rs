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
//| FILE: node_pool_network.rs                                                                                           |
//|======================================================================================================================|

//! Where each network's share chain starts (plan W2.8).
//!
//! A share chain starts at a genesis anchor: a hash no share can have, its Bitcoin height, and
//! the genesis balance table every snapshot folds onto (the table imported at the cutover, plan
//! Phase 4; empty until migration v64 imports it). Two nodes with different starts run different
//! share chains and never agree on a balance, so the start is fixed per network:
//!
//! - **regtest**: configuration. The default is [`regtest_default_genesis`](crate::node_pool_network::regtest_default_genesis) at height 0, the
//!   value the installer writes, so every regtest node shares it without being told.
//! - **signet**: configuration, required. Our signet's start is published with its launch.
//! - **mainnet**: compiled in, [`MAINNET_START`](crate::node_pool_network::MAINNET_START). It is unset until the flag day: a mainnet node
//!   refuses to start rather than guess, and a configured genesis is accepted only when it equals
//!   the compiled one.
//!
//! The genesis table is identified by its
//! [`genesis_table_digest`](crate::node_pool_network::genesis_table_digest), the same
//! [`table_root`](crate::canonical_payout::table_root) a block commits for its snapshot. A start
//! may pin it; a node then refuses to run on a genesis table whose digest differs.
//!
//! Pure: no I/O. The configuration side (reading, refusing, logging) is pool_sv2's.

use sha2::{Digest, Sha256};

use crate::canonical_payout::{table_root, Table};

/// The networks a node pool share chain runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodePoolNetwork {
    /// Bitcoin mainnet.
    Mainnet,
    /// Our signet.
    Signet,
    /// A local regtest chain.
    Regtest,
}

impl NodePoolNetwork {
    /// Parse a configured name: `mainnet` (also `bitcoin` and `main`), `signet` or `regtest`.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "mainnet" | "bitcoin" | "main" => Ok(Self::Mainnet),
            "signet" => Ok(Self::Signet),
            "regtest" => Ok(Self::Regtest),
            other => Err(format!(
                "network {other:?} is not one the node pool runs on (mainnet, signet or regtest)"
            )),
        }
    }

    /// The name the installer and the logs use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        }
    }

    /// The matching `bitcoin` crate network, for address encoding and checks.
    pub fn bitcoin_network(self) -> bitcoin::Network {
        match self {
            Self::Mainnet => bitcoin::Network::Bitcoin,
            Self::Signet => bitcoin::Network::Signet,
            Self::Regtest => bitcoin::Network::Regtest,
        }
    }
}

impl std::fmt::Display for NodePoolNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A start compiled into the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompiledStart {
    /// The genesis anchor, internal byte order.
    pub genesis_anchor: [u8; 32],
    /// Its `btc_height`.
    pub genesis_btc_height: u32,
    /// The pinned digest of the genesis table, when one is published.
    pub genesis_table_digest: Option<[u8; 32]>,
}

/// Mainnet's share-chain start. **Unset**: it is set, with the genesis table's digest, once the
/// flag day and the imported table are agreed (plan Phase 4). Until then a mainnet node refuses
/// to start.
pub const MAINNET_START: Option<CompiledStart> = None;

/// The label regtest's default genesis anchor is the SHA-256 of.
pub const REGTEST_GENESIS_LABEL: &[u8] = b"GhostNodePool/genesis/regtest";

/// Regtest's default genesis height.
pub const REGTEST_GENESIS_HEIGHT: u32 = 0;

/// Regtest's default genesis anchor: `sha256("GhostNodePool/genesis/regtest")`, the value the
/// installer writes (`8d8cd561…9c69f1229c`).
pub fn regtest_default_genesis() -> [u8; 32] {
    Sha256::digest(REGTEST_GENESIS_LABEL).into()
}

/// The digest a start pins a genesis table by: its `table_root`.
pub fn genesis_table_digest(table: &Table) -> [u8; 32] {
    table_root(table)
}

/// Where a start's values came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartSource {
    /// The node's configuration.
    Config,
    /// Compiled into the binary (mainnet).
    Compiled,
    /// The network's built-in default (regtest).
    Default,
}

impl StartSource {
    /// Name for logs and the status API.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Compiled => "compiled",
            Self::Default => "default",
        }
    }
}

/// The effective start of this node's share chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkStart {
    /// The network.
    pub network: NodePoolNetwork,
    /// The genesis anchor, internal byte order.
    pub genesis_anchor: [u8; 32],
    /// Its `btc_height`.
    pub genesis_btc_height: u32,
    /// The pinned genesis table digest, if any.
    pub pinned_table_digest: Option<[u8; 32]>,
    /// Where the anchor and height came from.
    pub source: StartSource,
}

impl NetworkStart {
    /// Check `table` against the pinned digest. Returns its digest, or a refusal naming both.
    pub fn check_table(&self, table: &Table) -> Result<[u8; 32], String> {
        let digest = genesis_table_digest(table);
        match self.pinned_table_digest {
            Some(pinned) if pinned != digest => Err(format!(
                "the genesis table's digest {} differs from the pinned {} for {}: this node \
                 holds a different genesis table from the one its share chain starts on, and \
                 will not run on it",
                hex::encode(digest),
                hex::encode(pinned),
                self.network
            )),
            _ => Ok(digest),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_payout::Balance;

    #[test]
    fn the_regtest_default_is_the_installers() {
        assert_eq!(
            hex::encode(regtest_default_genesis()),
            "8d8cd561340ff83e99410e115619d64ad94516264d3e5cd6a991109c69f1229c"
        );
        assert_eq!(REGTEST_GENESIS_HEIGHT, 0);
    }

    #[test]
    fn mainnet_is_unset_until_the_flag_day() {
        assert!(MAINNET_START.is_none());
    }

    #[test]
    fn network_names_parse() {
        for (s, n) in [
            ("mainnet", NodePoolNetwork::Mainnet),
            ("Bitcoin", NodePoolNetwork::Mainnet),
            ("main", NodePoolNetwork::Mainnet),
            (" signet ", NodePoolNetwork::Signet),
            ("regtest", NodePoolNetwork::Regtest),
        ] {
            assert_eq!(NodePoolNetwork::parse(s).unwrap(), n);
        }
        assert!(NodePoolNetwork::parse("testnet").is_err());
        assert_eq!(
            NodePoolNetwork::Signet.bitcoin_network(),
            bitcoin::Network::Signet
        );
    }

    #[test]
    fn a_pinned_digest_refuses_any_other_table() {
        let empty = Table::new();
        let mut one = Table::new();
        one.insert(
            vec![0x51, 0x20],
            Balance {
                owed: 5,
                queue_since: None,
            },
        );
        let mut s = NetworkStart {
            network: NodePoolNetwork::Signet,
            genesis_anchor: [1; 32],
            genesis_btc_height: 7,
            pinned_table_digest: None,
            source: StartSource::Config,
        };
        assert_eq!(s.check_table(&one).unwrap(), table_root(&one));
        s.pinned_table_digest = Some(genesis_table_digest(&empty));
        assert_eq!(s.check_table(&empty).unwrap(), table_root(&empty));
        let e = s.check_table(&one).unwrap_err();
        assert!(e.contains("differs from the pinned"), "{e}");
        assert!(e.contains(&hex::encode(table_root(&one))), "{e}");
    }
}
