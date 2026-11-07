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
//! - **mainnet**: compiled in, [`MAINNET_START`](crate::node_pool_network::MAINNET_START). It is set at the flag day (genesis 974,875): a mainnet node
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

use crate::canonical_payout::{table_root, Halving, Table};

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

    /// The network's subsidy schedule: regtest halves every 150 blocks, mainnet and signet every
    /// 210,000.
    pub fn halving(self) -> Halving {
        match self {
            Self::Mainnet | Self::Signet => Halving::MAINNET,
            Self::Regtest => Halving::REGTEST,
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

/// Mainnet's share-chain start, set at the flag day (2026-11-07).
///
/// - Genesis height 974,875: the old network's freeze, where all 8 old nodes held the
///   byte-identical finalised checkpoint (ledger root `e3cb77a2…dc8afe56`).
/// - Genesis table: the old ledger exported at that height at `Rm / D_avg` =
///   310,937,500 / 137,301,110,231,780 sats per difficulty-1 unit (the year's average
///   difficulty, floored); export digest `cfb62020…44dcb74e`, 4 rows, table root `43e8165e…71410d2d`.
/// - Genesis anchor: `sha256("GhostNodePool/genesis/mainnet" || table_root)`.
pub const MAINNET_START: Option<CompiledStart> = Some(CompiledStart {
    genesis_anchor: MAINNET_GENESIS_ANCHOR,
    genesis_btc_height: 974_875,
    genesis_table_digest: Some(MAINNET_GENESIS_TABLE_ROOT),
});

/// The label mainnet's genesis anchor hashes, followed by the genesis table root.
pub const MAINNET_GENESIS_LABEL: &[u8] = b"GhostNodePool/genesis/mainnet";

/// Mainnet's genesis table root (`table_root` of the imported old ledger), `43e8165e7ac1ba4b67b328ab0a2ecb8aa20cb2fb2a780b3e3527e59e71410d2d`.
pub const MAINNET_GENESIS_TABLE_ROOT: [u8; 32] = [
    0x43, 0xe8, 0x16, 0x5e, 0x7a, 0xc1, 0xba, 0x4b, 0x67, 0xb3, 0x28, 0xab, 0x0a, 0x2e, 0xcb, 0x8a,
    0xa2, 0x0c, 0xb2, 0xfb, 0x2a, 0x78, 0x0b, 0x3e, 0x35, 0x27, 0xe5, 0x9e, 0x71, 0x41, 0x0d, 0x2d,
];

/// Mainnet's genesis anchor, `a512f0c9378c31fe34160ee6388b62289596e46110d45079eec8eafe8c4c4526`.
pub const MAINNET_GENESIS_ANCHOR: [u8; 32] = [
    0xa5, 0x12, 0xf0, 0xc9, 0x37, 0x8c, 0x31, 0xfe, 0x34, 0x16, 0x0e, 0xe6, 0x38, 0x8b, 0x62, 0x28,
    0x95, 0x96, 0xe4, 0x61, 0x10, 0xd4, 0x50, 0x79, 0xee, 0xc8, 0xea, 0xfe, 0x8c, 0x4c, 0x45, 0x26,
];

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
    fn mainnet_starts_at_the_flag_day() {
        let c = MAINNET_START.expect("set at the flag day");
        assert_eq!(c.genesis_btc_height, 974_875);
        assert_eq!(c.genesis_table_digest, Some(MAINNET_GENESIS_TABLE_ROOT));
        let mut h = Sha256::new();
        h.update(MAINNET_GENESIS_LABEL);
        h.update(MAINNET_GENESIS_TABLE_ROOT);
        let anchor: [u8; 32] = h.finalize().into();
        assert_eq!(c.genesis_anchor, anchor);
        assert_eq!(
            hex::encode(c.genesis_anchor),
            "a512f0c9378c31fe34160ee6388b62289596e46110d45079eec8eafe8c4c4526"
        );
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

    /// Core's `nSubsidyHalvingInterval`: 210,000 on mainnet and signet, 150 on regtest. The
    /// subsidy of a regtest block above 149 is half of 50 BTC, as the template carries it.
    #[test]
    fn each_network_halves_on_its_own_schedule() {
        use crate::canonical_payout::subsidy;
        assert_eq!(NodePoolNetwork::Mainnet.halving().interval(), 210_000);
        assert_eq!(NodePoolNetwork::Signet.halving().interval(), 210_000);
        let regtest = NodePoolNetwork::Regtest.halving();
        assert_eq!(regtest.interval(), 150);
        assert_eq!(subsidy(149, regtest), 5_000_000_000);
        assert_eq!(subsidy(150, regtest), 2_500_000_000);
        assert_eq!(subsidy(300, regtest), 1_250_000_000);
        assert_eq!(subsidy(150 * 64, regtest), 0);
        assert_eq!(subsidy(150, Halving::MAINNET), 5_000_000_000);
        assert_eq!(subsidy(974_500, Halving::MAINNET), 312_500_000);
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
