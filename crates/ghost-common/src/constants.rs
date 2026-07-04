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
//| FILE: constants.rs                                                                                                   |
//|======================================================================================================================|

//! System constants for Bitcoin Ghost v1.4
//!
//! All magic numbers and configuration defaults are defined here.

// =============================================================================
// BITCOIN UNIT CONSTANTS
// =============================================================================

/// Satoshis per Bitcoin (1 BTC = 100,000,000 sats)
pub const SATS_PER_BTC: u64 = 100_000_000;

/// Satoshis per Bitcoin as f64 for floating point calculations
pub const SATS_PER_BTC_F64: f64 = 100_000_000.0;

// =============================================================================
// ECONOMIC CONSTANTS — PROTOCOL CONSTANTS, DO NOT MODIFY AFTER MAINNET
// =============================================================================

/// Pool fee in basis points (100 bps = 1% of block subsidy)
/// SECURITY: Use basis points for integer arithmetic to avoid float ambiguity.
/// This is the single source of truth for pool fee calculation.
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const POOL_FEE_BASIS_POINTS: u64 = 100;

/// Treasury threshold in satoshis (21 BTC)
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const TREASURY_THRESHOLD_SATS: u64 = 21 * SATS_PER_BTC;

/// Treasury decay period in years
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const TREASURY_DECAY_YEARS: u32 = 5;

/// Dust threshold in satoshis
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const DUST_THRESHOLD_SATS: u64 = 546;

// =============================================================================
// COINBASE OUTPUT LIMITS — PROTOCOL CONSTANTS, DO NOT MODIFY AFTER MAINNET
// =============================================================================

/// Maximum miner outputs in coinbase
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const MAX_MINER_OUTPUTS: usize = 200;

/// Maximum node reward outputs in coinbase
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const MAX_NODE_OUTPUTS: usize = 100;

/// Maximum total coinbase outputs (1 treasury + 100 nodes + 200 miners)
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const MAX_COINBASE_OUTPUTS: usize = 301;

// =============================================================================
// NODE REWARD SHARES (5-4-3-2-1 SYSTEM) — PROTOCOL CONSTANTS, DO NOT MODIFY AFTER MAINNET
// =============================================================================

/// Archive mode capability shares
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const ARCHIVE_MODE_SHARES: i32 = 5;

/// Ghost Pay capability shares
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const GHOST_PAY_SHARES: i32 = 4;

/// Public mining capability shares
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const PUBLIC_MINING_SHARES: i32 = 3;

/// Reaper strict mode capability shares
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const REAPER_SHARES: i32 = 2;

/// Elder status capability shares
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const ELDER_STATUS_SHARES: i32 = 1;

/// Maximum possible node shares
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const MAX_NODE_SHARES: i32 = 15;

/// MEDIUM-STOR-1: Compile-time assertion that max shares cannot overflow i32
/// This ensures total_shares() can safely use checked arithmetic
const _: () = {
    assert!(
        (ARCHIVE_MODE_SHARES as i64
            + GHOST_PAY_SHARES as i64
            + PUBLIC_MINING_SHARES as i64
            + REAPER_SHARES as i64
            + ELDER_STATUS_SHARES as i64)
            < i32::MAX as i64,
        "Maximum possible node shares must be less than i32::MAX"
    );
};

// =============================================================================
// UPTIME & ELDER — PROTOCOL CONSTANTS, DO NOT MODIFY AFTER MAINNET
// =============================================================================

/// Uptime gatekeeper threshold percentage (95%)
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const UPTIME_GATEKEEPER_THRESHOLD: f64 = 95.0;

/// Uptime window in days
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const UPTIME_WINDOW_DAYS: u64 = 7;

/// Maximum number of elders
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const MAX_ELDERS: u32 = 101;

/// Elder offline threshold in days (for revocation eligibility)
pub const ELDER_OFFLINE_THRESHOLD_DAYS: u64 = 7;

// =============================================================================
// CONSENSUS
// =============================================================================

/// BFT threshold percentage (67%)
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const BFT_THRESHOLD_PERCENT: u64 = 67;

/// BFT threshold percentage for MPC ceremony contribution approval (67%).
///
/// SINGLE SOURCE OF TRUTH shared by `ghost-mpc` and `ghost-consensus` so the
/// quorum required to apply a new MPC contribution is computed identically on
/// every node. A mismatch here is a consensus split: one node would apply a
/// contribution (advancing the trusted-setup lineage) while another rejects it.
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const MPC_BFT_THRESHOLD_PERCENT: u32 = 67;

/// Minimum number of MPC contributors before BFT supermajority voting applies.
///
/// During bootstrap (fewer than this many contributors) the genesis node may
/// approve alone (threshold = 1). At or above this count the threshold becomes
/// a `MPC_BFT_THRESHOLD_PERCENT` supermajority: `ceil(count * percent / 100)`.
/// Set to 4 because with only 3 contributors `ceil(3 * 67 / 100) = 3` would
/// require unanimity — too fragile, since any single offline node would block
/// all further contributions.
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const MPC_BFT_BOOTSTRAP_COUNT: u32 = 4;

/// Consensus voting timeout in milliseconds
pub const CONSENSUS_TIMEOUT_MS: u64 = 5000;

/// Health ping interval in seconds
pub const HEALTH_PING_INTERVAL_SECS: u64 = 10;

/// Share convergence timeout in milliseconds
pub const SHARE_CONVERGENCE_TIMEOUT_MS: u64 = 30000;

// =============================================================================
// VERIFICATION
// =============================================================================

/// Verification interval in seconds (5 minutes)
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const VERIFICATION_INTERVAL_SECS: u64 = 300;

/// Verification HTTP timeout in seconds
pub const VERIFICATION_TIMEOUT_SECS: u64 = 10;

/// Nodes to verify per round (3 peers every 5 minutes)
pub const NODES_TO_VERIFY_PER_ROUND: usize = 3;

/// Minimum challenges required for capability qualification
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const MIN_CHALLENGES_FOR_QUALIFICATION: usize = 10;

/// Archive mode pass rate threshold
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const ARCHIVE_PASS_RATE: f64 = 0.95;

/// Policy challenge pass rate threshold
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const POLICY_PASS_RATE: f64 = 0.95;

/// Stratum challenge pass rate threshold.
///
/// CONSENSUS SECURITY: this per-challenge percentage gate NO LONGER governs
/// stratum qualification. Stratum (and GhostPay) are liveness probes with no
/// chain ground truth, so they cannot be re-derived like Archive/Policy. They
/// are instead gated by a per-challenger MAJORITY (one vote per distinct
/// challenger; see `get_stratum_challenger_majority` in `ghost-storage`), which
/// a sub-50% colluding minority cannot flip and a flood cannot inflate. This
/// constant is retained because the legacy per-challenge path
/// (`get_qualified_capabilities`) and Archive/Policy still share the pattern.
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const STRATUM_PASS_RATE: f64 = 0.95;

/// Ghost Pay challenge pass rate threshold.
///
/// CONSENSUS SECURITY: like `STRATUM_PASS_RATE`, this per-challenge percentage
/// gate NO LONGER governs GhostPay qualification. GhostPay now qualifies on a
/// per-challenger MAJORITY (see `get_ghostpay_challenger_majority` in
/// `ghost-storage`). Retained for the legacy per-challenge path and the shared
/// Archive/Policy pattern.
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const GHOSTPAY_PASS_RATE: f64 = 0.90;

// =============================================================================
// NETWORK PORTS
// =============================================================================

/// SV2 Stratum port (SRI pool)
pub const SV2_STRATUM_PORT: u16 = 34255;

/// SV1 Stratum port (translator)
pub const SV1_STRATUM_PORT: u16 = 3333;

/// SV2 pool authority public key (the Noise static key SV2/Noise clients pin).
///
/// This is the network-wide authority key that every `pool_sv2` instance
/// publishes as `authority_public_key` in its pool config — it is identical
/// across all pool nodes, so a miner pins this single value to authenticate any
/// node it connects to. Surfaced on `/api/v1/mining/status` so the dashboard
/// can source it dynamically instead of hardcoding it in the frontend.
///
/// Operators running a bespoke authority keypair can override this per-node via
/// `[network] sv2_authority_public_key` in `pool.toml`.
pub const SV2_AUTHORITY_PUBLIC_KEY: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";

/// HTTP API port (plain HTTP — used by SRI share webhook on loopback, the
/// nginx public-API upstream, and the local dashboard).
pub const HTTP_API_PORT: u16 = 8080;

/// HTTPS API port for the inter-peer verification mesh.
///
/// Hosts the same routes as `HTTP_API_PORT` but only the verification client
/// uses this — peer challenges hit `https://<peer-ip>:VERIFICATION_HTTPS_PORT`
/// with identity-pinned TLS. SRI / nginx / dashboard never see TLS.
pub const VERIFICATION_HTTPS_PORT: u16 = 8443;

// P2P Consensus ports
/// Share propagation port
pub const SHARE_PROPAGATION_PORT: u16 = 8555;

/// Block announcement port
pub const BLOCK_ANNOUNCEMENT_PORT: u16 = 8556;

/// Consensus voting port
pub const CONSENSUS_VOTING_PORT: u16 = 8557;

/// Health monitoring port
pub const HEALTH_MONITORING_PORT: u16 = 8558;

/// Discovery port
pub const DISCOVERY_PORT: u16 = 8559;

/// Elder management port
pub const ELDER_MANAGEMENT_PORT: u16 = 8560;

/// Payout proposal port
pub const PAYOUT_PROPOSAL_PORT: u16 = 8561;

/// Payout transaction port
pub const PAYOUT_TRANSACTION_PORT: u16 = 8562;

// =============================================================================
// BITCOIN CORE
// =============================================================================

/// Bitcoin RPC port (signet)
pub const BITCOIN_RPC_PORT_SIGNET: u16 = 38332;

/// Bitcoin RPC port (mainnet)
pub const BITCOIN_RPC_PORT_MAINNET: u16 = 8332;

/// Bitcoin P2P port (signet)
pub const BITCOIN_P2P_PORT_SIGNET: u16 = 38333;

/// Bitcoin P2P port (mainnet)
pub const BITCOIN_P2P_PORT_MAINNET: u16 = 8333;

/// ZMQ hashblock port
pub const ZMQ_HASHBLOCK_PORT: u16 = 28332;

/// ZMQ hashtx port
pub const ZMQ_HASHTX_PORT: u16 = 28333;

/// ZMQ sequence port (for reorg detection)
pub const ZMQ_SEQUENCE_PORT: u16 = 28334;

// =============================================================================
// BUDS / POLICY
// =============================================================================

/// Maximum OP_RETURN size for "small" classification (bytes)
pub const MAX_OP_RETURN_SMALL_BYTES: usize = 80;

/// Maximum witness size per input for bitcoin_pure (bytes)
pub const MAX_WITNESS_BYTES_PER_INPUT: usize = 400;

/// Maximum outputs per transaction for bitcoin_pure
pub const MAX_TX_OUTPUTS_BITCOIN_PURE: usize = 50;

/// Maximum transaction size for bitcoin_pure (bytes)
pub const MAX_TX_SIZE_BITCOIN_PURE: usize = 100_000;

// =============================================================================
// GHOST PAY L2
// =============================================================================

/// L2 transfer fee in satoshis (flat fee per NoteSpend transfer)
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
/// Baked into circuit constraints; changing requires MPC ceremony reset.
pub const L2_TRANSFER_FEE_SATS: u64 = 10;

/// Virtual block time (seconds)
pub const L2_VIRTUAL_BLOCK_SECS: u64 = 10;

/// Epoch length in virtual blocks
pub const L2_EPOCH_BLOCKS: u64 = 2160;

/// Compute the L2 epoch number from a block height.
/// Ghost-pay tracks block height via RPC; this maps it to the epoch for fee tracking.
pub fn l2_epoch_from_height(block_height: u64) -> u64 {
    block_height / L2_EPOCH_BLOCKS
}

// =============================================================================
// SETTLEMENT CLASSES
// =============================================================================

/// Settlement class determines how frequently withdrawals are batched for L1 settlement.
///
/// Settlement is triggered at epoch boundaries. Each class settles at a different
/// frequency, trading speed for cost:
/// - Express: every epoch (~6h) — 1.5x fee
/// - Standard: every 4 epochs (~24h) — 1.0x fee
/// - Economy: every 28 epochs (~7d) — 0.5x fee
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementClass {
    Express,
    Standard,
    Economy,
}

impl SettlementClass {
    /// All settlement classes, for iteration.
    pub const ALL: [SettlementClass; 3] = [
        SettlementClass::Express,
        SettlementClass::Standard,
        SettlementClass::Economy,
    ];

    /// How many epochs between settlements for this class.
    pub fn epoch_multiplier(self) -> u64 {
        match self {
            Self::Express => 1,
            Self::Standard => 4,
            Self::Economy => 28,
        }
    }

    /// Fee multiplier relative to base fee rate.
    /// Express pays more for faster settlement; Economy pays less for batching.
    pub fn fee_multiplier(self) -> f64 {
        match self {
            Self::Express => 1.5,
            Self::Standard => 1.0,
            Self::Economy => 0.5,
        }
    }

    /// Returns true if this class should settle at the given epoch number.
    pub fn is_due_at_epoch(self, epoch: u64) -> bool {
        epoch > 0 && epoch % self.epoch_multiplier() == 0
    }

    /// Parse from string (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "express" => Some(Self::Express),
            "standard" => Some(Self::Standard),
            "economy" => Some(Self::Economy),
            _ => None,
        }
    }

    /// String representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Express => "express",
            Self::Standard => "standard",
            Self::Economy => "economy",
        }
    }
}

impl Default for SettlementClass {
    fn default() -> Self {
        Self::Standard
    }
}

/// Wraith denomination tiers (satoshis)
pub const WRAITH_DENOMINATIONS: [u64; 4] = [
    100_000,     // 0.001 BTC
    1_000_000,   // 0.01 BTC
    10_000_000,  // 0.1 BTC
    100_000_000, // 1 BTC
];

// =============================================================================
// PROTOCOL VERSIONS
// =============================================================================

/// Ghost protocol version
pub const GHOST_PROTOCOL_VERSION: u32 = 140;

/// Minimum supported protocol version
pub const MIN_PROTOCOL_VERSION: u32 = 140;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_sum() {
        let total = ARCHIVE_MODE_SHARES
            + GHOST_PAY_SHARES
            + PUBLIC_MINING_SHARES
            + REAPER_SHARES
            + ELDER_STATUS_SHARES;
        assert_eq!(total, MAX_NODE_SHARES);
    }

    #[test]
    fn test_coinbase_output_sum() {
        // 1 treasury + 100 nodes + 200 miners = 301
        assert_eq!(
            1 + MAX_NODE_OUTPUTS + MAX_MINER_OUTPUTS,
            MAX_COINBASE_OUTPUTS
        );
    }

    #[test]
    fn test_bft_threshold() {
        // 67% means we need 2/3 majority
        const { assert!(BFT_THRESHOLD_PERCENT > 50) };
        const { assert!(BFT_THRESHOLD_PERCENT < 100) };
    }

    #[test]
    fn test_pool_fee_basis_points_correct() {
        // SECURITY TEST: Verify POOL_FEE_BASIS_POINTS represents 1% correctly
        // 100 basis points = 1%
        assert_eq!(POOL_FEE_BASIS_POINTS, 100);

        // Verify the calculation produces correct results
        // For 312,500,000 sats (3.125 BTC), 1% should be 3,125,000 sats
        let subsidy = 312_500_000u64;
        let pool_fee = subsidy * POOL_FEE_BASIS_POINTS / 10000;
        assert_eq!(pool_fee, 3_125_000);

        // Verify miner pool is 99% of subsidy
        let miner_pool = subsidy - pool_fee;
        assert_eq!(miner_pool, 309_375_000);

        // Verify there's no precision loss with different subsidy values
        for subsidy in [625_000_000u64, 312_500_000, 156_250_000, 78_125_000] {
            let fee = subsidy * POOL_FEE_BASIS_POINTS / 10000;
            let remainder = subsidy - fee;
            // Total should equal original subsidy
            assert_eq!(fee + remainder, subsidy);
            // Fee should be exactly 1%
            assert_eq!(fee, subsidy / 100);
        }
    }

    #[test]
    fn test_settlement_class_epoch_due() {
        assert!(!SettlementClass::Express.is_due_at_epoch(0));
        assert!(SettlementClass::Express.is_due_at_epoch(1));
        assert!(SettlementClass::Express.is_due_at_epoch(4));

        assert!(!SettlementClass::Standard.is_due_at_epoch(0));
        assert!(!SettlementClass::Standard.is_due_at_epoch(1));
        assert!(SettlementClass::Standard.is_due_at_epoch(4));
        assert!(!SettlementClass::Standard.is_due_at_epoch(5));
        assert!(SettlementClass::Standard.is_due_at_epoch(8));

        assert!(!SettlementClass::Economy.is_due_at_epoch(0));
        assert!(!SettlementClass::Economy.is_due_at_epoch(4));
        assert!(SettlementClass::Economy.is_due_at_epoch(28));
        assert!(SettlementClass::Economy.is_due_at_epoch(56));
    }

    #[test]
    fn test_settlement_class_parse() {
        assert_eq!(
            SettlementClass::parse("express"),
            Some(SettlementClass::Express)
        );
        assert_eq!(
            SettlementClass::parse("standard"),
            Some(SettlementClass::Standard)
        );
        assert_eq!(
            SettlementClass::parse("economy"),
            Some(SettlementClass::Economy)
        );
        assert_eq!(
            SettlementClass::parse("Express"),
            Some(SettlementClass::Express)
        );
        assert_eq!(SettlementClass::parse("invalid"), None);
    }

    #[test]
    fn test_settlement_class_default() {
        assert_eq!(SettlementClass::default(), SettlementClass::Standard);
    }

    #[test]
    fn test_settlement_class_fee_multiplier() {
        assert!((SettlementClass::Express.fee_multiplier() - 1.5).abs() < f64::EPSILON);
        assert!((SettlementClass::Standard.fee_multiplier() - 1.0).abs() < f64::EPSILON);
        assert!((SettlementClass::Economy.fee_multiplier() - 0.5).abs() < f64::EPSILON);
    }
}
