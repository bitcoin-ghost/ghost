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

/// Dust threshold in satoshis
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const DUST_THRESHOLD_SATS: u64 = 546;

// =============================================================================
// UPTIME AND HEALTH
// =============================================================================

/// Uptime window in days
/// PROTOCOL CONSTANT — DO NOT MODIFY AFTER MAINNET
pub const UPTIME_WINDOW_DAYS: u64 = 7;

/// Health ping interval in seconds
pub const HEALTH_PING_INTERVAL_SECS: u64 = 10;

// =============================================================================
// NETWORK PORTS
// =============================================================================

/// SV2 Stratum port (SRI pool)
pub const SV2_STRATUM_PORT: u16 = 34255;

/// SV1 Stratum port (translator)
pub const SV1_STRATUM_PORT: u16 = 3333;

/// Template Distribution Protocol port, served by ghost-mining and consumed by pool_sv2.
///
/// Matches the `--tdp-port` default. Shared here so health checks can reason about the
/// provider without duplicating the literal.
pub const TDP_PORT: u16 = 8442;

/// HTTP API port (plain HTTP — used by SRI share webhook on loopback, the
/// nginx public-API upstream, and the local dashboard).
pub const HTTP_API_PORT: u16 = 8080;

/// HTTPS API port for the inter-peer verification mesh.
///
/// Hosts the same routes as `HTTP_API_PORT` but only the verification client
/// uses this — peer challenges hit `https://<peer-ip>:VERIFICATION_HTTPS_PORT`
/// with identity-pinned TLS. SRI / nginx / dashboard never see TLS.
pub const VERIFICATION_HTTPS_PORT: u16 = 8443;

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
// PROTOCOL VERSIONS
// =============================================================================

/// Ghost protocol version
pub const GHOST_PROTOCOL_VERSION: u32 = 140;

/// Minimum supported protocol version
pub const MIN_PROTOCOL_VERSION: u32 = 140;

/// How far back a miner's last share may be while it still counts as "active".
///
/// Every place that computes an active-miner figure MUST use this same value — the
/// node-local count, the gossiped per-node counts and the mesh-wide deduplicated total
/// are compared against each other, so a mismatch makes them disagree and the totals
/// stop reconciling. It was previously the literal `300` repeated at seven call sites
/// across three crates, with a comment at one of them warning that they had to match.
///
/// ## Why it is 900 and not 300
///
/// A share arrives on average every `difficulty * 2^48 / 0xFFFF / hashrate` seconds, and
/// share-finding is Poisson, so the chance a genuinely-mining miner submits nothing
/// inside the window is `e^(-window / mean_interval)`.
///
/// When the SV1 vardiff floor was 500 GH/s (difficulty ~1,164) a small bitaxe found a
/// share every ~10s, so a 300s window missed it with probability `e^-30` — never.
/// Raising the floor to 10 TH/s (difficulty ~23,283) to serve rented hashrate moved that
/// same miner to a ~200s mean, and `e^(-300/200)` = **22%**. With several small miners
/// connected, roughly one was always invisible, and the public pool page flapped between
/// 8, 7 and 6 while nothing was wrong.
///
/// At 900s the same miner is missed with probability `e^(-900/200)` = 1.1%.
///
/// ## If the vardiff floor changes again
///
/// This value is coupled to `min_individual_miner_hashrate` in the translator config, and
/// nothing enforces that coupling automatically — the floor lives in the translator's TOML
/// and this count lives in ghost-mining. Raise the floor materially and this window must be
/// re-checked against the arithmetic above, or the same bug returns silently.
pub const ACTIVE_MINER_WINDOW_SECS: i64 = 900;

#[cfg(test)]
mod tests {
    /// The active-miner window must stay comfortably longer than the mean share
    /// interval of the SMALLEST miner we expect to serve, or genuinely-mining miners
    /// blink out of the count and the pool page looks like it is losing them.
    ///
    /// This is the arithmetic that was wrong when the window was 300s: a 500 GH/s
    /// bitaxe at the 10 TH/s vardiff floor has a ~200s mean, and `e^(-300/200)` is 22%.
    /// Pinning it here means raising the floor again without revisiting the window
    /// fails this test instead of silently degrading the dashboard.
    #[test]
    fn test_active_miner_window_covers_the_smallest_expected_miner() {
        use super::ACTIVE_MINER_WINDOW_SECS;

        // difficulty -> hashes, using the exact stratum constant 2^48 / 0xFFFF.
        const HASHES_PER_DIFFICULTY: f64 = ((1u64 << 48) as f64) / (0xFFFF as f64);

        // The SV1 vardiff floor from config/sri/translator-config.toml, in H/s, and the
        // difficulty it produces. Keep both in step with that file.
        //
        // Difficulty is NOT hashrate/HASHES_PER_DIFFICULTY: vardiff sizes it so the miner
        // submits `shares_per_minute` shares, so the target share interval is part of it.
        //   D = hashrate * target_interval / HASHES_PER_DIFFICULTY
        // 10 TH/s at 6 shares/min gives 23,283, which is what the pool actually advertises
        // (measured 23,282.7 against a live node). Omitting the interval gives 2,328 and
        // makes this test pass on a window that is far too narrow.
        const VARDIFF_FLOOR_HS: f64 = 10_000_000_000_000.0;
        const SHARES_PER_MINUTE: f64 = 6.0;
        const TARGET_SHARE_INTERVAL_S: f64 = 60.0 / SHARES_PER_MINUTE;
        const FLOOR_DIFFICULTY: f64 =
            VARDIFF_FLOOR_HS * TARGET_SHARE_INTERVAL_S / HASHES_PER_DIFFICULTY;

        // Smallest miner we intend to serve on the low-difficulty path: a ~500 GH/s bitaxe.
        const SMALLEST_MINER_HS: f64 = 500_000_000_000.0;

        let mean_interval = FLOOR_DIFFICULTY * HASHES_PER_DIFFICULTY / SMALLEST_MINER_HS;
        let miss_probability = (-(ACTIVE_MINER_WINDOW_SECS as f64) / mean_interval).exp();

        assert!(
            miss_probability < 0.05,
            "a {SMALLEST_MINER_HS:.0} H/s miner has a {mean_interval:.0}s mean share \
             interval at the current floor; a {ACTIVE_MINER_WINDOW_SECS}s window misses it \
             {:.1}% of the time. Widen ACTIVE_MINER_WINDOW_SECS or lower the vardiff floor.",
            miss_probability * 100.0
        );
    }
}
