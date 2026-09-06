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
//| FILE: exit_availability.rs                                                                                            |
//|======================================================================================================================|

//! "You can always leave alone" — and the two ways it silently stops being true.
//!
//! The hot lane is `musig(owner, quorum)` with an `older(EXIT_DELAY)` leaf the
//! owner can take unaided. That looks like an unconditional guarantee. It is
//! not, and neither failure is visible in the script.
//!
//! # 1. Remixing resets the clock
//!
//! `OP_CSV` is **relative**. Every spend produces a new output whose delay
//! starts again at its confirmation. Resident coins remix continuously — that is
//! the whole cover-traffic design — so a coin remixing every `N` blocks with an
//! exit delay of `D` blocks reaches maturity only if `N > D`.
//!
//! With a seven-day delay and daily remixing, the exit leaf **never matures**.
//! The owner cannot leave alone, ever, and nothing about the script says so.
//!
//! The fix is behavioural, not scriptual: on an exit request the wallet stops
//! entering rounds and lets the coin sit still for `D`. So the honest promise is
//! *"you can leave alone within `EXIT_DELAY` of asking"* — which is fine, and
//! which requires the stopping behaviour to actually exist.
//!
//! # 2. Pre-signatures outlive the request
//!
//! Stopping only works if the quorum has nothing left to spend with. It needs
//! the owner's pre-signature to complete a round, so an owner who has pre-signed
//! several rounds ahead has handed over the means to keep resetting the clock
//! after they asked to leave.
//!
//! **Outstanding pre-signatures must be bounded**, or the exit guarantee is
//! worth exactly as many blocks as the quorum chooses to allow.

/// How the hot lane is being operated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitConfig {
    /// `older(EXIT_DELAY)` on the hot lane's escape leaf, in blocks.
    pub exit_delay_blocks: u32,
    /// Typical blocks between remixes of a resident coin.
    pub remix_interval_blocks: u32,
    /// Rounds the owner has pre-signed and not yet seen settle.
    pub outstanding_presignatures: u32,
    /// Blocks a round takes from pre-signature to settlement.
    pub round_settlement_blocks: u32,
}

/// Why an exit is not guaranteed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExitRisk {
    /// Remixing resets the clock faster than it runs down.
    #[error("remixing every {remix} blocks never lets a {delay}-block exit delay mature — the owner cannot leave unaided while the coin stays resident")]
    ClockNeverMatures {
        /// Remix cadence.
        remix: u32,
        /// Exit delay.
        delay: u32,
    },

    /// Pre-signed rounds let the quorum keep resetting after an exit request.
    #[error("{outstanding} pre-signed rounds can delay an exit by up to {worst_case_blocks} blocks after the owner asks to leave")]
    PresignaturesOutliveTheRequest {
        /// How many are outstanding.
        outstanding: u32,
        /// Worst-case additional delay.
        worst_case_blocks: u32,
    },
}

/// Blocks from an exit request to a unilateral exit becoming spendable.
///
/// Assumes the wallet stops entering rounds on request, which is the behaviour
/// the guarantee depends on. Outstanding pre-signatures still have to drain
/// first, because the quorum can complete them.
pub fn blocks_until_exit(cfg: &ExitConfig) -> u32 {
    let drain = cfg
        .outstanding_presignatures
        .saturating_mul(cfg.round_settlement_blocks);
    drain.saturating_add(cfg.exit_delay_blocks)
}

/// Everything preventing an unconditional exit, worst first.
///
/// `tolerated_delay_blocks` is how long an owner is willing to wait after
/// asking. Beyond it the guarantee has stopped meaning anything.
pub fn assess(cfg: &ExitConfig, tolerated_delay_blocks: u32) -> Vec<ExitRisk> {
    let mut risks = Vec::new();

    // The passive case: an owner who never asks to leave, whose coin keeps
    // remixing, has no maturing exit at any point.
    if cfg.remix_interval_blocks <= cfg.exit_delay_blocks {
        risks.push(ExitRisk::ClockNeverMatures {
            remix: cfg.remix_interval_blocks,
            delay: cfg.exit_delay_blocks,
        });
    }

    let worst = blocks_until_exit(cfg);
    if worst > tolerated_delay_blocks {
        risks.push(ExitRisk::PresignaturesOutliveTheRequest {
            outstanding: cfg.outstanding_presignatures,
            worst_case_blocks: worst,
        });
    }

    risks
}

/// The largest number of rounds an owner may pre-sign and still exit within
/// `tolerated_delay_blocks` of asking.
///
/// This is the number a wallet should enforce. Pre-signing further ahead is
/// convenient and quietly sells the exit guarantee.
pub fn max_safe_presignatures(cfg: &ExitConfig, tolerated_delay_blocks: u32) -> u32 {
    if cfg.round_settlement_blocks == 0 {
        return u32::MAX;
    }
    tolerated_delay_blocks.saturating_sub(cfg.exit_delay_blocks) / cfg.round_settlement_blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seven-day exit delay, daily remixing, one round pre-signed.
    fn realistic() -> ExitConfig {
        ExitConfig {
            exit_delay_blocks: 1_008,
            remix_interval_blocks: 144,
            outstanding_presignatures: 1,
            round_settlement_blocks: 36,
        }
    }

    #[test]
    fn continuous_remixing_means_the_exit_never_matures() {
        // The finding: a resident coin that keeps remixing never sits still long
        // enough for its own escape leaf, and the script gives no hint of it.
        let risks = assess(&realistic(), 2_000);
        assert!(risks.contains(&ExitRisk::ClockNeverMatures {
            remix: 144,
            delay: 1_008
        }));
    }

    #[test]
    fn stopping_remixing_is_what_makes_the_promise_true() {
        // Same config, but the coin is left alone: the delay now runs down and
        // the honest promise is "within EXIT_DELAY of asking".
        let mut cfg = realistic();
        cfg.remix_interval_blocks = 5_000;
        let risks = assess(&cfg, 2_000);
        assert!(!risks
            .iter()
            .any(|r| matches!(r, ExitRisk::ClockNeverMatures { .. })));
        assert_eq!(blocks_until_exit(&cfg), 1_044);
    }

    #[test]
    fn presigning_far_ahead_sells_the_exit_guarantee() {
        // Convenient, and it hands the quorum the means to keep resetting the
        // clock after the owner has asked to leave.
        let mut cfg = realistic();
        cfg.remix_interval_blocks = 5_000;
        cfg.outstanding_presignatures = 100;
        let risks = assess(&cfg, 2_000);
        assert!(risks.iter().any(|r| matches!(
            r,
            ExitRisk::PresignaturesOutliveTheRequest {
                outstanding: 100,
                ..
            }
        )));
        assert_eq!(blocks_until_exit(&cfg), 4_608);
    }

    #[test]
    fn the_safe_presignature_bound_is_computable() {
        let mut cfg = realistic();
        cfg.remix_interval_blocks = 5_000;
        // 2000 tolerated, 1008 of it the delay itself, 36 blocks a round.
        assert_eq!(max_safe_presignatures(&cfg, 2_000), 27);
        cfg.outstanding_presignatures = 27;
        assert!(blocks_until_exit(&cfg) <= 2_000);
        cfg.outstanding_presignatures = 28;
        assert!(blocks_until_exit(&cfg) > 2_000);
    }

    #[test]
    fn a_tolerance_below_the_delay_itself_permits_nothing() {
        // An owner unwilling to wait even the exit delay cannot safely pre-sign
        // at all, and the bound says so rather than returning something
        // reassuring.
        let cfg = realistic();
        assert_eq!(max_safe_presignatures(&cfg, 500), 0);
    }

    #[test]
    fn a_well_configured_lane_reports_no_risk() {
        let cfg = ExitConfig {
            exit_delay_blocks: 144,
            remix_interval_blocks: 1_000,
            outstanding_presignatures: 2,
            round_settlement_blocks: 36,
        };
        assert_eq!(assess(&cfg, 1_000), vec![]);
    }
}
