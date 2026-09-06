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

impl ExitConfig {
    /// A config anchored to the real hot-lane escape leaf.
    ///
    /// `exit_delay_blocks` is read from [`ghost_lock::HOT_EXIT_BLOCKS`] rather
    /// than restated. The two crates do not otherwise know about each other, so
    /// a change to the leaf would silently leave this analysis reasoning about
    /// a delay that no longer exists — drift a grep inside either crate cannot
    /// see.
    pub fn for_hot_lane(
        remix_interval_blocks: u32,
        outstanding_presignatures: u32,
        round_settlement_blocks: u32,
    ) -> Self {
        Self {
            exit_delay_blocks: ghost_lock::HOT_EXIT_BLOCKS,
            remix_interval_blocks,
            outstanding_presignatures,
            round_settlement_blocks,
        }
    }
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

/// Where a hot-lane coin is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaneState {
    /// Normal operation: the coin remixes and the owner pre-signs rounds.
    Active,
    /// The owner has asked to leave. **No new pre-signatures are issued.**
    Exiting {
        /// Height at which the request was made.
        requested_at: u32,
    },
}

/// Enforces the two behaviours the exit guarantee depends on.
///
/// [`assess`] reports whether an exit is *possible*. This is the thing that
/// makes it so, and both halves are behaviour a wallet must implement rather
/// than properties of the script:
///
/// 1. **Stop entering rounds on request.** A coin that keeps remixing keeps
///    resetting its own `older(EXIT_DELAY)` clock, so the leaf never matures.
/// 2. **Bound outstanding pre-signatures.** Stopping achieves nothing if the
///    quorum still holds signatures it can spend with — each one is another
///    round it can complete after the owner asked to leave.
///
/// The second is enforced here rather than merely computed, because a wallet
/// that pre-signs generously is more convenient at every individual moment and
/// only worse in aggregate. That is the shape of decision that needs a refusal
/// rather than a guideline.
#[derive(Debug, Clone)]
pub struct ExitController {
    state: LaneState,
    outstanding: u32,
    cfg: ExitConfig,
    tolerated_delay_blocks: u32,
    refused_presignatures: u64,
}

impl ExitController {
    /// New controller for an active lane.
    pub fn new(cfg: ExitConfig, tolerated_delay_blocks: u32) -> Self {
        Self {
            state: LaneState::Active,
            outstanding: cfg.outstanding_presignatures,
            cfg,
            tolerated_delay_blocks,
            refused_presignatures: 0,
        }
    }

    /// Current state.
    pub fn state(&self) -> LaneState {
        self.state
    }

    /// Pre-signatures the quorum could still spend with.
    pub fn outstanding(&self) -> u32 {
        self.outstanding
    }

    /// How many pre-signature requests were refused.
    ///
    /// Rising steadily means the wallet is trying to pre-sign further ahead than
    /// the exit guarantee permits, which is a bug in the wallet rather than a
    /// user problem.
    pub fn refused(&self) -> u64 {
        self.refused_presignatures
    }

    /// May the owner pre-sign another round right now?
    pub fn may_presign(&self) -> bool {
        if matches!(self.state, LaneState::Exiting { .. }) {
            return false;
        }
        let mut probe = self.cfg;
        probe.outstanding_presignatures = self.outstanding;
        self.outstanding < max_safe_presignatures(&probe, self.tolerated_delay_blocks)
    }

    /// Record a pre-signature, or refuse it.
    pub fn presign(&mut self) -> bool {
        if !self.may_presign() {
            self.refused_presignatures += 1;
            return false;
        }
        self.outstanding += 1;
        true
    }

    /// A round settled, freeing one pre-signature.
    pub fn on_round_settled(&mut self) {
        self.outstanding = self.outstanding.saturating_sub(1);
    }

    /// The owner asks to leave. Idempotent — the first request is what counts.
    pub fn request_exit(&mut self, height: u32) {
        if matches!(self.state, LaneState::Active) {
            self.state = LaneState::Exiting {
                requested_at: height,
            };
        }
    }

    /// Height at which the unilateral exit becomes spendable, once known.
    ///
    /// `None` while pre-signatures are outstanding: the quorum can still
    /// complete a round and restart the clock, so no honest answer exists yet.
    /// Reporting an optimistic height would be worse than reporting none.
    pub fn exit_available_at(&self) -> Option<u32> {
        let LaneState::Exiting { requested_at } = self.state else {
            return None;
        };
        if self.outstanding > 0 {
            return None;
        }
        Some(requested_at.saturating_add(self.cfg.exit_delay_blocks))
    }
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

    fn controller() -> ExitController {
        let mut cfg = realistic();
        cfg.remix_interval_blocks = 5_000;
        cfg.outstanding_presignatures = 0;
        ExitController::new(cfg, 2_000)
    }

    #[test]
    fn requesting_an_exit_stops_new_presignatures() {
        // The whole mechanism. Without this the coin keeps remixing and its own
        // escape leaf never matures.
        let mut c = controller();
        assert!(c.presign());
        c.request_exit(900_000);
        assert!(!c.may_presign());
        assert!(
            !c.presign(),
            "a wallet must not pre-sign after an exit request"
        );
        assert_eq!(c.refused(), 1);
    }

    #[test]
    fn the_presignature_bound_is_enforced_not_merely_reported() {
        // Pre-signing further ahead is more convenient at every single moment
        // and only worse in aggregate, so it needs a refusal rather than advice.
        let mut c = controller();
        let mut granted = 0;
        for _ in 0..200 {
            if c.presign() {
                granted += 1;
            }
        }
        assert_eq!(granted, 27, "the computed bound must be the enforced bound");
        assert!(c.refused() > 0);
        assert_eq!(c.outstanding(), 27);
    }

    #[test]
    fn no_exit_height_is_offered_while_signatures_are_outstanding() {
        // The quorum can still complete a round and restart the clock, so no
        // honest answer exists. An optimistic height would be worse than none.
        let mut c = controller();
        c.presign();
        c.presign();
        c.request_exit(900_000);
        assert_eq!(c.exit_available_at(), None);

        c.on_round_settled();
        assert_eq!(c.exit_available_at(), None, "one still outstanding");

        c.on_round_settled();
        assert_eq!(
            c.exit_available_at(),
            Some(900_000 + ghost_lock::HOT_EXIT_BLOCKS),
            "now the clock can actually run"
        );
    }

    #[test]
    fn requesting_twice_does_not_restart_the_clock() {
        let mut c = controller();
        c.request_exit(900_000);
        c.request_exit(950_000);
        assert_eq!(
            c.exit_available_at(),
            Some(900_000 + ghost_lock::HOT_EXIT_BLOCKS)
        );
    }

    #[test]
    fn settling_below_zero_does_not_wrap() {
        let mut c = controller();
        c.on_round_settled();
        c.on_round_settled();
        assert_eq!(c.outstanding(), 0);
    }

    #[test]
    fn the_analysis_reads_the_delay_from_the_crate_that_defines_it() {
        // Cross-crate drift is the version of this a single-crate grep cannot
        // find: `ghost-lock` owns the escape leaf, `wraith-protocol` reasons
        // about it, and nothing connected them.
        let cfg = ExitConfig::for_hot_lane(5_000, 1, 36);
        assert_eq!(cfg.exit_delay_blocks, ghost_lock::HOT_EXIT_BLOCKS);
        assert_eq!(
            realistic().exit_delay_blocks,
            ghost_lock::HOT_EXIT_BLOCKS,
            "the fixture has drifted from the leaf it claims to model"
        );
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
