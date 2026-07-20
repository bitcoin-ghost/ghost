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
//| FILE: lib.rs                                                                                                         |
//|======================================================================================================================|

//! Ghost Pool Library
//!
//! Core components for Bitcoin Ghost mining pool operations.
//! This library provides all necessary functionality for running a Ghost mining node.
//!
//! # Modules
//!
//! - [`coinbase_verifier`] - Validates coinbase transactions against approved payouts
//! - [`payout`] - Payout proposal creation and BFT consensus integration
//! - [`payout_validator`] - Validates payout proposals against economic rules
//! - [`registry`] - Load balancer registration and health reporting
//! - [`reorg`] - Chain reorganization detection and handling
//! - [`round`] - Mining round management and share tracking
//! - [`rpc`] - JSON-RPC request parsing for Stratum protocol
//! - [`template`] - Block template processing with BUDS filtering
//! - [`template_provider`] - Template Distribution Protocol (TDP) server
//! - [`treasury`] - Treasury state and fee distribution tracking
//! - [`validation`] - Input validation for miner credentials and shares

/// Periodic operator-alert monitors (behind-tip / update-available).
pub mod alert_monitors;

/// Coinbase transaction verification against payout commitments.
pub mod coinbase_verifier;

/// `tracing` layer that feeds ghost-pool's log tail into the dashboard `/logs`
/// ring buffer.
pub mod log_ring;

/// Payout proposal creation and consensus coordination.
pub mod payout;

/// Payout-ledger checkpoint finalisation (BFT-agreed snapshot the coinbase is a
/// pure function of).
pub mod payout_checkpoint;

/// Economic validation of payout proposals.
pub mod payout_validator;

/// Load balancer registration and node discovery.
pub mod registry;

/// Chain reorganization detection and recovery.
pub mod reorg;

/// Mining round lifecycle and share accounting.
pub mod round;

/// Stratum JSON-RPC request parsing.
pub mod rpc;

/// Block template processing with policy filtering.
pub mod template;

/// Template Distribution Protocol (TDP) for SRI integration.
pub mod template_provider;

/// Treasury and fee distribution state.
pub mod treasury;

/// P2P share proof handling for cross-node share propagation.
pub mod share_handler;

/// GHOST-03: ledger convergence (share-set reconciliation) between mesh nodes.
pub mod convergence;

/// Chain height at which the security-audit cluster's ENFORCEMENT activates
/// fleet-wide. Mirrors `PAYOUT_ADDRESS_GROUPING_HEIGHT`: baking the activation as
/// a deterministic block-height gate (not a flag) means every node — running the
/// same binary — flips at the exact same chain position, so the fleet can roll
/// the binary out canary-style with NO mixed-version enforcement window.
///
/// Before this height the binary still SIGNS shares, converges ledgers and
/// propagates equivocation bans (all additive, mixed-version-safe), but it does
/// NOT yet drop unsigned shares (GHOST-09) or reject a mismatched payout split
/// (GHOST-02) — making it behaviour-identical to the pre-audit binary in a mixed
/// mesh. After it, both enforcements are live everywhere at once.
///
/// ACTIVATION HEIGHT — set for the audit-cluster rollout. Chosen at `954_736`
/// (the chain tip when this was cut) + ~464 blocks ≈ 77h of headroom, leaving
/// well over 24h between the completion of the canary roll (VM4→VM1, a few hours)
/// and the gate firing, so the whole fleet is on the audit binary in dark mode
/// before enforcement turns on everywhere at once. If the deploy slips far enough
/// that the tip approaches this height before the roll completes, bump this value
/// and rebuild — the binary must reach every VM while still below the gate.
pub const CLUSTER_ENFORCEMENT_HEIGHT: u64 = 955_200;

/// At and above this height the payout ledger is grouped by payout address rather
/// than by miner_id, so a multi-rig operator takes one coinbase output instead of N.
///
/// This lives here, not in `main.rs`, because BOTH the proposer (block-found) and the
/// GHOST-02 validator must group the ledger the same way. A validator that grouped
/// differently from the proposer would reject an honest split.
pub const PAYOUT_ADDRESS_GROUPING_HEIGHT: u64 = 946_743;

/// At and above this height, TX fees go to the NODE REWARD POOL (shared out by 5-4-3-2-1
/// capability shares) instead of 100% to the block finder.
///
/// This is what makes a block's coinbase fully determined BEFORE the block is found, and so it
/// is what makes tip-change payout ratification possible at all.
///
/// Every other part of the coinbase — the miner split (unpaid ledger) and the node reward split
/// (verified capabilities) — is already fixed by state that exists at tip change. The block
/// finder was the single unknown, and it existed only to receive the fees. Remove it and the
/// mesh can ratify the whole coinbase in advance, which is the only way a block can pay miners:
/// a block's coinbase is fixed when its template is built, so it can only ever pay a payout that
/// was already approved.
///
/// Fees remain NODE income and never touch the miner pool; only *which* nodes changes. Which
/// node "finds" a block is luck — it is whichever node the load balancer routed the winning
/// miner to — whereas capability shares reflect actual contribution.
///
/// Coinbase construction is consensus-visible, so this is a height gate, not a feature flag: a
/// mixed-version fleet must not split on how the coinbase is built. Both code paths exist in the
/// new binary; every node switches at the same block.
///
/// SET THIS BEFORE DEPLOY — comfortably past the roll window (~144 blocks/day).
/// v1.10.32 activated this at 958_760 and it FAILED live: the tip-change proposer anchors its
/// ledger cutoff at now(), where the miner ledger is not yet converged across nodes (GHOST-03
/// gossip lag), so validators recompute a different miner split and GHOST-02 rejects every
/// tip-change proposal — the coinbase never armed and fell back to treasury-only. v1.10.33
/// REVERTS to dormant while the cutoff/convergence root cause is fixed. Re-activate only after
/// the tip-change anchors a converged cutoff and it is verified against real gossip lag.
pub const FEE_TO_NODE_POOL_HEIGHT: u64 = u64::MAX;

/// Multi-operator share-injection defence. At and above this height, a `ShareProof` MUST
/// carry its 80-byte block header and every node independently re-verifies the PoW
/// (`sha256d(header) == share_hash` + meets difficulty) instead of trusting the origin's
/// signed numeric claim — see `DifficultyCalculator::verify_pow_preimage`. Below it, the
/// legacy numeric check stands (correct for a single-operator fleet trusting its own SRI).
///
/// A share's PoW binding is consensus-visible (it decides which shares are creditable and
/// so the coinbase split), hence a height gate: the header is populated into proofs and
/// required by verifiers only at/above this block, so a mixed-version fleet computes
/// identical `signing_bytes` and identical ledgers during the roll. DORMANT until every
/// node AND the SRI layer emit the header; SET comfortably past the roll window.
pub const SHARE_POW_VERIFY_HEIGHT: u64 = u64::MAX;

/// Activation heights, resolved once at startup.
///
/// A regtest chain is ~100 blocks tall, so every mainnet gate is dormant there and a regtest
/// rehearsal silently exercises the PRE-gate paths — proving nothing about the behaviour being
/// shipped. The previous way round that was to patch the constants and rebuild, which means the
/// binary under test was not the binary deployed. That is how a 4-node regtest run produced 24
/// green enforcement coinbases on 2026-06-21 while the bug it was meant to catch was live.
///
/// So the gates are overridable from the environment — but NEVER on mainnet, where the constants
/// above are the only truth. A test cluster runs the real shipping binary with the gates pulled
/// down, rather than a different binary built for the occasion.
mod gates {
    use ghost_common::config::BitcoinNetwork;
    use std::sync::OnceLock;

    pub(super) static CLUSTER_ENFORCEMENT: OnceLock<u64> = OnceLock::new();
    pub(super) static FEE_TO_NODE_POOL: OnceLock<u64> = OnceLock::new();

    pub(super) fn from_env(var: &str, network: &BitcoinNetwork, default: u64) -> u64 {
        if matches!(network, BitcoinNetwork::Mainnet) {
            return default; // mainnet gates are not negotiable
        }
        std::env::var(var)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(default)
    }
}

/// Resolve the activation gates for this run. Call once, at startup, before anything reads them.
pub fn init_activation_heights(network: &ghost_common::config::BitcoinNetwork) {
    let enforcement = gates::from_env(
        "GHOST_CLUSTER_ENFORCEMENT_HEIGHT",
        network,
        CLUSTER_ENFORCEMENT_HEIGHT,
    );
    let fee = gates::from_env(
        "GHOST_FEE_TO_NODE_POOL_HEIGHT",
        network,
        FEE_TO_NODE_POOL_HEIGHT,
    );
    let _ = gates::CLUSTER_ENFORCEMENT.set(enforcement);
    let _ = gates::FEE_TO_NODE_POOL.set(fee);

    if enforcement != CLUSTER_ENFORCEMENT_HEIGHT || fee != FEE_TO_NODE_POOL_HEIGHT {
        tracing::warn!(
            cluster_enforcement_height = enforcement,
            fee_to_node_pool_height = fee,
            network = ?network,
            "Activation heights OVERRIDDEN from the environment — non-mainnet only"
        );
    }
}

/// The height at which GHOST-02 split mismatches become a rejection rather than a warning.
pub fn cluster_enforcement_height() -> u64 {
    *gates::CLUSTER_ENFORCEMENT.get_or_init(|| CLUSTER_ENFORCEMENT_HEIGHT)
}

/// The height at which TX fees move to the node reward pool and the coinbase becomes ratifiable
/// at tip change.
pub fn fee_to_node_pool_height() -> u64 {
    *gates::FEE_TO_NODE_POOL.get_or_init(|| FEE_TO_NODE_POOL_HEIGHT)
}

/// GhostGlyph P2P handler for visual identity registration.
pub mod glyph_handler;

/// Input validation utilities for security.
pub mod validation;

/// Capability self-check (Phase 3): per-capability prerequisite probes
/// surfaced via `/health/self_check` for operator visibility.
pub mod self_check;

/// Hardware-derived miner capacity (CPU/RAM/FD limits → max miners).
/// Operator's `network.max_miners` is a ceiling, not a floor.
pub mod capacity;

/// Cumulative Reaper stats — txs evaluated, reaped, accepted, dead-bytes
/// total, plus per-DeadCodeType counters. Read by `/api/v1/reaper/status`.
pub mod reaper_stats;

/// Decentralised Wraith coordinator election — live wiring (read-only, gated
/// off by default). Computes and publishes the per-epoch coordinator draw via
/// `wraith-protocol`; activates no role and changes no consensus message.
pub mod coordinator_election;

pub mod coordinator_supervisor;

/// CONSENSUS SECURITY: re-derives peer-broadcast capability verdicts against
/// this node's own Bitcoin Core, so a colluding minority of challengers cannot
/// fabricate a FAIL (to grief an honest node under the 95% gate) or a PASS.
pub mod verification_reverify;

// L2 uses NullifierRouteHandler from ghost-consensus (sender-side proofs).
