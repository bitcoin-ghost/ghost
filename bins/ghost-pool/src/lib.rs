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

/// Coinbase transaction verification against payout commitments.
pub mod coinbase_verifier;

/// Payout proposal creation and consensus coordination.
pub mod payout;

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

// L2 uses NullifierRouteHandler from ghost-consensus (sender-side proofs).
