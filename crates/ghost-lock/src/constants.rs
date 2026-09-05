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
//| FILE: constants.rs                                                                                                       |
//|======================================================================================================================|

//! Timelock and policy constants for Ghost Locks.
//!
//! Every value here is load-bearing. The two recovery delays are deliberately
//! **asymmetric**: whichever key an attacker holds, the honest key's path opens
//! a month earlier. Tests assert that gap so it cannot be "tidied" away.

/// Relative-timelock ceiling for BIP-68 block-based sequences.
///
/// `nSequence` carries the value in 16 bits, so the largest expressible relative
/// lock is 65,535 blocks — roughly **15 months**. This is why inheritance cannot
/// use CSV: an 18–24 month delay does not fit, and must be expressed as an
/// absolute `OP_CHECKLOCKTIMEVERIFY` height refreshed at each rollover.
pub const CSV_MAX_BLOCKS: u32 = 65_535;

/// Owner-alone recovery on the vault, in blocks (~14 months).
///
/// Opens when the backup device is lost.
pub const OWNER_RECOVERY_BLOCKS: u32 = 61_200;

/// Backup-alone recovery on the vault, in blocks (~15 months).
///
/// Opens when the phone is lost. Sits exactly on [`CSV_MAX_BLOCKS`] — that is
/// the ceiling, not a placeholder, and it is the reason the gap below is only
/// about a month.
pub const BACKUP_RECOVERY_BLOCKS: u32 = CSV_MAX_BLOCKS;

/// Minimum acceptable gap between the two recovery paths, in blocks (~30 days).
///
/// The honest party must always reach its path first. Shrinking this turns a
/// staggered race into a coin flip.
pub const MIN_RECOVERY_GAP_BLOCKS: u32 = 4_320;

/// Owner-alone escape from the hot lane, in blocks (~7 days).
///
/// The hot lane delegates co-signing to a quorum. This leaf is what makes that
/// delegation rather than custody: if the quorum goes dark, the owner sweeps.
pub const HOT_EXIT_BLOCKS: u32 = 1_008;

/// Owner-alone recall from the liquidity lane, in blocks (~14 days).
///
/// The liquidity lane **is** custody — the quorum spends alone. This leaf bounds
/// how long a silent quorum can hold the funds.
pub const LIQUIDITY_RECALL_BLOCKS: u32 = 2_016;

// ---------------------------------------------------------------------------
// Invariants, enforced at COMPILE TIME.
//
// These are guards against a future edit, so they fail the build rather than a
// test run. If one of these fires, the constant above it was changed and the
// change was almost certainly wrong.
// ---------------------------------------------------------------------------

const _: () = assert!(
    BACKUP_RECOVERY_BLOCKS == CSV_MAX_BLOCKS,
    "the longer recovery path must use the whole BIP-68 range"
);

const _: () = assert!(
    OWNER_RECOVERY_BLOCKS < BACKUP_RECOVERY_BLOCKS,
    "the owner must reach recovery before the backup key can"
);

const _: () = assert!(
    BACKUP_RECOVERY_BLOCKS - OWNER_RECOVERY_BLOCKS >= MIN_RECOVERY_GAP_BLOCKS,
    "staggered race collapsed: the honest party no longer has a head start"
);

const _: () = assert!(OWNER_RECOVERY_BLOCKS <= CSV_MAX_BLOCKS);
const _: () = assert!(HOT_EXIT_BLOCKS <= CSV_MAX_BLOCKS);
const _: () = assert!(LIQUIDITY_RECALL_BLOCKS <= CSV_MAX_BLOCKS);
