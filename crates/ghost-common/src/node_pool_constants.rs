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
//| FILE: node_pool_constants.rs                                                                                         |
//|======================================================================================================================|

//! Node pool protocol constants, in one place.
//!
//! Every value here belongs to the node pool (`docs/NODE_POOL_SPEC.md`), the only mode. Where the
//! share chain starts is network configuration (`[node_pool.relay]` genesis), not a height here.
//! They live in their own module, not in `constants.rs`, because that module is glob-re-exported
//! from the crate root and short names such as `MIN_PAYOUT_SATS` would collide with, or be
//! mistaken for, the old payout constants.
//!
//! The payout values must agree with `docs/node-pool-reference/refimpl_v3.py`, the normative
//! reference; the vector test in `canonical_payout` pins them against `test_vectors_v3.json`.

/// One face unit is `2^-32` sat; a balance of `x` sats is `x << 32` face units.
pub const FACE_UNIT_SHIFT: u32 = 32;

/// Face units per sat, `2^32` (`ONE` in the reference).
pub const FACE_PER_SAT: i128 = 1 << FACE_UNIT_SHIFT;

/// Minimum payout, and the eligibility floor, in sats.
pub const MIN_PAYOUT_SATS: u64 = 1_000;

/// The eligibility floor in face units (`FLOOR` in the reference): 1,000 sats.
pub const PAYOUT_FLOOR_FACE: i128 = MIN_PAYOUT_SATS as i128 * FACE_PER_SAT;

/// Treasury base is `subsidy / TREASURY_DIVISOR`, 0.5% of the subsidy.
pub const TREASURY_DIVISOR: u64 = 200;

/// `cut(H) = H - SNAPSHOT_CUT_LAG`: block `H` pays from the table as it stood 20 blocks earlier.
pub const SNAPSHOT_CUT_LAG: u32 = 20;

/// Miner outputs per slot class, smallest first (spec 2.1, provisional). The class a job carries is
/// committed in its share tag as the miner-output count itself, so this table may grow without
/// changing the meaning of an existing tag.
pub const SLOT_CLASSES: [u16; 6] = [3, 9, 44, 143, 364, 500];

/// The largest slot class: at most this many miner outputs in any coinbase.
pub const MAX_MINER_OUTPUTS: u16 = 500;

/// Bitcoin subsidy before the first halving, in sats.
pub const INITIAL_SUBSIDY_SATS: u64 = 5_000_000_000;

/// Blocks per subsidy era on mainnet, signet and testnet.
pub const HALVING_INTERVAL: u32 = 210_000;

/// Regtest's halving interval (Core's regtest `nSubsidyHalvingInterval`).
pub const REGTEST_HALVING_INTERVAL: u32 = 150;

/// PLACEHOLDER treasury output script. NOT the real treasury: the user supplies the address later
/// (plan section 5, item 1), and this constant must be replaced before any network uses it.
///
/// It is the reference's placeholder, byte for byte, so the golden vectors match:
/// `0x51 0x20 || sha256("placeholder treasury, compiled constant, see plan section 5")`.
pub const TREASURY_SCRIPT_PLACEHOLDER: [u8; 34] = [
    0x51, 0x20, 0x99, 0x25, 0x16, 0x78, 0x15, 0xd1, 0x20, 0x2e, 0x98, 0x5d, 0xc6, 0x07, 0xbc, 0xea,
    0xb1, 0x62, 0xcb, 0x70, 0xc9, 0x8d, 0x29, 0x2d, 0xa3, 0x59, 0x2c, 0x08, 0x7b, 0x44, 0xa3, 0xfe,
    0xfb, 0x2f,
];

/// Magic of the ledger commitment `OP_RETURN`: `OP_RETURN PUSH36 "GHNP" || table_root`.
pub const LEDGER_COMMITMENT_MAGIC: &[u8; 4] = b"GHNP";

/// Domain separator of the share tag (spec 2.1).
pub const SHARE_TAG_DOMAIN: &[u8] = b"GhostShare/v2";

/// Bytes of the share tag carried in the coinbase scriptSig's `GHNT` push.
pub const SHARE_TAG_LEN: usize = 20;

/// Bytes of `parent_anchor` carried in the `GHPP` payout-tag slot of every coinbase.
pub const PARENT_ANCHOR_TAG_LEN: usize = 16;

/// A share's job height `H` must be at least the including anchor's `btc_height` minus this.
pub const SHARE_HEIGHT_WINDOW: u32 = 12;

/// An anchor is a network share meeting `T_net + ANCHOR_TIER_OFFSET` (256x harder).
pub const ANCHOR_TIER_OFFSET: u8 = 8;

/// Lowest network tier, `log2` of the network-share difficulty (about 20 TH/s of pool hash).
pub const T_NET_FLOOR: u8 = 10;

/// Highest network tier. Not in the spec: a safety clamp so `T_net + 8` stays a meaningful target
/// shift and anchor work fits 256 bits. Far above any real pool (10 EH/s is about tier 39).
pub const T_NET_CEILING: u8 = 200;

/// Target anchor spacing in seconds.
pub const ANCHOR_SPACING_SECS: u64 = 54;

/// Bitcoin block interval in seconds, the retarget's clock.
pub const BTC_BLOCK_INTERVAL_SECS: u64 = 600;

/// Retarget window, in Bitcoin blocks, non-overlapping; reset after every tier change.
pub const RETARGET_WINDOW_BLOCKS: u32 = 36;

/// The fast path reads the last this-many Bitcoin blocks.
pub const RETARGET_FAST_BLOCKS: u32 = 6;

/// The fast path jumps when it reads more than this many tiers off.
pub const RETARGET_FAST_TIERS: u32 = 3;

/// Cap on anchors counted for one Bitcoin interval, so the retarget arithmetic stays in `u128`.
/// Far beyond anything real (about 11 anchors per block at target), and it only bounds the size
/// of a jump that is already the largest the fast path can make in practice.
pub const RETARGET_MAX_COUNT_PER_BLOCK: u32 = 1 << 20;

/// Re-inclusion depth from the spec's constants table. Recorded here, NOT used by any rule yet:
/// see `docs/node-pool-reference/PORTING_NOTES.md`.
pub const REINCLUSION_DEPTH_K: u32 = 120;

/// Hard ceiling on a node pool coinbase, non-witness bytes, extranonce and any outputs the SV2
/// pool adds included. The largest slot class (500 P2TR miner outputs) builds about 21.9 KB.
/// Measured on regtest (W0.2): a 22,034 B coinbase mined on a full template under a 90,000 WU
/// reserve, and the SV2 wire carried up to 65,436 B before `SubmitSolution` overflowed, so this
/// leaves the wire a wide margin. A job above it is refused, never sent.
pub const MAX_COINBASE_BYTES: usize = 22_000;

/// `blockreservedweight` a node pool node gives ghostd: the weight `getblocktemplate` leaves
/// free for the block header, the transaction count and the coinbase. ghostd's default, 8,000
/// WU, lost a block at a 2.25 KB coinbase on a full template (W0.2).
pub const NODE_POOL_BLOCK_RESERVED_WEIGHT: u64 = 90_000;

// The reserve must hold the largest coinbase the ceiling allows, plus the 80-byte header, a
// 5-byte transaction count and the 36 witness bytes of a segwit coinbase.
const _: () =
    assert!((MAX_COINBASE_BYTES as u64) * 4 + 36 + (80 + 5) * 4 <= NODE_POOL_BLOCK_RESERVED_WEIGHT);
