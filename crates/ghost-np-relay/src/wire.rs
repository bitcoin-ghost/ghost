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
//| FILE: wire.rs                                                                                                        |
//|======================================================================================================================|

//! Wire messages between node pool nodes.
//!
//! A frame is `len u32 LE || type u8 || payload`, where `len` counts the payload only. Every
//! integer is little-endian; every list carries its count first. Each message type has its own
//! payload cap, checked from the frame header before the payload is read, so a peer cannot make
//! this node buffer more than the largest legitimate message of the type it announced.
//!
//! | Type | Message | Payload |
//! |---|---|---|
//! | 0 | `Hello` | `"GHNR"`, version u16, genesis anchor 32, nonce u64, listen port u16, tip 32, tip work 32 BE, user agent (u8 len) |
//! | 1 | `Share` (NS) | a [`NetShare`] |
//! | 2 | `Anchor` | btc_height u32, the anchor's own [`NetShare`] |
//! | 3 | `Batch` | anchor 32, count u32, share ids 32 each, in batch order |
//! | 4 | `GetBatch` | anchor 32 |
//! | 5 | `GetShares` | count u32, share ids |
//! | 6 | `Shares` | count u16, [`NetShare`]s |
//! | 7 | `GetAnchor` | anchor 32 |
//! | 8 | `NotFound` | kind u8 (0 anchor, 1 batch, 2 share), hash 32 |
//! | 9 | `Tip` | anchor 32, cumulative work 32 BE, anchor height u32 |
//! | 10 | `GetAddr` | empty |
//! | 11 | `Addr` | count u8, addresses (u8 len, UTF-8 `host:port`) |
//! | 12 | `GetHeaders` | count u8, locator anchor hashes (newest first) |
//! | 13 | `Headers` | count u16, anchors in chain order: btc_height u32, the anchor's [`NetShare`] |
//! | 14 | `GetBtcBlocks` | count u8, Bitcoin block hashes |
//! | 15 | `BtcBlocks` | count u16, [`BtcBlockMsg`]s |
//! | 16 | `GetStamps` | empty |
//! | 17 | `Stamps` | node_id 32, count u8, (parent_anchor 32, batch_root 32) newest first |
//! | 18 | `GetAdvert` | empty |
//! | 19 | `Advert` | SV1 port u16, SV2 port u16, SV2 authority key (u8 len, UTF-8) |
//!
//! `NotFound` kind 3 is a Bitcoin block; kind 4 (hash all zeros) answers `GetStamps` from a node
//! that does not stamp jobs; kind 5 (hash all zeros) answers `GetAdvert` from a node that serves
//! no miners. Messages 12 to 15 are share-chain sync (W2.13): a node
//! behind its peers asks for anchor headers after the last locator hash on the peer's best chain,
//! then fetches their batches with `GetBatch` / `GetShares`, and fetches from the archive any
//! Bitcoin block its own Bitcoin node does not have (stale blocks, which Bitcoin peers never
//! serve).
//!
//! Messages 16 and 17 are the job stamp (W2.9): what this node's mining jobs commit to in their
//! share tag besides the miner's own payee and the job's tier and slot class. A miner's
//! `ghost-audit` opens its job's tag with them; without them the tag is a hash the miner cannot
//! check. They are self-authenticating: a stamp that does not hash to the tag in the coinbase
//! proves nothing, so the auditor trusts the audited node for nothing by asking it.
//!
//! Messages 18 and 19 are the mining advert (W2.10): the stratum ports this node serves miners
//! on. They carry ports only, never a host: the endpoints are on the IP the asker reached the
//! relay at, so an advert cannot point a lister or a miner at a third party's machine. Open
//! listing reads the advert, probes those ports with `ghost-audit probe`, and lists the node only
//! on a pass; the advert itself is a claim, worth nothing until the probe measures it.
//!
//! **Forward compatibility.** A frame of a type this build does not know is skipped, unread, with
//! no penalty, as long as its length is within [`MAX_FRAME_PAYLOAD`], the largest cap of any known
//! type. So a later build can add message types without a version bump, and an older node simply
//! never answers them. A known type that breaks its own caps or does not decode is still
//! malformed and scored. `PROTOCOL_VERSION` changes only for a change an older node would
//! misread: a new meaning for an existing type or field. See [`Message::read_header`].
//!
//! A [`NetShare`] is `header 80 || coinbase (u32 len) || merkle branch (u8 count, 32 each) ||
//! node_id 32 || tier u8 || slot_class u16 || payee_script (u8 len) || parent_anchor 32 ||
//! batch_root 32`: the share's header, its non-witness coinbase, the branch from the coinbase
//! txid to the header's merkle root, and the tag preimage. Its id is the header hash.

use bitcoin::block::Header;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::Transaction;

use ghost_common::anchor_chain::{AnchorHash, ShareId};
use ghost_common::node_pool_u256::U256;
use ghost_common::share_commit::ShareTagPreimage;
use ghost_storage::node_pool_store::NpShareRecord;

use crate::relay::JobAnchor;

/// Protocol version spoken by this build.
pub const PROTOCOL_VERSION: u16 = 1;
/// First bytes of every `Hello`.
pub const HELLO_MAGIC: [u8; 4] = *b"GHNR";
/// Largest coinbase accepted on the wire. Above the 22,000-byte job ceiling, which is local
/// policy, so a share from a node with a different ceiling still decodes and is judged.
pub const MAX_COINBASE_WIRE_BYTES: usize = 32 * 1024;
/// Longest merkle branch (a block holds far fewer than 2^32 transactions).
pub const MAX_BRANCH_LEN: usize = 32;
/// Longest payee script accepted on the wire (the classes are at most 34 bytes).
pub const MAX_PAYEE_WIRE_BYTES: usize = 64;
/// Most shares one batch may list. About 16x the expected 256 network shares per anchor.
pub const MAX_BATCH_SHARES: usize = 4_096;
/// Most shares in one `Shares` message.
pub const MAX_SHARES_PER_MESSAGE: usize = 64;
/// Most ids in one `GetShares`.
pub const MAX_IDS_PER_REQUEST: usize = MAX_BATCH_SHARES;
/// Most addresses in one `Addr`.
pub const MAX_ADDRS: usize = 64;
/// Longest address string.
pub const MAX_ADDR_LEN: usize = 128;
/// Longest user agent.
pub const MAX_USER_AGENT: usize = 64;
/// Bytes of a frame header.
pub const FRAME_HEADER_LEN: usize = 5;
/// Most hashes in a `GetHeaders` locator.
pub const MAX_LOCATOR: usize = 64;
/// Most anchors in one `Headers` message.
pub const MAX_HEADERS_PER_MESSAGE: usize = 32;
/// Most Bitcoin blocks asked for, or sent, in one message.
pub const MAX_BTC_BLOCKS_PER_MESSAGE: usize = 16;

/// Most job stamps in one `Stamps`: about 8 minutes of re-batches at the 30 s backstop.
pub const MAX_STAMPS: usize = 16;
/// Longest SV2 authority key string in an `Advert` (base58check of a 32-byte key is about 53).
pub const MAX_AUTHORITY_KEY_LEN: usize = 64;

/// Largest encoded [`NetShare`].
pub const MAX_SHARE_BYTES: usize = 80
    + 4
    + MAX_COINBASE_WIRE_BYTES
    + 1
    + 32 * MAX_BRANCH_LEN
    + 32
    + 1
    + 2
    + 1
    + MAX_PAYEE_WIRE_BYTES
    + 64;

/// Largest encoded [`BtcBlockMsg`].
pub const MAX_BTC_BLOCK_BYTES: usize =
    80 + 4 + 4 + MAX_COINBASE_WIRE_BYTES + 1 + 32 * MAX_BRANCH_LEN;

/// Message type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MsgType {
    /// Handshake.
    Hello = 0,
    /// A network share.
    Share = 1,
    /// An anchor header.
    Anchor = 2,
    /// The share ids an anchor includes.
    Batch = 3,
    /// Ask for a batch.
    GetBatch = 4,
    /// Ask for share bodies.
    GetShares = 5,
    /// Share bodies.
    Shares = 6,
    /// Ask for an anchor header.
    GetAnchor = 7,
    /// The asked-for item is not held.
    NotFound = 8,
    /// The sender's best tip.
    Tip = 9,
    /// Ask for peer addresses.
    GetAddr = 10,
    /// Peer addresses.
    Addr = 11,
    /// Ask for anchor headers after a locator.
    GetHeaders = 12,
    /// Anchor headers in chain order.
    Headers = 13,
    /// Ask for archived Bitcoin blocks.
    GetBtcBlocks = 14,
    /// Archived Bitcoin blocks.
    BtcBlocks = 15,
    /// Ask for the node's recent job stamps.
    GetStamps = 16,
    /// The node's recent job stamps.
    Stamps = 17,
    /// Ask for the node's mining advert.
    GetAdvert = 18,
    /// The node's mining advert.
    Advert = 19,
}

impl MsgType {
    /// The type for a code, if known.
    pub const fn from_code(c: u8) -> Option<MsgType> {
        use MsgType::*;
        Some(match c {
            0 => Hello,
            1 => Share,
            2 => Anchor,
            3 => Batch,
            4 => GetBatch,
            5 => GetShares,
            6 => Shares,
            7 => GetAnchor,
            8 => NotFound,
            9 => Tip,
            10 => GetAddr,
            11 => Addr,
            12 => GetHeaders,
            13 => Headers,
            14 => GetBtcBlocks,
            15 => BtcBlocks,
            16 => GetStamps,
            17 => Stamps,
            18 => GetAdvert,
            19 => Advert,
            _ => return None,
        })
    }

    /// The largest payload a message of this type may carry.
    pub const fn max_payload(self) -> usize {
        use MsgType::*;
        match self {
            Hello => 4 + 2 + 32 + 8 + 2 + 32 + 32 + 1 + MAX_USER_AGENT,
            Share => MAX_SHARE_BYTES,
            Anchor => 4 + MAX_SHARE_BYTES,
            Batch => 32 + 4 + 32 * MAX_BATCH_SHARES,
            GetBatch | GetAnchor => 32,
            GetShares => 4 + 32 * MAX_IDS_PER_REQUEST,
            Shares => 2 + MAX_SHARES_PER_MESSAGE * MAX_SHARE_BYTES,
            NotFound => 33,
            Tip => 32 + 32 + 4,
            GetAddr => 0,
            Addr => 1 + MAX_ADDRS * (1 + MAX_ADDR_LEN),
            GetHeaders => 1 + 32 * MAX_LOCATOR,
            Headers => 2 + MAX_HEADERS_PER_MESSAGE * (4 + MAX_SHARE_BYTES),
            GetBtcBlocks => 1 + 32 * MAX_BTC_BLOCKS_PER_MESSAGE,
            BtcBlocks => 2 + MAX_BTC_BLOCKS_PER_MESSAGE * MAX_BTC_BLOCK_BYTES,
            GetStamps => 0,
            Stamps => 32 + 1 + 64 * MAX_STAMPS,
            GetAdvert => 0,
            Advert => 2 + 2 + 1 + MAX_AUTHORITY_KEY_LEN,
        }
    }
}

/// The largest payload of any known message type. A frame of an unknown type up to this length
/// is skipped without penalty (forward compatibility); a longer one is malformed.
pub const MAX_FRAME_PAYLOAD: usize = {
    let mut max = 0;
    let mut c = 0u8;
    loop {
        if let Some(t) = MsgType::from_code(c) {
            if t.max_payload() > max {
                max = t.max_payload();
            }
        }
        if c == u8::MAX {
            break;
        }
        c += 1;
    }
    max
};

/// A frame header as read off the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameHead {
    /// A type this build knows, with its payload length (within the type's cap).
    Known(MsgType, usize),
    /// A type this build does not know: its payload is skipped, unread, without penalty.
    Unknown {
        /// The type code.
        code: u8,
        /// Payload length (at most [`MAX_FRAME_PAYLOAD`]).
        len: usize,
    },
}

/// Why bytes did not decode. Every variant is the sender's fault.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// Fewer bytes than the message needs.
    #[error("truncated")]
    Truncated,
    /// Bytes left over after the message.
    #[error("trailing bytes")]
    Trailing,
    /// No such message type.
    #[error("unknown message type {0}")]
    UnknownType(u8),
    /// The payload is larger than its type allows.
    #[error("payload of {len} bytes over the {max}-byte cap")]
    TooLarge {
        /// Announced length.
        len: usize,
        /// The type's cap.
        max: usize,
    },
    /// A list longer than its cap.
    #[error("list of {0} over its cap")]
    TooMany(usize),
    /// The header did not decode.
    #[error("bad header")]
    BadHeader,
    /// The coinbase did not decode as a transaction.
    #[error("bad coinbase")]
    BadCoinbase,
    /// A string that is not UTF-8.
    #[error("bad string")]
    BadString,
    /// A `Hello` without the magic.
    #[error("bad magic")]
    BadMagic,
}

/// A share as it travels: everything a peer needs to check it alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetShare {
    /// The block header the miner hashed.
    pub header: Header,
    /// The coinbase, non-witness serialization.
    pub coinbase: Vec<u8>,
    /// Merkle branch from the coinbase txid to the header's merkle root.
    pub merkle_branch: Vec<[u8; 32]>,
    /// The tag preimage the coinbase commits to.
    pub tag: ShareTagPreimage,
}

impl NetShare {
    /// A share from its parts as a pool holds them: the 80-byte header, the serialized coinbase
    /// (with or without witness data) and the merkle branch.
    pub fn from_parts(
        header80: &[u8],
        coinbase: Vec<u8>,
        merkle_branch: Vec<[u8; 32]>,
        tag: ShareTagPreimage,
    ) -> Result<NetShare, WireError> {
        if header80.len() != 80 {
            return Err(WireError::BadHeader);
        }
        let header = deserialize(header80).map_err(|_| WireError::BadHeader)?;
        let tx: Transaction = deserialize(&coinbase).map_err(|_| WireError::BadCoinbase)?;
        if merkle_branch.len() > MAX_BRANCH_LEN {
            return Err(WireError::TooMany(merkle_branch.len()));
        }
        // Carried without witness data: the txid, which is what folds to the root, ignores it.
        let coinbase = bitcoin::consensus::encode::serialize(&strip_witness(tx));
        if coinbase.len() > MAX_COINBASE_WIRE_BYTES {
            return Err(WireError::TooMany(coinbase.len()));
        }
        Ok(NetShare {
            header,
            coinbase,
            merkle_branch,
            tag,
        })
    }

    /// The share's id: its header hash, internal byte order.
    pub fn id(&self) -> ShareId {
        self.header.block_hash().to_byte_array()
    }

    /// The header's `prev_hash`, internal byte order.
    pub fn prev_hash(&self) -> [u8; 32] {
        self.header.prev_blockhash.to_byte_array()
    }

    /// The coinbase as a transaction.
    pub fn coinbase_tx(&self) -> Result<Transaction, WireError> {
        deserialize(&self.coinbase).map_err(|_| WireError::BadCoinbase)
    }

    /// The stored form, at job height `job_height`.
    pub fn to_record(&self, job_height: u32) -> NpShareRecord {
        let mut header = [0u8; 80];
        header.copy_from_slice(&serialize(&self.header));
        NpShareRecord {
            share_id: self.id(),
            header,
            coinbase: self.coinbase.clone(),
            merkle_branch: self.merkle_branch.clone(),
            tag: self.tag.clone(),
            job_height,
        }
    }

    /// From the stored form.
    pub fn from_record(r: &NpShareRecord) -> Result<NetShare, WireError> {
        Ok(NetShare {
            header: deserialize(&r.header).map_err(|_| WireError::BadHeader)?,
            coinbase: r.coinbase.clone(),
            merkle_branch: r.merkle_branch.clone(),
            tag: r.tag.clone(),
        })
    }
}

/// An anchor header: the anchor's own share and the Bitcoin tip height its job saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorMsg {
    /// `btc_height`: the height of the share header's `prev_hash`.
    pub btc_height: u32,
    /// The anchor's own share. Its tag commits `parent_anchor` and `batch_root`.
    pub share: NetShare,
}

/// The handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// Protocol version.
    pub version: u16,
    /// The genesis anchor: nodes on different share chains do not talk.
    pub genesis: AnchorHash,
    /// Random per process, to drop connections to self.
    pub nonce: u64,
    /// The port this node accepts connections on, 0 for none.
    pub listen_port: u16,
    /// The sender's best tip.
    pub tip: AnchorHash,
    /// Its cumulative work.
    pub tip_work: U256,
    /// Free text.
    pub user_agent: String,
}

/// A Bitcoin block from the archive: its header, height, and coinbase (non-witness) with the
/// merkle branch from the coinbase txid to the header's merkle root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtcBlockMsg {
    /// The header.
    pub header: Header,
    /// Its height.
    pub height: u32,
    /// The coinbase, non-witness serialization.
    pub coinbase: Vec<u8>,
    /// The merkle branch.
    pub branch: Vec<[u8; 32]>,
}

/// What a `NotFound` refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotFoundKind {
    /// An anchor header.
    Anchor = 0,
    /// A batch.
    Batch = 1,
    /// A share.
    Share = 2,
    /// An archived Bitcoin block.
    BtcBlock = 3,
    /// Job stamps: this node does not stamp jobs (no pool attached).
    Stamps = 4,
    /// A mining advert: this node serves no miners (no pool attached, or nothing advertised).
    Advert = 5,
}

/// The stratum ports a node serves miners on, on the IP its relay port was reached at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeAdvert {
    /// SV1 stratum port, 0 for none.
    pub sv1_port: u16,
    /// SV2 port, 0 for none.
    pub sv2_port: u16,
    /// The SV2 authority public key miners check the Noise handshake against, as pool_sv2
    /// prints it (base58check). Empty for none. At most [`MAX_AUTHORITY_KEY_LEN`] bytes.
    pub sv2_authority_key: String,
}

/// What a node's mining jobs commit to in their share tag, besides each miner's own payee, tier
/// and slot class: its `node_id`, and the anchor and batch root of its recent job stamps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobStamps {
    /// The node id every tag of this node commits.
    pub node_id: [u8; 32],
    /// The last stamps published to its jobs, newest first, at most [`MAX_STAMPS`].
    pub recent: Vec<JobAnchor>,
}

/// One relay message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Handshake.
    Hello(Hello),
    /// A network share.
    Share(NetShare),
    /// An anchor header.
    Anchor(AnchorMsg),
    /// The share ids an anchor includes, in batch order.
    Batch {
        /// The anchor.
        anchor: AnchorHash,
        /// Share ids.
        ids: Vec<ShareId>,
    },
    /// Ask for an anchor's batch.
    GetBatch(AnchorHash),
    /// Ask for share bodies.
    GetShares(Vec<ShareId>),
    /// Share bodies.
    Shares(Vec<NetShare>),
    /// Ask for an anchor header.
    GetAnchor(AnchorHash),
    /// The asked-for item is not held.
    NotFound(NotFoundKind, [u8; 32]),
    /// The sender's best tip.
    Tip {
        /// Tip anchor.
        hash: AnchorHash,
        /// Cumulative work.
        work: U256,
        /// Anchor height.
        height: u32,
    },
    /// Ask for addresses.
    GetAddr,
    /// Peer addresses, `host:port`.
    Addr(Vec<String>),
    /// Ask for the anchors after the first locator hash on the receiver's best chain.
    GetHeaders(Vec<AnchorHash>),
    /// Anchor headers, parents first.
    Headers(Vec<AnchorMsg>),
    /// Ask for archived Bitcoin blocks by hash.
    GetBtcBlocks(Vec<[u8; 32]>),
    /// Archived Bitcoin blocks.
    BtcBlocks(Vec<BtcBlockMsg>),
    /// Ask for the node's job stamps.
    GetStamps,
    /// The node's job stamps.
    Stamps(JobStamps),
    /// Ask for the node's mining advert.
    GetAdvert,
    /// The node's mining advert.
    Advert(NodeAdvert),
}

impl Message {
    /// The message's type.
    pub fn msg_type(&self) -> MsgType {
        match self {
            Message::Hello(_) => MsgType::Hello,
            Message::Share(_) => MsgType::Share,
            Message::Anchor(_) => MsgType::Anchor,
            Message::Batch { .. } => MsgType::Batch,
            Message::GetBatch(_) => MsgType::GetBatch,
            Message::GetShares(_) => MsgType::GetShares,
            Message::Shares(_) => MsgType::Shares,
            Message::GetAnchor(_) => MsgType::GetAnchor,
            Message::NotFound(..) => MsgType::NotFound,
            Message::Tip { .. } => MsgType::Tip,
            Message::GetAddr => MsgType::GetAddr,
            Message::Addr(_) => MsgType::Addr,
            Message::GetHeaders(_) => MsgType::GetHeaders,
            Message::Headers(_) => MsgType::Headers,
            Message::GetBtcBlocks(_) => MsgType::GetBtcBlocks,
            Message::BtcBlocks(_) => MsgType::BtcBlocks,
            Message::GetStamps => MsgType::GetStamps,
            Message::Stamps(_) => MsgType::Stamps,
            Message::GetAdvert => MsgType::GetAdvert,
            Message::Advert(_) => MsgType::Advert,
        }
    }

    /// The whole frame: header and payload. Panics only if the message breaks its own caps,
    /// which this node never builds.
    pub fn encode(&self) -> Vec<u8> {
        let mut p = Vec::new();
        self.encode_payload(&mut p);
        let t = self.msg_type();
        assert!(
            p.len() <= t.max_payload(),
            "{t:?} payload of {} bytes over its cap",
            p.len()
        );
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + p.len());
        out.extend_from_slice(&(p.len() as u32).to_le_bytes());
        out.push(t as u8);
        out.extend_from_slice(&p);
        out
    }

    fn encode_payload(&self, p: &mut Vec<u8>) {
        match self {
            Message::Hello(h) => {
                p.extend_from_slice(&HELLO_MAGIC);
                p.extend_from_slice(&h.version.to_le_bytes());
                p.extend_from_slice(&h.genesis);
                p.extend_from_slice(&h.nonce.to_le_bytes());
                p.extend_from_slice(&h.listen_port.to_le_bytes());
                p.extend_from_slice(&h.tip);
                p.extend_from_slice(&h.tip_work.to_be_bytes());
                put_str(p, &h.user_agent, MAX_USER_AGENT);
            }
            Message::Share(s) => put_share(p, s),
            Message::Anchor(a) => {
                p.extend_from_slice(&a.btc_height.to_le_bytes());
                put_share(p, &a.share);
            }
            Message::Batch { anchor, ids } => {
                p.extend_from_slice(anchor);
                put_ids(p, ids);
            }
            Message::GetBatch(h) | Message::GetAnchor(h) => p.extend_from_slice(h),
            Message::GetShares(ids) => put_ids(p, ids),
            Message::Shares(v) => {
                p.extend_from_slice(&(v.len() as u16).to_le_bytes());
                v.iter().for_each(|s| put_share(p, s));
            }
            Message::NotFound(k, h) => {
                p.push(*k as u8);
                p.extend_from_slice(h);
            }
            Message::Tip { hash, work, height } => {
                p.extend_from_slice(hash);
                p.extend_from_slice(&work.to_be_bytes());
                p.extend_from_slice(&height.to_le_bytes());
            }
            Message::GetAddr | Message::GetStamps | Message::GetAdvert => {}
            Message::Advert(a) => {
                p.extend_from_slice(&a.sv1_port.to_le_bytes());
                p.extend_from_slice(&a.sv2_port.to_le_bytes());
                put_str(p, &a.sv2_authority_key, MAX_AUTHORITY_KEY_LEN);
            }
            Message::Stamps(s) => {
                p.extend_from_slice(&s.node_id);
                p.push(s.recent.len() as u8);
                for j in &s.recent {
                    p.extend_from_slice(&j.parent_anchor);
                    p.extend_from_slice(&j.batch_root);
                }
            }
            Message::Addr(v) => {
                p.push(v.len() as u8);
                v.iter().for_each(|a| put_str(p, a, MAX_ADDR_LEN));
            }
            Message::GetHeaders(v) | Message::GetBtcBlocks(v) => {
                p.push(v.len() as u8);
                v.iter().for_each(|h| p.extend_from_slice(h));
            }
            Message::Headers(v) => {
                p.extend_from_slice(&(v.len() as u16).to_le_bytes());
                for a in v {
                    p.extend_from_slice(&a.btc_height.to_le_bytes());
                    put_share(p, &a.share);
                }
            }
            Message::BtcBlocks(v) => {
                p.extend_from_slice(&(v.len() as u16).to_le_bytes());
                for b in v {
                    p.extend_from_slice(&serialize(&b.header));
                    p.extend_from_slice(&b.height.to_le_bytes());
                    p.extend_from_slice(&(b.coinbase.len() as u32).to_le_bytes());
                    p.extend_from_slice(&b.coinbase);
                    p.push(b.branch.len() as u8);
                    b.branch.iter().for_each(|x| p.extend_from_slice(x));
                }
            }
        }
    }

    /// Read a frame header off a stream, before any payload. A known type over its cap is
    /// refused. An unknown type is [`FrameHead::Unknown`], for the reader to skip without penalty
    /// (a newer peer's message), unless its length is over [`MAX_FRAME_PAYLOAD`].
    pub fn read_header(h: &[u8; FRAME_HEADER_LEN]) -> Result<FrameHead, WireError> {
        let len = u32::from_le_bytes([h[0], h[1], h[2], h[3]]) as usize;
        let Some(t) = MsgType::from_code(h[4]) else {
            if len > MAX_FRAME_PAYLOAD {
                return Err(WireError::TooLarge {
                    len,
                    max: MAX_FRAME_PAYLOAD,
                });
            }
            return Ok(FrameHead::Unknown { code: h[4], len });
        };
        if len > t.max_payload() {
            return Err(WireError::TooLarge {
                len,
                max: t.max_payload(),
            });
        }
        Ok(FrameHead::Known(t, len))
    }

    /// Read a frame header that must be of a known type: the type and payload length, refusing
    /// an unknown type or a length over the type's cap. For decoding a whole frame as a
    /// [`Message`]; a stream reader uses [`Message::read_header`] and skips unknown types.
    pub fn decode_header(h: &[u8; FRAME_HEADER_LEN]) -> Result<(MsgType, usize), WireError> {
        match Self::read_header(h)? {
            FrameHead::Known(t, len) => Ok((t, len)),
            FrameHead::Unknown { code, .. } => Err(WireError::UnknownType(code)),
        }
    }

    /// Decode a payload of type `t`.
    pub fn decode_payload(t: MsgType, payload: &[u8]) -> Result<Message, WireError> {
        if payload.len() > t.max_payload() {
            return Err(WireError::TooLarge {
                len: payload.len(),
                max: t.max_payload(),
            });
        }
        let mut r = Reader(payload);
        let m = match t {
            MsgType::Hello => {
                if r.take(4)? != HELLO_MAGIC {
                    return Err(WireError::BadMagic);
                }
                Message::Hello(Hello {
                    version: r.u16()?,
                    genesis: r.arr32()?,
                    nonce: r.u64()?,
                    listen_port: r.u16()?,
                    tip: r.arr32()?,
                    tip_work: U256::from_be_bytes(r.arr32()?),
                    user_agent: r.string(MAX_USER_AGENT)?,
                })
            }
            MsgType::Share => Message::Share(r.share()?),
            MsgType::Anchor => Message::Anchor(AnchorMsg {
                btc_height: r.u32()?,
                share: r.share()?,
            }),
            MsgType::Batch => Message::Batch {
                anchor: r.arr32()?,
                ids: r.ids(MAX_BATCH_SHARES)?,
            },
            MsgType::GetBatch => Message::GetBatch(r.arr32()?),
            MsgType::GetAnchor => Message::GetAnchor(r.arr32()?),
            MsgType::GetShares => Message::GetShares(r.ids(MAX_IDS_PER_REQUEST)?),
            MsgType::Shares => {
                let n = r.u16()? as usize;
                if n > MAX_SHARES_PER_MESSAGE {
                    return Err(WireError::TooMany(n));
                }
                Message::Shares((0..n).map(|_| r.share()).collect::<Result<_, _>>()?)
            }
            MsgType::NotFound => {
                let k = match r.u8()? {
                    0 => NotFoundKind::Anchor,
                    1 => NotFoundKind::Batch,
                    2 => NotFoundKind::Share,
                    3 => NotFoundKind::BtcBlock,
                    4 => NotFoundKind::Stamps,
                    5 => NotFoundKind::Advert,
                    _ => return Err(WireError::Truncated),
                };
                Message::NotFound(k, r.arr32()?)
            }
            MsgType::Tip => Message::Tip {
                hash: r.arr32()?,
                work: U256::from_be_bytes(r.arr32()?),
                height: r.u32()?,
            },
            MsgType::GetAddr => Message::GetAddr,
            MsgType::GetStamps => Message::GetStamps,
            MsgType::GetAdvert => Message::GetAdvert,
            MsgType::Advert => Message::Advert(NodeAdvert {
                sv1_port: r.u16()?,
                sv2_port: r.u16()?,
                sv2_authority_key: r.string(MAX_AUTHORITY_KEY_LEN)?,
            }),
            MsgType::Stamps => {
                let node_id = r.arr32()?;
                let n = r.u8()? as usize;
                if n > MAX_STAMPS {
                    return Err(WireError::TooMany(n));
                }
                let recent = (0..n)
                    .map(|_| {
                        Ok(JobAnchor {
                            parent_anchor: r.arr32()?,
                            batch_root: r.arr32()?,
                        })
                    })
                    .collect::<Result<_, WireError>>()?;
                Message::Stamps(JobStamps { node_id, recent })
            }
            MsgType::Addr => {
                let n = r.u8()? as usize;
                if n > MAX_ADDRS {
                    return Err(WireError::TooMany(n));
                }
                Message::Addr(
                    (0..n)
                        .map(|_| r.string(MAX_ADDR_LEN))
                        .collect::<Result<_, _>>()?,
                )
            }
            MsgType::GetHeaders => Message::GetHeaders(r.hashes(MAX_LOCATOR)?),
            MsgType::GetBtcBlocks => Message::GetBtcBlocks(r.hashes(MAX_BTC_BLOCKS_PER_MESSAGE)?),
            MsgType::Headers => {
                let n = r.u16()? as usize;
                if n > MAX_HEADERS_PER_MESSAGE {
                    return Err(WireError::TooMany(n));
                }
                Message::Headers(
                    (0..n)
                        .map(|_| {
                            Ok(AnchorMsg {
                                btc_height: r.u32()?,
                                share: r.share()?,
                            })
                        })
                        .collect::<Result<_, WireError>>()?,
                )
            }
            MsgType::BtcBlocks => {
                let n = r.u16()? as usize;
                if n > MAX_BTC_BLOCKS_PER_MESSAGE {
                    return Err(WireError::TooMany(n));
                }
                Message::BtcBlocks((0..n).map(|_| r.btc_block()).collect::<Result<_, _>>()?)
            }
        };
        if !r.0.is_empty() {
            return Err(WireError::Trailing);
        }
        Ok(m)
    }

    /// Decode a whole frame (header and payload).
    pub fn decode(frame: &[u8]) -> Result<Message, WireError> {
        let h: &[u8; FRAME_HEADER_LEN] = frame
            .get(..FRAME_HEADER_LEN)
            .and_then(|h| h.try_into().ok())
            .ok_or(WireError::Truncated)?;
        let (t, len) = Self::decode_header(h)?;
        let payload = &frame[FRAME_HEADER_LEN..];
        match payload.len().cmp(&len) {
            std::cmp::Ordering::Less => Err(WireError::Truncated),
            std::cmp::Ordering::Greater => Err(WireError::Trailing),
            std::cmp::Ordering::Equal => Self::decode_payload(t, payload),
        }
    }
}

fn strip_witness(mut tx: Transaction) -> Transaction {
    for i in &mut tx.input {
        i.witness.clear();
    }
    tx
}

fn put_str(p: &mut Vec<u8>, s: &str, max: usize) {
    let b = &s.as_bytes()[..s.len().min(max)];
    p.push(b.len() as u8);
    p.extend_from_slice(b);
}

fn put_ids(p: &mut Vec<u8>, ids: &[[u8; 32]]) {
    p.extend_from_slice(&(ids.len() as u32).to_le_bytes());
    ids.iter().for_each(|i| p.extend_from_slice(i));
}

fn put_share(p: &mut Vec<u8>, s: &NetShare) {
    p.extend_from_slice(&serialize(&s.header));
    p.extend_from_slice(&(s.coinbase.len() as u32).to_le_bytes());
    p.extend_from_slice(&s.coinbase);
    p.push(s.merkle_branch.len() as u8);
    s.merkle_branch.iter().for_each(|b| p.extend_from_slice(b));
    p.extend_from_slice(&s.tag.node_id);
    p.push(s.tag.tier);
    p.extend_from_slice(&s.tag.slot_class.to_le_bytes());
    p.push(s.tag.payee_script.len() as u8);
    p.extend_from_slice(&s.tag.payee_script);
    p.extend_from_slice(&s.tag.parent_anchor);
    p.extend_from_slice(&s.tag.batch_root);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.0.len() < n {
            return Err(WireError::Truncated);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }

    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().expect("2")))
    }

    fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4")))
    }

    fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("8")))
    }

    fn arr32(&mut self) -> Result<[u8; 32], WireError> {
        Ok(self.take(32)?.try_into().expect("32"))
    }

    fn ids(&mut self, max: usize) -> Result<Vec<[u8; 32]>, WireError> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(WireError::TooMany(n));
        }
        (0..n).map(|_| self.arr32()).collect()
    }

    fn hashes(&mut self, max: usize) -> Result<Vec<[u8; 32]>, WireError> {
        let n = self.u8()? as usize;
        if n > max {
            return Err(WireError::TooMany(n));
        }
        (0..n).map(|_| self.arr32()).collect()
    }

    fn btc_block(&mut self) -> Result<BtcBlockMsg, WireError> {
        let header: Header = deserialize(self.take(80)?).map_err(|_| WireError::BadHeader)?;
        let height = self.u32()?;
        let n = self.u32()? as usize;
        if n > MAX_COINBASE_WIRE_BYTES {
            return Err(WireError::TooMany(n));
        }
        let coinbase = self.take(n)?.to_vec();
        let b = self.u8()? as usize;
        if b > MAX_BRANCH_LEN {
            return Err(WireError::TooMany(b));
        }
        let branch = (0..b).map(|_| self.arr32()).collect::<Result<_, _>>()?;
        Ok(BtcBlockMsg {
            header,
            height,
            coinbase,
            branch,
        })
    }

    fn string(&mut self, max: usize) -> Result<String, WireError> {
        let n = self.u8()? as usize;
        if n > max {
            return Err(WireError::TooMany(n));
        }
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| WireError::BadString)
    }

    fn share(&mut self) -> Result<NetShare, WireError> {
        let header: Header = deserialize(self.take(80)?).map_err(|_| WireError::BadHeader)?;
        let n = self.u32()? as usize;
        if n > MAX_COINBASE_WIRE_BYTES {
            return Err(WireError::TooMany(n));
        }
        let coinbase = self.take(n)?.to_vec();
        let b = self.u8()? as usize;
        if b > MAX_BRANCH_LEN {
            return Err(WireError::TooMany(b));
        }
        let merkle_branch = (0..b).map(|_| self.arr32()).collect::<Result<_, _>>()?;
        let node_id = self.arr32()?;
        let tier = self.u8()?;
        let slot_class = self.u16()?;
        let pl = self.u8()? as usize;
        if pl > MAX_PAYEE_WIRE_BYTES {
            return Err(WireError::TooMany(pl));
        }
        let payee_script = self.take(pl)?.to_vec();
        let parent_anchor = self.arr32()?;
        let batch_root = self.arr32()?;
        Ok(NetShare {
            header,
            coinbase,
            merkle_branch,
            tag: ShareTagPreimage {
                node_id,
                tier,
                slot_class,
                payee_script,
                parent_anchor,
                batch_root,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::block::Version;
    use bitcoin::hash_types::TxMerkleNode;
    use bitcoin::{BlockHash, CompactTarget};

    pub(crate) fn sample_share(seed: u8) -> NetShare {
        NetShare {
            header: Header {
                version: Version::from_consensus(0x2000_0000),
                prev_blockhash: BlockHash::from_byte_array([seed; 32]),
                merkle_root: TxMerkleNode::from_byte_array([seed ^ 1; 32]),
                time: 1_800_000_000,
                bits: CompactTarget::from_consensus(0x1702_1be5),
                nonce: seed as u32,
            },
            coinbase: vec![seed; 120],
            merkle_branch: vec![[seed; 32], [2; 32]],
            tag: ShareTagPreimage {
                node_id: [3; 32],
                tier: 12,
                slot_class: 44,
                payee_script: vec![0x51, 0x20, seed],
                parent_anchor: [4; 32],
                batch_root: [5; 32],
            },
        }
    }

    fn all_messages() -> Vec<Message> {
        vec![
            Message::Hello(Hello {
                version: PROTOCOL_VERSION,
                genesis: [1; 32],
                nonce: 7,
                listen_port: 8566,
                tip: [2; 32],
                tip_work: U256::pow2(40).unwrap(),
                user_agent: "ghost/1".into(),
            }),
            Message::Share(sample_share(1)),
            Message::Anchor(AnchorMsg {
                btc_height: 974_500,
                share: sample_share(2),
            }),
            Message::Batch {
                anchor: [3; 32],
                ids: vec![[4; 32], [5; 32]],
            },
            Message::Batch {
                anchor: [3; 32],
                ids: vec![],
            },
            Message::GetBatch([6; 32]),
            Message::GetShares(vec![[7; 32]]),
            Message::Shares(vec![sample_share(3), sample_share(4)]),
            Message::GetAnchor([8; 32]),
            Message::NotFound(NotFoundKind::Batch, [9; 32]),
            Message::Tip {
                hash: [10; 32],
                work: U256::pow2(100).unwrap(),
                height: 42,
            },
            Message::GetAddr,
            Message::Addr(vec!["10.0.0.1:8566".into(), "[::1]:8566".into()]),
            Message::GetHeaders(vec![[11; 32], [12; 32]]),
            Message::GetHeaders(vec![]),
            Message::Headers(vec![
                AnchorMsg {
                    btc_height: 974_501,
                    share: sample_share(5),
                },
                AnchorMsg {
                    btc_height: 974_502,
                    share: sample_share(6),
                },
            ]),
            Message::GetBtcBlocks(vec![[13; 32]]),
            Message::BtcBlocks(vec![BtcBlockMsg {
                header: sample_share(7).header,
                height: 974_503,
                coinbase: vec![7; 90],
                branch: vec![[8; 32]],
            }]),
            Message::NotFound(NotFoundKind::BtcBlock, [14; 32]),
            Message::GetStamps,
            Message::Stamps(JobStamps {
                node_id: [15; 32],
                recent: vec![
                    JobAnchor {
                        parent_anchor: [16; 32],
                        batch_root: [17; 32],
                    },
                    JobAnchor {
                        parent_anchor: [18; 32],
                        batch_root: [19; 32],
                    },
                ],
            }),
            Message::Stamps(JobStamps {
                node_id: [20; 32],
                recent: vec![],
            }),
            Message::NotFound(NotFoundKind::Stamps, [0; 32]),
            Message::GetAdvert,
            Message::Advert(NodeAdvert {
                sv1_port: 3333,
                sv2_port: 34255,
                sv2_authority_key: "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72".into(),
            }),
            Message::Advert(NodeAdvert::default()),
            Message::NotFound(NotFoundKind::Advert, [0; 32]),
        ]
    }

    #[test]
    fn an_advert_is_pinned_and_capped() {
        let f = Message::Advert(NodeAdvert {
            sv1_port: 0x0D05,
            sv2_port: 0x85CF,
            sv2_authority_key: "ab".into(),
        })
        .encode();
        assert_eq!(&f[..5], &[7, 0, 0, 0, 19]);
        assert_eq!(&f[5..], &[0x05, 0x0D, 0xCF, 0x85, 2, b'a', b'b']);
        // A key longer than the cap is cut on encode and refused on decode.
        let long = Message::Advert(NodeAdvert {
            sv2_authority_key: "k".repeat(MAX_AUTHORITY_KEY_LEN + 10),
            ..NodeAdvert::default()
        })
        .encode();
        assert_eq!(long.len(), FRAME_HEADER_LEN + 5 + MAX_AUTHORITY_KEY_LEN);
        let mut p = vec![0u8; 4];
        p.push((MAX_AUTHORITY_KEY_LEN + 1) as u8);
        p.extend(vec![b'k'; MAX_AUTHORITY_KEY_LEN + 1]);
        assert!(Message::decode_payload(MsgType::Advert, &p).is_err());
        assert!(Message::decode_header(&[1, 0, 0, 0, 18]).is_err());
    }

    #[test]
    fn every_message_round_trips() {
        for m in all_messages() {
            let f = m.encode();
            assert_eq!(Message::decode(&f), Ok(m.clone()), "{:?}", m.msg_type());
            // Every strict prefix is refused, never misread.
            for cut in [FRAME_HEADER_LEN, f.len() - 1] {
                if cut < f.len() {
                    assert!(Message::decode(&f[..cut]).is_err(), "{:?}", m.msg_type());
                }
            }
            let mut long = f.clone();
            long.push(0);
            assert!(Message::decode(&long).is_err());
        }
    }

    #[test]
    fn payload_bytes_are_pinned() {
        let f = Message::GetBatch([0xAB; 32]).encode();
        assert_eq!(&f[..5], &[32, 0, 0, 0, 4]);
        let f = Message::Tip {
            hash: [1; 32],
            work: U256::from_u128(0x0102),
            height: 0x0304,
        }
        .encode();
        assert_eq!(f.len(), 5 + 68);
        assert_eq!(&f[5 + 32 + 30..5 + 32 + 32], &[1, 2]);
        assert_eq!(&f[5 + 64..], &[4, 3, 0, 0]);
        // A share: 80-byte header first, then the coinbase length.
        let s = sample_share(9);
        let f = Message::Share(s.clone()).encode();
        assert_eq!(&f[5..85], serialize(&s.header).as_slice());
        assert_eq!(&f[85..89], &120u32.to_le_bytes());
    }

    #[test]
    fn caps_are_enforced_from_the_header() {
        // An unknown type and an over-cap length are refused before any payload.
        assert_eq!(
            Message::decode_header(&[0, 0, 0, 0, 99]),
            Err(WireError::UnknownType(99))
        );
        let over = (MsgType::GetBatch.max_payload() as u32 + 1).to_le_bytes();
        assert!(matches!(
            Message::decode_header(&[over[0], over[1], over[2], over[3], 4]),
            Err(WireError::TooLarge { .. })
        ));
        assert!(Message::decode_header(&[0xFF, 0xFF, 0xFF, 0xFF, 6]).is_err());
        // A stream reader is told an unknown type's length, to skip it, up to the frame cap.
        let at_cap = (MAX_FRAME_PAYLOAD as u32).to_le_bytes();
        assert_eq!(
            Message::read_header(&[at_cap[0], at_cap[1], at_cap[2], at_cap[3], 200]),
            Ok(FrameHead::Unknown {
                code: 200,
                len: MAX_FRAME_PAYLOAD
            })
        );
        let over = (MAX_FRAME_PAYLOAD as u32 + 1).to_le_bytes();
        assert!(matches!(
            Message::read_header(&[over[0], over[1], over[2], over[3], 200]),
            Err(WireError::TooLarge { .. })
        ));
        // The cap is the largest known type's, so no known message is ever longer.
        assert!((0..=u8::MAX)
            .filter_map(MsgType::from_code)
            .all(|t| t.max_payload() <= MAX_FRAME_PAYLOAD));
        // A list count above its cap is refused even when the frame is within the type's cap.
        let mut p = vec![0u8; 32];
        p.extend_from_slice(&((MAX_BATCH_SHARES + 1) as u32).to_le_bytes());
        assert_eq!(
            Message::decode_payload(MsgType::Batch, &p),
            Err(WireError::TooMany(MAX_BATCH_SHARES + 1))
        );
        let mut s = Message::Share(sample_share(1)).encode()[5..].to_vec();
        s[80..84].copy_from_slice(&((MAX_COINBASE_WIRE_BYTES + 1) as u32).to_le_bytes());
        assert!(Message::decode_payload(MsgType::Share, &s).is_err());
        let mut h = Message::Hello(Hello {
            version: 1,
            genesis: [0; 32],
            nonce: 0,
            listen_port: 0,
            tip: [0; 32],
            tip_work: U256::ZERO,
            user_agent: String::new(),
        })
        .encode()[5..]
            .to_vec();
        h[0] = b'X';
        assert_eq!(
            Message::decode_payload(MsgType::Hello, &h),
            Err(WireError::BadMagic)
        );
        // Sync lists over their caps are refused.
        let mut g = vec![(MAX_LOCATOR + 1) as u8];
        g.extend(vec![0u8; 32 * (MAX_LOCATOR + 1)]);
        assert!(Message::decode_payload(MsgType::GetHeaders, &g).is_err());
        let over = ((MAX_HEADERS_PER_MESSAGE + 1) as u16).to_le_bytes();
        assert_eq!(
            Message::decode_payload(MsgType::Headers, &over),
            Err(WireError::TooMany(MAX_HEADERS_PER_MESSAGE + 1))
        );
        let over = ((MAX_BTC_BLOCKS_PER_MESSAGE + 1) as u16).to_le_bytes();
        assert!(Message::decode_payload(MsgType::BtcBlocks, &over).is_err());
        let mut st = vec![0u8; 32];
        st.push((MAX_STAMPS + 1) as u8);
        st.extend(vec![0u8; 64 * (MAX_STAMPS + 1)]);
        assert!(Message::decode_payload(MsgType::Stamps, &st).is_err());
        let full = Message::Stamps(JobStamps {
            node_id: [1; 32],
            recent: vec![
                JobAnchor {
                    parent_anchor: [2; 32],
                    batch_root: [3; 32],
                };
                MAX_STAMPS
            ],
        });
        assert!(Message::decode(&full.encode()).is_ok());
        // The largest legal sync messages fit their caps.
        let headers = Message::Headers(
            (0..MAX_HEADERS_PER_MESSAGE)
                .map(|i| AnchorMsg {
                    btc_height: i as u32,
                    share: sample_share(i as u8),
                })
                .collect(),
        );
        assert!(Message::decode(&headers.encode()).is_ok());
        // The largest legal batch fits its cap.
        let big = Message::Batch {
            anchor: [0; 32],
            ids: vec![[1; 32]; MAX_BATCH_SHARES],
        };
        assert!(Message::decode(&big.encode()).is_ok());
    }

    #[test]
    fn a_pool_share_drops_its_witness_and_keeps_its_id() {
        use bitcoin::{OutPoint, ScriptBuf, Sequence, TxIn, Witness};
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![1, 2]),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[[0u8; 32]]),
            }],
            output: vec![],
        };
        let s = sample_share(3);
        let h = serialize(&s.header);
        let p = NetShare::from_parts(&h, serialize(&tx), vec![], s.tag.clone()).unwrap();
        assert_eq!(p.id(), s.id());
        assert_eq!(p.coinbase_tx().unwrap().compute_txid(), tx.compute_txid());
        assert!(p.coinbase.len() < serialize(&tx).len());
        assert!(NetShare::from_parts(&h[..79], serialize(&tx), vec![], s.tag.clone()).is_err());
        assert!(NetShare::from_parts(&h, vec![1, 2, 3], vec![], s.tag).is_err());
    }

    #[test]
    fn records_round_trip() {
        let s = sample_share(5);
        let r = s.to_record(974_501);
        assert_eq!(r.share_id, s.id());
        assert_eq!(NetShare::from_record(&r), Ok(s));
    }
}
