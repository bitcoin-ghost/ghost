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
//| FILE: sv2.rs                                                                                                         |
//|======================================================================================================================|

//! A Stratum V2 client that connects like a miner and only ever listens.
//!
//! It runs the Noise handshake against the node's SV2 port and **checks the node's certificate
//! against the authority key** the node advertises (a node that cannot prove that key is refused
//! before anything else is read), sends `SetupConnection`, opens one mining channel and reads
//! `SetNewPrevHash`, `SetTarget`, `SetExtranoncePrefix`, `NewMiningJob` and
//! `NewExtendedMiningJob`. It never sends `SubmitShares*`.
//!
//! The two channel kinds expose different things:
//!
//! - an **extended** channel's job carries the coinbase itself, split around the extranonce
//!   ([`crate::sv2::ExtendedJob`]): the auditor fills the extranonce with its channel's prefix and
//!   zeros and judges the coinbase exactly as it judges an SV1 job;
//! - a **standard** channel's job carries only the merkle root ([`crate::sv2::StandardJob`]).
//!   The coinbase behind it is checked by rebuilding it ([`crate::sv2::rebuild_standard`]): see
//!   [`crate::audit_sv2_jobs`].

use std::str::FromStr;
use std::time::Duration;

use bitcoin::consensus::deserialize;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{Target, Transaction};
use stratum_apps::key_utils::Secp256k1PublicKey;
use stratum_apps::network_helpers::noise_stream::{NoiseTcpReadHalf, NoiseTcpWriteHalf};
use stratum_apps::network_helpers::{connect_with_noise, Error as NetError};
use stratum_apps::stratum_core::codec_sv2::{Error as CodecError, StandardSv2Frame};
use stratum_apps::stratum_core::common_messages_sv2::{Protocol, SetupConnection};
use stratum_apps::stratum_core::mining_sv2::{
    OpenExtendedMiningChannel, OpenStandardMiningChannel,
};
use stratum_apps::stratum_core::noise_sv2::Error as NoiseError;
use stratum_apps::stratum_core::parsers_sv2::{AnyMessage, CommonMessages, Mining};
use stratum_apps::utils::protocol_message_type::{protocol_message_type, MessageType};
use tokio::net::TcpStream;

use ghost_common::canonical_payout::{coinbase_outputs, ledger_root_of, subsidy, Table};
use ghost_common::coinbase_tags::{
    encode_node_tag, encode_payout_tag, extract_node_tag, extract_payout_tag,
    MAX_DIFFICULTY_TIER_LOG2, MIN_DIFFICULTY_TIER_LOG2,
};
use ghost_common::node_pool_constants::SLOT_CLASSES;
use ghost_common::share_commit::ShareTagPreimage;
use ghost_np_relay::relay::JobAnchor;

use crate::job::Job;

type Message = AnyMessage<'static>;
type Frame = StandardSv2Frame<Message>;

/// The hash rate the auditor's channels declare unless told otherwise: 1 TH/s, the smallest
/// miner pool_sv2's vardiff sizes for.
pub const DEFAULT_HASH_RATE: f32 = 1e12;

/// `SetupConnection` flag a header-only miner sets: send it standard jobs, not group jobs.
const REQUIRES_STANDARD_JOBS: u32 = 1;
/// Extranonce bytes the auditor asks to roll on an extended channel (it rolls none).
const MIN_EXTRANONCE_SIZE: u16 = 4;

/// Why the SV2 session failed.
#[derive(Debug, thiserror::Error)]
pub enum Sv2Error {
    /// Could not connect, or the connection broke.
    #[error("connection: {0}")]
    Io(String),
    /// No answer in time.
    #[error("timed out waiting for {0}")]
    Timeout(&'static str),
    /// The node closed the connection.
    #[error("the node closed the connection")]
    Closed,
    /// The authority key is not a valid SV2 public key.
    #[error("the SV2 authority key {0:?} is not a valid key")]
    BadKey(String),
    /// The node's Noise certificate is not signed by the authority key: it is not the server
    /// the key names, or the key it advertises is not its own.
    #[error("the node's Noise certificate is not signed by the authority key {0}")]
    WrongKey(String),
    /// The node sent something that is not Stratum V2 mining.
    #[error("protocol: {0}")]
    Protocol(String),
    /// The node refused the connection or the channel (the payout address, for one).
    #[error("refused: {0}")]
    Refused(String),
}

/// What the auditor tells the node it is, in `SetupConnection`. The node may pick an extended
/// channel's slot class from these, so passing the miner's own audits the class it is served.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sv2Device {
    /// `vendor`.
    pub vendor: String,
    /// `hardware_version`.
    pub hardware_version: String,
    /// `firmware`.
    pub firmware: String,
}

impl Sv2Device {
    /// From `vendor/hardware_version/firmware`; missing parts are empty.
    pub fn parse(s: &str) -> Sv2Device {
        let mut p = s.splitn(3, '/');
        let mut next = || p.next().unwrap_or_default().to_string();
        Sv2Device {
            vendor: next(),
            hardware_version: next(),
            firmware: next(),
        }
    }
}

/// How to connect.
#[derive(Debug, Clone)]
pub struct Sv2Config {
    /// `host:port` of the node's SV2 port.
    pub addr: String,
    /// The authority public key the node's Noise certificate must be signed by (base58check, as
    /// pool_sv2 prints it and the relay `Advert` carries it).
    pub authority_key: String,
    /// The channel's `user_identity`: the payout address (optionally `address.worker`).
    pub username: String,
    /// The device fields of `SetupConnection`.
    pub device: Sv2Device,
    /// The hash rate the channel declares, in H/s; the node derives the channel's target from it.
    pub nominal_hash_rate: f32,
    /// Deadline for the connection, the handshake and each answer.
    pub timeout: Duration,
}

/// Which channel to open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelKind {
    /// A standard channel: jobs carry the merkle root only.
    Standard,
    /// An extended channel: jobs carry the coinbase.
    Extended,
}

/// A job on a standard channel.
#[derive(Debug, Clone, PartialEq)]
pub struct StandardJob {
    /// The job id, as `std-<id>`.
    pub job_id: String,
    /// The header's `prev_hash`, internal byte order.
    pub prev_hash: [u8; 32],
    /// Header version.
    pub version: u32,
    /// Header bits.
    pub bits: u32,
    /// Header time (`min_ntime`).
    pub time: u32,
    /// The merkle root the miner hashes, internal byte order.
    pub merkle_root: [u8; 32],
    /// The channel's extranonce prefix: the whole extranonce of a standard job.
    pub extranonce_prefix: Vec<u8>,
    /// The channel's share difficulty when the job arrived.
    pub difficulty: Option<f64>,
}

/// A job on an extended channel: the coinbase, with the extranonce filled.
#[derive(Debug, Clone)]
pub struct ExtendedJob {
    /// The job, judged like an SV1 job. Its id is `ext-<id>`.
    pub job: Job,
    /// The full extranonce length in the coinbase (channel prefix plus the miner's part).
    pub extranonce_len: usize,
}

/// One job from either channel kind.
#[derive(Debug, Clone)]
pub enum Sv2Job {
    /// From a standard channel.
    Standard(StandardJob),
    /// From an extended channel.
    Extended(ExtendedJob),
}

/// A job as it arrived, before its `prev_hash` is known.
#[derive(Debug, Clone)]
enum RawJob {
    Standard {
        job_id: u32,
        version: u32,
        merkle_root: [u8; 32],
    },
    Extended {
        job_id: u32,
        version: u32,
        merkle_path: Vec<[u8; 32]>,
        prefix: Vec<u8>,
        suffix: Vec<u8>,
    },
}

impl RawJob {
    fn job_id(&self) -> u32 {
        match self {
            RawJob::Standard { job_id, .. } | RawJob::Extended { job_id, .. } => *job_id,
        }
    }
}

/// An open channel.
pub struct Sv2Session {
    reader: NoiseTcpReadHalf<Message>,
    // Kept so the connection stays open; the auditor never writes after the channel opens.
    writer: NoiseTcpWriteHalf<Message>,
    kind: ChannelKind,
    channel_id: u32,
    target: Option<[u8; 32]>,
    extranonce_prefix: Vec<u8>,
    extranonce_size: usize,
    /// `(prev_hash, nbits)` of the last `SetNewPrevHash`.
    chain: Option<([u8; 32], u32)>,
    future: Vec<RawJob>,
    pending: Vec<Sv2Job>,
}

fn net_error(e: NetError, key: &str) -> Sv2Error {
    match e {
        NetError::CodecError(CodecError::NoiseSv2Error(NoiseError::InvalidCertificate(_))) => {
            Sv2Error::WrongKey(key.to_string())
        }
        NetError::HandshakeTimeout => Sv2Error::Timeout("the Noise handshake"),
        NetError::SocketClosed => Sv2Error::Closed,
        NetError::HandshakeRemoteInvalidMessage | NetError::CodecError(_) => {
            Sv2Error::Protocol(e.to_string())
        }
        other => Sv2Error::Io(other.to_string()),
    }
}

fn bytes32(b: &[u8], what: &str) -> Result<[u8; 32], Sv2Error> {
    b.try_into()
        .map_err(|_| Sv2Error::Protocol(format!("{what} is not 32 bytes")))
}

/// The share difficulty of a channel target (little-endian, as SV2 sends it).
pub fn difficulty_of(target_le: &[u8; 32]) -> f64 {
    Target::from_le_bytes(*target_le).difficulty_float()
}

impl Sv2Session {
    /// Connect, prove the authority key, set up and open a `kind` channel.
    pub async fn connect(cfg: &Sv2Config, kind: ChannelKind) -> Result<Sv2Session, Sv2Error> {
        let key = Secp256k1PublicKey::from_str(cfg.authority_key.trim())
            .map_err(|_| Sv2Error::BadKey(cfg.authority_key.clone()))?;
        let stream = tokio::time::timeout(cfg.timeout, TcpStream::connect(&cfg.addr))
            .await
            .map_err(|_| Sv2Error::Timeout("the connection"))?
            .map_err(|e| Sv2Error::Io(e.to_string()))?;
        let _ = stream.set_nodelay(true);
        let peer = stream
            .peer_addr()
            .map_err(|e| Sv2Error::Io(e.to_string()))?;
        let noise = tokio::time::timeout(
            cfg.timeout,
            connect_with_noise::<Message>(stream, Some(key)),
        )
        .await
        .map_err(|_| Sv2Error::Timeout("the Noise handshake"))?
        .map_err(|e| net_error(e, &cfg.authority_key))?;
        let (reader, writer) = noise.into_split();
        let mut s = Sv2Session {
            reader,
            writer,
            kind,
            channel_id: 0,
            target: None,
            extranonce_prefix: Vec::new(),
            extranonce_size: 0,
            chain: None,
            future: Vec::new(),
            pending: Vec::new(),
        };
        let str0255 = |v: &str, what: &str| {
            v.to_string()
                .try_into()
                .map_err(|_| Sv2Error::Protocol(format!("{what} is over 255 bytes")))
        };
        let setup = SetupConnection {
            protocol: Protocol::MiningProtocol,
            min_version: 2,
            max_version: 2,
            flags: match kind {
                ChannelKind::Standard => REQUIRES_STANDARD_JOBS,
                ChannelKind::Extended => 0,
            },
            endpoint_host: str0255(&peer.ip().to_string(), "the host")?,
            endpoint_port: peer.port(),
            vendor: str0255(&cfg.device.vendor, "the vendor")?,
            hardware_version: str0255(&cfg.device.hardware_version, "the hardware version")?,
            firmware: str0255(&cfg.device.firmware, "the firmware")?,
            device_id: str0255("", "the device id")?,
        };
        s.send(AnyMessage::Common(setup.into())).await?;
        tokio::time::timeout(cfg.timeout, s.await_setup())
            .await
            .map_err(|_| Sv2Error::Timeout("SetupConnection.Success"))??;
        let identity = str0255(&cfg.username, "the user identity")?;
        let max_target = vec![0xFF_u8; 32]
            .try_into()
            .map_err(|_| Sv2Error::Protocol("max target".into()))?;
        let open = match kind {
            ChannelKind::Standard => Mining::OpenStandardMiningChannel(OpenStandardMiningChannel {
                request_id: 1.into(),
                user_identity: identity,
                nominal_hash_rate: cfg.nominal_hash_rate,
                max_target,
            }),
            ChannelKind::Extended => Mining::OpenExtendedMiningChannel(OpenExtendedMiningChannel {
                request_id: 1,
                user_identity: identity,
                nominal_hash_rate: cfg.nominal_hash_rate,
                max_target,
                min_extranonce_size: MIN_EXTRANONCE_SIZE,
            }),
        };
        s.send(AnyMessage::Mining(open)).await?;
        tokio::time::timeout(cfg.timeout, s.await_open())
            .await
            .map_err(|_| Sv2Error::Timeout("the channel to open"))??;
        Ok(s)
    }

    /// The channel kind.
    pub fn kind(&self) -> ChannelKind {
        self.kind
    }

    /// The channel's share difficulty, from its last target.
    pub fn difficulty(&self) -> Option<f64> {
        self.target.as_ref().map(difficulty_of)
    }

    async fn send(&mut self, m: Message) -> Result<(), Sv2Error> {
        let frame: Frame = m
            .try_into()
            .map_err(|e| Sv2Error::Protocol(format!("encoding: {e:?}")))?;
        self.writer
            .write_frame(frame.into())
            .await
            .map_err(|e| Sv2Error::Io(e.to_string()))
    }

    /// Read one frame: `Ok(None)` for anything that is neither common nor mining.
    async fn read(&mut self) -> Result<Option<Parsed>, Sv2Error> {
        let either = self.reader.read_frame().await.map_err(|e| match e {
            NetError::SocketClosed => Sv2Error::Closed,
            e => Sv2Error::Io(e.to_string()),
        })?;
        let mut frame: Frame = either
            .try_into()
            .map_err(|_| Sv2Error::Protocol("a handshake frame after the handshake".into()))?;
        let header = frame
            .get_header()
            .ok_or_else(|| Sv2Error::Protocol("a frame with no header".into()))?;
        let (ext, mt) = (header.ext_type(), header.msg_type());
        let payload = frame.payload();
        match protocol_message_type(ext, mt) {
            MessageType::Common => {
                let m: CommonMessages<'_> = (mt, payload)
                    .try_into()
                    .map_err(|e| Sv2Error::Protocol(format!("common message {mt}: {e:?}")))?;
                Ok(Some(match m {
                    CommonMessages::SetupConnectionSuccess(_) => Parsed::SetupOk,
                    CommonMessages::SetupConnectionError(e) => Parsed::Refused(format!(
                        "SetupConnection: {} (flags {:#b})",
                        e.error_code.as_utf8_or_hex(),
                        e.flags
                    )),
                    CommonMessages::Reconnect(_) => {
                        Parsed::Refused("the node asked the miner to reconnect elsewhere".into())
                    }
                    _ => Parsed::Other,
                }))
            }
            MessageType::Mining => {
                let m: Mining<'_> = (mt, payload)
                    .try_into()
                    .map_err(|e| Sv2Error::Protocol(format!("mining message {mt}: {e:?}")))?;
                Ok(Some(Parsed::Mining(Box::new(MiningMsg::from(m)?))))
            }
            _ => Ok(None),
        }
    }

    async fn await_setup(&mut self) -> Result<(), Sv2Error> {
        loop {
            match self.read().await? {
                Some(Parsed::SetupOk) => return Ok(()),
                Some(Parsed::Refused(why)) => return Err(Sv2Error::Refused(why)),
                Some(Parsed::Mining(_)) => {
                    return Err(Sv2Error::Protocol(
                        "a mining message before SetupConnection.Success".into(),
                    ))
                }
                _ => {}
            }
        }
    }

    async fn await_open(&mut self) -> Result<(), Sv2Error> {
        loop {
            match self.read().await? {
                Some(Parsed::Refused(why)) => return Err(Sv2Error::Refused(why)),
                Some(Parsed::Mining(m)) => match *m {
                    MiningMsg::Opened {
                        channel_id,
                        target,
                        extranonce_prefix,
                        extranonce_size,
                    } => {
                        self.channel_id = channel_id;
                        self.target = Some(target);
                        self.extranonce_prefix = extranonce_prefix;
                        self.extranonce_size = extranonce_size;
                        return Ok(());
                    }
                    MiningMsg::OpenError(why) => return Err(Sv2Error::Refused(why)),
                    other => self.on_mining(other)?,
                },
                _ => {}
            }
        }
    }

    fn concrete(&self, raw: RawJob, time: u32) -> Result<Sv2Job, Sv2Error> {
        let Some((prev_hash, bits)) = self.chain else {
            return Err(Sv2Error::Protocol(
                "an active job before any SetNewPrevHash".into(),
            ));
        };
        let difficulty = self.difficulty();
        Ok(match raw {
            RawJob::Standard {
                job_id,
                version,
                merkle_root,
            } => Sv2Job::Standard(StandardJob {
                job_id: format!("std-{job_id}"),
                prev_hash,
                version,
                bits,
                time,
                merkle_root,
                extranonce_prefix: self.extranonce_prefix.clone(),
                difficulty,
            }),
            RawJob::Extended {
                job_id,
                version,
                merkle_path,
                prefix,
                suffix,
            } => {
                let mut raw = prefix;
                raw.extend_from_slice(&self.extranonce_prefix);
                raw.extend(std::iter::repeat_n(0u8, self.extranonce_size));
                raw.extend_from_slice(&suffix);
                let coinbase: Transaction = deserialize(&raw)
                    .map_err(|e| Sv2Error::Protocol(format!("the coinbase does not parse: {e}")))?;
                Sv2Job::Extended(ExtendedJob {
                    job: Job {
                        job_id: format!("ext-{job_id}"),
                        prev_hash,
                        coinbase,
                        coinbase_bytes: raw.len(),
                        merkle_branch: merkle_path,
                        version,
                        bits,
                        time,
                        difficulty,
                    },
                    extranonce_len: self.extranonce_prefix.len() + self.extranonce_size,
                })
            }
        })
    }

    fn on_mining(&mut self, m: MiningMsg) -> Result<(), Sv2Error> {
        match m {
            MiningMsg::Job {
                channel_id,
                raw,
                min_ntime,
            } if channel_id == self.channel_id => match min_ntime {
                None => {
                    self.future.retain(|j| j.job_id() != raw.job_id());
                    self.future.push(raw);
                }
                Some(t) => {
                    let j = self.concrete(raw, t)?;
                    self.pending.push(j);
                }
            },
            MiningMsg::PrevHash {
                channel_id,
                job_id,
                prev_hash,
                min_ntime,
                nbits,
            } if channel_id == self.channel_id => {
                self.chain = Some((prev_hash, nbits));
                let future = std::mem::take(&mut self.future);
                if let Some(raw) = future.into_iter().find(|j| j.job_id() == job_id) {
                    let j = self.concrete(raw, min_ntime)?;
                    self.pending.push(j);
                }
            }
            MiningMsg::Target { channel_id, target } if channel_id == self.channel_id => {
                self.target = Some(target);
            }
            MiningMsg::Extranonce { channel_id, prefix } if channel_id == self.channel_id => {
                self.extranonce_prefix = prefix;
            }
            MiningMsg::Closed(why) => {
                return Err(Sv2Error::Refused(format!(
                    "the node closed the channel: {why}"
                )))
            }
            _ => {}
        }
        Ok(())
    }

    /// The next job, in the order the node activated them.
    pub async fn next_job(&mut self, timeout: Duration) -> Result<Sv2Job, Sv2Error> {
        if !self.pending.is_empty() {
            return Ok(self.pending.remove(0));
        }
        let wait = async {
            loop {
                match self.read().await? {
                    Some(Parsed::Refused(why)) => return Err(Sv2Error::Refused(why)),
                    Some(Parsed::Mining(m)) => {
                        self.on_mining(*m)?;
                        if !self.pending.is_empty() {
                            return Ok(self.pending.remove(0));
                        }
                    }
                    _ => {}
                }
            }
        };
        tokio::time::timeout(timeout, wait)
            .await
            .map_err(|_| Sv2Error::Timeout("a job"))?
    }
}

enum Parsed {
    SetupOk,
    Refused(String),
    Mining(Box<MiningMsg>),
    Other,
}

/// The mining messages the auditor reads, owned.
enum MiningMsg {
    Opened {
        channel_id: u32,
        target: [u8; 32],
        extranonce_prefix: Vec<u8>,
        extranonce_size: usize,
    },
    OpenError(String),
    Job {
        channel_id: u32,
        raw: RawJob,
        min_ntime: Option<u32>,
    },
    PrevHash {
        channel_id: u32,
        job_id: u32,
        prev_hash: [u8; 32],
        min_ntime: u32,
        nbits: u32,
    },
    Target {
        channel_id: u32,
        target: [u8; 32],
    },
    Extranonce {
        channel_id: u32,
        prefix: Vec<u8>,
    },
    Closed(String),
    Other,
}

impl MiningMsg {
    fn from(m: Mining<'_>) -> Result<MiningMsg, Sv2Error> {
        Ok(match m {
            Mining::OpenStandardMiningChannelSuccess(m) => MiningMsg::Opened {
                channel_id: m.channel_id,
                target: bytes32(m.target.inner_as_ref(), "the target")?,
                extranonce_prefix: m.extranonce_prefix.to_vec(),
                extranonce_size: 0,
            },
            Mining::OpenExtendedMiningChannelSuccess(m) => MiningMsg::Opened {
                channel_id: m.channel_id,
                target: bytes32(m.target.inner_as_ref(), "the target")?,
                extranonce_prefix: m.extranonce_prefix.to_vec(),
                extranonce_size: m.extranonce_size as usize,
            },
            Mining::OpenMiningChannelError(m) => {
                MiningMsg::OpenError(format!("channel open: {}", m.error_code.as_utf8_or_hex()))
            }
            Mining::NewMiningJob(m) => MiningMsg::Job {
                channel_id: m.channel_id,
                min_ntime: m.min_ntime.clone().into_inner(),
                raw: RawJob::Standard {
                    job_id: m.job_id,
                    version: m.version,
                    merkle_root: bytes32(m.merkle_root.inner_as_ref(), "the merkle root")?,
                },
            },
            Mining::NewExtendedMiningJob(m) => MiningMsg::Job {
                channel_id: m.channel_id,
                min_ntime: m.min_ntime.clone().into_inner(),
                raw: RawJob::Extended {
                    job_id: m.job_id,
                    version: m.version,
                    merkle_path: m
                        .merkle_path
                        .inner_as_ref()
                        .into_iter()
                        .map(|n| bytes32(n, "a merkle path entry"))
                        .collect::<Result<_, _>>()?,
                    prefix: m.coinbase_tx_prefix.to_vec(),
                    suffix: m.coinbase_tx_suffix.to_vec(),
                },
            },
            Mining::SetNewPrevHash(m) => MiningMsg::PrevHash {
                channel_id: m.channel_id,
                job_id: m.job_id,
                prev_hash: bytes32(m.prev_hash.inner_as_ref(), "the prev hash")?,
                min_ntime: m.min_ntime,
                nbits: m.nbits,
            },
            Mining::SetTarget(m) => MiningMsg::Target {
                channel_id: m.channel_id,
                target: bytes32(m.maximum_target.inner_as_ref(), "the target")?,
            },
            Mining::SetExtranoncePrefix(m) => MiningMsg::Extranonce {
                channel_id: m.channel_id,
                prefix: m.extranonce_prefix.to_vec(),
            },
            Mining::CloseChannel(m) => MiningMsg::Closed(m.reason_code.as_utf8_or_hex()),
            _ => MiningMsg::Other,
        })
    }
}

fn varint(n: usize, out: &mut Vec<u8>) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        _ => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// The tiers to try for a standard job: the one its difficulty quantises to first (pool_sv2's
/// `tier_for_target`), then every other tier a node can commit (`10..=63`; pool_sv2 clamps to
/// that range, and a share outside it is not credited anywhere).
fn tier_order(difficulty: Option<f64>) -> Vec<u8> {
    let (lo, hi) = (
        MIN_DIFFICULTY_TIER_LOG2 as u8,
        MAX_DIFFICULTY_TIER_LOG2 as u8,
    );
    let expected = difficulty.map(|d| {
        (d.max(1.0) * (1.0 + 1e-9))
            .log2()
            .floor()
            .clamp(lo as f64, hi as f64) as u8
    });
    let mut order: Vec<u8> = expected.into_iter().collect();
    order.extend((lo..=hi).filter(|t| Some(*t) != expected));
    order
}

/// Rebuild the coinbase behind a standard job, or `None` if no canonical coinbase crediting
/// `payee` hashes to its merkle root.
///
/// A standard job is only a merkle root, so the auditor cannot read its coinbase; it can only
/// guess it and check the guess. The node builds every channel's job from the same template
/// with the same layout (pool_sv2's job factory), so an extended job on that template, `ext`,
/// gives everything a standard coinbase takes from the template: version, BIP34 height and the
/// rest of the template's scriptSig, sequence, lock time, the witness commitment, the fees and
/// the finder's script, and the merkle path. What differs per channel the auditor supplies
/// itself, canonically:
///
/// - the `GHPP` slot and `GHNT` tag, for every stamp the node disclosed with its table held
///   (`tables`), every slot class and every tier from 10 to 63, with `payee` and the node's
///   `node_id`;
/// - the outputs: the canonical outputs for that stamp's table, `h` and slot class, built by
///   [`ghost_common::canonical_payout::coinbase_outputs`] as pool_sv2 builds them;
/// - the extranonce: the standard channel's prefix.
///
/// A candidate whose txid folds up `ext`'s merkle path to the job's merkle root is the coinbase
/// the miner would hash (a second preimage of sha256d is out of reach), and it is returned as a
/// [`Job`] for the ordinary checks. No candidate matching means the job's coinbase is not a
/// canonical coinbase crediting `payee` under any stamp the node discloses, or that `ext` is
/// from another template.
pub fn rebuild_standard(
    std: &StandardJob,
    ext: &ExtendedJob,
    payee: &[u8],
    node_id: &[u8; 32],
    tables: &[(JobAnchor, std::sync::Arc<Table>)],
    h: u32,
) -> Option<Job> {
    let cb = &ext.job.coinbase;
    let input = cb.input.first()?;
    let sig = input.script_sig.as_bytes();
    let n = ext.extranonce_len;
    if n == 0 || n > 75 || sig.len() <= n || sig[sig.len() - n - 1] as usize != n {
        return None;
    }
    let body = &sig[..sig.len() - n - 1];
    let old_pp = encode_payout_tag(&extract_payout_tag(body)?);
    let old_nt = encode_node_tag(&extract_node_tag(body)?);
    let pp_at = find(body, &old_pp)?;
    let nt_at = find(body, &old_nt)?;
    let en = &std.extranonce_prefix;
    if en.is_empty() || en.len() > 75 {
        return None;
    }

    let outs: Vec<(u64, Vec<u8>)> = cb
        .output
        .iter()
        .map(|o| (o.value.to_sat(), o.script_pubkey.to_bytes()))
        .collect();
    ledger_root_of(&outs)?;
    let g = outs.len() - 2;
    let template_tail = &outs[g + 1..];
    let total = outs.iter().try_fold(0u64, |a, (v, _)| a.checked_add(*v))?;
    let fees = total.checked_sub(subsidy(h))?;
    let finder: Vec<u8> = if fees > 0 {
        outs.get(g.checked_sub(1)?)?.1.clone()
    } else {
        Vec::new()
    };

    let mut head = Vec::with_capacity(41);
    head.extend_from_slice(&cb.version.0.to_le_bytes());
    head.push(1);
    head.extend_from_slice(&[0u8; 32]);
    head.extend_from_slice(&u32::MAX.to_le_bytes());
    let tiers = tier_order(std.difficulty);

    for (stamp, table) in tables {
        // The full class first: pool_sv2 serves it to every standard channel.
        for class in SLOT_CLASSES.into_iter().rev() {
            let Ok((canon, _)) =
                coinbase_outputs(h, table, class as usize, &finder, fees, &[0; 32])
            else {
                continue;
            };
            let mut outputs: Vec<(u64, Vec<u8>)> = canon[..canon.len() - 1].to_vec();
            outputs.extend_from_slice(template_tail);
            let mut tail = Vec::new();
            tail.extend_from_slice(&input.sequence.0.to_le_bytes());
            varint(outputs.len(), &mut tail);
            for (v, s) in &outputs {
                tail.extend_from_slice(&v.to_le_bytes());
                varint(s.len(), &mut tail);
                tail.extend_from_slice(s);
            }
            tail.extend_from_slice(&cb.lock_time.to_consensus_u32().to_le_bytes());
            for &tier in &tiers {
                let pre = ShareTagPreimage {
                    node_id: *node_id,
                    tier,
                    slot_class: class,
                    payee_script: payee.to_vec(),
                    parent_anchor: stamp.parent_anchor,
                    batch_root: stamp.batch_root,
                };
                let mut s = body.to_vec();
                s[pp_at..pp_at + old_pp.len()]
                    .copy_from_slice(&encode_payout_tag(&pre.parent_anchor_tag()));
                s[nt_at..nt_at + old_nt.len()].copy_from_slice(&encode_node_tag(&pre.tag()));
                s.push(en.len() as u8);
                s.extend_from_slice(en);
                let mut raw = head.clone();
                varint(s.len(), &mut raw);
                raw.extend_from_slice(&s);
                raw.extend_from_slice(&tail);
                let mut root = sha256d::Hash::hash(&raw).to_byte_array();
                for node in &ext.job.merkle_branch {
                    let mut b = [0u8; 64];
                    b[..32].copy_from_slice(&root);
                    b[32..].copy_from_slice(node);
                    root = sha256d::Hash::hash(&b).to_byte_array();
                }
                if root == std.merkle_root {
                    let coinbase: Transaction = deserialize(&raw).ok()?;
                    return Some(Job {
                        job_id: std.job_id.clone(),
                        prev_hash: std.prev_hash,
                        coinbase,
                        coinbase_bytes: raw.len(),
                        merkle_branch: ext.job.merkle_branch.clone(),
                        version: std.version,
                        bits: std.bits,
                        time: std.time,
                        difficulty: std.difficulty,
                    });
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_fields_parse_from_slashes() {
        let d = Sv2Device::parse("Braiins/S19/2024.1/extra");
        assert_eq!(
            (
                d.vendor.as_str(),
                d.hardware_version.as_str(),
                d.firmware.as_str()
            ),
            ("Braiins", "S19", "2024.1/extra")
        );
        assert_eq!(
            Sv2Device::parse("x"),
            Sv2Device {
                vendor: "x".into(),
                ..Sv2Device::default()
            }
        );
    }

    #[test]
    fn the_channel_tier_is_tried_first_then_every_committable_tier() {
        let o = tier_order(Some(2_328.0));
        assert_eq!(o[0], 11);
        assert_eq!(o.len(), 54);
        assert!(o.iter().all(|t| (10..=63).contains(t)));
        // Below the floor the floor tier is first, as pool_sv2 clamps.
        assert_eq!(tier_order(Some(3.0))[0], 10);
        assert_eq!(tier_order(None).len(), 54);
    }

    #[test]
    fn difficulty_one_is_the_diff1_target() {
        let mut t = [0u8; 32];
        t[26] = 0xFF;
        t[27] = 0xFF;
        assert!((difficulty_of(&t) - 1.0).abs() < 1e-9);
    }
}
