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
//| FILE: client.rs                                                                                                      |
//|======================================================================================================================|

//! A one-shot relay client: shake hands with one node and ask it one thing (W2.9, W2.10).
//!
//! `ghost-audit` and the public prober use it to read a node's advert (its `Hello`: protocol
//! version, genesis, tip, user agent), its job stamps ([`crate::wire::JobStamps`]), the stratum
//! ports it serves miners on ([`crate::wire::NodeAdvert`]), and the peer addresses it gossips
//! (`GetAddr`), which is how open listing discovers nodes. It is not
//! a peer: it relays nothing, claims the genesis as its tip so it is never asked for anything,
//! and closes as soon as it has its answer.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use ghost_common::anchor_chain::AnchorHash;
use ghost_common::node_pool_u256::U256;

use crate::wire::{
    FrameHead, Hello, JobStamps, Message, NodeAdvert, NotFoundKind, WireError, FRAME_HEADER_LEN,
    PROTOCOL_VERSION,
};

/// Frames read past the handshake while waiting for an answer, before giving up.
const MAX_FRAMES: usize = 64;

/// Why a one-shot request failed.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Could not connect, or the connection broke.
    #[error("connection: {0}")]
    Io(String),
    /// No answer in time.
    #[error("timed out")]
    Timeout,
    /// The node sent bytes that are not a relay message.
    #[error("wire: {0}")]
    Wire(#[from] WireError),
    /// The node's first message was not a `Hello`.
    #[error("no Hello from the node")]
    NoHello,
    /// The node speaks another protocol version.
    #[error("protocol version {theirs}, this build speaks {ours}")]
    Version {
        /// The node's version.
        theirs: u16,
        /// Ours.
        ours: u16,
    },
    /// The node is on another share chain.
    #[error("genesis {theirs} is not this share chain's")]
    Genesis {
        /// The node's genesis, hex.
        theirs: String,
    },
    /// The node does not answer `GetStamps`: it does not stamp jobs, or is too old to.
    #[error("the node does not serve job stamps")]
    NoStamps,
    /// The node does not answer `GetAdvert`: it serves no miners, or is too old to say.
    #[error("the node does not advertise stratum ports")]
    NoAdvert,
}

/// An open, handshaken connection.
pub struct Session {
    stream: TcpStream,
    /// The node's `Hello`.
    pub hello: Hello,
}

/// Read the next frame of a known type, skipping any of a type this build does not know (a
/// newer node's), as the relay itself does.
async fn read_frame(s: &mut TcpStream) -> Result<Message, ClientError> {
    loop {
        let mut h = [0u8; FRAME_HEADER_LEN];
        s.read_exact(&mut h)
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;
        match Message::read_header(&h)? {
            FrameHead::Known(t, len) => {
                let mut p = vec![0u8; len];
                s.read_exact(&mut p)
                    .await
                    .map_err(|e| ClientError::Io(e.to_string()))?;
                return Ok(Message::decode_payload(t, &p)?);
            }
            FrameHead::Unknown { len, .. } => {
                let skipped =
                    tokio::io::copy(&mut (&mut *s).take(len as u64), &mut tokio::io::sink())
                        .await
                        .map_err(|e| ClientError::Io(e.to_string()))?;
                if skipped != len as u64 {
                    return Err(ClientError::Io("connection closed mid-frame".into()));
                }
            }
        }
    }
}

impl Session {
    /// Connect to `addr` and exchange `Hello`s on `genesis`. The node's version and genesis are
    /// checked here; a mismatch is an error naming what the node said.
    pub async fn open(
        addr: SocketAddr,
        genesis: AnchorHash,
        user_agent: &str,
        timeout: Duration,
    ) -> Result<Session, ClientError> {
        tokio::time::timeout(timeout, Self::open_inner(addr, genesis, user_agent))
            .await
            .map_err(|_| ClientError::Timeout)?
    }

    async fn open_inner(
        addr: SocketAddr,
        genesis: AnchorHash,
        user_agent: &str,
    ) -> Result<Session, ClientError> {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;
        let _ = stream.set_nodelay(true);
        let ours = Hello {
            version: PROTOCOL_VERSION,
            genesis,
            nonce: rand::random(),
            listen_port: 0,
            tip: genesis,
            tip_work: U256::ZERO,
            user_agent: user_agent
                .chars()
                .take(crate::wire::MAX_USER_AGENT)
                .collect(),
        };
        stream
            .write_all(&Message::Hello(ours).encode())
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;
        let hello = match read_frame(&mut stream).await? {
            Message::Hello(h) => h,
            _ => return Err(ClientError::NoHello),
        };
        if hello.version != PROTOCOL_VERSION {
            return Err(ClientError::Version {
                theirs: hello.version,
                ours: PROTOCOL_VERSION,
            });
        }
        if hello.genesis != genesis {
            return Err(ClientError::Genesis {
                theirs: hex::encode(hello.genesis),
            });
        }
        Ok(Session { stream, hello })
    }

    /// Ask for the node's job stamps.
    pub async fn stamps(&mut self, timeout: Duration) -> Result<JobStamps, ClientError> {
        tokio::time::timeout(timeout, self.stamps_inner())
            .await
            .map_err(|_| ClientError::Timeout)?
    }

    async fn stamps_inner(&mut self) -> Result<JobStamps, ClientError> {
        self.stream
            .write_all(&Message::GetStamps.encode())
            .await
            .map_err(|e| ClientError::Io(e.to_string()))?;
        for _ in 0..MAX_FRAMES {
            match read_frame(&mut self.stream).await? {
                Message::Stamps(s) => return Ok(s),
                Message::NotFound(NotFoundKind::Stamps, _) => return Err(ClientError::NoStamps),
                _ => {}
            }
        }
        Err(ClientError::NoStamps)
    }
}

impl Session {
    /// Ask for the node's mining advert: the stratum ports it serves miners on.
    pub async fn advert(&mut self, timeout: Duration) -> Result<NodeAdvert, ClientError> {
        tokio::time::timeout(timeout, self.advert_inner())
            .await
            .map_err(|_| ClientError::Timeout)?
    }

    async fn advert_inner(&mut self) -> Result<NodeAdvert, ClientError> {
        self.send(&Message::GetAdvert).await?;
        for _ in 0..MAX_FRAMES {
            match read_frame(&mut self.stream).await? {
                Message::Advert(a) => return Ok(a),
                Message::NotFound(NotFoundKind::Advert, _) => return Err(ClientError::NoAdvert),
                _ => {}
            }
        }
        Err(ClientError::NoAdvert)
    }

    /// Ask for the peer addresses the node gossips (at most [`crate::wire::MAX_ADDRS`], as the
    /// wire caps them), as sent: unparsed and unchecked. An empty list if it sends none in time.
    pub async fn addrs(&mut self, timeout: Duration) -> Result<Vec<String>, ClientError> {
        match tokio::time::timeout(timeout, self.addrs_inner()).await {
            Ok(r) => r,
            Err(_) => Err(ClientError::Timeout),
        }
    }

    async fn addrs_inner(&mut self) -> Result<Vec<String>, ClientError> {
        self.send(&Message::GetAddr).await?;
        for _ in 0..MAX_FRAMES {
            if let Message::Addr(v) = read_frame(&mut self.stream).await? {
                return Ok(v);
            }
        }
        Ok(Vec::new())
    }

    async fn send(&mut self, m: &Message) -> Result<(), ClientError> {
        self.stream
            .write_all(&m.encode())
            .await
            .map_err(|e| ClientError::Io(e.to_string()))
    }
}

/// Connect, shake hands, and read the node's job stamps.
pub async fn fetch_stamps(
    addr: SocketAddr,
    genesis: AnchorHash,
    user_agent: &str,
    timeout: Duration,
) -> Result<(Hello, JobStamps), ClientError> {
    let mut s = Session::open(addr, genesis, user_agent, timeout).await?;
    let stamps = s.stamps(timeout).await?;
    Ok((s.hello, stamps))
}
