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
//| FILE: net.rs                                                                                                         |
//|======================================================================================================================|

//! The TCP transport: connections, handshake, discovery, limits, and the task that drives the
//! relay core.
//!
//! One task owns the [`Relay`]. Each connection has a reader task that decodes frames (refusing
//! an over-cap frame from its header, before reading the payload) and a writer task fed by a
//! bounded queue; a peer that cannot keep up with its queue is dropped. Both sides send `Hello`
//! first; a peer on another genesis or protocol version is closed, and a connection to self is
//! closed and its address forgotten.
//!
//! Peers come from configuration and from `Addr` gossip: any reachable node that completes the
//! handshake is a peer. The transport is plain TCP: everything carried is public and checked on
//! arrival, so nothing relies on the channel being private or authenticated.
//!
//! The task also answers `GetStamps` with the job stamps it published to pool_sv2 (W2.9), when
//! [`crate::net::NetConfig::node_id`] is set, and `GetAdvert` with the stratum ports in
//! [`crate::net::NetConfig::advert`] (W2.10), so open listing can find and probe the node.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use ghost_common::anchor_chain::AnchorHash;
use ghost_common::canonical_payout::Table;

use crate::headers::HeaderOracle;
use crate::peers::{penalty, AddrBook, AddrSource, PeerState};
use crate::relay::{JobAnchor, Out, PeerId, Relay, RelayStatus};
use crate::settlement::{BlockSource, Settlement, SettlementStatus};
use crate::wire::{
    FrameHead, Hello, JobStamps, Message, NetShare, NodeAdvert, NotFoundKind, WireError,
    FRAME_HEADER_LEN, MAX_ADDRS, MAX_STAMPS, PROTOCOL_VERSION,
};

/// Transport settings.
#[derive(Debug, Clone)]
pub struct NetConfig {
    /// Where to accept connections. `None`: outbound only.
    pub listen: Option<SocketAddr>,
    /// The port to advertise, when it differs from the listen port (NAT).
    pub advertise_port: Option<u16>,
    /// Peers to dial at start and keep dialling.
    pub peers: Vec<SocketAddr>,
    /// Outbound connections to keep.
    pub max_outbound: usize,
    /// Inbound connections accepted.
    pub max_inbound: usize,
    /// Inbound connections accepted from one IP.
    pub max_inbound_per_ip: usize,
    /// Sent in `Hello`.
    pub user_agent: String,
    /// Core timer period, milliseconds.
    pub tick_ms: u64,
    /// How often to top up outbound connections, seconds.
    pub dial_secs: u64,
    /// The node id pool_sv2 stamps its jobs with. Set, the node answers `GetStamps` with it and
    /// its recent job stamps so a miner's `ghost-audit` can open its job's tag; `None` (a relay
    /// with no pool, such as the auditor's own) answers `NotFound`.
    pub node_id: Option<[u8; 32]>,
    /// The stratum ports this node serves miners on. Set, the node answers `GetAdvert` with
    /// them (W2.10, open listing); `None` answers `NotFound`.
    pub advert: Option<NodeAdvert>,
}

impl Default for NetConfig {
    fn default() -> Self {
        NetConfig {
            listen: None,
            advertise_port: None,
            peers: Vec::new(),
            max_outbound: 8,
            max_inbound: 64,
            max_inbound_per_ip: 8,
            user_agent: format!("ghost-np-relay/{}", env!("CARGO_PKG_VERSION")),
            tick_ms: 1_000,
            dial_secs: 5,
            node_id: None,
            advert: None,
        }
    }
}

/// Where new job anchors go: pool_sv2's `AnchorDriver::publish`.
pub type Publisher = Arc<dyn Fn(JobAnchor) + Send + Sync>;

/// pool_sv2 asking for the table a job must pay: [`Relay::block_table`] after settlement has
/// caught up with the Bitcoin tip; or, with `prev`, [`Relay::block_table_on`] that Bitcoin block
/// (`ghost-audit`, judging a job on whatever `prev_hash` it names).
pub struct TableRequest {
    /// The anchor the job builds on.
    pub parent: AnchorHash,
    /// The job's height.
    pub height: u32,
    /// The job's `prev_hash`, internal byte order. `None`: this node's best-chain block at
    /// `height - 1`. Given, the answer is `None` unless it is an archived block at `height - 1`.
    pub prev: Option<[u8; 32]>,
    /// Where the answer goes; `None` if the anchor is not held.
    pub reply: tokio::sync::oneshot::Sender<Option<Arc<Table>>>,
}

/// Settlement and where it reads the Bitcoin best chain from.
pub type SettlementParts = (Settlement, Arc<dyn BlockSource>);

/// A running relay.
pub struct RelayHandle {
    /// Local shares from pool_sv2.
    pub local: mpsc::Sender<NetShare>,
    /// Table requests from pool_sv2's coinbase builder.
    pub tables: mpsc::Sender<TableRequest>,
    /// The core's status after every event.
    pub status: watch::Receiver<RelayStatus>,
    /// Settlement's progress after every sync (the default, all unknown, without settlement).
    pub settlement: watch::Receiver<SettlementStatus>,
    /// The bound listen address, if listening.
    pub listen_addr: Option<SocketAddr>,
    /// The driving task.
    pub task: JoinHandle<()>,
}

/// Frames queued per peer before it counts as too slow.
const PEER_QUEUE: usize = 1_024;
/// Handshake deadline.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Dial deadline.
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
/// Local shares queued from pool_sv2.
const LOCAL_QUEUE: usize = 4_096;
/// Table requests queued from pool_sv2.
const TABLE_QUEUE: usize = 256;
/// Most blocks read back from the local Bitcoin node for one wanted hash.
const MAX_LOCAL_WALK: usize = 2_016;

enum Event {
    Inbound(TcpStream, SocketAddr),
    Dialed(SocketAddr, std::io::Result<TcpStream>),
    Ready {
        conn: u64,
        hello: Hello,
        tx: mpsc::Sender<Arc<Vec<u8>>>,
    },
    Msg(u64, Message),
    Bad(u64, WireError),
    Closed(u64),
}

struct Conn {
    addr: SocketAddr,
    outbound: bool,
    tx: Option<mpsc::Sender<Arc<Vec<u8>>>>,
    state: PeerState,
    nonce: u64,
    task: JoinHandle<()>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Start the relay: bind, dial the configured peers, and drive `relay` until the task is aborted.
pub async fn spawn(
    relay: Relay,
    cfg: NetConfig,
    oracle: Arc<dyn HeaderOracle>,
    publish: Publisher,
) -> std::io::Result<RelayHandle> {
    spawn_with_settlement(relay, cfg, oracle, publish, None).await
}

/// [`spawn`], with settlement following the Bitcoin best chain in the same task, so every table
/// the relay checks or serves subtracts what settled blocks paid.
pub async fn spawn_with_settlement(
    relay: Relay,
    cfg: NetConfig,
    oracle: Arc<dyn HeaderOracle>,
    publish: Publisher,
    settlement: Option<SettlementParts>,
) -> std::io::Result<RelayHandle> {
    let listener = match cfg.listen {
        Some(a) => Some(TcpListener::bind(a).await?),
        None => None,
    };
    let listen_addr = listener.as_ref().map(|l| l.local_addr()).transpose()?;
    let (ev_tx, ev_rx) = mpsc::channel(4 * PEER_QUEUE);
    if let Some(l) = listener {
        let tx = ev_tx.clone();
        tokio::spawn(async move {
            loop {
                match l.accept().await {
                    Ok((s, a)) => {
                        if tx.send(Event::Inbound(s, a)).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        warn!("NP_RELAY: accept failed: {e}");
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        });
    }
    let (local_tx, local_rx) = mpsc::channel(LOCAL_QUEUE);
    let (tables_tx, tables_rx) = mpsc::channel(TABLE_QUEUE);
    let (status_tx, status_rx) = watch::channel(relay.status());
    let (settlement_tx, settlement_rx) = watch::channel(SettlementStatus::default());
    let mut book = AddrBook::default();
    for p in &cfg.peers {
        book.add(*p, AddrSource::Configured);
    }
    let node = Node {
        relay,
        listen_port: cfg.advertise_port.or(listen_addr.map(|a| a.port())),
        cfg,
        oracle,
        publish,
        book,
        conns: HashMap::new(),
        dialing: HashSet::new(),
        self_addrs: HashSet::new(),
        next_conn: 1,
        nonce: rand::random(),
        ev_tx,
        status_tx,
        settlement_tx,
        settlement,
        stamps: VecDeque::new(),
    };
    let task = tokio::spawn(node.run(ev_rx, local_rx, tables_rx));
    Ok(RelayHandle {
        local: local_tx,
        tables: tables_tx,
        status: status_rx,
        settlement: settlement_rx,
        listen_addr,
        task,
    })
}

struct Node {
    relay: Relay,
    cfg: NetConfig,
    listen_port: Option<u16>,
    oracle: Arc<dyn HeaderOracle>,
    publish: Publisher,
    book: AddrBook,
    conns: HashMap<u64, Conn>,
    dialing: HashSet<SocketAddr>,
    self_addrs: HashSet<SocketAddr>,
    next_conn: u64,
    nonce: u64,
    ev_tx: mpsc::Sender<Event>,
    status_tx: watch::Sender<RelayStatus>,
    settlement_tx: watch::Sender<SettlementStatus>,
    settlement: Option<SettlementParts>,
    /// Job stamps published to pool_sv2, newest first, at most [`MAX_STAMPS`].
    stamps: VecDeque<JobAnchor>,
}

impl Node {
    async fn run(
        mut self,
        mut ev_rx: mpsc::Receiver<Event>,
        mut local_rx: mpsc::Receiver<NetShare>,
        mut tables_rx: mpsc::Receiver<TableRequest>,
    ) {
        let mut tick = tokio::time::interval(Duration::from_millis(self.cfg.tick_ms.max(10)));
        let mut ticks: u64 = 0;
        self.flush_out();
        self.dial();
        loop {
            tokio::select! {
                Some(ev) = ev_rx.recv() => self.on_event(ev).await,
                Some(s) = local_rx.recv() => {
                    self.oracle.prefetch(&[s.prev_hash()]).await;
                    let r = self.relay.on_local_share(s, self.oracle.lookup(), now_secs());
                    if let Err(e) = r {
                        debug!("NP_RELAY: local share not relayed: {e}");
                    }
                    self.flush_out();
                }
                Some(req) = tables_rx.recv() => {
                    self.settle().await;
                    let t = match req.prev {
                        None => self.relay.block_table(&req.parent, req.height),
                        Some(prev) => {
                            let at = self.relay.archive().get(&prev).map(|b| b.height);
                            match at {
                                Some(h) if h.checked_add(1) == Some(req.height) => {
                                    self.relay.block_table_on(&req.parent, req.height, &prev)
                                }
                                Some(_) => None,
                                None => {
                                    self.fetch_blocks(vec![prev]).await;
                                    None
                                }
                            }
                        }
                    };
                    let _ = req.reply.send(t);
                }
                _ = tick.tick() => {
                    ticks += 1;
                    let per_sec = (1_000 / self.cfg.tick_ms.max(10)).max(1);
                    if ticks % (5 * per_sec) == 1 {
                        if let Some(h) = self.oracle.tip_height().await {
                            self.relay.set_btc_tip(h);
                        }
                        self.settle().await;
                    }
                    self.reconcile();
                    let need = self.relay.take_needed_headers();
                    if !need.is_empty() {
                        self.oracle.prefetch(&need).await;
                        self.fetch_blocks(need).await;
                    }
                    let outs = self.relay.tick(self.oracle.lookup(), now_secs());
                    self.dispatch(outs);
                    if ticks.is_multiple_of(self.cfg.dial_secs.max(1) * per_sec) {
                        self.dial();
                    }
                    if ticks.is_multiple_of(60 * per_sec) {
                        let s = self.relay.status();
                        info!(
                            best = %hex::encode(s.best),
                            height = s.height,
                            t_net = s.t_net,
                            peers = self.conns.values().filter(|c| c.tx.is_some()).count(),
                            loose = s.loose,
                            unseen = s.unseen,
                            "NP_RELAY: status"
                        );
                    }
                }
            }
            self.status_tx.send_replace(self.relay.status());
        }
    }

    /// Settlement catches up with the Bitcoin best chain. Run on every table request, which
    /// pool_sv2 sends the moment a template on a new Bitcoin tip arrives, so the new tip is
    /// settled (and the relay's view of the tip moved) before that tip's jobs are built; the
    /// 5 s tick is only the backstop.
    async fn settle(&mut self) {
        if let Some((s, src)) = self.settlement.as_mut() {
            if let Err(e) = s.sync(&mut self.relay, src.as_ref()).await {
                warn!("NP_SETTLE: sync failed: {e}");
            }
            let st = s.status();
            if let Some(tip) = st.bitcoin_tip {
                self.relay.set_btc_tip(tip);
            }
            self.settlement_tx.send_replace(st);
        }
    }

    /// Bitcoin blocks share checks wanted: from the local Bitcoin node first (walking back to an
    /// archived ancestor), then from peers' archives.
    async fn fetch_blocks(&mut self, need: Vec<[u8; 32]>) {
        let mut missing = Vec::new();
        for h in need {
            let mut cur = h;
            for _ in 0..MAX_LOCAL_WALK {
                if self.relay.archive().has_full(&cur) {
                    break;
                }
                let local = match self.settlement.as_ref() {
                    Some((_, src)) => src.block(&cur).await,
                    None => None,
                };
                let Some(b) = local else {
                    missing.push(cur);
                    break;
                };
                let prev = b.prev();
                if let Err(e) = self.relay.archive().insert_local(b, now_secs() as i64) {
                    warn!("NP_RELAY: archiving a local block failed: {e}");
                    break;
                }
                cur = prev;
            }
        }
        if !missing.is_empty() {
            self.relay.request_btc_blocks(&missing);
            self.flush_out();
        }
    }

    /// Provisional blocks whose anchor arrived are checked.
    fn reconcile(&mut self) {
        if let Some((s, _)) = self.settlement.as_mut() {
            if s.pending() > 0 {
                if let Err(e) = s.reconcile(&mut self.relay) {
                    warn!("NP_SETTLE: reconcile failed: {e}");
                }
                self.settlement_tx.send_replace(s.status());
            }
        }
    }

    fn flush_out(&mut self) {
        let outs = self.relay.take_out();
        self.dispatch(outs);
    }

    async fn on_event(&mut self, ev: Event) {
        match ev {
            Event::Inbound(s, a) => {
                let inbound = self.conns.values().filter(|c| !c.outbound).count();
                let from_ip = self
                    .conns
                    .values()
                    .filter(|c| !c.outbound && c.addr.ip() == a.ip())
                    .count();
                if inbound >= self.cfg.max_inbound
                    || from_ip >= self.cfg.max_inbound_per_ip
                    || self.book.is_banned(&a.ip(), now_secs())
                {
                    return;
                }
                self.start_conn(s, a, false);
            }
            Event::Dialed(a, r) => {
                self.dialing.remove(&a);
                match r {
                    Ok(s) => self.start_conn(s, a, true),
                    Err(e) => {
                        debug!("NP_RELAY: dial {a} failed: {e}");
                        self.book.failed(&a, now_secs());
                    }
                }
            }
            Event::Ready { conn, hello, tx } => self.on_ready(conn, hello, tx),
            Event::Msg(conn, m) => self.on_msg(conn, m).await,
            Event::Bad(conn, e) => {
                self.penalize(conn, penalty::MALFORMED, &format!("malformed frame: {e}"));
                self.close(conn);
            }
            Event::Closed(conn) => self.close(conn),
        }
    }

    fn our_hello(&self) -> Hello {
        let s = self.relay.status();
        Hello {
            version: PROTOCOL_VERSION,
            genesis: self.relay.chain().genesis(),
            nonce: self.nonce,
            listen_port: self.listen_port.unwrap_or(0),
            tip: s.best,
            tip_work: s.work,
            user_agent: self.cfg.user_agent.clone(),
        }
    }

    fn start_conn(&mut self, s: TcpStream, addr: SocketAddr, outbound: bool) {
        let conn = self.next_conn;
        self.next_conn += 1;
        let hello = self.our_hello();
        let ev = self.ev_tx.clone();
        let task = tokio::spawn(conn_task(conn, s, hello, ev));
        self.conns.insert(
            conn,
            Conn {
                addr,
                outbound,
                tx: None,
                state: PeerState::default(),
                nonce: 0,
                task,
            },
        );
    }

    fn on_ready(&mut self, conn: u64, hello: Hello, tx: mpsc::Sender<Arc<Vec<u8>>>) {
        let genesis = self.relay.chain().genesis();
        let dup = self
            .conns
            .iter()
            .any(|(id, c)| *id != conn && c.tx.is_some() && c.nonce == hello.nonce);
        let Some(c) = self.conns.get_mut(&conn) else {
            return;
        };
        if hello.nonce == self.nonce {
            if c.outbound {
                self.self_addrs.insert(c.addr);
            }
            self.close(conn);
            return;
        }
        if hello.version != PROTOCOL_VERSION || hello.genesis != genesis || dup {
            debug!(
                peer = %c.addr,
                "NP_RELAY: closing: version {} genesis match {} duplicate {dup}",
                hello.version,
                hello.genesis == genesis
            );
            self.close(conn);
            return;
        }
        c.tx = Some(tx);
        c.nonce = hello.nonce;
        let (addr, outbound) = (c.addr, c.outbound);
        if outbound {
            self.book.succeeded(&addr);
        }
        if hello.listen_port != 0 {
            self.book.add(
                SocketAddr::new(addr.ip(), hello.listen_port),
                AddrSource::Learned,
            );
        }
        info!(peer = %addr, outbound, agent = %hello.user_agent, "NP_RELAY: peer connected");
        self.send(conn, &Message::GetAddr);
        let outs = self.relay.peer_connected(conn);
        self.dispatch(outs);
        let tip = Message::Tip {
            hash: hello.tip,
            work: hello.tip_work,
            height: 0,
        };
        let outs = self
            .relay
            .on_message(conn, tip, self.oracle.lookup(), now_secs());
        self.dispatch(outs);
    }

    async fn on_msg(&mut self, conn: u64, m: Message) {
        let Some(c) = self.conns.get_mut(&conn) else {
            return;
        };
        if c.tx.is_none() || !c.state.admit(m.msg_type(), now_ms()) {
            return;
        }
        match m {
            Message::Hello(_) => {}
            Message::GetAddr => {
                let addrs: Vec<String> = self
                    .book
                    .sample(MAX_ADDRS)
                    .into_iter()
                    .map(|a| a.to_string())
                    .collect();
                self.send(conn, &Message::Addr(addrs));
            }
            Message::Addr(v) => {
                for a in v {
                    if let Ok(a) = a.parse::<SocketAddr>() {
                        self.book.add(a, AddrSource::Learned);
                    }
                }
            }
            Message::GetStamps => {
                let reply = match self.cfg.node_id {
                    Some(node_id) if !self.stamps.is_empty() => Message::Stamps(JobStamps {
                        node_id,
                        recent: self.stamps.iter().copied().collect(),
                    }),
                    _ => Message::NotFound(NotFoundKind::Stamps, [0; 32]),
                };
                self.send(conn, &reply);
            }
            Message::Stamps(_) => {}
            Message::GetAdvert => {
                let reply = match &self.cfg.advert {
                    Some(a) if a.sv1_port != 0 || a.sv2_port != 0 => Message::Advert(a.clone()),
                    _ => Message::NotFound(NotFoundKind::Advert, [0; 32]),
                };
                self.send(conn, &reply);
            }
            Message::Advert(_) => {}
            m => {
                let prevs: Vec<[u8; 32]> = match &m {
                    Message::Share(s) => vec![s.prev_hash()],
                    Message::Anchor(a) => vec![a.share.prev_hash()],
                    Message::Shares(v) => v.iter().map(|s| s.prev_hash()).collect(),
                    Message::Headers(v) => v.iter().map(|a| a.share.prev_hash()).collect(),
                    _ => vec![],
                };
                if !prevs.is_empty() {
                    self.oracle.prefetch(&prevs).await;
                }
                let outs = self
                    .relay
                    .on_message(conn, m, self.oracle.lookup(), now_secs());
                self.dispatch(outs);
            }
        }
    }

    fn dispatch(&mut self, outs: Vec<Out>) {
        for o in outs {
            match o {
                Out::Send(p, m) => self.send(p, &m),
                Out::Broadcast { msg, except } => {
                    let f = Arc::new(msg.encode());
                    let ids: Vec<u64> = self
                        .conns
                        .iter()
                        .filter(|(id, c)| Some(**id) != except && c.tx.is_some())
                        .map(|(id, _)| *id)
                        .collect();
                    for id in ids {
                        self.send_frame(id, f.clone());
                    }
                }
                Out::Penalize {
                    peer,
                    score,
                    reason,
                } => self.penalize(peer, score, &reason),
                Out::Publish(job) => {
                    self.stamps.retain(|j| *j != job);
                    self.stamps.push_front(job);
                    self.stamps.truncate(MAX_STAMPS);
                    (self.publish)(job)
                }
            }
        }
    }

    fn send(&mut self, conn: PeerId, m: &Message) {
        #[cfg(feature = "fault-injection")]
        let m = &crate::fault::tamper(m.clone());
        self.send_frame(conn, Arc::new(m.encode()));
    }

    fn send_frame(&mut self, conn: PeerId, f: Arc<Vec<u8>>) {
        let full = match self.conns.get(&conn).and_then(|c| c.tx.as_ref()) {
            Some(tx) => tx.try_send(f).is_err(),
            None => return,
        };
        if full {
            warn!(conn, "NP_RELAY: peer too slow; closing");
            self.close(conn);
        }
    }

    fn penalize(&mut self, conn: PeerId, score: u32, reason: &str) {
        let Some(c) = self.conns.get_mut(&conn) else {
            return;
        };
        if c.state.penalize(score) {
            let ip: IpAddr = c.addr.ip();
            warn!(peer = %c.addr, "NP_RELAY: banned: {reason}");
            self.book.ban(ip, now_secs());
            self.close(conn);
        }
    }

    fn close(&mut self, conn: u64) {
        if let Some(c) = self.conns.remove(&conn) {
            c.task.abort();
            if c.tx.is_some() {
                self.relay.peer_disconnected(conn);
                info!(peer = %c.addr, "NP_RELAY: peer disconnected");
            }
        }
    }

    fn dial(&mut self) {
        let now = now_secs();
        let outbound = self.conns.values().filter(|c| c.outbound).count() + self.dialing.len();
        if outbound >= self.cfg.max_outbound {
            return;
        }
        let connected: HashSet<SocketAddr> = self.conns.values().map(|c| c.addr).collect();
        let own_port = self.listen_port;
        let cands: Vec<SocketAddr> = self
            .book
            .candidates(now)
            .into_iter()
            .filter(|a| !connected.contains(a) && !self.dialing.contains(a))
            .filter(|a| !self.self_addrs.contains(a))
            .filter(|a| !(a.ip().is_loopback() && Some(a.port()) == own_port))
            .take(self.cfg.max_outbound - outbound)
            .collect();
        // Test builds: a lying relay dials from its own listen address, so the peers it lies to
        // can tell it apart by IP on a one-host test network (fault.rs).
        #[cfg(feature = "fault-injection")]
        let bind = self
            .cfg
            .listen
            .map(|l| l.ip())
            .filter(|ip| !ip.is_unspecified());
        for a in cands {
            self.dialing.insert(a);
            let tx = self.ev_tx.clone();
            tokio::spawn(async move {
                #[cfg(feature = "fault-injection")]
                let connect = crate::fault::connect_from(bind, a);
                #[cfg(not(feature = "fault-injection"))]
                let connect = TcpStream::connect(a);
                let r = match tokio::time::timeout(DIAL_TIMEOUT, connect).await {
                    Ok(r) => r,
                    Err(_) => Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "dial timed out",
                    )),
                };
                let _ = tx.send(Event::Dialed(a, r)).await;
            });
        }
    }
}

enum ReadErr {
    Eof,
    Io,
    Wire(WireError),
}

/// Read the next frame of a known type. A frame of a type this build does not know (a newer
/// peer's) is skipped unread, logged at debug and never scored; see [`Message::read_header`].
async fn read_frame(r: &mut OwnedReadHalf) -> Result<Message, ReadErr> {
    loop {
        let mut h = [0u8; FRAME_HEADER_LEN];
        if let Err(e) = r.read_exact(&mut h).await {
            return Err(if e.kind() == std::io::ErrorKind::UnexpectedEof {
                ReadErr::Eof
            } else {
                ReadErr::Io
            });
        }
        match Message::read_header(&h).map_err(ReadErr::Wire)? {
            FrameHead::Known(t, len) => {
                let mut p = vec![0u8; len];
                r.read_exact(&mut p).await.map_err(|_| ReadErr::Io)?;
                return Message::decode_payload(t, &p).map_err(ReadErr::Wire);
            }
            FrameHead::Unknown { code, len } => {
                let skipped =
                    tokio::io::copy(&mut (&mut *r).take(len as u64), &mut tokio::io::sink())
                        .await
                        .map_err(|_| ReadErr::Io)?;
                if skipped != len as u64 {
                    return Err(ReadErr::Eof);
                }
                debug!("NP_RELAY: skipped a frame of unknown type {code} ({len} bytes)");
            }
        }
    }
}

async fn conn_task(conn: u64, s: TcpStream, hello: Hello, ev: mpsc::Sender<Event>) {
    let _ = s.set_nodelay(true);
    let (mut r, mut w) = s.into_split();
    if w.write_all(&Message::Hello(hello).encode()).await.is_err() {
        let _ = ev.send(Event::Closed(conn)).await;
        return;
    }
    let theirs = match tokio::time::timeout(HELLO_TIMEOUT, read_frame(&mut r)).await {
        Ok(Ok(Message::Hello(h))) => h,
        Ok(Err(ReadErr::Wire(e))) => {
            let _ = ev.send(Event::Bad(conn, e)).await;
            return;
        }
        _ => {
            let _ = ev.send(Event::Closed(conn)).await;
            return;
        }
    };
    let (tx, mut rx) = mpsc::channel::<Arc<Vec<u8>>>(PEER_QUEUE);
    let writer = tokio::spawn(async move {
        while let Some(f) = rx.recv().await {
            if w.write_all(&f).await.is_err() {
                return;
            }
        }
    });
    if ev
        .send(Event::Ready {
            conn,
            hello: theirs,
            tx,
        })
        .await
        .is_err()
    {
        writer.abort();
        return;
    }
    loop {
        match read_frame(&mut r).await {
            Ok(m) => {
                if ev.send(Event::Msg(conn, m)).await.is_err() {
                    break;
                }
            }
            Err(ReadErr::Wire(e)) => {
                let _ = ev.send(Event::Bad(conn, e)).await;
                break;
            }
            Err(ReadErr::Eof) | Err(ReadErr::Io) => {
                let _ = ev.send(Event::Closed(conn)).await;
                break;
            }
        }
    }
    // Let queued frames drain; the writer ends when the node drops this peer's sender.
    let _ = writer.await;
}
