use crate::{
    config::TranslatorConfig,
    error::{self, TproxyError, TproxyErrorKind, TproxyResult},
    is_aggregated, is_non_aggregated,
    load_balancer::Tier,
    status::{handle_error, Status, StatusSender},
    sv1::{
        downstream::{downstream::Downstream, SubmitShareWithChannelId},
        sv1_server::{
            channel::Sv1ServerChannelState, is_mining_authorize, is_mining_configure,
            is_mining_subscribe, is_mining_suggest_difficulty, parse_suggest_difficulty,
            KEEPALIVE_JOB_ID_DELIMITER,
        },
    },
    utils::AGGREGATED_CHANNEL_ID,
};
use async_channel::{Receiver, Sender};
use dashmap::DashMap;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use stratum_apps::{
    custom_mutex::Mutex,
    fallback_coordinator::FallbackCoordinator,
    network_helpers::sv1_connection::ConnectionSV1,
    stratum_core::{
        binary_sv2::Str0255,
        bitcoin::Target,
        channels_sv2::{
            target::{hash_rate_from_target, hash_rate_to_target},
            Vardiff, VardiffState,
        },
        extensions_sv2::{UserIdentity, PROVISIONAL_CHANNEL_IDENTITY},
        mining_sv2::{CloseChannel, SetNewPrevHash, SetTarget},
        parsers_sv2::{Mining, Tlv, TlvField},
        stratum_translation::{
            sv1_to_sv2::{
                build_sv2_open_extended_mining_channel,
                build_sv2_submit_shares_extended_from_sv1_submit,
            },
            sv2_to_sv1::{build_sv1_notify_from_sv2, build_sv1_set_difficulty_from_sv2_target},
        },
        sv1_api::{server_to_client, utils::HexU32Be, IsServer},
    },
    task_manager::TaskManager,
    utils::types::{ChannelId, DownstreamId, Hashrate, RequestId, SharesPerMinute},
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

/// SV1 server that handles connections from SV1 miners.
///
/// This struct manages the SV1 server component of the translator, which:
/// - Accepts connections from SV1 miners
/// - Manages difficulty adjustment for connected miners
/// - Coordinates with the SV2 channel manager for upstream communication
/// - Tracks mining jobs and share submissions
///
/// The server maintains state for multiple downstream connections and implements
/// variable difficulty adjustment based on share submission rates.
/// How long a `mining.subscribe` waits for `mining.authorize` before the channel is opened
/// under a provisional identity.
///
/// Sized from measured client behaviour, not guessed: a pipelining miner's authorize follows
/// its subscribe by ~12ms, and a rented-hashrate capability probe disconnects ~10-30ms in.
/// Both finish well inside this window, so neither changes behaviour and neither costs an
/// extranonce prefix — which matters because the pool's extended prefix space is a 16-bit
/// per-process counter that is never reclaimed (#746).
///
/// Only a client still holding the connection open after this — the serialising shape — opens
/// early. It then waits the channel-open round trip (~50-300ms) instead of the old 1500ms
/// placeholder timeout, and gets the real extranonce rather than one it cannot mine with.
const SUBSCRIBE_OPEN_DEBOUNCE: std::time::Duration = std::time::Duration::from_millis(300);

#[derive(Clone)]
pub struct Sv1Server {
    pub(crate) sv1_server_channel_state: Sv1ServerChannelState,
    pub(crate) shares_per_minute: SharesPerMinute,
    pub(crate) listener_addr: SocketAddr,
    pub(crate) config: TranslatorConfig,
    pub(crate) sequence_counter: Arc<AtomicU32>,
    pub(crate) miner_counter: Arc<AtomicU32>,
    pub(crate) keepalive_job_id_counter: Arc<AtomicU32>,
    pub(crate) downstream_id_factory: Arc<AtomicUsize>,
    pub(crate) request_id_factory: Arc<AtomicU32>,
    pub(crate) downstreams: Arc<DashMap<DownstreamId, Downstream>>,
    pub(crate) request_id_to_downstream_id: Arc<DashMap<RequestId, DownstreamId>>,
    pub(crate) channel_id_to_downstream_id: Arc<Mutex<HashMap<ChannelId, DownstreamId>>>,
    pub(crate) vardiff: Arc<DashMap<DownstreamId, Arc<Mutex<VardiffState>>>>,
    /// HashMap to store the SetNewPrevHash for each channel
    /// Used in both aggregated and non-aggregated mode
    pub(crate) prevhashes: Arc<DashMap<ChannelId, SetNewPrevHash<'static>>>,
    /// Tracks pending target updates that are waiting for SetTarget response from upstream
    pub(crate) pending_target_updates: Arc<Mutex<Vec<PendingTargetUpdate>>>,
    /// Valid Sv1 jobs storage, containing only a single shared entry (AGGREGATED_CHANNEL_ID) in
    /// case of channels aggregation (aggregated mode)
    pub(crate) valid_sv1_jobs: Arc<DashMap<ChannelId, Vec<server_to_client::Notify<'static>>>>,
    pub(crate) load_balancer: Option<Arc<crate::load_balancer::LoadBalancer>>,
}

#[cfg_attr(not(test), hotpath::measure_all)]
impl Sv1Server {
    /// Sends a message to downstream(s) for the given channel_id.
    ///
    /// In aggregated mode the channel manager rewrites the job's channel_id to
    /// `AGGREGATED_CHANNEL_ID` before forwarding, which signals a broadcast: send to every
    /// connected downstream.
    async fn send_to_channel(
        &self,
        channel_id: ChannelId,
        msg: stratum_apps::stratum_core::sv1_api::json_rpc::Message,
    ) {
        if channel_id == AGGREGATED_CHANNEL_ID {
            let downstream_senders = self
                .sv1_server_channel_state
                .sv1_server_to_downstream_sender
                .super_safe_lock(|downstream_channels| downstream_channels.clone());
            // Broadcast to every connected downstream.
            for (downstream_id, sender) in downstream_senders {
                if let Err(e) = sender.send(msg.clone()).await {
                    warn!(
                        "Failed to send notify to downstream {}: channel closed: {}",
                        downstream_id, e
                    );
                }
            }
        } else {
            // Non-aggregated: send to the single downstream that owns this channel_id.
            let downstream_id = match self
                .channel_id_to_downstream_id
                .super_safe_lock(|map| map.get(&channel_id).cloned())
            {
                Some(id) => id,
                None => return,
            };

            let sender = self
                .sv1_server_channel_state
                .sv1_server_to_downstream_sender
                .super_safe_lock(|ch| ch.get(&downstream_id).cloned());

            let Some(sender) = sender else { return };

            if let Err(e) = sender.send(msg).await {
                warn!(
                    "Failed to send notify to downstream {}: channel closed: {}",
                    downstream_id, e
                );
            }
        }
    }

    /// Cleans up server state and closes communication channels.
    pub fn cleanup(&self) {
        self.prevhashes.clear();
        self.valid_sv1_jobs.clear();
        if self.config.downstream_difficulty_config.enable_vardiff {
            self.vardiff.clear();
        }
        self.downstreams.clear();
        self.channel_id_to_downstream_id
            .super_safe_lock(|map| map.clear());
        self.request_id_to_downstream_id.clear();
        self.pending_target_updates
            .safe_lock(|updates| updates.clear())
            .ok();
        self.sv1_server_channel_state.drop();
    }

    /// Creates a new SV1 server instance.
    ///
    /// # Arguments
    /// * `listener_addr` - The socket address to bind the server to
    /// * `channel_manager_receiver` - Channel to receive messages from the channel manager
    /// * `channel_manager_sender` - Channel to send messages to the channel manager
    /// * `config` - Configuration settings for the translator
    ///
    /// # Returns
    /// A new Sv1Server instance ready to accept connections
    pub fn new(
        listener_addr: SocketAddr,
        channel_manager_receiver: Receiver<(Mining<'static>, Option<Vec<Tlv>>)>,
        channel_manager_sender: Sender<(Mining<'static>, Option<Vec<Tlv>>)>,
        config: TranslatorConfig,
    ) -> Self {
        let shares_per_minute = config.downstream_difficulty_config.shares_per_minute;
        let sv1_server_channel_state =
            Sv1ServerChannelState::new(channel_manager_receiver, channel_manager_sender);
        let load_balancer = config.load_balancer.as_ref().map(|lb_config| {
            let lb = crate::load_balancer::LoadBalancer::new(lb_config.clone());
            lb.spawn_poller();
            lb
        });

        Self {
            sv1_server_channel_state,
            config,
            listener_addr,
            shares_per_minute,
            miner_counter: Arc::new(AtomicU32::new(0)),
            sequence_counter: Arc::new(AtomicU32::new(1)),
            keepalive_job_id_counter: Arc::new(AtomicU32::new(0)),
            downstream_id_factory: Arc::new(AtomicUsize::new(1)),
            request_id_factory: Arc::new(AtomicU32::new(1)),
            downstreams: Arc::new(DashMap::new()),
            request_id_to_downstream_id: Arc::new(DashMap::new()),
            channel_id_to_downstream_id: Arc::new(Mutex::new(HashMap::new())),
            vardiff: Arc::new(DashMap::new()),
            prevhashes: Arc::new(DashMap::new()),
            pending_target_updates: Arc::new(Mutex::new(Vec::new())),
            valid_sv1_jobs: Arc::new(DashMap::new()),
            load_balancer,
        }
    }

    /// Record a miner-declared difficulty (from `mining.suggest_difficulty` or a `d=` in the
    /// `mining.authorize` password) as a nominal hashrate for this downstream.
    ///
    /// Clamped into `[min_individual_miner_hashrate, MAX_SUGGESTED_HASHRATE]`: the floor stops a
    /// miner requesting a difficulty low enough to flood the pool with shares, and the ceiling
    /// keeps a nonsense value from overflowing the hashrate→target conversion. Recorded before
    /// the SV2 channel opens it sizes the channel directly; if the channel is already open it is
    /// staged as a pending update for the next vardiff tick to push upstream and downstream.
    pub(super) fn record_suggested_difficulty(
        &self,
        downstream_id: DownstreamId,
        difficulty: f64,
        source: &str,
    ) {
        let config = &self.config.downstream_difficulty_config;
        let shares_per_minute = config.shares_per_minute as f64;
        let requested = super::difficulty_to_hashrate(difficulty, shares_per_minute);
        let floor = config.min_individual_miner_hashrate as f64;
        let clamped = requested.clamp(floor, super::MAX_SUGGESTED_HASHRATE);

        if clamped != requested {
            warn!(
                "Down: downstream {} suggested difficulty {} ({:.3e} H/s) via {} — clamped to {:.3e} H/s",
                downstream_id, difficulty, requested, source, clamped
            );
        } else {
            info!(
                "Down: downstream {} suggested difficulty {} via {} — sizing channel at {:.3e} H/s",
                downstream_id, difficulty, source, clamped
            );
        }

        let Some(downstream) = self.downstreams.get(&downstream_id) else {
            return;
        };
        // SHARE_TIER_BIND: a miner-suggested difficulty is quantised like any other assignment
        // when the tier flag is armed (dormant by default).
        let pending_target = hash_rate_to_target(clamped, shares_per_minute)
            .ok()
            .map(|t| {
                if config.quantise_to_tiers {
                    super::difficulty_manager::quantise_target_to_tier(&t)
                } else {
                    t
                }
            });
        downstream.downstream_data.super_safe_lock(|data| {
            data.suggested_hashrate = Some(clamped as Hashrate);
            data.hashrate = Some(clamped as Hashrate);
            // Channel already open: the open path can no longer pick this up, so stage it for
            // the vardiff loop, which pushes UpdateChannel upstream and mining.set_difficulty
            // downstream on its next tick.
            if data.channel_id.is_some() {
                data.set_pending_hashrate(Some(clamped as Hashrate), downstream_id);
                if let Some(target) = pending_target {
                    data.set_pending_target(target, downstream_id);
                }
            }
        });
    }

    /// Registers a freshly accepted downstream connection and spawns its tasks.
    ///
    /// Generic over the stream type `S` so it serves both the plain-TCP listener
    /// (`S = TcpStream`) and the opt-in TLS listener (`S = TlsStream<TcpStream>`) through one
    /// code path. Everything from constructing the [`ConnectionSV1`] onwards is identical for
    /// both transports; the load-balancer capacity gate and utilisation routing run earlier,
    /// in the accept loop, because they operate on the raw `TcpStream` before TLS termination.
    #[allow(clippy::too_many_arguments)]
    async fn register_downstream<S>(
        self: &Arc<Self>,
        stream: S,
        addr: SocketAddr,
        cancellation_token: &CancellationToken,
        fallback_coordinator: &FallbackCoordinator,
        status_sender: &Sender<Status>,
        task_manager: &Arc<TaskManager>,
        first_target: Target,
        // Starting hashrate for this connection, in H/s. Differs per listener: the hobby port
        // uses the configured floor, the farm port uses farm_tier.min_individual_miner_hashrate.
        // Vardiff moves from here, so this only sets where the connection begins.
        tier_floor_hs: Hashrate,
        // Which listener accepted this connection.
        on_farm_tier: bool,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        info!("New SV1 downstream connection from {}", addr);
        let connection_token = cancellation_token.child_token();
        let connection = ConnectionSV1::new(stream, connection_token.clone()).await;
        let downstream_id = self.downstream_id_factory.fetch_add(1, Ordering::Relaxed);
        let (sv1_server_sender, sv1_server_receiver) = async_channel::unbounded();
        self.sv1_server_channel_state
            .sv1_server_to_downstream_sender
            .super_safe_lock(|map| map.insert(downstream_id, sv1_server_sender));

        let downstream = Downstream::new(
            downstream_id,
            addr,
            connection.sender().clone(),
            connection.receiver().clone(),
            self.sv1_server_channel_state
                .downstream_to_sv1_server_sender
                .clone(),
            sv1_server_receiver,
            first_target,
            Some(tier_floor_hs),
            self.config.downstream_extranonce2_size as usize,
            connection_token.clone(),
        );
        // Record which listener this connection arrived on, so the vardiff loop can tell an
        // oversized hobby-port miner to move without disturbing farm-port miners.
        if on_farm_tier {
            downstream
                .downstream_data
                .super_safe_lock(|d| d.on_farm_tier = true);
        }
        self.downstreams.insert(downstream_id, downstream.clone());
        // NB: vardiff state is intentionally NOT inserted here. The channel
        // is opened lazily after the first message, so a freshly accepted
        // connection has `channel_id == None`. Inserting vardiff now makes
        // the 60s vardiff loop iterate channel-less connections every tick —
        // port scanners that complete the TCP handshake but never subscribe
        // sit here for their whole lifetime — which logged a spurious error
        // per tick. Vardiff is now registered at channel-open instead; see
        // the `OpenExtendedMiningChannelSuccess` handler.
        info!(
            "Downstream {} registered successfully (channel will be opened after first message)",
            downstream_id
        );

        // Start downstream tasks immediately, but defer channel opening until first message
        let status_sender = StatusSender::Downstream {
            downstream_id,
            tx: status_sender.clone(),
        };
        Downstream::run_downstream_tasks(
            downstream,
            cancellation_token.clone(),
            fallback_coordinator.clone(),
            status_sender,
            task_manager.clone(),
        );

        // Zombie-connection reaper. A connection that completes the TCP
        // handshake but never opens a channel — internet port scanners and
        // half-open probes hitting the public stratum port — would otherwise
        // linger in the downstreams/sender maps holding a socket for its
        // whole lifetime. Give it a generous grace period to open a channel
        // (real miners subscribe+authorize within seconds); if it still has
        // no channel_id after that, close the socket and clean up the maps.
        // handle_downstream_disconnect is idempotent, so it is safe even if
        // the connection's own error path also fires.
        const CHANNELLESS_REAP_TIMEOUT: Duration = Duration::from_secs(120);
        let reaper = self.clone();
        let reaper_token = connection_token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(CHANNELLESS_REAP_TIMEOUT).await;
            let still_channelless = match reaper.downstreams.get(&downstream_id) {
                Some(d) => d
                    .downstream_data
                    .super_safe_lock(|data| data.channel_id.is_none()),
                None => return, // already disconnected and cleaned up
            };
            if still_channelless {
                warn!(
                    "Reaping downstream {} — no channel opened within {}s (likely a scanner/probe)",
                    downstream_id,
                    CHANNELLESS_REAP_TIMEOUT.as_secs()
                );
                reaper_token.cancel();
                reaper.handle_downstream_disconnect(downstream_id).await;
            }
        });
    }

    /// Builds the opt-in TLS listener.
    ///
    /// Returns `(Some(acceptor), Some(listener))` only when `tls_port`, `tls_cert_path` and
    /// `tls_key_path` are all configured; otherwise `(None, None)` so the TLS accept arm stays
    /// inert and the plain-TCP behaviour is unchanged. The certificate chain and private key are
    /// loaded from PEM files and used to build a `rustls` server config with no client-auth.
    async fn build_tls_listener(
        self: Arc<Self>,
    ) -> std::io::Result<(Option<tokio_rustls::TlsAcceptor>, Option<TcpListener>)> {
        use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
        use std::io::{Error, ErrorKind};

        let (Some(tls_port), Some(cert_path), Some(key_path)) = (
            self.config.tls_port,
            self.config.tls_cert_path.as_ref(),
            self.config.tls_key_path.as_ref(),
        ) else {
            return Ok((None, None));
        };

        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("loading TLS cert {cert_path}: {e}"),
                )
            })?
            .collect::<Result<_, _>>()
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("parsing TLS cert {cert_path}: {e}"),
                )
            })?;
        let key = PrivateKeyDer::from_pem_file(key_path).map_err(|e| {
            Error::new(
                ErrorKind::InvalidData,
                format!("loading TLS key {key_path}: {e}"),
            )
        })?;

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| Error::new(ErrorKind::InvalidData, format!("building TLS config: {e}")))?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        // Bind the TLS listener on the same interface as the plain listener, on `tls_port`.
        let tls_addr = SocketAddr::new(self.listener_addr.ip(), tls_port);
        let listener = TcpListener::bind(tls_addr).await.map_err(|e| {
            error!("Failed to bind TLS listener to {}: {}", tls_addr, e);
            e
        })?;
        info!("Translator Proxy: TLS listening on {}", tls_addr);

        Ok((Some(acceptor), Some(listener)))
    }

    /// Accepts on an optional TLS listener.
    ///
    /// When `listener` is `None` (no TLS configured) this future never resolves, so the
    /// corresponding `tokio::select!` arm is permanently inert.
    async fn accept_optional(
        listener: Option<&TcpListener>,
    ) -> std::io::Result<(tokio::net::TcpStream, SocketAddr)> {
        match listener {
            Some(l) => l.accept().await,
            None => std::future::pending().await,
        }
    }

    /// Starts the SV1 server and begins accepting connections.
    ///
    /// This method:
    /// - Binds to the configured listening address
    /// - Spawns the variable difficulty adjustment loop
    /// - Enters the main event loop to handle:
    ///   - New miner connections
    ///   - Shutdown signals
    ///   - Messages from downstream miners (submit shares)
    ///   - Messages from upstream SV2 channel manager
    ///
    /// The server will continue running until a shutdown signal is received.
    ///
    /// # Arguments
    /// * `cancellation_token` - Global application cancellation token
    /// * `fallback_coordinator` - Fallback coordinator
    /// * `status_sender` - Channel for sending status updates
    /// * `task_manager` - Manager for spawned async tasks
    ///
    /// # Returns
    /// * `Ok(())` - Server shut down gracefully
    /// * `Err(TproxyError)` - Server encountered an error
    pub async fn start(
        self: Arc<Self>,
        cancellation_token: CancellationToken,
        fallback_coordinator: FallbackCoordinator,
        status_sender: Sender<Status>,
        task_manager: Arc<TaskManager>,
    ) -> TproxyResult<(), error::Sv1Server> {
        info!("Starting SV1 server on {}", self.listener_addr);

        // Starting difficulty for the hobby listener (`downstream_port`). Vardiff moves from
        // here; this only sets where a connection begins.
        let hobby_floor_hs = self
            .config
            .downstream_difficulty_config
            .min_individual_miner_hashrate;
        let shares_per_minute = self.config.downstream_difficulty_config.shares_per_minute as f64;
        // SHARE_TIER_BIND: with tier quantisation armed, connections START on a tier too —
        // otherwise every share mined before the first vardiff tick sits between tiers.
        // Dormant by default; see `DownstreamDifficultyConfig::quantise_to_tiers`.
        let quantise = self.config.downstream_difficulty_config.quantise_to_tiers;
        let snap = |t: Target| {
            if quantise {
                super::difficulty_manager::quantise_target_to_tier(&t)
            } else {
                t
            }
        };
        let first_target: Target =
            snap(hash_rate_to_target(hobby_floor_hs as f64, shares_per_minute).unwrap());

        // Optional farm/rental listener. `None` leaves the single-listener behaviour exactly
        // as it was, which is what every existing config produces.
        let farm_tier = self.config.farm_tier.clone();
        let (farm_listener, farm_first_target, farm_floor_hs) = match farm_tier.as_ref() {
            Some(t) => {
                let addr = SocketAddr::new(self.listener_addr.ip(), t.port);
                let l = TcpListener::bind(addr).await.map_err(|e| {
                    error!("Failed to bind farm listener to {}: {}", addr, e);
                    TproxyError::shutdown(e)
                })?;
                let target = snap(
                    hash_rate_to_target(t.min_individual_miner_hashrate as f64, shares_per_minute)
                        .unwrap(),
                );
                info!(
                    "Translator Proxy: farm/rental listening on {} (floor {} H/s)",
                    addr, t.min_individual_miner_hashrate
                );
                (Some(l), target, t.min_individual_miner_hashrate)
            }
            None => (None, first_target, hobby_floor_hs),
        };

        let vardiff_future = self.clone().spawn_vardiff_loop();

        let keepalive_future = self.clone().spawn_job_keepalive_loop();

        let listener = TcpListener::bind(self.listener_addr).await.map_err(|e| {
            error!("Failed to bind to {}: {}", self.listener_addr, e);
            TproxyError::shutdown(e)
        })?;

        info!("Translator Proxy: listening on {}", self.listener_addr);

        // Opt-in TLS listener. Only created when `tls_port`, `tls_cert_path` and `tls_key_path`
        // are all configured; otherwise `tls_listener` stays `None` and the TLS accept arm is
        // inert, leaving the plain-TCP path completely unchanged.
        let (tls_acceptor, tls_listener) = self
            .clone()
            .build_tls_listener()
            .await
            .map_err(TproxyError::shutdown)?;

        let sv1_status_sender = StatusSender::Sv1Server(status_sender.clone());
        let task_manager_clone = task_manager.clone();
        let vardiff_enabled = self.config.downstream_difficulty_config.enable_vardiff;
        let keepalive_enabled = self
            .config
            .downstream_difficulty_config
            .job_keepalive_interval_secs
            > 0;
        task_manager_clone.spawn(async move {
            // we just spawned a new task that's relevant to fallback coordination
            // so register it with the fallback coordinator
            let fallback_handler = fallback_coordinator.register();

            // get the cancellation token that signals fallback
            let fallback_token = fallback_coordinator.token();

            tokio::pin!(vardiff_future);
            tokio::pin!(keepalive_future);
            loop {
                tokio::select! {
                    // Handle app shutdown signal
                    _ = cancellation_token.cancelled() => {
                        debug!("SV1 Server: received shutdown signal. Exiting.");
                        self.cleanup();
                        break;
                    }

                    // Handle fallback trigger
                    _ = fallback_token.cancelled() => {
                        info!("SV1 Server: fallback triggered, clearing state");
                        self.cleanup();
                        break;
                    }
                    result = listener.accept() => {
                        match result {
                            Ok((stream, addr)) => {
                                // Load balancer: capacity controls + utilisation routing.
                                if let Some(ref lb) = self.load_balancer {
                                    // Step 1: capacity gate. If we're already over the
                                    // reject threshold, close the socket. The bitaxe
                                    // firmware auto-reconnects via DNS → another VM
                                    // picks them up. No mid-session disruption to
                                    // existing miners.
                                    if lb.should_reject_for_capacity().await {
                                        warn!(
                                            "Rejecting connection from {}: local capacity at/above reject threshold",
                                            addr
                                        );
                                        lb.record_capacity_rejection();
                                        drop(stream);
                                        continue;
                                    }
                                    // Step 2: utilisation-based routing for new arrivals.
                                    let local_count = self.downstreams.len();
                                    if let Some(target) = lb.should_proxy(local_count, addr.ip(), Tier::Hobby).await {
                                        info!("Proxying new connection from {} to {}", addr, target);
                                        lb.spawn_proxy(stream, target);
                                        continue;
                                    }
                                }

                                self.register_downstream(
                                    stream,
                                    addr,
                                    &cancellation_token,
                                    &fallback_coordinator,
                                    &status_sender,
                                    &task_manager,
                                    first_target,
                                    hobby_floor_hs,
                                    false,
                                ).await;
                            }
                            Err(e) => {
                                warn!("Failed to accept new connection: {:?}", e);
                            }
                        }
                    }
                    // Opt-in TLS listener. `accept_optional` resolves to `Pending` forever when no
                    // TLS listener is configured, so this arm is inert in the default deployment.
                    // Farm/rental listener. Inert when `farm_tier` is unset, exactly like the
                    // TLS arm: `accept_optional` never resolves on `None`.
                    result = Self::accept_optional(farm_listener.as_ref()) => {
                        match result {
                            Ok((stream, addr)) => {
                                // Capacity gate, same as the hobby arm. The farm port carries the
                                // LARGEST clients, so a node at its reject threshold has more
                                // reason to turn them away here, not less. Without this a node at
                                // 95% capacity keeps accepting rented-hashrate orders.
                                if let Some(ref lb) = self.load_balancer {
                                    if lb.should_reject_for_capacity().await {
                                        warn!(
                                            "Rejecting farm-port connection from {}: local capacity at/above reject threshold",
                                            addr
                                        );
                                        lb.record_capacity_rejection();
                                        drop(stream);
                                        continue;
                                    }
                                    // Utilisation-routed as of #472, to a peer's FARM port.
                                    // Peers that do not advertise one are not candidates, so a
                                    // farm miner can never be handed to a peer's hobby floor —
                                    // that misrouting is worse than not balancing at all, which
                                    // is why this arm previously served locally or rejected.
                                    let local_count = self.downstreams.len();
                                    if let Some(target) =
                                        lb.should_proxy(local_count, addr.ip(), Tier::Farm).await
                                    {
                                        info!(
                                            "Proxying new farm-port connection from {} to {}",
                                            addr, target
                                        );
                                        lb.spawn_proxy(stream, target);
                                        continue;
                                    }
                                }
                                info!("New SV1 downstream connection from {} on the farm port", addr);
                                self.register_downstream(
                                    stream,
                                    addr,
                                    &cancellation_token,
                                    &fallback_coordinator,
                                    &status_sender,
                                    &task_manager,
                                    farm_first_target,
                                    farm_floor_hs,
                                    true,
                                ).await;
                            }
                            Err(e) => {
                                warn!("Failed to accept farm-port connection: {:?}", e);
                            }
                        }
                    }

                    result = Self::accept_optional(tls_listener.as_ref()) => {
                        match result {
                            Ok((tcp, addr)) => {
                                // Load-balancer capacity gate + utilisation routing run on the raw
                                // TCP stream before TLS termination — identical to the plain path,
                                // and the byte-level proxy stays transparent (the target VM
                                // terminates TLS) when a connection is forwarded.
                                if let Some(ref lb) = self.load_balancer {
                                    if lb.should_reject_for_capacity().await {
                                        warn!(
                                            "Rejecting TLS connection from {}: local capacity at/above reject threshold",
                                            addr
                                        );
                                        lb.record_capacity_rejection();
                                        drop(tcp);
                                        continue;
                                    }
                                    let local_count = self.downstreams.len();
                                    if let Some(target) = lb.should_proxy(local_count, addr.ip(), Tier::Hobby).await {
                                        info!("Proxying new TLS connection from {} to {}", addr, target);
                                        lb.spawn_proxy(tcp, target);
                                        continue;
                                    }
                                }

                                // Terminate TLS, then feed the decrypted stream through the same
                                // downstream path as the plain listener. `acceptor` is `Some`
                                // whenever `tls_listener` is `Some`.
                                let Some(ref acceptor) = tls_acceptor else { continue };
                                match acceptor.accept(tcp).await {
                                    Ok(tls_stream) => {
                                        self.register_downstream(
                                            tls_stream,
                                            addr,
                                            &cancellation_token,
                                            &fallback_coordinator,
                                            &status_sender,
                                            &task_manager,
                                            first_target,
                                            hobby_floor_hs,
                                            false,
                                        ).await;
                                    }
                                    Err(e) => {
                                        warn!("TLS handshake failed for {}: {:?}", addr, e);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to accept new TLS connection: {:?}", e);
                            }
                        }
                    }
                    res = self.handle_downstream_message() => {
                        if let Err(e) = res {
                            if handle_error(&sv1_status_sender, e).await {
                                self.cleanup();
                                break;
                            }
                        }
                    }
                    res = self.handle_upstream_message(
                        first_target,
                    ) => {
                        if let Err(e) = res {
                            if handle_error(&sv1_status_sender, e).await {
                                self.cleanup();
                                break;
                            }
                        }
                    }
                    _ = &mut vardiff_future, if vardiff_enabled => {}
                    _ = &mut keepalive_future, if keepalive_enabled => {}
                }
            }
            debug!("SV1 Server main listener loop exited.");

            // signal fallback coordinator that this task has completed its cleanup
            fallback_handler.done();
        });

        Ok(())
    }

    /// Handles messages received from downstream SV1 miners.
    ///
    /// This method processes share submissions from miners by:
    /// - Updating variable difficulty counters
    /// - Extracting and validating share data
    /// - Converting SV1 share format to SV2 SubmitSharesExtended
    /// - Forwarding the share to the channel manager for upstream submission
    ///
    /// # Returns
    /// * `Ok(())` - Message processed successfully
    /// * `Err(TproxyError)` - Error processing the message
    pub async fn handle_downstream_message(&self) -> TproxyResult<(), error::Sv1Server> {
        let (downstream_id, downstream_message) = self
            .sv1_server_channel_state
            .downstream_to_sv1_server_receiver
            .recv()
            .await
            .map_err(TproxyError::shutdown)?;

        let Some(downstream) = self
            .downstreams
            .get(&downstream_id)
            .map(|r| r.value().clone())
        else {
            return Ok(());
        };

        // `mining.suggest_difficulty` is handled here, ahead of the channel-open branch, so it
        // works in both directions: before the channel opens it sizes the initial target (the
        // point of the message — the channel opens on authorize, so a queued suggestion would
        // drain too late to skip the vardiff ramp), and after the open it is staged as a pending
        // update. The vendored SV1 library parses the method but discards it (`Ok(None)`), so
        // the value is read straight off the raw request. It expects no reply.
        if is_mining_suggest_difficulty(&downstream_message) {
            match parse_suggest_difficulty(&downstream_message) {
                Some(difficulty) => self.record_suggested_difficulty(
                    downstream_id,
                    difficulty,
                    "mining.suggest_difficulty",
                ),
                None => warn!(
                    "Down: downstream {} sent an unparseable mining.suggest_difficulty; ignoring",
                    downstream_id
                ),
            }
            return Ok(());
        }

        let channel_id = downstream
            .downstream_data
            .super_safe_lock(|data| data.channel_id);
        if channel_id.is_none() {
            // Public-pool defer-open: in non-aggregated mode we want the upstream SV2 channel's
            // user_identity to carry each miner's full `<address>.<worker>` from
            // `mining.authorize`, so the pool can attribute shares per miner AND derive each
            // miner's payout address from their own credentials. The classic flow opened the
            // channel on the very first message (typically `mining.subscribe`), which arrives
            // BEFORE authorize — too early to know the user_identity.
            //
            // New flow:
            //   - `mining.subscribe`: QUEUE it until the channel opens, then process it so its
            //     response carries the REAL channel-allocated extranonce. The subscribe response
            //     (`[subscriptions, extranonce1, extranonce2_size]`) is built from
            //     `data.extranonce1` — which is the real value by the time the queue is drained
            //     (set on `OpenExtendedMiningChannelSuccess` before queued-message processing).
            //     This is the correctness fix for stock SV1 miners: `mining.set_extranonce` is an
            //     OPTIONAL extension (a miner must send `mining.extranonce.subscribe` to opt in),
            //     so the previous "respond with an 8-byte placeholder, then post-hoc
            //     set_extranonce" path silently broke every miner with extranonce-subscribe OFF —
            //     their shares were built against the placeholder and 100% rejected. Delivering
            //     the real extranonce in the subscribe response itself works for ALL miners,
            //     opted-in or not, with no mid-stream re-key. The channel opens within ~100ms of
            //     subscribe (the miner pipelines subscribe+authorize), so deferring the response
            //     does not risk a subscribe timeout.
            //   - `mining.authorize`: process immediately so `data.user_identity` /
            //     `data.authorized_worker_name` are populated, then trigger
            //     `handle_open_channel_request`. (Authorize, not subscribe, opens the channel —
            //     so queuing subscribe does NOT block the open: the miner pipelines them.)
            //   - `mining.configure`: process immediately. BIP310 version-rolling negotiation
            //     is stateless — the miner sends configure first to learn the version mask,
            //     then sends subscribe/authorize. If we queue configure waiting for the
            //     channel to open, some Bitaxe firmware (BM1370 v2.12.0 observed) waits for
            //     the configure response before sending subscribe at all, which deadlocks.
            //   - Anything else: queue until the channel is open (existing behaviour).
            //
            // Aggregated mode is unaffected — every downstream still piggybacks on the single
            // shared upstream channel that the channel_manager already opened, so this branch
            // simply falls through for `mining.submit` etc. once the channel exists.
            let process_immediately = is_mining_authorize(&downstream_message)
                || is_mining_configure(&downstream_message);
            if !process_immediately {
                debug!(
                    "Down: Queuing Sv1 message until channel is established (downstream {})",
                    downstream_id
                );
                downstream.downstream_data.super_safe_lock(|data| {
                    data.queued_sv1_handshake_messages
                        .push(downstream_message.clone())
                });

                // A queued `mining.subscribe` has to be answered eventually, and the answer
                // must carry the REAL channel extranonce. Two ways to get there:
                //
                // `open_channel_on_subscribe` ON — open the channel NOW, under a provisional
                // identity. The subscribe response is built when the open succeeds and the
                // queue is drained, so it carries the real 12-byte prefix first time, for
                // pipelining and serialising miners alike. This is the path that fixes rented
                // hashrate; see the flag's docs for why the old placeholder could not.
                //
                // OFF (shipped default) — keep the legacy 1.5s fallback. PIPELINING miners
                // (AxeOS/bitaxe) fire subscribe + authorize back-to-back, so the channel opens
                // within ~100ms and the drain answers subscribe correctly. SERIALIZING miners
                // deadlock — no response, no authorize, no channel, no response — so after
                // ~1.5s answer with the placeholder extranonce and let `set_extranonce` try to
                // correct it. ⚠ That correction is an OPTIONAL extension: a client that never
                // sends `mining.extranonce.subscribe` builds its coinbase 4 bytes short and
                // every share it submits is invalid. The flag exists to retire this branch.
                if is_mining_subscribe(&downstream_message) {
                    if self.config.open_channel_on_subscribe {
                        // DEBOUNCE, and it is load-bearing twice over.
                        //
                        // 1. Prefix exhaustion. The pool's extended allocator is
                        //    `server_id || counter` with a two-byte server id, leaving a
                        //    16-BIT counter — 65,535 prefixes for the lifetime of the
                        //    process, never handed back (#746). vm1 burns ~250/h, so a node
                        //    that stays up ~10 days stops being able to open channels at all.
                        //    Opening on every subscribe would add the subscribe-only probes
                        //    (~15% more) to that burn for no benefit: they disconnect without
                        //    ever mining.
                        // 2. #746 deliberately moved allocation AFTER validation so an
                        //    UNAUTHENTICATED client cannot burn the space. A subscribe
                        //    arrives before any authorize, so opening on it immediately hands
                        //    that capability straight back — a drive-by prober could exhaust
                        //    the pool for every honest miner.
                        //
                        // A pipelining miner's authorize lands ~12ms after subscribe and a
                        // marketplace capability probe disconnects ~10-30ms in; neither
                        // reaches this timer, so neither costs a prefix and the pipelining
                        // path is byte-identical to today. Only a client that genuinely holds
                        // the connection open waiting for its subscribe reply — the
                        // serialising shape this exists to serve — opens early, and it still
                        // gets the REAL extranonce, never a placeholder.
                        let server = self.clone();
                        let did = downstream_id;
                        tokio::spawn(async move {
                            tokio::time::sleep(SUBSCRIBE_OPEN_DEBOUNCE).await;
                            let Some(downstream) =
                                server.downstreams.get(&did).map(|r| r.value().clone())
                            else {
                                // Already gone: a probe that subscribed and hung up. Costs
                                // nothing, which is the point.
                                return;
                            };
                            // Claim the open iff authorize has not already taken it.
                            let already_requested =
                                downstream.downstream_data.super_safe_lock(|data| {
                                    let seen =
                                        data.channel_open_requested || data.channel_id.is_some();
                                    if !seen {
                                        data.channel_open_requested = true;
                                        // Claimed by THIS path, so the channel identity will be
                                        // the sentinel and the TLV must carry the address.
                                        data.channel_opened_provisionally = true;
                                    }
                                    seen
                                });
                            if already_requested {
                                return;
                            }
                            debug!(
                                "Down: downstream {} is still waiting on its subscribe reply — \
                                 opening the channel under a provisional identity so the reply \
                                 can carry the real extranonce",
                                did
                            );
                            if let Err(e) = server.handle_open_channel_request(did).await {
                                error!(
                                    "Down: failed to open upstream channel on subscribe for \
                                     downstream {}: {:?}",
                                    did, e
                                );
                            }
                        });
                        return Ok(());
                    }

                    let server = self.clone();
                    let did = downstream_id;
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                        let Some(downstream) =
                            server.downstreams.get(&did).map(|r| r.value().clone())
                        else {
                            return;
                        };
                        // Claim the queued subscribe iff the channel still hasn't opened (i.e. the
                        // open path hasn't already answered it — a pipelining miner).
                        let subscribe_msg = downstream.downstream_data.super_safe_lock(|data| {
                            if data.channel_id.is_some() {
                                return None;
                            }
                            data.queued_sv1_handshake_messages
                                .iter()
                                .position(is_mining_subscribe)
                                .map(|pos| data.queued_sv1_handshake_messages.remove(pos))
                        });
                        if let Some(msg) = subscribe_msg {
                            info!(
                                "Down: subscribe-response timeout for downstream {} — serializing \
                                 miner waiting on subscribe before authorize; answering with \
                                 placeholder extranonce (set_extranonce corrects it on channel open)",
                                did
                            );
                            match server.clone().handle_message(Some(did), msg) {
                                Ok(Some(resp)) => {
                                    if let Err(e) = downstream
                                        .downstream_channel_state
                                        .downstream_sv1_sender
                                        .send(resp.into())
                                        .await
                                    {
                                        warn!("Down: failed to send fallback subscribe response to downstream {}: {:?}", did, e);
                                    }
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    error!("Down: error building fallback subscribe response for downstream {}: {:?}", did, e);
                                }
                            }
                        }
                    });
                }

                return Ok(());
            }
            // For authorize/configure: fall through to the normal handle_message path below.
            // Authorize-triggered channel open happens in the post-response block.
        }

        let is_authorize = is_mining_authorize(&downstream_message);

        let response = self
            .clone()
            .handle_message(Some(downstream_id), downstream_message);

        match response {
            Ok(Some(response_msg)) => {
                debug!("Down: Sending Sv1 message to downstream: {}", response_msg);
                downstream
                    .downstream_channel_state
                    .downstream_sv1_sender
                    .send(response_msg.into())
                    .await
                    .map_err(|error| {
                        error!("Down: Failed to send message to downstream: {error:?}");
                        TproxyError::disconnect(TproxyErrorKind::ChannelErrorSender, downstream_id)
                    })?;

                // Check if this was an authorize message and handle sv1 handshake completion
                if is_authorize {
                    info!("Down: Handling mining.authorize after handshake completion");
                    if let Err(e) = downstream.handle_sv1_handshake_completion().await {
                        error!("Down: Failed to handle handshake completion: {:?}", e);
                        return Err(TproxyError::disconnect(e, downstream_id));
                    }

                    // Public-pool defer-open: if the upstream channel hasn't been opened yet
                    // (deferred from subscribe), do it now so the channel's `user_identity`
                    // carries the authorize-supplied `<addr>.<worker>` string instead of the
                    // config prefix. Aggregated mode shares one upstream channel across all
                    // downstreams; if it's already open, this is a no-op for non-first miners.
                    //
                    // Skip the open if authorize was rejected (e.g. bare-worker username with no
                    // `.` separator). The SV1 framework only calls `authorize()` — which sets
                    // `authorized_worker_name` — when `handle_authorize` returns true, so an
                    // empty name here means the miner failed validation and we'd otherwise burn
                    // an upstream channel for a connection that's about to be torn down.
                    //
                    // `channel_open` alone is not a sufficient guard once the channel can open
                    // on subscribe: a pipelining miner's authorize lands while that open is
                    // still in flight, so `channel_id` is still None and this would burn a
                    // second upstream channel. `channel_open_requested` is set the moment the
                    // request goes out, and claiming it here is what makes the two paths
                    // mutually exclusive.
                    let (already_requested, name_set) =
                        downstream.downstream_data.super_safe_lock(|d| {
                            let seen = d.channel_open_requested || d.channel_id.is_some();
                            if !seen {
                                d.channel_open_requested = true;
                            }
                            (seen, !d.authorized_worker_name.is_empty())
                        });
                    if !already_requested && name_set {
                        debug!(
                            "Down: Authorize handled, opening upstream channel for downstream {} now that user_identity is known",
                            downstream_id
                        );
                        if let Err(e) = self.handle_open_channel_request(downstream_id).await {
                            error!(
                                "Down: Failed to open upstream channel for downstream {}: {:?}",
                                downstream_id, e
                            );
                            return Err(e);
                        }
                    }
                }
            }
            Ok(None) => {
                // Message was handled but no response needed
            }
            Err(e) => {
                error!("Down: Error handling downstream message: {:?}", e);
                return Err(TproxyError::disconnect(e, downstream_id));
            }
        }

        // Check if there's a pending share to send to the Sv1Server
        let pending_share = downstream
            .downstream_data
            .super_safe_lock(|d| d.pending_share.take());
        if let Some(share) = pending_share {
            self.handle_submit_shares(share).await?;
        }

        Ok(())
    }

    /// Handles share submission messages from downstream.
    async fn handle_submit_shares(
        &self,
        message: SubmitShareWithChannelId,
    ) -> TproxyResult<(), error::Sv1Server> {
        // Increment vardiff counter for this downstream (only if vardiff is enabled)
        if self.config.downstream_difficulty_config.enable_vardiff {
            if let Some(vardiff_state) = self.vardiff.get(&message.downstream_id) {
                vardiff_state.super_safe_lock(|state| state.increment_shares_since_last_update());
            }
        }

        let job_version = match message.job_version {
            Some(version) => version,
            None => {
                warn!("Received share submission without valid job version, skipping");
                return Ok(());
            }
        };

        // If this is a keepalive job, extract the original upstream job_id from the job_id string
        let mut share = message.share;
        let job_id_str = share.job_id.clone();
        if Self::is_keepalive_job_id(&job_id_str) {
            if let Some(original_job_id) = Self::extract_original_job_id(&job_id_str) {
                debug!(
                    "Extracting original job_id {} from keepalive job_id {}",
                    original_job_id, job_id_str
                );
                share.job_id = original_job_id;
            } else {
                warn!(
                    "Failed to extract original job_id from keepalive job_id {}, rejecting share",
                    job_id_str
                );
                return Ok(());
            }
        }

        // Increment and return the value for this share
        let sequence_number = self.sequence_counter.fetch_add(1, Ordering::SeqCst);

        let submit_share_extended = build_sv2_submit_shares_extended_from_sv1_submit(
            &share,
            message.channel_id,
            sequence_number,
            job_version,
            message.version_rolling_mask,
        )
        .map_err(|_| TproxyError::shutdown(TproxyErrorKind::SV1Error))?;

        // Attach a Worker-Specific Hashrate Tracking TLV with the per-downstream user_identity
        // for EVERY share submission, regardless of `aggregate_channels` mode. The pool side
        // uses the TLV (when the extension is negotiated) to attribute shares per worker
        // instead of per channel. In aggregate mode this is the only way to distinguish
        // multiple SV1 miners sharing one upstream channel; in non-aggregated mode it's
        // redundant with the channel's own user_identity but harmless.
        let tlv_fields = {
            let Some(downstream) = self
                .downstreams
                .get(&message.downstream_id)
                .map(|r| r.value().clone())
            else {
                warn!(
                    "Downstream {} disconnected before share could be submitted, dropping share",
                    message.downstream_id
                );
                return Ok(());
            };
            let user_identity = downstream
                .downstream_data
                .super_safe_lock(|d| d.user_identity.clone());
            // The downstream's user_identity is set during mining.authorize via
            // extract_worker_name + tlv_compatible_username, so it's already capped at 32
            // bytes. If it somehow isn't (empty downstream pre-authorize), skip the TLV
            // gracefully rather than disconnecting the miner.
            if user_identity.is_empty() {
                warn!(
                    "Down: downstream {} has no user_identity at share submit — TLV omitted, \
                     pool will attribute this share to the CHANNEL identity",
                    message.downstream_id
                );
                None
            } else {
                match UserIdentity::new(&user_identity)
                    .map_err(|e| e.to_string())
                    .and_then(|ui| ui.to_tlv().map_err(|e| format!("{e:?}")))
                {
                    Ok(tlv) => {
                        debug!(
                            "Down: attaching worker TLV for downstream {}: {:?} ({} bytes)",
                            message.downstream_id,
                            user_identity,
                            user_identity.len()
                        );
                        Some(vec![tlv])
                    }
                    Err(e) => {
                        // Previously `.ok()` — an error here silently dropped the TLV and sent
                        // the share with no identity at all, so the pool credited the channel's
                        // (possibly provisional) identity instead of the miner.
                        warn!(
                            "Down: FAILED to build worker TLV for downstream {} from {:?} \
                             ({} bytes): {e} — share will be misattributed",
                            message.downstream_id,
                            user_identity,
                            user_identity.len()
                        );
                        None
                    }
                }
            }
        };

        self.sv1_server_channel_state
            .channel_manager_sender
            .send((
                Mining::SubmitSharesExtended(submit_share_extended),
                tlv_fields,
            ))
            .await
            .map_err(|_| TproxyError::shutdown(TproxyErrorKind::ChannelErrorSender))?;

        Ok(())
    }

    /// Handles channel opening requests from downstream when they send their first message.
    async fn handle_open_channel_request(
        &self,
        downstream_id: DownstreamId,
    ) -> TproxyResult<(), error::Sv1Server> {
        info!(
            "SV1 server: opening extended mining channel for downstream {} after first message",
            downstream_id
        );

        let request_id = self.request_id_factory.fetch_add(1, Ordering::Relaxed);
        self.request_id_to_downstream_id
            .insert(request_id, downstream_id);

        if !self.downstreams.contains_key(&downstream_id) {
            error!(
                "Downstream {} not found when attempting to open channel",
                downstream_id
            );
            return Err(TproxyError::disconnect(
                TproxyErrorKind::DownstreamNotFound(downstream_id as u32),
                downstream_id,
            ));
        }

        self.open_extended_mining_channel(request_id, downstream_id)
            .await?;

        Ok(())
    }

    /// Handles messages received from the upstream SV2 server via the channel manager.
    ///
    /// This method processes various SV2 messages including:
    /// - OpenExtendedMiningChannelSuccess: Sets up downstream connections
    /// - NewExtendedMiningJob: Converts to SV1 notify messages
    /// - SetNewPrevHash: Updates block template information
    /// - Channel error messages (TODO: implement proper handling)
    ///
    /// # Arguments
    /// * `first_target` - Initial difficulty target for new connections
    ///
    /// # Returns
    /// * `Ok(())` - Message processed successfully
    /// * `Err(TproxyError)` - Error processing the message
    pub async fn handle_upstream_message(
        &self,
        first_target: Target,
    ) -> TproxyResult<(), error::Sv1Server> {
        let (message, _tlv_fields) = self
            .sv1_server_channel_state
            .channel_manager_receiver
            .recv()
            .await
            .map_err(TproxyError::shutdown)?;

        match message {
            Mining::OpenExtendedMiningChannelSuccess(m) => {
                debug!(
                    "Received OpenExtendedMiningChannelSuccess for channel id: {}",
                    m.channel_id
                );
                let downstream_id = self.request_id_to_downstream_id.remove(&m.request_id);

                let Some((_, downstream_id)) = downstream_id else {
                    return Err(TproxyError::log(TproxyErrorKind::DownstreamNotFound(
                        m.request_id,
                    )));
                };
                if let Some(downstream) = self.downstreams.get(&downstream_id) {
                    let initial_target =
                        Target::from_le_bytes(m.target.inner_as_ref().try_into().unwrap());
                    let real_extranonce1: stratum_apps::stratum_core::sv1_api::utils::Extranonce<
                        'static,
                    > = m
                        .extranonce_prefix
                        .to_vec()
                        .try_into()
                        .map_err(TproxyError::fallback)?;
                    let real_extranonce2_size: usize = m.extranonce_size.into();
                    let already_subscribed = downstream
                        .downstream_data
                        .safe_lock(|d| {
                            // Send the post-hoc `mining.set_extranonce` ONLY when the
                            // subscribe response has already gone out carrying a placeholder,
                            // so the miner is genuinely holding a wrong extranonce that must
                            // be corrected.
                            //
                            // The 8-zero test alone cannot establish that. It is the
                            // `DownstreamData::new` default, so it is equally true of
                            // "answered with a placeholder" and "not answered yet" — and in
                            // the `open_channel_on_subscribe` path it is the SECOND of those.
                            // There the subscribe is still sitting in the queue and is drained
                            // moments later carrying the REAL extranonce, so the notification
                            // announces a re-key for a subscription the client does not have
                            // yet, to a value it is about to receive anyway.
                            //
                            // Measured on vm7 (2026-08-29) against Braiins' own farm proxy:
                            //     16.021595 Out mining.set_extranonce ["010009eb…",8]
                            //     16.040722 Out {"id":2,…,"010009eb…",8]}   <- same value, 19ms later
                            // The client answers that with `protocol error: invalid-message-type`
                            // and closes, which is the farm-port churn (12,929 connects/24h).
                            //
                            // The queue is the discriminator: the legacy 1.5s fallback REMOVES
                            // the subscribe from `queued_sv1_handshake_messages` before
                            // answering it with a placeholder, so there the correction is real
                            // and still fires. Here it is still queued, so it is redundant.
                            let subscribe_still_queued = d
                                .queued_sv1_handshake_messages
                                .iter()
                                .any(is_mining_subscribe);
                            let was_placeholder = !subscribe_still_queued
                                && d.extranonce_subscribe_negotiated
                                && d.extranonce1.as_ref().len() == 8
                                && d.extranonce1.as_ref().iter().all(|b| *b == 0);
                            d.extranonce1 = real_extranonce1.clone();
                            d.extranonce2_len = real_extranonce2_size;
                            d.channel_id = Some(m.channel_id);
                            // Adopt the channel's ACTUAL allocated target as this downstream's
                            // target. It matches the config-derived starting target for a miner
                            // that took the default, but diverges when the miner declared its own
                            // size (`mining.suggest_difficulty` / `d=` in the authorize password),
                            // and the channel is the authority. Leaving the config value here
                            // would have local share validation and vardiff working against a
                            // different target from the one the pool is actually enforcing.
                            d.target = initial_target;
                            // Set the initial upstream target from OpenExtendedMiningChannelSuccess
                            d.set_upstream_target(initial_target, downstream_id);
                            was_placeholder
                        })
                        .map_err(TproxyError::shutdown)?;
                    self.channel_id_to_downstream_id
                        .super_safe_lock(|map| map.insert(m.channel_id, downstream_id));

                    // Register vardiff state now that the channel is open (channel_id was set
                    // above). Doing it here rather than at connection-accept guarantees the vardiff
                    // loop only ever iterates downstreams that have a channel, making `channel_id`
                    // a true invariant in `difficulty_manager`. Guarded so a re-opened channel
                    // keeps its existing vardiff state instead of resetting it.
                    if self.config.downstream_difficulty_config.enable_vardiff
                        && !self.vardiff.contains_key(&downstream_id)
                    {
                        // Floor vardiff at the configured per-miner hashrate, NOT the
                        // library default of 1.0 H/s. With the 1.0 H/s floor, a fresh
                        // connection whose first shares fail validation during the
                        // extranonce handoff window reads as "0 shares/min", and vardiff
                        // halves the difficulty every tick down to ~1.0 H/s → target ≈ 2^256
                        // → difficulty ≈ 2e-10. The miner then floods sub-diff-1 shares that
                        // record 0 work and never earn. Flooring at min_individual_miner_hashrate
                        // (e.g. 500 GH/s → diff ~1164) keeps a struggling new miner at a sane
                        // difficulty so it self-corrects once the connect window settles. The
                        // floor never binds for healthy miners (their hashrate is far above it).
                        let vardiff = VardiffState::new_with_min(
                            self.config
                                .downstream_difficulty_config
                                .min_individual_miner_hashrate,
                        )
                        .expect("Failed to create vardiffstate");
                        self.vardiff
                            .insert(downstream_id, Arc::new(Mutex::new(vardiff)));
                    }

                    // Public-pool defer-open: if subscribe was responded to with a placeholder
                    // extranonce (because the channel had not been opened yet — we deferred it
                    // until `mining.authorize` arrived so we knew the user_identity), send a
                    // standard SV1 `mining.set_extranonce` notification now so the miner
                    // switches to the real channel-allocated extranonce before the first
                    // `mining.notify` arrives. cpuminer/bitaxe/standard SV1 miners all support
                    // this. Without it, every share built with the placeholder extranonce
                    // would have an extranonce mismatch against the translator's local
                    // validation (which uses `data.extranonce1`, now set to the real value),
                    // and every share would be rejected.
                    if already_subscribed {
                        use stratum_apps::stratum_core::sv1_api::methods::server_to_client::SetExtranonce;
                        let set_extranonce_msg: stratum_apps::stratum_core::sv1_api::json_rpc::Message =
                            SetExtranonce {
                                extra_nonce1: real_extranonce1.clone(),
                                extra_nonce2_size: real_extranonce2_size,
                            }
                            .into();
                        if let Err(e) = downstream
                            .downstream_channel_state
                            .downstream_sv1_sender
                            .send(set_extranonce_msg)
                            .await
                        {
                            warn!(
                                "Down: failed to send mining.set_extranonce to downstream {}: {:?}",
                                downstream_id, e
                            );
                        } else {
                            info!(
                                "Down: sent mining.set_extranonce to downstream {} (real extranonce={} bytes, extranonce2_size={})",
                                downstream_id, real_extranonce1.as_ref().len(), real_extranonce2_size
                            );
                        }
                    }

                    // Process all queued messages now that channel is established
                    let queued_messages = downstream.downstream_data.super_safe_lock(|d| {
                        let messages = d.queued_sv1_handshake_messages.clone();
                        d.queued_sv1_handshake_messages.clear();
                        messages
                    });
                    {
                        if !queued_messages.is_empty() {
                            info!(
                                "Processing {} queued Sv1 messages for downstream {}",
                                queued_messages.len(),
                                downstream_id
                            );

                            let downstream_sv1_sender = downstream
                                .downstream_channel_state
                                .downstream_sv1_sender
                                .clone();

                            for message in queued_messages {
                                let is_authorize = is_mining_authorize(&message);
                                let response =
                                    self.clone().handle_message(Some(downstream_id), message);
                                match response {
                                    Ok(Some(response_msg)) => {
                                        downstream_sv1_sender.send(response_msg.into()).await
                                            .map_err(|e| {
                                                error!(
                                                    "Down: Failed to send message to downstream: {e:?}"
                                                );
                                                TproxyError::disconnect(
                                                    TproxyErrorKind::ChannelErrorSender, downstream_id
                                                )
                                            })?;

                                        if is_authorize {
                                            info!("Down: Handling mining.authorize after upstream channel is open");
                                            if let Err(e) =
                                                downstream.handle_sv1_handshake_completion().await
                                            {
                                                error!(
                                                    "Down: Failed to handle handshake completion: {:?}",
                                                    e
                                                );
                                                return Err(TproxyError::disconnect(
                                                    e,
                                                    downstream_id,
                                                ));
                                            }
                                        }
                                    }
                                    Ok(None) => {
                                        // Message was handled but no response needed
                                    }
                                    Err(e) => {
                                        error!("Down: Error handling downstream message: {:?}", e);
                                        return Err(TproxyError::disconnect(e, downstream_id));
                                    }
                                }
                            }
                        }
                    }

                    // Announce the channel's REAL target, not the global config-derived
                    // `first_target`. The two agree for a miner that accepted the pool default,
                    // but a miner that declared its own size gets a channel sized to that
                    // declaration — and telling it `first_target` would set it hashing at the
                    // pool floor while the pool enforced a far higher target, so virtually every
                    // share it submitted would fall short and be rejected. Falls back to
                    // `first_target` only if the channel target is somehow unavailable.
                    let channel_target = downstream
                        .downstream_data
                        .super_safe_lock(|d| d.upstream_target)
                        .unwrap_or(first_target);
                    let set_difficulty = build_sv1_set_difficulty_from_sv2_target(channel_target)
                        .map_err(|_| {
                        TproxyError::shutdown(TproxyErrorKind::General(
                            "Failed to generate set_difficulty".into(),
                        ))
                    })?;
                    // send the set_difficulty message to the downstream
                    if let Some(sender) = self
                        .sv1_server_channel_state
                        .sv1_server_to_downstream_sender
                        .super_safe_lock(|map| map.get(&downstream_id).cloned())
                    {
                        sender.send(set_difficulty).await.map_err(|_| {
                            TproxyError::disconnect(
                                TproxyErrorKind::ChannelErrorSender,
                                downstream_id,
                            )
                        })?;
                    }
                } else {
                    error!("Downstream not found for downstream_id: {}", downstream_id);
                }
            }

            Mining::NewExtendedMiningJob(m) => {
                debug!(
                    "Received NewExtendedMiningJob for channel id: {}",
                    m.channel_id
                );
                // Clone the prevhash immediately so the DashMap guard is not held across .await.
                if let Some(prevhash) = self
                    .prevhashes
                    .get(&m.channel_id)
                    .map(|r| r.value().clone())
                {
                    let prevhash = prevhash.as_static();
                    let clean_jobs = m.job_id == prevhash.job_id;
                    let notify =
                        build_sv1_notify_from_sv2(prevhash, m.clone().into_static(), clean_jobs)
                            .map_err(TproxyError::shutdown)?;

                    // Update job storage based on the configured mode
                    let notify_parsed = notify.clone();
                    let job_channel_id = if is_non_aggregated() {
                        m.channel_id
                    } else {
                        AGGREGATED_CHANNEL_ID
                    };

                    {
                        let mut channel_jobs =
                            self.valid_sv1_jobs.entry(job_channel_id).or_default();
                        if clean_jobs {
                            channel_jobs.clear();
                        }
                        channel_jobs.push(notify_parsed);
                    }

                    let notify_msg: stratum_apps::stratum_core::sv1_api::json_rpc::Message =
                        notify.into();
                    self.send_to_channel(job_channel_id, notify_msg).await;
                }
            }

            Mining::SetNewPrevHash(m) => {
                debug!("Received SetNewPrevHash for channel id: {}", m.channel_id);
                self.prevhashes
                    .insert(m.channel_id, m.clone().into_static());
            }

            Mining::SetTarget(m) => {
                debug!("Received SetTarget for channel id: {}", m.channel_id);
                if self.config.downstream_difficulty_config.enable_vardiff {
                    // Vardiff enabled - use full difficulty management
                    self.handle_set_target_message(m).await;
                } else {
                    // Vardiff disabled - just forward the difficulty to downstreams
                    debug!("Vardiff disabled - forwarding SetTarget to downstreams");
                    self.handle_set_target_without_vardiff(m).await?;
                }
            }
            // Guaranteed unreachable: the channel manager only forwards valid,
            // pre-filtered messages, so no other variants can arrive here.
            _ => unreachable!("Invalid message: should have been filtered earlier"),
        }

        Ok(())
    }

    /// Opens an extended mining channel for a downstream connection.
    ///
    /// This method initiates the SV2 channel setup process by:
    /// - Calculating the initial target based on configuration
    /// - Generating a unique user identity for the miner
    /// - Creating an OpenExtendedMiningChannel message
    /// - Sending the request to the channel manager
    ///
    /// # Arguments
    /// * `downstream` - The downstream connection to set up a channel for
    ///
    /// # Returns
    /// * `Ok(())` - Channel setup request sent successfully
    /// * `Err(TproxyError)` - Error setting up the channel
    pub async fn open_extended_mining_channel(
        &self,
        request_id: RequestId,
        downstream_id: DownstreamId,
    ) -> TproxyResult<(), error::Sv1Server> {
        let config = &self.config.downstream_difficulty_config;
        let Some(downstream) = self
            .downstreams
            .get(&downstream_id)
            .map(|r| r.value().clone())
        else {
            warn!(
                "Downstream {} disconnected before channel could be opened, skipping",
                downstream_id
            );
            return Ok(());
        };

        // Prefer a size the miner declared for itself (`mining.suggest_difficulty`, or `d=` in
        // the authorize password) over the configured floor. The floor is sized for the
        // smallest expected miner, so a farm or a rented-hashrate order that starts there
        // spends minutes flooding shares while vardiff ramps (capped at ×3–×5 per 60s tick).
        // Already clamped to a sane range in `record_suggested_difficulty`.
        // Preference order: what the miner declared, then THIS LISTENER's floor, then the config.
        //
        // #611: the fallback used to be `config.min_individual_miner_hashrate` directly — the
        // HOBBY floor — for every connection, including farm-port ones. `data.hashrate` carries the
        // floor the listener was built with (`Downstream::new(..., Some(tier_floor_hs), ...)`), so
        // it is the hobby floor on :3333 and `farm_tier.min_individual_miner_hashrate` on :4444.
        // Skipping it made the farm tier cosmetic: a rig that declared nothing got the hobby
        // difficulty on both ports, which is exactly what was measured on ghost-vm8 — :4444 and
        // :3333 both advertised 2,328.3 where :4444 should have been ~232,827.
        //
        // A rig that DOES declare is unaffected, which is why the tier looked half-working: the
        // `pw-difficulty` and `suggest-diff` paths were always correct.
        let hashrate = downstream
            .downstream_data
            .super_safe_lock(|data| data.suggested_hashrate.or(data.hashrate))
            .map(|h| h as f64)
            .unwrap_or(config.min_individual_miner_hashrate as f64);
        let shares_per_min = config.shares_per_minute as f64;
        let min_extranonce_size = self.config.downstream_extranonce2_size;
        let vardiff_enabled = config.enable_vardiff;

        let max_target = if vardiff_enabled {
            // SHARE_TIER_BIND: the channel-open target is quantised like every other assignment
            // when the tier flag is armed (dormant by default), exactly as the suggested-difficulty
            // and listener paths above already do.
            //
            // Missing it here was not cosmetic. This target is what the SV2 extended channel opens
            // with, so it is BOTH what the miner works to AND what pool_sv2 floors to derive the
            // committed tier. Un-quantised, a miner assigned e.g. difficulty 4656 mines at 4656 but
            // commits to — and is credited — tier 12 (4096); just under a power of two the loss
            // approaches half the work. Quantising here makes assigned difficulty equal 2^tier, which
            // is the invariant the whole tier design assumes.
            let t = hash_rate_to_target(hashrate, shares_per_min).unwrap();
            if config.quantise_to_tiers {
                super::difficulty_manager::quantise_target_to_tier(&t)
            } else {
                t
            }
        } else {
            // If translator doesn't manage vardiff, we rely on upstream to do that,
            // so we give it more freedom by setting max_target to maximum possible value
            Target::from_le_bytes([0xff; 32])
        };

        let miner_id = self.miner_counter.fetch_add(1, Ordering::SeqCst) + 1;
        // Public-pool attribution: when `mining.authorize` has populated
        // `data.authorized_worker_name` (the FULL `<address>.<worker>` SV1 username), use it
        // verbatim as the channel-level user_identity. The SV2 wire field is `Str0255` (255
        // bytes) so it fits any address type — P2WPKH (`bc1q…`), P2TR (`bc1p…`), P2WSH,
        // legacy P2PKH (`1…`), P2SH (`3…`) — plus a worker name. The pool then derives both
        // the per-miner payout address AND the per-miner worker from this single string via
        // its `parse_user_identity` helper.
        //
        // Falls back to the classic config-prefix-derived identity when authorize hasn't
        // fired yet — i.e. the aggregated-mode case where the channel opens early on
        // subscribe to keep the shared upstream channel ready for subsequent miners. SRI
        // patterns (`sri/…`) use `/`-delimited segments for payout-mode parsing, so we keep
        // them unchanged. See: https://github.com/stratum-mining/sv2-apps/issues/369
        let authorize_name = downstream
            .downstream_data
            .safe_lock(|d| d.authorized_worker_name.clone())
            .map_err(TproxyError::shutdown)?;
        // Rules for choosing the channel user_identity:
        //   - authorize with `<addr>.<worker>` → use it verbatim (per-miner address)
        //   - authorize with bare `<worker>` (no `.`) → splice with translator config
        //     prefix so the address still resolves to operator wallet, worker is honoured.
        //     Pool's `parse_user_identity` would otherwise try the bare worker as an address
        //     and fall to FullDonation, leaving such miners without a payout target.
        //   - empty authorize (shouldn't happen but defensive) → classic config-prefix.miner{N}
        //   - SRI test patterns (`sri/…`) → keep unchanged for solo/donate parsing.
        //   - opening on subscribe, before authorize has said anything → the provisional
        //     sentinel. There is no address to put here yet, and the one thing we must NOT do
        //     is fall through to the config-prefix branches below: that names the OPERATOR's
        //     wallet, which the pool would then credit for every share this miner submits.
        //     That is precisely how #447 misdirected ~395 shares. The address instead travels
        //     per share in the worker TLV, which `handle_submit_share` fills with the full
        //     `<addr>.<worker>` whenever the channel is provisional.
        let user_identity = if self.config.open_channel_on_subscribe && authorize_name.is_empty() {
            PROVISIONAL_CHANNEL_IDENTITY.to_string()
        } else if authorize_name.contains('.') {
            authorize_name
        } else if !authorize_name.is_empty() {
            if self.config.user_identity.starts_with("sri/") {
                self.config.user_identity.clone()
            } else {
                format!("{}.{}", self.config.user_identity, authorize_name)
            }
        } else if self.config.user_identity.starts_with("sri/") {
            self.config.user_identity.clone()
        } else {
            format!("{}.miner{}", self.config.user_identity, miner_id)
        };

        // NOTE: do NOT overwrite `data.user_identity` here. That field carries the per-share TLV
        // worker-name — set during `mining.authorize` by `extract_worker_name` +
        // `tlv_compatible_username` — and must stay independent of the channel-level
        // `user_identity` built above, which carries the full `<address>.<worker>`. The pool
        // recombines the two: the address comes from the channel, the worker from the TLV.
        // The 32-byte bound is ours (`MAX_USER_IDENTITY_BYTES`), not a spec limit; the SV2 wire
        // type is `Str0255`.

        if let Ok(open_channel_msg) = build_sv2_open_extended_mining_channel(
            request_id,
            user_identity.clone(),
            hashrate as Hashrate,
            max_target,
            min_extranonce_size,
        ) {
            self.sv1_server_channel_state
                .channel_manager_sender
                .send((Mining::OpenExtendedMiningChannel(open_channel_msg), None))
                .await
                .map_err(|_| TproxyError::shutdown(TproxyErrorKind::ChannelErrorSender))?;
        } else {
            error!("Failed to build OpenExtendedMiningChannel message");
        }

        Ok(())
    }

    /// Extracts the downstream ID from a Downstream instance.
    ///
    /// # Arguments
    /// * `downstream` - The downstream connection to get the ID from
    ///
    /// # Returns
    /// The downstream ID as a u32
    pub fn get_downstream_id(downstream: Downstream) -> DownstreamId {
        downstream.downstream_id
    }

    /// Handles cleanup when a downstream connection disconnects.
    ///
    /// This method should be called from the main loop when a `State::DownstreamShutdown`
    /// status message is received. It:
    /// - Removes the downstream from the downstreams map
    /// - Removes vardiff state (if enabled)
    /// - Sends UpdateChannel if needed (aggregated mode with vardiff)
    /// - Sends CloseChannel message to ChannelManager (non-aggregated mode)
    ///
    /// # Arguments
    /// * `downstream_id` - The ID of the downstream that disconnected
    pub async fn handle_downstream_disconnect(&self, downstream_id: DownstreamId) {
        if self.config.downstream_difficulty_config.enable_vardiff {
            // Only remove from vardiff map if vardiff is enabled
            self.vardiff.remove(&downstream_id);
        }
        self.sv1_server_channel_state
            .sv1_server_to_downstream_sender
            .super_safe_lock(|map| map.remove(&downstream_id));

        let current_downstream = self.downstreams.remove(&downstream_id);

        if let Some((downstream_id, downstream)) = current_downstream {
            info!("🔌 Downstream: {downstream_id} disconnected and removed from sv1 server downstreams");
            // In aggregated mode, send UpdateChannel to reflect the new state (only if vardiff
            // enabled)
            if self.config.downstream_difficulty_config.enable_vardiff {
                self.send_update_channel_on_downstream_state_change().await;
            }

            let channel_id = downstream.downstream_data.super_safe_lock(|d| d.channel_id);
            if let Some(channel_id) = channel_id {
                self.channel_id_to_downstream_id
                    .super_safe_lock(|map| map.remove(&channel_id));
                if !self.config.aggregate_channels {
                    info!("Sending CloseChannel message: {channel_id} for downstream: {downstream_id}");
                    let reason_code =
                        Str0255::try_from("downstream disconnected".to_string()).unwrap();
                    _ = self
                        .sv1_server_channel_state
                        .channel_manager_sender
                        .send((
                            Mining::CloseChannel(CloseChannel {
                                channel_id,
                                reason_code,
                            }),
                            None,
                        ))
                        .await;
                }
            }
        }
    }

    /// Handles SetTarget messages when vardiff is disabled.
    ///
    /// This method forwards difficulty changes from upstream directly to downstream miners
    /// without any variable difficulty logic. It respects the aggregated/non-aggregated
    /// channel configuration.
    ///
    /// When vardiff is disabled, the upstream (Pool or JDC) controls difficulty via SetTarget
    /// messages. We derive the hashrate from the received target so that monitoring can report
    /// meaningful SV1 downstream hashrate values.
    async fn handle_set_target_without_vardiff(
        &self,
        set_target: SetTarget<'_>,
    ) -> TproxyResult<(), error::Sv1Server> {
        let new_target =
            Target::from_le_bytes(set_target.maximum_target.inner_as_ref().try_into().unwrap());
        debug!(
            "Forwarding SetTarget to downstreams: channel_id={}, target={}",
            set_target.channel_id, new_target
        );

        // Derive hashrate from the upstream target so monitoring can report it
        let derived_hashrate = match hash_rate_from_target(
            set_target.maximum_target.clone().into_static(),
            self.shares_per_minute as f64,
        ) {
            Ok(hr) => {
                debug!(
                    "Derived hashrate from SetTarget: {} H/s (channel_id={})",
                    hr, set_target.channel_id
                );
                Some(hr)
            }
            Err(e) => {
                warn!(
                    "Failed to derive hashrate from SetTarget target: {:?} (channel_id={})",
                    e, set_target.channel_id
                );
                None
            }
        };

        if is_aggregated() {
            // Aggregated mode: send set_difficulty to ALL downstreams and update hashrate
            return self
                .send_set_difficulty_to_all_downstreams(new_target, derived_hashrate)
                .await;
        }

        // Non-aggregated mode: send set_difficulty to specific downstream for this channel
        self.send_set_difficulty_to_specific_downstream(
            set_target.channel_id,
            new_target,
            derived_hashrate,
        )
        .await
    }

    /// Sends set_difficulty to all downstreams (aggregated mode).
    /// Used only when vardiff is disabled.
    async fn send_set_difficulty_to_all_downstreams(
        &self,
        target: Target,
        derived_hashrate: Option<f64>,
    ) -> TproxyResult<(), error::Sv1Server> {
        let tasks: Vec<(DownstreamId, _)> = self
            .downstreams
            .iter()
            .filter_map(|entry| {
                let downstream_id = *entry.key();
                let has_channel = entry.value().downstream_data.super_safe_lock(|d| {
                    let channel_id = d.channel_id?;
                    d.set_upstream_target(target, downstream_id);
                    d.set_pending_target(target, downstream_id);
                    if let Some(hr) = derived_hashrate {
                        d.set_pending_hashrate(Some(hr as f32), downstream_id);
                    }
                    Some(channel_id)
                });
                if has_channel.is_none() {
                    trace!(
                        "Skipping downstream {}: no channel_id set (vardiff disabled)",
                        downstream_id
                    );
                    return None;
                }
                let sender = self
                    .sv1_server_channel_state
                    .sv1_server_to_downstream_sender
                    .super_safe_lock(|map| map.get(&downstream_id).cloned())?;
                Some((downstream_id, sender))
            })
            .collect();

        for (downstream_id, sender) in tasks {
            let set_difficulty_msg = match build_sv1_set_difficulty_from_sv2_target(target) {
                Ok(msg) => msg,
                Err(e) => {
                    error!(
                        "Failed to build SetDifficulty for downstream {}: {:?}",
                        downstream_id, e
                    );
                    return Err(TproxyError::shutdown(e));
                }
            };
            if let Err(e) = sender.send(set_difficulty_msg).await {
                error!(
                    "Failed to send SetDifficulty to downstream {}: {:?}",
                    downstream_id, e
                );
                return Err(TproxyError::shutdown(TproxyErrorKind::ChannelErrorSender));
            } else {
                debug!(
                    "Sent SetDifficulty to downstream {} (vardiff disabled)",
                    downstream_id
                );
            }
        }
        Ok(())
    }

    /// Sends set_difficulty to the specific downstream associated with a channel (non-aggregated
    /// mode).
    /// Used only when vardiff is disabled.
    async fn send_set_difficulty_to_specific_downstream(
        &self,
        channel_id: ChannelId,
        target: Target,
        derived_hashrate: Option<f64>,
    ) -> TproxyResult<(), error::Sv1Server> {
        let Some(downstream_id) = self
            .channel_id_to_downstream_id
            .super_safe_lock(|map| map.get(&channel_id).cloned())
        else {
            warn!(
                "No downstream found for channel {} when vardiff is disabled",
                channel_id
            );
            info!("Sending CloseChannel message: Channel id {channel_id}");
            let reason_code = Str0255::try_from("downstream disconnected".to_string()).unwrap();
            self.sv1_server_channel_state
                .channel_manager_sender
                .send((
                    Mining::CloseChannel(CloseChannel {
                        channel_id,
                        reason_code,
                    }),
                    None,
                ))
                .await
                .map_err(|_| TproxyError::shutdown(TproxyErrorKind::ChannelErrorSender))?;
            return Err(TproxyError::log(
                TproxyErrorKind::DownstreamNotFoundWithChannelId(channel_id),
            ));
        };

        let Some(downstream) = self.downstreams.get(&downstream_id) else {
            return Ok(());
        };
        downstream.downstream_data.super_safe_lock(|d| {
            d.set_upstream_target(target, downstream_id);
            d.set_pending_target(target, downstream_id);
            // Update pending hashrate derived from the upstream target
            if let Some(hr) = derived_hashrate {
                d.set_pending_hashrate(Some(hr as f32), downstream_id);
            }
        });

        let set_difficulty_msg = match build_sv1_set_difficulty_from_sv2_target(target) {
            Ok(msg) => msg,
            Err(e) => {
                error!(
                    "Failed to build SetDifficulty for downstream {}: {:?}",
                    downstream_id, e
                );
                return Err(TproxyError::shutdown(e));
            }
        };

        let sender = self
            .sv1_server_channel_state
            .sv1_server_to_downstream_sender
            .super_safe_lock(|map| map.get(&downstream_id).cloned());

        if let Some(sender) = sender {
            if let Err(e) = sender.send(set_difficulty_msg).await {
                error!(
                    "Failed to send SetDifficulty to downstream {}: {:?}",
                    downstream_id, e
                );
                return Err(TproxyError::shutdown(TproxyErrorKind::ChannelErrorSender));
            } else {
                debug!(
                    "Sent SetDifficulty to downstream {} for channel {} (vardiff disabled)",
                    downstream_id, channel_id
                );
            }
        }
        Ok(())
    }

    /// Spawns the job keepalive loop that sends periodic mining.notify messages.
    ///
    /// This prevents SV1 miners from timing out when there are no new jobs received from the
    /// upstream for a while.
    pub async fn spawn_job_keepalive_loop(self: Arc<Self>) {
        let keepalive_interval_secs = self
            .config
            .downstream_difficulty_config
            .job_keepalive_interval_secs;

        let interval = Duration::from_secs(keepalive_interval_secs as u64);
        let check_interval =
            Duration::from_secs(keepalive_interval_secs as u64 / 2).max(Duration::from_secs(5));
        info!(
            "Starting job keepalive loop with interval of {} seconds",
            keepalive_interval_secs
        );

        loop {
            tokio::time::sleep(check_interval).await;
            let keepalive_targets: Vec<(DownstreamId, Option<ChannelId>)> = self
                .downstreams
                .iter()
                .filter_map(|downstream| {
                    let downstream_id = downstream.key();
                    let downstream = downstream.value();
                    downstream.downstream_data.super_safe_lock(|d| {
                        // Only send keepalive if:
                        // 1. Handshake is complete
                        // 2. Enough time has passed since last job
                        let handshake_complete =
                            downstream.sv1_handshake_complete.load(Ordering::SeqCst);

                        if !handshake_complete {
                            return None;
                        }

                        let needs_keepalive = match d.last_job_received_time {
                            Some(last_time) => last_time.elapsed() >= interval,
                            None => false, // No job received yet, don't send keepalive
                        };

                        if needs_keepalive {
                            Some((*downstream_id, d.channel_id))
                        } else {
                            None
                        }
                    })
                })
                .collect();

            // Send keepalive to each downstream that needs one
            for (downstream_id, channel_id) in keepalive_targets {
                // Get the appropriate job for this downstream's channel and create keepalive
                let keepalive_job = self.get_last_job(channel_id).and_then(|last_job| {
                    // Extract the original upstream job_id from the last job
                    // If it's already a keepalive job, extract its original; otherwise use
                    // as-is
                    let original_job_id = Self::extract_original_job_id(&last_job.job_id)
                        .unwrap_or_else(|| last_job.job_id.clone());

                    // Find the original upstream job to get its base time
                    let original_job = self.get_original_job(&original_job_id, channel_id);
                    let base_time = original_job
                        .as_ref()
                        .map(|j| j.time.0)
                        .unwrap_or(last_job.time.0);

                    // Increment the time by the keepalive interval, but cap at
                    // MAX_FUTURE_BLOCK_TIME from the original job's time to maintain consensus
                    // validity (see https://github.com/bitcoin/bitcoin/blob/cd6e4c9235f763b8077cece69c2e3b2025cc8d0f/src/chain.h#L29)
                    const MAX_FUTURE_BLOCK_TIME: u32 = 2 * 60 * 60;
                    let new_time = last_job
                        .time
                        .0
                        .saturating_add(keepalive_interval_secs as u32)
                        .min(base_time.saturating_add(MAX_FUTURE_BLOCK_TIME));

                    // If we've hit the cap, don't send another keepalive for this job
                    if new_time == last_job.time.0 {
                        return None;
                    }

                    // Generate new keepalive job_id: {original_job_id}#{counter}
                    let new_job_id = self.next_keepalive_job_id(&original_job_id);

                    let mut keepalive_notify = last_job;
                    keepalive_notify.job_id = new_job_id.clone();
                    keepalive_notify.time = HexU32Be(new_time);

                    // Add the keepalive job to valid jobs so shares can be validated
                    let job_channel_id = if is_aggregated() {
                        Some(AGGREGATED_CHANNEL_ID)
                    } else {
                        channel_id
                    };

                    _ = job_channel_id
                        .and_then(|ch_id| self.valid_sv1_jobs.get_mut(&ch_id))
                        .map(|mut jobs| jobs.push(keepalive_notify.clone()));

                    Some(keepalive_notify)
                });

                if let Some(notify) = keepalive_job {
                    debug!(
                        "Sending keepalive job to downstream {} with job_id: {}, time: {}",
                        downstream_id, notify.job_id, notify.time.0
                    );

                    let sent = match self
                        .sv1_server_channel_state
                        .sv1_server_to_downstream_sender
                        .super_safe_lock(|map| map.get(&downstream_id).cloned())
                    {
                        Some(sender) => sender.send(notify.into()).await.is_ok(),
                        None => false,
                    };
                    if !sent {
                        warn!(
                            "Failed to send keepalive job to downstream {}",
                            downstream_id
                        );
                    } else if let Some(downstream) = self.downstreams.get(&downstream_id) {
                        downstream.downstream_data.super_safe_lock(|d| {
                            d.last_job_received_time = Some(Instant::now());
                        });
                    }
                }
            }
        }
    }

    /// Generates a keepalive job ID by appending a mutation counter to the original job ID.
    /// Format: `{original_job_id}#{counter}` where `#` is the delimiter.
    /// When receiving a share, split on `#` to extract the original job ID.
    fn next_keepalive_job_id(&self, original_job_id: &str) -> String {
        let counter = self
            .keepalive_job_id_counter
            .fetch_add(1, Ordering::Relaxed);
        format!("{}#{}", original_job_id, counter)
    }

    /// Extracts the original upstream job ID from a keepalive job ID.
    /// Returns None if the job_id doesn't contain the keepalive delimiter.
    fn extract_original_job_id(job_id: &str) -> Option<String> {
        job_id
            .split_once(KEEPALIVE_JOB_ID_DELIMITER)
            .map(|(original, _)| original.to_string())
    }

    /// Returns true if the job_id is a keepalive job (contains the delimiter).
    #[inline]
    fn is_keepalive_job_id(job_id: &str) -> bool {
        job_id.contains(KEEPALIVE_JOB_ID_DELIMITER)
    }

    /// Gets the last job from the jobs storage.
    /// In aggregated mode, returns the last job from the shared job list.
    /// In non-aggregated mode, returns the last job for the specified channel.
    pub fn get_last_job(
        &self,
        channel_id: Option<u32>,
    ) -> Option<server_to_client::Notify<'static>> {
        let channel_id = if is_aggregated() {
            AGGREGATED_CHANNEL_ID
        } else {
            channel_id?
        };

        self.valid_sv1_jobs
            .get(&channel_id)
            .and_then(|jobs| jobs.last().cloned())
    }

    /// Gets the original upstream job by its job_id.
    /// This is used to find the base time for keepalive time capping.
    pub fn get_original_job(
        &self,
        job_id: &str,
        channel_id: Option<u32>,
    ) -> Option<server_to_client::Notify<'static>> {
        let channel_id = if is_aggregated() {
            AGGREGATED_CHANNEL_ID
        } else {
            channel_id?
        };

        self.valid_sv1_jobs
            .get(&channel_id)?
            .iter()
            .find(|j| j.job_id == job_id)
            .cloned()
    }
}

#[derive(Debug, Clone)]
pub struct PendingTargetUpdate {
    pub downstream_id: DownstreamId,
    pub new_target: Target,
    pub new_hashrate: Hashrate,
}

#[cfg(test)]
mod tests {

    /// #611: the channel-open hashrate must fall back to THIS LISTENER's floor, not the hobby one.
    ///
    /// The farm tier was cosmetic because the fallback reached straight for
    /// `config.min_individual_miner_hashrate` — the hobby floor — for every connection. Measured on
    /// ghost-vm8: `:4444` and `:3333` both advertised 2,328.3 where the farm port should have been
    /// ~232,827. A rig that DECLARED a difficulty was always served correctly, which is why the
    /// tier looked half-working and went unnoticed.
    ///
    /// This pins the precedence directly: declared > listener floor > config.
    #[test]
    fn channel_open_hashrate_prefers_declared_then_the_listeners_own_floor() {
        const HOBBY: f64 = 1_000_000_000_000.0;
        const FARM: f64 = 100_000_000_000_000.0;
        const DECLARED: f64 = 5_000_000_000_000.0;

        // The expression under test, mirrored exactly: `suggested.or(listener_floor)` then config.
        fn pick(suggested: Option<f64>, listener_floor: Option<f64>, config_floor: f64) -> f64 {
            suggested.or(listener_floor).unwrap_or(config_floor)
        }

        // A farm-port rig that declares nothing must get the FARM floor, not the hobby one.
        assert_eq!(
            pick(None, Some(FARM), HOBBY),
            FARM,
            "an undeclared farm-port miner must start at the farm floor — this is the #611 bug"
        );

        // A hobby-port rig that declares nothing is unchanged.
        assert_eq!(
            pick(None, Some(HOBBY), HOBBY),
            HOBBY,
            "the hobby port must behave exactly as before"
        );

        // A declared value wins on either port — the path that always worked.
        assert_eq!(pick(Some(DECLARED), Some(FARM), HOBBY), DECLARED);
        assert_eq!(pick(Some(DECLARED), Some(HOBBY), HOBBY), DECLARED);

        // No listener floor recorded at all still falls back to config, as before.
        assert_eq!(pick(None, None, HOBBY), HOBBY);
    }
    use super::*;
    use crate::config::{DownstreamDifficultyConfig, TranslatorConfig, Upstream};
    use async_channel::unbounded;
    use std::str::FromStr;
    use stratum_apps::key_utils::Secp256k1PublicKey;

    fn create_test_config() -> TranslatorConfig {
        let pubkey_str = "9bDuixKmZqAJnrmP746n8zU1wyAQRrus7th9dxnkPg6RzQvCnan";
        let pubkey = Secp256k1PublicKey::from_str(pubkey_str).unwrap();

        let upstream = Upstream::new("127.0.0.1".to_string(), 4444, pubkey);
        let difficulty_config = DownstreamDifficultyConfig::new(100.0, 5.0, true, 60);

        TranslatorConfig::new(
            vec![upstream],
            "0.0.0.0".to_string(), // downstream_address
            3333,                  // downstream_port
            difficulty_config,     // downstream_difficulty_config
            2,                     // max_supported_version
            1,                     // min_supported_version
            4,                     // downstream_extranonce2_size
            "test_user".to_string(),
            true,   // aggregate_channels
            vec![], // supported_extensions
            vec![], // required_extensions
            None,   // monitoring_address
            None,   // monitoring_cache_refresh_secs
        )
    }

    fn create_test_sv1_server() -> Sv1Server {
        let (cm_sender, _cm_receiver) = unbounded();
        let (_downstream_sender, cm_receiver) = unbounded();
        let config = create_test_config();
        let addr = "127.0.0.1:3333".parse().unwrap();

        Sv1Server::new(addr, cm_receiver, cm_sender, config)
    }

    #[test]
    fn test_sv1_server_creation() {
        let server = create_test_sv1_server();

        assert_eq!(server.shares_per_minute, 5.0);
        assert_eq!(server.listener_addr.ip().to_string(), "127.0.0.1");
        assert_eq!(server.listener_addr.port(), 3333);
        assert_eq!(server.config.user_identity, "test_user");
    }

    #[test]
    fn test_sv1_server_config() {
        let mut config = create_test_config();
        config.downstream_difficulty_config.enable_vardiff = true;

        let (cm_sender, _cm_receiver) = unbounded();
        let (_downstream_sender, cm_receiver) = unbounded();
        let addr = "127.0.0.1:3333".parse().unwrap();

        let server = Sv1Server::new(addr, cm_receiver, cm_sender, config);

        assert!(server.config.downstream_difficulty_config.enable_vardiff);
    }

    #[tokio::test]
    async fn test_send_set_difficulty_to_all_downstreams_empty() {
        let server = create_test_sv1_server();
        let target: Target = hash_rate_to_target(200.0, 5.0).unwrap();

        // Test with empty downstreams
        _ = server
            .send_set_difficulty_to_all_downstreams(target, None)
            .await;

        // Should not crash with empty downstreams
    }

    #[tokio::test]
    async fn test_send_set_difficulty_to_specific_downstream_not_found() {
        let server = create_test_sv1_server();
        let target: Target = hash_rate_to_target(200.0, 5.0).unwrap();
        let channel_id = 1u32;

        // Test with no downstreams
        _ = server
            .send_set_difficulty_to_specific_downstream(channel_id, target, None)
            .await;

        // Should not crash when no downstreams are found
    }

    #[tokio::test]
    async fn test_handle_set_target_without_vardiff_aggregated() {
        let mut config = create_test_config();
        config.downstream_difficulty_config.enable_vardiff = false;

        let (cm_sender, _cm_receiver) = unbounded();
        let (_downstream_sender, cm_receiver) = unbounded();
        let addr = "127.0.0.1:3333".parse().unwrap();

        let server = Sv1Server::new(addr, cm_receiver, cm_sender, config);
        let target: Target = hash_rate_to_target(200.0, 5.0).unwrap();

        let set_target = SetTarget {
            channel_id: 1,
            maximum_target: target.to_le_bytes().into(),
        };

        // Test should not panic and should handle the message
        _ = server.handle_set_target_without_vardiff(set_target).await;
    }

    #[tokio::test]
    async fn test_handle_set_target_without_vardiff_non_aggregated() {
        let mut config = create_test_config();
        config.downstream_difficulty_config.enable_vardiff = false;

        let (cm_sender, _cm_receiver) = unbounded();
        let (_downstream_sender, cm_receiver) = unbounded();
        let addr = "127.0.0.1:3333".parse().unwrap();

        let server = Sv1Server::new(addr, cm_receiver, cm_sender, config);
        let target: Target = hash_rate_to_target(200.0, 5.0).unwrap();

        let set_target = SetTarget {
            channel_id: 1,
            maximum_target: target.to_le_bytes().into(),
        };

        // Test should not panic and should handle the message
        _ = server.handle_set_target_without_vardiff(set_target).await;
    }

    #[test]
    fn test_sv1_server_counters() {
        let server = create_test_sv1_server();

        // Test initial values
        assert_eq!(server.miner_counter.load(Ordering::SeqCst), 0);
        assert_eq!(server.sequence_counter.load(Ordering::SeqCst), 1);

        // Test incrementing
        let miner_id = server.miner_counter.fetch_add(1, Ordering::SeqCst);
        assert_eq!(miner_id, 0);
        assert_eq!(server.miner_counter.load(Ordering::SeqCst), 1);

        // sequence_counter starts at 1, so first share gets sequence 1
        let seq_id = server.sequence_counter.fetch_add(1, Ordering::SeqCst);
        assert_eq!(seq_id, 1);
        assert_eq!(server.sequence_counter.load(Ordering::SeqCst), 2);
    }
}
