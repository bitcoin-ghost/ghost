use std::sync::Arc;
mod common_message_handler;
use async_channel::{unbounded, Receiver, Sender};
use bitcoin_core_sv2::template_distribution_protocol::CancellationToken;
use stratum_apps::{
    key_utils::Secp256k1PublicKey,
    network_helpers::{self, connect_with_noise, resolve_host_port},
    stratum_core::{
        framing_sv2,
        handlers_sv2::HandleCommonMessagesFromServerAsync,
        parsers_sv2::{AnyMessage, TemplateDistribution},
    },
    task_manager::TaskManager,
    utils::{
        protocol_message_type::{protocol_message_type, MessageType},
        types::{Message, Sv2Frame},
    },
};
use tokio::net::TcpStream;
use tracing::{debug, error, info, warn};

use crate::{
    error::{self, Action, PoolError, PoolErrorKind, PoolResult},
    io_task::spawn_io_tasks,
    utils::get_setup_connection_message_tp,
};

#[derive(Clone)]
pub struct Sv2TpChannel {
    channel_manager_sender: Sender<TemplateDistribution<'static>>,
    channel_manager_receiver: Receiver<TemplateDistribution<'static>>,
    tp_sender: Sender<Sv2Frame>,
    tp_receiver: Receiver<Sv2Frame>,
}

#[derive(Clone)]
pub struct Sv2Tp {
    sv2_tp_channel: Sv2TpChannel,
    /// Retained so the session can be re-established without tearing down the pool.
    tp_address: String,
    public_key: Option<Secp256k1PublicKey>,
    task_manager: Arc<TaskManager>,
    /// Last `CoinbaseOutputConstraints` sent upstream, replayed after a reconnect.
    ///
    /// The channel manager sends this exactly once, at its own startup, and the template
    /// provider will not emit templates until it has it. A reconnected session is a fresh
    /// session from the TP's point of view, so without replaying this the pool would come
    /// back up and then sit silent, receiving no work.
    last_coinbase_constraints: Arc<std::sync::Mutex<Option<TemplateDistribution<'static>>>>,
}

#[cfg_attr(not(test), hotpath::measure_all)]
impl Sv2Tp {
    /// Establish a new connection to a Sv2 Template Provider.
    ///
    /// - Opens a TCP connection
    /// - Performs Noise handshake
    /// - Spawns IO tasks for inbound/outbound frames
    ///
    /// Retries up to 3 times before returning [`PoolError::Shutdown`].
    pub async fn new(
        tp_address: String,
        public_key: Option<Secp256k1PublicKey>,
        channel_manager_receiver: Receiver<TemplateDistribution<'static>>,
        channel_manager_sender: Sender<TemplateDistribution<'static>>,
        cancellation_token: CancellationToken,
        task_manager: Arc<TaskManager>,
    ) -> PoolResult<Sv2Tp, error::TemplateProvider> {
        const MAX_RETRIES: usize = 3;

        for attempt in 1..=MAX_RETRIES {
            info!(attempt, MAX_RETRIES, "Connecting to template provider");

            match TcpStream::connect(tp_address.as_str()).await {
                Ok(stream) => {
                    info!(
                        attempt,
                        "TCP connection established, starting Noise handshake"
                    );

                    tokio::select! {
                        result = connect_with_noise(stream, public_key) => {
                            match result {
                                Ok(noise_stream) => {
                                    info!(attempt, "Noise handshake completed successfully");

                                    let (noise_stream_reader, noise_stream_writer) =
                                        noise_stream.into_split();

                                    let (inbound_tx, inbound_rx) = unbounded::<Sv2Frame>();
                                    let (outbound_tx, outbound_rx) = unbounded::<Sv2Frame>();

                                    info!(attempt, "Spawning IO tasks for template receiver");

                                    spawn_io_tasks(
                                        task_manager.clone(),
                                        noise_stream_reader,
                                        noise_stream_writer,
                                        outbound_rx,
                                        inbound_tx,
                                        cancellation_token.clone(),
                                    );

                                    let template_receiver_channel = Sv2TpChannel {
                                        channel_manager_receiver,
                                        channel_manager_sender,
                                        tp_receiver: inbound_rx,
                                        tp_sender: outbound_tx,
                                    };

                                    info!(attempt, "TemplateReceiver initialized successfully");
                                    return Ok(Sv2Tp {
                                        sv2_tp_channel: template_receiver_channel,
                                        tp_address: tp_address.clone(),
                                        public_key,
                                        task_manager: task_manager.clone(),
                                        last_coinbase_constraints: Arc::new(
                                            std::sync::Mutex::new(None),
                                        ),
                                    });
                                }
                                Err(network_helpers::Error::InvalidKey) => {
                                    return Err(PoolError::shutdown(PoolErrorKind::InvalidKey))
                                }
                                Err(e) => {
                                    error!(attempt, error = ?e, "Noise handshake failed");
                                }
                            }
                        }
                        _ = cancellation_token.cancelled() => {
                            info!("Shutdown received during handshake, dropping connection");
                            return Err(PoolError::shutdown(PoolErrorKind::CouldNotInitiateSystem))
                        }
                    }
                }
                Err(e) => {
                    warn!(attempt, MAX_RETRIES, error = ?e, "Failed to connect to template provider");
                }
            }

            if attempt < MAX_RETRIES {
                debug!(attempt, "Retrying connection after backoff");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }

        error!("Exhausted all connection attempts, shutting down TemplateReceiver");
        Err(PoolError::shutdown(PoolErrorKind::CouldNotInitiateSystem))
    }

    /// Re-establish the template-provider session in place, without tearing down the pool.
    ///
    /// A dropped TP connection used to be fatal: the reader task closed the inbound channel,
    /// the message loop saw `Action::Shutdown` and cancelled the global token, the process
    /// exited and systemd restarted it — roughly 15s during which every miner on the node was
    /// disconnected. Three nodes were doing this hourly, on the hour, because the TDP
    /// connection has a fixed lifetime. Losing the TP is a transient upstream condition and
    /// belongs in a reconnect loop, not a process exit.
    ///
    /// Restores the full session: new TCP + Noise, fresh IO tasks, `SetupConnection`, then a
    /// replay of the cached `CoinbaseOutputConstraints` — without which the TP accepts the
    /// connection but never sends a template, leaving the pool up and idle.
    async fn reconnect(
        &mut self,
        cancellation_token: &CancellationToken,
    ) -> PoolResult<(), error::TemplateProvider> {
        const MAX_RECONNECT_ATTEMPTS: usize = 10;

        for attempt in 1..=MAX_RECONNECT_ATTEMPTS {
            if cancellation_token.is_cancelled() {
                return Err(PoolError::shutdown(PoolErrorKind::CouldNotInitiateSystem));
            }
            info!(
                attempt,
                MAX_RECONNECT_ATTEMPTS, "Reconnecting to template provider"
            );

            match TcpStream::connect(self.tp_address.as_str()).await {
                Ok(stream) => match connect_with_noise(stream, self.public_key).await {
                    Ok(noise_stream) => {
                        let (reader, writer) = noise_stream.into_split();
                        let (inbound_tx, inbound_rx) = unbounded::<Sv2Frame>();
                        let (outbound_tx, outbound_rx) = unbounded::<Sv2Frame>();
                        spawn_io_tasks(
                            self.task_manager.clone(),
                            reader,
                            writer,
                            outbound_rx,
                            inbound_tx,
                            cancellation_token.clone(),
                        );
                        self.sv2_tp_channel.tp_receiver = inbound_rx;
                        self.sv2_tp_channel.tp_sender = outbound_tx;

                        let addr = self.tp_address.clone();
                        if let Err(e) = self.setup_connection(addr).await {
                            warn!(attempt, error = ?e, "Handshake failed on reconnect");
                        } else {
                            // Re-prime the TP, or it will never send us a template.
                            let cached = self
                                .last_coinbase_constraints
                                .lock()
                                .ok()
                                .and_then(|slot| slot.clone());
                            if let Some(constraints) = cached {
                                let message =
                                    AnyMessage::TemplateDistribution(constraints).into_static();
                                match Sv2Frame::try_from(message) {
                                    Ok(frame) => {
                                        if let Err(e) =
                                            self.sv2_tp_channel.tp_sender.send(frame).await
                                        {
                                            warn!(error = ?e, "Failed to replay coinbase constraints");
                                            continue;
                                        }
                                        info!("Replayed CoinbaseOutputConstraints after reconnect");
                                    }
                                    Err(e) => {
                                        warn!(error = ?e, "Failed to encode cached coinbase constraints")
                                    }
                                }
                            } else {
                                warn!(
                                    "No cached CoinbaseOutputConstraints to replay — the template \
                                     provider may not send templates until the channel manager \
                                     resends them"
                                );
                            }
                            info!(attempt, "Template provider session re-established");
                            return Ok(());
                        }
                    }
                    Err(network_helpers::Error::InvalidKey) => {
                        error!("Template provider key invalid — not retrying");
                        return Err(PoolError::shutdown(PoolErrorKind::InvalidKey));
                    }
                    Err(e) => warn!(attempt, error = ?e, "Noise handshake failed on reconnect"),
                },
                Err(e) => warn!(attempt, error = ?e, "TCP connect failed on reconnect"),
            }

            // Linear backoff, capped — the TP is usually back within a few seconds.
            let delay = std::cmp::min(attempt as u64, 5);
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
        }

        error!("Exhausted template-provider reconnect attempts");
        Err(PoolError::shutdown(PoolErrorKind::CouldNotInitiateSystem))
    }

    /// Start unified message loop for Sv2Tp.
    ///
    /// Responsibilities:
    /// - Run handshake (`setup_connection`)
    /// - Handle:
    ///   - Messages from Template Provider
    ///   - Messages from ChannelManager
    ///   - Shutdown signals (upstream/job-declarator fallback)
    pub async fn start(
        mut self,
        socket_address: String,
        cancellation_token: CancellationToken,
        task_manager: Arc<TaskManager>,
    ) -> PoolResult<(), error::TemplateProvider> {
        info!("Initialized state for starting template receiver");
        self.setup_connection(socket_address).await?;

        info!("Setup Connection done. connection with template receiver is now done");
        task_manager.spawn(async move {
            loop {
                let mut self_clone_1 = self.clone();
                let self_clone_2 = self.clone();
                tokio::select! {
                    _ = cancellation_token.cancelled() => {
                        info!("Template Receiver: received shutdown signal");
                        break;
                    }
                    res = self_clone_1.handle_template_provider_message() => {
                        if let Err(e) = res {
                            error!("TemplateReceiver template provider handler failed: {e:?}");
                            match e.action {
                                Action::Shutdown => {
                                    // Losing the TP is transient — reconnect in place rather
                                    // than cancelling the global token and taking the whole
                                    // pool (and every miner on it) down with us. Only if
                                    // reconnection is genuinely exhausted do we fall through to
                                    // the old fatal behaviour.
                                    warn!("Template provider connection lost — attempting to reconnect");
                                    match self.reconnect(&cancellation_token).await {
                                        Ok(()) => {
                                            info!("Template provider reconnected; resuming");
                                            continue;
                                        }
                                        Err(reconnect_err) => {
                                            error!(
                                                "Template provider reconnect failed: {reconnect_err:?} — shutting down"
                                            );
                                            cancellation_token.cancel();
                                            break;
                                        }
                                    }
                                }
                                Action::Log => {
                                    warn!("Log-only error from Template Provider: {:?}", e.kind);
                                }
                                _ => {}
                            }
                        }
                    }
                    res = self_clone_2.handle_channel_manager_message() => {
                        if let Err(e) = res {
                            error!("TemplateReceiver channel manager handler failed: {e:?}");
                            match e.action {
                                Action::Shutdown => {
                                    cancellation_token.cancel();
                                    break;
                                }
                                Action::Log => {
                                    warn!("Log-only error from Template Provider: {:?}", e.kind);
                                }
                                _ => {}
                            }
                        }
                    },
                }
            }
            warn!("TemplateReceiver: unified message loop exited.");
        });
        Ok(())
    }

    /// Handle inbound messages from the template provider.
    ///
    /// Routes:
    /// - `Common` messages → handled locally
    /// - `TemplateDistribution` messages → forwarded to ChannelManager
    /// - Unsupported messages → logged and ignored
    pub async fn handle_template_provider_message(
        &mut self,
    ) -> PoolResult<(), error::TemplateProvider> {
        let mut sv2_frame = self
            .sv2_tp_channel
            .tp_receiver
            .recv()
            .await
            .map_err(PoolError::shutdown)?;
        debug!("Received SV2 frame from Template provider.");
        let header = sv2_frame.get_header().ok_or_else(|| {
            error!("SV2 frame missing header");
            PoolError::shutdown(framing_sv2::Error::MissingHeader)
        })?;

        match protocol_message_type(header.ext_type(), header.msg_type()) {
            MessageType::Common => {
                info!(
                    ext_type = ?header.ext_type(),
                    msg_type = ?header.msg_type(),
                    "Handling common message from Template provider."
                );

                self.handle_common_message_frame_from_server(None, header, sv2_frame.payload())
                    .await?;
            }
            MessageType::TemplateDistribution => {
                let message =
                    TemplateDistribution::try_from((header.msg_type(), sv2_frame.payload()))
                        .map_err(PoolError::shutdown)?
                        .into_static();

                self.sv2_tp_channel
                    .channel_manager_sender
                    .send(message)
                    .await
                    .map_err(|e| {
                        error!(error=?e, "Failed to send template distribution message to channel manager.");
                        PoolError::shutdown(PoolErrorKind::ChannelErrorSender)
                    })?;
            }
            _ => {
                warn!(
                    ext_type = ?header.ext_type(),
                    msg_type = ?header.msg_type(),
                    "Received unsupported message type from template provider."
                );
            }
        }
        Ok(())
    }

    /// Handle messages from channel manager → template provider.
    ///
    /// Forwards outbound frames upstream
    pub async fn handle_channel_manager_message(&self) -> PoolResult<(), error::TemplateProvider> {
        let msg = self
            .sv2_tp_channel
            .channel_manager_receiver
            .recv()
            .await
            .map_err(PoolError::shutdown)?;
        // Remember the coinbase constraints so a reconnected session can be primed with them.
        if matches!(msg, TemplateDistribution::CoinbaseOutputConstraints(_)) {
            if let Ok(mut slot) = self.last_coinbase_constraints.lock() {
                *slot = Some(msg.clone().into_static());
            }
        }
        let message = AnyMessage::TemplateDistribution(msg).into_static();
        let frame: Sv2Frame = message.try_into().map_err(PoolError::shutdown)?;

        debug!("Forwarding message from channel manager to outbound_tx");
        self.sv2_tp_channel
            .tp_sender
            .send(frame)
            .await
            .map_err(|_| PoolError::shutdown(PoolErrorKind::ChannelErrorSender))?;

        Ok(())
    }

    // Performs the initial handshake with Template Provider.
    pub async fn setup_connection(
        &mut self,
        addr: String,
    ) -> PoolResult<(), error::TemplateProvider> {
        let socket = resolve_host_port(&addr).await.map_err(|e| {
            error!(%addr, "Failed to resolve template provider address: {e}");
            PoolError::shutdown(PoolErrorKind::InvalidSocketAddress(addr.clone()))
        })?;

        debug!(%socket, "Building SetupConnection message to the Template Provider");
        let setup_msg = get_setup_connection_message_tp(socket).map_err(PoolError::shutdown)?;
        let frame: Sv2Frame = Message::Common(setup_msg.into())
            .try_into()
            .map_err(PoolError::shutdown)?;

        info!("Sending SetupConnection message to the Template Provider");
        self.sv2_tp_channel
            .tp_sender
            .send(frame)
            .await
            .map_err(|_| {
                error!("Failed to send setup connection message upstream");
                PoolError::shutdown(PoolErrorKind::ChannelErrorSender)
            })?;

        info!("Waiting for upstream handshake response");
        let mut incoming: Sv2Frame = self.sv2_tp_channel.tp_receiver.recv().await.map_err(|e| {
            error!(?e, "Upstream connection closed during handshake");
            PoolError::shutdown(e)
        })?;

        let header = incoming.get_header().ok_or_else(|| {
            error!("Handshake frame missing header");
            PoolError::shutdown(framing_sv2::Error::MissingHeader)
        })?;
        debug!(
            ext_type = ?header.ext_type(),
            msg_type = ?header.msg_type(),
            "Received upstream handshake response"
        );

        self.handle_common_message_frame_from_server(None, header, incoming.payload())
            .await?;
        info!("Handshake with upstream completed successfully");
        Ok(())
    }
}
