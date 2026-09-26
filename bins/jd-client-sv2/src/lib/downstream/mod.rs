use std::{
    collections::HashMap,
    sync::{atomic::AtomicU32, Arc},
};

use async_channel::{unbounded, Receiver, Sender};
use stratum_apps::{
    custom_mutex::Mutex,
    fallback_coordinator::FallbackCoordinator,
    network_helpers::noise_stream::NoiseTcpStream,
    stratum_core::{
        channels_sv2::server::{
            extended::ExtendedChannel,
            group::GroupChannel,
            jobs::{extended::ExtendedJob, job_store::DefaultJobStore, standard::StandardJob},
            standard::StandardChannel,
        },
        common_messages_sv2::MESSAGE_TYPE_SETUP_CONNECTION,
        handlers_sv2::{HandleCommonMessagesFromClientAsync, HandleExtensionsFromClientAsync},
        parsers_sv2::{parse_message_frame_with_tlvs, AnyMessage, Mining, Tlv},
    },
    task_manager::TaskManager,
    utils::types::{DownstreamId, Message, Sv2Frame},
};

use bitcoin_core_sv2::template_distribution_protocol::CancellationToken;
use tracing::{debug, error, warn};

use crate::{
    error::{self, JDCError, JDCErrorKind, JDCResult},
    io_task::spawn_io_tasks,
    status::{handle_error, Status, StatusSender},
};

use stratum_apps::utils::types::ChannelId;

mod common_message_handler;
mod extensions_message_handler;

/// Holds state related to a downstream connection's mining channels.
///
/// This includes:
/// - Whether the downstream requires a standard job (`require_std_job`).
/// - An optional [`GroupChannel`] if group channeling is used.
/// - Active [`ExtendedChannel`]s keyed by channel ID.
/// - Active [`StandardChannel`]s keyed by channel ID.
pub struct DownstreamData {
    pub require_std_job: bool,
    pub group_channel: GroupChannel<'static, DefaultJobStore<ExtendedJob<'static>>>,
    pub extended_channels:
        HashMap<ChannelId, ExtendedChannel<'static, DefaultJobStore<ExtendedJob<'static>>>>,
    pub standard_channels:
        HashMap<ChannelId, StandardChannel<'static, DefaultJobStore<StandardJob<'static>>>>,
    pub channel_id_factory: AtomicU32,
    /// Extensions that have been successfully negotiated with this client
    pub negotiated_extensions: Vec<u16>,
    /// Extensions that the JDC supports
    pub supported_extensions: Vec<u16>,
    /// Extensions that the JDC requires
    pub required_extensions: Vec<u16>,
}

/// Communication layer for a downstream connection.
///
/// Provides the messaging primitives for interacting with the
/// channel manager and the downstream peer:
/// - `channel_manager_sender`: sends frames to the channel manager.
/// - `channel_manager_receiver`: receives messages from the channel manager.
/// - `downstream_sender`: sends frames to the downstream.
/// - `downstream_receiver`: receives frames from the downstream.
#[derive(Clone)]
pub struct DownstreamChannel {
    channel_manager_sender: Sender<(DownstreamId, Mining<'static>, Option<Vec<Tlv>>)>,
    channel_manager_receiver: Receiver<(Mining<'static>, Option<Vec<Tlv>>)>,
    downstream_sender: Sender<Sv2Frame>,
    downstream_receiver: Receiver<Sv2Frame>,
    /// Per-connection cancellation token (child of the global token).
    /// Cancelled when this downstream's message loop exits, causing
    /// the associated I/O tasks to shut down.
    connection_token: CancellationToken,
}

/// Represents a downstream client connected to this node.
#[derive(Clone)]
pub struct Downstream {
    pub downstream_data: Arc<Mutex<DownstreamData>>,
    downstream_channel: DownstreamChannel,
    pub downstream_id: DownstreamId,
}

#[cfg_attr(not(test), hotpath::measure_all)]
impl Downstream {
    /// Creates a new [`Downstream`] instance and spawns the necessary I/O tasks.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        downstream_id: DownstreamId,
        channel_id_factory: AtomicU32,
        group_channel: GroupChannel<'static, DefaultJobStore<ExtendedJob<'static>>>,
        channel_manager_sender: Sender<(DownstreamId, Mining<'static>, Option<Vec<Tlv>>)>,
        channel_manager_receiver: Receiver<(Mining<'static>, Option<Vec<Tlv>>)>,
        noise_stream: NoiseTcpStream<Message>,
        cancellation_token: CancellationToken,
        fallback_coordinator: FallbackCoordinator,
        task_manager: Arc<TaskManager>,
        supported_extensions: Vec<u16>,
        required_extensions: Vec<u16>,
    ) -> Self {
        let (noise_stream_reader, noise_stream_writer) = noise_stream.into_split();
        let (inbound_tx, inbound_rx) = unbounded::<Sv2Frame>();
        let (outbound_tx, outbound_rx) = unbounded::<Sv2Frame>();

        // Create a per-connection child token so we can cancel this
        // connection's I/O tasks independently of the global shutdown.
        let connection_token = cancellation_token.child_token();
        spawn_io_tasks(
            task_manager,
            noise_stream_reader,
            noise_stream_writer,
            outbound_rx,
            inbound_tx,
            connection_token.clone(),
            fallback_coordinator.clone(),
        );

        let downstream_channel = DownstreamChannel {
            channel_manager_receiver,
            channel_manager_sender,
            downstream_sender: outbound_tx,
            downstream_receiver: inbound_rx,
            connection_token,
        };

        let downstream_data = Arc::new(Mutex::new(DownstreamData {
            require_std_job: false,
            extended_channels: HashMap::new(),
            standard_channels: HashMap::new(),
            group_channel,
            channel_id_factory,
            negotiated_extensions: vec![],
            supported_extensions,
            required_extensions,
        }));

        Downstream {
            downstream_channel,
            downstream_data,
            downstream_id,
        }
    }

    /// Starts the downstream loop.
    ///
    /// Responsibilities:
    /// - Performs the initial `SetupConnection` handshake with the downstream.
    /// - Forwards mining-related messages to the channel manager.
    /// - Forwards channel manager messages back to the downstream peer.
    pub async fn start(
        mut self,
        cancellation_token: CancellationToken,
        fallback_coordinator: FallbackCoordinator,
        status_sender: Sender<Status>,
        task_manager: Arc<TaskManager>,
    ) {
        let status_sender = StatusSender::Downstream {
            downstream_id: self.downstream_id,
            tx: status_sender,
        };

        // Setup initial connection
        if let Err(e) = self.setup_connection_with_downstream().await {
            error!(?e, "Failed to set up downstream connection");

            // sleep to make sure SetupConnectionError is sent
            // before we break the TCP connection
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            handle_error(&status_sender, e).await;
            return;
        }

        task_manager.spawn(async move {
            let fallback_handler = fallback_coordinator.register();
            let fallback_token = fallback_coordinator.token();

            loop {
                let mut self_clone_1 = self.clone();
                let downstream_id = self_clone_1.downstream_id;
                let self_clone_2 = self.clone();
                tokio::select! {
                    _ = cancellation_token.cancelled() => {
                        debug!("Downstream {downstream_id}: received shutdown signal");
                        break;
                    }
                    _ = fallback_token.cancelled() => {
                        debug!("Downstream {downstream_id}: received fallback signal");
                        break;
                    }
                    // ⛔ ONLY the `recv()` may sit in this `select!` (#933).
                    frame = self_clone_1.downstream_channel.downstream_receiver.recv() => {
                        let res = match frame {
                            Ok(f) => self_clone_1.process_downstream_message(f).await,
                            Err(e) => Err(JDCError::disconnect(e, downstream_id)),
                        };
                        if let Err(e) = res {
                            error!(?e, "Error handling downstream message for {downstream_id}");
                            if handle_error(&status_sender, e).await {
                                break;
                            }
                        }
                    }
                    cm = self_clone_2.downstream_channel.channel_manager_receiver.recv() => {
                        let res = self_clone_2.clone().process_channel_manager_message(cm).await;
                        if let Err(e) = res {
                            error!(?e, "Error handling channel manager message for {downstream_id}");
                            if handle_error(&status_sender, e).await {
                                break;
                            }
                        }
                    }

                }
            }

            self.downstream_channel.connection_token.cancel();
            warn!("Downstream: unified message loop exited.");
            fallback_handler.done();
        });
    }

    // Performs the initial handshake with a downstream peer.
    async fn setup_connection_with_downstream(&mut self) -> JDCResult<(), error::Downstream> {
        let mut frame = self
            .downstream_channel
            .downstream_receiver
            .recv()
            .await
            .map_err(|error| JDCError::disconnect(error, self.downstream_id))?;
        let header = frame.get_header().expect("frame header must be present");
        if header.msg_type() == MESSAGE_TYPE_SETUP_CONNECTION {
            self.handle_common_message_frame_from_client(None, header, frame.payload())
                .await?;
            return Ok(());
        }
        Err(JDCError::disconnect(
            JDCErrorKind::UnexpectedMessage(header.ext_type(), header.msg_type()),
            self.downstream_id,
        ))
    }

    /// Everything that happens to a channel-manager message AFTER it is off the channel.
    ///
    /// ⛔ Split from the `recv()`: `async_channel::recv()` is cancellation-safe, this is not —
    /// the message is already OFF the queue, so a cancelled future loses it outright with no
    /// error and nothing to retry (#933, same shape as #854/#926).
    ///
    /// Must be called from a `select!` branch BODY, never as a branch future.
    #[allow(clippy::type_complexity)]
    // Handles messages sent from the channel manager to this downstream.
    async fn process_channel_manager_message(
        self,
        received: Result<(Mining<'static>, Option<Vec<Tlv>>), async_channel::RecvError>,
    ) -> JDCResult<(), error::Downstream> {
        let (message, _tlv_fields) = match received {
            Ok(msg) => msg,
            Err(e) => {
                warn!(
                    ?e,
                    "Channel manager receiver closed - disconnecting downstream"
                );
                return Err(JDCError::disconnect(
                    JDCErrorKind::ChannelErrorReceiver(e),
                    self.downstream_id,
                ));
            }
        };

        let message = AnyMessage::Mining(message);
        let sv2_frame: Sv2Frame = message.try_into().map_err(JDCError::shutdown)?;

        self.downstream_channel
            .downstream_sender
            .send(sv2_frame)
            .await
            .map_err(|e| {
                error!(?e, "Downstream send failed");
                JDCError::disconnect(JDCErrorKind::ChannelErrorSender, self.downstream_id)
            })?;

        Ok(())
    }

    // Handles incoming messages from the downstream peer.
    /// Everything that happens to a downstream frame AFTER it is off the channel.
    ///
    /// ⛔ Split from the `recv()`: `async_channel::recv()` is cancellation-safe, this is not —
    /// the message is already OFF the queue, so a cancelled future loses it outright with no
    /// error and nothing to retry (#933, same shape as #854/#926).
    ///
    /// Must be called from a `select!` branch BODY, never as a branch future.
    async fn process_downstream_message(
        &mut self,
        mut sv2_frame: Sv2Frame,
    ) -> JDCResult<(), error::Downstream> {
        let header = sv2_frame
            .get_header()
            .expect("frame header must be present");
        let payload = sv2_frame.payload();
        let negotiated_extensions = self
            .downstream_data
            .super_safe_lock(|data| data.negotiated_extensions.clone());
        let (any_message, tlv_fields) =
            parse_message_frame_with_tlvs(header, payload, &negotiated_extensions)
                .map_err(|error| JDCError::disconnect(error, self.downstream_id))?;
        match any_message {
            AnyMessage::Mining(message) => {
                self.downstream_channel
                    .channel_manager_sender
                    .send((self.downstream_id, message, tlv_fields))
                    .await
                    .map_err(|e| {
                        error!(?e, "Failed to send mining message to channel manager.");
                        JDCError::shutdown(JDCErrorKind::ChannelErrorSender)
                    })?;
            }
            AnyMessage::Extensions(message) => {
                self.handle_extensions_message_from_client(None, message, tlv_fields.as_deref())
                    .await?;
            }
            _ => {
                warn!(
                    "Received unsupported message type from downstream: {}",
                    header.msg_type()
                );
                return Ok(());
            }
        }
        Ok(())
    }
}
