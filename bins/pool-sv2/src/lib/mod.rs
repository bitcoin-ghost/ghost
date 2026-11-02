#![allow(rustdoc::all)] // imported SV2 crate: relax strict rustdoc policy (SRI upstream doc style)
#![allow(clippy::result_large_err)] // Err variant sits AT clippy's 128-byte threshold, not past
                                    // it. Boxing would change signatures across a crate imported from SRI upstream, so the churn is
                                    // paid twice: once now, and again at every upstream sync. Revisit if the variant grows.
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::JoinHandle,
};

use async_channel::unbounded;

use bitcoin_core_sv2::template_distribution_protocol::CancellationToken;
use stratum_apps::{
    task_manager::TaskManager, tp_type::TemplateProviderType,
    utils::types::GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS,
};
use tokio::sync::Notify;
use tracing::{debug, error, info, warn};

use crate::{
    channel_manager::ChannelManager,
    config::PoolConfig,
    error::PoolErrorKind,
    template_receiver::{
        bitcoin_core::{connect_to_bitcoin_core, BitcoinCoreSv2TDPConfig},
        sv2_tp::Sv2Tp,
    },
};

pub mod channel_manager;
pub mod config;
pub mod connection_limit;
pub mod downstream;
pub mod error;
mod io_task;
pub mod miner_stats;
#[cfg(feature = "monitoring")]
mod monitoring;
pub mod node_pool;
pub mod node_pool_api;
pub mod node_pool_genesis_import;
pub mod node_pool_miner_api;
pub mod node_pool_relay;
pub mod share_webhook;
pub mod template_receiver;
pub mod tier_binding;
pub mod utils;

#[derive(Debug, Clone)]
pub struct PoolSv2 {
    config: PoolConfig,
    cancellation_token: CancellationToken,
    shutdown_notify: Arc<Notify>,
    is_alive: Arc<AtomicBool>,
}

#[cfg_attr(not(test), hotpath::measure_all)]
impl PoolSv2 {
    pub fn new(config: PoolConfig) -> Self {
        Self {
            config,
            cancellation_token: CancellationToken::new(),
            shutdown_notify: Arc::new(Notify::new()),
            is_alive: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Starts the Pool main loop.
    pub async fn start(&self) -> Result<(), PoolErrorKind> {
        let coinbase_outputs = vec![self.config.get_txout()];

        let cancellation_token = self.cancellation_token.clone();

        let task_manager = Arc::new(TaskManager::new());

        let (downstream_to_channel_manager_sender, downstream_to_channel_manager_receiver) =
            unbounded();

        let (channel_manager_to_tp_sender, channel_manager_to_tp_receiver) = unbounded();
        let (tp_to_channel_manager_sender, tp_to_channel_manager_receiver) = unbounded();

        debug!("Channels initialized.");

        // Optional ghost-style share webhook: when configured, spawn a worker that
        // batches validated shares and POSTs them to a downstream service (ghost-mining).
        let share_webhook_sender = if let Some(webhook_cfg) = self.config.share_webhook() {
            info!(
                "Share webhook enabled: POST to {} (batch={}, timeout={}ms)",
                webhook_cfg.url, webhook_cfg.batch_size, webhook_cfg.batch_timeout_ms
            );
            let pool_id = self.config.server_id();
            // `?`, not a log-and-continue: a share webhook that cannot sign discards every share
            // it is handed, and does so after SV2 has already acknowledged the submission to the
            // miner. Refusing to start is the only outcome that is visible.
            let (sender, worker) =
                crate::share_webhook::ShareWebhookWorker::new(webhook_cfg.clone(), pool_id)?;
            let ct = cancellation_token.clone();
            tokio::spawn(async move {
                worker.run(ct).await;
            });
            Some(sender)
        } else {
            None
        };

        let channel_manager = ChannelManager::new(
            self.config.clone(),
            channel_manager_to_tp_sender.clone(),
            tp_to_channel_manager_receiver,
            downstream_to_channel_manager_receiver,
            share_webhook_sender,
        )
        .await?;

        // Start monitoring server if configured
        #[cfg(feature = "monitoring")]
        if let Some(monitoring_addr) = self.config.monitoring_address() {
            info!(
                "Initializing monitoring server on http://{}",
                monitoring_addr
            );

            let monitoring_server = stratum_apps::monitoring::MonitoringServer::new(
                monitoring_addr,
                None, // Pool doesn't have channels opened with servers
                Some(Arc::new(channel_manager.clone())), // channels opened with clients
                std::time::Duration::from_secs(
                    self.config.monitoring_cache_refresh_secs().unwrap_or(15),
                ),
            )
            .expect("Failed to initialize monitoring server")
            // The node pool's ledger and status API (W2.11), on the same loopback listener.
            .with_routes(crate::node_pool_api::router(
                channel_manager.node_pool_api.clone(),
            ))
            // The miner pages' API (W2.17).
            .with_routes(crate::node_pool_miner_api::router(
                channel_manager.node_pool_api.clone(),
            ));

            let cancellation_token_clone = cancellation_token.clone();
            let shutdown_signal = async move {
                cancellation_token_clone.cancelled().await;
            };

            task_manager.spawn(async move {
                if let Err(e) = monitoring_server.run(shutdown_signal).await {
                    error!("Monitoring server error: {}", e);
                }
            });
        }

        let channel_manager_clone = channel_manager.clone();
        let mut bitcoin_core_sv2_join_handle: Option<JoinHandle<()>> = None;

        match self.config.template_provider_type().clone() {
            TemplateProviderType::Sv2Tp {
                address,
                public_key,
            } => {
                let sv2_tp = Sv2Tp::new(
                    address.clone(),
                    public_key,
                    channel_manager_to_tp_receiver,
                    tp_to_channel_manager_sender,
                    cancellation_token.clone(),
                    task_manager.clone(),
                )
                .await?;

                sv2_tp
                    .start(address, cancellation_token.clone(), task_manager.clone())
                    .await?;

                info!("Sv2 Template Provider setup done");
            }
            TemplateProviderType::BitcoinCoreIpc {
                network,
                data_dir,
                fee_threshold,
                min_interval,
            } => {
                let unix_socket_path =
                    stratum_apps::tp_type::resolve_ipc_socket_path(&network, data_dir)
                        .ok_or_else(|| PoolErrorKind::Configuration(
                            "Could not determine Bitcoin data directory. Please set data_dir in config.".to_string()
                        ))?;

                info!(
                    "Using Bitcoin Core IPC socket at: {}",
                    unix_socket_path.display()
                );

                // incoming and outgoing TDP channels from the perspective of BitcoinCoreSv2TDP
                let incoming_tdp_receiver = channel_manager_to_tp_receiver.clone();
                let outgoing_tdp_sender = tp_to_channel_manager_sender.clone();

                let bitcoin_core_config = BitcoinCoreSv2TDPConfig {
                    unix_socket_path,
                    fee_threshold,
                    min_interval,
                    incoming_tdp_receiver,
                    outgoing_tdp_sender,
                    cancellation_token: CancellationToken::new(),
                };

                bitcoin_core_sv2_join_handle = Some(
                    connect_to_bitcoin_core(
                        bitcoin_core_config,
                        cancellation_token.clone(),
                        task_manager.clone(),
                    )
                    .await,
                );
            }
        }

        channel_manager
            .start(
                cancellation_token.clone(),
                task_manager.clone(),
                coinbase_outputs,
            )
            .await?;

        channel_manager_clone
            .start_downstream_server(
                *self.config.authority_public_key(),
                *self.config.authority_secret_key(),
                self.config.cert_validity_sec(),
                *self.config.listen_address(),
                task_manager.clone(),
                cancellation_token.clone(),
                downstream_to_channel_manager_sender,
                Arc::new(crate::connection_limit::ConnectionLimiter::new(
                    self.config.max_downstream_connections(),
                    self.config.max_connections_per_ip(),
                )),
            )
            .await?;

        info!("Spawning status listener task...");

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl+C received — initiating graceful shutdown...");
                cancellation_token.cancel();
            }
            _ = cancellation_token.cancelled() => {}
        }

        if let Some(bitcoin_core_sv2_join_handle) = bitcoin_core_sv2_join_handle {
            info!("Waiting for BitcoinCoreSv2TDP dedicated thread to shutdown...");
            match bitcoin_core_sv2_join_handle.join() {
                Ok(_) => info!("BitcoinCoreSv2TDP dedicated thread shutdown complete."),
                Err(e) => error!("BitcoinCoreSv2TDP dedicated thread error: {e:?}"),
            }
        }

        warn!(
            "Graceful shutdown: waiting {} seconds for tasks to finish",
            GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS
        );

        match tokio::time::timeout(
            std::time::Duration::from_secs(GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS),
            task_manager.join_all(),
        )
        .await
        {
            Ok(_) => {
                info!("All tasks joined cleanly");
            }
            Err(_) => {
                warn!(
                    "Tasks did not finish within {} seconds, aborting",
                    GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS
                );
                task_manager.abort_all().await;
                info!("Joining aborted tasks...");
                task_manager.join_all().await;
                warn!("Forced shutdown complete");
            }
        }
        self.shutdown_notify.notify_waiters();
        self.is_alive.store(false, Ordering::Relaxed);
        info!("Pool shutdown complete.");
        Ok(())
    }

    pub async fn shutdown(&self) {
        if !self.is_alive.load(Ordering::Relaxed) {
            return;
        }
        // The Notified future is guaranteed to receive wakeups from notify_waiters()
        // as soon as it has been created, even if it has not yet been polled.
        let notified = self.shutdown_notify.notified();
        self.cancellation_token.cancel();
        notified.await;
    }
}

impl Drop for PoolSv2 {
    fn drop(&mut self) {
        info!("PoolSv2 dropped");
        self.cancellation_token.cancel();
    }
}
