use std::sync::Arc;

use async_channel::{Receiver, Sender};
use bitcoin_core_sv2::template_distribution_protocol::CancellationToken;
use stratum_apps::{
    fallback_coordinator::FallbackCoordinator,
    network_helpers::noise_stream::{NoiseTcpReadHalf, NoiseTcpWriteHalf},
    stratum_core::framing_sv2::framing::Frame,
    task_manager::TaskManager,
    utils::types::{Message, Sv2Frame},
};
use tracing::{error, trace, warn, Instrument as _};

/// Spawns async reader and writer tasks for handling framed I/O with shutdown support.
#[track_caller]
#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(test), hotpath::measure)]
pub fn spawn_io_tasks(
    task_manager: Arc<TaskManager>,
    mut reader: NoiseTcpReadHalf<Message>,
    mut writer: NoiseTcpWriteHalf<Message>,
    outbound_rx: Receiver<Sv2Frame>,
    inbound_tx: Sender<Sv2Frame>,
    cancellation_token: CancellationToken,
    fallback_coordinator: FallbackCoordinator,
) {
    let caller = std::panic::Location::caller();
    let inbound_tx_clone = inbound_tx.clone();
    let outbound_rx_clone = outbound_rx.clone();

    {
        let cancellation_token_clone = cancellation_token.clone();
        let fallback_coordinator_clone = fallback_coordinator.clone();

        task_manager.spawn(
            async move {
                // we just spawned a new task that's relevant to fallback coordination
                // so register it with the fallback coordinator
                let fallback_handler = fallback_coordinator_clone.register();

                // get the cancellation token that signals fallback
                let fallback_token = fallback_coordinator_clone.token();

                trace!("Reader task started");
                // Why the loop ended, carried to the exit log. The three error paths below
                // already log an `error!`, but the two cancellation paths log only `trace!` —
                // so at INFO a deliberately cancelled reader was indistinguishable from one
                // that simply vanished, and the one visible line said neither (#973).
                //
                // `break <value>` rather than a mutable local: every exit must supply a reason
                // or it will not compile, and there is no dummy initial value to go stale.
                let exit_reason = loop {
                    tokio::select! {
                        _ = cancellation_token_clone.cancelled() => {
                            trace!("Received shutdown signal");
                            inbound_tx.close();
                            break "shutdown signal (cancellation token)";
                        }
                        _ = fallback_token.cancelled() => {
                            trace!("Received fallback signal");
                            inbound_tx.close();
                            break "fallback signal (FallbackCoordinator)";
                        }
                        res = reader.read_frame() => {
                            match res {
                                Ok(frame) => {
                                    match frame {
                                        Frame::HandShake(frame) => {
                                            error!(?frame, "Received handshake frame");
                                            drop(frame);
                                            break "unexpected handshake frame";
                                        },
                                        Frame::Sv2(sv2_frame) => {
                                            trace!("Received inbound frame");
                                            if let Err(e) = inbound_tx.send(sv2_frame).await {
                                                inbound_tx.close();
                                                error!(error=?e, "Failed to forward inbound frame");
                                                break "inbound channel send failed";
                                            }
                                        },
                                    }
                                }
                                Err(e) => {
                                    error!(error=?e, "Reader error");
                                    inbound_tx.close();
                                    break "read_frame error";
                                }
                            }
                        }
                    }
                };
                inbound_tx.close();
                outbound_rx_clone.close();
                drop(inbound_tx);
                drop(outbound_rx_clone);

                // signal fallback coordinator that this task has completed its cleanup
                fallback_handler.done();
                warn!(reason = exit_reason, "Reader task exited.");
            }
            .instrument(tracing::trace_span!(
                "reader_task",
                spawned_at = %format!("{}:{}", caller.file(), caller.line())
            )),
        );
    }

    {
        let fallback_coordinator_clone = fallback_coordinator.clone();
        task_manager.spawn(
            async move {
                // we just spawned a new task that's relevant to fallback coordination
                // so register it with the fallback coordinator
                let fallback_handler = fallback_coordinator_clone.register();

                // get the cancellation token that signals fallback
                let fallback_token = fallback_coordinator_clone.token();

                trace!("Writer task started");
                // See the reader above: the cancellation exits are TRACE, so the exit log has to
                // carry the reason or a cancelled writer looks like a vanished one (#973).
                let exit_reason = loop {
                    tokio::select! {
                        _ = cancellation_token.cancelled() => {
                            trace!("Received shutdown signal");
                            inbound_tx_clone.close();
                            break "shutdown signal (cancellation token)";
                        }
                        _ = fallback_token.cancelled() => {
                            trace!("Received fallback signal");
                            inbound_tx_clone.close();
                            break "fallback signal (FallbackCoordinator)";
                        }
                        res = outbound_rx.recv() => {
                            match res {
                                Ok(frame) => {
                                    trace!("Sending outbound frame");
                                    if let Err(e) = writer.write_frame(frame.into()).await {
                                        error!(error=?e, "Writer error");
                                        outbound_rx.close();
                                        break "write_frame error";
                                    }
                                }
                                Err(_) => {
                                    outbound_rx.close();
                                    warn!("Outbound channel closed");
                                    break "outbound channel closed";
                                }
                            }
                        }
                    }
                };
                outbound_rx.close();
                inbound_tx_clone.close();
                drop(outbound_rx);
                drop(inbound_tx_clone);

                // signal fallback coordinator that this task has completed its cleanup
                fallback_handler.done();
                warn!(reason = exit_reason, "Writer task exited.");
            }
            .instrument(tracing::trace_span!(
                "writer_task",
                spawned_at = %format!("{}:{}", caller.file(), caller.line())
            )),
        );
    }
}
