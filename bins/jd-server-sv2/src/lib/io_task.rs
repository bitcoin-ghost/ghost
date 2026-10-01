//! Low-level Noise I/O tasks.
//!
//! [`spawn_io_tasks`] creates a matched pair of reader and writer tasks that bridge a
//! Noise-encrypted TCP stream to in-process `async_channel` endpoints. Both tasks honour
//! a [`CancellationToken`] for graceful shutdown.

use std::sync::Arc;

use async_channel::{Receiver, Sender};
use bitcoin_core_sv2::job_declaration_protocol::CancellationToken;
use stratum_apps::{
    network_helpers::noise_stream::{NoiseTcpReadHalf, NoiseTcpWriteHalf},
    stratum_core::framing_sv2::framing::Frame,
    task_manager::TaskManager,
    utils::types::{Message, Sv2Frame},
};
use tracing::{error, trace, warn, Instrument as _};

/// Spawns a reader task and a writer task for framed Noise I/O.
///
/// The reader forwards inbound SV2 frames into `inbound_tx`; the writer drains `outbound_rx`
/// and writes each frame to the TCP stream. Both tasks exit (and close their channels) when
/// the [`CancellationToken`] fires or the underlying stream errors.
#[track_caller]
#[cfg_attr(not(test), hotpath::measure)]
pub fn spawn_io_tasks(
    task_manager: Arc<TaskManager>,
    mut reader: NoiseTcpReadHalf<Message>,
    mut writer: NoiseTcpWriteHalf<Message>,
    outbound_rx: Receiver<Sv2Frame>,
    inbound_tx: Sender<Sv2Frame>,
    cancellation_token: CancellationToken,
) {
    let caller = std::panic::Location::caller();
    let inbound_tx_clone = inbound_tx.clone();
    let outbound_rx_clone = outbound_rx.clone();

    {
        let cancellation_token = cancellation_token.clone();

        task_manager.spawn(
            async move {
                trace!("Reader task started");
                // The error exits below each log an `error!`; the cancellation exit logs only
                // `trace!`. Without a reason on the exit line, a deliberately cancelled reader
                // was indistinguishable at INFO from one that simply vanished (#973).
                // `break <value>` forces every exit to name itself or fail to compile.
                let exit_reason = loop {
                    tokio::select! {
                        _ = cancellation_token.cancelled() => {
                            trace!("Received shutdown");
                            inbound_tx.close();
                            break "shutdown signal (cancellation token)";
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
                warn!(reason = exit_reason, "Reader task exited.");
            }
            .instrument(tracing::trace_span!(
                "reader_task",
                spawned_at = %format!("{}:{}", caller.file(), caller.line())
            )),
        );
    }

    {
        let cancellation_token = cancellation_token.clone();
        task_manager.spawn(
            async move {
                trace!("Writer task started");
                // See the reader above (#973).
                let exit_reason = loop {
                    tokio::select! {
                        _ = cancellation_token.cancelled() => {
                            trace!("Received shutdown");
                            outbound_rx.close();
                            break "shutdown signal (cancellation token)";
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
                warn!(reason = exit_reason, "Writer task exited.");
            }
            .instrument(tracing::trace_span!(
                "writer_task",
                spawned_at = %format!("{}:{}", caller.file(), caller.line())
            )),
        );
    }
}
