//! ## Status Reporting System
//!
//! This module provides a centralized way for components of the Translator to report
//! health updates, shutdown reasons, or fatal errors to the main runtime loop.
//!
//! Each task wraps its report in a [`Status`] and sends it over an async channel,
//! tagged with a [`Sender`] variant that identifies the source subsystem.

use stratum_apps::utils::types::DownstreamId;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::error::{Action, TproxyError, TproxyErrorKind};

/// Identifies the component that originated a [`Status`] update.
///
/// Each variant contains a channel to the main coordinator, and optionally a component ID
/// (e.g. a downstream connection ID).
///
/// Every variant also carries the runtime's cancellation token. It is not used
/// to send anything — it is how a failed send is told apart from a failure. See
/// [`StatusSender::shutdown_started`].
#[derive(Debug, Clone)]
pub enum StatusSender {
    /// A specific downstream connection.
    Downstream {
        downstream_id: DownstreamId,
        tx: async_channel::Sender<Status>,
        shutdown: CancellationToken,
    },
    /// The SV1 server listener.
    Sv1Server {
        tx: async_channel::Sender<Status>,
        shutdown: CancellationToken,
    },
    /// The SV2 <-> SV1 bridge manager.
    ChannelManager {
        tx: async_channel::Sender<Status>,
        shutdown: CancellationToken,
    },
    /// The upstream SV2 connection handler.
    Upstream {
        tx: async_channel::Sender<Status>,
        shutdown: CancellationToken,
    },
}

impl StatusSender {
    /// Sends a [`Status`] update.
    #[cfg_attr(not(test), hotpath::measure)]
    pub async fn send(&self, status: Status) -> Result<(), async_channel::SendError<Status>> {
        match self {
            Self::Downstream {
                downstream_id, tx, ..
            } => {
                debug!(
                    "Sending status from Downstream [{}]: {:?}",
                    downstream_id, status.state
                );
                tx.send(status).await
            }
            Self::Sv1Server { tx, .. } => {
                debug!("Sending status from Sv1Server: {:?}", status.state);
                tx.send(status).await
            }
            Self::ChannelManager { tx, .. } => {
                debug!("Sending status from ChannelManager: {:?}", status.state);
                tx.send(status).await
            }
            Self::Upstream { tx, .. } => {
                debug!("Sending status from Upstream: {:?}", status.state);
                tx.send(status).await
            }
        }
    }

    /// Whether the runtime has been told to stop.
    ///
    /// This is what separates "we cannot report state" from "there is nobody
    /// left to report to, because we are shutting down". The status channels are
    /// unbounded, so a send has exactly one failure mode — the channel is
    /// closed, meaning every receiver has been dropped. The only receiver lives
    /// in the supervisor loop, which drops it on the way out. A failed send is
    /// therefore normal during teardown and alarming outside it.
    pub fn shutdown_started(&self) -> bool {
        let token = match self {
            Self::Downstream { shutdown, .. }
            | Self::Sv1Server { shutdown, .. }
            | Self::ChannelManager { shutdown, .. }
            | Self::Upstream { shutdown, .. } => shutdown,
        };
        token.is_cancelled()
    }
}

/// React to a status that could not be delivered.
///
/// ⚖ These sites used to call [`std::process::abort`] unconditionally. The
/// intent was sound and came from #812 — a translator that hung while systemd
/// still reported `active`, serving nothing for 45 minutes — where dying loudly
/// beats pretending to work.
///
/// What made it wrong here is narrower: an unbounded send cannot fail from load
/// or slowness, only from the channel being closed, and the channel closes
/// because the supervisor loop has already exited. So the guard fired at the one
/// moment it was least useful — during an orderly shutdown, turning it into
/// `SIGABRT` and a core dump, on `systemctl stop` as much as anywhere.
///
/// The loud failure is kept for the case it was written for: a send that fails
/// while the runtime has NOT been told to stop is a genuine impossibility, and
/// still aborts.
fn report_undeliverable(sender: &StatusSender, what: &str, error: &impl std::fmt::Debug) {
    if sender.shutdown_started() {
        debug!("{what} not delivered from {sender:?}: shutting down, nobody is listening any more");
        return;
    }
    tracing::error!("Failed to send {what} from {sender:?}: {error:?} — the status channel is closed but shutdown was never requested");
    std::process::abort();
}

/// The type of event or error being reported by a component.
#[derive(Debug)]
/// ⚠ Every variant boxes its `TproxyErrorKind` for the same reason `TproxyError` does: the
/// enum is 128 bytes, and `State` is carried by `Status`, which is carried by
/// `async_channel::SendError<Status>` — so an unboxed kind made the error arm of every
/// `send()` 128 bytes wide, on success paths too. The `SendError` is third-party and cannot be
/// boxed at the edge, so the size has to come off here.
pub enum State {
    /// Downstream task exited or encountered an unrecoverable error.
    DownstreamShutdown {
        downstream_id: DownstreamId,
        reason: Box<TproxyErrorKind>,
    },
    /// SV1 server listener exited unexpectedly.
    Sv1ServerShutdown(Box<TproxyErrorKind>),
    /// Channel manager shut down (SV2 bridge manager).
    ChannelManagerShutdown(Box<TproxyErrorKind>),
    /// Upstream SV2 connection closed or failed.
    UpstreamShutdown(Box<TproxyErrorKind>),
}

/// A message reporting the current [`State`] of a component.
#[derive(Debug)]
pub struct Status {
    pub state: State,
}

#[cfg_attr(not(test), hotpath::measure)]
async fn send_status<O>(sender: &StatusSender, error: TproxyError<O>) -> bool {
    use Action::*;

    match error.action {
        Log => {
            warn!("Log-only error from {:?}: {:?}", sender, error.kind);
            false
        }

        Disconnect(downstream_id) => {
            let state = State::DownstreamShutdown {
                downstream_id,
                reason: error.kind,
            };

            if let Err(e) = sender.send(Status { state }).await {
                report_undeliverable(sender, "downstream shutdown status", &e);
            }
            matches!(sender, StatusSender::Downstream { .. })
        }

        Fallback => {
            let state = State::UpstreamShutdown(error.kind);

            if let Err(e) = sender.send(Status { state }).await {
                report_undeliverable(sender, "fallback status", &e);
            }
            matches!(sender, StatusSender::Upstream { .. })
        }

        Shutdown => {
            let state = match sender {
                StatusSender::ChannelManager { .. } => {
                    warn!(
                        "Channel Manager shutdown requested due to error: {:?}",
                        error.kind
                    );
                    State::ChannelManagerShutdown(error.kind)
                }
                StatusSender::Sv1Server { .. } => {
                    warn!(
                        "Sv1Server shutdown requested due to error: {:?}",
                        error.kind
                    );
                    State::Sv1ServerShutdown(error.kind)
                }
                _ => State::ChannelManagerShutdown(error.kind),
            };

            if let Err(e) = sender.send(Status { state }).await {
                report_undeliverable(sender, "shutdown status", &e);
            }
            true
        }
    }
}

#[cfg_attr(not(test), hotpath::measure)]
pub async fn handle_error<O>(sender: &StatusSender, e: TproxyError<O>) -> bool {
    send_status(sender, e).await
}

/// Size guard for [`Status`].
///
/// `Status` travels inside `async_channel::SendError<Status>`, which is the `Err` arm of every
/// `StatusSender::send`. A `Result` is as large as its larger arm, so a fat `Status` is paid on
/// success paths too — and `SendError` is third-party, so the size can only be controlled here.
///
/// ⚠ This is a compile-time assertion because the lint that catches it
/// (`clippy::result_large_err`, threshold 128 bytes) only exists on rust ≥ 1.98. A developer on
/// an older toolchain gets a clean local clippy run and a red CI. This fails the build for
/// everyone, on any toolchain.
///
/// If this trips: box the offending variant's payload rather than raising the bound.
const _: () = assert!(
    std::mem::size_of::<Status>() <= 32,
    "Status has grown — it is the Err arm of every StatusSender::send; box the payload"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{ChannelManager, TproxyError};

    fn closed_sender(shutdown: CancellationToken) -> StatusSender {
        let (tx, rx) = async_channel::unbounded::<Status>();
        // Drop the only receiver, which is the single way an unbounded send can
        // fail — and exactly what the supervisor loop does on its way out.
        drop(rx);
        StatusSender::ChannelManager { tx, shutdown }
    }

    /// A status that cannot be delivered during shutdown must not take the
    /// process down with it.
    ///
    /// This test surviving IS the assertion. Before this change the same
    /// sequence reached `std::process::abort()`, and the whole test binary died
    /// with SIGABRT and a core dump — which is what `translator_aggregated_
    /// integration` was doing on every fallback (#859, found via #854).
    #[tokio::test]
    async fn a_status_that_cannot_be_delivered_during_shutdown_does_not_abort() {
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let sender = closed_sender(shutdown);

        let breaks_loop = handle_error(
            &sender,
            TproxyError::<ChannelManager>::fallback(TproxyErrorKind::SV1Error),
        )
        .await;

        // A ChannelManager reporting a fallback does not break its own loop —
        // it waits to be told, which is unchanged by this fix.
        assert!(!breaks_loop);
    }

    #[test]
    fn a_sender_knows_whether_shutdown_has_begun() {
        let token = CancellationToken::new();
        let sender = closed_sender(token.clone());
        assert!(
            !sender.shutdown_started(),
            "a live runtime must not look like a shutdown, or a real fault would be swallowed"
        );
        token.cancel();
        assert!(sender.shutdown_started());
    }

    /// Every variant reports shutdown, not just the one the fix was written
    /// against — the three abort sites are shared by all four.
    #[test]
    fn every_sender_variant_reports_shutdown() {
        let token = CancellationToken::new();
        token.cancel();
        let (tx, _rx) = async_channel::unbounded::<Status>();
        let senders = [
            StatusSender::Downstream {
                downstream_id: 1,
                tx: tx.clone(),
                shutdown: token.clone(),
            },
            StatusSender::Sv1Server {
                tx: tx.clone(),
                shutdown: token.clone(),
            },
            StatusSender::ChannelManager {
                tx: tx.clone(),
                shutdown: token.clone(),
            },
            StatusSender::Upstream {
                tx,
                shutdown: token,
            },
        ];
        for s in senders {
            assert!(s.shutdown_started(), "{s:?} did not report shutdown");
        }
    }
}
