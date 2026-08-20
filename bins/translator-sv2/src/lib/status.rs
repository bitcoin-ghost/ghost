//! ## Status Reporting System
//!
//! This module provides a centralized way for components of the Translator to report
//! health updates, shutdown reasons, or fatal errors to the main runtime loop.
//!
//! Each task wraps its report in a [`Status`] and sends it over an async channel,
//! tagged with a [`Sender`] variant that identifies the source subsystem.

use stratum_apps::utils::types::DownstreamId;
use tracing::{debug, warn};

use crate::error::{Action, TproxyError, TproxyErrorKind};

/// Identifies the component that originated a [`Status`] update.
///
/// Each variant contains a channel to the main coordinator, and optionally a component ID
/// (e.g. a downstream connection ID).
#[derive(Debug, Clone)]
pub enum StatusSender {
    /// A specific downstream connection.
    Downstream {
        downstream_id: DownstreamId,
        tx: async_channel::Sender<Status>,
    },
    /// The SV1 server listener.
    Sv1Server(async_channel::Sender<Status>),
    /// The SV2 <-> SV1 bridge manager.
    ChannelManager(async_channel::Sender<Status>),
    /// The upstream SV2 connection handler.
    Upstream(async_channel::Sender<Status>),
}

impl StatusSender {
    /// Sends a [`Status`] update.
    #[cfg_attr(not(test), hotpath::measure)]
    pub async fn send(&self, status: Status) -> Result<(), async_channel::SendError<Status>> {
        match self {
            Self::Downstream { downstream_id, tx } => {
                debug!(
                    "Sending status from Downstream [{}]: {:?}",
                    downstream_id, status.state
                );
                tx.send(status).await
            }
            Self::Sv1Server(tx) => {
                debug!("Sending status from Sv1Server: {:?}", status.state);
                tx.send(status).await
            }
            Self::ChannelManager(tx) => {
                debug!("Sending status from ChannelManager: {:?}", status.state);
                tx.send(status).await
            }
            Self::Upstream(tx) => {
                debug!("Sending status from Upstream: {:?}", status.state);
                tx.send(status).await
            }
        }
    }
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
                tracing::error!(
                    "Failed to send downstream shutdown status from {:?}: {:?}",
                    sender,
                    e
                );
                std::process::abort();
            }
            matches!(sender, StatusSender::Downstream { .. })
        }

        Fallback => {
            let state = State::UpstreamShutdown(error.kind);

            if let Err(e) = sender.send(Status { state }).await {
                tracing::error!("Failed to send fallback status from {:?}: {:?}", sender, e);
                std::process::abort();
            }
            matches!(sender, StatusSender::Upstream { .. })
        }

        Shutdown => {
            let state = match sender {
                StatusSender::ChannelManager(_) => {
                    warn!(
                        "Channel Manager shutdown requested due to error: {:?}",
                        error.kind
                    );
                    State::ChannelManagerShutdown(error.kind)
                }
                StatusSender::Sv1Server(_) => {
                    warn!(
                        "Sv1Server shutdown requested due to error: {:?}",
                        error.kind
                    );
                    State::Sv1ServerShutdown(error.kind)
                }
                _ => State::ChannelManagerShutdown(error.kind),
            };

            if let Err(e) = sender.send(Status { state }).await {
                tracing::error!("Failed to send shutdown status from {:?}: {:?}", sender, e);
                std::process::abort();
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
