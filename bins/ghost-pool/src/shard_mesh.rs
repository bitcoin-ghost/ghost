//! The share shard's mesh handler — the receive half of gossip.
//!
//! `crates/ghost-consensus/src/shard_handler.rs` holds the verification and merge logic and is
//! thoroughly tested; what was missing was anything that *connected* it. Nothing registered a
//! handler and nothing broadcast a summary, so every node folded into its own column and no node
//! ever saw another's. That is not a subtle failure — it makes the whole convergence design
//! unobservable — and it survived because the layer being tested and the layer being wired are
//! different layers.
//!
//! Found by the Stage 4 dark soak, which is what a dark soak is for: two nodes folded correctly
//! for four hours and never converged, because there was no path between them.
//!
//! ## Why rejections are logged rather than treated as faults
//!
//! During a rolling cutover an armed node and a not-yet-armed one legitimately disagree — the
//! epoch floor refuses pre-genesis epochs and the genesis marker refuses summaries produced under
//! a different genesis. Both are *expected* traffic, not misbehaviour, so they are logged at INFO
//! rather than raised as errors. A roll is healthy when they STOP — which is only an actionable
//! statement if they are visible at the level the fleet actually runs at.
//!
//! The same reasoning applies to the SEND half in `main.rs`: raising only the receive logs left
//! the fleet able to see summaries arriving but not leaving, which is half-blind in exactly the
//! way this was meant to fix. "Did my summary go out?" and "did my peer's arrive?" are the two
//! halves of one question and belong at the same level.

use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, info, warn};

use ghost_common::error::GhostResult;
use ghost_common::types::NodeId;
use ghost_consensus::mesh::MessageHandler;
use ghost_consensus::message::{MessageEnvelope, ShardEpochSummaryMessage, ShardTableSyncMessage};
use ghost_consensus::MessageType;

use crate::shard::{PeerMergeOutcome, ShardRuntime, TableSyncMerge};

/// Where a served table-sync response is handed off to be sent.
///
/// The handler cannot send it itself: `MessageHandler::handle_message` has no access to the mesh,
/// and giving it one would make the shard handler own a reference to the thing dispatching to it.
pub type SyncResponder = tokio::sync::mpsc::Sender<(NodeId, ShardTableSyncMessage)>;

/// Routes gossiped shard messages into the runtime.
///
/// Holds the runtime rather than the table so every merge goes through the same verified path the
/// rest of the shard uses — there is no second way into the counters.
pub struct ShardMeshHandler {
    shard: Arc<ShardRuntime>,
    /// Outbound queue for table-sync responses. `None` leaves the node able to REQUEST and to
    /// merge what it is sent, but unable to serve — which is a silent half-wiring, so it is
    /// logged when a request arrives with nothing to answer it.
    sync_out: Option<SyncResponder>,
}

impl ShardMeshHandler {
    pub fn new(shard: Arc<ShardRuntime>) -> Self {
        Self {
            shard,
            sync_out: None,
        }
    }

    /// Wire the responder half, so this node can SERVE whole-table syncs as well as request them.
    pub fn with_sync_responder(mut self, tx: SyncResponder) -> Self {
        self.sync_out = Some(tx);
        self
    }

    fn handle_summary(&self, envelope: &MessageEnvelope) -> GhostResult<()> {
        let msg: ShardEpochSummaryMessage = match serde_json::from_slice(&envelope.payload) {
            Ok(m) => m,
            Err(e) => {
                // Malformed payloads are dropped, not propagated: an old binary that does not know
                // this message type drops it at deserialise without banning, and a peer sending
                // junk should not be able to error-spam a handler.
                debug!(error = %e, "shard: undeserialisable epoch summary dropped");
                return Ok(());
            }
        };

        let epoch = msg.summary.epoch;
        let node = hex::encode(&msg.summary.node_id[..4]);

        match self.shard.apply_peer_summary(&msg)? {
            PeerMergeOutcome::Merged {
                addresses,
                table_root,
                summary_retained,
            } => {
                // INFO, not debug. The question the Stage 4 soak could not answer was "are
                // summaries arriving and merging at all", and the fleet runs at info unless
                // RUST_LOG says otherwise — logging the answer at debug would leave the wiring
                // exactly as unobservable as the gap it was written to close.
                info!(
                    epoch,
                    peer = %node,
                    addresses,
                    table_root = %hex::encode(&table_root[..8]),
                    "shard: merged a peer's epoch summary"
                );
                if let Some(why) = summary_retained {
                    // The counter moved but the evidence did not. Next epoch's chain check for
                    // this peer is blind, and a conflicting same-epoch summary is the storage
                    // layer refusing to overwrite evidence — both are worth saying out loud.
                    warn!(epoch, peer = %node, reason = %why,
                          "shard: merged, but could NOT retain the peer's summary");
                }
            }
            PeerMergeOutcome::NotAdmitted => {
                // WARN, not info: on a single-operator fleet every peer should be in the ratified
                // set, so this means either an unknown node is gossiping at us or our own
                // checkpoint view has gone stale — both worth looking at rather than scrolling past.
                warn!(
                    epoch,
                    peer = %node,
                    "shard: sender is not in the ratified node set — summary NOT merged"
                );
            }
            PeerMergeOutcome::SoloRefused => {
                debug!(epoch, peer = %node, "shard: solo mode — peer summary not merged");
            }
            PeerMergeOutcome::OwnEcho => {}
            PeerMergeOutcome::Rejected(why) => {
                // INFO for the same reason: during a rolling cutover the epoch floor and the
                // genesis marker refuse peers legitimately, and "the roll is healthy when these
                // stop" is only actionable if they are visible.
                info!(epoch, peer = %node, reason = %why, "shard: peer summary refused");
            }
        }
        Ok(())
    }

    /// Whole-table sync (§12.6), both directions.
    ///
    /// This is the ONLY path that can repair a column a node missed entirely: epoch summaries
    /// carry just the addresses active in that epoch, so a node which has gone quiet gossips
    /// nothing, and a peer that was absent while it worked stays permanently short. Handling
    /// `ShardEpochSummary` alone — which is all this handler used to do — left that gap open.
    ///
    /// Returns the response to send back, when the message was a Request.
    fn handle_table_sync(
        &self,
        envelope: &MessageEnvelope,
    ) -> GhostResult<Option<ShardTableSyncMessage>> {
        let msg: ShardTableSyncMessage = match serde_json::from_slice(&envelope.payload) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "shard: undeserialisable table sync dropped");
                return Ok(None);
            }
        };

        match &msg {
            ShardTableSyncMessage::Request {
                requesting_node,
                table_root,
            } => {
                // Serve it. The requester's root is logged next to ours so a divergence is
                // visible from either end without correlating two nodes' logs by hand.
                let ours = self.shard.table_root();
                info!(
                    peer = %hex::encode(&requesting_node[..4]),
                    peer_root = %hex::encode(&table_root[..8]),
                    our_root = %hex::encode(&ours[..8]),
                    agree = (*table_root == ours),
                    "shard: serving a whole-table sync request"
                );
                Ok(Some(self.shard.table_sync_response()))
            }
            ShardTableSyncMessage::Response {
                responding_node, ..
            } => {
                let peer = hex::encode(&responding_node[..4]);
                match self.shard.apply_table_sync(&msg)? {
                    TableSyncMerge::Applied {
                        columns_gained,
                        columns_raised,
                        roots_match,
                        table_root,
                    } => {
                        // Gaining a column is the headline: it is the failure epoch summaries
                        // cannot fix, so it is logged loudly enough to be seen in a normal roll.
                        if columns_gained > 0 {
                            warn!(
                                peer = %peer, columns_gained, columns_raised, roots_match,
                                table_root = %hex::encode(&table_root[..8]),
                                "shard: table sync RECOVERED columns this node was missing"
                            );
                        } else {
                            info!(
                                peer = %peer, columns_raised, roots_match,
                                table_root = %hex::encode(&table_root[..8]),
                                "shard: table sync applied"
                            );
                        }
                        // Roots still differing after a merge is not necessarily a fault: the root
                        // commits `settled` too, which never crosses the mesh. Worth saying, not
                        // worth alarming about.
                        if !roots_match {
                            debug!(peer = %peer,
                                "shard: roots still differ after sync (settled is chain-derived, not gossiped)");
                        }
                    }
                    TableSyncMerge::NotAdmitted => {
                        warn!(peer = %peer, "shard: table sync from a node outside the ratified set — NOT merged");
                    }
                    TableSyncMerge::SoloRefused => {
                        debug!(peer = %peer, "shard: solo mode — table sync not merged");
                    }
                    TableSyncMerge::OwnEcho => {}
                    TableSyncMerge::Rejected(why) => {
                        info!(peer = %peer, reason = %why, "shard: table sync refused");
                    }
                }
                Ok(None)
            }
        }
    }
}

#[async_trait]
impl MessageHandler for ShardMeshHandler {
    async fn handle_message(&self, envelope: Arc<MessageEnvelope>) -> GhostResult<()> {
        match envelope.msg_type {
            MessageType::ShardEpochSummary => {
                // A merge failure must not kill the handler task — the mesh delivers to every
                // handler and one shard hiccup should not stop the rest of consensus receiving
                // its messages.
                if let Err(e) = self.handle_summary(&envelope) {
                    warn!(error = %e, "shard: epoch summary handling failed");
                }
            }
            MessageType::ShardTableSync => match self.handle_table_sync(&envelope) {
                Ok(Some(response)) => {
                    if let Some(tx) = self.sync_out.as_ref() {
                        // Bounded channel, and a full one is dropped rather than awaited: the
                        // requester retries, and blocking the mesh dispatch task to serve a
                        // sync would delay every other message on the connection.
                        if tx.try_send((envelope.sender, response)).is_err() {
                            warn!("shard: table-sync response dropped (send queue full)");
                        }
                    } else {
                        debug!("shard: table-sync request received but no responder channel wired");
                    }
                }
                Ok(None) => {}
                Err(e) => warn!(error = %e, "shard: table sync handling failed"),
            },
            _ => {}
        }
        Ok(())
    }
}
