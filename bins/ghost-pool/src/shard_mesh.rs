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
use ghost_consensus::mesh::MessageHandler;
use ghost_consensus::message::{MessageEnvelope, ShardEpochSummaryMessage};
use ghost_consensus::MessageType;

use crate::shard::{PeerMergeOutcome, ShardRuntime};

/// Routes gossiped shard messages into the runtime.
///
/// Holds the runtime rather than the table so every merge goes through the same verified path the
/// rest of the shard uses — there is no second way into the counters.
pub struct ShardMeshHandler {
    shard: Arc<ShardRuntime>,
}

impl ShardMeshHandler {
    pub fn new(shard: Arc<ShardRuntime>) -> Self {
        Self { shard }
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
}

#[async_trait]
impl MessageHandler for ShardMeshHandler {
    async fn handle_message(&self, envelope: Arc<MessageEnvelope>) -> GhostResult<()> {
        if envelope.msg_type != MessageType::ShardEpochSummary {
            return Ok(());
        }
        // A merge failure must not kill the handler task — the mesh delivers to every handler and
        // one shard hiccup should not stop the rest of consensus receiving its messages.
        if let Err(e) = self.handle_summary(&envelope) {
            warn!(error = %e, "shard: epoch summary handling failed");
        }
        Ok(())
    }
}
