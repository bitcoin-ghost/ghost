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
use ghost_consensus::message::{
    MessageEnvelope, ShardEpochSummaryMessage, ShardSampleRequestMessage,
    ShardSampleResponseMessage, ShardTableSyncMessage,
};
use ghost_consensus::MessageType;

use crate::shard::{PeerMergeOutcome, ShardRuntime, TableSyncMerge};

/// Where a served table-sync response is handed off to be sent.
///
/// The handler cannot send it itself: `MessageHandler::handle_message` has no access to the mesh,
/// and giving it one would make the shard handler own a reference to the thing dispatching to it.
pub type SyncResponder = tokio::sync::mpsc::Sender<(NodeId, ShardTableSyncMessage)>;

/// Where a served §6 sampling response is handed off to be sent, for the same reason as
/// [`SyncResponder`]: the handler has no mesh reference of its own.
pub type SampleResponder = tokio::sync::mpsc::Sender<(NodeId, ShardSampleResponseMessage)>;

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
    /// When each peer was last SERVED a whole table.
    ///
    /// Serving is expensive — a DB read for admission, the table lock, a full clone and
    /// canonicalisation, and an ed25519 signature — and it runs inline on the mesh receive path,
    /// which dispatches handlers sequentially. Without a cooldown one peer looping requests would
    /// stall this node's inbound votes, checkpoints and summaries behind it. The asker's hourly
    /// cadence is self-imposed and therefore not a limit on anyone else's behaviour.
    last_served: parking_lot::Mutex<std::collections::HashMap<NodeId, std::time::Instant>>,
    /// Outbound queue for served §6 sampling responses. `None` leaves the node able to REQUEST
    /// audits but unable to answer them, which is a silent half-wiring — so it is logged.
    sample_out: Option<SampleResponder>,
    /// The share checks in force RIGHT NOW, reusing the SBC path's `ChecksFn` rather than a second
    /// spelling of the same predicate.
    ///
    /// ⚠ A function, not a value, and era-aware by construction. A share must be judged by its own
    /// round, not the current height: a height-derived predicate condemns every pre-gate share the
    /// instant the fleet crosses a gate, which quarantined vm5 fleet-wide on 2026-08-12. Sampling
    /// turns that into a PUBLISHED accusation against an honest node, so without this the response
    /// half stays unwired rather than running on a predicate that could frame a peer.
    checks: Option<crate::sbc_handler::ChecksFn>,
}

/// Minimum gap between whole-table syncs served to the SAME peer. Well under the hourly ask
/// cadence, so an honest peer never trips it — including one that restarts and asks early.
const SERVE_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(300);

impl ShardMeshHandler {
    pub fn new(shard: Arc<ShardRuntime>) -> Self {
        Self {
            shard,
            sync_out: None,
            last_served: parking_lot::Mutex::new(std::collections::HashMap::new()),
            sample_out: None,
            checks: None,
        }
    }

    /// Wire the era-aware share checks, enabling §6 sampling RESPONSES to be verified.
    pub fn with_share_checks(mut self, checks: crate::sbc_handler::ChecksFn) -> Self {
        self.checks = Some(checks);
        self
    }

    /// Wire the responder half for §6 sampling, so this node can ANSWER audits.
    pub fn with_sample_responder(mut self, tx: SampleResponder) -> Self {
        self.sample_out = Some(tx);
        self
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
                let peer = hex::encode(&envelope.sender[..4]);

                // ⚠ Admission is checked against `envelope.sender`, NEVER `requesting_node`.
                //
                // `ShardTableSyncMessage::Request` is deliberately unsigned, so `requesting_node`
                // is an unauthenticated assertion by whoever sent the bytes — only
                // `envelope.sender` is bound by `validate_and_verify`. Checking the payload field
                // would let any node whose envelopes we accept name a ratified id and receive the
                // whole accrued table, with payout addresses in the clear inside the envelope,
                // unicast back to ITS address. That is precisely the harvest this check exists to
                // stop, so a mismatch between the two is refused outright rather than tolerated.
                if *requesting_node != envelope.sender {
                    warn!(
                        sender = %peer,
                        claimed = %hex::encode(&requesting_node[..4]),
                        "shard: table sync request claims a different node id than it was signed by — NOT served"
                    );
                    return Ok(None);
                }

                // Cooldown BEFORE the admission DB read and the signing, so a flood costs this
                // node a hashmap lookup rather than a table clone per message.
                {
                    let mut seen = self.last_served.lock();
                    let now = std::time::Instant::now();
                    if let Some(prev) = seen.get(&envelope.sender) {
                        if now.duration_since(*prev) < SERVE_COOLDOWN {
                            debug!(peer = %peer, "shard: table sync request within cooldown — not served");
                            return Ok(None);
                        }
                    }
                    // Bound the map: it is keyed by peer, and only ratified peers get this far in
                    // the normal case, but an unbounded map fed by envelope.sender is a memory
                    // sink an attacker controls.
                    if seen.len() > 256 {
                        seen.retain(|_, t| now.duration_since(*t) < SERVE_COOLDOWN);
                    }
                    seen.insert(envelope.sender, now);
                }

                match self.shard.table_sync_response_for(&envelope.sender)? {
                    Some(response) => {
                        // Read the root out of the response we are actually sending. Re-reading it
                        // from the runtime would take the lock a third time and could pick up a
                        // fold that landed in between, making `agree=` describe a table the peer
                        // never received — misleading on the very divergence this log exists for.
                        let ours = match &response {
                            ShardTableSyncMessage::Response { table_root, .. } => *table_root,
                            ShardTableSyncMessage::Request { table_root, .. } => *table_root,
                        };
                        info!(
                            peer = %peer,
                            peer_root = %hex::encode(&table_root[..8]),
                            our_root = %hex::encode(&ours[..8]),
                            agree = (*table_root == ours),
                            "shard: serving a whole-table sync request"
                        );
                        Ok(Some(response))
                    }
                    None => {
                        warn!(peer = %peer,
                            "shard: table sync requested by a node outside the ratified set (or we are solo) — NOT served");
                        Ok(None)
                    }
                }
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
            MessageType::ShardSampleRequest => {
                let req: ShardSampleRequestMessage = match serde_json::from_slice(&envelope.payload)
                {
                    Ok(m) => m,
                    Err(e) => {
                        debug!(error = %e, "shard: undeserialisable sampling request dropped");
                        return Ok(());
                    }
                };
                // Answer only what the SENDER asked for. `requesting_node` is payload, so a
                // mismatch means someone is trying to have our evidence delivered elsewhere —
                // the same unsigned-field trap as the table-sync request.
                if req.requesting_node != envelope.sender {
                    warn!(
                        sender = %hex::encode(&envelope.sender[..4]),
                        claimed = %hex::encode(&req.requesting_node[..4]),
                        "shard: sampling request claims a different requester than it was signed \
                         by — NOT served"
                    );
                    return Ok(());
                }
                match self.shard.sample_response_for(&req) {
                    Ok(Some(response)) => {
                        info!(
                            epoch = req.epoch,
                            peer = %hex::encode(&envelope.sender[..4]),
                            leaves = response.leaves.len(),
                            asked = req.leaf_indices.len(),
                            "shard: serving a §6 sampling request"
                        );
                        match self.sample_out.as_ref() {
                            Some(tx) => {
                                if tx.try_send((envelope.sender, response)).is_err() {
                                    warn!("shard: sampling response dropped (send queue full)");
                                }
                            }
                            None => debug!(
                                "shard: sampling request received but no responder channel wired"
                            ),
                        }
                    }
                    Ok(None) => debug!(
                        epoch = req.epoch,
                        "shard: sampling request not served (not ours, not ratified, or no \
                         matching evidence)"
                    ),
                    Err(e) => warn!(error = %e, "shard: sampling request handling failed"),
                }
            }
            MessageType::ShardSampleResponse => {
                let resp: ShardSampleResponseMessage =
                    match serde_json::from_slice(&envelope.payload) {
                        Ok(m) => m,
                        Err(e) => {
                            debug!(error = %e, "shard: undeserialisable sampling response dropped");
                            return Ok(());
                        }
                    };
                // Without the era-aware checks there is NO safe predicate to judge against, and a
                // wrong one publishes an accusation rather than merely rejecting a share. Refuse
                // to verify rather than guess.
                let Some(checks_fn) = self.checks.as_ref() else {
                    warn!(
                        "shard: sampling response received but the era-aware share checks are not \
                         wired — NOT verified (a height-derived predicate would risk framing an \
                         honest peer)"
                    );
                    return Ok(());
                };
                // Bind the claimed responder to the authenticated sender, exactly as the
                // request arm does. `responding_node` is payload, so without this a peer whose
                // envelopes we accept could answer on another node's behalf — and combined with
                // the pending-audit lookup that is how an audit gets misdirected or discarded.
                if resp.responding_node != envelope.sender {
                    warn!(
                        sender = %hex::encode(&envelope.sender[..4]),
                        claimed = %hex::encode(&resp.responding_node[..4]),
                        "shard: sampling response claims a different responder than it was signed \
                         by — dropped"
                    );
                    return Ok(());
                }

                // ⚠ Judge the peer's shares by BLOCK HEIGHT, never by our local rounds.
                //
                // `checks_fn()` builds the era from OUR activation rounds, and those are
                // node-local: a long-running node auditing a newly commissioned one would see
                // every `share.round_id < activation`, take the pre-bind branch, and reject
                // shares that were signed correctly — publishing λ accusations against an honest
                // operator. Multi-operator is precisely the case §6 exists for, so that predicate
                // must not be used across nodes.
                //
                // The epoch gives a height both sides derive identically from the chain
                // (`epoch * EPOCH_BLOCKS`), and the gates are defined in height terms before
                // being translated into local rounds. `checks_fn` is still consulted for the
                // fallback below, so the wiring stays honest about needing it.
                let _local_checks = checks_fn();
                let epoch_height = resp
                    .epoch
                    .saturating_mul(ghost_common::share_shard::EPOCH_BLOCKS.get());
                let checks = crate::sbc_checks::NodeBatchChecks::at_shared_height(epoch_height);
                let predicate = |share: &ghost_common::types::ShareProof| {
                    use ghost_common::batch_consensus::BatchChecks;
                    checks.share_is_valid(share)
                };
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                match self.shard.apply_sample_response(&resp, &predicate, now_ms) {
                    Ok(Some(outcome)) => {
                        // Evidence is the headline: it is a publishable accusation that a peer
                        // committed work it cannot back, which is what §6 exists to produce.
                        if outcome.evidence.is_empty() {
                            info!(
                                epoch = resp.epoch,
                                peer = %hex::encode(&resp.responding_node[..4]),
                                verified = outcome.verified.len(),
                                unanswered = outcome.unanswered.len(),
                                "shard: §6 audit clean"
                            );
                        } else {
                            warn!(
                                epoch = resp.epoch,
                                peer = %hex::encode(&resp.responding_node[..4]),
                                verified = outcome.verified.len(),
                                unanswered = outcome.unanswered.len(),
                                evidence = outcome.evidence.len(),
                                "shard: §6 audit FAILED — committed leaves do not pass validity"
                            );
                        }
                    }
                    Ok(None) => {}
                    Err(e) => warn!(error = %e, "shard: sampling response handling failed"),
                }
            }
            _ => {}
        }
        Ok(())
    }
}
