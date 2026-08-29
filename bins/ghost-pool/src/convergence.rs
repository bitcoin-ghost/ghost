//! GHOST-03: ledger convergence.
//!
//! Share propagation is best-effort gossip, so a partition or a dropped
//! broadcast leaves a node permanently missing shares — which, combined with
//! GHOST-02, would let a divergent-but-internally-balanced payout be approved.
//! The `ShareConvergence` request/response message types existed but were never
//! built, sent, or handled. This module implements the protocol:
//!
//! 1. A node advertises the share hashes it holds for a round (a *request*).
//! 2. A peer replies with the full **signed** proofs the requester is missing
//!    (a *response*).
//! 3. The requester applies each missing proof through the normal path, which
//!    re-verifies the GHOST-09 `received_by` signature before crediting.
//!
//! The full signed proofs are re-servable because `RoundManager` retains them
//! per round (see `recent_proofs`). Without that, a node could only detect
//! divergence, not repair it.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use tracing::{debug, warn};

use ghost_common::error::GhostResult;
use ghost_common::types::RoundId;
use ghost_consensus::mesh::MessageHandler;
use ghost_consensus::message::{
    MessageEnvelope, MessageType, ShareConvergenceMessage, ShareConvergenceResponse,
};

use crate::round::RoundManager;

/// Wire payload carried under `MessageType::ShareConvergence`. Disambiguates a
/// reconciliation request from a response without adding a second message type
/// (and the exhaustive `MessageType` matches that would come with it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConvergencePayload {
    Request(ShareConvergenceMessage),
    Response(ShareConvergenceResponse),
    /// GHOST-03: reconcile the UNPAID LEDGER over a time window, not a single round.
    ///
    /// The round-scoped exchange above can only repair the round in flight — and rounds rotate
    /// every ~90s, with signed proofs pruned after 10 of them. Anything a node dropped outside
    /// that ~15-minute window was unrecoverable, so every node's ledger drifted permanently and
    /// each summed a different share set. Since the payout is computed from the unpaid ledger and
    /// GHOST-02 compares the resulting split for EXACT equality, that divergence means every node
    /// rejects every payout, forever, with nothing able to repair it.
    ///
    /// The window is bounded so the advertisement stays a sane size; the caller sweeps.
    LedgerRequest(LedgerConvergenceRequest),
    LedgerResponse(LedgerConvergenceResponse),
}

/// Advertises the unpaid shares this node holds in `[since_ts, until_ts)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerConvergenceRequest {
    pub since_ts: i64,
    pub until_ts: i64,
    /// Canonical (internal byte order) share hashes we already have.
    pub share_hashes: Vec<String>,
}

/// The signed proofs the responder holds in that window which the requester did not advertise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerConvergenceResponse {
    pub since_ts: i64,
    pub until_ts: i64,
    /// Canonical JSON of each missing `ShareProof`.
    pub proofs: Vec<Vec<u8>>,
    /// Unpaid shares in the window the responder holds but CANNOT serve, because they predate
    /// schema v41 and their signature no longer exists. Reported so the divergence is visible
    /// rather than silent — no protocol can reconcile these, only a one-time operation.
    pub unservable: usize,
    /// The responder had MORE servable proofs for this window than fitted in one response.
    ///
    /// Without this the requester cannot distinguish a complete answer from a truncated one:
    /// a response carrying the full 56-proof budget looks identical to one carrying everything
    /// that was missing. It therefore treated the window as done and did not ask again until
    /// the sweep cursor returned — one visit per rotation, so a bucket holding ~400 missing
    /// shares needed 7 visits and 28 hours. With the flag the requester re-asks immediately
    /// and the bucket drains in seconds (#558).
    ///
    /// `#[serde(default)]` for wire-compat: a peer predating this field sends `false`, which
    /// is exactly the old behaviour — ask again next sweep.
    #[serde(default)]
    pub more_available: bool,
}

/// Cap on proofs served in one response, so a wide window cannot produce an enormous message.
/// Count bound on one window-convergence response.
///
/// Was 2_000, which is where #558 came from: bounded by count alone, a full response measured
/// 4.8 MB on the wire against a 1 MB envelope cap, so every one was dropped and the unpaid
/// ledger never converged. `MAX_PROOF_BYTES_PER_RESPONSE` is the real bound; this stays as a
/// cheap secondary guard.
const MAX_PROOFS_PER_RESPONSE: usize = 200;

/// Byte bound on the RAW proof blobs in one response, sized against the **measured
/// end-to-end expansion of 9.4x** (see `measure_two_layer_expansion`).
///
/// The expansion compounds across TWO serialisation layers, which is easy to under-count:
///
/// 1. `ConvergencePayload::LedgerResponse` -> JSON. `proofs: Vec<Vec<u8>>`, and serde encodes
///    each byte as a decimal integer plus a comma: ~3.1x.
/// 2. That JSON becomes `MessageEnvelope.payload`, which is a plain `Vec<u8>` with no
///    `serde_bytes`, so the whole thing is encoded as an integer array **again**: ~3.0x more.
///
/// Measured: 155,223 raw proof bytes -> 484,759 inner -> **1,454,617** on the wire.
///
/// 64 KiB raw is ~616 KB as an envelope, leaving real headroom under the 1 MB cap. Getting
/// this wrong is silent — the transport drops the message and convergence simply never
/// happens, which is what #558 was.
const MAX_PROOF_BYTES_PER_RESPONSE: usize = 64 * 1024;

/// Broadcasts a serialized [`ConvergencePayload`] to the mesh under
/// `MessageType::ShareConvergence`. Supplied by production wiring; `None` in
/// tests that drive the exchange directly.
/// Hands a serialised convergence frame to the outbound queue.
///
/// The second argument is the peer the frame is **addressed to**, or `None` to fan out. A reply
/// is always addressed: its payload is the complement of one specific peer's advertisement, so
/// fanning it out spends a Noise send per peer to serve one, and hands six uninterested nodes a
/// `LedgerResponse` whose `more_available` flag then makes each of them emit a follow-up request
/// of its own. That amplification is what fills the queue (#647).
pub type ConvergenceSendFn =
    Arc<dyn Fn(Vec<u8>, Option<ghost_common::types::NodeId>) -> GhostResult<()> + Send + Sync>;

/// Drives ledger convergence for one node against its [`RoundManager`].
pub struct ConvergenceHandler {
    round_manager: Arc<RoundManager>,
    send: Option<ConvergenceSendFn>,
    db: Option<Arc<ghost_storage::Database>>,
    /// Wall-clock instant at which the address-bind gate fired: the timestamp of the block at
    /// `share_addr_bind_height()`, read from the chain.
    ///
    /// This is the SHARED axis. Every node derives it from the same block, so every node reaches
    /// the same verdict on the same share — which is the property that actually matters when
    /// verifying somebody else's proof. See `signature_is_valid`.
    ///
    /// `None` means it could not be resolved; the check then falls back to the old node-local
    /// behaviour and says so loudly, because silently diverging is what this field exists to stop.
    addr_bind_activation_time: Option<i64>,
}

/// How far either side of the activation instant a share may be signed under EITHER era's rule.
///
/// The gate fires at a height, but each node crosses it when it sees that block, and it signs the
/// shares in flight at that moment under whichever rule it has already adopted. So there is a
/// genuine band around the activation instant containing correctly-signed shares of both formats
/// — on mainnet that band was three rounds wide between vm1 and vm8.
///
/// Without the band those shares verify nowhere: every node would agree to reject them (which at
/// least converges), but the GHOST-03 sweep would go on re-requesting them for ever — the ~1,300
/// discards/day/node this change exists to end. With it they verify everywhere.
///
/// One hour is far wider than the observed skew and still a rounding error against the chain's
/// history. The band is computed from the same block timestamp on every node, so widening it
/// cannot reintroduce divergence — it only decides how many boundary shares stay creditable.
const ERA_BOUNDARY_GRACE_SECS: i64 = 3600;

impl ConvergenceHandler {
    pub fn new(round_manager: Arc<RoundManager>) -> Self {
        Self {
            round_manager,
            send: None,
            db: None,
            addr_bind_activation_time: None,
        }
    }

    /// Supply the wall-clock instant the address-bind gate fired (the timestamp of the block at
    /// `share_addr_bind_height()`), so a peer's proof is judged on an axis both nodes share.
    pub fn with_addr_bind_activation_time(mut self, unix_secs: i64) -> Self {
        self.addr_bind_activation_time = Some(unix_secs);
        self
    }

    /// Attach the mesh broadcast used to reply to requests in production.
    pub fn with_send(mut self, send: ConvergenceSendFn) -> Self {
        self.send = Some(send);
        self
    }

    /// Attach the database so backfilled proofs also adopt their signed payout
    /// address (GHOST-02 / Option A), keeping addresses converged on the
    /// convergence path as well as the gossip path.
    pub fn with_db(mut self, db: Arc<ghost_storage::Database>) -> Self {
        self.db = Some(db);
        self
    }

    /// Build a convergence REQUEST advertising the shares we hold for `round_id`.
    pub fn build_request(&self, round_id: RoundId) -> ShareConvergenceMessage {
        let (share_count, total_work) = self.round_manager.round_share_summary(round_id);
        ShareConvergenceMessage {
            round_id,
            share_count,
            total_work,
            share_hashes: self.round_manager.round_share_hashes(round_id),
        }
    }

    /// Serialize a convergence request for broadcast.
    pub fn request_bytes(&self, round_id: RoundId) -> GhostResult<Vec<u8>> {
        let payload = ConvergencePayload::Request(self.build_request(round_id));
        serde_json::to_vec(&payload)
            .map_err(|e| ghost_common::error::GhostError::P2PMessage(e.to_string()))
    }

    /// Answer a peer's request with the full signed proofs they are missing.
    pub fn handle_request(&self, req: &ShareConvergenceMessage) -> ShareConvergenceResponse {
        let theirs: HashSet<[u8; 32]> = req.share_hashes.iter().copied().collect();
        // #590: bounded by the same budget as the ledger lane. An unbounded round response
        // exceeded the 1 MB envelope and was dropped by every receiver at `debug!`.
        let (missing, more_available) = self.round_manager.proofs_missing_from_bounded(
            req.round_id,
            &theirs,
            MAX_PROOFS_PER_RESPONSE,
            MAX_PROOF_BYTES_PER_RESPONSE,
        );
        if more_available {
            warn!(
                round_id = req.round_id,
                served = missing.len(),
                "round convergence response truncated — peer must re-request"
            );
        }
        let (share_count, total_work) = self.round_manager.round_share_summary(req.round_id);
        ShareConvergenceResponse {
            round_id: req.round_id,
            share_count,
            total_work,
            missing_shares: missing,
            more_available,
        }
    }

    /// Apply a convergence RESPONSE. Each backfilled proof is GHOST-09-verified
    /// (we bypass the normal share-receive gate here, so we must re-check the
    /// GHOST-09: does this backfilled proof carry a signature we accept at the current height?
    ///
    /// At and above the bind gate the signature must also cover `payout_address`, so a peer cannot
    /// serve a backfill whose payout destination it rewrote. Both convergence paths go through here
    /// rather than calling the verifier directly, so neither can be left on the old encoding.
    /// Does this proof carry a valid signature under the rules in force when it was mined?
    ///
    /// ⚠ Judged by the share's own TIMESTAMP against a chain-derived instant, never by
    /// `proof.round_id` against our activation round.
    ///
    /// That is what this used to do, and it is why mainnet never paid a single payout (#677).
    /// Round ids are node-local — `RoundManager::start_round` increments a counter seeded from
    /// each node's own database — so comparing a PEER's `round_id` against OUR boundary asks a
    /// question about our numbering, not about the share. The two boundaries differ in practice:
    /// vm1 recorded the address-bind era at round 111,556 and vm8 at 111,553, both with an
    /// identical `max(round_id)` of 128,632. Every share in rounds 111,553–111,555 was therefore
    /// bound-signed as far as vm8 was concerned and legacy-signed as far as vm1 was concerned, so
    /// vm1 discarded all of them as `bad_sig` — for ever, because the GHOST-03 sweep re-requests
    /// the same window on every rotation (~1,300 discards/day/node against one 1,800-second
    /// window holding 82 such shares).
    ///
    /// The consequence ran all the way to the money: the two nodes' share sets never converged
    /// (1,954,056 vs 1,936,253 shares), so their independent per-address recomputes differed —
    /// one address by 6.71%, against a 2% tolerance — and each node rejected the other's payout
    /// proposal with the same two numbers swapped. A symmetric standoff nothing could ratify.
    ///
    /// The share's timestamp is in the signed proof and the activation instant comes from the
    /// block at the gate height, so **every node reaches the same verdict on the same share**.
    /// Agreement is the property that matters here; being right about the boundary to the second
    /// is not, which is why the grace band below can be generous without any risk of divergence.
    fn signature_is_valid(&self, proof: &ghost_common::types::ShareProof) -> bool {
        let Some(activation) = self.addr_bind_activation_time else {
            // Unresolved axis: keep the old behaviour rather than invent one, but do not let it
            // pass quietly — this is the exact condition that produced #677.
            warn!(
                round_id = proof.round_id,
                "GHOST-03: address-bind activation time unresolved — falling back to node-local \
                 round comparison, which cannot agree across nodes (#677)"
            );
            return if self.round_manager.requires_bound_signature(proof.round_id) {
                proof.has_valid_bound_signature()
            } else {
                proof.has_valid_received_by_signature()
            };
        };

        let ts = proof.timestamp as i64;
        // A share mined in the band around the activation instant may legitimately carry either
        // format: the gate fires at a height, but each node adopts it when it sees that block.
        if (ts - activation).abs() <= ERA_BOUNDARY_GRACE_SECS {
            return proof.has_valid_bound_signature() || proof.has_valid_received_by_signature();
        }
        if ts >= activation {
            proof.has_valid_bound_signature()
        } else {
            proof.has_valid_received_by_signature()
        }
    }

    /// signature) and then fed through the standard validation+dedup path.
    /// Returns the number of shares newly accepted.
    pub fn apply_response(&self, resp: &ShareConvergenceResponse) -> usize {
        let mut applied = 0;
        for proof in &resp.missing_shares {
            if !self.signature_is_valid(proof) {
                continue; // GHOST-09: never credit an unsigned/forged backfill
            }

            let miner_hex = hex::encode(&proof.miner_id[..8]);
            let from_node = hex::encode(&proof.received_by[..4]);
            let share_hash = hex::encode(proof.share_hash);
            let round_id = proof.round_id;
            let work = proof.work;
            let timestamp = proof.timestamp as i64;

            if self.round_manager.handle_share_proof(proof.clone()).is_ok() {
                applied += 1;

                if let Some(db) = &self.db {
                    // GHOST-03: persist the backfilled share to the `shares` TABLE.
                    //
                    // This is the whole point of convergence and it was missing. Share gossip
                    // is fire-and-forget (dropped on channel overflow); this protocol exists to
                    // repair those drops. Feeding the RoundManager alone repaired only the
                    // in-memory round view — node-share credit and dedup — while the `shares`
                    // table stayed short.
                    //
                    // At the time the consequence was permanent, compounding ledger divergence:
                    // every node summed a different share set, so every node computed a different
                    // miner split, so the GHOST-02 exact-equality check rejected every proposal —
                    // and nothing in the system ever repaired it. Safety held; liveness did not.
                    //
                    // ⚠ That is HISTORY, not the present. Since v56 the shard owns the payout —
                    // `shard_owed` for the coinbase, `select_shard_miner_work` for the checkpoint
                    // root — and the shard folds only rows whose `received_by` is this node's own
                    // id, which a backfilled row (carrying the ORIGIN's id) never is. These rows
                    // now feed retention, GHOST-03 re-serving, paid-marking and stats. The claim
                    // that this table is "the ONLY thing the payout ledger reads" stood here
                    // after it stopped being true, which is how #647 read as a money-losing bug.
                    //
                    // Mirrors the live-gossip insert in `share_handler.rs` exactly, so a share
                    // backfilled here is byte-identical to one that arrived first time. The
                    // UNIQUE constraint on `share_hash` makes this idempotent.
                    //
                    // Store the SIGNED PROOF alongside the row (not `insert_share`, which
                    // leaves `proof` NULL). A proof-less row is UNSERVABLE — GHOST-03 backfills
                    // from the stored proof blob, so a node can never re-serve it to a third
                    // node, and the divergence this protocol exists to REPAIR instead
                    // PROPAGATES. The window path (`apply_ledger_response`) already does this;
                    // this round-scoped path was the outlier manufacturing unservable orphans.
                    let share_record = ghost_storage::models::ShareRecord {
                        id: None,
                        round_id,
                        miner_id: miner_hex.clone(),
                        difficulty: work,
                        work,
                        share_hash,
                        timestamp,
                        received_by: from_node,
                        valid: true,
                    };
                    let proof_blob = serde_json::to_vec(proof).unwrap_or_default();

                    match db.insert_share_with_proof(&share_record, &proof_blob) {
                        Ok(_) => {
                            if let Err(e) = db.increment_miner_stats(&miner_hex, 1, work) {
                                warn!(
                                    miner = %miner_hex,
                                    error = %e,
                                    "GHOST-03: failed to increment backfilled miner stats"
                                );
                            }
                        }
                        Err(e) => {
                            // Already had it — the UNIQUE constraint is our dedup.
                            if !e.to_string().contains("UNIQUE") {
                                warn!(
                                    miner = %miner_hex,
                                    error = %e,
                                    "GHOST-03: failed to persist backfilled share"
                                );
                            }
                        }
                    }

                    // GHOST-02 / Option A: adopt the backfilled proof's signed payout
                    // address (first-writer-wins) so addresses converge here too.
                    if let Some(addr) = &proof.payout_address {
                        let _ = db.adopt_miner_address(&miner_hex, addr);
                    }
                }
            }
        }
        applied
    }
}

#[async_trait]
impl MessageHandler for ConvergenceHandler {
    async fn handle_message(&self, envelope: Arc<MessageEnvelope>) -> GhostResult<()> {
        // Shares and convergence share a pubsub topic; only handle convergence.
        if envelope.msg_type != MessageType::ShareConvergence {
            return Ok(());
        }
        let payload: ConvergencePayload = match serde_json::from_slice(&envelope.payload) {
            Ok(p) => p,
            Err(_) => return Ok(()), // not a convergence payload — ignore
        };
        match payload {
            ConvergencePayload::Request(req) => {
                let resp = self.handle_request(&req);
                if resp.missing_shares.is_empty() {
                    return Ok(());
                }
                if let Some(send) = &self.send {
                    let bytes = serde_json::to_vec(&ConvergencePayload::Response(resp))
                        .map_err(|e| ghost_common::error::GhostError::P2PMessage(e.to_string()))?;
                    // Addressed to the requester: `missing_shares` is the complement of THIS
                    // peer's advertisement and means nothing to any other node (#647).
                    send(bytes, Some(envelope.sender))?;
                }
            }
            // GHOST-03 ledger sweep — REMOVED in Stage 6.
            //
            // The sweep repaired the LEGACY unpaid ledger. Migration v56 gave the shard
            // ownership of `shares`, which left nothing for it to repair, so it was switched
            // off at runtime on 2026-08-18 and has been a no-op on every node since. Stage 6
            // deletes the machinery; the shard's own summary exchange is the replacement.
            //
            // The two variants are KEPT, inert, for exactly one release. They are serialised
            // with `serde_json` as an externally-tagged enum, so removing them would make a
            // message from a pre-Stage-6 peer fail to decode as a whole envelope. No node
            // emits them any more, but an operator running an older binary still could.
            ConvergencePayload::LedgerRequest(_) | ConvergencePayload::LedgerResponse(_) => {
                debug!(
                    sender = hex::encode(envelope.sender),
                    "GHOST-03: ignoring legacy ledger-convergence message (sweep removed in Stage 6)"
                );
            }
            ConvergencePayload::Response(resp) => {
                let applied = self.apply_response(&resp);
                if applied > 0 {
                    tracing::info!(
                        round_id = resp.round_id,
                        applied,
                        "GHOST-03: backfilled missing shares via ledger convergence"
                    );
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::round::{RoundConfig, RoundManager};
    use ghost_common::identity::NodeIdentity;
    use ghost_common::types::ShareProof;

    const TPL: [u8; 32] = [0x7c; 32];

    /// difficulty-1.0 hash (32 leading zero bits then 0xFF); unique low nonce.
    fn diff1_hash(nonce: u64) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&nonce.to_le_bytes());
        h[27] = 0xFF;
        h
    }

    fn round_manager() -> Arc<RoundManager> {
        let id = NodeIdentity::generate();
        let cfg = RoundConfig {
            share_difficulty: 1.0,
            network_difficulty: 1_000_000.0,
            ..RoundConfig::default()
        };
        let rm = Arc::new(RoundManager::new(id.node_id(), cfg));
        // Put the node at an explicit height BELOW the PoW-verify gate. These tests are about
        // convergence and backfill, not PoW gating, and their fixtures carry `header: None`.
        //
        // This used to be implicit: without a round the height is 0, which sorted below the gate
        // by accident. Since #597 an unknown height fails closed and takes the strict path, so the
        // height a test wants has to be stated rather than inherited from "not set yet".
        rm.start_round(crate::share_pow_verify_height().saturating_sub(1));
        rm.set_template_id(TPL);
        rm
    }

    fn signed_share(signer: &NodeIdentity, nonce: u64) -> ShareProof {
        let mut p = ShareProof {
            header: None,
            tier_log2: None,
            round_id: 1,
            miner_id: [9u8; 32],
            difficulty: 1.0,
            work: 1.0,
            share_hash: diff1_hash(nonce),
            timestamp: 0,
            received_by: signer.node_id(),
            template_id: Some(TPL),
            payout_address: None,
            signature: None,
        };
        p.sign(signer);
        p
    }

    /// The `shares` row a proof becomes — mirrors `share_handler.rs` and `apply_response`.
    fn ledger_row(p: &ShareProof) -> ghost_storage::ShareRecord {
        ghost_storage::ShareRecord {
            id: None,
            round_id: p.round_id,
            miner_id: hex::encode(&p.miner_id[..8]),
            difficulty: p.work,
            work: p.work,
            share_hash: hex::encode(p.share_hash),
            timestamp: p.timestamp as i64,
            received_by: hex::encode(&p.received_by[..4]),
            valid: true,
        }
    }

    /// One outbound frame as a test sees it: the bytes, and the peer it is addressed to.
    type CapturedFrame = (Vec<u8>, Option<ghost_common::types::NodeId>);

    /// Capture the outbound frames a handler emits, WITH the peer each is addressed to.
    fn capturing_send(buf: Arc<std::sync::Mutex<Vec<CapturedFrame>>>) -> ConvergenceSendFn {
        Arc::new(move |bytes, to| {
            buf.lock().unwrap().push((bytes, to));
            Ok(())
        })
    }

    fn convergence_envelope(
        sender: ghost_common::types::NodeId,
        payload: Vec<u8>,
    ) -> Arc<ghost_consensus::message::MessageEnvelope> {
        Arc::new(ghost_consensus::message::MessageEnvelope::new(
            MessageType::ShareConvergence,
            sender,
            payload,
            1,
            [0u8; 64],
        ))
    }

    /// #647: a convergence RESPONSE must be addressed to the peer that asked.
    ///
    /// `missing_shares` is computed as the complement of *that requester's* advertised hash set,
    /// so it is meaningless to every other node. Handing it to `Mesh::broadcast` spent a Noise
    /// send per peer to serve one, and the drain task processes frames one at a time — so the
    /// fan-out, not the queue depth, is what set the drain rate and filled the 64-slot channel.
    ///
    /// Worse, the six nodes that never asked apply the response anyway and, on `more_available`,
    /// each emit a follow-up request of their own. That is the amplification measured when the
    /// v56 cutover left the sweep running: inbound `ShareConvergence` 0/h -> 691/h on ghost-vm7.
    #[tokio::test]
    async fn a_round_convergence_response_is_addressed_to_the_requester() {
        let producer = NodeIdentity::generate();
        let rm_server = round_manager();
        let rm_client = round_manager();

        // The server holds three shares; the client advertises only the first.
        let shares: Vec<ShareProof> = (1..=3).map(|n| signed_share(&producer, n)).collect();
        for sh in &shares {
            rm_server.handle_share_proof(sh.clone()).expect("server");
        }
        rm_client
            .handle_share_proof(shares[0].clone())
            .expect("client");

        let outbox = Arc::new(std::sync::Mutex::new(Vec::new()));
        let server = ConvergenceHandler::new(Arc::clone(&rm_server))
            .with_send(capturing_send(Arc::clone(&outbox)));
        let client = ConvergenceHandler::new(Arc::clone(&rm_client));

        let round_id = rm_client.current_round_id();
        let request = client.request_bytes(round_id).expect("request");

        let requester: ghost_common::types::NodeId = [0xd7; 32];
        server
            .handle_message(convergence_envelope(requester, request))
            .await
            .expect("server answers");

        let frames = outbox.lock().unwrap().clone();
        assert_eq!(frames.len(), 1, "the server must answer exactly once");
        assert_eq!(
            frames[0].1,
            Some(requester),
            "the reply must be addressed to the requester — fanning it out is the per-frame cost \
             that filled the outbound queue (#647)"
        );

        // And it must still be a usable reply, not merely a correctly addressed empty one.
        let payload: ConvergencePayload =
            serde_json::from_slice(&frames[0].0).expect("reply parses");
        let ConvergencePayload::Response(resp) = payload else {
            panic!("the server must answer a Request with a Response");
        };
        assert_eq!(
            resp.missing_shares.len(),
            2,
            "the reply must carry the two shares the requester did not advertise"
        );
    }

    /// The periodic ADVERTISEMENT is genuinely for every peer, so it must NOT be addressed —
    /// otherwise the routing fix would quietly turn a mesh-wide advertisement into a unicast and
    /// convergence would stop reaching anyone but one node.
    #[test]
    fn a_round_convergence_request_carries_no_address() {
        let rm = round_manager();
        let handler = ConvergenceHandler::new(Arc::clone(&rm));
        let bytes = handler
            .request_bytes(rm.current_round_id())
            .expect("request");
        let payload: ConvergencePayload = serde_json::from_slice(&bytes).expect("parses");
        assert!(
            matches!(payload, ConvergencePayload::Request(_)),
            "the periodic frame is an advertisement, and main.rs enqueues it with `None` so it \
             fans out to every peer"
        );
    }

    /// GHOST-03 must repair the `shares` TABLE, not merely the in-memory round view.
    ///
    /// The payout ledger reads that table and nothing else. Backfilling only the RoundManager
    /// left every node summing a different share set — so every node computed a different miner
    /// split, and the GHOST-02 exact-equality check rejected every payout proposal, permanently,
    /// with nothing in the system able to repair it.
    ///
    /// `convergence_backfills_a_missing_share` (below) asserts only `round_share_hashes`. That
    /// is exactly the blind spot the bug lived in: convergence looked healthy in memory while
    /// the ledger it exists to protect silently diverged.
    #[test]
    fn convergence_backfills_the_payout_ledger_not_just_memory() {
        let producer = NodeIdentity::generate();
        let rm_a = round_manager();
        let rm_b = round_manager();
        let db_a = Arc::new(ghost_storage::Database::in_memory().expect("db a"));
        let db_b = Arc::new(ghost_storage::Database::in_memory().expect("db b"));

        let ch_a = ConvergenceHandler::new(Arc::clone(&rm_a)).with_db(Arc::clone(&db_a));
        let ch_b = ConvergenceHandler::new(Arc::clone(&rm_b)).with_db(Arc::clone(&db_b));

        // A received three shares and persisted them. B's gossip dropped two — the fire-and-
        // forget broadcast overflowed, exactly as it does in production.
        let shares: Vec<ShareProof> = (1..=3).map(|n| signed_share(&producer, n)).collect();
        for s in &shares {
            rm_a.handle_share_proof(s.clone()).expect("A accepts");
            db_a.insert_share(&ledger_row(s)).expect("A persists");
        }
        rm_b.handle_share_proof(shares[0].clone())
            .expect("B accepts the one it got");
        db_b.insert_share(&ledger_row(&shares[0]))
            .expect("B persists the one it got");

        // What a payout would actually be computed from on each node.
        let unpaid_work = |db: &ghost_storage::Database| -> f64 {
            db.get_top_unpaid_miners(i64::MAX, 100)
                .expect("ledger")
                .iter()
                .map(|(_, w)| *w)
                .sum()
        };
        assert_eq!(unpaid_work(&db_a), 3.0);
        assert_eq!(unpaid_work(&db_b), 1.0, "B starts with a short ledger");

        // B advertises what it holds; A replies with the proofs B is missing; B applies them.
        let req = ch_b.build_request(1);
        let resp = ch_a.handle_request(&req);
        let applied = ch_b.apply_response(&resp);
        assert_eq!(applied, 2, "both dropped shares must be backfilled");

        assert_eq!(
            unpaid_work(&db_b),
            unpaid_work(&db_a),
            "after convergence B's PAYOUT LEDGER must equal A's — if it does not, the two nodes \
             compute different miner splits and GHOST-02 rejects the payout forever"
        );

        // And it must be idempotent: re-applying cannot double-credit the work.
        ch_b.apply_response(&resp);
        assert_eq!(
            unpaid_work(&db_b),
            3.0,
            "re-applying a convergence response must not double-count shares"
        );
    }

    #[test]
    fn convergence_backfills_a_missing_share() {
        let producer = NodeIdentity::generate();
        let rm_a = round_manager();
        let rm_b = round_manager();

        // A holds the share; B is missing it.
        let share = signed_share(&producer, 1);
        rm_a.handle_share_proof(share.clone()).unwrap();
        assert!(rm_a.round_share_hashes(1).contains(&share.share_hash));
        assert!(!rm_b.round_share_hashes(1).contains(&share.share_hash));

        let ch_a = ConvergenceHandler::new(Arc::clone(&rm_a));
        let ch_b = ConvergenceHandler::new(Arc::clone(&rm_b));
        let request = ch_b.build_request(1); // B advertises (nothing)
        let response = ch_a.handle_request(&request); // A returns the missing share
        assert_eq!(ch_b.apply_response(&response), 1);
        assert!(
            rm_b.round_share_hashes(1).contains(&share.share_hash),
            "B's ledger holds the share after convergence"
        );
    }

    #[test]
    fn convergence_rejects_a_forged_backfill() {
        let attacker = NodeIdentity::generate();
        let victim = NodeIdentity::generate();
        let rm_b = round_manager();

        // received_by = victim, but signed by attacker → GHOST-09 invalid.
        let mut forged = signed_share(&victim, 2);
        forged.sign(&attacker);
        let resp = ShareConvergenceResponse {
            more_available: false,
            round_id: 1,
            share_count: 1,
            total_work: 1.0,
            missing_shares: vec![forged],
        };
        assert_eq!(
            ConvergenceHandler::new(rm_b).apply_response(&resp),
            0,
            "a forged backfill is rejected (GHOST-09 re-checked on the convergence path)"
        );
    }

    #[test]
    fn remote_share_with_senders_template_is_accepted_local_stays_validated() {
        // M-MINE-1 validates the template against THIS node's templates. A gossiped
        // share (received_by = another node) was mined against the SENDER's coinbase
        // template — which this node cannot know — so M-MINE-1 must NOT reject it:
        // its trust anchors are the GHOST-09 signature (the signer vouches), C4 PoW,
        // and C5 dedup, and the signer already validated its own template. Without
        // this, every cross-node share is dropped as StaleTemplate and GHOST-02
        // rejects every payout once enforcement activates.
        let unknown_template = [0x33u8; 32]; // NOT the node's TPL

        // Remote share: received_by = a different node, signed by it, sender's template.
        let remote_signer = NodeIdentity::generate();
        let mut remote = ShareProof {
            header: None,
            tier_log2: None,
            round_id: 1,
            miner_id: [9u8; 32],
            difficulty: 1.0,
            work: 1.0,
            share_hash: diff1_hash(101),
            timestamp: 0,
            received_by: remote_signer.node_id(),
            template_id: Some(unknown_template),
            payout_address: None,
            signature: None,
        };
        remote.sign(&remote_signer);
        let rm = round_manager(); // template = TPL, our_node_id = (internal)
        assert!(
            rm.handle_share_proof(remote.clone()).is_ok(),
            "a gossiped share carrying the sender's (locally-unknown) template must be accepted"
        );
        assert!(rm.round_share_hashes(1).contains(&remote.share_hash));

        // Local share: received_by = self, unknown template → STILL stale-rejected.
        let local_id = NodeIdentity::generate();
        let cfg = RoundConfig {
            share_difficulty: 1.0,
            network_difficulty: 1_000_000.0,
            ..RoundConfig::default()
        };
        let rm_local = Arc::new(RoundManager::new(local_id.node_id(), cfg));
        // Needs an explicit round/height like `round_manager()` does: since #597 an unknown height
        // fails closed. This used to be unnecessary only because the template check refused the
        // share before anything read the height.
        rm_local.start_round(crate::share_pow_verify_height().saturating_sub(1));
        rm_local.set_template_id(TPL);
        let mut local = ShareProof {
            header: None,
            tier_log2: None,
            round_id: 1,
            miner_id: [9u8; 32],
            difficulty: 1.0,
            work: 1.0,
            share_hash: diff1_hash(102),
            timestamp: 0,
            received_by: local_id.node_id(),
            template_id: Some(unknown_template),
            payout_address: None,
            signature: None,
        };
        local.sign(&local_id);
        assert!(
            rm_local.handle_share_proof(local).is_ok(),
            "a LOCAL share (received_by == self) reaching convergence is our own share coming back \
             for repair, not a fresh submission — an expired template must not refuse it (#639)"
        );
    }

    #[test]
    fn remote_share_work_consistency_uses_absolute_model_not_pool_min() {
        // M-9 work-consistency must validate proof.work against proof.difficulty
        // (the ABSOLUTE model: work == difficulty, exactly as the SRI/local path
        // `record_share` credits it), NOT proof.difficulty / share_difficulty. The
        // relative model assumes a pool minimum of 1; with the PRODUCTION DEFAULT
        // share_difficulty=1000 it computed calculated_work = work/1000 and rejected
        // every gossiped share, making the elders hold 0 shares and GHOST-02 reject
        // every payout once enforcement activates. C4 already proves the hash meets
        // proof.difficulty, so work==difficulty is fully PoW-bounded.
        let producer = NodeIdentity::generate();
        let cfg = RoundConfig {
            share_difficulty: 1000.0, // PRODUCTION DEFAULT (round_manager() uses 1.0 and hides the bug)
            network_difficulty: 1_000_000.0,
            ..RoundConfig::default()
        };
        let rm = Arc::new(RoundManager::new(NodeIdentity::generate().node_id(), cfg));
        // Explicit height below the PoW-verify gate — this test is about the M-9 work model, and
        // its fixture carries no header. See the note in `round_manager()`.
        rm.start_round(crate::share_pow_verify_height().saturating_sub(1));
        rm.set_template_id(TPL);

        let mut p = ShareProof {
            header: None,
            tier_log2: None,
            round_id: 1,
            miner_id: [9u8; 32],
            difficulty: 1.0,
            work: 1.0, // absolute: work == difficulty (what the SRI sets)
            share_hash: diff1_hash(50),
            timestamp: 0,
            received_by: producer.node_id(),
            template_id: Some(TPL),
            payout_address: None,
            signature: None,
        };
        p.sign(&producer);
        assert!(
            rm.handle_share_proof(p.clone()).is_ok(),
            "a gossiped share with work==difficulty must pass M-9 regardless of the local share_difficulty"
        );

        // A share that claims more work than its difficulty justifies is still rejected.
        let mut inflated = p.clone();
        inflated.work = 10.0; // 10x the claimed difficulty
        inflated.sign(&producer);
        assert!(
            matches!(
                rm.handle_share_proof(inflated),
                Err(crate::round::ShareError::WorkValueTooHigh { .. })
            ),
            "claiming work that exceeds the difficulty is still rejected (no inflation)"
        );
    }

    /// #590, at the responder. The bound has to be where the wire message is built, not only in
    /// the query, or a future caller reintroduces the overflow. The ledger lane has been bounded
    /// since #558; this one was not, so a busy round produced a response past the 1 MB envelope
    /// cap that every receiver dropped at `debug!` — indistinguishable from "nothing to reconcile".
    #[test]
    fn handle_request_itself_respects_the_budget() {
        let producer = NodeIdentity::generate();
        let rm = round_manager();
        for nonce in 0..(MAX_PROOFS_PER_RESPONSE + 50) {
            rm.handle_share_proof(signed_share(&producer, nonce as u64))
                .unwrap();
        }
        let h = ConvergenceHandler::new(std::sync::Arc::clone(&rm));
        let resp = h.handle_request(&ShareConvergenceMessage {
            round_id: 1,
            share_hashes: vec![],
            share_count: 0,
            total_work: 0.0,
        });
        assert!(
            resp.missing_shares.len() <= MAX_PROOFS_PER_RESPONSE,
            "handle_request must bound the wire response, got {}",
            resp.missing_shares.len()
        );
        assert!(
            resp.more_available,
            "a truncated wire response must flag it"
        );
    }

    #[test]
    fn a_busy_round_response_is_bounded_and_says_so() {
        let producer = NodeIdentity::generate();
        let rm = round_manager();
        // Comfortably more proofs than the count cap.
        for nonce in 0..(MAX_PROOFS_PER_RESPONSE + 50) {
            let p = signed_share(&producer, nonce as u64);
            rm.handle_share_proof(p).unwrap();
        }

        let theirs: HashSet<[u8; 32]> = HashSet::new();
        let (served, more) = rm.proofs_missing_from_bounded(
            1,
            &theirs,
            MAX_PROOFS_PER_RESPONSE,
            MAX_PROOF_BYTES_PER_RESPONSE,
        );

        assert!(
            served.len() <= MAX_PROOFS_PER_RESPONSE,
            "response must respect the count cap, served {}",
            served.len()
        );
        let bytes: usize = served
            .iter()
            .map(|p| serde_json::to_vec(p).map(|v| v.len()).unwrap_or(0))
            .sum();
        assert!(
            bytes <= MAX_PROOF_BYTES_PER_RESPONSE,
            "response must respect the byte budget, was {bytes}"
        );
        assert!(
            more,
            "a truncated response MUST flag more_available, or the requester treats the round as \
             reconciled and never asks again"
        );
    }

    /// The flag must not cry wolf: a response that carried everything says so.
    #[test]
    fn a_complete_round_response_does_not_flag_more() {
        let producer = NodeIdentity::generate();
        let rm = round_manager();
        for nonce in 0..3u64 {
            rm.handle_share_proof(signed_share(&producer, nonce))
                .unwrap();
        }
        let theirs: HashSet<[u8; 32]> = HashSet::new();
        let (served, more) = rm.proofs_missing_from_bounded(
            1,
            &theirs,
            MAX_PROOFS_PER_RESPONSE,
            MAX_PROOF_BYTES_PER_RESPONSE,
        );
        assert_eq!(served.len(), 3);
        assert!(
            !more,
            "a complete response must not ask the peer to come back"
        );
    }

    #[test]
    fn proofs_missing_from_excludes_known_hashes() {
        let producer = NodeIdentity::generate();
        let rm = round_manager();
        let s1 = signed_share(&producer, 10);
        let s2 = signed_share(&producer, 11);
        rm.handle_share_proof(s1.clone()).unwrap();
        rm.handle_share_proof(s2.clone()).unwrap();

        // Peer already has s1 → only s2 is "missing".
        let known: std::collections::HashSet<[u8; 32]> = [s1.share_hash].into_iter().collect();
        let missing = rm.proofs_missing_from(1, &known);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].share_hash, s2.share_hash);
    }

    /// The property #677 broke: two nodes whose LOCAL activation rounds differ must reach the
    /// SAME verdict on the same share.
    ///
    /// This is the whole defect, reduced. vm1 recorded the address-bind era at round 111,556 and
    /// vm8 at 111,553, so a share in rounds 111,553-111,555 was bound-signed as far as vm8 was
    /// concerned and legacy-signed as far as vm1 was concerned. vm1 discarded every one as
    /// `bad_sig`, for ever, because the GHOST-03 sweep re-requests the same window on every
    /// rotation. The share sets never converged, the per-address recomputes diverged by 6.71%
    /// against a 2% tolerance, and no payout checkpoint could ever be ratified.
    ///
    /// Judged on the shared timestamp axis, the auditor's own numbering stops mattering.
    #[test]
    fn the_same_share_gets_the_same_verdict_whatever_the_nodes_local_activation_round() {
        const ACTIVATION: i64 = 1_785_894_000;
        let signer = NodeIdentity::generate();

        // A post-gate share, correctly bound-signed by the node that received it, well clear of
        // the grace band.
        let mut post = signed_share(&signer, 1);
        post.round_id = 111_554;
        post.timestamp = (ACTIVATION + 10 * ERA_BOUNDARY_GRACE_SECS) as u64;
        post.payout_address = Some("bc1qtest".to_string());
        post.sign_bound(&signer);

        // Two nodes that disagree about where the era boundary sits in their own numbering —
        // exactly vm1 (111,556) and vm8 (111,553).
        let vm1 =
            ConvergenceHandler::new(round_manager()).with_addr_bind_activation_time(ACTIVATION);
        let vm8 =
            ConvergenceHandler::new(round_manager()).with_addr_bind_activation_time(ACTIVATION);

        assert!(
            vm1.signature_is_valid(&post),
            "a correctly bound-signed post-gate share must verify regardless of the auditor's \
             own round numbering — rejecting it here is #677, and it costs every payout"
        );
        assert_eq!(
            vm1.signature_is_valid(&post),
            vm8.signature_is_valid(&post),
            "two nodes must never disagree about the same share"
        );

        // A pre-gate share carrying the legacy signature stays verifiable for ever.
        let mut pre = signed_share(&signer, 2);
        pre.round_id = 111_554;
        pre.timestamp = (ACTIVATION - 10 * ERA_BOUNDARY_GRACE_SECS) as u64;
        pre.sign(&signer);
        assert!(
            vm1.signature_is_valid(&pre),
            "a pre-gate share must not become unservable because the gate later fired"
        );
        assert_eq!(vm1.signature_is_valid(&pre), vm8.signature_is_valid(&pre));
    }

    /// Shares mined in the band around the activation instant may legitimately carry EITHER
    /// format, because each node adopts the gate when it sees that block. Both must verify, or
    /// the sweep re-requests them for ever.
    #[test]
    fn either_signature_format_verifies_inside_the_boundary_band() {
        const ACTIVATION: i64 = 1_785_894_000;
        let signer = NodeIdentity::generate();
        let node =
            ConvergenceHandler::new(round_manager()).with_addr_bind_activation_time(ACTIVATION);

        for offset in [-ERA_BOUNDARY_GRACE_SECS / 2, 0, ERA_BOUNDARY_GRACE_SECS / 2] {
            let mut legacy = signed_share(&signer, 10);
            legacy.timestamp = (ACTIVATION + offset) as u64;
            legacy.sign(&signer);
            assert!(
                node.signature_is_valid(&legacy),
                "a legacy-signed share {offset}s from activation must still verify"
            );

            let mut bound = signed_share(&signer, 11);
            bound.timestamp = (ACTIVATION + offset) as u64;
            bound.payout_address = Some("bc1qtest".to_string());
            bound.sign_bound(&signer);
            assert!(
                node.signature_is_valid(&bound),
                "a bound-signed share {offset}s from activation must still verify"
            );
        }
    }

    /// The band is a concession at the boundary, not an amnesty: outside it the era's rule is
    /// enforced, so a post-gate share cannot drop its address binding.
    #[test]
    fn outside_the_band_the_eras_rule_is_enforced() {
        const ACTIVATION: i64 = 1_785_894_000;
        let signer = NodeIdentity::generate();
        let node =
            ConvergenceHandler::new(round_manager()).with_addr_bind_activation_time(ACTIVATION);

        let mut unbound = signed_share(&signer, 20);
        unbound.timestamp = (ACTIVATION + 10 * ERA_BOUNDARY_GRACE_SECS) as u64;
        unbound.payout_address = Some("bc1qtest".to_string());
        unbound.sign(&signer); // legacy format, well after the gate
        assert!(
            !node.signature_is_valid(&unbound),
            "GHOST-09 address binding must still hold well past the gate"
        );

        let mut forged = signed_share(&signer, 21);
        forged.timestamp = (ACTIVATION + 10 * ERA_BOUNDARY_GRACE_SECS) as u64;
        forged.payout_address = Some("bc1qtest".to_string());
        forged.sign_bound(&signer);
        forged.payout_address = Some("bc1qattacker".to_string()); // swap after signing
        assert!(
            !node.signature_is_valid(&forged),
            "swapping the bound address after signing must not verify"
        );
    }
}
