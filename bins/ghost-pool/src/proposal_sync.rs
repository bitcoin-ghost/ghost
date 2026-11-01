//! Getting a won block's payout proposal to the nodes that need it.
//!
//! Settling a won block means reading the payout identity off its coinbase and finding the proposal
//! that identity names. Only the node that built a proposal holds it — since the vote was removed
//! nothing gossips it — so without this every other node cannot settle the block, and its ledger
//! silently keeps owing work the pool already paid.
//!
//! So the winner pushes the proposal when its block is accepted, and a node that still lacks it when
//! the block matures asks for it, repeatedly, until it arrives (`ShardRuntime::retry_deferred`).
//!
//! **What a peer can and cannot do here.** A response is accepted only if it answers a question this
//! node asked, about an identity read off the chain, and only if the proposal hashes to that
//! identity recomputed from its own contents. So a peer cannot doctor a proposal, and cannot plant
//! one the chain never named. Only known nodes are listened to, because the hash proves a proposal
//! is the one named and not that it is this pool's: another Ghost deployment's block carries the
//! same tag, and accepting its proposal would mark that block ours and discharge our miners' work
//! against money this pool never received.
//!
//! A push arrives before anyone has asked, so it cannot be held to the same test. It is accepted
//! only from the node that built the proposal, and it proves nothing about a block: it stores a
//! proposal, and a block still has to name that proposal on chain before anything settles.

use std::sync::Arc;

use async_trait::async_trait;
use ghost_common::error::GhostResult;
use ghost_common::types::{NodeId, PayoutProposal};
use ghost_consensus::mesh::MessageHandler;
use ghost_consensus::message::{MessageEnvelope, MessageType};
use ghost_consensus::vote_handler::compute_proposal_hash;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Request and response share one message type, disambiguated on deserialize — the same shape the
/// convergence and checkpoint-sync exchanges use, so no second type is needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalSyncPayload {
    /// "Who does this payout identity belong to?" — the 16 bytes read off a coinbase.
    Request { payout_id: [u8; 16] },
    /// The proposal, as stored JSON. Verified by rehashing, never by trusting the sender.
    Response { proposal_json: String },
    /// "I won a block paying this" — sent once, by the node that built the proposal.
    ///
    /// A node on an older build cannot parse this variant and ignores it, which leaves it where it
    /// was before and costs nothing else.
    Push { proposal_json: String },
}

/// Broadcasts a serialized [`ProposalSyncPayload`] to the mesh.
pub type ProposalSyncSendFn = Arc<dyn Fn(Vec<u8>) -> GhostResult<()> + Send + Sync>;

/// Serves proposal requests from peers, and accepts answers to our own.
pub struct ProposalSyncHandler {
    db: Arc<ghost_storage::Database>,
    send: Option<ProposalSyncSendFn>,
}

impl ProposalSyncHandler {
    pub fn new(db: Arc<ghost_storage::Database>) -> Self {
        Self { db, send: None }
    }

    pub fn with_send(mut self, send: ProposalSyncSendFn) -> Self {
        self.send = Some(send);
        self
    }

    /// Ask the mesh for the proposal a coinbase names.
    pub fn request(&self, payout_id: [u8; 16]) -> GhostResult<()> {
        let Some(send) = &self.send else {
            return Ok(());
        };
        let payload = serde_json::to_vec(&ProposalSyncPayload::Request { payout_id })
            .map_err(|e| ghost_common::error::GhostError::Serialization(e.to_string()))?;
        info!(
            payout_id = %hex::encode(payout_id),
            "requesting the payout proposal a won block names but we do not hold"
        );
        send(payload)
    }

    /// Tell the mesh about a block we won, given the proposal its coinbase names.
    ///
    /// Marks the proposal first: the send is best effort and a peer that misses it pulls from us at
    /// maturity, which only works if we still hold it then.
    pub fn announce_win(&self, proposal_hash: [u8; 32]) -> GhostResult<()> {
        let payout_id = payout_id_of(&proposal_hash);
        self.db.mark_proposal_won(&payout_id)?;
        let Some((_, proposal_json)) = self.db.get_proposal_by_hash_prefix(&payout_id)? else {
            warn!(
                payout_id = %hex::encode(payout_id),
                "won a block whose payout proposal we no longer hold — peers cannot settle it"
            );
            return Ok(());
        };
        let Some(send) = &self.send else {
            return Ok(());
        };
        let payload = serde_json::to_vec(&ProposalSyncPayload::Push { proposal_json })
            .map_err(|e| ghost_common::error::GhostError::Serialization(e.to_string()))?;
        info!(payout_id = %hex::encode(payout_id), "pushing a won block's payout proposal");
        send(payload)
    }

    /// Answer a peer's request, if we hold the proposal.
    fn serve(&self, payout_id: [u8; 16]) -> GhostResult<()> {
        let Some(send) = &self.send else {
            return Ok(());
        };
        let Some((_, proposal_json)) = self.db.get_proposal_by_hash_prefix(&payout_id)? else {
            return Ok(()); // Not held here; some other peer will answer.
        };
        let payload = serde_json::to_vec(&ProposalSyncPayload::Response { proposal_json })
            .map_err(|e| ghost_common::error::GhostError::Serialization(e.to_string()))?;
        debug!(payout_id = %hex::encode(payout_id), "serving a payout proposal to a peer");
        send(payload)
    }

    /// The nodes this exchange listens to: the elders and the latest ratified node set. Both,
    /// because a node can be in one without the other, and either alone would refuse a real win.
    fn is_known(&self, node: &NodeId) -> GhostResult<bool> {
        if self.db.get_mpc_elder_node_ids()?.contains(node) {
            return Ok(true);
        }
        Ok(self
            .db
            .get_latest_payout_ledger_checkpoint()?
            .is_some_and(|cp| cp.node_shares.iter().any(|(id, _)| id == node)))
    }

    /// Parse a proposal and recompute its hash; `None` unless its contents hash to what it claims.
    fn self_hashing(proposal_json: &str) -> Option<PayoutProposal> {
        let proposal: PayoutProposal = match serde_json::from_str(proposal_json) {
            Ok(p) => p,
            Err(e) => {
                debug!(error = %e, "discarding an unparseable payout proposal from a peer");
                return None;
            }
        };
        let recomputed = compute_proposal_hash(&proposal);
        if recomputed != proposal.proposal_hash {
            warn!(
                claimed = %hex::encode(&proposal.proposal_hash[..8]),
                recomputed = %hex::encode(&recomputed[..8]),
                "discarding a proposal whose contents do not hash to the identity it claims"
            );
            return None;
        }
        Some(proposal)
    }

    /// Store a verified proposal, unless we already hold it.
    ///
    /// ⛔ `store_payout_proposal` is `INSERT OR REPLACE`, which resets `is_approved`. Replaying a
    /// proposal this node has armed must not disarm it across a restart.
    fn store_new(&self, proposal: &PayoutProposal, proposal_json: &str) -> GhostResult<()> {
        let payout_id = payout_id_of(&proposal.proposal_hash);
        if self.db.get_proposal_by_hash_prefix(&payout_id)?.is_none() {
            self.db.store_payout_proposal(
                &proposal.proposal_hash,
                proposal.round_id,
                proposal.block_height,
                proposal_json,
            )?;
            info!(
                proposal = %hex::encode(&proposal.proposal_hash[..8]),
                "stored a payout proposal fetched from a peer"
            );
        }
        Ok(())
    }

    /// Accept an answer to a request of ours; see the module docs for what each check is for.
    pub fn accept(&self, sender: &NodeId, proposal_json: &str) -> GhostResult<Option<[u8; 32]>> {
        if !self.is_known(sender)? {
            debug!(sender = %hex::encode(&sender[..8]), "proposal response from an unknown node");
            return Ok(None);
        }
        let Some(proposal) = Self::self_hashing(proposal_json) else {
            return Ok(None);
        };
        let payout_id = payout_id_of(&proposal.proposal_hash);
        let asked = self
            .db
            .list_deferred_settlements()?
            .iter()
            .any(|(_, _, wanted)| *wanted == payout_id);
        if !asked {
            debug!(payout_id = %hex::encode(payout_id), "proposal response nobody asked for");
            return Ok(None);
        }
        // Being asked for means a block on the chain names it.
        self.db.mark_proposal_won(&payout_id)?;
        self.store_new(&proposal, proposal_json)?;
        Ok(Some(proposal.proposal_hash))
    }

    /// Accept a push from the node that won; see the module docs for why this is enough.
    ///
    /// Not marked won: the only evidence so far is the sender's word, and a mark never expires. The
    /// walk marks it once the chain agrees, and a copy pruned before then is fetched like any other.
    pub fn accept_push(
        &self,
        sender: &NodeId,
        proposal_json: &str,
    ) -> GhostResult<Option<[u8; 32]>> {
        if !self.is_known(sender)? {
            debug!(sender = %hex::encode(&sender[..8]), "proposal push from an unknown node");
            return Ok(None);
        }
        let Some(proposal) = Self::self_hashing(proposal_json) else {
            return Ok(None);
        };
        if proposal.proposer != *sender {
            warn!(
                sender = %hex::encode(&sender[..8]),
                proposer = %hex::encode(&proposal.proposer[..8]),
                "discarding a pushed proposal the sender did not build"
            );
            return Ok(None);
        }
        self.store_new(&proposal, proposal_json)?;
        Ok(Some(proposal.proposal_hash))
    }

    pub(crate) fn on_payload(
        &self,
        sender: &NodeId,
        payload: ProposalSyncPayload,
    ) -> GhostResult<()> {
        match payload {
            // Every holder answers with a broadcast, so a stranger's request must not cost one.
            ProposalSyncPayload::Request { payout_id } => {
                if self.is_known(sender)? {
                    self.serve(payout_id)?;
                }
                Ok(())
            }
            ProposalSyncPayload::Response { proposal_json } => {
                self.accept(sender, &proposal_json).map(|_| ())
            }
            ProposalSyncPayload::Push { proposal_json } => {
                self.accept_push(sender, &proposal_json).map(|_| ())
            }
        }
    }
}

fn payout_id_of(proposal_hash: &[u8; 32]) -> [u8; 16] {
    let mut id = [0u8; 16];
    id.copy_from_slice(&proposal_hash[..16]);
    id
}

#[async_trait]
impl MessageHandler for ProposalSyncHandler {
    async fn handle_message(&self, envelope: Arc<MessageEnvelope>) -> GhostResult<()> {
        if envelope.msg_type != MessageType::PayoutProposalSync {
            return Ok(());
        }
        // A peer on an older build sends something we cannot parse; ignoring it keeps a mixed
        // fleet working rather than filling the log.
        let Ok(payload) = serde_json::from_slice::<ProposalSyncPayload>(&envelope.payload) else {
            return Ok(());
        };
        self.on_payload(&envelope.sender, payload)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ghost_common::types::{PayoutEntry, PayoutType};

    pub(crate) fn a_proposal() -> PayoutProposal {
        let mut p = PayoutProposal {
            proposal_hash: [0u8; 32],
            round_id: 7,
            block_hash: [3u8; 32],
            block_height: 960_000,
            proposer: [9u8; 32],
            miner_payouts: vec![PayoutEntry {
                address: b"bc1qminer".to_vec(),
                amount: 100,
                recipient_id: [1u8; 32],
                payout_type: PayoutType::Mining,
            }],
            node_payouts: vec![],
            treasury_amount: 5,
            treasury_address: b"bc1qtreasury".to_vec(),
            tx_fees: 1,
            subsidy: 312_500_000,
            timestamp: 1_700_000_000,
            tx_fees_unallocated: 0,
        };
        p.proposal_hash = compute_proposal_hash(&p);
        p
    }

    const PEER: NodeId = [0x77; 32];
    const STRANGER: NodeId = [0x66; 32];

    fn handler() -> (Arc<ghost_storage::Database>, ProposalSyncHandler) {
        let db = Arc::new(ghost_storage::Database::in_memory().expect("db"));
        ratify(&db, &[PEER, a_proposal().proposer]);
        (Arc::clone(&db), ProposalSyncHandler::new(db))
    }

    /// Make `nodes` the ratified set — the same row a finalised checkpoint leaves.
    pub(crate) fn ratify(db: &ghost_storage::Database, nodes: &[NodeId]) {
        db.upsert_payout_ledger_checkpoint(&ghost_storage::queries::PayoutLedgerCheckpointRecord {
            height: 1,
            cutoff_ts: 1,
            ledger_root: [0u8; 32],
            proposer_id: hex::encode(nodes[0]),
            active_node_count: nodes.len() as u32,
            miner_payouts: vec![],
            node_shares: nodes.iter().map(|n| (*n, 5)).collect(),
        })
        .expect("ratify");
    }

    /// A handler that records what it would have put on the wire.
    fn capturing(db: &Arc<ghost_storage::Database>) -> (ProposalSyncHandler, Arc<Sent>) {
        let sent: Arc<Sent> = Arc::default();
        let tx = Arc::clone(&sent);
        let handler = ProposalSyncHandler::new(Arc::clone(db)).with_send(Arc::new(move |bytes| {
            tx.lock().push(bytes);
            Ok(())
        }));
        (handler, sent)
    }

    type Sent = parking_lot::Mutex<Vec<Vec<u8>>>;

    fn id_of(p: &PayoutProposal) -> [u8; 16] {
        payout_id_of(&p.proposal_hash)
    }

    fn holds(db: &ghost_storage::Database, p: &PayoutProposal) -> bool {
        db.get_proposal_by_hash_prefix(&id_of(p)).unwrap().is_some()
    }

    fn ask_for(db: &ghost_storage::Database, p: &PayoutProposal) {
        db.defer_settlement("00aa", 960_000, &id_of(p)).unwrap();
    }

    /// An honest response to our own question is stored, and afterwards the proposal is findable by
    /// the identity a coinbase would name — which is the whole point of fetching it.
    #[test]
    fn an_answer_to_our_request_is_accepted_and_becomes_findable() {
        let (db, h) = handler();
        let proposal = a_proposal();
        ask_for(&db, &proposal);
        let json = serde_json::to_string(&proposal).unwrap();

        let stored = h.accept(&PEER, &json).expect("accept");

        assert_eq!(stored, Some(proposal.proposal_hash));
        assert!(
            holds(&db, &proposal),
            "a fetched proposal must be findable by the identity the coinbase carries"
        );

        // Asked for means a block names it, so this copy is one a later node can fetch.
        let past_any_window = chrono::Utc::now().timestamp() + 3600;
        db.prune_payout_proposals(past_any_window).unwrap();
        assert!(
            holds(&db, &proposal),
            "a fetched proposal must outlive the prune"
        );
    }

    /// A self-hashing proposal proves only that it is itself. If no block asked for it, storing it
    /// would let any known peer give a node an owner for a tag that means nothing.
    #[test]
    fn a_proposal_nobody_asked_for_is_refused() {
        let (db, h) = handler();
        let proposal = a_proposal();
        let json = serde_json::to_string(&proposal).unwrap();

        assert_eq!(h.accept(&PEER, &json).expect("accept"), None);
        assert!(!holds(&db, &proposal));
    }

    /// The real proposal behind a real tag is exactly what a sibling Ghost deployment could send
    /// about its own block. The hash cannot tell that apart; only who is speaking can.
    #[test]
    fn an_unknown_node_cannot_answer_a_request() {
        let (db, h) = handler();
        let proposal = a_proposal();
        ask_for(&db, &proposal);
        let json = serde_json::to_string(&proposal).unwrap();

        assert_eq!(h.accept(&STRANGER, &json).expect("accept"), None);
        assert!(!holds(&db, &proposal));
    }

    /// The elders count as known even with no ratified checkpoint, so a young node can settle.
    #[test]
    fn an_elder_is_known_without_a_checkpoint() {
        let db = Arc::new(ghost_storage::Database::in_memory().expect("db"));
        let h = ProposalSyncHandler::new(Arc::clone(&db));
        let proposal = a_proposal();
        ask_for(&db, &proposal);
        let json = serde_json::to_string(&proposal).unwrap();
        assert_eq!(h.accept(&PEER, &json).expect("accept"), None);

        db.save_mpc_contribution(&ghost_storage::queries::MpcContributionRecord {
            elder_position: 0,
            contributor_node_id: hex::encode(PEER),
            prev_params_hash: [0u8; 32],
            new_params_hash: [1u8; 32],
            contribution_proof: vec![2u8; 4],
            epoch: 1,
            created_at: 1,
        })
        .expect("elder");

        assert!(h.accept(&PEER, &json).expect("accept").is_some());
    }

    /// The trust-free property: a peer cannot hand back a doctored proposal under a real identity.
    ///
    /// Here the amounts are altered while the claimed hash is left alone — exactly what a peer
    /// would do to redirect a payout it knows we are about to settle.
    #[test]
    fn a_doctored_proposal_is_refused() {
        let (db, h) = handler();
        let mut proposal = a_proposal();
        let real_hash = proposal.proposal_hash;
        ask_for(&db, &proposal);

        proposal.miner_payouts[0].amount = 999_999;
        proposal.miner_payouts[0].address = b"bc1qattacker".to_vec();
        // Claimed identity left untouched, so it still "looks like" the one we asked for.
        proposal.proposal_hash = real_hash;

        let json = serde_json::to_string(&proposal).unwrap();
        assert_eq!(
            h.accept(&PEER, &json).expect("accept"),
            None,
            "contents that do not hash to the claimed identity must be refused"
        );
        assert!(!holds(&db, &proposal), "nothing should have been stored");
    }

    #[test]
    fn unparseable_responses_are_ignored() {
        let (_, h) = handler();
        assert_eq!(h.accept(&PEER, "not json").expect("accept"), None);
    }

    /// Serving a request we cannot answer is a no-op rather than an error — some other peer holds
    /// it, and a node that lacks it has nothing useful to say.
    #[test]
    fn serving_an_unknown_identity_is_a_no_op() {
        let (_, h) = handler();
        assert!(h.serve([0xAB; 16]).is_ok());
    }

    /// The push carries the proposal the block names, and marks it before it can be lost to a send
    /// that fails.
    #[test]
    fn a_win_is_pushed_and_marked_won() {
        let (db, _) = handler();
        let (h, sent) = capturing(&db);
        let proposal = a_proposal();
        let json = serde_json::to_string(&proposal).unwrap();
        db.store_payout_proposal(
            &proposal.proposal_hash,
            proposal.round_id,
            proposal.block_height,
            &json,
        )
        .unwrap();

        h.announce_win(proposal.proposal_hash).expect("announce");

        let sent = sent.lock();
        assert_eq!(sent.len(), 1, "one win is one push");
        let Ok(ProposalSyncPayload::Push { proposal_json }) = serde_json::from_slice(&sent[0])
        else {
            panic!("the win must go out as a push");
        };
        assert_eq!(proposal_json, json);

        let ancient = chrono::Utc::now().timestamp() + 3600;
        assert_eq!(db.prune_payout_proposals(ancient).unwrap(), 0);
        assert!(
            holds(&db, &proposal),
            "a won proposal must outlive the prune"
        );
    }

    /// A push is taken from the node that built the proposal, and needs no request.
    #[test]
    fn a_push_from_its_proposer_is_stored() {
        let (db, h) = handler();
        let proposal = a_proposal();
        let json = serde_json::to_string(&proposal).unwrap();

        let stored = h.accept_push(&proposal.proposer, &json).expect("push");

        assert_eq!(stored, Some(proposal.proposal_hash));
        assert!(holds(&db, &proposal));
    }

    /// A push skips the request check, so nothing but its proposer can use that route.
    #[test]
    fn a_push_about_someone_elses_proposal_is_refused() {
        let (db, h) = handler();
        let proposal = a_proposal();
        let json = serde_json::to_string(&proposal).unwrap();

        assert_eq!(h.accept_push(&PEER, &json).expect("push"), None);
        assert!(!holds(&db, &proposal));
    }

    #[test]
    fn a_push_from_an_unknown_node_is_refused() {
        let (db, h) = handler();
        let mut proposal = a_proposal();
        proposal.proposer = STRANGER;
        proposal.proposal_hash = compute_proposal_hash(&proposal);
        let json = serde_json::to_string(&proposal).unwrap();

        assert_eq!(h.accept_push(&STRANGER, &json).expect("push"), None);
        assert!(!holds(&db, &proposal));
    }

    /// `store_payout_proposal` replaces, so a replay of the row a node has armed would clear
    /// `is_approved` and leave it unarmed after a restart.
    #[test]
    fn a_replay_cannot_disarm_the_proposal_we_have_approved() {
        let (db, h) = handler();
        let proposal = a_proposal();
        let json = serde_json::to_string(&proposal).unwrap();
        db.store_payout_proposal(&proposal.proposal_hash, 7, 960_000, &json)
            .unwrap();
        db.mark_payout_approved(&proposal.proposal_hash).unwrap();
        ask_for(&db, &proposal);

        h.accept_push(&proposal.proposer, &json).expect("push");
        h.accept(&PEER, &json).expect("response");

        assert!(
            db.get_approved_payout_proposal().unwrap().is_some(),
            "the approved row must still be approved"
        );
    }

    /// Answering costs a broadcast per holder, so a stranger's request gets nothing.
    #[test]
    fn only_a_known_node_is_served() {
        let (db, _) = handler();
        let (h, sent) = capturing(&db);
        let proposal = a_proposal();
        let json = serde_json::to_string(&proposal).unwrap();
        db.store_payout_proposal(&proposal.proposal_hash, 7, 960_000, &json)
            .unwrap();
        let ask = || ProposalSyncPayload::Request {
            payout_id: id_of(&proposal),
        };

        h.on_payload(&STRANGER, ask()).expect("stranger");
        assert_eq!(sent.lock().len(), 0);

        h.on_payload(&PEER, ask()).expect("peer");
        assert_eq!(sent.lock().len(), 1);
    }

    /// Does a proposal survive the trip? `payload` is written as decimal integers, so a message that
    /// passes its own size check can still be too big for the envelope and never arrive.
    #[test]
    fn a_proposal_with_five_hundred_payees_fits_the_envelope() {
        let mut proposal = a_proposal();
        let entry = PayoutEntry {
            address: vec![b'q'; 62], // a bech32m taproot address, the longest we pay
            amount: 312_500_000,
            recipient_id: [0xFF; 32],
            payout_type: PayoutType::Mining,
        };
        proposal.miner_payouts = vec![entry; 500];
        proposal.proposal_hash = compute_proposal_hash(&proposal);
        let payload = serde_json::to_vec(&ProposalSyncPayload::Push {
            proposal_json: serde_json::to_string(&proposal).unwrap(),
        })
        .unwrap();
        let wire = serde_json::to_vec(&payload).unwrap().len();

        assert!(
            payload.len() <= ghost_consensus::message_validator::MAX_PAYOUT_PROPOSAL_SIZE,
            "payload {} bytes",
            payload.len()
        );
        assert!(
            wire + 2_000 <= ghost_consensus::message_validator::MAX_ENVELOPE_SIZE,
            "{wire} bytes on the wire"
        );
    }
}
