//! Fetching a payout proposal a node needs but never received.
//!
//! Settling a won block means reading the payout identity off its coinbase and finding the proposal
//! that identity names. A node that was down when that proposal was gossiped does not have it —
//! proposals are broadcast once and never rebroadcast — so the block cannot be settled, and the
//! ledger silently keeps owing work the pool already paid.
//!
//! Alarming about it would put a human in the loop. Instead the node asks its peers and settles when
//! the answer arrives.
//!
//! **The fetch needs no trust.** The chain already names the payout: the coinbase carries the first
//! 16 bytes of the proposal hash. A response is accepted only if the proposal it carries *hashes to
//! that identity*, recomputed from its own contents. A forged proposal cannot, so there is nothing
//! to sign, nothing to vote on, and no peer to trust — the chain is the anchor.

use std::sync::Arc;

use async_trait::async_trait;
use ghost_common::error::GhostResult;
use ghost_common::types::PayoutProposal;
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

    /// Accept a proposal from a peer — but only if it proves itself.
    ///
    /// The proposal's hash is recomputed from its own contents and must match what it claims, so a
    /// peer cannot hand back a doctored proposal under a real identity. Whether the identity is one
    /// we actually wanted is then settled by the caller matching it against a coinbase.
    pub fn accept(&self, proposal_json: &str) -> GhostResult<Option<[u8; 32]>> {
        let proposal: PayoutProposal = match serde_json::from_str(proposal_json) {
            Ok(p) => p,
            Err(e) => {
                debug!(error = %e, "discarding an unparseable proposal-sync response");
                return Ok(None);
            }
        };

        let recomputed = compute_proposal_hash(&proposal);
        if recomputed != proposal.proposal_hash {
            warn!(
                claimed = %hex::encode(&proposal.proposal_hash[..8]),
                recomputed = %hex::encode(&recomputed[..8]),
                "discarding a proposal whose contents do not hash to the identity it claims"
            );
            return Ok(None);
        }

        self.db.store_payout_proposal(
            &recomputed,
            proposal.round_id,
            proposal.block_height,
            proposal_json,
        )?;
        info!(
            proposal = %hex::encode(&recomputed[..8]),
            "stored a payout proposal fetched from a peer"
        );
        Ok(Some(recomputed))
    }
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
        match payload {
            ProposalSyncPayload::Request { payout_id } => self.serve(payout_id),
            ProposalSyncPayload::Response { proposal_json } => {
                self.accept(&proposal_json).map(|_| ())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::types::{PayoutEntry, PayoutType};

    fn a_proposal() -> PayoutProposal {
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

    fn handler() -> (Arc<ghost_storage::Database>, ProposalSyncHandler) {
        let db = Arc::new(ghost_storage::Database::in_memory().expect("db"));
        (Arc::clone(&db), ProposalSyncHandler::new(db))
    }

    /// An honest response is stored, and afterwards the proposal is findable by the identity a
    /// coinbase would name — which is the whole point of fetching it.
    #[test]
    fn an_honest_proposal_is_accepted_and_becomes_findable() {
        let (db, h) = handler();
        let proposal = a_proposal();
        let json = serde_json::to_string(&proposal).unwrap();

        let stored = h.accept(&json).expect("accept").expect("should store");
        assert_eq!(stored, proposal.proposal_hash);

        let mut payout_id = [0u8; 16];
        payout_id.copy_from_slice(&proposal.proposal_hash[..16]);
        assert!(
            db.get_proposal_by_hash_prefix(&payout_id)
                .unwrap()
                .is_some(),
            "a fetched proposal must be findable by the identity the coinbase carries"
        );
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

        proposal.miner_payouts[0].amount = 999_999;
        proposal.miner_payouts[0].address = b"bc1qattacker".to_vec();
        // Claimed identity left untouched, so it still "looks like" the one we asked for.
        proposal.proposal_hash = real_hash;

        let json = serde_json::to_string(&proposal).unwrap();
        assert_eq!(
            h.accept(&json).expect("accept"),
            None,
            "contents that do not hash to the claimed identity must be refused"
        );

        let mut payout_id = [0u8; 16];
        payout_id.copy_from_slice(&real_hash[..16]);
        assert!(
            db.get_proposal_by_hash_prefix(&payout_id)
                .unwrap()
                .is_none(),
            "nothing should have been stored"
        );
    }

    #[test]
    fn unparseable_responses_are_ignored() {
        let (_, h) = handler();
        assert_eq!(h.accept("not json").expect("accept"), None);
    }

    /// Serving a request we cannot answer is a no-op rather than an error — some other peer holds
    /// it, and a node that lacks it has nothing useful to say.
    #[test]
    fn serving_an_unknown_identity_is_a_no_op() {
        let (_, h) = handler();
        assert!(h.serve([0xAB; 16]).is_ok());
    }
}
