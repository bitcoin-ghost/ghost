//! Settling the ledger from what is on the chain, rather than from what this node happens to know.
//!
//! Settlement marks a miner's shares paid so the next payout does not pay the same work twice. It
//! ran in exactly one place — the node that submitted the winning block — so the other seven kept
//! owing the entire paid set, and being the majority, their view is the one that reaches quorum.
//! That is a double-payment path, and it is why the unpaid ledger only ever grew.
//!
//! A won block already says who it paid: the coinbase carries a tag naming the payout, and the
//! outputs are the payment itself. So every node can settle from its own view of the chain with no
//! gossip, no new consensus object, and nothing to agree on. A node that was offline settles by
//! scanning the blocks it missed.
//!
//! The tag is necessary because the outputs alone are not enough — the mined coinbase is built from
//! a fee-adjusted proposal whose treasury and node amounts absorb that node's own fee drift, so it
//! matches no stored proposal. Naming the payout turns a guess into a lookup.

use std::sync::Arc;

use ghost_common::error::GhostResult;
use ghost_common::types::PayoutProposal;
use ghost_storage::queries::SettlementApplied;
use ghost_storage::Database;
use tracing::{debug, error, info, warn};

/// What observing a block led to.
#[derive(Debug, Clone, PartialEq)]
pub enum SettleOutcome {
    /// Not one of ours — the overwhelmingly common case, since every block anyone mines is checked.
    NotOurs,
    /// Settled, with what was applied.
    Settled(Box<SettlementApplied>),
    /// Already settled; nothing changed.
    AlreadySettled,
    /// The coinbase names a payout this node does not hold, so it cannot be settled here.
    ///
    /// Distinct from `NotOurs` on purpose: this block IS ours and we cannot act on it, which is a
    /// condition worth alarming on rather than filing under "someone else's block".
    ProposalMissing { payout_id: [u8; 16] },
    /// Below the activation gate: matched and reported, deliberately not applied.
    DryRunMatch { payout_id: [u8; 16] },
}

/// Settles the ledger by observing blocks.
pub struct SettlementObserver {
    db: Arc<Database>,
    rpc: Arc<ghost_common::rpc::BitcoinRpc>,
    grouping_height: u64,
    /// Below the activation height the observer matches and logs but writes nothing.
    ///
    /// Settlement changes the unpaid ledger, which every node votes with, so a mixed fleet where
    /// only some nodes observe-settle would split on the first won block. Dry-run gives the
    /// evidence that matching works before the behaviour turns on everywhere at once.
    activation_height: u64,
}

impl SettlementObserver {
    pub fn new(
        db: Arc<Database>,
        rpc: Arc<ghost_common::rpc::BitcoinRpc>,
        grouping_height: u64,
        activation_height: u64,
    ) -> Self {
        Self {
            db,
            rpc,
            grouping_height,
            activation_height,
        }
    }

    /// Pull the coinbase scriptSig out of a block.
    async fn coinbase_scriptsig(&self, block_hash: &str) -> GhostResult<Vec<u8>> {
        // Verbosity 0: raw hex. Parsing the block ourselves avoids depending on the shape of the
        // verbose JSON, which differs between Core versions.
        let raw = self.rpc.get_block(block_hash, 0).await?;
        let hex_str = raw.as_str().unwrap_or_default();
        let bytes = hex::decode(hex_str).map_err(|e| {
            ghost_common::error::GhostError::Rpc(format!("block {block_hash} not hex: {e}"))
        })?;
        let block: bitcoin::Block = bitcoin::consensus::deserialize(&bytes).map_err(|e| {
            ghost_common::error::GhostError::Rpc(format!("block {block_hash} undecodable: {e}"))
        })?;
        let coinbase = block.txdata.first().ok_or_else(|| {
            ghost_common::error::GhostError::Rpc(format!("block {block_hash} has no transactions"))
        })?;
        let script_sig = coinbase
            .input
            .first()
            .ok_or_else(|| {
                ghost_common::error::GhostError::Rpc(format!(
                    "block {block_hash} coinbase has no input"
                ))
            })?
            .script_sig
            .as_bytes()
            .to_vec();
        Ok(script_sig)
    }

    /// Settle a block if its coinbase names a payout this node holds.
    ///
    /// Every block the node sees passes through here, including everyone else's, so the common
    /// path must be cheap and must say `NotOurs` rather than doing anything.
    pub async fn on_block_connected(&self, block_hash: &str, height: u64) -> SettleOutcome {
        let scriptsig = match self.coinbase_scriptsig(block_hash).await {
            Ok(s) => s,
            Err(e) => {
                warn!(block_hash, error = %e, "could not read a block's coinbase; not settling it");
                return SettleOutcome::NotOurs;
            }
        };

        let Some(payout_id) = ghost_common::coinbase_tags::extract_payout_tag(&scriptsig) else {
            return SettleOutcome::NotOurs;
        };

        let found = match self.db.get_proposal_by_hash_prefix(&payout_id) {
            Ok(f) => f,
            Err(e) => {
                error!(block_hash, error = %e, "proposal lookup failed for a tagged block");
                return SettleOutcome::NotOurs;
            }
        };

        let Some((proposal_hash, json)) = found else {
            // The block is ours — it carries our tag — but the proposal is gone or was never
            // stored. Loud, because it means a won block cannot be settled here.
            warn!(
                block_hash,
                payout_id = %hex::encode(payout_id),
                "a block carries our payout tag but the proposal is not held — cannot settle it"
            );
            return SettleOutcome::ProposalMissing { payout_id };
        };

        let proposal: PayoutProposal = match serde_json::from_str(&json) {
            Ok(p) => p,
            Err(e) => {
                error!(
                    block_hash,
                    proposal = %hex::encode(&proposal_hash[..8]),
                    error = %e,
                    "stored proposal will not deserialize; cannot settle"
                );
                return SettleOutcome::ProposalMissing { payout_id };
            }
        };

        if height < self.activation_height {
            info!(
                block_hash,
                height,
                payout_id = %hex::encode(payout_id),
                proposal = %hex::encode(&proposal_hash[..8]),
                "DRY RUN: would settle this block (below the activation height)"
            );
            return SettleOutcome::DryRunMatch { payout_id };
        }

        match crate::payout::apply_settlement(&self.db, &proposal, self.grouping_height, block_hash)
        {
            Ok(Some(applied)) => SettleOutcome::Settled(Box::new(applied)),
            Ok(None) => SettleOutcome::AlreadySettled,
            Err(e) => {
                error!(block_hash, error = %e, "settling an observed block failed");
                SettleOutcome::NotOurs
            }
        }
    }

    /// Undo a settlement whose block left the main chain.
    ///
    /// The work it paid is owed again. Reversal inverts the amounts settlement recorded rather than
    /// recomputing them: by now the ledger has moved on, so re-deriving would unmark the wrong rows.
    pub fn on_block_disconnected(&self, block_hash: &str) -> Option<SettlementApplied> {
        match self.db.reverse_settlement(block_hash) {
            Ok(Some(reversed)) => {
                info!(
                    block_hash,
                    shares_unmarked = reversed.shares_marked,
                    treasury_debited = reversed.treasury_bumped,
                    "reversed a settlement — its block left the main chain, so the work is owed again"
                );
                Some(reversed)
            }
            Ok(None) => {
                debug!(
                    block_hash,
                    "disconnected block had no settlement to reverse"
                );
                None
            }
            Err(e) => {
                error!(block_hash, error = %e, "failed to reverse a settlement");
                None
            }
        }
    }

    /// Re-check settled blocks against the chain, and reverse any that are no longer on it.
    ///
    /// A `Disconnected` event can be missed — a restart, a dropped subscription — and a settlement
    /// left standing for an orphaned block is work wrongly marked paid, which is silent. This is the
    /// backstop that makes the reversal path self-healing rather than event-dependent.
    pub async fn reconcile(&self) -> GhostResult<usize> {
        let settled = self.db.list_unreversed_settled_blocks()?;
        let mut reversed = 0usize;

        for (block_hash, height) in settled {
            // `getblockheader` reports -1 confirmations for a block that is no longer on the main
            // chain. Anything else (including an error) is treated as "still there" — reversing on
            // a transient RPC failure would unmark real payments.
            let confirmations = match self.rpc.get_block_header(&block_hash).await {
                Ok(header) => header.confirmations,
                Err(e) => {
                    debug!(block_hash, error = %e, "could not check a settled block; leaving it");
                    continue;
                }
            };

            if confirmations == -1 {
                warn!(
                    block_hash,
                    height, "a settled block is no longer on the main chain — reversing"
                );
                if self.on_block_disconnected(&block_hash).is_some() {
                    reversed += 1;
                }
            }
        }

        if reversed > 0 {
            info!(
                reversed,
                "reconciliation reversed settlements for blocks that left the chain"
            );
        }
        Ok(reversed)
    }
}
