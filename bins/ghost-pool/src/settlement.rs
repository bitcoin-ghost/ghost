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
        self.settle_from_scriptsig(block_hash, height, &scriptsig)
    }

    /// Decide and apply, given a coinbase scriptSig already in hand.
    ///
    /// Split from the fetch so the decision path is testable without a live Core: everything that
    /// can be wrong — reading the tag, finding the proposal, settling the right shares — is here,
    /// while the fetch above is a thin wrapper worth exercising only against a real node.
    pub fn settle_from_scriptsig(
        &self,
        block_hash: &str,
        height: u64,
        scriptsig: &[u8],
    ) -> SettleOutcome {
        let Some(payout_id) = ghost_common::coinbase_tags::extract_payout_tag(scriptsig) else {
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

    /// Bring settlement back in line with the chain, in both directions.
    ///
    /// Events alone are not enough. A node that is restarting when a block lands never sees its
    /// `Connected` event, so it never settles — and deploys happen. Relying on events would leave
    /// that node's ledger owing work the pool already paid, which is exactly the divergence this
    /// whole mechanism exists to remove; making it rarer is not fixing it.
    ///
    /// So this does two passes:
    ///
    /// - **backward**: any settled block no longer on the main chain is reversed, because a
    ///   `Disconnected` event can be missed the same way, and a settlement left standing for an
    ///   orphaned block is work silently marked paid.
    /// - **forward**: every block since the last scan is examined, and any carrying our payout tag
    ///   is settled. This is what closes the missed-event hole.
    ///
    /// The forward pass is cursor-driven rather than a fixed lookback, so steady state costs a
    /// block or two per run while a node returning from downtime catches up on everything it
    /// missed. Settling is idempotent, so re-examining a block is harmless.
    pub async fn reconcile(&self) -> GhostResult<usize> {
        let reversed = self.reverse_departed_blocks().await?;
        self.settle_missed_blocks().await?;
        Ok(reversed)
    }

    /// kv key holding the height the forward scan has reached.
    const SCAN_CURSOR_KEY: &'static str = "settlement.scan_height";

    /// Most blocks to examine in one catch-up, so a very stale cursor cannot stall startup.
    ///
    /// Anything further behind is reported and picked up next run rather than done in one burst.
    const MAX_CATCHUP_BLOCKS: u64 = 500;

    /// Forward pass: settle any block since the last scan that names one of our payouts.
    async fn settle_missed_blocks(&self) -> GhostResult<()> {
        let tip = self.rpc.get_block_count().await?;

        // First run has no cursor. Start one block back rather than at genesis — there is nothing
        // to settle in history this node has never had proposals for, and scanning the whole chain
        // on first start would be pointless work.
        let cursor: u64 = match self.db.kv_get(Self::SCAN_CURSOR_KEY)? {
            Some(v) => v.parse().unwrap_or(tip.saturating_sub(1)),
            None => tip.saturating_sub(1),
        };

        if cursor >= tip {
            return Ok(());
        }

        let behind = tip - cursor;
        let scan_to = if behind > Self::MAX_CATCHUP_BLOCKS {
            warn!(
                behind,
                limit = Self::MAX_CATCHUP_BLOCKS,
                "settlement scan is a long way behind; catching up in batches"
            );
            cursor + Self::MAX_CATCHUP_BLOCKS
        } else {
            tip
        };

        let mut settled = 0usize;
        for height in (cursor + 1)..=scan_to {
            let hash = match self.rpc.get_block_hash(height).await {
                Ok(h) => h,
                Err(e) => {
                    // Stop at the first gap rather than skipping it — advancing the cursor past a
                    // height we could not read would lose that block permanently.
                    warn!(height, error = %e, "settlement scan stopped: could not read block hash");
                    break;
                }
            };

            if let SettleOutcome::Settled(applied) = self.on_block_connected(&hash, height).await {
                settled += 1;
                info!(
                    height,
                    block = %hash,
                    shares_marked = applied.shares_marked,
                    "settled a won block the event stream missed"
                );
            }

            // Advance per block, so an interruption resumes rather than restarts.
            self.db.kv_set(Self::SCAN_CURSOR_KEY, &height.to_string())?;
        }

        if settled > 0 {
            warn!(
                settled,
                "the forward scan settled blocks that no Connected event was seen for — \
                 expected after a restart, worth investigating otherwise"
            );
        }
        Ok(())
    }

    /// Backward pass: reverse settlements whose blocks left the main chain.
    async fn reverse_departed_blocks(&self) -> GhostResult<usize> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::types::{PayoutEntry, PayoutType};
    use ghost_storage::models::{MinerRecord, ShareRecord};

    const MINER: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4.worker";
    const ADDRESS: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const PROPOSAL_HASH: [u8; 32] = [0x5A; 32];

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    /// A node that did NOT submit the block: it holds the shares and the gossiped proposal, and
    /// nothing else. No armed snapshot, no submission — which is the situation seven of eight
    /// nodes are in every time the pool wins.
    fn non_submitting_node(shares: usize) -> (Arc<Database>, SettlementObserver) {
        let db = Arc::new(Database::in_memory().expect("db"));

        db.upsert_miner(&MinerRecord {
            miner_id: MINER.to_string(),
            payout_address: ADDRESS.to_string(),
            first_seen: now(),
            last_seen: now(),
            connected_node: None,
            total_shares: 0,
            total_work: 0.0,
            blocks_won: 0,
            total_payouts_sats: 0,
            avg_hashrate_ths: 0.0,
        })
        .expect("miner");

        for i in 0..shares {
            db.insert_share(&ShareRecord {
                id: None,
                round_id: 1,
                miner_id: MINER.to_string(),
                difficulty: 1.0,
                work: 1.0,
                share_hash: format!("settle_observed_{i}"),
                timestamp: now() - 600,
                received_by: "node".to_string(),
                valid: true,
            })
            .expect("share");
        }

        // The proposal reaches every node by gossip, not just the proposer.
        let proposal = PayoutProposal {
            proposal_hash: PROPOSAL_HASH,
            round_id: 1,
            block_hash: [0u8; 32],
            block_height: 960_000,
            proposer: [1u8; 32],
            miner_payouts: vec![PayoutEntry {
                address: ADDRESS.as_bytes().to_vec(),
                amount: 100_000_000,
                recipient_id: {
                    let h = ghost_common::identity::hash_message(ADDRESS.as_bytes());
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&h);
                    id
                },
                payout_type: PayoutType::Mining,
            }],
            node_payouts: vec![],
            treasury_amount: 0,
            treasury_address: ADDRESS.as_bytes().to_vec(),
            tx_fees: 0,
            subsidy: 312_500_000,
            timestamp: now() as u64,
            tx_fees_unallocated: 0,
        };
        db.store_payout_proposal(
            &PROPOSAL_HASH,
            1,
            960_000,
            &serde_json::to_string(&proposal).expect("json"),
        )
        .expect("store proposal");

        let rpc =
            Arc::new(ghost_common::rpc::BitcoinRpc::new("127.0.0.1", 8332, "u", "p").expect("rpc"));
        // Activation height 0 — the gate itself is tested separately; here we are proving the
        // settlement path works at all.
        let observer = SettlementObserver::new(
            Arc::clone(&db),
            rpc,
            crate::PAYOUT_ADDRESS_GROUPING_HEIGHT,
            0,
        );
        (db, observer)
    }

    /// The coinbase of a block won by SOME OTHER node, carrying the payout tag.
    fn winning_coinbase_scriptsig() -> Vec<u8> {
        let mut s = vec![0x03, 0x40, 0x1f, 0x0e]; // BIP34 height
        let mut id = [0u8; 16];
        id.copy_from_slice(&PROPOSAL_HASH[..16]);
        s.extend_from_slice(&ghost_common::coinbase_tags::encode_payout_tag(&id));
        s.extend_from_slice(b"GHOST PublicPool");
        s
    }

    /// **The point of the whole package.** A node that did not submit the winning block settles it
    /// anyway, from the chain.
    ///
    /// On main this cannot happen: settlement runs only from the block-submitted path, keyed on the
    /// snapshot the node's own template was built against, so seven of eight nodes never mark
    /// anything paid. They then propose paying the same work again — and being the majority, their
    /// view is the one that reaches quorum.
    #[test]
    fn a_node_that_did_not_submit_the_block_still_settles_it() {
        let (db, observer) = non_submitting_node(4);

        let (unpaid_before, _) = db.get_miner_unpaid_stats(MINER).expect("stats");
        assert_eq!(unpaid_before, 4, "fixture should start with unpaid work");

        let outcome =
            observer.settle_from_scriptsig("0000won", 960_001, &winning_coinbase_scriptsig());

        match outcome {
            SettleOutcome::Settled(applied) => {
                assert_eq!(
                    applied.shares_marked, 4,
                    "all the paid work should be marked"
                );
                assert_eq!(applied.proposal_hash, PROPOSAL_HASH);
            }
            other => panic!("a non-submitting node failed to settle: {other:?}"),
        }

        let (unpaid_after, _) = db.get_miner_unpaid_stats(MINER).expect("stats");
        assert_eq!(
            unpaid_after, 0,
            "work paid by the block must no longer be owed — otherwise this node proposes paying \
             it again"
        );
    }

    /// Settling twice must apply once: the submitting node settles immediately, every other node
    /// settles on observing, and the forward scan may reach the same block again.
    #[test]
    fn observing_the_same_block_twice_applies_once() {
        let (db, observer) = non_submitting_node(3);
        let scriptsig = winning_coinbase_scriptsig();

        assert!(matches!(
            observer.settle_from_scriptsig("0000won", 960_001, &scriptsig),
            SettleOutcome::Settled(_)
        ));
        assert_eq!(
            observer.settle_from_scriptsig("0000won", 960_001, &scriptsig),
            SettleOutcome::AlreadySettled
        );

        let (unpaid, _) = db.get_miner_unpaid_stats(MINER).expect("stats");
        assert_eq!(unpaid, 0);
    }

    /// Everyone else's blocks pass through this path too, and must do nothing at all.
    #[test]
    fn a_block_without_our_tag_is_not_ours() {
        let (db, observer) = non_submitting_node(2);

        // A plausible foreign coinbase: height push then some other pool's text.
        let mut foreign = vec![0x03, 0x40, 0x1f, 0x0e];
        foreign.extend_from_slice(b"/SomeOtherPool/");

        assert_eq!(
            observer.settle_from_scriptsig("0000foreign", 960_001, &foreign),
            SettleOutcome::NotOurs
        );

        let (unpaid, _) = db.get_miner_unpaid_stats(MINER).expect("stats");
        assert_eq!(unpaid, 2, "a stranger's block must not touch our ledger");
    }

    /// A block carrying our tag whose proposal we do not hold is reported distinctly — it IS ours
    /// and cannot be settled here, which is worth alarming on rather than filing under "not ours".
    #[test]
    fn our_tag_without_the_proposal_is_reported_not_ignored() {
        let (db, observer) = non_submitting_node(2);

        let mut s = vec![0x03, 0x40, 0x1f, 0x0e];
        s.extend_from_slice(&ghost_common::coinbase_tags::encode_payout_tag(&[0xEE; 16]));

        assert_eq!(
            observer.settle_from_scriptsig("0000unknown", 960_001, &s),
            SettleOutcome::ProposalMissing {
                payout_id: [0xEE; 16]
            }
        );

        let (unpaid, _) = db.get_miner_unpaid_stats(MINER).expect("stats");
        assert_eq!(unpaid, 2, "nothing should be settled on a proposal we lack");
    }

    /// Below the activation height the observer matches and reports but writes nothing, so the
    /// dry run can prove matching works before the ledger behaviour changes fleet-wide.
    #[test]
    fn below_the_activation_height_nothing_is_written() {
        let (db, _) = non_submitting_node(3);
        let rpc =
            Arc::new(ghost_common::rpc::BitcoinRpc::new("127.0.0.1", 8332, "u", "p").expect("rpc"));
        let gated = SettlementObserver::new(
            Arc::clone(&db),
            rpc,
            crate::PAYOUT_ADDRESS_GROUPING_HEIGHT,
            u64::MAX,
        );

        let mut id = [0u8; 16];
        id.copy_from_slice(&PROPOSAL_HASH[..16]);
        assert_eq!(
            gated.settle_from_scriptsig("0000won", 960_001, &winning_coinbase_scriptsig()),
            SettleOutcome::DryRunMatch { payout_id: id }
        );

        let (unpaid, _) = db.get_miner_unpaid_stats(MINER).expect("stats");
        assert_eq!(unpaid, 3, "a dry run must not change the ledger");
    }
}
