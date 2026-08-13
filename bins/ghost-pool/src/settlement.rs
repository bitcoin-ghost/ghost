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
//!
//! That same drift is why settlement credits from the MINED outputs, not the stored proposal
//! (#601): the ratified `treasury_amount` is what the fleet agreed to, the coinbase pays the
//! winner's adjusted amount, and booking the former records money the chain never moved. The
//! tag answers WHICH payout a block paid; the outputs answer HOW MUCH.

use std::sync::Arc;

use ghost_common::error::GhostResult;
use ghost_common::types::PayoutProposal;
use ghost_storage::queries::SettlementApplied;
use ghost_storage::Database;
use tracing::{debug, error, info, warn};

/// Pull the coinbase scriptSig and outputs out of a block, from this node's own Core.
///
/// Both come from the same coinbase: the scriptSig carries the tag naming the payout, the
/// outputs are what the chain actually paid — which is what settlement credits (#601), since
/// the mined amounts carry the winner's fee-drift adjustment and the stored proposal does not.
///
/// A free function rather than a method because BOTH ledgers' settlements read coinbases the
/// same way — the tip-observing [`SettlementObserver`] here, and the shard's maturity settlement
/// (`shard.rs`), which must share this exact spelling: it carries the internal-vs-display
/// hash-order fix below, and a fresh implementation would re-hit that trap.
pub(crate) async fn fetch_coinbase_parts(
    rpc: &ghost_common::rpc::BitcoinRpc,
    block_hash: &str,
) -> GhostResult<(Vec<u8>, Vec<crate::coinbase_verifier::CoinbaseOutput>)> {
    // Normalise to display order first. `BlockEvent` hashes arrive in internal order despite
    // the parser's doc claiming otherwise (observed on vm5, 2026-08-01: every settlement probe
    // got "Block not found" for a block that existed). Settlement is the first consumer to
    // take one of these to an RPC call, which is why it surfaced here.
    let block_hash = &ghost_common::zmq::block_hash_to_display_order(block_hash);
    // Verbosity 0: raw hex. Parsing the block ourselves avoids depending on the shape of the
    // verbose JSON, which differs between Core versions.
    let raw = rpc.get_block(block_hash, 0).await?;
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
    let outputs = coinbase
        .output
        .iter()
        .map(|o| crate::coinbase_verifier::CoinbaseOutput {
            value: o.value.to_sat(),
            script_pubkey: o.script_pubkey.as_bytes().to_vec(),
        })
        .collect();
    Ok((script_sig, outputs))
}

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
    /// Fetches a proposal a won block names but this node never received.
    ///
    /// Without it a missed proposal leaves the block unsettled until somebody reads a log. The
    /// forward scan in `reconcile` then settles it once the answer lands, so the recovery completes
    /// without anyone intervening.
    proposal_sync: Option<Arc<crate::proposal_sync::ProposalSyncHandler>>,
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
            proposal_sync: None,
        }
    }

    /// Attach the peer fetch used to recover a proposal this node is missing.
    pub fn with_proposal_sync(
        mut self,
        sync: Arc<crate::proposal_sync::ProposalSyncHandler>,
    ) -> Self {
        self.proposal_sync = Some(sync);
        self
    }

    /// Pull the coinbase scriptSig and outputs out of a block — the shared spelling in
    /// [`fetch_coinbase_parts`], kept as a method so call sites read naturally.
    async fn coinbase_parts(
        &self,
        block_hash: &str,
    ) -> GhostResult<(Vec<u8>, Vec<crate::coinbase_verifier::CoinbaseOutput>)> {
        fetch_coinbase_parts(&self.rpc, block_hash).await
    }

    /// Settle a block if its coinbase names a payout this node holds.
    ///
    /// Every block the node sees passes through here, including everyone else's, so the common
    /// path must be cheap and must say `NotOurs` rather than doing anything.
    pub async fn on_block_connected(&self, block_hash: &str, height: u64) -> SettleOutcome {
        let (scriptsig, outputs) = match self.coinbase_parts(block_hash).await {
            Ok(parts) => parts,
            Err(e) => {
                warn!(block_hash, error = %e, "could not read a block's coinbase; not settling it");
                return SettleOutcome::NotOurs;
            }
        };
        self.settle_from_coinbase(block_hash, height, &scriptsig, &outputs)
    }

    /// Decide and apply, given a coinbase's scriptSig and outputs already in hand.
    ///
    /// Split from the fetch so the decision path is testable without a live Core: everything that
    /// can be wrong — reading the tag, finding the proposal, settling the right shares, crediting
    /// what the chain paid rather than what was ratified (#601) — is here, while the fetch above
    /// is a thin wrapper worth exercising only against a real node.
    pub fn settle_from_coinbase(
        &self,
        block_hash: &str,
        height: u64,
        scriptsig: &[u8],
        mined_outputs: &[crate::coinbase_verifier::CoinbaseOutput],
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
            // The block is ours — it carries our tag — but we never received the proposal, most
            // likely because we were down when it was gossiped. Ask the mesh rather than warning
            // and waiting for someone to notice.
            //
            // The fetch is safe without trust because the chain names the payout, so a response is
            // only accepted if it hashes to the identity this coinbase carries.
            //
            // Asking is not enough on its own: the answer lands seconds later, by which time this
            // block has been seen and the forward scan's cursor has moved past it, so nothing would
            // ever apply it. Recording the block is what closes that loop — reconciliation retries
            // exactly these, and the row outlives a restart.
            warn!(
                block_hash,
                payout_id = %hex::encode(payout_id),
                "a block carries our payout tag but the proposal is not held — requesting it"
            );
            if let Err(e) = self.db.defer_settlement(block_hash, height, &payout_id) {
                error!(block_hash, error = %e, "could not record a block awaiting its proposal");
            }
            if let Some(sync) = &self.proposal_sync {
                if let Err(e) = sync.request(payout_id) {
                    warn!(error = %e, "could not request the missing payout proposal");
                }
            }
            return SettleOutcome::ProposalMissing { payout_id };
        };

        // The proposal is in hand, so whatever happens next this block is no longer waiting on one.
        // Discharged on the dry-run path too: the deferral tracks "cannot resolve the payout", not
        // "has not been applied", and the gate is a separate question.
        if let Err(e) = self.db.clear_deferred_settlement(block_hash) {
            debug!(block_hash, error = %e, "could not clear a deferred settlement");
        }

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

        match crate::payout::apply_settlement(
            &self.db,
            &proposal,
            self.grouping_height,
            block_hash,
            Some(mined_outputs),
        ) {
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
    /// - **deferred**: blocks known to be ours but unsettleable because their proposal had not
    ///   arrived. The forward cursor has long since passed them, so only an explicit retry can
    ///   finish the recovery a peer fetch started.
    /// - **forward**: every block since the last scan is examined, and any carrying our payout tag
    ///   is settled. This is what closes the missed-event hole.
    ///
    /// Deferred runs before forward so a proposal that arrived since the last pass is applied
    /// straight away, rather than waiting a further tick behind a scan that cannot see it.
    ///
    /// The forward pass is cursor-driven rather than a fixed lookback, so steady state costs a
    /// block or two per run while a node returning from downtime catches up on everything it
    /// missed. Settling is idempotent, so re-examining a block is harmless.
    pub async fn reconcile(&self) -> GhostResult<usize> {
        let reversed = self.reverse_departed_blocks().await?;
        self.retry_deferred_blocks().await?;
        self.settle_missed_blocks().await?;
        Ok(reversed)
    }

    /// Retry blocks that were ours but had no proposal to settle against.
    ///
    /// Each one is either resolvable now — because a peer answered — or asked for again. Asking
    /// repeatedly is the point: the peer that holds it may itself have been down when we first
    /// asked, and a recovery that gives up after one attempt is a recovery that needs an operator.
    async fn retry_deferred_blocks(&self) -> GhostResult<()> {
        let deferred = self.db.list_deferred_settlements()?;
        if deferred.is_empty() {
            return Ok(());
        }

        for (block_hash, height, payout_id) in deferred {
            // A block can be orphaned while it waits. Settling it then would mark work paid by a
            // block that no longer pays anyone. Only `-1` is treated as departed — an RPC failure
            // leaves the deferral alone rather than discarding it.
            if let Ok(header) = self.rpc.get_block_header(&block_hash).await {
                if header.confirmations == -1 {
                    warn!(
                        block_hash,
                        height, "a block awaiting its proposal left the main chain — dropping it"
                    );
                    self.db.clear_deferred_settlement(&block_hash)?;
                    continue;
                }
            }

            if self.db.get_proposal_by_hash_prefix(&payout_id)?.is_none() {
                debug!(
                    block_hash,
                    payout_id = %hex::encode(payout_id),
                    "still awaiting a payout proposal — asking again"
                );
                if let Some(sync) = &self.proposal_sync {
                    if let Err(e) = sync.request(payout_id) {
                        warn!(error = %e, "could not re-request a missing payout proposal");
                    }
                }
                continue;
            }

            match self.on_block_connected(&block_hash, height).await {
                SettleOutcome::Settled(applied) => info!(
                    block_hash,
                    height,
                    shares_marked = applied.shares_marked,
                    "settled a block once its payout proposal was recovered from a peer"
                ),
                other => debug!(
                    block_hash,
                    ?other,
                    "deferred block resolved without settling"
                ),
            }
        }
        Ok(())
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

    fn spk(addr: &str) -> Vec<u8> {
        crate::coinbase_verifier::address_to_script_pubkey(addr.as_bytes())
            .expect("test address must convert to a script pubkey")
    }

    /// The outputs the winning block actually paid — for the fixture proposal (no fee drift:
    /// mined total below subsidy makes available fees 0, matching `tx_fees: 0`), exactly its
    /// single miner output, so #601's reconstruction verifies.
    fn winning_coinbase_outputs() -> Vec<crate::coinbase_verifier::CoinbaseOutput> {
        vec![crate::coinbase_verifier::CoinbaseOutput {
            value: 100_000_000,
            script_pubkey: spk(ADDRESS),
        }]
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

        let outcome = observer.settle_from_coinbase(
            "0000won",
            960_001,
            &winning_coinbase_scriptsig(),
            &winning_coinbase_outputs(),
        );

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
            observer.settle_from_coinbase(
                "0000won",
                960_001,
                &scriptsig,
                &winning_coinbase_outputs()
            ),
            SettleOutcome::Settled(_)
        ));
        assert_eq!(
            observer.settle_from_coinbase(
                "0000won",
                960_001,
                &scriptsig,
                &winning_coinbase_outputs()
            ),
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
            observer.settle_from_coinbase("0000foreign", 960_001, &foreign, &[]),
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
            observer.settle_from_coinbase("0000unknown", 960_001, &s, &[]),
            SettleOutcome::ProposalMissing {
                payout_id: [0xEE; 16]
            }
        );

        let (unpaid, _) = db.get_miner_unpaid_stats(MINER).expect("stats");
        assert_eq!(unpaid, 2, "nothing should be settled on a proposal we lack");
    }

    /// **The recovery has to be remembered, not just requested.**
    ///
    /// The forward scan is cursor-driven, so by the time a peer answers, the cursor has passed the
    /// block and nothing would ever look at it again. Without this row the fetch is theatre: the
    /// proposal arrives, sits in the database, and the work stays wrongly owed forever.
    #[test]
    fn a_block_we_cannot_settle_yet_is_recorded_for_retry() {
        let (db, observer) = non_submitting_node(2);

        let mut s = vec![0x03, 0x40, 0x1f, 0x0e];
        s.extend_from_slice(&ghost_common::coinbase_tags::encode_payout_tag(&[0xEE; 16]));
        observer.settle_from_coinbase("0000unknown", 960_001, &s, &[]);

        assert_eq!(
            db.list_deferred_settlements().expect("deferred"),
            vec![("0000unknown".to_string(), 960_001, [0xEE; 16])],
            "a block awaiting its proposal must survive the moment it was observed"
        );
    }

    /// Once the proposal is in hand the deferral is discharged, so the retry list stays the small
    /// set of things actually stuck rather than a log of everything that was ever late.
    #[test]
    fn recovering_the_proposal_clears_the_deferral() {
        let (db, observer) = non_submitting_node(2);

        // Observed before the proposal was held.
        db.defer_settlement("0000won", 960_001, &{
            let mut id = [0u8; 16];
            id.copy_from_slice(&PROPOSAL_HASH[..16]);
            id
        })
        .expect("defer");

        assert!(matches!(
            observer.settle_from_coinbase(
                "0000won",
                960_001,
                &winning_coinbase_scriptsig(),
                &winning_coinbase_outputs()
            ),
            SettleOutcome::Settled(_)
        ));
        assert!(
            db.list_deferred_settlements().expect("deferred").is_empty(),
            "a settled block is no longer waiting on anything"
        );
    }

    /// Re-observing the same stuck block must not multiply it — the retry list is keyed on the
    /// block, and a node restarting in a loop would otherwise grow one row per restart.
    #[test]
    fn re_observing_a_stuck_block_does_not_duplicate_it() {
        let (db, observer) = non_submitting_node(1);

        let mut s = vec![0x03, 0x40, 0x1f, 0x0e];
        s.extend_from_slice(&ghost_common::coinbase_tags::encode_payout_tag(&[0xEE; 16]));
        observer.settle_from_coinbase("0000unknown", 960_001, &s, &[]);
        observer.settle_from_coinbase("0000unknown", 960_001, &s, &[]);

        assert_eq!(db.list_deferred_settlements().expect("deferred").len(), 1);
    }

    /// Build the winning scriptSig with the **real** template code, not by hand.
    ///
    /// Every other fixture here writes the bytes out longhand, which proves the parser agrees with
    /// the fixture — not that it agrees with the builder. If `coinbase_scriptsig` and
    /// `extract_payout_tag` ever drift apart, only this catches it, and the alternative place to
    /// find out is a won block that no node can settle.
    fn scriptsig_from_the_real_builder(payout: [u8; 32]) -> Vec<u8> {
        use crate::template::{TemplateConfig, TemplateProcessor};
        let rpc =
            Arc::new(ghost_common::rpc::BitcoinRpc::new("127.0.0.1", 8332, "u", "p").expect("rpc"));
        let processor = TemplateProcessor::new(
            TemplateConfig {
                coinbase_extra: "GHOST PublicPool".to_string(),
                pool_payout_address: ADDRESS.to_string(),
                node_id: Some([0x7Au8; 32]),
                ..Default::default()
            },
            rpc,
            ghost_policy::PolicyProfile::permissive(),
            Default::default(),
        );
        processor
            .coinbase_scriptsig(960_001, Some(payout), 20, None)
            .expect("the real builder must produce a scriptSig")
    }

    /// **End to end through the real coinbase builder.** The bytes a winning node would actually
    /// put on-chain are parsed by the settlement path and produce a settlement.
    #[test]
    fn a_scriptsig_from_the_real_builder_settles() {
        let (db, observer) = non_submitting_node(4);
        let scriptsig = scriptsig_from_the_real_builder(PROPOSAL_HASH);

        // The consensus ceiling, checked on the same bytes rather than in the abstract.
        assert!(
            scriptsig.len() + 20 <= 100,
            "scriptSig {} bytes + 20 extranonce breaches the 100-byte limit",
            scriptsig.len()
        );

        match observer.settle_from_coinbase(
            "0000real",
            960_001,
            &scriptsig,
            &winning_coinbase_outputs(),
        ) {
            SettleOutcome::Settled(applied) => assert_eq!(applied.shares_marked, 4),
            other => panic!("the real builder's coinbase did not settle: {other:?}"),
        }
        assert_eq!(db.get_miner_unpaid_stats(MINER).expect("stats").0, 0);
    }

    /// **The reorg round trip.** A won block settles, is orphaned and reversed — the work is owed
    /// again — then returns to the main chain and settles once more.
    ///
    /// The middle step is the one that matters: settlement is recorded as a flag rather than a
    /// deletion precisely so a block that comes back can re-settle through the same row. Deleting
    /// it would leave the returning block looking like one that was never settled, which is the
    /// same outcome but arrived at by luck.
    #[test]
    fn a_reorged_block_reverses_and_settles_again_when_it_returns() {
        let (db, observer) = non_submitting_node(5);
        let scriptsig = scriptsig_from_the_real_builder(PROPOSAL_HASH);

        assert!(matches!(
            observer.settle_from_coinbase(
                "0000reorg",
                960_001,
                &scriptsig,
                &winning_coinbase_outputs()
            ),
            SettleOutcome::Settled(_)
        ));
        assert_eq!(db.get_miner_unpaid_stats(MINER).expect("stats").0, 0);

        // Orphaned: the work is owed again, and by the amount that was actually recorded.
        let reversed = observer
            .on_block_disconnected("0000reorg")
            .expect("a settled block must be reversible");
        assert_eq!(reversed.shares_marked, 5);
        assert_eq!(
            db.get_miner_unpaid_stats(MINER).expect("stats").0,
            5,
            "reversal must put the work back"
        );

        // Reversing twice must not double-credit — a Disconnected event can arrive alongside a
        // reconcile that already reversed it.
        assert!(
            observer.on_block_disconnected("0000reorg").is_none(),
            "a second reversal must be a no-op, not a second credit"
        );
        assert_eq!(db.get_miner_unpaid_stats(MINER).expect("stats").0, 5);

        // And back on the main chain.
        assert!(matches!(
            observer.settle_from_coinbase(
                "0000reorg",
                960_001,
                &scriptsig,
                &winning_coinbase_outputs()
            ),
            SettleOutcome::Settled(_)
        ));
        assert_eq!(
            db.get_miner_unpaid_stats(MINER).expect("stats").0,
            0,
            "a returning block must settle again through the same row"
        );
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
            gated.settle_from_coinbase(
                "0000won",
                960_001,
                &winning_coinbase_scriptsig(),
                &winning_coinbase_outputs()
            ),
            SettleOutcome::DryRunMatch { payout_id: id }
        );

        let (unpaid, _) = db.get_miner_unpaid_stats(MINER).expect("stats");
        assert_eq!(unpaid, 3, "a dry run must not change the ledger");
    }

    /// **#601, at the observer.** A tagged block whose outputs are NOT the deterministic
    /// adjustment of the held proposal — a hand-mined rehearsal block, a winner on different
    /// code — still settles the SHARES (under-settling is the double-payment path), but credits
    /// the treasury only what the treasury script measurably received: here, nothing.
    #[test]
    fn a_hand_mined_block_settles_shares_but_credits_only_what_it_paid() {
        let (db, observer) = non_submitting_node(3);

        // One big output to a script unrelated to the fixture's treasury address.
        let foreign_outputs = vec![crate::coinbase_verifier::CoinbaseOutput {
            value: 5_000_000_000,
            script_pubkey: spk("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"),
        }];

        match observer.settle_from_coinbase(
            "0000hand",
            960_001,
            &winning_coinbase_scriptsig(),
            &foreign_outputs,
        ) {
            SettleOutcome::Settled(applied) => {
                assert_eq!(applied.shares_marked, 3, "the shares must still be marked");
                assert_eq!(
                    applied.treasury_bumped, 0,
                    "the treasury script received nothing, so nothing is credited — \
                     NOT the ratified amount"
                );
            }
            other => panic!("a tagged block must settle even when unreconstructable: {other:?}"),
        }

        let (unpaid, _) = db.get_miner_unpaid_stats(MINER).expect("stats");
        assert_eq!(unpaid, 0);
    }
}
