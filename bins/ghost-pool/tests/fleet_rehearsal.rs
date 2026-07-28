//! Full-sequence rehearsal: a divergent fleet is reconciled, ratifies a payout, mines a block
//! that a real node accepts, and pays its miners.
//!
//! Every piece of the payout fix has its own test. This proves they work TOGETHER, in order,
//! starting from the state the live fleet is actually in — which is the thing none of the other
//! tests do, and the exact gap that let a 4-node regtest run produce 24 green coinbases on
//! 2026-06-21 while the bug was live.
//!
//! The sequence, and what would break without each step:
//!
//!   1. DIVERGENT LEDGERS. Eight nodes, each missing a different ~5% of the shares — the live
//!      fleet's real state, caused by fire-and-forget gossip that GHOST-03 never repaired.
//!      These are pre-v41 rows: no stored proof, so no node can serve or verify them.
//!   2. THE PAYOUT IS REJECTED. Nodes summing different share sets compute different miner
//!      splits, and GHOST-02 compares them for EXACT equality. This is what the fleet would do
//!      today. If this step ever starts passing, the scenario has gone degenerate and the whole
//!      rehearsal proves nothing.
//!   3. RECONCILE. The one-time union across the operator's own nodes.
//!   4. THE PAYOUT IS RATIFIED. All eight nodes now agree.
//!   5. THE COINBASE IS ARMED AT TIP CHANGE, before any block is won — so the FIRST block the
//!      pool ever wins pays its miners, rather than paying pool_payout_address alone.
//!   6. A REAL BLOCK IS MINED AND ACCEPTED by ghostd, and the miners are paid in its coinbase.
//!   7. THE LEDGER SETTLES — and only now, because the coins finally exist.

use std::sync::Arc;

use ghost_common::config::{BitcoinNetwork, MiningMode};
use ghost_common::identity::NodeIdentity;
use ghost_common::rpc::BitcoinRpc;
use ghost_common::types::{PayoutProposal, TreasuryAddress};
use ghost_consensus::vote_handler::VoteHandler;
use ghost_consensus::voting::VotingManager;
use ghost_pool::payout::{
    make_proposal_validator, select_ledger_miner_work, settle_paid_block, BlockFoundData,
    PayoutConfig, PayoutHandler,
};
use ghost_pool::template::{TemplateConfig, TemplateProcessor};
use ghost_pool::treasury::TreasuryState;
use ghost_pool::PAYOUT_ADDRESS_GROUPING_HEIGHT;
use ghost_storage::{Database, MinerRecord, ShareRecord};
use ghost_verification::qualification::QualifiedCapabilityProvider;

const FLEET: usize = 8;
const MINERS: usize = 6;
const ROUNDS: u64 = 20;
const SHARES_PER_ROUND: usize = 6;

/// GHOST-02 enforcement forced ON. In production this is CLUSTER_ENFORCEMENT_HEIGHT (955_200),
/// already behind the tip. Leave it at the default on a short chain and the validator returns
/// Ok(()) unconditionally — GHOST-02 never runs and the rehearsal proves nothing.
const ENFORCEMENT: u64 = 0;

struct Node {
    db: Arc<Database>,
    handler: Arc<PayoutHandler>,
    template: Arc<TemplateProcessor>,
}

fn rpc() -> Option<Arc<BitcoinRpc>> {
    BitcoinRpc::new("127.0.0.1", 18443, "ghosttest", "ghosttest")
        .ok()
        .map(Arc::new)
}

fn addr(seed: u8) -> String {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[seed; 32]).expect("sk");
    let pk = bitcoin::PublicKey::new(sk.public_key(&secp));
    let cpk = bitcoin::CompressedPublicKey::try_from(pk).expect("cpk");
    bitcoin::Address::p2wpkh(&cpk, bitcoin::Network::Regtest).to_string()
}

fn miner_addrs() -> Vec<String> {
    (0..MINERS as u8).map(|i| addr(i + 20)).collect()
}

fn treasury_script() -> Vec<u8> {
    let a: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
        addr(200).parse().expect("treasury");
    a.assume_checked().script_pubkey().to_bytes()
}

/// Every share the pool ever received: `(share_hash, miner_index, round, work, timestamp)`.
fn all_shares(now: i64) -> Vec<(String, usize, u64, f64, i64)> {
    let mut out = Vec::new();
    for m in 0..MINERS {
        // Miners differ in size, and two go idle before the block is won — the live fleet has 19
        // miners on record and only ~8 active in any 90s window. A miner owed by the ledger but
        // absent from the winning round is exactly what a round-scoped split drops.
        //
        // Miner 2 is the crux: it holds the LARGEST unpaid balance despite having stopped
        // hashing halfway through, so it must still be the top-paid miner on-chain. Give it
        // enough weight per share that idling does not cost it the top spot, or the test asserts
        // a property the scenario does not actually have.
        let (work, last_round) = match m {
            2 => (9_000.0, ROUNDS / 2),     // owed the most, idle at the win
            4 => (500.0 * 5.0, ROUNDS - 3), // went idle shortly before the win
            _ => (500.0 * (m as f64 + 1.0), ROUNDS),
        };
        for r in 1..=last_round {
            for k in 0..SHARES_PER_ROUND {
                out.push((
                    format!("share-{m}-{r}-{k}"),
                    m,
                    r,
                    work,
                    now - 4_000 + (r as i64 * 90) + k as i64,
                ));
            }
        }
    }
    out
}

/// A node's view of the ledger: it dropped every Nth share, with a different offset per node.
///
/// This is the live fleet's actual state — fire-and-forget gossip dropped shares and GHOST-03
/// only ever repaired the in-memory round view, never the `shares` table the payout reads. These
/// rows are written WITHOUT a proof: pre-v41, so no node can serve or verify them, which is
/// precisely why no protocol can reconcile them.
fn seed_divergent(db: &Database, node: usize, now: i64) {
    let addrs = miner_addrs();
    for (m, address) in addrs.iter().enumerate() {
        db.upsert_miner(&MinerRecord {
            miner_id: format!("{address}.w{m}"),
            payout_address: address.clone(),
            first_seen: now - 9_000,
            last_seen: now,
            connected_node: None,
            total_shares: 0,
            total_work: 0.0,
            blocks_won: 0,
            total_payouts_sats: 0,
            avg_hashrate_ths: 0.0,
        })
        .expect("miner");
    }

    for (i, (hash, m, round, work, ts)) in all_shares(now).into_iter().enumerate() {
        // Drop ~5% — a different slice on each node, as real gossip loss would.
        if (i + node * 7).is_multiple_of(20) {
            continue;
        }
        db.insert_share(&ShareRecord {
            id: None,
            round_id: round,
            miner_id: format!("{}.w{m}", addrs[m]),
            difficulty: work,
            work,
            share_hash: hash,
            timestamp: ts,
            received_by: format!("node-{node}"),
            valid: true,
        })
        .expect("share");
    }
}

fn build_node(
    rpc: Arc<BitcoinRpc>,
    identity: Arc<NodeIdentity>,
    elders: &[[u8; 32]],
    node: usize,
    now: i64,
) -> Node {
    let db = Arc::new(Database::in_memory().expect("db"));
    seed_divergent(&db, node, now);

    for (i, e) in elders.iter().enumerate() {
        db.save_mpc_contribution(&ghost_storage::queries::MpcContributionRecord {
            elder_position: (i + 1) as u32,
            contributor_node_id: hex::encode(e),
            prev_params_hash: [0u8; 32],
            new_params_hash: [1u8; 32],
            contribution_proof: vec![7u8; 32],
            epoch: 1,
            created_at: now as u64,
        })
        .expect("elder");
    }

    let template = Arc::new(TemplateProcessor::new(
        TemplateConfig {
            treasury_address: TreasuryAddress::single(addr(200)),
            pool_payout_address: addr(201),
            network: BitcoinNetwork::Regtest,
            mining_mode: MiningMode::PublicPool,
            ..Default::default()
        },
        rpc,
        Default::default(),
        Default::default(),
    ));

    let vote_handler = Arc::new(
        VoteHandler::new(Arc::clone(&identity), Arc::new(VotingManager::new(100)))
            .with_database(Arc::clone(&db)),
    );

    let handler = Arc::new(
        PayoutHandler::new(
            identity,
            PayoutConfig {
                treasury_address: Some(treasury_script()),
                network: BitcoinNetwork::Regtest,
                ..Default::default()
            },
            Arc::clone(&db),
            vote_handler,
            Arc::clone(&template),
            Arc::new(QualifiedCapabilityProvider::new(Arc::clone(&db))),
        )
        .expect("handler"),
    );

    Node {
        db,
        handler,
        template,
    }
}

fn unpaid_work(db: &Database) -> f64 {
    db.get_top_unpaid_miners(i64::MAX, u32::MAX)
        .expect("ledger")
        .iter()
        .map(|(_, w)| *w)
        .sum()
}

/// Propose a payout for `height` from the unpaid ledger, exactly as the tip-change proposer does.
fn propose(
    node: &Node,
    cutoff: i64,
    height: u64,
    subsidy: u64,
    node_id: [u8; 32],
) -> PayoutProposal {
    let miner_work = select_ledger_miner_work(&node.db, cutoff, height, subsidy).expect("ledger");
    let hash = node
        .handler
        .handle_block_found(BlockFoundData {
            round_id: ROUNDS,
            ledger_cutoff_ts: cutoff,
            block_hash: [0x33; 32],
            block_height: height,
            block_timestamp: chrono::DateTime::from_timestamp(cutoff, 0).expect("ts"),
            winning_miner_id: "pool".to_string(),
            winning_miner_payout_address: None,
            treasury_address_snapshot: Some(treasury_script()),
            winning_node_id: node_id,
            subsidy_sats: subsidy,
            tx_fees_sats: 0,
            miner_work,
            node_shares: vec![],
            treasury_state: TreasuryState::new(),
        })
        .expect("propose");
    assert_ne!(hash, [0u8; 32], "a proposal must be produced");
    node.template.get_proposal(&hash).expect("stored")
}

/// How many of the fleet ratify this proposal against their own ledger (GHOST-02, enforced).
fn ratifying(nodes: &[Node], proposal: &PayoutProposal) -> usize {
    nodes
        .iter()
        .filter(|n| {
            let v = make_proposal_validator(Arc::clone(&n.handler), Arc::clone(&n.db), ENFORCEMENT);
            v(proposal).is_ok()
        })
        .count()
}

#[tokio::test]
async fn divergent_fleet_is_reconciled_ratifies_and_pays_its_miners_on_a_real_chain() {
    let Some(rpc) = rpc() else {
        eprintln!("SKIP: no regtest ghostd on 127.0.0.1:18443");
        return;
    };
    if rpc.get_block_count().await.is_err() {
        eprintln!("SKIP: regtest ghostd not responding");
        return;
    }

    let now = chrono::Utc::now().timestamp() - 3_600;
    let identities: Vec<Arc<NodeIdentity>> = (0..FLEET)
        .map(|_| Arc::new(NodeIdentity::generate()))
        .collect();
    let elders: Vec<[u8; 32]> = identities.iter().map(|i| i.node_id()).collect();

    let nodes: Vec<Node> = identities
        .iter()
        .enumerate()
        .map(|(i, id)| build_node(Arc::clone(&rpc), Arc::clone(id), &elders, i, now))
        .collect();

    // ---- 1. The fleet is DIVERGENT. This is the live state.
    let ledgers: Vec<f64> = nodes.iter().map(|n| unpaid_work(&n.db)).collect();
    let min = ledgers.iter().cloned().fold(f64::MAX, f64::min);
    let max = ledgers.iter().cloned().fold(0.0, f64::max);
    assert!(
        max > min,
        "the fleet must start divergent, or this rehearsal is not reproducing production"
    );
    eprintln!(
        "1. DIVERGENT: unpaid work spans {min:.0}..{max:.0} across {FLEET} nodes ({:.1}% spread)",
        100.0 * (max - min) / max
    );

    // ---- 2. The payout is REJECTED. This is what the fleet would do TODAY.
    let chain_height = rpc.get_block_count().await.expect("height");
    let height = chain_height + 1;
    let subsidy = 1_000_000_000u64;

    let doomed = propose(&nodes[0], now, height, subsidy, elders[0]);
    let before = ratifying(&nodes, &doomed);
    assert!(
        before < FLEET,
        "a divergent fleet MUST reject the payout — if every node ratifies here, the ledgers \
         are not really divergent and this rehearsal proves nothing"
    );
    eprintln!(
        "2. REJECTED: only {before}/{FLEET} nodes ratify a payout built on a divergent ledger"
    );

    // ---- 3. RECONCILE: the one-time union across the operator's own nodes.
    let mut union: std::collections::BTreeMap<String, ghost_storage::queries::UnpaidShareExport> =
        std::collections::BTreeMap::new();
    for n in &nodes {
        for s in n.db.export_unpaid_shares().expect("export") {
            union.entry(s.share_hash.clone()).or_insert(s);
        }
    }
    let union: Vec<_> = union.into_values().collect();
    for n in &nodes {
        n.db.import_unpaid_shares(&union, false).expect("import");
    }

    let after_ledgers: Vec<f64> = nodes.iter().map(|n| unpaid_work(&n.db)).collect();
    assert!(
        after_ledgers.windows(2).all(|w| (w[0] - w[1]).abs() < 1e-6),
        "after reconciliation every node must sum the SAME ledger, or GHOST-02 still rejects: \
         {after_ledgers:?}"
    );
    eprintln!(
        "3. RECONCILED: all {FLEET} nodes now sum an identical ledger ({:.0} work)",
        after_ledgers[0]
    );

    // ---- 4. The payout is RATIFIED.
    let proposal = propose(&nodes[0], now, height, subsidy, elders[0]);
    let approvals = ratifying(&nodes, &proposal);
    assert_eq!(
        approvals, FLEET,
        "a reconciled fleet must unanimously ratify its own honest payout"
    );
    eprintln!("4. RATIFIED: {approvals}/{FLEET} nodes approve");

    // ---- 5. The coinbase is ARMED before any block is won.
    let node = &nodes[0];
    node.template.set_approved_payout(proposal.proposal_hash);
    assert_eq!(
        node.template.approved_payout(),
        Some(proposal.proposal_hash),
        "the coinbase must be armed BEFORE the block is found — a block's coinbase is fixed when \
         its template is built, so it can only pay a payout that was already approved"
    );

    // The ledger is NOT settled: the coins do not exist yet.
    assert!(
        !select_ledger_miner_work(&node.db, now, height, subsidy)
            .expect("ledger")
            .is_empty(),
        "arming must not settle the ledger — ratifying at every tip would otherwise wipe it \
         every ~10 minutes while paying nobody"
    );
    eprintln!("5. ARMED: coinbase ratified before the block is won; ledger still owed");

    // ---- 6. Mine a REAL block and have ghostd accept it.
    let template = rpc
        .get_block_template_unchecked(vec!["segwit"])
        .await
        .expect("gbt");
    let coinbase = node
        .template
        .build_approved_coinbase(template.height, &template.default_witness_commitment)
        .expect("coinbase");

    use bitcoin::consensus::Encodable;
    use bitcoin::hashes::Hash;

    let mut header = bitcoin::block::Header {
        version: bitcoin::block::Version::from_consensus(template.version as i32),
        prev_blockhash: template.previousblockhash.parse().expect("prev"),
        merkle_root: bitcoin::TxMerkleNode::from_byte_array(
            coinbase.compute_txid().to_byte_array(),
        ),
        time: template.curtime as u32,
        bits: bitcoin::CompactTarget::from_consensus(
            u32::from_str_radix(&template.bits, 16).expect("bits"),
        ),
        nonce: 0,
    };
    let target = header.target();
    let mut mined = false;
    for nonce in 0..u32::MAX {
        header.nonce = nonce;
        if target.is_met_by(header.block_hash()) {
            mined = true;
            break;
        }
    }
    assert!(mined, "failed to meet the regtest target");

    let block = bitcoin::Block {
        header,
        txdata: vec![coinbase.clone()],
    };
    let mut raw = Vec::new();
    block.consensus_encode(&mut raw).expect("encode");

    let reject = rpc
        .submit_block(&hex::encode(&raw))
        .await
        .expect("submitblock");
    assert_eq!(
        reject, None,
        "ghostd REJECTED the block carrying the reconciled, mesh-ratified payout"
    );
    eprintln!(
        "6. ACCEPTED: ghostd took block {} at height {}",
        block.block_hash(),
        template.height
    );

    // Read it back off the chain: who actually got paid?
    let onchain = rpc
        .get_block(&block.block_hash().to_string(), 2)
        .await
        .expect("getblock");
    let mut paid = std::collections::BTreeMap::new();
    for vout in onchain["tx"][0]["vout"].as_array().expect("vout") {
        if let Some(a) = vout["scriptPubKey"]["address"].as_str() {
            let sats = (vout["value"].as_f64().expect("value") * 1e8).round() as u64;
            *paid.entry(a.to_string()).or_insert(0u64) += sats;
        }
    }
    for (i, a) in miner_addrs().iter().enumerate() {
        assert!(
            paid.get(a).copied().unwrap_or(0) > 0,
            "miner {i} is owed by the reconciled ledger but received NOTHING on-chain: {paid:?}"
        );
    }

    // The miner owed the most is the one who went idle before the win. A round-scoped split — or
    // an unreconciled ledger — would have paid them nothing.
    let idle_but_owed = &miner_addrs()[2];
    let top = miner_addrs()
        .into_iter()
        .max_by_key(|a| paid.get(a).copied().unwrap_or(0))
        .expect("a miner");
    assert_eq!(
        &top, idle_but_owed,
        "the miner with the largest unpaid balance must be paid the most on-chain, even though \
         they submitted nothing in the winning round"
    );
    eprintln!(
        "   miners paid on-chain: {} sats across {} outputs",
        miner_addrs()
            .iter()
            .map(|a| paid.get(a).copied().unwrap_or(0))
            .sum::<u64>(),
        coinbase.output.len()
    );

    // ---- 7. NOW the ledger settles — the coins exist.
    settle_paid_block(&node.db, &proposal, PAYOUT_ADDRESS_GROUPING_HEIGHT).expect("settle");
    assert!(
        select_ledger_miner_work(&node.db, now, height, subsidy)
            .expect("ledger")
            .is_empty(),
        "every share the accepted block paid must be marked paid, or the next block pays for the \
         same work twice"
    );
    eprintln!("7. SETTLED: ledger emptied only after the block that paid it was accepted");
}
