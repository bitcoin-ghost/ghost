//! End-to-end proof that a pool block win actually pays the miners.
//!
//! # Why this test exists
//!
//! The payout path had never executed in production: the pool has never won a block, and at
//! ~110 TH/s against mainnet it may not for a very long time. The GHOST-02 validator — the
//! only thing standing between an honest proposal and a rejected payout — recomputed the
//! miner split from `RoundManager::get_miner_work_scaled(proposal.round_id)`, the work of the
//! single ~90s job-round the block landed in, while the proposer built the split from the
//! cross-round UNPAID LEDGER. `validate_proposal_split` compares the two for exact equality,
//! so every honest node would have rejected the pool's own payout.
//!
//! # Why a naive regtest run does NOT catch this
//!
//! On regtest the block target is trivial, so every share is also a block. Each block sweeps
//! the unpaid ledger and marks those shares paid, so the ledger never accumulates: at
//! block-find it holds roughly ONE round's worth of shares. Ledger ≈ round, the two recomputes
//! agree, and GHOST-02 passes — which is exactly what a manual 4-node regtest run observed on
//! 2026-06-21 ("24 enforcement coinbases ... GHOST-02 recompute matches the proposer").
//!
//! Mainnet is the opposite: 1.1M unpaid shares across 1000+ rounds, accumulated over months of
//! never winning a block. There, a 90s round and the ledger are wildly different objects.
//!
//! So this test deliberately reproduces the MAINNET shape, not the regtest shape:
//!   * an unpaid ledger spanning many job-rounds, and
//!   * a miner who is owed by the ledger but submitted NOTHING in the winning round
//!     (the real fleet has 19 miners on record and ~8 active in any 90s window).
//!
//! `ghost02_round_scoped_recompute_is_rejected` pins the discrimination: it asserts the OLD
//! round-scoped recompute REJECTS this proposal. If that test ever passes, this suite has gone
//! blind to the bug it exists to catch.

use std::sync::Arc;

use ghost_common::config::{BitcoinNetwork, MiningMode};
use ghost_common::constants::BFT_THRESHOLD_PERCENT;
use ghost_common::identity::NodeIdentity;
use ghost_common::rpc::BitcoinRpc;
use ghost_common::types::{PayoutProposal, TreasuryAddress};
use ghost_consensus::vote_handler::VoteHandler;
use ghost_consensus::voting::VotingManager;
use ghost_pool::payout::{
    make_proposal_validator, select_ledger_miner_work, BlockFoundData, PayoutConfig, PayoutHandler,
};
use ghost_pool::template::{TemplateConfig, TemplateProcessor};
use ghost_pool::treasury::TreasuryState;
use ghost_pool::PAYOUT_ADDRESS_GROUPING_HEIGHT;
use ghost_storage::{Database, MinerRecord, ShareRecord};
use ghost_verification::qualification::QualifiedCapabilityProvider;

// ---------------------------------------------------------------------------
// Scenario: the mainnet shape
// ---------------------------------------------------------------------------

/// Job-rounds of unpaid shares that accumulate before the block is won. Rounds rotate per
/// template refresh (~90s in production), so a real ledger spans many of them.
const LEDGER_ROUNDS: u64 = 12;
const SHARES_PER_ROUND: usize = 8;

/// The winning block lands in this round.
const WINNING_ROUND: u64 = LEDGER_ROUNDS;

/// Production-like height: past PAYOUT_ADDRESS_GROUPING_HEIGHT (946_743), so the ledger groups
/// by payout address exactly as the live fleet does.
const BLOCK_HEIGHT: u64 = 957_896;

/// GHOST-02 enforcement forced ON. In production this is CLUSTER_ENFORCEMENT_HEIGHT (955_200),
/// already behind the chain tip. A test that left it at the default on a short chain would have
/// `block_height < enforcement_height`, the validator would return Ok(()) unconditionally, and
/// GHOST-02 would never run at all — a green test proving nothing.
const ENFORCEMENT_HEIGHT: u64 = 0;

const SUBSIDY_SATS: u64 = 312_500_000;
const TX_FEES_SATS: u64 = 4_200_000;

/// Sized to the live fleet (8 nodes). Mainnet BFT needs n >= 3f+1, so `MIN_VOTERS_FOR_BFT` is 7
/// — a smaller mesh cannot even form a voting session, and lowering that floor for the test
/// would prove something the fleet never does.
const MESH_NODES: usize = 8;

/// `(work_per_share, last_round_active)`.
///
/// `carol` is the crux: the largest unpaid balance on the ledger, but she went idle after round
/// 6 and submitted nothing in the winning round. A round-scoped recompute cannot see her at all.
const MINERS: [(f64, u64); 5] = [
    (1_000.0, LEDGER_ROUNDS), // alice  — hashing through the win
    (2_500.0, LEDGER_ROUNDS), // bob    — hashing through the win
    (9_000.0, 6),             // carol  — owed the most, idle at the win
    (400.0, LEDGER_ROUNDS),   // dave   — small, hashing through the win
    (600.0, 9),               // erin   — went idle 3 rounds before the win
];

// ---------------------------------------------------------------------------
// Node harness
// ---------------------------------------------------------------------------

/// One pool node: its own database, its own payout handler, its own view of the ledger.
struct Node {
    db: Arc<Database>,
    handler: Arc<PayoutHandler>,
    template: Arc<TemplateProcessor>,
}

/// The moment the block is found, anchored in the recent PAST.
///
/// This must be earlier than the wall clock, not later. The pre-fix `create_proposal` stamped
/// the proposal with `Utc::now()` — a moment strictly AFTER the cutoff its split was built
/// from. A validator re-deriving that stamp therefore sweeps in shares that landed in the gap.
/// If the scenario were future-dated, the re-derived `now` would fall BEFORE the shares and
/// exclude everything — the tests would still go red, but for a reason that cannot happen in
/// production, and the real race would go untested.
///
/// It must ALSO stay inside `PRE_GATE_FRESHNESS_SECS` (1800, `payout.rs`), which validators
/// apply to the proposal timestamp. This was `- 3_600`, chosen before that rule existed, so
/// every validator rejected the proposal outright:
///
/// ```text
/// node rejected the payout: pre-gate proposal timestamp ... not within 1800s of now ...
/// GHOST-02: 0/8 nodes approved, quorum needs 6
/// ```
///
/// which reads like a catastrophic payout failure and is purely a stale fixture. It went
/// unnoticed because CI never ran this target (#580).
///
/// 600 s keeps a real gap for the race under test while leaving 3x headroom on the freshness
/// bound, so a slow runner cannot drift the test into rejection.
fn block_found_at() -> i64 {
    chrono::Utc::now().timestamp() - 600
}

fn regtest_rpc() -> Option<Arc<BitcoinRpc>> {
    BitcoinRpc::new("127.0.0.1", 18443, "ghosttest", "ghosttest")
        .ok()
        .map(Arc::new)
}

/// A checksum-valid regtest P2WPKH address, derived deterministically.
fn addr(seed: u8) -> String {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[seed; 32]).expect("secret key");
    let pk = bitcoin::PublicKey::new(sk.public_key(&secp));
    let cpk = bitcoin::CompressedPublicKey::try_from(pk).expect("compressed");
    bitcoin::Address::p2wpkh(&cpk, bitcoin::Network::Regtest).to_string()
}

fn miner_addrs() -> Vec<String> {
    (1..=MINERS.len() as u8).map(|i| addr(i + 10)).collect()
}

fn treasury_addr() -> String {
    addr(200)
}

fn pool_addr() -> String {
    addr(201)
}

/// Seeds the SAME unpaid ledger every node converged on (GHOST-03): shares spanning many
/// job-rounds, with two miners going idle before the win.
fn seed_ledger(db: &Database, now: i64) {
    for (i, address) in miner_addrs().iter().enumerate() {
        let (work, last_round) = MINERS[i];
        let miner_id = format!("{address}.w{}", i + 1);

        db.upsert_miner(&MinerRecord {
            miner_id: miner_id.clone(),
            payout_address: address.clone(),
            first_seen: now - 5_000,
            last_seen: now,
            connected_node: None,
            total_shares: 0,
            total_work: 0.0,
            blocks_won: 0,
            total_payouts_sats: 0,
            avg_hashrate_ths: 0.0,
        })
        .expect("upsert miner");

        for round_id in 1..=last_round {
            for k in 0..SHARES_PER_ROUND {
                db.insert_share(&ShareRecord {
                    id: None,
                    round_id,
                    miner_id: miner_id.clone(),
                    difficulty: work,
                    work,
                    share_hash: format!("share-{i}-{round_id}-{k}"),
                    timestamp: now - 2_000 + (round_id as i64 * 90) + k as i64,
                    received_by: "node-a".to_string(),
                    valid: true,
                })
                .expect("insert share");
            }
        }
    }
}

/// The node that finds the block. It receives the TX fees, so H-FUND-1 requires it to have a
/// registered payout address or block production halts.
const WINNING_NODE_ID: [u8; 32] = [9u8; 32];

fn winning_node_addr() -> String {
    addr(202)
}

/// A 3-node mesh. Every node holds the same converged ledger (GHOST-03) and the same elder
/// set, and each recomputes the payout split independently — as the real fleet does.
fn build_mesh(rpc: Arc<BitcoinRpc>, now: i64, n: usize) -> Vec<Node> {
    let identities: Vec<Arc<NodeIdentity>> =
        (0..n).map(|_| Arc::new(NodeIdentity::generate())).collect();
    let elders: Vec<[u8; 32]> = identities.iter().map(|i| i.node_id()).collect();

    identities
        .iter()
        .map(|id| build_node(Arc::clone(&rpc), now, Arc::clone(id), &elders))
        .collect()
}

fn build_node(
    rpc: Arc<BitcoinRpc>,
    now: i64,
    identity: Arc<NodeIdentity>,
    elders: &[[u8; 32]],
) -> Node {
    let db = Arc::new(Database::in_memory().expect("in-memory db"));
    seed_ledger(&db, now);

    // Voting eligibility is read from the MPC elder set, not from a config list — seed it, or
    // `handle_proposal` has no voters and the proposal never enters consensus.
    for (i, elder) in elders.iter().enumerate() {
        db.save_mpc_contribution(&ghost_storage::queries::MpcContributionRecord {
            elder_position: (i + 1) as u32,
            contributor_node_id: hex::encode(elder),
            prev_params_hash: [0u8; 32],
            new_params_hash: [1u8; 32],
            contribution_proof: vec![7u8; 32],
            epoch: 1,
            created_at: now as u64,
        })
        .expect("seed mpc elder");
    }

    db.upsert_node(&ghost_storage::NodeRecord {
        node_id: hex::encode(WINNING_NODE_ID),
        public_address: None,
        display_name: Some("block-finder".to_string()),
        first_seen: now - 5_000,
        last_seen: now,
        is_elder: true,
        elder_order: Some(1),
        capabilities: "{}".to_string(),
        total_uptime_secs: 604_800,
        uptime_7d_percent: 100.0,
        verification_pass_rate: 1.0,
        total_shares_received: 0,
        total_blocks_found: 0,
        payout_address: Some(winning_node_addr()),
    })
    .expect("register block-finding node");

    let template_config = TemplateConfig {
        treasury_address: TreasuryAddress::single(treasury_addr()),
        pool_payout_address: pool_addr(),
        network: BitcoinNetwork::Regtest,
        mining_mode: MiningMode::PublicPool,
        ..Default::default()
    };
    let template = Arc::new(TemplateProcessor::new(
        template_config,
        rpc,
        Default::default(),
        Default::default(),
    ));

    let voting_manager = Arc::new(VotingManager::new(100));
    let vote_handler = Arc::new(
        VoteHandler::new(Arc::clone(&identity), voting_manager).with_database(Arc::clone(&db)),
    );

    let payout_config = PayoutConfig {
        treasury_address: Some(treasury_script()),
        network: BitcoinNetwork::Regtest,
        ..Default::default()
    };

    let handler = Arc::new(
        PayoutHandler::new(
            identity,
            payout_config,
            Arc::clone(&db),
            vote_handler,
            Arc::clone(&template),
            Arc::new(QualifiedCapabilityProvider::new(Arc::clone(&db))),
        )
        .expect("payout handler"),
    );

    Node {
        db,
        handler,
        template,
    }
}

/// The treasury scriptPubKey (P2WPKH) matching `treasury_addr()`.
fn treasury_script() -> Vec<u8> {
    let a: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
        treasury_addr().parse().expect("treasury addr");
    a.assume_checked().script_pubkey().to_bytes()
}

/// Builds the proposal exactly as the proposer does at block-found: split from the unpaid
/// ledger, cutoff carried onto the proposal.
fn propose(node: &Node, cutoff_ts: i64) -> PayoutProposal {
    propose_at(node, cutoff_ts, BLOCK_HEIGHT, SUBSIDY_SATS, TX_FEES_SATS)
}

fn propose_at(
    node: &Node,
    cutoff_ts: i64,
    height: u64,
    subsidy: u64,
    tx_fees: u64,
) -> PayoutProposal {
    let miner_work =
        select_ledger_miner_work(&node.db, cutoff_ts, height, subsidy).expect("ledger");

    assert_eq!(
        miner_work.len(),
        MINERS.len(),
        "every miner with unpaid work — including the idle ones — must be on the ledger"
    );

    let hash = node
        .handler
        .handle_block_found(BlockFoundData {
            shard_owed: None,
            round_id: WINNING_ROUND,
            ledger_cutoff_ts: cutoff_ts,
            block_hash: [0x11; 32],
            block_height: height,
            block_timestamp: chrono::DateTime::from_timestamp(cutoff_ts, 0).expect("ts"),
            winning_miner_id: "pool".to_string(),
            winning_miner_payout_address: Some(miner_addrs()[0].clone()),
            treasury_address_snapshot: Some(treasury_script()),
            winning_node_id: WINNING_NODE_ID,
            subsidy_sats: subsidy,
            tx_fees_sats: tx_fees,
            miner_work,
            node_shares: vec![],
            treasury_state: TreasuryState::new(),
        })
        .expect("handle_block_found");

    assert_ne!(
        hash, [0u8; 32],
        "a block win must produce a payout proposal"
    );

    node.template
        .get_proposal(&hash)
        .expect("proposal stored for coinbase assembly")
}

/// What the OLD validator recomputed: only the winning ~90s round, keyed by miner_id.
fn winning_round_work() -> Vec<(String, u128)> {
    use ghost_accounting::shares::WORK_SCALE;
    miner_addrs()
        .iter()
        .enumerate()
        .filter(|(i, _)| MINERS[*i].1 >= WINNING_ROUND)
        .map(|(i, address)| {
            let miner_id = format!("{address}.w{}", i + 1);
            let work = MINERS[i].0 * SHARES_PER_ROUND as f64;
            (miner_id, (work * WORK_SCALE as f64) as u128)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The proof
// ---------------------------------------------------------------------------

/// A block win is ratified by the whole mesh and its coinbase pays every miner the ledger owes.
///
/// This is the chain that has never run in production:
///   block found → proposal from unpaid ledger → every node's GHOST-02 recompute APPROVES
///   → coinbase carries the miner outputs → shares marked paid.
#[test]
fn block_win_is_ratified_and_pays_every_miner_the_ledger_owes() {
    let Some(rpc) = regtest_rpc() else {
        eprintln!("SKIP: no regtest ghostd on 127.0.0.1:18443");
        return;
    };
    let now = block_found_at();

    // The mesh, sized as the live fleet is. Each node holds its own DB and its own converged ledger.
    let nodes = build_mesh(rpc, now, MESH_NODES);

    // --- Node 0 wins a block and proposes the split from its unpaid ledger.
    let proposal = propose(&nodes[0], now);

    assert_eq!(
        proposal.timestamp as i64, now,
        "the proposal must carry the ledger cutoff its split was computed against"
    );

    // --- Every node independently recomputes the split (GHOST-02, enforcement ON) and votes.
    let approvals = nodes
        .iter()
        .filter(|n| {
            let validator = make_proposal_validator(
                Arc::clone(&n.handler),
                Arc::clone(&n.db),
                ENFORCEMENT_HEIGHT,
            );
            match validator(&proposal) {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("node rejected the payout: {e}");
                    false
                }
            }
        })
        .count();

    // BFT quorum: ceiling(n * 67 / 100).
    let quorum = (nodes.len() * BFT_THRESHOLD_PERCENT as usize).div_ceil(100);
    assert!(
        approvals >= quorum,
        "GHOST-02: {approvals}/{} nodes approved, quorum needs {quorum} — the fleet would \
         reject its own payout and the coinbase would fall back to paying pool_payout_address",
        nodes.len()
    );

    // --- Approved: the coinbase for the next template carries the payout.
    let node = &nodes[0];
    node.template.set_approved_payout(proposal.proposal_hash);
    let coinbase = node
        .template
        .build_approved_coinbase(BLOCK_HEIGHT, &None)
        .expect("approved coinbase");

    // --- Every miner the LEDGER owes is paid in the coinbase — including the idle ones.
    let paid: std::collections::BTreeMap<String, u64> = coinbase
        .output
        .iter()
        .filter_map(|o| {
            bitcoin::Address::from_script(&o.script_pubkey, bitcoin::Network::Regtest)
                .ok()
                .map(|a| (a.to_string(), o.value.to_sat()))
        })
        .collect();

    for (i, address) in miner_addrs().iter().enumerate() {
        assert!(
            paid.contains_key(address),
            "miner {i} is owed by the unpaid ledger but has no coinbase output — a \
             round-scoped split would drop exactly the miners who were idle at the win"
        );
    }

    // --- Amounts are proportional to each miner's UNPAID work, not their work in the last round.
    let total_work: f64 = MINERS
        .iter()
        .map(|(w, last)| w * SHARES_PER_ROUND as f64 * *last as f64)
        .sum();
    let miner_pool = proposal.miner_payouts.iter().map(|p| p.amount).sum::<u64>();

    for (i, address) in miner_addrs().iter().enumerate() {
        let (work, last) = MINERS[i];
        let share = (work * SHARES_PER_ROUND as f64 * last as f64) / total_work;
        let expected = (miner_pool as f64 * share) as u64;
        let actual = paid[address];
        let drift = (actual as i64 - expected as i64).unsigned_abs();
        assert!(
            drift <= 2,
            "miner {i} paid {actual} sats, expected ~{expected} (proportional to unpaid work)"
        );
    }

    // Carol is owed the most despite being idle at the win. If the split were round-scoped she
    // would be paid nothing at all; assert she out-earns everyone.
    let carol = &miner_addrs()[2];
    let top = paid
        .iter()
        .max_by_key(|(_, v)| **v)
        .expect("some miner is paid");
    assert_eq!(
        top.0, carol,
        "carol holds the largest unpaid balance and must be paid the most, even though she \
         submitted nothing in the winning round"
    );

    // --- No satoshis invented or lost: the coinbase spends exactly subsidy + fees.
    let coinbase_total: u64 = coinbase.output.iter().map(|o| o.value.to_sat()).sum();
    assert_eq!(
        coinbase_total,
        SUBSIDY_SATS + TX_FEES_SATS,
        "coinbase value must equal subsidy + fees exactly"
    );

    // --- Ratification alone must NOT settle the ledger.
    //
    // Approval only arms the coinbase; the coins appear when a block carrying this snapshot is
    // won. Settling here would mark the miners' work paid before a satoshi had moved — and with
    // payouts ratified at every tip, it would wipe the ledger every ~10 minutes while paying
    // nobody. The shares must still be owed at this point.
    let owed_after_ratification =
        select_ledger_miner_work(&node.db, now, BLOCK_HEIGHT, SUBSIDY_SATS).expect("ledger");
    assert_eq!(
        owed_after_ratification.len(),
        MINERS.len(),
        "an approved-but-unpaid proposal must leave every share still owed — the ledger is \
         settled when a block PAYS it, not when consensus approves it"
    );

    // --- The block is mined and accepted; its coinbase carries this payout. NOW settle.
    // No mined coinbase exists in this fixture — the legacy ratified-amount path (warned about
    // in production; see #601).
    ghost_pool::payout::settle_paid_block(
        &node.db,
        &proposal,
        PAYOUT_ADDRESS_GROUPING_HEIGHT,
        "e2e_block_hash",
        None,
    )
    .expect("settle the paid block");

    let still_unpaid =
        select_ledger_miner_work(&node.db, now, BLOCK_HEIGHT, SUBSIDY_SATS).expect("ledger");
    assert!(
        still_unpaid.is_empty(),
        "every share the accepted block paid must be marked paid — otherwise the next block \
         pays for the same work twice"
    );
}

/// A share that lands AFTER the proposer's cutoff must not break ratification.
///
/// This exercises the other half of the fix: the cutoff is CARRIED on the proposal
/// (`ledger_cutoff_ts` → `PayoutProposal::timestamp`) rather than re-derived. `create_proposal`
/// used to stamp `Utc::now()`, which runs after the ledger query and the dust filter — so the
/// stamp landed strictly LATER than the window the split was actually built from. A validator
/// recomputing at that stamp would sweep in shares the proposer never counted and reject an
/// honest proposal. At ~1 share/sec fleet-wide, that race is not hypothetical.
#[test]
fn share_arriving_after_the_cutoff_does_not_break_ratification() {
    let Some(rpc) = regtest_rpc() else {
        eprintln!("SKIP: no regtest ghostd on 127.0.0.1:18443");
        return;
    };
    let now = block_found_at();
    let nodes = build_mesh(rpc, now, MESH_NODES);

    // The block is found and the split is computed against the ledger as of `now`.
    let proposal = propose(&nodes[0], now);
    let paid_before: u64 = proposal.miner_payouts.iter().map(|p| p.amount).sum();

    // A share lands a few seconds later — after the cutoff, while the proposal is in flight.
    // Every node receives it, as they would via share gossip.
    for (i, node) in nodes.iter().enumerate() {
        let address = &miner_addrs()[0];
        node.db
            .insert_share(&ShareRecord {
                id: None,
                round_id: WINNING_ROUND + 1,
                miner_id: format!("{address}.w1"),
                difficulty: 50_000.0,
                work: 50_000.0,
                share_hash: format!("late-share-{i}"),
                timestamp: now + 5,
                received_by: "node-a".to_string(),
                valid: true,
            })
            .expect("late share");
    }

    // Every node still ratifies: the proposal names its own window, so the late share is simply
    // not in it. It rolls into the next block's ledger instead.
    for (i, node) in nodes.iter().enumerate() {
        let validator = make_proposal_validator(
            Arc::clone(&node.handler),
            Arc::clone(&node.db),
            ENFORCEMENT_HEIGHT,
        );
        validator(&proposal).unwrap_or_else(|e| {
            panic!(
                "node {i} rejected an honest proposal because a share arrived after the \
                 cutoff: {e} — the cutoff must be carried on the proposal, not re-derived"
            )
        });
    }

    // And the late share is still owed after this block is paid out.
    ghost_pool::payout::settle_paid_block(
        &nodes[0].db,
        &proposal,
        PAYOUT_ADDRESS_GROUPING_HEIGHT,
        "e2e_block_hash_multi",
        None,
    )
    .expect("settle the paid block");

    let still_owed = select_ledger_miner_work(&nodes[0].db, now + 60, BLOCK_HEIGHT, SUBSIDY_SATS)
        .expect("ledger");
    assert_eq!(
        still_owed.len(),
        1,
        "the post-cutoff share must survive as unpaid work for the next block, not vanish"
    );
    assert!(paid_before > 0, "this block still paid the miners it owed");
}

/// Tip-change arming: the coinbase is ratified BEFORE a block is won, so the FIRST block the
/// pool ever wins pays its miners.
///
/// A block's coinbase is fixed when its template is built, so it can only pay a payout that was
/// already approved. Proposals used to be created only on block-found, so `approved_payout`
/// always lagged one win behind — and starting from `None`, with the pool never having won, every
/// template carried the fallback coinbase. The first block would have paid its whole subsidy to
/// `pool_payout_address` and the miners nothing.
///
/// Two properties make tip-change ratification safe, and both are asserted here:
///   * exactly ONE node proposes per tip (a deterministic rotation over the elder set), and
///   * ratifying does NOT settle the ledger — the shares stay owed until a block pays them.
#[test]
fn tip_change_arms_the_coinbase_and_leaves_the_ledger_owed() {
    let Some(rpc) = regtest_rpc() else {
        eprintln!("SKIP: no regtest ghostd on 127.0.0.1:18443");
        return;
    };
    let now = block_found_at();
    let nodes = build_mesh(rpc, now, MESH_NODES);

    // Every node computes the same proposer for a given height, with no coordination.
    let elders_of = |n: &Node| -> Vec<[u8; 32]> {
        let mut e: Vec<[u8; 32]> =
            n.db.get_mpc_elder_node_ids()
                .expect("elders")
                .into_iter()
                .collect();
        e.sort_unstable();
        e
    };
    let reference = elders_of(&nodes[0]);
    for n in &nodes {
        assert_eq!(
            elders_of(n),
            reference,
            "every node must derive the same elder ordering, or they disagree on who proposes"
        );
    }
    assert_eq!(reference.len(), MESH_NODES);

    // Exactly one node's turn per height, and the turn rotates.
    let proposer_at = |h: u64| reference[(h as usize) % reference.len()];
    let mut seen = std::collections::HashSet::new();
    for h in BLOCK_HEIGHT..BLOCK_HEIGHT + MESH_NODES as u64 {
        seen.insert(proposer_at(h));
    }
    assert_eq!(
        seen.len(),
        MESH_NODES,
        "the proposer must rotate across the elder set, not pin to one node"
    );

    // The elected proposer arms the coinbase from the unpaid ledger, before any block is won.
    //
    // Rotating over the ELDER set is a determinism choice, not an authorisation one: any node may
    // submit a proposal (`handle_proposal` does not check the sender). But the elder set is the
    // only node list every node derives identically, so it is the only set they can agree a turn
    // order over. Rotate over a set they disagree about and you get zero proposers, or eight.
    let proposer_idx = reference
        .iter()
        .position(|e| *e == proposer_at(BLOCK_HEIGHT))
        .expect("the elected proposer must be in the set it was drawn from");
    let proposal = propose(&nodes[proposer_idx], now);
    assert!(
        !proposal.miner_payouts.is_empty(),
        "the armed coinbase must pay the miners the ledger owes"
    );

    // And the ledger is untouched: nothing is settled until a block actually pays it. If this
    // regressed, ratifying at every tip would wipe the ledger every ~10 minutes, paying no one.
    let still_owed =
        select_ledger_miner_work(&nodes[0].db, now, BLOCK_HEIGHT, SUBSIDY_SATS).expect("ledger");
    assert_eq!(
        still_owed.len(),
        MINERS.len(),
        "arming the coinbase must not settle the ledger — the coins do not exist yet"
    );
}

/// Discrimination check: the OLD round-scoped recompute REJECTS this same honest proposal.
///
/// This is what makes the test above meaningful. If this ever starts passing, the scenario has
/// gone degenerate (ledger ≈ round) and the suite is blind to the bug — which is precisely how
/// the 2026-06-21 regtest run produced 24 green coinbases while the bug was live.
#[test]
fn ghost02_round_scoped_recompute_is_rejected() {
    let Some(rpc) = regtest_rpc() else {
        eprintln!("SKIP: no regtest ghostd on 127.0.0.1:18443");
        return;
    };
    let now = block_found_at();
    let nodes = build_mesh(rpc, now, MESH_NODES);
    let node = &nodes[0];

    let proposal = propose(node, now);
    let round_work = winning_round_work();

    assert!(
        round_work.len() < MINERS.len(),
        "the scenario must have miners owed by the ledger but idle in the winning round, \
         or it cannot discriminate the bug"
    );

    let err = node
        .handler
        .validate_proposal_split(&proposal, &round_work, None, &TreasuryState::new())
        .expect_err(
            "a round-scoped recompute cannot reproduce a ledger-built split — if this \
             succeeds, the test scenario has gone degenerate and proves nothing",
        );
    assert!(err.contains("GHOST-02"), "unexpected rejection: {err}");
}

// ---------------------------------------------------------------------------
// The last mile: a real block, on a real chain, accepted by ghostd
// ---------------------------------------------------------------------------

/// Mine an actual block whose coinbase is the mesh-ratified payout, and have `ghostd` accept it.
///
/// Everything above proves the fleet ratifies the split and that we can assemble a coinbase from
/// it. It does not prove the chain will take it. This does: a real regtest chain, a real
/// `getblocktemplate`, a real proof-of-work grind, a real `submitblock`, and then we read the
/// block back out of the node and check who actually got paid.
///
/// NOTE ON HEIGHT: a regtest chain is ~100 blocks tall, far below
/// `PAYOUT_ADDRESS_GROUPING_HEIGHT` (946_743), so this exercises the PRE-gate ledger path
/// (grouped by miner_id, addresses resolved from the miners table). The post-gate
/// address-grouped path is what `block_win_is_ratified_and_pays_every_miner_the_ledger_owes`
/// covers. Between them both ledger groupings are proven.
#[tokio::test]
async fn mined_block_is_accepted_by_ghostd_and_pays_the_miners() {
    let Some(rpc) = regtest_rpc() else {
        eprintln!("SKIP: no regtest ghostd on 127.0.0.1:18443");
        return;
    };
    if rpc.get_block_count().await.is_err() {
        eprintln!("SKIP: regtest ghostd not responding");
        return;
    }

    // A chain to build on. Idempotent: the regtest node may already be primed from a previous
    // run, and re-generating would leave the RPC client's height sanity-check stale.
    let have = rpc.get_block_count().await.expect("height");
    if have < 101 {
        rpc.call_raw(
            "generatetoaddress",
            vec![
                serde_json::json!(101 - have),
                serde_json::json!(pool_addr()),
            ],
        )
        .await
        .expect("generate chain");
    }
    // Refresh the client's notion of the tip before asking for a template against it.
    rpc.get_block_count().await.expect("height");

    // `get_block_template` sanity-checks the target against mainnet-ish bounds and rejects
    // regtest's trivially-easy target. The unchecked variant is the one to use on regtest.
    let template = rpc
        .get_block_template_unchecked(vec!["segwit"])
        .await
        .expect("getblocktemplate");
    let height = template.height;
    let subsidy = template.coinbasevalue; // empty block → no fees, all subsidy

    let now = block_found_at();
    let nodes = build_mesh(Arc::clone(&rpc), now, MESH_NODES);

    // --- The pool finds a block. The split comes from the unpaid ledger.
    let proposal = propose_at(&nodes[0], now, height, subsidy, 0);

    // --- The mesh ratifies it (GHOST-02 enforced).
    let approvals = nodes
        .iter()
        .filter(|n| {
            let validator = make_proposal_validator(
                Arc::clone(&n.handler),
                Arc::clone(&n.db),
                ENFORCEMENT_HEIGHT,
            );
            validator(&proposal).is_ok()
        })
        .count();
    let quorum = (MESH_NODES * BFT_THRESHOLD_PERCENT as usize).div_ceil(100);
    assert!(
        approvals >= quorum,
        "{approvals}/{MESH_NODES} approved, quorum needs {quorum}"
    );

    // --- The ratified payout becomes the coinbase of the block we are about to mine.
    let node = &nodes[0];
    node.template.set_approved_payout(proposal.proposal_hash);
    let coinbase = node
        .template
        .build_approved_coinbase(height, &template.default_witness_commitment)
        .expect("approved coinbase");

    // --- Assemble the block: just the coinbase, on top of the current tip.
    use bitcoin::consensus::Encodable;
    use bitcoin::hashes::Hash;

    let prev: bitcoin::BlockHash = template
        .previousblockhash
        .parse()
        .expect("previousblockhash");
    let bits = u32::from_str_radix(&template.bits, 16).expect("bits");

    let mut header = bitcoin::block::Header {
        version: bitcoin::block::Version::from_consensus(template.version as i32),
        prev_blockhash: prev,
        // Single-transaction block: the merkle root IS the coinbase txid.
        merkle_root: bitcoin::TxMerkleNode::from_byte_array(
            coinbase.compute_txid().to_byte_array(),
        ),
        time: template.curtime as u32,
        bits: bitcoin::CompactTarget::from_consensus(bits),
        nonce: 0,
    };

    // --- Real proof-of-work. Regtest's target is easy, but this is a genuine grind.
    let target = header.target();
    let mut found = false;
    for nonce in 0..u32::MAX {
        header.nonce = nonce;
        if target.is_met_by(header.block_hash()) {
            found = true;
            break;
        }
    }
    assert!(found, "failed to find a nonce meeting the regtest target");

    let block = bitcoin::Block {
        header,
        txdata: vec![coinbase.clone()],
    };
    let mut raw = Vec::new();
    block.consensus_encode(&mut raw).expect("encode block");

    // --- Hand it to ghostd. A `None` reply means ACCEPTED; anything else is a rejection reason.
    let before = rpc.get_block_count().await.expect("height before");
    let reject = rpc
        .submit_block(&hex::encode(&raw))
        .await
        .expect("submitblock rpc");
    assert_eq!(
        reject, None,
        "ghostd REJECTED the block carrying the mesh-ratified payout coinbase"
    );

    let after = rpc.get_block_count().await.expect("height after");
    assert_eq!(
        after,
        before + 1,
        "the chain must have advanced by our block"
    );

    // --- Read our block back out of the node and see who actually got paid on-chain.
    let hash = block.block_hash().to_string();
    let onchain = rpc.get_block(&hash, 2).await.expect("getblock");
    let cb = &onchain["tx"][0];

    let mut paid_onchain = std::collections::BTreeMap::new();
    for vout in cb["vout"].as_array().expect("vout") {
        let sats = (vout["value"].as_f64().expect("value") * 1e8).round() as u64;
        if let Some(a) = vout["scriptPubKey"]["address"].as_str() {
            *paid_onchain.entry(a.to_string()).or_insert(0u64) += sats;
        }
    }

    for (i, address) in miner_addrs().iter().enumerate() {
        let got = paid_onchain.get(address).copied().unwrap_or(0);
        assert!(
            got > 0,
            "miner {i} ({address}) is owed by the ledger but received NOTHING in the \
             accepted block's coinbase — on-chain outputs: {paid_onchain:?}"
        );
    }

    // Carol — owed the most, idle at the win — must be the top-paid miner on-chain.
    let carol = &miner_addrs()[2];
    let top_miner = miner_addrs()
        .iter()
        .max_by_key(|a| paid_onchain.get(*a).copied().unwrap_or(0))
        .expect("a miner")
        .clone();
    assert_eq!(
        &top_miner, carol,
        "the miner with the largest unpaid ledger balance must be paid the most on-chain"
    );

    // The block's coinbase spends exactly the subsidy ghostd allows — it accepted it, but assert
    // it anyway so a future change that silently under-pays the miners is caught here.
    let coinbase_total: u64 = coinbase.output.iter().map(|o| o.value.to_sat()).sum();
    assert_eq!(
        coinbase_total, subsidy,
        "coinbase must spend the full subsidy"
    );

    eprintln!(
        "ACCEPTED block {hash} at height {height}: {} coinbase outputs, {} sats to miners",
        coinbase.output.len(),
        miner_addrs()
            .iter()
            .map(|a| paid_onchain.get(a).copied().unwrap_or(0))
            .sum::<u64>()
    );
}
