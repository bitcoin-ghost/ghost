//! Settlement rehearsal against a **real** Ghost Core in regtest.
//!
//! The unit tests hand `settle_from_scriptsig` bytes we produced ourselves. That proves the
//! decision logic, and nothing about the parts that only exist against a live node: the RPC calls,
//! the byte order of a block hash, whether a coinbase mined into a real chain still parses. Those
//! are exactly where this broke on the canary — `getblock` answered "Block not found" for every
//! block because `BlockEvent` hashes are internal order.
//!
//! So this drives the real path: a block mined into a real chain, read back over real RPC, settled,
//! then orphaned by a real reorg and reversed.
//!
//! Ignored by default — it needs a regtest node. Bring one up and run:
//!
//! ```text
//! ghostd -regtest -datadir=<dir> -rpcport=18999 -rpcuser=rt -rpcpassword=rt
//! GHOST_REGTEST_RPC=127.0.0.1:18999 cargo test -p ghost-pool --test regtest_settlement_rehearsal \
//!     -- --ignored --nocapture
//! ```

use std::sync::Arc;

use ghost_common::rpc::BitcoinRpc;
use ghost_pool::settlement::{SettleOutcome, SettlementObserver};
use ghost_storage::models::{MinerRecord, ShareRecord};
use ghost_storage::Database;

const MINER: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080.worker";
const ADDRESS: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
/// Matches the payout id the rehearsal block was mined with.
const PROPOSAL_HASH: [u8; 32] = [0x5A; 32];

fn rpc() -> Option<Arc<BitcoinRpc>> {
    let hostport = std::env::var("GHOST_REGTEST_RPC").ok()?;
    let (host, port) = hostport.split_once(':')?;
    Some(Arc::new(
        BitcoinRpc::new(host, port.parse().ok()?, "rt", "rt").expect("rpc"),
    ))
}

/// Drive Core directly for the operator-side actions.
///
/// `invalidateblock` is a thing an operator does, not a thing ghost-pool does — so it goes through
/// the CLI rather than widening a private RPC surface just to reach it from a test.
fn cli(args: &[&str]) -> String {
    let conf = std::env::var("GHOST_REGTEST_CONF").expect("set GHOST_REGTEST_CONF");
    let datadir = std::env::var("GHOST_REGTEST_DATADIR").expect("set GHOST_REGTEST_DATADIR");
    let out = std::process::Command::new("/home/defenwycke/bin/ghost-cli")
        .arg(format!("-conf={conf}"))
        .arg(format!("-datadir={datadir}"))
        .args(args)
        .output()
        .expect("ghost-cli must run");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// A node holding the shares and the gossiped proposal, and nothing else — the situation seven of
/// eight nodes are in every time the pool wins.
fn non_submitting_node(shares: usize) -> Arc<Database> {
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
            share_hash: format!("rehearsal_{i}"),
            timestamp: now() - 600,
            received_by: "node".to_string(),
            valid: true,
        })
        .expect("share");
    }

    let proposal = ghost_common::types::PayoutProposal {
        proposal_hash: PROPOSAL_HASH,
        round_id: 1,
        block_hash: [0u8; 32],
        block_height: 102,
        proposer: [1u8; 32],
        miner_payouts: vec![ghost_common::types::PayoutEntry {
            address: ADDRESS.as_bytes().to_vec(),
            amount: 100_000_000,
            recipient_id: {
                let h = ghost_common::identity::hash_message(ADDRESS.as_bytes());
                let mut id = [0u8; 32];
                id.copy_from_slice(&h);
                id
            },
            payout_type: ghost_common::types::PayoutType::Mining,
        }],
        node_payouts: vec![],
        treasury_amount: 0,
        treasury_address: ADDRESS.as_bytes().to_vec(),
        tx_fees: 0,
        subsidy: 5_000_000_000,
        timestamp: now() as u64,
        tx_fees_unallocated: 0,
    };
    db.store_payout_proposal(
        &PROPOSAL_HASH,
        1,
        102,
        &serde_json::to_string(&proposal).expect("json"),
    )
    .expect("store proposal");
    db
}

/// **The rehearsal.** A block that exists on a real chain, read over real RPC, settled by a node
/// that did not submit it — then orphaned and reversed.
#[tokio::test]
#[ignore = "needs a regtest node; set GHOST_REGTEST_RPC=host:port"]
async fn a_real_block_settles_and_a_real_reorg_reverses_it() {
    let Some(rpc) = rpc() else {
        panic!("set GHOST_REGTEST_RPC=host:port");
    };
    let tagged_height = std::env::var("GHOST_REGTEST_TAGGED_HEIGHT")
        .expect("set GHOST_REGTEST_TAGGED_HEIGHT to the tagged block's height")
        .parse::<u64>()
        .expect("height");

    let block_hash = rpc
        .get_block_hash(tagged_height)
        .await
        .expect("the tagged block must exist");
    println!("rehearsal block {tagged_height} = {block_hash}");

    let db = non_submitting_node(4);
    // Activation height 0: the gate is proven separately, here we are proving the path works.
    let observer = SettlementObserver::new(Arc::clone(&db), Arc::clone(&rpc), 0, 0);

    let (unpaid_before, _) = db.get_miner_unpaid_stats(MINER).expect("stats");
    assert_eq!(unpaid_before, 4, "fixture should start owing work");

    // --- settle, from the chain, over real RPC ---
    match observer
        .on_block_connected(&block_hash, tagged_height)
        .await
    {
        SettleOutcome::Settled(applied) => {
            println!("settled: {} shares marked", applied.shares_marked);
            assert_eq!(applied.shares_marked, 4);
        }
        other => panic!("a real tagged block failed to settle: {other:?}"),
    }
    assert_eq!(
        db.get_miner_unpaid_stats(MINER).expect("stats").0,
        0,
        "work paid by the block must no longer be owed"
    );

    // --- idempotence: the submitter also settles, and the forward scan may reach it again ---
    assert_eq!(
        observer
            .on_block_connected(&block_hash, tagged_height)
            .await,
        SettleOutcome::AlreadySettled,
        "settling twice must apply once"
    );

    // --- a real reorg ---
    println!("invalidating {block_hash} to force a reorg");
    cli(&["invalidateblock", &block_hash]);

    let reversed = observer
        .reconcile()
        .await
        .expect("reconcile must run against a live node");
    println!("reconcile reversed {reversed} settlement(s)");
    assert_eq!(reversed, 1, "the orphaned block's settlement must reverse");
    assert_eq!(
        db.get_miner_unpaid_stats(MINER).expect("stats").0,
        4,
        "reversal must put the work back — it is owed again"
    );

    // --- and back: reconsider the block, and it settles again through the same row ---
    cli(&["reconsiderblock", &block_hash]);
    match observer
        .on_block_connected(&block_hash, tagged_height)
        .await
    {
        SettleOutcome::Settled(_) => {}
        other => panic!("a returning block must settle again, got {other:?}"),
    }
    assert_eq!(
        db.get_miner_unpaid_stats(MINER).expect("stats").0,
        0,
        "a returning block must re-settle"
    );
    println!("rehearsal complete: settle -> reorg -> reverse -> return -> settle");
}
