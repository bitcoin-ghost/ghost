//! Shard maturity-settlement rehearsal against a **real** Ghost Core in regtest.
//!
//! `ShardRuntime::settle_matured` has six unit tests — idempotence, maturity depth, discharge
//! arithmetic, corrupt-cursor halting, per-call bounds. Every one of them hands the code bytes we
//! produced ourselves, which proves the decision logic and nothing about the parts that exist only
//! against a live node: the RPC calls, the byte order of a block hash, whether a coinbase mined
//! into a real chain still parses, whether the maturity lookback lands on real heights.
//!
//! That distinction is not theoretical here. `regtest_settlement_rehearsal.rs` exists because the
//! LEGACY settlement path shipped with exactly that gap and `getblock` then answered "Block not
//! found" for every block on the canary — `BlockEvent` hashes are internal order. The shard's
//! settlement walk makes the same class of call and has never been driven against a real chain.
//!
//! ⚠ **This is a TEST, not the full rehearsal, and the difference matters.** It cannot mine a
//! pool-tagged block, because `template.rs` refuses block submission without a verified coinbase
//! commitment and the only source of one is a BFT-ratified proposal (a single regtest node has no
//! quorum; the 4-node cluster in `docker/regtest-cluster` gets as far as creating the proposal but
//! its PUB/SUB liveness stops it reaching quorum). So it settles a block that already exists on the
//! chain, supplied by height.
//!
//! What that DOES cover, and nothing else does today:
//!   * the real `get_block_hash` / `get_block` RPC round trip
//!   * block-hash byte order end to end
//!   * a real coinbase parsing through `settle_block_from_coinbase`
//!   * the maturity lookback arithmetic against a real tip
//!   * the settled-blocks idempotence record surviving a real second pass
//!
//! What it does NOT cover: that a block the POOL mined pays what the shard says it should. That
//! needs quorum, and is the cluster's job.
//!
//! Ignored by default — it needs a regtest node:
//!
//! ```text
//! ghostd -regtest -datadir=<dir> -rpcport=18999 -rpcuser=rt -rpcpassword=rt
//! GHOST_REGTEST_RPC=127.0.0.1:18999 \
//! GHOST_REGTEST_TAGGED_HEIGHT=<height of a pool-tagged block> \
//!   cargo test -p ghost-pool --test regtest_shard_settlement -- --ignored --nocapture
//! ```

use std::sync::Arc;

use ghost_common::identity::NodeIdentity;
use ghost_common::rpc::BitcoinRpc;
use ghost_pool::shard::ShardRuntime;
use ghost_storage::Database;

fn rpc() -> Option<Arc<BitcoinRpc>> {
    let hostport = std::env::var("GHOST_REGTEST_RPC").ok()?;
    let (host, port) = hostport.split_once(':')?;
    Some(Arc::new(
        BitcoinRpc::new(host, port.parse().ok()?, "rt", "rt").expect("rpc"),
    ))
}

/// A shard runtime over a fresh in-memory database.
///
/// `owns_evidence` is FALSE, and deliberately still so after migration v56 flipped production to
/// TRUE: settlement must not DEPEND on the shard owning the shares table. Keeping it false here
/// means a settlement that only works once retention is deleting rows fails this rehearsal
/// instead of passing it by coincidence.
fn runtime() -> (Arc<Database>, ShardRuntime) {
    let db = Arc::new(Database::in_memory().expect("db"));
    db.set_encryption_key([0x42u8; 32]);
    let identity = Arc::new(NodeIdentity::generate());
    let rt = ShardRuntime::load(identity, Arc::clone(&db), false, false).expect("load");
    (db, rt)
}

/// **The rehearsal.** A block that exists on a real chain, read over real RPC, settled by the
/// shard's maturity walk — then settled again to prove the idempotence record is real rather than
/// an artefact of the in-memory fixtures.
#[tokio::test]
#[ignore = "needs a regtest node; see the module header"]
async fn the_shard_settles_a_real_block_read_over_real_rpc() {
    let Some(rpc) = rpc() else {
        panic!("set GHOST_REGTEST_RPC=host:port");
    };
    let tagged_height: u64 = std::env::var("GHOST_REGTEST_TAGGED_HEIGHT")
        .expect("set GHOST_REGTEST_TAGGED_HEIGHT to a pool-tagged block's height")
        .parse()
        .expect("height must be a number");

    // Confirm the block is actually reachable BEFORE settling, so a failure below is the shard's
    // and not the rig's. This is the exact call that answered "Block not found" on the canary.
    let block_hash = rpc
        .get_block_hash(tagged_height)
        .await
        .expect("the tagged block must exist — is GHOST_REGTEST_TAGGED_HEIGHT right?");
    println!("  rehearsal block {tagged_height} = {block_hash}");

    let tip = rpc.get_block_count().await.expect("tip");
    println!(
        "  tip = {tip}, maturity depth = 100, so the walk covers up to {}",
        tip.saturating_sub(100)
    );
    assert!(
        tip >= tagged_height + 100,
        "the tagged block must be at least 100 deep or the walk will correctly skip it — \
         generate more blocks first (tip {tip}, tagged {tagged_height})"
    );

    let (db, rt) = runtime();

    // First pass: the block should be examined and recorded.
    let first = rt.settle_matured(&rpc, tip).await.expect("settle");
    println!("  first pass:  {first:?}");

    let recorded: i64 = db
        .with_connection(|c| {
            c.query_row("SELECT COUNT(*) FROM shard_settled_blocks", [], |r| {
                r.get(0)
            })
            .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))
        })
        .expect("count");
    assert!(
        recorded > 0,
        "the walk covered a real chain and recorded NOTHING — either no block in the window \
         carried our payout tag, or the coinbase did not parse. Both are findings, not noise."
    );

    // Second pass: idempotence, against a real chain rather than a fixture.
    let second = rt.settle_matured(&rpc, tip).await.expect("re-settle");
    println!("  second pass: {second:?}");

    let recorded_again: i64 = db
        .with_connection(|c| {
            c.query_row("SELECT COUNT(*) FROM shard_settled_blocks", [], |r| {
                r.get(0)
            })
            .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))
        })
        .expect("count");
    assert_eq!(
        recorded, recorded_again,
        "a re-run must settle nothing twice — the settled-blocks record is the only thing \
         standing between a restart and a second discharge"
    );
}

/// A block below maturity depth must NOT settle, checked against a real tip rather than a
/// hand-set number.
///
/// The maturity rule is what removes reorg reversal from this path entirely: nothing is settled
/// while it could still be undone, so there is no reversal machinery to get wrong. That argument
/// only holds if the depth check actually uses the real chain height.
#[tokio::test]
#[ignore = "needs a regtest node; see the module header"]
async fn a_block_shallower_than_maturity_is_not_settled_against_a_real_tip() {
    let Some(rpc) = rpc() else {
        panic!("set GHOST_REGTEST_RPC=host:port");
    };
    let tip = rpc.get_block_count().await.expect("tip");
    let (db, rt) = runtime();

    // Claim a tip only 10 blocks above the real one's recent history: everything within 100 of it
    // is immature, so the walk must record nothing at all.
    let shallow_tip = tip.min(50);
    let report = rt.settle_matured(&rpc, shallow_tip).await.expect("settle");
    println!("  shallow tip {shallow_tip}: {report:?}");

    let recorded: i64 = db
        .with_connection(|c| {
            c.query_row("SELECT COUNT(*) FROM shard_settled_blocks", [], |r| {
                r.get(0)
            })
            .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))
        })
        .expect("count");
    assert_eq!(
        recorded, 0,
        "nothing within maturity depth may settle — the no-reversal argument depends on it"
    );
}
