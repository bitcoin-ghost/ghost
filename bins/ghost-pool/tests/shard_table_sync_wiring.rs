//! The §12.6 whole-table sync, driven through `ShardMeshHandler` — the WIRING, not the library.
//!
//! ## Why this test exists in `bins/ghost-pool` and not in `ghost-consensus`
//!
//! `ShardTableSync` was fully implemented and unit-tested in `ghost-consensus` for weeks while
//! having ZERO references anywhere in `bins/ghost-pool`. Nothing sent it, nothing served it, and
//! `ShardMeshHandler::handle_message` early-returned on any type that was not `ShardEpochSummary`,
//! so a response arriving on the wire was dropped without a log line. Every library test passed
//! throughout.
//!
//! That is the regression this file pins, and it can only be pinned here: a test that calls
//! `apply_table_sync_response` directly passes just as happily with the handler deleted. These
//! tests go through `MessageHandler::handle_message` with a real envelope, so removing the
//! dispatch arm, the admission check or the merge makes them fail.
//!
//! It is the third instance of the same shape found in one session — after the shard mesh handler
//! that nothing registered, and `with_private_peers_allowed` that nothing called. Pure core plus
//! green tests is not the job.

use std::sync::Arc;

use ghost_common::identity::NodeIdentity;
use ghost_common::share_shard::{EpochSummary, ShardTable};
use ghost_consensus::mesh::MessageHandler;
use ghost_consensus::message::{MessageEnvelope, ShardTableSyncMessage};
use ghost_consensus::MessageType;
use ghost_pool::shard::ShardRuntime;
use ghost_pool::shard_mesh::ShardMeshHandler;
use ghost_reconciliation::batch::compute_merkle_root;
use ghost_storage::queries::PayoutLedgerCheckpointRecord;
use ghost_storage::Database;

/// A runtime backed by an in-memory DB, with `ratified` admitted to the node set.
///
/// `peer_is_admissible` fails CLOSED when there is no checkpoint, so without this the handler
/// would refuse every message and the test would pass for the wrong reason.
fn runtime_with(ratified: &[[u8; 32]]) -> (Arc<ShardRuntime>, Arc<NodeIdentity>, Arc<Database>) {
    let db = Arc::new(Database::in_memory().expect("db"));
    db.upsert_payout_ledger_checkpoint(&PayoutLedgerCheckpointRecord {
        height: 1,
        cutoff_ts: 0,
        ledger_root: [0u8; 32],
        proposer_id: "00".into(),
        active_node_count: ratified.len() as u32,
        miner_payouts: vec![],
        node_shares: ratified.iter().map(|n| (*n, 5)).collect(),
    })
    .expect("checkpoint");

    let identity = Arc::new(NodeIdentity::generate());
    let rt = Arc::new(
        ShardRuntime::load(Arc::clone(&identity), Arc::clone(&db), false, false).expect("runtime"),
    );
    (rt, identity, db)
}

/// A signed response carrying `worker`'s column, exactly as a peer would serve it.
fn response_from(
    server: &NodeIdentity,
    worker: &NodeIdentity,
    addr: &str,
) -> ShardTableSyncMessage {
    let share = ghost_common::types::ShareProof {
        round_id: 1,
        miner_id: [7u8; 32],
        difficulty: 4.0,
        work: 4.0,
        share_hash: [7u8; 32],
        timestamp: 10,
        received_by: [0u8; 32],
        template_id: None,
        payout_address: Some(addr.to_string()),
        header: None,
        tier_log2: None,
        signature: None,
    };
    let summary = EpochSummary::build(
        1,
        worker,
        &Default::default(),
        std::slice::from_ref(&share),
        compute_merkle_root,
        None,
    )
    .expect("legal evidence");

    let mut table = ShardTable::new();
    table
        .apply_summary(&summary, std::slice::from_ref(&share), compute_merkle_root)
        .expect("verifies");
    ghost_consensus::shard_handler::build_table_sync_response(server, &table)
}

fn envelope(sender: [u8; 32], msg: &ShardTableSyncMessage) -> Arc<MessageEnvelope> {
    let mut env = MessageEnvelope::new(
        MessageType::ShardTableSync,
        sender,
        serde_json::to_vec(msg).expect("serialise"),
        1,
        [0u8; 64],
    );
    // The mesh has already verified the signature by the time a handler sees the envelope; these
    // tests exercise what the handler does with an authenticated message.
    env.sender = sender;
    Arc::new(env)
}

/// The regression: a response arriving on the wire must reach the table.
///
/// Fails if the dispatch arm is removed, if `apply_table_sync` stops merging, or if the response
/// is dropped as an unknown type — which is exactly what the code did before this was wired.
#[tokio::test]
async fn a_table_sync_response_delivered_to_the_handler_reaches_the_table() {
    let server = NodeIdentity::generate();
    let worker = NodeIdentity::generate();
    let (rt, _id, _db) = runtime_with(&[server.node_id(), worker.node_id()]);

    assert!(
        rt.owed().is_empty(),
        "precondition: the runtime starts with nothing"
    );

    let resp = response_from(&server, &worker, "bc1qalice");
    let handler = ShardMeshHandler::new(Arc::clone(&rt));
    handler
        .handle_message(envelope(server.node_id(), &resp))
        .await
        .expect("handled");

    let owed = rt.owed();
    assert_eq!(
        owed.get("bc1qalice").copied(),
        Some(4_000_000),
        "the merged column must be visible in owed(): this is the whole point of wiring it"
    );
}

/// A responder outside the ratified set is refused, and the table is untouched.
#[tokio::test]
async fn a_table_sync_from_an_unratified_node_is_not_merged() {
    let stranger = NodeIdentity::generate();
    let worker = NodeIdentity::generate();
    // Deliberately ratify someone ELSE, so the checkpoint is non-empty and admission is a real
    // decision rather than the fail-closed default.
    let (rt, _id, _db) = runtime_with(&[NodeIdentity::generate().node_id()]);

    let resp = response_from(&stranger, &worker, "bc1qalice");
    let handler = ShardMeshHandler::new(Arc::clone(&rt));
    handler
        .handle_message(envelope(stranger.node_id(), &resp))
        .await
        .expect("handled");

    assert!(
        rt.owed().is_empty(),
        "a stranger's whole table must not enter the counters — a max cannot be undone"
    );
}

/// A peer must not be able to move THIS node's own column.
///
/// `merge_accrued` maxes every column in the payload, so without the explicit filter a served
/// table containing our own node id would raise our counter permanently — and the next fold would
/// sign the inflated total and gossip it as our own statement.
#[tokio::test]
async fn a_peer_cannot_raise_this_nodes_own_column() {
    let server = NodeIdentity::generate();
    let db = Arc::new(Database::in_memory().expect("db"));
    let identity = Arc::new(NodeIdentity::generate());
    db.upsert_payout_ledger_checkpoint(&PayoutLedgerCheckpointRecord {
        height: 1,
        cutoff_ts: 0,
        ledger_root: [0u8; 32],
        proposer_id: "00".into(),
        active_node_count: 2,
        node_shares: vec![(server.node_id(), 5), (identity.node_id(), 5)],
        miner_payouts: vec![],
    })
    .expect("checkpoint");
    let rt = Arc::new(
        ShardRuntime::load(Arc::clone(&identity), Arc::clone(&db), false, false).expect("runtime"),
    );

    // The server serves a table whose column for OUR node id is populated.
    let resp = response_from(&server, &identity, "bc1qattacker");

    let handler = ShardMeshHandler::new(Arc::clone(&rt));
    handler
        .handle_message(envelope(server.node_id(), &resp))
        .await
        .expect("handled");

    assert!(
        rt.owed().get("bc1qattacker").is_none(),
        "a peer's claim about OUR column must be refused: we are authoritative for it, and a fold \
         would otherwise sign and gossip the inflation as our own"
    );
}

/// A request from a node that is not who it claims to be is not served.
///
/// `Request` is unsigned, so `requesting_node` is an assertion by whoever sent the bytes; only
/// `envelope.sender` is authenticated. Serving on the payload field would hand the whole
/// payout-address table to anyone who names a ratified id.
#[tokio::test]
async fn a_request_claiming_someone_elses_id_is_not_served() {
    let ratified = NodeIdentity::generate();
    let impostor = NodeIdentity::generate();
    let (rt, _id, _db) = runtime_with(&[ratified.node_id()]);

    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let handler = ShardMeshHandler::new(Arc::clone(&rt)).with_sync_responder(tx);

    // Sent BY the impostor, claiming to be the ratified node.
    let req = ShardTableSyncMessage::Request {
        requesting_node: ratified.node_id(),
        table_root: [0u8; 32],
    };
    handler
        .handle_message(envelope(impostor.node_id(), &req))
        .await
        .expect("handled");

    assert!(
        rx.try_recv().is_err(),
        "no response may be queued for a sender whose claimed id is not its authenticated one"
    );
}
