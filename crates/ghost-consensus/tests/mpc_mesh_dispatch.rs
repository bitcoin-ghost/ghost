//! Mesh-INCLUSIVE reproduction for MPC "Bug 3": a broadcast `MpcContribution`
//! must reach every eligible voter's registered handler.
//!
//! Unlike the in-process `ghost-mpc/tests/mpc_lifecycle.rs` (no mesh) and the
//! `mpc-xproc-harness` (drives the params fetch DIRECTLY, no broadcast/dispatch),
//! this test drives the REAL [`MeshNetwork`] transport: two mesh nodes on
//! localhost connected over the actual ZMQ + Noise ports. The "contributor"
//! calls `broadcast_message(MessageType::MpcContribution, ..)` and we assert the
//! "voter" node's registered [`MessageHandler`] actually receives and dispatches
//! it. This exercises the broadcast -> receive -> dispatch -> handler path that
//! was previously untested.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ghost_common::config::P2PPortConfig;
use ghost_common::error::GhostResult;
use ghost_common::identity::NodeIdentity;
use ghost_consensus::mesh::{MeshConfig, MeshNetwork, MessageHandler};
use ghost_consensus::message::{MessageEnvelope, MessageType, MpcContributionMessage};
use tokio::sync::Notify;

#[cfg(feature = "mpc-ceremony")]
use ghost_consensus::mpc_handler::MpcHandler;
#[cfg(feature = "mpc-ceremony")]
use ghost_storage::Database;

/// A minimal handler that records every `MpcContribution` envelope it is
/// dispatched. Stands in for the real `MpcHandler` at the transport boundary —
/// if this fires, the broadcast reached a registered handler on the voter.
struct RecordingHandler {
    mpc_received: Arc<AtomicUsize>,
    notify: Arc<Notify>,
}

#[async_trait]
impl MessageHandler for RecordingHandler {
    async fn handle_message(&self, envelope: Arc<MessageEnvelope>) -> GhostResult<()> {
        if envelope.msg_type == MessageType::MpcContribution {
            self.mpc_received.fetch_add(1, Ordering::SeqCst);
            self.notify.notify_waiters();
        }
        Ok(())
    }
}

/// Distinct ZMQ port block per node (so both can bind their PUB/SUB sockets on
/// localhost). Both nodes share a single `noise_port` because the SENDER dials
/// `peer_host:<its own config.noise_port>` (in prod every node uses the shared
/// DEFAULT_NOISE_PORT). Only the voter actually binds a Noise listener here.
fn mesh_config(zmq_base: u16, noise_port: u16) -> MeshConfig {
    MeshConfig {
        public_address: "127.0.0.1".to_string(),
        ports: P2PPortConfig {
            share_propagation: zmq_base,
            block_announcement: zmq_base + 1,
            consensus_voting: zmq_base + 2,
            health_monitoring: zmq_base + 3,
            discovery: zmq_base + 4,
            elder_management: zmq_base + 5,
            payout_proposal: zmq_base + 6,
            payout_transaction: zmq_base + 7,
        },
        noise_enabled: true,
        noise_port,
        // Keep the focus on dispatch, not Noise policy: ephemeral keys, no
        // hard requirement (broadcast still routes MpcContribution over Noise
        // because the noise pool is present).
        noise_required: true,
        ..MeshConfig::default()
    }
}

/// Spawn the REAL mesh-owned Noise receive listener (`MeshNetwork::run_noise_listener`,
/// the same code path production runs) on `mesh`. `is_mainnet=false` so the
/// loopback reverse-subscribe SSRF guard doesn't skip 127.0.0.1. The shutdown
/// sender is kept alive inside the task so the listener runs for the whole test.
fn spawn_noise_listener(mesh: Arc<MeshNetwork>, _noise_port: u16) {
    let (tx, rx) = tokio::sync::broadcast::channel::<()>(1);
    tokio::spawn(async move {
        let _keep_shutdown_open = tx; // dropping tx would trigger shutdown
        mesh.run_noise_listener(false, rx).await;
    });
}

fn sample_contribution() -> MpcContributionMessage {
    MpcContributionMessage {
        candidate: [0x55; 32],
        elder_position: 5,
        prev_params_hash: [0x11; 32],
        new_params_hash: [0x22; 32],
        contribution_proof: vec![0xAB; 128],
        signature: [0u8; 64],
        timestamp: chrono::Utc::now().timestamp_millis() as u64,
    }
}

/// Bug 3 reproduction: contributor broadcasts an `MpcContribution`; the voter's
/// registered handler must receive it. Pre-fix this FAILS (silent drop).
#[tokio::test]
async fn mpc_contribution_broadcast_reaches_voter_handler() {
    let noise_port = 19199u16;

    let voter_id = Arc::new(NodeIdentity::generate());
    let voter = Arc::new(
        MeshNetwork::try_new(Arc::clone(&voter_id), mesh_config(19100, noise_port))
            .expect("voter mesh init"),
    );

    let mpc_received = Arc::new(AtomicUsize::new(0));
    let notify = Arc::new(Notify::new());
    voter.register_handler(Arc::new(RecordingHandler {
        mpc_received: Arc::clone(&mpc_received),
        notify: Arc::clone(&notify),
    }));

    let contributor_id = Arc::new(NodeIdentity::generate());
    let contributor = Arc::new(
        MeshNetwork::try_new(Arc::clone(&contributor_id), mesh_config(19110, noise_port))
            .expect("contributor mesh init"),
    );

    voter.start().await.expect("voter mesh start");
    contributor.start().await.expect("contributor mesh start");

    // Voter serves inbound Noise (the prod receive plane).
    spawn_noise_listener(Arc::clone(&voter), noise_port);

    // Give the listener a moment to bind.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Contributor registers the voter as a connected peer, then broadcasts.
    contributor
        .connect_peer("127.0.0.1")
        .await
        .expect("connect_peer");

    let sent = contributor
        .broadcast_message(MessageType::MpcContribution, &sample_contribution())
        .await
        .expect("broadcast MpcContribution");
    assert!(sent >= 1, "contributor should have sent to the voter peer");

    // Wait up to 5s for the voter handler to receive the contribution.
    let waited = tokio::time::timeout(Duration::from_secs(5), notify.notified()).await;

    assert!(
        waited.is_ok() && mpc_received.load(Ordering::SeqCst) >= 1,
        "Bug 3: voter's registered handler never received the broadcast MpcContribution \
         (received={})",
        mpc_received.load(Ordering::SeqCst)
    );
}

/// Build a genesis (position 1) contribution signed by `signer`. The genesis
/// auto-approve path needs a valid candidate signature and position == 1; the
/// hashes only have to be non-zero/distinct.
#[cfg(feature = "mpc-ceremony")]
fn signed_genesis_contribution(signer: &NodeIdentity) -> MpcContributionMessage {
    let mut msg = MpcContributionMessage {
        candidate: signer.node_id(),
        elder_position: 1,
        prev_params_hash: [0x11; 32],
        new_params_hash: [0x22; 32],
        contribution_proof: vec![0xAB; 128],
        signature: [0u8; 64],
        timestamp: chrono::Utc::now().timestamp_millis() as u64,
    };
    let sm = msg.signing_message();
    msg.signature = signer.sign(&sm);
    msg
}

/// Bug 3 reproduction with the REAL `MpcHandler`: a broadcast genesis
/// `MpcContribution` must drive the voter's handler all the way through
/// `handle_message -> handle_contribution -> apply_contribution`, recording the
/// contribution in the voter's DB. This is the broadcast -> receive -> dispatch
/// -> handler -> ACT path that both prior harnesses skipped (mpc_lifecycle is
/// in-process, mpc-xproc drove the fetch directly).
#[cfg(feature = "mpc-ceremony")]
#[tokio::test]
async fn mpc_genesis_contribution_broadcast_is_processed_by_real_handler() {
    let noise_port = 19299u16;

    // Voter with a real MpcHandler over an in-memory DB (fresh ceremony: 0
    // contributors, so a position-1 contribution is genesis auto-approved).
    let voter_id = Arc::new(NodeIdentity::generate());
    let voter = Arc::new(
        MeshNetwork::try_new(Arc::clone(&voter_id), mesh_config(19200, noise_port))
            .expect("voter mesh init"),
    );

    let db = Arc::new(Database::in_memory().expect("in-memory db"));
    let handler = Arc::new(MpcHandler::new(Arc::clone(&voter_id), Arc::clone(&db)));
    handler.init_self_ref();
    voter.register_handler(Arc::clone(&handler) as Arc<dyn MessageHandler>);

    let contributor_id = Arc::new(NodeIdentity::generate());
    let contributor = Arc::new(
        MeshNetwork::try_new(Arc::clone(&contributor_id), mesh_config(19210, noise_port))
            .expect("contributor mesh init"),
    );

    voter.start().await.expect("voter mesh start");
    contributor.start().await.expect("contributor mesh start");
    spawn_noise_listener(Arc::clone(&voter), noise_port);
    tokio::time::sleep(Duration::from_millis(200)).await;

    contributor
        .connect_peer("127.0.0.1")
        .await
        .expect("connect_peer");

    let sent = contributor
        .broadcast_message(
            MessageType::MpcContribution,
            &signed_genesis_contribution(&contributor_id),
        )
        .await
        .expect("broadcast MpcContribution");
    assert!(sent >= 1, "contributor should have sent to the voter peer");

    // Poll up to 5s for the voter to record the applied genesis contribution.
    let mut recorded = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if db.get_mpc_contribution(1).ok().flatten().is_some() {
            recorded = true;
            break;
        }
    }

    assert!(
        recorded,
        "Bug 3: the broadcast MpcContribution never drove the real handler to \
         record/apply the contribution (position 1 not in DB)"
    );
}

/// Bug 3 reproduction, position >= 2 (the LIVE rolling-ceremony path the node5
/// mainnet attempt exercised): an elder voter receives a broadcast
/// `MpcContribution` and must drive it through `handle_message ->
/// handle_contribution -> verify_and_vote` (fetch + real crypto verify) and
/// record its approve vote. This is the exact broadcast -> dispatch -> vote seam
/// that the in-process crypto test (calls `verify_and_vote` directly) and the
/// xproc harness (drives the fetch directly) both bypass.
#[cfg(feature = "mpc-ceremony")]
#[tokio::test]
async fn mpc_position2_contribution_broadcast_drives_voter_vote() {
    use ghost_consensus::mpc_handler::{FetchedCeremonyParams, MpcParamsFetchFn};
    use ghost_mpc::CeremonyManager;
    use ghost_storage::queries::MpcContributionRecord;

    let noise_port = 19399u16;
    let tmp = tempfile::tempdir().unwrap();

    // ---- Voter ceremony state: genesis + an applied position-1 so the voter is
    // an elder (is_mpc_contributor) and the lineage head is position 1. --------
    let manager = Arc::new(CeremonyManager::new(tmp.path().to_path_buf()));
    manager.ensure_genesis_initialized().expect("genesis init");

    let voter_id = Arc::new(NodeIdentity::generate());
    let db = Arc::new(Database::in_memory().expect("in-memory db"));

    // Position 1, contributed by the VOTER itself → applies to the manager
    // (count 0 -> 1) and is recorded in the DB with contributor == voter, which
    // is what `is_mpc_elder(voter)` checks.
    let (p1_params, contrib1) = manager
        .generate_contribution(&hex::encode(voter_id.node_id()))
        .expect("generate position 1");
    manager
        .apply_contribution(p1_params, &contrib1)
        .expect("apply position 1");
    db.save_mpc_contribution(&MpcContributionRecord {
        elder_position: 1,
        contributor_node_id: hex::encode(voter_id.node_id()),
        prev_params_hash: contrib1.prev_params_hash,
        new_params_hash: contrib1.new_params_hash,
        contribution_proof: serde_json::to_vec(&contrib1.proof).unwrap(),
        epoch: 0,
        created_at: contrib1.timestamp,
    })
    .expect("save position 1 row");

    // ---- Position 2 candidate generated from the (count==1) manager ----------
    let (p2_params, contrib2) = manager
        .generate_contribution("contributor-2")
        .expect("generate position 2");
    let p2_params = Arc::new(p2_params);
    let claimed_hash = contrib2.new_params_hash;

    // The fetcher the voter uses to obtain the candidate params for verification.
    let fetch_params = Arc::clone(&p2_params);
    let fetcher: MpcParamsFetchFn = Arc::new(move |_expected: [u8; 32]| {
        let p = Arc::clone(&fetch_params);
        Box::pin(async move {
            Some(FetchedCeremonyParams {
                note_spend: p,
                payout: None,
                unshield: None,
            })
        })
    });

    let handler = Arc::new(
        MpcHandler::new(Arc::clone(&voter_id), Arc::clone(&db))
            .with_ceremony_manager(Arc::clone(&manager))
            .with_params_fetcher(fetcher),
    );
    handler.init_self_ref();

    let voter = Arc::new(
        MeshNetwork::try_new(Arc::clone(&voter_id), mesh_config(19300, noise_port))
            .expect("voter mesh init"),
    );
    voter.register_handler(Arc::clone(&handler) as Arc<dyn MessageHandler>);

    // ---- Contributor node broadcasts the position-2 contribution -------------
    let contributor_id = Arc::new(NodeIdentity::generate());
    let mut msg = MpcContributionMessage {
        candidate: contributor_id.node_id(),
        elder_position: 2,
        prev_params_hash: contrib2.prev_params_hash,
        new_params_hash: claimed_hash,
        contribution_proof: serde_json::to_vec(&contrib2.proof).unwrap(),
        signature: [0u8; 64],
        timestamp: contrib2.timestamp,
    };
    let sm = msg.signing_message();
    msg.signature = contributor_id.sign(&sm);

    let contributor = Arc::new(
        MeshNetwork::try_new(Arc::clone(&contributor_id), mesh_config(19310, noise_port))
            .expect("contributor mesh init"),
    );

    voter.start().await.expect("voter mesh start");
    contributor.start().await.expect("contributor mesh start");
    spawn_noise_listener(Arc::clone(&voter), noise_port);
    tokio::time::sleep(Duration::from_millis(200)).await;

    contributor
        .connect_peer("127.0.0.1")
        .await
        .expect("connect_peer");

    let sent = contributor
        .broadcast_message(MessageType::MpcContribution, &msg)
        .await
        .expect("broadcast MpcContribution");
    assert!(sent >= 1, "contributor should have sent to the voter peer");

    // Poll up to 20s for the voter to cast (and record) its approve vote for
    // position 2 — proof that the broadcast drove verify_and_vote over the mesh.
    let mut approvals = 0u32;
    for _ in 0..1200 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Ok((a, _r)) = db.count_mpc_approvals(2) {
            if a >= 1 {
                approvals = a;
                break;
            }
        }
    }

    assert!(
        approvals >= 1,
        "Bug 3: the broadcast position-2 MpcContribution never drove the voter to \
         verify_and_vote (no approve vote recorded for position 2)"
    );
}

/// Bug 3 reproduction, MULTI-VOTER quorum (the real fleet path): with a
/// contributor count of 4 the BFT threshold is 3, so a contribution only
/// applies once THREE elders' votes aggregate on a node. This exercises the
/// broadcast -> dispatch -> `handle_verification_vote` -> quorum -> apply path
/// across nodes — the exact "no apply, ceremony can't advance" symptom, which
/// every threshold-1 test (self-vote applies alone) structurally cannot show.
#[cfg(feature = "mpc-ceremony")]
#[tokio::test]
async fn mpc_crossnode_votes_aggregate_to_quorum_and_apply() {
    use ghost_storage::queries::MpcContributionRecord;

    let noise_port = 19499u16;

    // Four elders (positions 1..4); `voter` is one of them. count == 4 → the
    // shared BFT threshold is 3.
    let voter_id = Arc::new(NodeIdentity::generate());
    let e2 = NodeIdentity::generate();
    let e3 = NodeIdentity::generate();
    let e4 = NodeIdentity::generate();
    let elders = [
        (1u32, voter_id.node_id(), [0x01u8; 32], [0x11u8; 32]),
        (2u32, e2.node_id(), [0x11u8; 32], [0x22u8; 32]),
        (3u32, e3.node_id(), [0x22u8; 32], [0x33u8; 32]),
        (4u32, e4.node_id(), [0x33u8; 32], [0x44u8; 32]),
    ];

    let db = Arc::new(Database::in_memory().expect("in-memory db"));
    for (pos, id, prev, new) in elders {
        db.save_mpc_contribution(&MpcContributionRecord {
            elder_position: pos,
            contributor_node_id: hex::encode(id),
            prev_params_hash: prev,
            new_params_hash: new,
            contribution_proof: vec![0xAB; 32],
            epoch: 0,
            created_at: 0,
        })
        .expect("save elder row");
    }
    assert_eq!(
        db.get_mpc_elder_count().unwrap(),
        4,
        "count==4 → threshold 3"
    );

    // Real handler WITHOUT a ceremony manager: the voter abstains on its own
    // crypto verify (no self-vote), so the apply is driven PURELY by the three
    // aggregated cross-node votes — isolating the quorum path.
    let handler = Arc::new(MpcHandler::new(Arc::clone(&voter_id), Arc::clone(&db)));
    handler.init_self_ref();

    let voter = Arc::new(
        MeshNetwork::try_new(Arc::clone(&voter_id), mesh_config(19400, noise_port))
            .expect("voter mesh init"),
    );
    voter.register_handler(Arc::clone(&handler) as Arc<dyn MessageHandler>);

    // Position-5 contribution (prev chains from position 4's new hash).
    let contributor_id = Arc::new(NodeIdentity::generate());
    let mut contribution = MpcContributionMessage {
        candidate: contributor_id.node_id(),
        elder_position: 5,
        prev_params_hash: [0x44u8; 32],
        new_params_hash: [0x55u8; 32],
        contribution_proof: vec![0xCD; 128],
        signature: [0u8; 64],
        timestamp: chrono::Utc::now().timestamp_millis() as u64,
    };
    let sm = contribution.signing_message();
    contribution.signature = contributor_id.sign(&sm);
    let contribution_hash = contribution.contribution_hash();

    let contributor = Arc::new(
        MeshNetwork::try_new(Arc::clone(&contributor_id), mesh_config(19410, noise_port))
            .expect("contributor mesh init"),
    );

    voter.start().await.expect("voter mesh start");
    contributor.start().await.expect("contributor mesh start");
    spawn_noise_listener(Arc::clone(&voter), noise_port);
    tokio::time::sleep(Duration::from_millis(200)).await;
    contributor
        .connect_peer("127.0.0.1")
        .await
        .expect("connect_peer");

    // 1) Deliver the contribution so the voter holds it pending (it abstains).
    contributor
        .broadcast_message(MessageType::MpcContribution, &contribution)
        .await
        .expect("broadcast contribution");
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 2) Three elders broadcast approve votes; they must aggregate to quorum (3)
    //    on the voter and drive the apply.
    for elder in [&e2, &e3, &e4] {
        let mut vote = ghost_consensus::message::MpcVerificationVoteMessage {
            contribution_hash,
            voter: elder.node_id(),
            approve: true,
            rejection_reason: None,
            signature: [0u8; 64],
            timestamp: chrono::Utc::now().timestamp_millis() as u64,
        };
        vote.signature = elder.sign(&vote.signing_message());
        // Relay pre-serialized (matches the production vote relay which uses
        // create_envelope_raw over the serialized vote payload).
        let payload = serde_json::to_vec(&vote).unwrap();
        let envelope = contributor
            .create_envelope_raw(MessageType::MpcVerificationVote, payload)
            .expect("envelope");
        contributor
            .broadcast(envelope)
            .await
            .expect("broadcast vote");
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    // The three aggregated votes (threshold 3) must apply the contribution.
    let mut applied = false;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if db.get_mpc_contribution(5).ok().flatten().is_some() {
            applied = true;
            break;
        }
    }

    assert!(
        applied,
        "Bug 3: three cross-node approve votes did not aggregate to quorum and apply \
         position 5 (approvals recorded: {:?})",
        db.count_mpc_approvals(5)
    );
}
