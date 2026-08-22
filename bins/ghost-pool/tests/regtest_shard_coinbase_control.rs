//! Negative control for `regtest_shard_coinbase_e2e`.
//!
//! That test proves a coinbase built from the shard, with no vote, is accepted by a real
//! `ghostd`. Its argument rests on the fixture being UNABLE to arm a coinbase any other way:
//! `PublicPool` mode with no MPC elders seeded means the BFT path cannot reach quorum.
//!
//! This asserts that premise. If the fixture can arm a coinbase below the gate, then the
//! positive test proves nothing about `PAYOUT_FROM_SHARD_HEIGHT` — it would be passing on the
//! fixture's own permissiveness, which is the "check that cannot fail" shape this repo has been
//! bitten by repeatedly.
//!
//! ⚠ **This must be its own binary.** The gate resolves through a `OnceLock`, so the first test
//! to touch it fixes it process-wide. Sharing a binary with the armed test meant the control ran
//! with the gate already on and failed for a reason that had nothing to do with what it checks.
//!
//! ```text
//! GHOST_REGTEST_REQUIRED=1 cargo test -p ghost-pool --test regtest_shard_coinbase_control
//! ```

use std::collections::BTreeMap;
use std::sync::Arc;

use ghost_common::config::{BitcoinNetwork, MiningMode};
use ghost_common::identity::NodeIdentity;
use ghost_common::rpc::BitcoinRpc;
use ghost_common::types::TreasuryAddress;
use ghost_consensus::vote_handler::VoteHandler;
use ghost_consensus::voting::VotingManager;
use ghost_pool::payout::{BlockFoundData, PayoutConfig, PayoutHandler};
use ghost_pool::template::{TemplateConfig, TemplateProcessor};
use ghost_storage::Database;
use ghost_verification::qualification::QualifiedCapabilityProvider;

mod common;

fn addr(seed: u8) -> String {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[seed; 32]).expect("secret key");
    let pk = bitcoin::PublicKey::new(sk.public_key(&secp));
    let cpk = bitcoin::CompressedPublicKey::try_from(pk).expect("compressed");
    bitcoin::Address::p2wpkh(&cpk, bitcoin::Network::Regtest).to_string()
}

fn treasury_script() -> Vec<u8> {
    let a: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
        addr(0xF0).parse().expect("treasury address");
    a.assume_checked().script_pubkey().to_bytes()
}

/// Byte-for-byte the fixture `regtest_shard_coinbase_e2e` uses. If these drift, the control stops
/// controlling anything — it would be asserting a property of a different fixture.
fn build_handler(rpc: Arc<BitcoinRpc>) -> (Arc<PayoutHandler>, Arc<TemplateProcessor>) {
    let identity = Arc::new(NodeIdentity::generate());
    let db = Arc::new(Database::in_memory().expect("in-memory db"));

    let template = Arc::new(TemplateProcessor::new(
        TemplateConfig {
            treasury_address: TreasuryAddress::single(addr(0xF0)),
            pool_payout_address: addr(9),
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
            MiningMode::PublicPool,
        )
        .expect("payout handler"),
    );

    (handler, template)
}

/// Below the gate, the fixture must NOT be able to arm a coinbase.
#[tokio::test]
async fn the_vote_path_cannot_arm_a_coinbase_without_elders() {
    let Some(rpc) = common::require_regtest().await else {
        return;
    };

    // Deliberately NOT arming the gate. The shipped default is 964,100 and regtest is ~500, so
    // `handle_block_found` must take the BFT path — which has no voters here.
    assert!(
        ghost_pool::payout_from_shard_height() > 1_000,
        "the gate is armed in this process; the control cannot control anything"
    );

    let (handler, template) = build_handler(rpc);

    let mut owed = BTreeMap::new();
    owed.insert(addr(1), 600_000i64);

    let _ = handler.handle_block_found(BlockFoundData {
        shard_owed: Some(owed),
        round_id: 1,
        ledger_cutoff_ts: chrono::Utc::now().timestamp() - 60,
        block_hash: [0x11; 32],
        block_height: 500,
        block_timestamp: chrono::Utc::now(),
        winning_miner_id: "pool".to_string(),
        winning_miner_payout_address: Some(addr(1)),
        treasury_address_snapshot: Some(treasury_script()),
        winning_node_id: [9u8; 32],
        subsidy_sats: 5_000_000_000,
        tx_fees_sats: 0,
        miner_work: Vec::new(),
        node_shares: Vec::new(),
        treasury_state: Default::default(),
    });

    assert!(
        template.approved_payout().is_none(),
        "the fixture armed a coinbase BELOW the gate — so `regtest_shard_coinbase_e2e` would \
         pass whether or not PAYOUT_FROM_SHARD_HEIGHT did anything, and proves nothing"
    );
}
