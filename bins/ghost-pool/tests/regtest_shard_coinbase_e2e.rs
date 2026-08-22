//! The last mile for Stage 6 step 3: a real block whose coinbase came from the shard, with no
//! BFT vote anywhere in the path, accepted by a real `ghostd`.
//!
//! # Why this exists
//!
//! `payout_ledger_e2e::mined_block_is_accepted_by_ghostd_and_pays_the_miners` proves the chain
//! accepts a coinbase built from a **mesh-ratified** payout. That file is deleted in Stage 6
//! Release B along with the BFT payout path, and the shard side had no equivalent: its coverage
//! (`regtest_shard_settlement`) is *settlement* — discharging `owed` from a matured coinbase —
//! not coinbase construction and payment.
//!
//! So without this, deleting the legacy path would remove the only end-to-end proof that a mined
//! block pays the miners it should. This is that proof, on the path that replaces it.
//!
//! # What makes the no-vote claim real rather than assumed
//!
//! Two things, deliberately:
//!
//! 1. **The mode is `PublicPool`.** A `PrivatePool` or solo node approves its own proposal
//!    without a vote regardless of any gate (#592, `f3736bc33`), so a test in those modes would
//!    pass whether or not `PAYOUT_FROM_SHARD_HEIGHT` worked at all — it would be a check that
//!    cannot fail.
//! 2. **No MPC elders are seeded.** `handle_proposal` resolves its voter set from
//!    `mpc_contributions`; with none, the BFT path cannot reach quorum and cannot arm a coinbase.
//!
//! Together those mean a coinbase that exists at all is proof the gate bypassed the vote.
//!
//! ⛔ The negative control — that the SAME fixture cannot arm a coinbase BELOW the gate — lives in
//! `regtest_shard_coinbase_control.rs`, in its own test binary, and it is not optional: without
//! it this file would pass even if the gate did nothing.
//!
//! It cannot live here. `PAYOUT_FROM_SHARD_HEIGHT` resolves through a `OnceLock`, so the first
//! test to touch it fixes it for the whole process. Running both in one binary meant the armed
//! test won the race and the control then ran WITH the gate on — it failed for the right reason
//! and told us nothing about the gate. Two tests that disagree about a process-global cannot
//! share a process.
//!
//! # Running it
//!
//! Needs a regtest `ghostd`. Credentials come from the environment with the shipped
//! `docker-compose.yml` defaults; see `common/mod.rs`. `docker start rc-bitcoind` is enough.
//!
//! ```text
//! GHOST_REGTEST_REQUIRED=1 cargo test -p ghost-pool --test regtest_shard_coinbase_e2e
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

/// Regtest heights are ~500; the shipped gate is 964,100. Without an override the no-vote path
/// is unreachable here, so every assertion below would be about the BFT path instead.
///
/// ⚠ `gates::from_env` refuses overrides on Mainnet ("mainnet gates are not negotiable"), so this
/// only works because the network is Regtest. It is also a `OnceLock`, so it must be set before
/// anything reads a gate — and it is per-process, which is why this lives in its own test binary
/// rather than beside the legacy tests.
fn arm_the_no_vote_gate() {
    std::env::set_var("GHOST_PAYOUT_FROM_SHARD_HEIGHT", "0");
    ghost_pool::init_activation_heights(&BitcoinNetwork::Regtest);
    assert_eq!(
        ghost_pool::payout_from_shard_height(),
        0,
        "the gate override did not take — every assertion below would silently be about the \
         BFT path instead"
    );
}

fn addr(seed: u8) -> String {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[seed; 32]).expect("secret key");
    let pk = bitcoin::PublicKey::new(sk.public_key(&secp));
    let cpk = bitcoin::CompressedPublicKey::try_from(pk).expect("compressed");
    bitcoin::Address::p2wpkh(&cpk, bitcoin::Network::Regtest).to_string()
}

fn treasury_addr() -> String {
    addr(0xF0)
}

fn treasury_script() -> Vec<u8> {
    let a: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
        treasury_addr().parse().expect("treasury address");
    a.assume_checked().script_pubkey().to_bytes()
}

/// The shard's `owed()` snapshot: payout address -> micro-work.
///
/// This is the whole input. There is no seeded share ledger, because the shard path does not read
/// one — that asymmetry is the change Stage 6 is making, and the fixture shows it.
fn shard_owed() -> BTreeMap<String, i64> {
    let mut owed = BTreeMap::new();
    owed.insert(addr(1), 600_000i64);
    owed.insert(addr(2), 300_000i64);
    owed.insert(addr(3), 100_000i64);
    owed
}

struct Node {
    handler: Arc<PayoutHandler>,
    template: Arc<TemplateProcessor>,
}

/// A single node in `PublicPool` mode with **no elders seeded** — see the module docs.
fn build_node(rpc: Arc<BitcoinRpc>) -> Node {
    let identity = Arc::new(NodeIdentity::generate());
    let db = Arc::new(Database::in_memory().expect("in-memory db"));

    let template = Arc::new(TemplateProcessor::new(
        TemplateConfig {
            treasury_address: TreasuryAddress::single(treasury_addr()),
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

    Node { handler, template }
}

fn block_found(height: u64, subsidy: u64) -> BlockFoundData {
    BlockFoundData {
        shard_owed: Some(shard_owed()),
        round_id: 1,
        ledger_cutoff_ts: chrono::Utc::now().timestamp() - 60,
        block_hash: [0x11; 32],
        block_height: height,
        block_timestamp: chrono::Utc::now(),
        winning_miner_id: "pool".to_string(),
        winning_miner_payout_address: Some(addr(1)),
        treasury_address_snapshot: Some(treasury_script()),
        winning_node_id: [9u8; 32],
        subsidy_sats: subsidy,
        tx_fees_sats: 0,
        miner_work: Vec::new(),
        node_shares: Vec::new(),
        treasury_state: Default::default(),
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────

/// A block whose coinbase came from the shard, with no vote, accepted by a real `ghostd`.
#[tokio::test]
async fn a_shard_built_coinbase_with_no_vote_is_accepted_and_pays_the_owed_addresses() {
    let Some(rpc) = common::require_regtest().await else {
        return;
    };
    arm_the_no_vote_gate();

    let have = rpc.get_block_count().await.expect("height");
    if have < 101 {
        rpc.call_raw(
            "generatetoaddress",
            vec![serde_json::json!(101 - have), serde_json::json!(addr(9))],
        )
        .await
        .expect("prime the chain");
    }
    rpc.get_block_count().await.expect("height");

    // ⚠ This block is assembled COINBASE-ONLY, so the template's `default_witness_commitment`
    // must have been computed over a coinbase-only transaction set. If the mempool holds
    // anything, the template includes it, the commitment covers those transactions, and ghostd
    // rejects the block with `bad-witness-merkle-match`.
    //
    // The legacy `payout_ledger_e2e` has the same requirement and states it only as a comment
    // ("empty block -> no fees, all subsidy"). It passed for years by luck and failed the moment
    // a single transaction was sitting in the mempool — which nobody noticed, because the whole
    // file had never run. Drain first, then ASSERT the assumption rather than hoping for it.
    let mempool = rpc
        .call_raw("getmempoolinfo", vec![])
        .await
        .expect("getmempoolinfo");
    if mempool["size"].as_u64().unwrap_or(0) > 0 {
        rpc.call_raw(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr(9))],
        )
        .await
        .expect("drain the mempool into a block");
        rpc.get_block_count().await.expect("height");
    }

    let template = rpc
        .get_block_template_unchecked(vec!["segwit"])
        .await
        .expect("getblocktemplate");
    assert!(
        template.transactions.is_empty(),
        "the template carries {} transaction(s); this test assembles a coinbase-only block, so \
         its witness commitment would not match and ghostd would answer \
         `bad-witness-merkle-match`",
        template.transactions.len()
    );
    let height = template.height;
    let subsidy = template.coinbasevalue;

    let node = build_node(Arc::clone(&rpc));

    // The whole change under test: no ratification step between here and the coinbase.
    let proposal_hash = node
        .handler
        .handle_block_found(block_found(height, subsidy))
        .expect("shard payout");
    assert_ne!(
        proposal_hash, [0u8; 32],
        "no proposal was produced from the shard's owed balances"
    );
    assert_eq!(
        node.template.approved_payout(),
        Some(proposal_hash),
        "the no-vote path did not arm the coinbase — with no elders seeded, nothing else could"
    );

    let coinbase = node
        .template
        .build_approved_coinbase(height, &template.default_witness_commitment)
        .expect("coinbase from the shard payout");

    use bitcoin::consensus::Encodable;
    use bitcoin::hashes::Hash;

    let prev: bitcoin::BlockHash = template.previousblockhash.parse().expect("prev hash");
    let bits = u32::from_str_radix(&template.bits, 16).expect("bits");
    let mut header = bitcoin::block::Header {
        version: bitcoin::block::Version::from_consensus(template.version as i32),
        prev_blockhash: prev,
        merkle_root: bitcoin::TxMerkleNode::from_byte_array(
            coinbase.compute_txid().to_byte_array(),
        ),
        time: template.curtime as u32,
        bits: bitcoin::CompactTarget::from_consensus(bits),
        nonce: 0,
    };

    let target = header.target();
    let mut found = false;
    for nonce in 0..u32::MAX {
        header.nonce = nonce;
        if target.is_met_by(header.block_hash()) {
            found = true;
            break;
        }
    }
    assert!(found, "no nonce met the regtest target");

    let block = bitcoin::Block {
        header,
        txdata: vec![coinbase.clone()],
    };
    let mut raw = Vec::new();
    block.consensus_encode(&mut raw).expect("encode");

    let before = rpc.get_block_count().await.expect("height before");
    let reject = rpc
        .submit_block(&hex::encode(&raw))
        .await
        .expect("submitblock");
    assert_eq!(
        reject, None,
        "ghostd REJECTED a block whose coinbase came from the shard with no vote"
    );
    assert_eq!(
        rpc.get_block_count().await.expect("height after"),
        before + 1,
        "the chain did not advance by our block"
    );

    // Who actually got paid, read back off the chain rather than from our own structures.
    let onchain = rpc
        .get_block(&block.block_hash().to_string(), 2)
        .await
        .expect("getblock");
    let outs = onchain["tx"][0]["vout"]
        .as_array()
        .expect("coinbase outputs");

    let paid: BTreeMap<String, u64> = outs
        .iter()
        .filter_map(|o| {
            let a = o["scriptPubKey"]["address"].as_str()?.to_string();
            let sats = (o["value"].as_f64()? * 100_000_000.0).round() as u64;
            Some((a, sats))
        })
        .collect();

    for owed_addr in shard_owed().keys() {
        assert!(
            paid.contains_key(owed_addr),
            "an address the shard owed was not paid on-chain: {owed_addr} (paid: {paid:?})"
        );
    }

    // Proportionality: 600k/300k/100k of the miner pool. Checked as an ordering rather than an
    // exact split, because the pool is subsidy minus treasury and node amounts, and pinning that
    // arithmetic here would duplicate `payout.rs` rather than test it.
    let (a1, a2, a3) = (addr(1), addr(2), addr(3));
    assert!(
        paid[&a1] > paid[&a2] && paid[&a2] > paid[&a3],
        "payments did not follow owed work 600k > 300k > 100k: {paid:?}"
    );
}
