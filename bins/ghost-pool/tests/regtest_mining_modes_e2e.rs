//! The three mining modes, each proven on a real chain: a real `ghostd` accepts the block, and
//! the coinbase it accepted pays what that mode is supposed to pay.
//!
//! # Why this exists
//!
//! The v1 release checklist (#608 §B) asks for all three modes — solo, private pool, public pool
//! — "proven end-to-end on a chain", and records that none of them had been. The mode logic has
//! good unit coverage (`test_solo_mode_full_subsidy_minus_fee`,
//! `solo_proposal_builds_a_coinbase_through_the_shared_path`, and the `is_single_operator_mode`
//! family), but a unit test asserts what *we* think the coinbase says. It cannot tell us the
//! chain agrees.
//!
//! The distinction is not academic. A coinbase can be internally consistent, hash correctly, and
//! still be rejected — wrong subsidy for the height, a malformed witness commitment, an output
//! script the chain will not take. Only a real `submitblock` settles it.
//!
//! **PublicPool is deliberately NOT retested here.**
//! `regtest_shard_coinbase_e2e::a_shard_built_coinbase_with_no_vote_is_accepted_and_pays_the_owed_addresses`
//! already proves that mode on this exact path, and duplicating it would mean two tests to keep in
//! step for no extra evidence. This file covers the two modes that had no chain-level proof at all.
//!
//! # What makes each assertion real
//!
//! Every payment claim is read back from `getblock` — from the chain's copy of the coinbase, not
//! from the `PayoutProposal` we built. A test that asserts against its own input structures would
//! pass even if `build_approved_coinbase` dropped every output on the floor.
//!
//! # Running it
//!
//! Needs a regtest `ghostd`; `docker start rc-bitcoind` is enough. Credentials come from the
//! environment with the shipped `docker-compose.yml` defaults — see `common/mod.rs`.
//!
//! ```text
//! GHOST_REGTEST_REQUIRED=1 cargo test -p ghost-pool --test regtest_mining_modes_e2e
//! ```

use std::sync::Arc;

use ghost_common::config::{BitcoinNetwork, MiningMode};
use ghost_common::identity::NodeIdentity;
use ghost_common::rpc::BitcoinRpc;
use ghost_common::types::TreasuryAddress;
use ghost_pool::payout::{PayoutConfig, PayoutHandler, SoloBlockFoundData};
use ghost_pool::template::{TemplateConfig, TemplateProcessor};
use ghost_storage::Database;
use ghost_verification::qualification::QualifiedCapabilityProvider;

mod common;

/// The regtest chain is one shared, mutable resource and these tests both mine on it. Run in
/// parallel — which is `cargo test`'s default — one test advances the tip while the other is
/// still building on the height it read, and `submitblock` answers `"inconclusive"`: well-formed
/// but unattachable. That failure looks exactly like a bad coinbase and is not one, so the lock
/// is here rather than a note asking the runner to pass `--test-threads=1`.
///
/// It must cover fetch-template THROUGH submit, not just the submit: the race is on the height
/// read, not the write.
static CHAIN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Regtest heights are ~500 and the shipped fee-split gate is 959,290, so without an override
/// every mode here would be proven on the SUPERSEDED pre-gate fee model — the one that is not
/// what mainnet runs. Arming it makes this a test of the shipping behaviour.
///
/// ⚠ `gates::from_env` refuses overrides on Mainnet, so this only works because the network is
/// Regtest. It resolves through a `OnceLock`, so it must be set before anything reads a gate.
fn arm_gates() {
    std::env::set_var("GHOST_COINBASE_FEE_SPLIT_HEIGHT", "0");
    std::env::set_var("GHOST_PAYOUT_FROM_SHARD_HEIGHT", "0");
    ghost_pool::init_activation_heights(&BitcoinNetwork::Regtest);
    assert_eq!(
        ghost_pool::coinbase_fee_split_height(),
        0,
        "the fee-split override did not take — the assertions below would silently be about the \
         superseded pre-gate model"
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
    addr(200)
}

fn treasury_script() -> Vec<u8> {
    use std::str::FromStr;
    bitcoin::Address::from_str(&treasury_addr())
        .expect("treasury address")
        .assume_checked()
        .script_pubkey()
        .to_bytes()
}

struct Node {
    handler: Arc<PayoutHandler>,
    template: Arc<TemplateProcessor>,
}

fn build_node(rpc: Arc<BitcoinRpc>, mode: MiningMode, solo_payout: Option<String>) -> Node {
    let identity = Arc::new(NodeIdentity::generate());
    let db = Arc::new(Database::in_memory().expect("in-memory db"));

    let template = Arc::new(TemplateProcessor::new(
        TemplateConfig {
            treasury_address: TreasuryAddress::single(treasury_addr()),
            pool_payout_address: addr(9),
            solo_payout_address: solo_payout,
            network: BitcoinNetwork::Regtest,
            mining_mode: mode,
            ..Default::default()
        },
        rpc,
        Default::default(),
        Default::default(),
    ));

    let handler = Arc::new(
        PayoutHandler::new(
            identity,
            PayoutConfig {
                treasury_address: Some(treasury_script()),
                network: BitcoinNetwork::Regtest,
                ..Default::default()
            },
            Arc::clone(&db),
            Arc::clone(&template),
            Arc::new(QualifiedCapabilityProvider::new(Arc::clone(&db))),
        )
        .expect("payout handler"),
    );

    Node { handler, template }
}

/// Mine the coinbase into a real block and submit it. Returns the on-chain coinbase outputs as
/// `(address, value_sats)`, read back from `getblock` rather than from what we built.
async fn mine_and_read_back(
    rpc: &BitcoinRpc,
    prev_hash: &str,
    bits_hex: &str,
    version: u32,
    curtime: u64,
    coinbase: bitcoin::Transaction,
    what: &str,
) -> Vec<(String, u64)> {
    use bitcoin::consensus::Encodable;
    use bitcoin::hashes::Hash;

    let prev: bitcoin::BlockHash = prev_hash.parse().expect("prev hash");
    let bits = u32::from_str_radix(bits_hex, 16).expect("bits");
    let mut header = bitcoin::block::Header {
        version: bitcoin::block::Version::from_consensus(version as i32),
        prev_blockhash: prev,
        merkle_root: bitcoin::TxMerkleNode::from_byte_array(
            coinbase.compute_txid().to_byte_array(),
        ),
        time: curtime as u32,
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
    assert!(found, "{what}: no nonce met the regtest target");

    let block = bitcoin::Block {
        header,
        txdata: vec![coinbase],
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
        "{what}: ghostd REJECTED the block — the coinbase this mode builds is not one the chain \
         will take, which no unit test could have told us"
    );
    assert_eq!(
        rpc.get_block_count().await.expect("height after"),
        before + 1,
        "{what}: submitblock reported no rejection but the chain did not advance"
    );

    let onchain = rpc
        .get_block(&block.block_hash().to_string(), 2)
        .await
        .expect("getblock");
    onchain["tx"][0]["vout"]
        .as_array()
        .expect("coinbase outputs")
        .iter()
        .filter_map(|o| {
            let sats = (o["value"].as_f64()? * 100_000_000.0).round() as u64;
            let a = o["scriptPubKey"]["address"].as_str()?.to_string();
            Some((a, sats))
        })
        .collect()
}

/// Both tests assemble a COINBASE-ONLY block, so the template must carry no transactions — its
/// `default_witness_commitment` covers whatever the template includes, and a mempool transaction
/// left in it would make ghostd answer `bad-witness-merkle-match` for a reason that has nothing
/// to do with mining modes.
async fn drain_and_fetch(rpc: &BitcoinRpc) -> ghost_common::rpc::BlockTemplate {
    let mempool = rpc
        .call_raw("getrawmempool", vec![])
        .await
        .expect("getrawmempool");
    if mempool.as_array().map(|a| !a.is_empty()).unwrap_or(false) {
        rpc.call_raw(
            "generatetoaddress",
            vec![serde_json::json!(1), serde_json::json!(addr(9))],
        )
        .await
        .expect("drain the mempool into a block");
    }
    let t = rpc
        .get_block_template_unchecked(vec!["segwit"])
        .await
        .expect("getblocktemplate");
    assert!(
        t.transactions.is_empty(),
        "the template still carries {} transaction(s) after draining",
        t.transactions.len()
    );
    t
}

// ─────────────────────────────────────────────────────────────────────────────────────────────

/// **PrivateSolo.** One operator mining for themselves: the reward goes to `solo_payout_address`,
/// not to a pool split, and there is no vote in the path because there is no mesh to vote.
#[tokio::test]
async fn private_solo_pays_the_solo_address_and_the_chain_accepts_it() {
    let Some(rpc) = common::require_regtest().await else {
        return;
    };
    arm_gates();
    let _chain = CHAIN.lock().await;

    let solo = addr(42);
    let node = build_node(
        Arc::clone(&rpc),
        MiningMode::PrivateSolo,
        Some(solo.clone()),
    );

    let template = drain_and_fetch(&rpc).await;
    let height = template.height;

    let hash = node
        .handler
        .handle_solo_block_found(SoloBlockFoundData {
            round_id: 1,
            block_hash: [0x11; 32],
            block_height: height,
            block_timestamp: chrono::Utc::now(),
            solo_payout_address: solo.clone(),
            subsidy_sats: template.coinbasevalue,
            treasury_address_snapshot: Some(treasury_script()),
            tx_fees_sats: 0,
            node_shares: Vec::new(),
            treasury_state: Default::default(),
        })
        .expect("solo block found");
    assert_ne!(
        hash, [0u8; 32],
        "solo produced no proposal — #592 made solo approve its own payout rather than submit it \
         to BFT, so an empty hash means that path regressed"
    );

    let coinbase = node
        .template
        .build_approved_coinbase(height, &template.default_witness_commitment)
        .expect("solo coinbase");

    let outs = mine_and_read_back(
        &rpc,
        &template.previousblockhash,
        &template.bits,
        template.version,
        template.curtime,
        coinbase,
        "PrivateSolo",
    )
    .await;

    let to_solo: u64 = outs
        .iter()
        .filter(|(a, _)| *a == solo)
        .map(|(_, v)| *v)
        .sum();
    assert!(
        to_solo > 0,
        "the solo address was paid NOTHING by a block it mined in solo mode; on-chain outputs \
         were {outs:?}"
    );

    // The defining property of the mode: the operator takes the reward, not a pool split.
    let total: u64 = outs.iter().map(|(_, v)| *v).sum();
    assert!(
        to_solo * 100 >= total * 95,
        "solo took {to_solo} of {total} sats — the mode is supposed to pay the operator, so \
         anything under ~99% means a pool split leaked into the solo path"
    );

    // Nothing should reach the pool address; that is what separates this mode from PrivatePool.
    let pool_addr = addr(9);
    assert!(
        !outs.iter().any(|(a, v)| *a == pool_addr && *v > 0),
        "solo mode paid the POOL payout address — outputs were {outs:?}"
    );
}

/// **PrivatePool.** One operator paying their own miners: there is a pool split, but no vote,
/// because a quorum would be that operator's own nodes agreeing with themselves.
#[tokio::test]
async fn private_pool_pays_its_miners_and_the_chain_accepts_it() {
    let Some(rpc) = common::require_regtest().await else {
        return;
    };
    arm_gates();
    let _chain = CHAIN.lock().await;

    let node = build_node(Arc::clone(&rpc), MiningMode::PrivatePool, None);

    let template = drain_and_fetch(&rpc).await;
    let height = template.height;

    let mut owed = std::collections::BTreeMap::new();
    owed.insert(addr(1), 700_000i64);
    owed.insert(addr(2), 300_000i64);

    let hash = node
        .handler
        .handle_block_found(ghost_pool::payout::BlockFoundData {
            shard_owed: Some(owed.clone()),
            round_id: 1,
            ledger_cutoff_ts: chrono::Utc::now().timestamp() - 60,
            block_hash: [0x22; 32],
            block_height: height,
            block_timestamp: chrono::Utc::now(),
            winning_miner_id: "pool".to_string(),
            winning_miner_payout_address: Some(addr(1)),
            treasury_address_snapshot: Some(treasury_script()),
            winning_node_id: [9u8; 32],
            subsidy_sats: template.coinbasevalue,
            tx_fees_sats: 0,
            miner_work: Vec::new(),
            node_shares: Vec::new(),
            treasury_state: Default::default(),
        })
        .expect("private-pool block found");
    assert_ne!(
        hash, [0u8; 32],
        "PrivatePool produced no proposal — a single-operator mode must approve its own payout \
         without a vote, and no elders are seeded here, so an empty hash means it tried to vote"
    );

    let coinbase = node
        .template
        .build_approved_coinbase(height, &template.default_witness_commitment)
        .expect("private-pool coinbase");

    let outs = mine_and_read_back(
        &rpc,
        &template.previousblockhash,
        &template.bits,
        template.version,
        template.curtime,
        coinbase,
        "PrivatePool",
    )
    .await;

    // The defining property: the operator's OWN miners are paid, by address, from the shard.
    for who in owed.keys() {
        let paid: u64 = outs.iter().filter(|(a, _)| a == who).map(|(_, v)| *v).sum();
        assert!(
            paid > 0,
            "miner {who} was owed work but received nothing on-chain; outputs were {outs:?}"
        );
    }
}
