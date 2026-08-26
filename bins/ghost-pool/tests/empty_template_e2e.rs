//! Empty (coinbase-only) template on tip change.
//!
//! The Haze release adds `publish_empty_template()` so a ZMQ tip change can hand
//! miners work on the new tip with zero transaction-assembly latency — the full
//! template (`refresh_template_forced`) follows. This test proves, against a real
//! regtest ghostd, that with a fee-paying transaction sitting in the mempool the
//! empty path emits a coinbase-only template (no txs, no fees) while the forced
//! full path includes that transaction and its fee.
//!
//! Skips when no regtest ghostd is reachable, UNLESS `GHOST_REGTEST_REQUIRED` is set, in which
//! case an unreachable node is a failure — see `common::skip_or_fail`. A silent skip is why
//! seven e2e tests reported green without ever executing (#770).

use std::sync::Arc;

use ghost_common::config::{BitcoinNetwork, MiningMode};
use ghost_common::rpc::BitcoinRpc;
use ghost_common::types::TreasuryAddress;
use ghost_pool::template::{TemplateConfig, TemplateProcessor};
use serde_json::json;

mod common;

fn rpc() -> Option<Arc<BitcoinRpc>> {
    // Credentials from the environment with the shipped compose defaults (see `common`).
    let mut r = common::regtest_rpc_raw()?;
    // The checked get_block_template validates the target against the rpc's network
    // (mainnet by default), and regtest's trivial target reads as "too easy" under
    // the mainnet limit. Point the rpc at Regtest so it uses the permissive limit.
    r.set_network(BitcoinNetwork::Regtest);
    Some(Arc::new(r))
}

fn addr(seed: u8) -> String {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[seed; 32]).expect("sk");
    let pk = bitcoin::PublicKey::new(sk.public_key(&secp));
    let cpk = bitcoin::CompressedPublicKey::try_from(pk).expect("cpk");
    bitcoin::Address::p2wpkh(&cpk, bitcoin::Network::Regtest).to_string()
}

#[tokio::test]
async fn empty_template_is_coinbase_only_while_forced_full_includes_mempool() {
    let Some(rpc) = rpc() else {
        common::skip_or_fail("no regtest ghostd");
        return;
    };
    if rpc.get_block_count().await.is_err() {
        common::skip_or_fail("regtest ghostd not responding");
        return;
    }

    // A single loaded wallet lets wallet RPCs resolve on the base URL.
    //
    // `createwallet` fails once the wallet exists, and ghostd does not load a wallet
    // automatically, so the SECOND run against a given node reached `getnewaddress` with
    // nothing loaded and died on `RPC error -18: No wallet is loaded`. Discarding the result
    // hid which of the two had happened. Create, then fall back to loading; `loadwallet` in
    // turn fails harmlessly when it is already loaded, which is the steady state.
    if rpc
        .call_raw("createwallet", vec![json!("etest")])
        .await
        .is_err()
    {
        let _ = rpc.call_raw("loadwallet", vec![json!("etest")]).await;
    }
    let mining_addr = rpc
        .call_raw("getnewaddress", vec![])
        .await
        .expect("getnewaddress")
        .as_str()
        .expect("addr str")
        .to_string();

    // Mature a coinbase, then put a fee-paying tx in the mempool (unconfirmed).
    rpc.call_raw("generatetoaddress", vec![json!(101), json!(mining_addr)])
        .await
        .expect("generate");

    // ⛔ Refresh the client's cached tip after generating, or `validate_template` rejects every
    // template that follows.
    //
    // `BitcoinRpc` remembers the height it last saw and checks a template against it within
    // `MAX_HEIGHT_DEVIATION` (10). Mining 101 blocks moves the chain 101 past that cache, so the
    // first template is ~101 out and fails with `Height out of range: template=N, expected near
    // N-101`.
    //
    // ⚠ This test could never have passed — the deviation is unconditional, not environmental.
    // It went unnoticed because the file skipped: its hardcoded `ghosttest` credentials matched
    // no shipped config, so a credential mismatch read as "no regtest node" and the test reported
    // success without executing. See `common/mod.rs`.
    rpc.get_block_count().await.expect("refresh cached tip");
    let dest = rpc.call_raw("getnewaddress", vec![]).await.expect("addr2");
    rpc.call_raw("sendtoaddress", vec![dest, json!(1.0)])
        .await
        .expect("sendtoaddress");
    let mempool = rpc
        .call_raw("getrawmempool", vec![])
        .await
        .expect("mempool");
    assert!(
        mempool.as_array().map(|a| a.len()).unwrap_or(0) >= 1,
        "expected a tx in the mempool to distinguish empty from full"
    );

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

    // Empty path first (current_work is None, so it publishes): coinbase-only.
    template
        .publish_empty_template()
        .await
        .expect("publish empty");
    let empty = template.current_work().expect("empty work");
    assert_eq!(empty.total_fees, 0, "empty template must carry no fees");
    assert_eq!(empty.tx_count, 1, "empty template is coinbase-only");
    assert!(
        empty.merkle_branches.is_empty(),
        "coinbase-only template has no merkle branches"
    );

    // Forced full rebuild at the same tip: includes the mempool tx + its fee.
    template
        .refresh_template_forced()
        .await
        .expect("refresh full");
    let full = template.current_work().expect("full work");
    assert!(
        full.tx_count > empty.tx_count,
        "full template must include the mempool tx (full={} empty={})",
        full.tx_count,
        empty.tx_count
    );
    assert!(
        full.total_fees > 0,
        "full template must collect the mempool tx's fee"
    );
}
