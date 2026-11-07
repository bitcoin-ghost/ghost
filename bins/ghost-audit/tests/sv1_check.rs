//! `ghost-audit` against a fake SV1 node, in process: a job whose coinbase follows the solo rule
//! passes, and one that pays the treasury a sat short (the sat moved to the miner) fails.

use std::time::Duration;

use bitcoin::absolute::LockTime;
use bitcoin::consensus::serialize;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use ghost_audit::audit_sv1;
use ghost_audit::check::Verdict;
use ghost_audit::sv1::Sv1Config;
use ghost_common::coinbase_tags::bip34_height_push;
use ghost_common::solo::{solo_outputs, CoinbaseOutput, Halving, SoloNetwork};

/// The miner: a regtest P2WPKH.
const ADDRESS: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
const EXTRANONCE1: [u8; 4] = [0x0a, 0x0b, 0x0c, 0x0d];
const EXTRANONCE2_SIZE: usize = 4;
const HEIGHT: u64 = 200;

fn payee() -> Vec<u8> {
    let a: bitcoin::Address<bitcoin::address::NetworkUnchecked> = ADDRESS.parse().unwrap();
    a.require_network(bitcoin::Network::Regtest)
        .unwrap()
        .script_pubkey()
        .to_bytes()
}

/// `(coinb1, coinb2)` of a coinbase at [`HEIGHT`] paying `outs`, split around the extranonce.
fn halves(outs: &[CoinbaseOutput]) -> (String, String) {
    let n = EXTRANONCE1.len() + EXTRANONCE2_SIZE;
    let mut sig = bip34_height_push(HEIGHT);
    sig.push(n as u8);
    sig.extend(vec![0u8; n]);
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(sig.clone()),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outs
            .iter()
            .map(|(v, s)| TxOut {
                value: Amount::from_sat(*v),
                script_pubkey: ScriptBuf::from_bytes(s.clone()),
            })
            .collect(),
    };
    let raw = serialize(&tx);
    // version, input count, outpoint, scriptSig length (one byte), then the scriptSig.
    let at = 4 + 1 + 36 + 1 + sig.len() - n;
    (hex::encode(&raw[..at]), hex::encode(&raw[at + n..]))
}

/// A node that answers the handshake and sends one `mining.notify` paying `outs`.
async fn fake_node(outs: Vec<CoinbaseOutput>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let (r, mut w) = sock.into_split();
        let mut lines = BufReader::new(r).lines();
        let sub: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        let auth: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
        let (c1, c2) = halves(&outs);
        for m in [
            json!({"id": sub["id"], "result": [[], hex::encode(EXTRANONCE1), EXTRANONCE2_SIZE], "error": null}),
            json!({"id": auth["id"], "result": true, "error": null}),
            json!({"id": null, "method": "mining.set_difficulty", "params": [1.0]}),
            json!({"id": null, "method": "mining.notify", "params": [
                "1", "00".repeat(32), c1, c2, [], "20000000", "207fffff", "65000000", true
            ]}),
        ] {
            w.write_all(format!("{m}\n").as_bytes()).await.unwrap();
        }
        // Hold the connection until the auditor is done.
        while let Ok(Some(_)) = lines.next_line().await {}
    });
    addr
}

async fn check(outs: Vec<CoinbaseOutput>) -> ghost_audit::check::JobReport {
    let addr = fake_node(outs).await;
    let cfg = Sv1Config {
        addr,
        username: format!("{ADDRESS}.rig1"),
        password: "x".into(),
        user_agent: "test/1".into(),
        timeout: Duration::from_secs(10),
    };
    let mut reports = audit_sv1(
        &cfg,
        &payee(),
        SoloNetwork::Regtest,
        1,
        Duration::from_secs(10),
        |_| {},
    )
    .await
    .expect("the session runs");
    assert_eq!(reports.len(), 1);
    reports.remove(0)
}

#[tokio::test]
async fn a_job_that_pays_the_rule_passes() {
    let [t, m] = solo_outputs(HEIGHT as u32, Halving::REGTEST, 12_345, &payee());
    let mut witness = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    witness.extend([0x22; 32]);
    let r = check(vec![t.clone(), m.clone(), (0, witness)]).await;
    assert_eq!(r.verdict, Verdict::Pass, "{r:?}");
    assert_eq!(r.height, Some(HEIGHT));
    assert_eq!(r.treasury_sats, Some(t.0));
    assert_eq!(r.miner_sats, Some(m.0));
    assert_eq!(r.fees_sats, Some(12_345));
}

#[tokio::test]
async fn a_treasury_one_sat_short_fails() {
    let [t, m] = solo_outputs(HEIGHT as u32, Halving::REGTEST, 0, &payee());
    let r = check(vec![(t.0 - 1, t.1), (m.0 + 1, m.1)]).await;
    assert_eq!(r.verdict, Verdict::Fail, "{r:?}");
    assert!(r.reason.unwrap().contains("treasury"));
}
