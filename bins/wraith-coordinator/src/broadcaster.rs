//! Pluggable transaction-broadcast backend.
//!
//! Same shape as the `BondLedger` trait elsewhere. Tests inject
//! `StubBroadcaster` which just records the call; production wires
//! `GhostdBroadcaster` which forwards to a bitcoind JSON-RPC node.
//! The coordinator's broadcast path is deliberately decoupled from
//! the network layer so the tx-merge logic can be unit-tested without
//! a full node, and so a malfunctioning broadcaster doesn't poison
//! the round-state machine.

use std::sync::{Arc, Mutex};

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::Transaction;
use tracing::{debug, warn};

use crate::rpc::{RpcClient, RpcError};

/// Errors any [`Broadcaster`] implementation may surface to the
/// coordinator. The state machine in `/witness` decides whether to
/// retry or fail the round based on which variant comes back.
#[derive(Debug, thiserror::Error)]
pub enum BroadcastError {
    /// Broadcaster backend isn't configured. Until phase D wires the
    /// bitcoind RPC client, the production `new()` constructor leaves
    /// this as `None` and `/witness` returns 503 on the final submit.
    #[error("broadcast backend not configured")]
    NotConfigured,
    /// The backend rejected the transaction (e.g. bitcoind returned
    /// `bad-txns-inputs-missingorspent`). The round can't recover —
    /// transition to Failed.
    #[error("backend rejected transaction: {0}")]
    Rejected(String),
    /// The backend was unreachable (network error, RPC timeout). The
    /// round may be retryable; for v1 we fail-fast, future iterations
    /// can add retry logic.
    #[error("backend unreachable: {0}")]
    Unreachable(String),
}

/// Trait the coordinator calls once all witnesses are merged. Send +
/// Sync so the state can hold an `Arc<dyn Broadcaster>`. The
/// implementation is responsible for any network I/O — synchronous
/// signature because broadcast is rare (once per round) and the
/// coordinator's HTTP handler is happy to block briefly on it.
pub trait Broadcaster: Send + Sync {
    /// Submit `tx` to the network. Returns the txid the network sees,
    /// which the coordinator cross-checks against the txid it
    /// computed from the assembled round (if they don't match, the
    /// backend is buggy or compromised — surface as `Rejected`).
    fn broadcast(&self, tx: &Transaction) -> Result<bitcoin::Txid, BroadcastError>;
}

/// Test broadcaster — records every call into a shared `Vec` so tests
/// can assert "yes, the round transaction did get broadcast" without
/// running a real bitcoind. Returns the tx's own computed txid as the
/// "network" txid (matches what an honest backend would do).
#[derive(Debug, Default, Clone)]
pub struct StubBroadcaster {
    pub broadcasted: Arc<Mutex<Vec<Transaction>>>,
}

impl StubBroadcaster {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn count(&self) -> usize {
        self.broadcasted.lock().expect("stub poisoned").len()
    }

    pub fn last(&self) -> Option<Transaction> {
        self.broadcasted
            .lock()
            .expect("stub poisoned")
            .last()
            .cloned()
    }
}

impl Broadcaster for StubBroadcaster {
    fn broadcast(&self, tx: &Transaction) -> Result<bitcoin::Txid, BroadcastError> {
        let txid = tx.compute_txid();
        self.broadcasted
            .lock()
            .expect("stub poisoned")
            .push(tx.clone());
        Ok(txid)
    }
}

// ---------------------------------------------------------------------------
// Production: bitcoind JSON-RPC broadcaster
// ---------------------------------------------------------------------------

/// `sendrawtransaction` over the node's JSON-RPC interface.
///
/// The transport, auth and request shapes live in [`crate::rpc`] — the
/// coordinator talks to one node and `GhostdUtxoSource` needs the same
/// connection, so only the method and the error mapping are here.
///
/// Synchronous request because:
///   - the surrounding `Broadcaster` trait is sync,
///   - broadcast happens once per round (rare), and
///   - we explicitly want the HTTP handler to block briefly until the
///     network has accepted the tx so the `/witness` response carries
///     the truth and can transition the session correctly.
pub struct GhostdBroadcaster {
    rpc: RpcClient,
}

impl GhostdBroadcaster {
    /// Construct from a bitcoind RPC URL + (user, password), as found
    /// in `bitcoin.conf`'s `rpcuser=` / `rpcpassword=`.
    pub fn new(
        endpoint: impl Into<String>,
        user: &str,
        password: &str,
    ) -> Result<Self, BroadcastError> {
        Ok(Self {
            rpc: RpcClient::new(endpoint, user, password),
        })
    }

    /// Convenience: build from bitcoind's `.cookie` file.
    pub fn from_cookie(
        endpoint: impl Into<String>,
        cookie_path: impl AsRef<std::path::Path>,
    ) -> Result<Self, BroadcastError> {
        RpcClient::from_cookie(endpoint, cookie_path)
            .map(|rpc| Self { rpc })
            .map_err(|e| BroadcastError::Unreachable(e.to_string()))
    }

    /// Build from an already-constructed client, so the same node
    /// connection can also serve `gettxout` for input verification
    /// without a second set of credentials.
    pub fn from_rpc(rpc: RpcClient) -> Self {
        Self { rpc }
    }
}

impl Broadcaster for GhostdBroadcaster {
    fn broadcast(&self, tx: &Transaction) -> Result<bitcoin::Txid, BroadcastError> {
        let raw_hex = serialize_hex(tx);
        debug!(endpoint = %self.rpc.endpoint(), txid = %tx.compute_txid(), "sending sendrawtransaction");

        let result = match self.rpc.call(
            "sendrawtransaction",
            vec![serde_json::Value::String(raw_hex)],
        ) {
            Ok(v) => v,
            // bitcoind RPC errors have well-known codes; most of them
            // mean the tx is bad (already-spent, low-fee, etc.) — that's
            // a Rejected, not Unreachable. We intentionally don't try
            // to retry — the tx won't succeed elsewhere either.
            Err(RpcError::Rpc { code, message }) => {
                warn!(code, %message, "bitcoind rejected tx");
                return Err(BroadcastError::Rejected(format!("code {code}: {message}")));
            }
            // Malformed output is treated as Unreachable so the round can
            // potentially be retried by an operator after diagnosis.
            Err(e) => return Err(BroadcastError::Unreachable(e.to_string())),
        };

        // Result is a JSON string of the txid (64-char hex).
        let txid_hex = result
            .as_str()
            .ok_or_else(|| BroadcastError::Unreachable("RPC result is not a string".into()))?;
        use std::str::FromStr;
        bitcoin::Txid::from_str(txid_hex).map_err(|e| {
            BroadcastError::Unreachable(format!("RPC returned malformed txid {txid_hex}: {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::JoinHandle;

    /// Tiny one-shot HTTP/1.1 server that accepts ONE request,
    /// asserts the JSON body matches `expected_method`, and replies
    /// with the supplied body. Lets us drive `GhostdBroadcaster`
    /// end-to-end without pulling in a full mock HTTP framework.
    fn one_shot_rpc(
        expected_method: &'static str,
        reply_status: u16,
        reply_body: serde_json::Value,
    ) -> (String, JoinHandle<serde_json::Value>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let body = read_request(&stream);
            let parsed: serde_json::Value = serde_json::from_str(&body).expect("body parse");
            assert_eq!(parsed["method"], expected_method, "wrong RPC method");
            // Reply.
            let body_str = reply_body.to_string();
            let resp = format!(
                "HTTP/1.1 {status} OK\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {len}\r\n\
                 \r\n\
                 {body}",
                status = reply_status,
                len = body_str.len(),
                body = body_str,
            );
            stream.write_all(resp.as_bytes()).expect("write");
            parsed
        });
        (url, handle)
    }

    fn read_request(stream: &TcpStream) -> String {
        let mut reader = BufReader::new(stream);
        let mut headers = Vec::new();
        let mut content_length: usize = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).expect("read header");
            if line == "\r\n" {
                break;
            }
            // HTTP header names are case-insensitive (RFC 7230 §3.2);
            // reqwest sends them lowercase.
            let lower = line.to_ascii_lowercase();
            if let Some(rest) = lower.strip_prefix("content-length:") {
                content_length = rest.trim().parse().unwrap_or(0);
            }
            headers.push(line);
        }
        let mut body = vec![0u8; content_length];
        std::io::Read::read_exact(&mut reader, &mut body).expect("read body");
        String::from_utf8(body).expect("utf8")
    }

    fn fixture_tx() -> Transaction {
        // Smallest possible signed-shape tx; the broadcaster doesn't
        // care about consensus-validity, only about consensus encoding.
        bitcoin::Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        }
    }

    #[test]
    fn bitcoind_broadcaster_returns_txid_on_success() {
        let returned_txid = "0000000000000000000000000000000000000000000000000000000000000001";
        let (url, server) = one_shot_rpc(
            "sendrawtransaction",
            200,
            serde_json::json!({
                "result": returned_txid,
                "error": null,
                "id": "wraith-coordinator",
            }),
        );
        let bb = GhostdBroadcaster::new(url, "user", "pass").unwrap();
        let txid = bb.broadcast(&fixture_tx()).expect("broadcast ok");
        assert_eq!(txid.to_string(), returned_txid);
        let req_body = server.join().unwrap();
        // Body params should carry our serialized tx hex.
        assert_eq!(req_body["method"], "sendrawtransaction");
        assert!(req_body["params"][0].as_str().unwrap().len() >= 16);
    }

    #[test]
    fn bitcoind_broadcaster_surfaces_rpc_error_as_rejected() {
        let (url, server) = one_shot_rpc(
            "sendrawtransaction",
            200,
            serde_json::json!({
                "result": null,
                "error": { "code": -26, "message": "min relay fee not met" },
                "id": "wraith-coordinator",
            }),
        );
        let bb = GhostdBroadcaster::new(url, "u", "p").unwrap();
        let err = bb.broadcast(&fixture_tx()).expect_err("rejected");
        match err {
            BroadcastError::Rejected(detail) => {
                assert!(detail.contains("min relay fee"));
                assert!(detail.contains("-26"));
            }
            other => panic!("expected Rejected; got {other:?}"),
        }
        server.join().unwrap();
    }

    #[test]
    fn bitcoind_broadcaster_surfaces_connect_failures_as_unreachable() {
        // 127.0.0.1:1 is reserved-low and rejects connect immediately.
        let bb = GhostdBroadcaster::new("http://127.0.0.1:1/", "u", "p").unwrap();
        let err = bb.broadcast(&fixture_tx()).expect_err("unreachable");
        match err {
            BroadcastError::Unreachable(_) => {}
            other => panic!("expected Unreachable; got {other:?}"),
        }
    }
}
