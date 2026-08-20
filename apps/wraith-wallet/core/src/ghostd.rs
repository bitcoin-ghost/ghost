//! Sync bitcoind JSON-RPC client used by the wallet's
//! unilateral-exit (LocksRecover) path.
//!
//! Why not reuse the chain client (ghost-pay)? Because the whole
//! point of the recovery flow is "no operator cooperation." Going
//! through ghost-pay defeats it. The wallet talks straight to the
//! user's own bitcoind for this path.
//!
//! Why ureq, not reqwest? `reqwest::blocking` spawns its own internal
//! tokio runtime which panics on Drop inside the surrounding
//! tokio runtime. ureq is pure-sync, no internal runtime — fits the
//! "occasional sync HTTP call from inside an async handler" use
//! case cleanly.
//!
//! Surface kept tight on purpose:
//!   - `get_block_count` — to check whether the timelock has matured
//!   - `get_raw_transaction` — to find the funding vout + its scriptPubKey
//!     (so we know the prevout we're spending without trusting the
//!     operator)
//!   - `send_raw_transaction` — to broadcast the recovery tx
//!
//! Anything else (mempool inspection, fee estimation, address
//! validation) the wallet does locally or doesn't need.

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum GhostdError {
    #[error("bitcoind unreachable: {0}")]
    Unreachable(String),
    #[error("bitcoind RPC rejected request: code {code}: {message}")]
    Rpc { code: i32, message: String },
    #[error("response parse: {0}")]
    Parse(String),
    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
}

pub struct GhostdRpc {
    endpoint: String,
    auth_header: String,
    agent: ureq::Agent,
}

impl GhostdRpc {
    pub fn new(endpoint: impl Into<String>, user: &str, password: &str) -> Self {
        use base64::Engine;
        let creds = format!("{user}:{password}");
        let encoded = base64::engine::general_purpose::STANDARD.encode(creds);
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            .build();
        Self {
            endpoint: endpoint.into(),
            auth_header: format!("Basic {encoded}"),
            agent,
        }
    }

    pub fn from_cookie(
        endpoint: impl Into<String>,
        cookie_path: impl AsRef<std::path::Path>,
    ) -> Result<Self, GhostdError> {
        let raw = std::fs::read_to_string(cookie_path.as_ref())
            .map_err(|e| GhostdError::Unreachable(format!("cookie read: {e}")))?;
        let raw = raw.trim();
        let (user, password) = raw
            .split_once(':')
            .ok_or_else(|| GhostdError::Unreachable("malformed cookie file".into()))?;
        Ok(Self::new(endpoint, user, password))
    }

    fn rpc<R: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<R, GhostdError> {
        let body = RpcRequest {
            jsonrpc: "1.0",
            id: "wraithd",
            method,
            params,
        };
        let resp = self
            .agent
            .post(&self.endpoint)
            .set("Authorization", &self.auth_header)
            .send_json(&body);
        let resp = match resp {
            Ok(r) => r,
            Err(ureq::Error::Status(_, response)) => response,
            Err(ureq::Error::Transport(t)) => {
                return Err(GhostdError::Unreachable(format!("{:?}: {t}", t.kind())));
            }
        };
        let parsed: RpcResponse<R> = resp
            .into_json()
            .map_err(|e| GhostdError::Parse(e.to_string()))?;
        if let Some(err) = parsed.error {
            return Err(GhostdError::Rpc {
                code: err.code,
                message: err.message,
            });
        }
        parsed
            .result
            .ok_or_else(|| GhostdError::Parse("RPC returned neither result nor error".into()))
    }

    /// Current best-block height. Used to check whether a lock's
    /// CSV-relative timelock has matured.
    pub fn get_block_count(&self) -> Result<u64, GhostdError> {
        self.rpc("getblockcount", vec![])
    }

    /// The block hash at `height`, as the node reports it.
    ///
    /// Used to re-derive a coordinator epoch's beacon from the chain rather
    /// than believing the one the operator published beside its election
    /// (#697). Same reasoning as the recovery path this client was built for:
    /// asking the operator to confirm the operator's own claim is not a check.
    ///
    /// The returned hex is fed to `wraith_protocol::derive_beacon` decoded
    /// as-is, with no byte reversal — the node deriving the beacon does the
    /// same, and the two must agree exactly.
    pub fn get_block_hash(&self, height: u64) -> Result<String, GhostdError> {
        self.rpc("getblockhash", vec![serde_json::Value::from(height)])
    }

    /// Fetch a transaction in verbose mode. Returns enough to find
    /// the vout whose scriptPubKey matches the lock's funding
    /// address.
    pub fn get_raw_transaction_verbose(&self, txid: &str) -> Result<RawTransaction, GhostdError> {
        self.rpc(
            "getrawtransaction",
            vec![
                serde_json::Value::String(txid.to_string()),
                serde_json::Value::Bool(true),
            ],
        )
    }

    /// Push a signed transaction to the mempool. Returns the txid the
    /// node accepted. Errors map cleanly:
    ///   - bitcoind RPC error → `GhostdError::Rpc { code, message }`
    ///     (e.g. bad-txns-inputs-missingorspent, premature-spend, etc.)
    ///   - transport / connect → `GhostdError::Unreachable`
    pub fn send_raw_transaction(&self, raw_hex: &str) -> Result<String, GhostdError> {
        self.rpc(
            "sendrawtransaction",
            vec![serde_json::Value::String(raw_hex.to_string())],
        )
    }
}

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'a str,
    id: &'a str,
    method: &'a str,
    params: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct RpcResponse<R> {
    result: Option<R>,
    error: Option<RpcError>,
}

#[derive(Deserialize, Debug)]
struct RpcError {
    code: i32,
    message: String,
}

/// Subset of bitcoind's verbose `getrawtransaction` output. We only
/// pull what the recovery path needs.
#[derive(Debug, Deserialize)]
pub struct RawTransaction {
    pub txid: String,
    pub vout: Vec<RawVout>,
    /// `confirmations` is omitted when the tx is in the mempool. The
    /// wallet doesn't strictly need this, but having it helps logs.
    #[serde(default)]
    pub confirmations: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct RawVout {
    /// vout index.
    pub n: u32,
    /// Output value in BTC. Bitcoin Core encodes as float; we accept
    /// it as a string + parse manually OR use serde_json::Number.
    /// Float is fine for this read-only conversion.
    pub value: f64,
    #[serde(rename = "scriptPubKey")]
    pub script_pubkey: RawScriptPubKey,
}

impl RawVout {
    /// Convert the float `value` (BTC) to satoshis. Bitcoin Core
    /// emits 8-decimal floats; `(value * 1e8).round()` is the
    /// canonical conversion and avoids accumulating fp error on
    /// well-formed inputs.
    pub fn value_sats(&self) -> u64 {
        (self.value * 100_000_000.0).round() as u64
    }
}

#[derive(Debug, Deserialize)]
pub struct RawScriptPubKey {
    /// Hex-encoded scriptPubKey.
    pub hex: String,
    /// Address (when scriptPubKey is a standard one). Bitcoin Core
    /// recent versions emit this as `address` (singular); older
    /// versions used `addresses` (array). We accept both.
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub addresses: Option<Vec<String>>,
    #[serde(rename = "type", default)]
    pub script_type: Option<String>,
}

impl RawScriptPubKey {
    /// Convenience — returns the first address if present (modern
    /// `address` field, falling back to legacy `addresses`).
    pub fn first_address(&self) -> Option<&str> {
        self.address.as_deref().or_else(|| {
            self.addresses
                .as_ref()
                .and_then(|v| v.first().map(|s| s.as_str()))
        })
    }
}
