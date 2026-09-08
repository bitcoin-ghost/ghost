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

    /// One block, with every input's previous output resolved.
    ///
    /// `getblock <hash> 3` is what makes local scanning possible without an
    /// indexer: the node returns each input's `prevout` from its undo data,
    /// so the wallet can tell which inputs were its own — and therefore what
    /// it *spent* — without a `txindex` or a lookup per input.
    ///
    /// Verbosity 2 would give outputs only, which finds money arriving but
    /// not money leaving. A history that shows credits and no debits is worse
    /// than none: it reads like a balance that only ever grows.
    pub fn get_block_with_prevouts(&self, hash: &str) -> Result<VerboseBlock, GhostdError> {
        self.rpc(
            "getblock",
            vec![
                serde_json::Value::String(hash.to_string()),
                serde_json::Value::from(3u8),
            ],
        )
    }

    /// `scantxoutset start` over a set of `addr(...)` descriptors.
    ///
    /// Walks the whole UTXO set, so it is expensive and bitcoind serialises
    /// it: one scan at a time per node. That cost is the price of not asking
    /// an operator's indexer where your money is.
    ///
    /// Returns `(unspents, chain_height)`.
    pub fn scan_tx_out_set(
        &self,
        addresses: &[String],
    ) -> Result<(Vec<ScannedOutput>, u64), GhostdError> {
        let descriptors: Vec<serde_json::Value> = addresses
            .iter()
            .map(|a| serde_json::Value::String(format!("addr({a})")))
            .collect();
        let res: serde_json::Value = self.rpc(
            "scantxoutset",
            vec![
                serde_json::Value::String("start".into()),
                serde_json::Value::Array(descriptors),
            ],
        )?;

        // `success: false` is bitcoind saying the scan did not complete —
        // usually another scan is already running. Treating that as "no
        // coins" would report an empty wallet, which is the worst possible
        // way to be wrong about a balance.
        if res.get("success").and_then(|v| v.as_bool()) != Some(true) {
            return Err(GhostdError::Parse(
                "scantxoutset did not complete (another scan may be running); \
                 refusing to report a balance from a partial scan"
                    .into(),
            ));
        }
        let height = res
            .get("height")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| GhostdError::Parse("scantxoutset returned no height".into()))?;
        let unspents: Vec<ScannedOutput> = serde_json::from_value(
            res.get("unspents")
                .cloned()
                .unwrap_or(serde_json::json!([])),
        )
        .map_err(|e| GhostdError::Parse(format!("scantxoutset unspents: {e}")))?;
        Ok((unspents, height))
    }

    /// Push a signed transaction to the mempool. Returns the txid the
    /// node accepted. Errors map cleanly:
    ///
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

/// One row of `scantxoutset`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ScannedOutput {
    pub txid: String,
    pub vout: u32,
    /// BTC as a JSON number, exactly as bitcoind reports it.
    pub amount: f64,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: String,
    /// Height the output was created at.
    pub height: u64,
}

/// One block from `getblock <hash> 3`.
///
/// Only the fields a wallet scan needs. `#[serde(default)]` is deliberately
/// absent on `height` and `tx`: a block without them is not a block this can
/// scan, and defaulting them would silently scan nothing.
#[derive(Debug, Clone, Deserialize)]
pub struct VerboseBlock {
    pub hash: String,
    pub height: u64,
    /// Block time, unix seconds. What a transaction's history entry is dated
    /// by — the wallet may not have been running when it was mined.
    pub time: i64,
    pub tx: Vec<BlockTx>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockTx {
    pub txid: String,
    #[serde(default)]
    pub vin: Vec<BlockVin>,
    #[serde(default)]
    pub vout: Vec<RawVout>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockVin {
    /// Absent on a coinbase input, which spends nothing.
    #[serde(default)]
    pub txid: Option<String>,
    #[serde(default)]
    pub vout: Option<u32>,
    /// The output this input spends. Present for every non-coinbase input at
    /// verbosity 3; `None` marks an input whose value is not knowable here,
    /// which makes any fee computed from this transaction wrong rather than
    /// merely approximate.
    #[serde(default)]
    pub prevout: Option<Prevout>,
    /// Set only on the coinbase input.
    #[serde(default)]
    pub coinbase: Option<String>,
}

impl BlockVin {
    /// Whether this is the coinbase input.
    pub fn is_coinbase(&self) -> bool {
        self.coinbase.is_some()
    }
}

/// The output an input spends, as the node resolved it from undo data.
#[derive(Debug, Clone, Deserialize)]
pub struct Prevout {
    /// Value in BTC, as bitcoind encodes it.
    pub value: f64,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: RawScriptPubKey,
}

impl Prevout {
    /// BTC → satoshis, rounded rather than truncated. `0.000_123_45` arriving
    /// as `0.000_123_449_999` must not lose a satoshi.
    pub fn value_sats(&self) -> u64 {
        (self.value * 100_000_000.0).round() as u64
    }
}
