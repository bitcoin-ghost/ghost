//! Pluggable UTXO-set lookup.
//!
//! Same shape as [`crate::broadcaster::Broadcaster`] and `BondLedger`:
//! a trait the handlers call, a mock for tests, and a real
//! implementation over the bitcoind JSON-RPC connection the operator
//! already configures for broadcast.
//!
//! ## Why registration needs this
//!
//! `TxInputRef` is entirely wallet-asserted — `txid`, `vout`,
//! `value_sats` and `scriptpubkey_hex` all arrive in the request body.
//! Until this module existed nothing checked any of them against the
//! chain, so:
//!
//!   - the round arithmetic was computed from a value the participant
//!     chose,
//!   - the input might already be spent, or never have existed, and
//!   - an ownership proof would be worthless: a signature over a
//!     *wallet-supplied* scriptPubKey says nothing about the real
//!     outpoint, so anyone could register someone else's coin, prove
//!     "ownership" of their own script, and get the victim's outpoint
//!     banned.
//!
//! One `gettxout` settles all of it: existence, value, scriptPubKey and
//! unspent-ness in a single call, read from the UTXO set — so no
//! `-txindex` is required on the node.
//!
//! See #699.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use bitcoin::{Amount, Denomination, OutPoint, ScriptBuf};
use tracing::{debug, warn};

use crate::rpc::{RpcClient, RpcError};

/// What the chain says about an outpoint. Every field here is
/// authoritative; the wallet's claims are checked against it, never the
/// other way round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    pub value_sats: u64,
    pub script_pubkey: ScriptBuf,
    /// Confirmations as reported by the node. `0` means the output is
    /// only in the mempool — its parent can still be replaced, so a
    /// round must not build on it.
    pub confirmations: u32,
    /// Coinbase outputs are unspendable until 100 confirmations.
    pub coinbase: bool,
}

/// Errors a [`UtxoSource`] may surface. Note the deliberate absence of
/// a "not found" variant — a missing outpoint is `Ok(None)`, because it
/// is a normal answer about the chain rather than a failure to ask.
/// "No source configured" is likewise absent: that is decided before a
/// lookup is attempted, by the handler, from `CoordinatorState`.
#[derive(Debug, thiserror::Error)]
pub enum UtxoError {
    /// The node was unreachable, or answered with something that isn't
    /// a `gettxout` result.
    #[error("utxo source unreachable: {0}")]
    Unreachable(String),
}

/// Trait the handlers call. `Send + Sync` so the state can hold an
/// `Arc<dyn UtxoSource>`. Synchronous for the same reason as
/// `Broadcaster`: one lookup per registration, and the handler is happy
/// to block briefly.
pub trait UtxoSource: Send + Sync {
    /// Look `outpoint` up in the UTXO set.
    ///
    /// `Ok(None)` means the outpoint is not spendable — it never
    /// existed, or it has been spent (including spent by an unconfirmed
    /// transaction). Callers must not distinguish those cases: telling a
    /// caller *which* it was leaks chain state they did not ask for.
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, UtxoError>;
}

/// Test source backed by an explicit map. Anything not in the map reads
/// as unspendable, which is what makes it useful: a test that wants an
/// outpoint accepted has to say so.
#[derive(Debug, Default, Clone)]
pub struct MockUtxoSource {
    entries: Arc<Mutex<HashMap<OutPoint, Utxo>>>,
}

impl MockUtxoSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a confirmed, non-coinbase output.
    pub fn insert(&self, outpoint: OutPoint, value_sats: u64, script_pubkey: ScriptBuf) {
        self.insert_utxo(
            outpoint,
            Utxo {
                value_sats,
                script_pubkey,
                confirmations: 6,
                coinbase: false,
            },
        );
    }

    /// Add an output with every field chosen by the caller — for tests
    /// about confirmations or coinbase maturity.
    pub fn insert_utxo(&self, outpoint: OutPoint, utxo: Utxo) {
        self.entries
            .lock()
            .expect("mock utxo source poisoned")
            .insert(outpoint, utxo);
    }

    /// Drop an entry, so a test can model the outpoint being spent
    /// between one registration and the next.
    pub fn remove(&self, outpoint: &OutPoint) {
        self.entries
            .lock()
            .expect("mock utxo source poisoned")
            .remove(outpoint);
    }
}

impl UtxoSource for MockUtxoSource {
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, UtxoError> {
        Ok(self
            .entries
            .lock()
            .expect("mock utxo source poisoned")
            .get(outpoint)
            .cloned())
    }
}

/// Real source: bitcoind `gettxout` over the same JSON-RPC connection
/// the broadcaster uses.
pub struct GhostdUtxoSource {
    rpc: RpcClient,
}

impl GhostdUtxoSource {
    pub fn new(rpc: RpcClient) -> Self {
        Self { rpc }
    }
}

impl UtxoSource for GhostdUtxoSource {
    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<Utxo>, UtxoError> {
        debug!(%outpoint, "gettxout");
        // `include_mempool = true` so an outpoint already being spent by
        // an unconfirmed transaction reads as gone. Without it a
        // participant could register a coin they are simultaneously
        // spending elsewhere, and the round would fail at broadcast.
        let params = vec![
            serde_json::Value::String(outpoint.txid.to_string()),
            serde_json::Value::from(outpoint.vout),
            serde_json::Value::Bool(true),
        ];
        let result = match self.rpc.call("gettxout", params) {
            Ok(v) => v,
            Err(RpcError::Rpc { code, message }) => {
                // gettxout answers a missing output with JSON null, not
                // an error, so an actual RPC error means the node is
                // unhappy with us rather than the outpoint being absent.
                warn!(code, %message, "gettxout RPC error");
                return Err(UtxoError::Unreachable(format!("code {code}: {message}")));
            }
            Err(e) => return Err(UtxoError::Unreachable(e.to_string())),
        };

        if result.is_null() {
            return Ok(None);
        }

        let value = result
            .get("value")
            .ok_or_else(|| UtxoError::Unreachable("gettxout result has no `value`".into()))?;
        // bitcoind reports value in BTC. Going via the JSON number's own
        // string form keeps this exact — `as_f64` would round, and this
        // number decides whether the round's arithmetic balances.
        let value_sats = Amount::from_str_in(&value.to_string(), Denomination::Bitcoin)
            .map_err(|e| UtxoError::Unreachable(format!("gettxout value {value}: {e}")))?
            .to_sat();

        let spk_hex = result
            .get("scriptPubKey")
            .and_then(|s| s.get("hex"))
            .and_then(|h| h.as_str())
            .ok_or_else(|| {
                UtxoError::Unreachable("gettxout result has no `scriptPubKey.hex`".into())
            })?;
        let script_pubkey = ScriptBuf::from_hex(spk_hex)
            .map_err(|e| UtxoError::Unreachable(format!("gettxout scriptPubKey {spk_hex}: {e}")))?;

        let confirmations = result
            .get("confirmations")
            .and_then(|c| c.as_u64())
            .ok_or_else(|| {
                UtxoError::Unreachable("gettxout result has no `confirmations`".into())
            })? as u32;
        let coinbase = result
            .get("coinbase")
            .and_then(|c| c.as_bool())
            .unwrap_or(false);

        Ok(Some(Utxo {
            value_sats,
            script_pubkey,
            confirmations,
            coinbase,
        }))
    }
}

/// Parse a wallet-supplied `txid:vout` pair into an `OutPoint`.
/// Returns the wallet-facing detail string on failure.
pub fn parse_outpoint(txid: &str, vout: u32) -> Result<OutPoint, String> {
    let txid = bitcoin::Txid::from_str(txid.trim())
        .map_err(|e| format!("could not parse txid '{txid}': {e}"))?;
    Ok(OutPoint { txid, vout })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outpoint(n: u8) -> OutPoint {
        OutPoint {
            txid: bitcoin::Txid::from_str(&format!("{:02x}", n).repeat(32)).unwrap(),
            vout: 0,
        }
    }

    #[test]
    fn mock_reports_an_absent_outpoint_as_unspendable() {
        let src = MockUtxoSource::new();
        assert_eq!(src.get_utxo(&outpoint(1)).unwrap(), None);
    }

    #[test]
    fn mock_returns_what_was_inserted() {
        let src = MockUtxoSource::new();
        let spk = ScriptBuf::from_hex("0014aabbccddeeff00112233445566778899aabbccdd").unwrap();
        src.insert(outpoint(2), 200_000, spk.clone());
        let got = src.get_utxo(&outpoint(2)).unwrap().expect("present");
        assert_eq!(got.value_sats, 200_000);
        assert_eq!(got.script_pubkey, spk);
        assert!(!got.coinbase);
        assert!(got.confirmations >= 1);
    }

    #[test]
    fn mock_models_a_spend_by_removal() {
        let src = MockUtxoSource::new();
        src.insert(outpoint(3), 1, ScriptBuf::new());
        src.remove(&outpoint(3));
        assert_eq!(src.get_utxo(&outpoint(3)).unwrap(), None);
    }

    #[test]
    fn outpoints_parse_and_reject() {
        assert!(parse_outpoint(&"11".repeat(32), 4).is_ok());
        assert!(parse_outpoint("not-a-txid", 0).is_err());
    }
}
