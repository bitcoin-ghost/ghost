//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: coinbase_verifier.rs                                                                                           |
//|======================================================================================================================|

//! Reading a mined coinbase: its scriptSig and outputs, from this node's own Core.
//!
//! The pre-submission check against a voted payout commitment is gone: every job's coinbase is
//! the node pool's canonical one, and pool_sv2 checks a solved block against the outputs its job
//! was built with before submitting (`NodePool::check_block`). What remains is used by the share
//! shard's settlement (`shard.rs`).

use bitcoin::address::NetworkUnchecked;

/// Convert bech32 address string bytes to script pubkey bytes.
/// PayoutEntry.address stores bech32 strings as raw bytes;
/// this converts them to match the script pubkey format in actual coinbase outputs.
///
/// `pub(crate)` because settlement (#601) needs the same conversion to measure what a mined
/// coinbase actually paid an address — a second implementation of this mapping is how H-8
/// happened, so there must only ever be this one.
pub(crate) fn address_to_script_pubkey(address_bytes: &[u8]) -> Option<Vec<u8>> {
    let addr_str = std::str::from_utf8(address_bytes).ok()?;
    let addr = addr_str
        .parse::<bitcoin::Address<NetworkUnchecked>>()
        .ok()?;
    let script = addr.assume_checked().script_pubkey();
    Some(script.as_bytes().to_vec())
}

/// One coinbase output: value and script.
#[derive(Debug, Clone)]
pub struct CoinbaseOutput {
    /// Output value in satoshis
    pub value: u64,
    /// Script pubkey bytes
    pub script_pubkey: Vec<u8>,
}

/// Pull the coinbase scriptSig and outputs out of a block, from this node's own Core.
///
/// Both come from the same coinbase: the scriptSig carries the tag naming the payout, the
/// outputs are what the chain actually paid — which is what settlement credits (#601), since
/// the mined amounts carry the winner's fee-drift adjustment and the stored proposal does not.
///
/// ⛔ **Rehomed here from `settlement.rs` by the Stage 6 deletion, deliberately and before that
/// file was removed.** It used to be shared by both ledgers' settlements; the legacy
/// tip-observing one is gone and the shard's maturity settlement (`shard.rs`) is now the only
/// caller. It stays a free function next to [`CoinbaseOutput`] rather than moving into `shard.rs`
/// because what it encodes is how to READ a coinbase, not how to settle one.
///
/// ⚠ It carries the internal-vs-display hash-order fix below. A fresh implementation would
/// re-hit that trap — which is exactly why this was moved rather than rewritten.
pub(crate) async fn fetch_coinbase_parts(
    rpc: &ghost_common::rpc::BitcoinRpc,
    block_hash: &str,
) -> ghost_common::error::GhostResult<(Vec<u8>, Vec<CoinbaseOutput>)> {
    // Normalise to display order first. `BlockEvent` hashes arrive in internal order despite
    // the parser's doc claiming otherwise (observed on vm5, 2026-08-01: every settlement probe
    // got "Block not found" for a block that existed). Settlement is the first consumer to
    // take one of these to an RPC call, which is why it surfaced here.
    let block_hash = &ghost_common::zmq::block_hash_to_display_order(block_hash);
    // Verbosity 0: raw hex. Parsing the block ourselves avoids depending on the shape of the
    // verbose JSON, which differs between Core versions.
    let raw = rpc.get_block(block_hash, 0).await?;
    let hex_str = raw.as_str().unwrap_or_default();
    let bytes = hex::decode(hex_str).map_err(|e| {
        ghost_common::error::GhostError::Rpc(format!("block {block_hash} not hex: {e}"))
    })?;
    let block: bitcoin::Block = bitcoin::consensus::deserialize(&bytes).map_err(|e| {
        ghost_common::error::GhostError::Rpc(format!("block {block_hash} undecodable: {e}"))
    })?;
    let coinbase = block.txdata.first().ok_or_else(|| {
        ghost_common::error::GhostError::Rpc(format!("block {block_hash} has no transactions"))
    })?;
    let script_sig = coinbase
        .input
        .first()
        .ok_or_else(|| {
            ghost_common::error::GhostError::Rpc(format!(
                "block {block_hash} coinbase has no input"
            ))
        })?
        .script_sig
        .as_bytes()
        .to_vec();
    let outputs = coinbase
        .output
        .iter()
        .map(|o| crate::coinbase_verifier::CoinbaseOutput {
            value: o.value.to_sat(),
            script_pubkey: o.script_pubkey.as_bytes().to_vec(),
        })
        .collect();
    Ok((script_sig, outputs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_to_script_pubkey() {
        // BIP173 test vector
        let script = address_to_script_pubkey(b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(script.is_some());
        let script = script.unwrap();
        // P2WPKH: OP_0 <20-byte-hash> → 0x0014 + 20 bytes = 22 bytes
        assert_eq!(script.len(), 22);
        assert_eq!(script[0], 0x00); // witness version 0
        assert_eq!(script[1], 0x14); // push 20 bytes

        // Invalid address returns None
        assert!(address_to_script_pubkey(b"not-a-valid-address").is_none());

        // Raw bytes (not UTF-8) return None
        assert!(address_to_script_pubkey(&[0xff, 0xfe, 0xfd]).is_none());
    }
}
