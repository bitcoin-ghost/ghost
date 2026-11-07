//! Node pool payee-script classes, where a miner's payout address is accepted.
//!
//! The node pool pays only P2SH, P2WPKH, P2WSH and P2TR (spec 2.1): their sizes are bounded, so
//! the 22 KB coinbase ceiling holds for every slot class, and they carry no sigops, so payouts
//! never eat into the 400 sigop cost `getblocktemplate` leaves for the coinbase. P2PKH costs 4
//! sigops an output and regtest lost a block at 120 of them.
//!
//! The class itself is `ghost_common::share_commit::payee_script_class`, the same function a
//! peer runs when it checks a share. This module turns an address into its script and applies
//! the class rule.

use ghost_common::share_commit::{payee_script_class, PayeeScriptClass};
use std::str::FromStr;

/// Why a payout address is refused for the node pool.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayeeRefusal {
    #[error("not a Bitcoin address")]
    Unparseable,
    #[error("address is for another network")]
    WrongNetwork,
    #[error("script class not accepted by the node pool (P2SH, P2WPKH, P2WSH or P2TR only)")]
    Class,
}

/// The payee script and class of `address` on `network`.
pub fn node_pool_payee_script(
    address: &str,
    network: bitcoin::Network,
) -> Result<(Vec<u8>, PayeeScriptClass), PayeeRefusal> {
    let script = bitcoin::Address::from_str(address.trim())
        .map_err(|_| PayeeRefusal::Unparseable)?
        .require_network(network)
        .map_err(|_| PayeeRefusal::WrongNetwork)?
        .script_pubkey()
        .into_bytes();
    let class = payee_script_class(&script).ok_or(PayeeRefusal::Class)?;
    Ok((script, class))
}

/// Whether a miner's payout address may be recorded: only the four node pool classes pass.
pub fn accept_payout_address(address: &str, network: bitcoin::Network) -> Result<(), PayeeRefusal> {
    node_pool_payee_script(address, network).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network::{Bitcoin, Regtest};

    // BIP173 / BIP350 / BIP13 vectors, mainnet.
    const P2WPKH: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const P2WSH: &str = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    const P2TR: &str = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
    const P2SH: &str = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
    const P2PKH: &str = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";

    #[test]
    fn the_four_classes_pass() {
        for (addr, class, len) in [
            (P2SH, PayeeScriptClass::P2sh, 23),
            (P2WPKH, PayeeScriptClass::P2wpkh, 22),
            (P2WSH, PayeeScriptClass::P2wsh, 34),
            (P2TR, PayeeScriptClass::P2tr, 34),
        ] {
            let (script, got) = node_pool_payee_script(addr, Bitcoin).unwrap();
            assert_eq!(got, class, "{addr}");
            assert_eq!(script.len(), len, "{addr}");
        }
    }

    #[test]
    fn p2pkh_and_junk_are_refused() {
        assert_eq!(
            node_pool_payee_script(P2PKH, Bitcoin),
            Err(PayeeRefusal::Class)
        );
        assert_eq!(
            node_pool_payee_script("not-an-address", Bitcoin),
            Err(PayeeRefusal::Unparseable)
        );
        assert_eq!(
            node_pool_payee_script("", Bitcoin),
            Err(PayeeRefusal::Unparseable)
        );
        assert_eq!(
            node_pool_payee_script(P2TR, Regtest),
            Err(PayeeRefusal::WrongNetwork)
        );
    }

    /// Segwit v2+ outputs parse as addresses but are not a node pool class.
    #[test]
    fn future_witness_versions_are_refused() {
        let v2 = "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs";
        assert!(bitcoin::Address::from_str(v2).is_ok());
        assert_eq!(
            node_pool_payee_script(v2, Bitcoin),
            Err(PayeeRefusal::Class)
        );
    }

    #[test]
    fn only_the_four_classes_are_recorded() {
        assert_eq!(
            accept_payout_address(P2PKH, Bitcoin),
            Err(PayeeRefusal::Class)
        );
        assert_eq!(
            accept_payout_address("junk", Bitcoin),
            Err(PayeeRefusal::Unparseable)
        );
        assert_eq!(accept_payout_address(P2TR, Bitcoin), Ok(()));
    }
}
