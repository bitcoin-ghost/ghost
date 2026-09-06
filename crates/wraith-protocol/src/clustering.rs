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
//| FILE: clustering.rs                                                                                                 |
//|======================================================================================================================|

//! Grouping a round's coins by owner, from data the round already has.
//!
//! [`crate::anonymity_set`] merges seats by cluster, and `admission` and
//! `composition` both read one — but nothing produced a cluster, so every coin
//! arrived as `None` and every rule that depended on ancestry silently did
//! nothing. This is the missing producer.
//!
//! # Two signals, no extra chain access
//!
//! 1. **Shared funding transaction.** Two coins with the same txid are outputs
//!    of one transaction. That is the exact shape of "fund twenty addresses from
//!    one wallet", and also the exact shape of an honest ladder participant's
//!    preparatory split — which is fine, because both are genuinely *one
//!    entity* and that is what the cluster says.
//! 2. **Shared scriptPubKey.** Two coins paying the same script are the same
//!    address. Nothing weaker than an outright declaration links two coins more
//!    firmly.
//!
//! Both come from the outpoint and the UTXO lookup the coordinator already
//! performs. No transaction-graph walk, no new RPC, and a participant can
//! recompute the whole thing.
//!
//! # What it does not catch
//!
//! An attacker who funds each Sybil from a **separate transaction** to a
//! **separate address** defeats both signals. Catching that needs real ancestry
//! — walking back through the transaction graph for a common ancestor within
//! some depth — which needs a source that can fetch parent transactions.
//! `UtxoSource` cannot, so that is a later piece of work and not a line of
//! defence today.
//!
//! What this does is raise the floor from *nothing* to *the naive shape*, and
//! make the attacker pay for separate funding paths. It should be described that
//! way and no better.

use std::collections::HashMap;

use crate::signing_ledger::OutPointKey;

/// What is known about one coin, from the outpoint plus the UTXO lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinFacts {
    /// The coin.
    pub outpoint: OutPointKey,
    /// Its scriptPubKey, as the **chain** reports it.
    ///
    /// From the chain and never from the submission: a script the submitter
    /// chose proves nothing about who owns the coin.
    pub script_pubkey: Vec<u8>,
}

/// Same minimal union-find as `anonymity_set`. Rounds are small.
struct Union {
    parent: Vec<usize>,
}

impl Union {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n).collect(),
        }
    }
    fn find(&mut self, mut x: usize) -> usize {
        while self.parent[x] != x {
            self.parent[x] = self.parent[self.parent[x]];
            x = self.parent[x];
        }
        x
    }
    fn union(&mut self, a: usize, b: usize) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            // Always point the higher root at the lower one, so the root of a
            // group is its first-appearing member. That is what makes cluster
            // ids depend on input order alone and stay comparable between
            // nodes.
            self.parent[ra.max(rb)] = ra.min(rb);
        }
    }
}

/// Cluster a round's coins.
///
/// Returns one entry per input coin, in the same order: `Some(id)` when the coin
/// was linked to at least one other, `None` when nothing linked it.
///
/// `None` means *no evidence found*, never *proven independent* — the
/// distinction is carried through to [`crate::anonymity_set::SetReport`], where
/// it is reported as unverified rather than counted as a guarantee.
///
/// Cluster ids are assigned in first-appearance order, so two nodes given the
/// same coins in the same order produce identical ids and can be compared.
pub fn cluster_coins(coins: &[CoinFacts]) -> Vec<Option<u64>> {
    if coins.is_empty() {
        return Vec::new();
    }
    let mut uf = Union::new(coins.len());

    let mut by_txid: HashMap<[u8; 32], usize> = HashMap::new();
    let mut by_script: HashMap<&[u8], usize> = HashMap::new();

    for (i, c) in coins.iter().enumerate() {
        // Signal 1 — siblings of one funding transaction.
        match by_txid.get(&c.outpoint.txid) {
            Some(&first) => uf.union(first, i),
            None => {
                by_txid.insert(c.outpoint.txid, i);
            }
        }
        // Signal 2 — the same address twice. An empty script carries no
        // information and must not group every unknown coin together.
        if !c.script_pubkey.is_empty() {
            match by_script.get(c.script_pubkey.as_slice()) {
                Some(&first) => uf.union(first, i),
                None => {
                    by_script.insert(c.script_pubkey.as_slice(), i);
                }
            }
        }
    }

    // Only groups of two or more are clusters; a lone coin stays `None`.
    let mut members: HashMap<usize, usize> = HashMap::new();
    for i in 0..coins.len() {
        *members.entry(uf.find(i)).or_insert(0) += 1;
    }

    let mut ids: HashMap<usize, u64> = HashMap::new();
    let mut next: u64 = 0;
    let mut out = Vec::with_capacity(coins.len());
    for i in 0..coins.len() {
        let root = uf.find(i);
        if members[&root] < 2 {
            out.push(None);
            continue;
        }
        let id = *ids.entry(root).or_insert_with(|| {
            let v = next;
            next += 1;
            v
        });
        out.push(Some(id));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coin(txid: u8, vout: u32, script: &[u8]) -> CoinFacts {
        CoinFacts {
            outpoint: OutPointKey {
                txid: [txid; 32],
                vout,
            },
            script_pubkey: script.to_vec(),
        }
    }

    #[test]
    fn coins_from_one_funding_transaction_cluster() {
        // "Fund twenty addresses from one wallet" — one transaction, many
        // outputs, all different addresses. The txid gives it away.
        let coins: Vec<CoinFacts> = (0..20u32).map(|v| coin(9, v, &[v as u8, 1, 2])).collect();
        let ids = cluster_coins(&coins);
        assert!(ids.iter().all(|c| *c == Some(0)), "{ids:?}");
    }

    #[test]
    fn the_same_address_twice_clusters() {
        let coins = vec![
            coin(1, 0, &[0xaa, 0xbb]),
            coin(2, 0, &[0xaa, 0xbb]),
            coin(3, 0, &[0xcc]),
        ];
        let ids = cluster_coins(&coins);
        assert_eq!(ids[0], ids[1]);
        assert!(ids[0].is_some());
        assert_eq!(ids[2], None);
    }

    #[test]
    fn unrelated_coins_are_not_clustered() {
        // `None` must mean "no evidence", so independent coins must not be
        // swept into one group — that would report an anonymity set of 1 for
        // every honest round.
        let coins = vec![
            coin(1, 0, &[1]),
            coin(2, 0, &[2]),
            coin(3, 0, &[3]),
            coin(4, 0, &[4]),
        ];
        assert_eq!(cluster_coins(&coins), vec![None, None, None, None]);
    }

    #[test]
    fn an_empty_script_does_not_group_every_unknown_coin() {
        // An unreadable script carries no information. Treating it as a shared
        // one would collapse the set exactly when the data is worst.
        let coins = vec![coin(1, 0, &[]), coin(2, 0, &[]), coin(3, 0, &[])];
        assert_eq!(cluster_coins(&coins), vec![None, None, None]);
    }

    #[test]
    fn linkage_is_transitive_across_the_two_signals() {
        // A shares a txid with B; B shares an address with C. All three are one
        // owner, and handling the signals separately would miss it.
        let coins = vec![
            coin(5, 0, &[0x01]),
            coin(5, 1, &[0x02]),
            coin(7, 0, &[0x02]),
        ];
        let ids = cluster_coins(&coins);
        assert_eq!(ids[0], ids[1]);
        assert_eq!(ids[1], ids[2]);
        assert!(ids[0].is_some());
    }

    #[test]
    fn an_honest_ladder_split_clusters_as_one_entity() {
        // A ladder participant is told to split a coin into exact rungs first,
        // so their rungs share a txid. That is correct and not a false
        // positive: they ARE one entity, which is what the cluster says.
        let rungs: Vec<CoinFacts> = (0..6u32).map(|v| coin(3, v, &[v as u8])).collect();
        let ids = cluster_coins(&rungs);
        assert!(ids.iter().all(|c| *c == Some(0)));
    }

    #[test]
    fn cluster_ids_are_stable_for_the_same_input() {
        let coins = vec![
            coin(1, 0, &[1]),
            coin(2, 0, &[2]),
            coin(2, 1, &[3]),
            coin(9, 0, &[1]),
        ];
        assert_eq!(cluster_coins(&coins), cluster_coins(&coins));
    }

    #[test]
    fn separate_funding_paths_are_not_caught_and_that_is_stated() {
        // The honest limit: an attacker funding each Sybil from its own
        // transaction to its own address defeats both signals. Catching it
        // needs a transaction-graph walk that `UtxoSource` cannot do.
        //
        // Pinned as a test so the gap is visible in the suite rather than only
        // in prose.
        let coins: Vec<CoinFacts> = (0..10u8).map(|i| coin(i, 0, &[i, 0xff])).collect();
        assert!(cluster_coins(&coins).iter().all(|c| c.is_none()));
    }

    #[test]
    fn an_empty_round_clusters_to_nothing() {
        assert_eq!(cluster_coins(&[]), Vec::<Option<u64>>::new());
    }
}
