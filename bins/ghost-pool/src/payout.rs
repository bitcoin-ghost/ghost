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
//| FILE: payout.rs                                                                                                      |
//|======================================================================================================================|

//! The old payout ledger's checkpoint root.
//!
//! What a block pays is the node pool's canonical payout (`ghost_common::canonical_payout`),
//! built per job by pool_sv2 and settled by the node pool relay. What remains here is the root
//! the old payout-ledger checkpoints still finalise over the share shard (`payout_checkpoint`);
//! it feeds no coinbase and goes with the checkpoints.

use ghost_common::types::NodeId;

/// The checkpoint's miner work, from the share shard: `(address, weight)` sorted work-desc then
/// address-asc, the input of [`compute_ledger_root`]. The weight is `owed` micro-work.
///
/// Non-positive balances are dropped: `owed()` is `accrued − settled` and can go negative
/// transiently, and the `i64 → u128` cast would otherwise wrap a small negative into a number
/// larger than the entire pool. Capped at `MAX_MINER_OUTPUTS`, which the checkpoint root has
/// always used; no coinbase is built from this list any more.
pub fn select_shard_miner_work(
    owed: &std::collections::BTreeMap<String, i64>,
) -> Vec<(String, u128)> {
    let mut rows: Vec<(String, u128)> = owed
        .iter()
        .filter(|(_, &micro)| micro > 0)
        .map(|(addr, &micro)| (addr.clone(), micro as u128))
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows.truncate(ghost_common::constants::MAX_MINER_OUTPUTS);
    rows
}

/// Domain-separated tag for the payout-ledger checkpoint root. Bump the version
/// suffix if the canonical encoding below ever changes (it is consensus-visible).
const LEDGER_ROOT_DOMAIN: &[u8] = b"PayoutLedgerRoot/v1";

/// Deterministic 32-byte root over the payout inputs as of a fixed cutoff: the
/// canonical unpaid-miner set (payout address → scaled integer work) and the
/// qualified-node set (node_id → 5-4-3-2-1 capability shares). This is the object
/// the fleet BFT-finalises; the coinbase then becomes a pure function of the
/// checkpoint carrying this root, so every node builds the identical coinbase and
/// GHOST-02/Component-E recompute-reject can never spuriously fire.
///
/// PURE and ORDER-INDEPENDENT: both sets are sorted canonically here (miners by
/// work desc then address asc — matching `select_ledger_miner_work`'s order; nodes
/// by node_id asc), so two nodes holding the same rows produce a byte-identical
/// root regardless of the order their queries returned. Work is a `u128` (already
/// `WORK_SCALE`-quantised, never a float) so the hash is reproducible. Every field
/// is length-prefixed to prevent concatenation ambiguity.
pub fn compute_ledger_root(
    miners: &[(String, u128)],
    nodes: &[(NodeId, i32)],
    cutoff_ts: i64,
    block_height: u64,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut m = miners.to_vec();
    m.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut n = nodes.to_vec();
    n.sort_by_key(|x| x.0);

    let mut h = Sha256::new();
    h.update(LEDGER_ROOT_DOMAIN);
    h.update(cutoff_ts.to_le_bytes());
    h.update(block_height.to_le_bytes());
    h.update((m.len() as u32).to_le_bytes());
    for (addr, work) in &m {
        h.update((addr.len() as u32).to_le_bytes());
        h.update(addr.as_bytes());
        h.update(work.to_le_bytes());
    }
    h.update((n.len() as u32).to_le_bytes());
    for (node_id, shares) in &n {
        h.update(&node_id[..]);
        h.update(shares.to_le_bytes());
    }
    let out = h.finalize();
    let mut root = [0u8; 32];
    root.copy_from_slice(&out);
    root
}

/// Diagnostic breakdown of the ledger-root inputs, for isolating live root
/// divergence. Hashes the miner-set and node-set SEPARATELY (each with the same
/// canonical encoding `compute_ledger_root` uses for that half) and includes their
/// counts plus the full node list (node_id prefix : shares). Comparing this string
/// across nodes tells us (a) whether the rejecters agree with each other, and
/// (b) whether the miner half or the node half is the divergent one — and for the
/// node half, exactly which node/shares differ. Diagnostic only; not consensus.
pub fn ledger_root_diag(
    miners: &[(String, u128)],
    nodes: &[(NodeId, i32)],
    cutoff_ts: i64,
    block_height: u64,
) -> String {
    use sha2::{Digest, Sha256};

    let mut m = miners.to_vec();
    m.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut mh = Sha256::new();
    for (addr, work) in &m {
        mh.update((addr.len() as u32).to_le_bytes());
        mh.update(addr.as_bytes());
        mh.update(work.to_le_bytes());
    }
    let mdig = mh.finalize();

    let mut n = nodes.to_vec();
    n.sort_by_key(|x| x.0);
    let mut nh = Sha256::new();
    for (node_id, shares) in &n {
        nh.update(&node_id[..]);
        nh.update(shares.to_le_bytes());
    }
    let ndig = nh.finalize();
    let node_list: Vec<String> = n
        .iter()
        .map(|(id, s)| format!("{}:{}", hex::encode(&id[..4]), s))
        .collect();

    let root = compute_ledger_root(miners, nodes, cutoff_ts, block_height);
    format!(
        "root={} miners{{n={},h={}}} nodes{{n={},h={},[{}]}}",
        hex::encode(&root[..8]),
        m.len(),
        hex::encode(&mdig[..8]),
        n.len(),
        hex::encode(&ndig[..8]),
        node_list.join(","),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    /// `owed()` is `accrued − settled` and is documented to go negative transiently. The cast to
    /// `u128` is where that becomes money: `-1i64 as u128` is 2^128−1, an address weighted above
    /// the entire pool, and the coinbase splits proportionally. So the filter is not tidiness.
    #[test]
    fn shard_miner_work_drops_non_positive_balances_before_the_cast() {
        let owed = std::collections::BTreeMap::from([
            ("bc1qalice".to_string(), 500i64),
            ("bc1qbob".to_string(), -1i64),
            ("bc1qcarol".to_string(), 0i64),
        ]);
        let got = super::select_shard_miner_work(&owed);
        assert_eq!(
            got,
            vec![("bc1qalice".to_string(), 500u128)],
            "a negative or zero balance reached the output"
        );
        assert!(
            got.iter().all(|(_, w)| *w < u128::MAX / 2),
            "a negative balance wrapped through the u128 cast"
        );
    }

    /// Canonical order: work descending, address ascending on a tie. `compute_ledger_root` sorts
    /// internally so the root does not depend on this, but the adopted list is persisted and read
    /// back by the coinbase builder, and a total order means two nodes cannot differ on a tie.
    #[test]
    fn shard_miner_work_is_ordered_work_desc_then_address_asc() {
        let owed = std::collections::BTreeMap::from([
            ("bc1qb".to_string(), 10i64),
            ("bc1qa".to_string(), 10i64),
            ("bc1qc".to_string(), 99i64),
        ]);
        assert_eq!(
            super::select_shard_miner_work(&owed),
            vec![
                ("bc1qc".to_string(), 99u128),
                ("bc1qa".to_string(), 10u128),
                ("bc1qb".to_string(), 10u128),
            ]
        );
    }

    /// The adopted list must never be longer than a coinbase can pay, or the checkpoint ratifies
    /// a split that cannot be built. Truncation keeps the LARGEST balances, which is why the sort
    /// has to happen first — the reverse order would drop the addresses that matter.
    #[test]
    fn shard_miner_work_caps_at_max_miner_outputs_keeping_the_largest() {
        let cap = ghost_common::constants::MAX_MINER_OUTPUTS;
        let owed: std::collections::BTreeMap<String, i64> = (0..cap as i64 + 25)
            .map(|i| (format!("bc1q{i:04}"), i + 1))
            .collect();
        let got = super::select_shard_miner_work(&owed);
        assert_eq!(got.len(), cap, "cap not applied");
        assert_eq!(
            got[0].1,
            (cap as u128) + 25,
            "truncation kept the wrong end of the list"
        );
        let smallest_kept = got.last().expect("non-empty").1;
        assert_eq!(smallest_kept, 26u128, "expected the largest `cap` balances");
    }

    #[test]
    fn shard_miner_work_on_an_empty_shard_is_empty_not_a_panic() {
        assert!(super::select_shard_miner_work(&std::collections::BTreeMap::new()).is_empty());
    }

    #[test]
    fn ledger_root_is_deterministic_and_order_independent() {
        let miners_a = vec![
            ("bc1qaaa".to_string(), 100u128),
            ("bc1qbbb".to_string(), 250u128),
            ("bc1qccc".to_string(), 250u128), // tie on work → address breaks it
        ];
        let nodes_a = vec![(nid(3), 9i32), (nid(1), 15i32), (nid(2), 7i32)];

        // Same content, different query order on BOTH sets.
        let miners_b = vec![
            ("bc1qccc".to_string(), 250u128),
            ("bc1qaaa".to_string(), 100u128),
            ("bc1qbbb".to_string(), 250u128),
        ];
        let nodes_b = vec![(nid(1), 15i32), (nid(2), 7i32), (nid(3), 9i32)];

        let root_a = compute_ledger_root(&miners_a, &nodes_a, 1_784_000_000, 958_800);
        let root_b = compute_ledger_root(&miners_b, &nodes_b, 1_784_000_000, 958_800);
        assert_eq!(root_a, root_b, "root must be independent of input order");

        // Recompute must be byte-stable across calls.
        let root_a2 = compute_ledger_root(&miners_a, &nodes_a, 1_784_000_000, 958_800);
        assert_eq!(root_a, root_a2);
    }

    #[test]
    fn ledger_root_changes_when_any_input_changes() {
        let miners = vec![("bc1qaaa".to_string(), 100u128)];
        let nodes = vec![(nid(1), 15i32)];
        let base = compute_ledger_root(&miners, &nodes, 1_784_000_000, 958_800);

        // different miner work
        let m2 = vec![("bc1qaaa".to_string(), 101u128)];
        assert_ne!(
            base,
            compute_ledger_root(&m2, &nodes, 1_784_000_000, 958_800)
        );
        // different node shares
        let n2 = vec![(nid(1), 14i32)];
        assert_ne!(
            base,
            compute_ledger_root(&miners, &n2, 1_784_000_000, 958_800)
        );
        // different cutoff
        assert_ne!(
            base,
            compute_ledger_root(&miners, &nodes, 1_784_000_001, 958_800)
        );
        // different height
        assert_ne!(
            base,
            compute_ledger_root(&miners, &nodes, 1_784_000_000, 958_801)
        );
    }

    #[test]
    fn ledger_root_length_prefixing_prevents_ambiguity() {
        // ("ab","c") vs ("a","bc") must not collide (concatenation ambiguity guard).
        let m1 = vec![("ab".to_string(), 1u128), ("c".to_string(), 1u128)];
        let m2 = vec![("a".to_string(), 1u128), ("bc".to_string(), 1u128)];
        let nodes: Vec<(NodeId, i32)> = vec![];
        assert_ne!(
            compute_ledger_root(&m1, &nodes, 1, 1),
            compute_ledger_root(&m2, &nodes, 1, 1),
        );
    }

    #[test]
    fn ledger_root_handles_empty_sets() {
        let empty_m: Vec<(String, u128)> = vec![];
        let empty_n: Vec<(NodeId, i32)> = vec![];
        // Deterministic, non-panicking, and distinct from a populated root.
        let r0 = compute_ledger_root(&empty_m, &empty_n, 1, 1);
        assert_eq!(r0, compute_ledger_root(&empty_m, &empty_n, 1, 1));
        let r1 = compute_ledger_root(&[("x".to_string(), 1)], &empty_n, 1, 1);
        assert_ne!(r0, r1);
    }
}
