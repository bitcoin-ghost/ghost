//|======================================================================================================================|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: np_flagday_fixture.rs                                                                                          |
//|======================================================================================================================|

//! A realistic OLD-format `ghost.db` for rehearsing the node pool flag day (export, migration v65,
//! genesis import). Written by this release's own code, not raw SQL, wherever a writer exists:
//!
//! - schema: `Database::open` (every migration up to this release's latest), address encryption
//!   keyed as `ghost-mining` keys it (from the node key, `ghost/db-encryption/v1`);
//! - the shard: `ShardTable::install_genesis`, `accrue` (one column per fleet node) and
//!   `record_settled`, saved with `Database::shard_save_table` and read back with
//!   `shard_load_table` (its root checked);
//! - the checkpoint: `owed()` -> `payout::select_shard_miner_work` (the live path, capped at
//!   `MAX_MINER_OUTPUTS`) -> `payout::compute_ledger_root` -> `upsert_payout_ledger_checkpoint`.
//!   `--uncapped` writes every positive balance instead: what a full-shard-table export source
//!   would carry. No live code writes such a checkpoint;
//! - kept tables: `create_round`, `upsert_miner`, `insert_share`, `record_won_block`,
//!   `get_or_create_node_reward` (balance 0, as every health report leaves it);
//! - `--dirty`: `insert_ghost_lock`, `insert_withdrawal_request_atomic`, `insert_l2_note`,
//!   `credit_node_reward` (rows migration v65 must halt on);
//! - MPC lineage: `save_mpc_ceremony_state`-style rows are written with raw INSERTs (as the
//!   exporter's own tests do), since the ceremony writers need live ceremony objects.
//!
//! The ledger is a pure function of `--seed`, so several databases built with different node keys
//! (one per old node) hold the same ledger under different encryption.
//!
//! ```text
//! cargo run -p ghost-mining --example np_flagday_fixture -- --db ghost.db --node-key node.key \
//!     --network signet --height 30 --miners 4000 --seed 1 [--uncapped] [--dirty] [--no-p2pkh] \
//!     [--shares N]
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str::FromStr;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::{Address, Network, ScriptBuf};
use ghost_common::identity::NodeIdentity;
use ghost_common::share_shard::ShardTable;
use ghost_storage::models::*;
use ghost_storage::{Database, PayoutLedgerCheckpointRecord};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // splitmix64
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn h32(tag: &str) -> [u8; 32] {
    sha256::Hash::hash(tag.as_bytes()).to_byte_array()
}

/// Address `i` of the population: P2WPKH 45%, P2PKH 15%, P2SH 10%, P2TR 20%, P2WSH 10%.
/// With `no_p2pkh` the P2PKH slots are P2WPKH (the node pool's payee classes only).
fn address(seed: u64, i: usize, network: Network, no_p2pkh: bool) -> (String, &'static str) {
    let h = h32(&format!("np-flagday/{seed}/miner/{i}"));
    let slot = match i % 20 {
        9..=11 if no_p2pkh => 0,
        s => s,
    };
    let (script, kind) = match slot {
        0..=8 => {
            let mut s = vec![0x00, 0x14];
            s.extend_from_slice(&h[..20]);
            (s, "p2wpkh")
        }
        9..=11 => {
            let mut s = vec![0x76, 0xa9, 0x14];
            s.extend_from_slice(&h[..20]);
            s.extend_from_slice(&[0x88, 0xac]);
            (s, "p2pkh")
        }
        12..=13 => {
            let mut s = vec![0xa9, 0x14];
            s.extend_from_slice(&h[..20]);
            s.push(0x87);
            (s, "p2sh")
        }
        14..=17 => {
            // A valid x-only key is not needed for the script: Address::from_script reads the
            // witness program as it stands.
            let mut s = vec![0x51, 0x20];
            s.extend_from_slice(&h);
            (s, "p2tr")
        }
        _ => {
            let mut s = vec![0x00, 0x20];
            s.extend_from_slice(&h);
            (s, "p2wsh")
        }
    };
    let addr = Address::from_script(&ScriptBuf::from_bytes(script), network)
        .expect("standard script")
        .to_string();
    (addr, kind)
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let db_path = PathBuf::from(arg(&args, "--db").expect("--db PATH"));
    let key_path = PathBuf::from(arg(&args, "--node-key").expect("--node-key PATH"));
    let network = Network::from_str(&arg(&args, "--network").unwrap_or("bitcoin".into()))?;
    let height: u64 = arg(&args, "--height").expect("--height H").parse()?;
    let n_miners: usize = arg(&args, "--miners").unwrap_or("4000".into()).parse()?;
    let seed: u64 = arg(&args, "--seed").unwrap_or("1".into()).parse()?;
    let n_shares: usize = arg(&args, "--shares").unwrap_or("20000".into()).parse()?;
    let uncapped = args.iter().any(|a| a == "--uncapped");
    let dirty = args.iter().any(|a| a == "--dirty");
    let no_p2pkh = args.iter().any(|a| a == "--no-p2pkh");

    let identity = if key_path.exists() {
        NodeIdentity::load(&key_path)?
    } else {
        let id = NodeIdentity::generate();
        id.save(&key_path)?;
        id
    };
    let me = identity.node_id();

    // Schema: every migration of this release.
    let db = Database::open(&db_path)?;
    {
        // As ghost-mining derives it (main.rs, P-4).
        let sig = identity.signer().sign(b"ghost/db-encryption/v1");
        let mut buf = b"ghost/db-encryption-key/v1".to_vec();
        buf.extend_from_slice(sig.as_ref());
        db.set_encryption_key(sha256::Hash::hash(&buf).to_byte_array());
    }

    // ── The ledger: a function of the seed alone ──────────────────────────────────────────
    let mut rng = Rng(seed);
    let fleet: Vec<[u8; 32]> = (0..8)
        .map(|i| h32(&format!("np-flagday/{seed}/node/{i}")))
        .collect();
    let mut table = ShardTable::new();
    let mut genesis_col: BTreeMap<String, i64> = BTreeMap::new();
    let mut kinds: BTreeMap<&str, usize> = BTreeMap::new();
    let mut addrs = Vec::with_capacity(n_miners);
    for i in 0..n_miners {
        let (a, kind) = address(seed, i, network, no_p2pkh);
        *kinds.entry(kind).or_default() += 1;
        // Owed micro-work: a long tail of dust, a body, and a few whales.
        let r = rng.range(0, 999);
        let micro: i64 = if i < 5 {
            rng.range(2_000_000_000_000, 40_000_000_000_000) as i64
        } else if r < 700 {
            rng.range(1, 2_500_000_000) as i64
        } else if r < 980 {
            rng.range(2_500_000_000, 400_000_000_000) as i64
        } else {
            rng.range(400_000_000_000, 2_000_000_000_000) as i64
        };
        // Spread it: part opening balance (genesis column), part accrued on 1-3 fleet nodes.
        let opening = if i % 3 == 0 { micro / 2 } else { 0 };
        if opening > 0 {
            genesis_col.insert(a.clone(), opening);
        }
        let mut rest = micro - opening;
        let k = rng.range(1, 3) as usize;
        for j in 0..k {
            let node = fleet[(i + j * 3) % fleet.len()];
            let part = if j + 1 == k { rest } else { rest / 2 };
            if part > 0 {
                table.accrue(node, &a, part);
            }
            rest -= part;
        }
        addrs.push(a);
    }
    table.install_genesis(genesis_col);
    // Settlement: 10% of miners were partly paid, 1% exactly paid out, two overpaid (owed < 0,
    // the transient the selector must drop).
    let owed_before = table.owed();
    for (i, a) in addrs.iter().enumerate() {
        let o = *owed_before.get(a).unwrap_or(&0);
        if i % 10 == 7 {
            table.record_settled(a, o / 3);
        } else if i % 100 == 41 {
            table.record_settled(a, o);
        } else if i == 13 || i == 26 {
            table.record_settled(a, o + 1_000);
        }
    }
    let epoch = height / 6;
    db.shard_save_table(&table, epoch, height)?;
    let loaded = db.shard_load_table()?;
    anyhow::ensure!(
        loaded.compute_table_root() == table.compute_table_root(),
        "the shard table did not read back to its root"
    );
    let owed = loaded.owed();
    let positive: Vec<(String, u128)> = {
        let mut v: Vec<(String, u128)> = owed
            .iter()
            .filter(|(_, &m)| m > 0)
            .map(|(a, &m)| (a.clone(), m as u128))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    };
    let capped = ghost_pool::payout::select_shard_miner_work(&owed);
    let miners = if uncapped {
        positive.clone()
    } else {
        capped.clone()
    };

    // node_shares as the 5-4-3-2-1 split leaves them.
    let node_shares: Vec<([u8; 32], i32)> = fleet
        .iter()
        .zip([10, 10, 10, 8, 6, 5, 4, 2])
        .map(|(n, s)| (*n, s))
        .collect();
    let cutoff_base = 1_790_000_000i64;
    for (dh, list) in [
        (2u64, &miners[..miners.len() / 2]),
        (1, &miners[..]),
        (0, &miners[..]),
    ] {
        let h = height - dh;
        let cutoff = cutoff_base + (h as i64) * 600;
        let list = list.to_vec();
        db.upsert_payout_ledger_checkpoint(&PayoutLedgerCheckpointRecord {
            height: h,
            cutoff_ts: cutoff,
            ledger_root: ghost_pool::payout::compute_ledger_root(&list, &node_shares, cutoff, h),
            proposer_id: hex::encode(fleet[(h % 8) as usize]),
            active_node_count: 8,
            miner_payouts: list,
            node_shares: node_shares.clone(),
        })?;
    }

    // ── Kept tables: rounds, miners, shares, won blocks, node rewards at 0 ─────────────────
    let rounds = 24u64;
    for r in 0..rounds {
        let bh = height - rounds + r + 1;
        db.create_round(&RoundRecord {
            round_id: r + 1,
            block_height: bh,
            block_hash: None,
            start_time: cutoff_base + (bh as i64) * 600,
            end_time: Some(cutoff_base + (bh as i64) * 600 + 600),
            total_shares: 0,
            total_work: 0.0,
            winning_miner: None,
            found_by_node: None,
            payout_status: PayoutStatus::Active,
            subsidy_sats: None,
            tx_fees_sats: None,
        })?;
    }
    db.record_won_block(height - 7)?;
    for (i, a) in addrs.iter().enumerate().take(n_miners.min(2_000)) {
        db.upsert_miner(&MinerRecord {
            miner_id: hex::encode(&h32(&format!("np-flagday/{seed}/minerid/{i}"))[..20]),
            payout_address: a.clone(),
            first_seen: cutoff_base,
            last_seen: cutoff_base + (height as i64) * 600,
            connected_node: Some(hex::encode(me)),
            total_shares: 10,
            total_work: 10.0,
            blocks_won: 0,
            total_payouts_sats: 0,
            avg_hashrate_ths: 0.1,
        })?;
    }
    for s in 0..n_shares {
        let i = s % n_miners.clamp(1, 2_000);
        db.insert_share(&ShareRecord {
            id: None,
            round_id: rounds - (s as u64 % 4),
            miner_id: hex::encode(&h32(&format!("np-flagday/{seed}/minerid/{i}"))[..20]),
            difficulty: 65_536.0,
            work: 65_536.0,
            share_hash: hex::encode(h32(&format!(
                "np-flagday/{seed}/{}/share/{s}",
                hex::encode(me)
            ))),
            timestamp: cutoff_base + (height as i64) * 600 - (s as i64 % 3_600),
            received_by: hex::encode(me),
            valid: true,
        })?;
    }
    for n in &fleet {
        db.get_or_create_node_reward(&hex::encode(n))?;
    }

    // ── MPC lineage (raw, as the exporter's tests write it) ───────────────────────────────
    db.with_connection(|c| {
        c.execute_batch(
            "INSERT OR IGNORE INTO mpc_ceremony (id, contribution_count, current_params_hash, \
               is_ossified, updated_at) VALUES (1, 2, x'0102', 1, 1700000000);
             INSERT OR IGNORE INTO mpc_contributions VALUES \
               (1, 'aa', x'00', x'01', x'ee', 1, 1700000001), \
               (2, 'bb', x'01', x'02', x'ff', 1, 1700000002);
             INSERT OR IGNORE INTO mpc_verification_votes VALUES (1, 'bb', 1, x'aa', 1700000003);
             INSERT OR IGNORE INTO mpc_params_files VALUES (x'02', '/var/lib/ghost/mpc/2.bin', 10, 2, 1700000004);",
        )
        .map_err(|e| ghost_common::error::GhostError::Database(e.to_string()))
    })?;

    // ── Rows v65 must halt on ─────────────────────────────────────────────────────────────
    if dirty {
        db.insert_ghost_lock(&GhostLockRecord {
            lock_id: "11".repeat(32),
            owner_ghost_id: "ghost1flagday".into(),
            lock_pubkey: "02".to_string() + &"22".repeat(32),
            recovery_pubkey: "03".to_string() + &"33".repeat(32),
            denomination: "Small".into(),
            amount_sats: 100_000,
            timelock_tier: "Standard".into(),
            creation_height: (height - 100) as u32,
            recovery_height: (height + 4_000) as u32,
            state: GhostLockState::Active,
            funding_txid: Some("44".repeat(32)),
            funding_vout: Some(0),
            spend_txid: None,
            output_script: "5120".to_string() + &"55".repeat(32),
            jump_risk_tier: "Low".into(),
            next_jump_height: None,
            created_at: cutoff_base,
            updated_at: cutoff_base,
            source: "manual".into(),
            wraith_fee_sats: 0,
            key_index: Some(0),
        })?;
        db.insert_withdrawal_request_atomic(&WithdrawalRequest {
            id: None,
            ghost_id: "ghost1flagday".into(),
            lock_id: "11".repeat(32),
            destination_address: addrs[0].clone(),
            amount_sats: 99_000,
            fee_sats: 1_000,
            status: WithdrawalStatus::Pending,
            batch_id: None,
            l1_txid: None,
            settlement_class: "standard".into(),
            created_at: cutoff_base,
            updated_at: cutoff_base,
        })?;
        db.insert_l2_epoch(&ghost_storage::L2EpochRecord {
            epoch: 1,
            start_height: height - 60,
            end_height: None,
            initial_root: [0u8; 32],
            final_root: None,
            notes_migrated: 0,
            status: "active".into(),
        })?;
        db.insert_l2_note(1, 0, &h32("np-flagday/l2note"), height - 50)?;
        db.credit_node_reward(&hex::encode(fleet[1]), 12_345, 1)?;
    }
    db.checkpoint()?;

    let total: u128 = positive.iter().map(|m| m.1).sum();
    let in_cp: u128 = miners.iter().map(|m| m.1).sum();
    println!(
        "FIXTURE db={} node_id={} network={network} height={height} seed={seed} miners={n_miners} \
         kinds={kinds:?} shard_root={} positive_balances={} checkpoint_miners={} (live cap {}) \
         checkpoint_work={in_cp} of total_owed_work={total} ({:.4}%) uncapped={uncapped} dirty={dirty} \
         shares={n_shares}",
        db_path.display(),
        identity.node_id_hex(),
        hex::encode(loaded.compute_table_root()),
        positive.len(),
        miners.len(),
        capped.len(),
        in_cp as f64 * 100.0 / total.max(1) as f64,
    );
    Ok(())
}
