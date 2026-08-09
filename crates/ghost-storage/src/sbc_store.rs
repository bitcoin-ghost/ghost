//! Persistence for the share-batch chain (WP-5 shadow run).
//!
//! See `docs/SHARE_BATCH_CHAIN.md`. Three things must survive a restart, and nothing else:
//!
//! - **balances** — the payable state, ~68 rows. This is the whole point: the model exists because
//!   "payable state is O(shares), not O(addresses)", and here it is O(addresses).
//! - **the adopted chain, bounded** — `MAX(seq)` is the head a new batch is judged against, and the
//!   recent entries answer a lagging peer's sync. Not history for its own sake.
//! - **quarantine** — release is operator-only by design, so it cannot live in memory.
//!
//! Shares are NOT archived here. They travel inside a batch so new work can enter the chain, but
//! once folded the balance carries the value forward.
//!
//! Dark: nothing wires these into a runtime path yet.

use std::collections::BTreeMap;

use rusqlite::params;
use sha2::{Digest, Sha256};

use ghost_common::error::{GhostError, GhostResult};

use crate::database::Database;

/// How many adopted batches to retain.
///
/// This bounds both the sync window (how far a node can fall behind and still catch up without a
/// full replay) and the disk cost of the chain. 4,096 at the ~30 s proposal cadence is roughly 34
/// hours — comfortably longer than the 4-day outage this fleet has actually had would need at its
/// worst, and short enough that the table stays small.
///
/// Deliberately generous: a node that falls outside the window cannot resync from a peer and needs
/// a full genesis replay, which is the expensive failure this parameter exists to avoid. Storage is
/// the cheap side of that trade.
pub const BATCH_RETENTION: u64 = 4_096;

/// Deterministic lookup key for a payout address.
///
/// NOT the ciphertext: `encrypt_sensitive` draws a fresh random nonce per call, so the same address
/// encrypts differently every time and a ciphertext key could never be matched — every write would
/// insert a new row and a miner's balance would scatter across duplicates instead of accumulating.
pub fn address_key(plaintext: &str) -> Vec<u8> {
    Sha256::digest(plaintext.as_bytes()).to_vec()
}

/// The chain head: what a newly-arrived batch must build on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainHead {
    pub seq: u64,
    pub batch_hash: [u8; 32],
    pub state_root: [u8; 32],
    /// When the PROPOSER closed this batch. Advisory — it says nothing about when this node
    /// adopted it, and for genesis it is the converted checkpoint's cutoff, which can be days old.
    pub close_ts: i64,
    /// When THIS node adopted the batch.
    ///
    /// Distinct from `close_ts` and not interchangeable with it. The next sequence opens when this
    /// batch is adopted, so this is what the stall-escalation clock must run from. Using
    /// `close_ts` instead made escalation start from the genesis checkpoint's cutoff. Measured on
    /// ghost-vm8: cutoff 1786228093, adopted 1786260566 — a 32,473 s gap, so escalation read 416
    /// steps where it should have read ~34. The rota sat permanently escalated, rotating the turn
    /// every 90 s instead of giving a proposer a stable one.
    pub finalised_at: i64,
}

fn blob32(v: Vec<u8>, what: &str) -> GhostResult<[u8; 32]> {
    <[u8; 32]>::try_from(v.as_slice())
        .map_err(|_| GhostError::Database(format!("{what} is not 32 bytes")))
}

impl Database {
    /// Load the running balances, decrypted into the form the fold uses.
    ///
    /// Returns `BTreeMap<plaintext address, micro-work>` — exactly `fold_shares`'s type. The state
    /// root commits to PLAINTEXT addresses, so plaintext is what has to reach the fold; the rows
    /// are keyed by hash purely so they can be looked up.
    ///
    /// A row whose address cannot be decrypted is an ERROR, not a skip. Silently dropping it would
    /// remove a miner's balance from the state root, and every node that could decrypt it would
    /// then compute a different root — a divergence that looks like consensus failure rather than
    /// like the key problem it actually is.
    pub fn sbc_load_balances(&self) -> GhostResult<BTreeMap<String, i64>> {
        let rows: Vec<(String, i64)> = self.with_connection(|conn| {
            let mut stmt = conn
                .prepare("SELECT address_enc, micro_work FROM sbc_balances")
                .map_err(|e| GhostError::Database(e.to_string()))?;
            let out = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(out)
        })?;

        let mut balances = BTreeMap::new();
        for (enc, micro) in rows {
            let plain = self.decrypt_address(&enc)?;
            balances.insert(plain, micro);
        }
        Ok(balances)
    }

    /// Replace the balances with the state after `seq`.
    ///
    /// One transaction: a partially-written balance set is a state root nothing can reproduce, and
    /// a crash mid-write would leave the node silently disagreeing with the fleet forever.
    ///
    /// Addresses absent from `balances` are DELETED rather than left behind. A stale row would keep
    /// contributing to `sbc_load_balances` and therefore to the next state root, which is how a
    /// node ends up internally consistent and externally wrong.
    pub fn sbc_save_balances(&self, balances: &BTreeMap<String, i64>, seq: u64) -> GhostResult<()> {
        let encrypted: Vec<(Vec<u8>, String, i64)> = balances
            .iter()
            .map(|(addr, micro)| Ok((address_key(addr), self.encrypt_address(addr)?, *micro)))
            .collect::<GhostResult<Vec<_>>>()?;

        self.with_connection(|conn| {
            conn.execute_batch("BEGIN IMMEDIATE")
                .map_err(|e| GhostError::Database(e.to_string()))?;

            let result = (|| -> GhostResult<()> {
                conn.execute("DELETE FROM sbc_balances", [])
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                for (key, enc, micro) in &encrypted {
                    conn.execute(
                        "INSERT INTO sbc_balances (address_hash, address_enc, micro_work, \
                         updated_seq) VALUES (?1, ?2, ?3, ?4)",
                        params![key, enc, micro, seq as i64],
                    )
                    .map_err(|e| GhostError::Database(e.to_string()))?;
                }
                Ok(())
            })();

            match result {
                Ok(()) => conn
                    .execute_batch("COMMIT")
                    .map_err(|e| GhostError::Database(e.to_string())),
                Err(e) => {
                    let _ = conn.execute_batch("ROLLBACK");
                    Err(e)
                }
            }
        })
    }

    /// The highest adopted batch, or `None` before genesis.
    pub fn sbc_head(&self) -> GhostResult<Option<ChainHead>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT seq, batch_hash, state_root, close_ts, finalised_at \
                     FROM sbc_batches ORDER BY seq DESC LIMIT 1",
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            let mut rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, i64>(4)?,
                    ))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?;

            match rows.next() {
                None => Ok(None),
                Some(row) => {
                    let (seq, hash, root, close_ts, finalised_at) =
                        row.map_err(|e| GhostError::Database(e.to_string()))?;
                    Ok(Some(ChainHead {
                        seq: seq as u64,
                        batch_hash: blob32(hash, "batch_hash")?,
                        state_root: blob32(root, "state_root")?,
                        close_ts,
                        finalised_at,
                    }))
                }
            }
        })
    }

    /// Record an adopted batch, and prune outside the retention window.
    ///
    /// `batch_json` is stored verbatim so a sync response is served exactly as adopted. A
    /// re-serialisation that differs by one byte is a batch hash that no longer verifies, and the
    /// peer would read a correct answer as a fault.
    ///
    /// Idempotent on `seq`: adopting the same batch twice must not fail, because finalisation can
    /// be observed more than once and the second observation is not an error. A DIFFERENT batch at
    /// the same seq is rejected — that is equivocation, and silently overwriting the chain head is
    /// how a fork becomes invisible.
    #[allow(clippy::too_many_arguments)]
    pub fn sbc_store_batch(
        &self,
        seq: u64,
        batch_hash: [u8; 32],
        prev_hash: [u8; 32],
        proposer: [u8; 32],
        close_ts: i64,
        state_root: [u8; 32],
        share_count: u32,
        batch_json: &str,
        now: i64,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            let existing: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT batch_hash FROM sbc_batches WHERE seq = ?1",
                    params![seq as i64],
                    |r| r.get(0),
                )
                .ok();

            if let Some(have) = existing {
                return if have == batch_hash.to_vec() {
                    Ok(())
                } else {
                    Err(GhostError::Database(format!(
                        "seq {seq} already holds a different batch — refusing to overwrite \
                         (equivocation, not a retry)"
                    )))
                };
            }

            conn.execute(
                "INSERT INTO sbc_batches (seq, batch_hash, prev_hash, proposer, close_ts, \
                 state_root, share_count, batch_json, finalised_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    seq as i64,
                    batch_hash.to_vec(),
                    prev_hash.to_vec(),
                    proposer.to_vec(),
                    close_ts,
                    state_root.to_vec(),
                    share_count as i64,
                    batch_json,
                    now
                ],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;

            // Prune below the window. Uses this batch's seq rather than MAX(seq) so the retained
            // span is measured from the head being written, not from whatever happens to be
            // highest — they differ while a node is catching up.
            let floor = seq.saturating_sub(BATCH_RETENTION);
            if floor > 0 {
                conn.execute(
                    "DELETE FROM sbc_batches WHERE seq < ?1",
                    params![floor as i64],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            }
            Ok(())
        })
    }

    /// The adopted batch at `seq`, verbatim, for answering a sync request.
    pub fn sbc_get_batch(&self, seq: u64) -> GhostResult<Option<String>> {
        self.with_connection(|conn| {
            Ok(conn
                .query_row(
                    "SELECT batch_json FROM sbc_batches WHERE seq = ?1",
                    params![seq as i64],
                    |r| r.get::<_, String>(0),
                )
                .ok())
        })
    }

    /// Quarantine a peer. Idempotent — the first reason is kept, since it is the one that was
    /// actually decided on evidence.
    pub fn sbc_quarantine(
        &self,
        node_id: [u8; 32],
        reason: &str,
        batch_seq: Option<u64>,
        now: i64,
    ) -> GhostResult<()> {
        self.with_connection(|conn| {
            conn.execute(
                "INSERT INTO sbc_quarantine (node_id, reason, batch_seq, quarantined_at) \
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT(node_id) DO NOTHING",
                params![node_id.to_vec(), reason, batch_seq.map(|s| s as i64), now],
            )
            .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Every quarantined peer, for rebuilding the in-memory set at startup.
    pub fn sbc_quarantined(&self) -> GhostResult<Vec<([u8; 32], String)>> {
        self.with_connection(|conn| {
            let mut stmt = conn
                .prepare("SELECT node_id, reason FROM sbc_quarantine")
                .map_err(|e| GhostError::Database(e.to_string()))?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?))
                })
                .map_err(|e| GhostError::Database(e.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| GhostError::Database(e.to_string()))?;
            rows.into_iter()
                .map(|(id, reason)| Ok((blob32(id, "node_id")?, reason)))
                .collect()
        })
    }

    /// Release a peer. Operator-only by design — an automatic timer would let a Byzantine node
    /// misbehave, wait it out, and repeat indefinitely.
    pub fn sbc_release(&self, node_id: [u8; 32]) -> GhostResult<bool> {
        self.with_connection(|conn| {
            let n = conn
                .execute(
                    "DELETE FROM sbc_quarantine WHERE node_id = ?1",
                    params![node_id.to_vec()],
                )
                .map_err(|e| GhostError::Database(e.to_string()))?;
            Ok(n > 0)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Database {
        let db = Database::in_memory().expect("in-memory db");
        db.set_encryption_key([0x42u8; 32]);
        db
    }

    fn bal(pairs: &[(&str, i64)]) -> BTreeMap<String, i64> {
        pairs.iter().map(|(a, w)| (a.to_string(), *w)).collect()
    }

    /// Balances must round-trip through encryption unchanged.
    ///
    /// The state root commits to plaintext addresses and i64 micro-work. If either side of the
    /// round trip alters a value, this node's root diverges from the fleet's while every local
    /// check still passes — the hardest kind of fault to attribute.
    #[test]
    fn balances_round_trip_through_encryption() {
        let db = db();
        let before = bal(&[
            (
                "bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492",
                56_331_582_763_867_633,
            ),
            ("148WRjKfSSo911CYRLzeyYm1QKhy7kCXTN", 478_353_203),
            ("bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h", -42),
        ]);

        db.sbc_save_balances(&before, 7).expect("save");
        let after = db.sbc_load_balances().expect("load");

        assert_eq!(
            before, after,
            "balances must survive the round trip exactly"
        );
    }

    /// A save must REPLACE, not merge. A balance that has gone to zero and been dropped from the
    /// map must not linger in the table, or it keeps contributing to the next state root.
    #[test]
    fn saving_replaces_rather_than_merges() {
        let db = db();
        db.sbc_save_balances(&bal(&[("addr_a", 10), ("addr_b", 20)]), 1)
            .expect("first save");
        db.sbc_save_balances(&bal(&[("addr_a", 30)]), 2)
            .expect("second save");

        let after = db.sbc_load_balances().expect("load");
        assert_eq!(
            after,
            bal(&[("addr_a", 30)]),
            "addr_b must be gone, not stale"
        );
    }

    /// The same address must always produce the same key, or a lookup can never match.
    #[test]
    fn address_key_is_deterministic_unlike_the_ciphertext() {
        let db = db();
        let addr = "bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492";

        assert_eq!(address_key(addr), address_key(addr));
        assert_ne!(address_key(addr), address_key("bc1qother"));

        // The reason the key is a hash and not the ciphertext.
        let a = db.encrypt_address(addr).expect("enc a");
        let b = db.encrypt_address(addr).expect("enc b");
        assert_ne!(
            a, b,
            "ciphertext is nonce-randomised, so it cannot be a key"
        );
    }

    /// Re-adopting the same batch is a retry. Adopting a DIFFERENT batch at the same sequence is
    /// equivocation, and must not silently overwrite the chain.
    #[test]
    fn a_different_batch_at_the_same_seq_is_refused() {
        let db = db();
        db.sbc_store_batch(
            1, [1u8; 32], [0u8; 32], [9u8; 32], 100, [2u8; 32], 3, "{}", 0,
        )
        .expect("first adopt");

        db.sbc_store_batch(
            1, [1u8; 32], [0u8; 32], [9u8; 32], 100, [2u8; 32], 3, "{}", 0,
        )
        .expect("re-adopting the same batch is idempotent, not an error");

        let err = db
            .sbc_store_batch(
                1,
                [0xEEu8; 32],
                [0u8; 32],
                [9u8; 32],
                100,
                [3u8; 32],
                3,
                "{}",
                0,
            )
            .expect_err("a different batch at the same seq must be refused");
        assert!(
            format!("{err}").contains("equivocation"),
            "the refusal must name what it is: {err}"
        );

        // The original must still be the one on record.
        let head = db.sbc_head().expect("head").expect("some head");
        assert_eq!(head.batch_hash, [1u8; 32]);
    }

    /// `close_ts` and `finalised_at` are different facts and must not be conflated.
    ///
    /// `close_ts` is when the PROPOSER closed the batch; `finalised_at` is when THIS node adopted
    /// it. The next sequence opens on adoption, so the stall-escalation clock runs from
    /// `finalised_at`. Reading `close_ts` instead started escalation from the genesis checkpoint's
    /// cutoff, which on ghost-vm8 was 32,473 s (9 h) before adoption — leaving the rota permanently
    /// escalated and rotating the turn every 90 s instead of giving a proposer a stable one.
    #[test]
    fn the_head_reports_adoption_time_separately_from_close_time() {
        let db = db();
        let close_ts = 1_786_228_093; // a genesis checkpoint's cutoff: days in the past
        let adopted_at = 1_786_470_000; // when this node actually took it

        db.sbc_store_batch(
            0, [1u8; 32], [0u8; 32], [0u8; 32], close_ts, [2u8; 32], 0, "{}", adopted_at,
        )
        .expect("adopt");

        let head = db.sbc_head().expect("head").expect("some");
        assert_eq!(head.close_ts, close_ts, "close_ts is the proposer's claim");
        assert_eq!(
            head.finalised_at, adopted_at,
            "finalised_at is when we adopted it — the escalation clock reads THIS"
        );
        assert_ne!(
            head.close_ts, head.finalised_at,
            "the two must stay distinguishable; conflating them is the defect"
        );
    }

    /// The head is the highest sequence, and is `None` before genesis.
    #[test]
    fn head_is_the_highest_seq() {
        let db = db();
        assert_eq!(db.sbc_head().expect("head"), None, "no head before genesis");

        for seq in [1u64, 2, 3] {
            db.sbc_store_batch(
                seq,
                [seq as u8; 32],
                [0u8; 32],
                [9u8; 32],
                100 + seq as i64,
                [seq as u8; 32],
                0,
                "{}",
                0,
            )
            .expect("adopt");
        }
        let head = db.sbc_head().expect("head").expect("some");
        assert_eq!(head.seq, 3);
        assert_eq!(head.close_ts, 103);
    }

    /// Pruning must keep the retention window and drop only what is outside it — including the
    /// head itself, which must never be pruned or the chain loses the parent it judges against.
    #[test]
    fn pruning_keeps_the_window_and_never_the_head() {
        let db = db();
        let head_seq = BATCH_RETENTION + 5;

        for seq in [1u64, 2, head_seq - 1, head_seq] {
            db.sbc_store_batch(
                seq,
                [(seq % 251) as u8; 32],
                [0u8; 32],
                [9u8; 32],
                100,
                [1u8; 32],
                0,
                "{}",
                0,
            )
            .expect("adopt");
        }

        assert!(
            db.sbc_get_batch(1).expect("get").is_none(),
            "seq 1 is outside the window"
        );
        assert!(
            db.sbc_get_batch(2).expect("get").is_none(),
            "seq 2 is outside the window"
        );
        assert!(
            db.sbc_get_batch(head_seq).expect("get").is_some(),
            "the head must survive"
        );
        assert_eq!(db.sbc_head().expect("head").expect("some").seq, head_seq);
    }

    /// A sync response is served verbatim — a re-serialisation differing by one byte is a batch
    /// hash that no longer verifies.
    #[test]
    fn a_batch_is_served_back_byte_for_byte() {
        let db = db();
        let json = r#"{"seq":4,"shares":[{"work":1.5}],"note":"spacing  matters"}"#;
        db.sbc_store_batch(
            4, [4u8; 32], [0u8; 32], [9u8; 32], 100, [5u8; 32], 1, json, 0,
        )
        .expect("adopt");
        assert_eq!(db.sbc_get_batch(4).expect("get").as_deref(), Some(json));
    }

    /// Quarantine outlives the process, keeps its original reason, and releases only on request.
    #[test]
    fn quarantine_is_idempotent_and_operator_released() {
        let db = db();
        db.sbc_quarantine([7u8; 32], "wrong state root", Some(9), 0)
            .expect("q");
        db.sbc_quarantine([7u8; 32], "some later reason", Some(11), 5)
            .expect("q again");

        let all = db.sbc_quarantined().expect("list");
        assert_eq!(all.len(), 1, "quarantining twice must not duplicate");
        assert_eq!(
            all[0].1, "wrong state root",
            "the first reason is the one decided on evidence"
        );

        assert!(db.sbc_release([7u8; 32]).expect("release"));
        assert!(db.sbc_quarantined().expect("list").is_empty());
        assert!(
            !db.sbc_release([7u8; 32]).expect("release again"),
            "releasing twice is false"
        );
    }
}
