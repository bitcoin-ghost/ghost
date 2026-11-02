//|======================================================================================================================|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: node_pool_genesis_export.rs                                                                                    |
//|======================================================================================================================|

//! The cutover's ledger export, read and checked as a share-chain genesis table (plan Phase 4).
//!
//! Every program that starts a relay on the cutover's genesis table builds that table here, from
//! the published export, so they cannot disagree on it: pool_sv2's import (`--np-import-genesis`)
//! and `ghost-audit`'s own relay node (`--genesis-export`).
//!
//! An export directory holds `ledger-export.bin` and `ledger-export.json` as `ghost-mining
//! --np-export` writes them (`docs/LEDGER_EXPORT.md` on `feat/ledger-export`). The checks, every
//! one refusing:
//!
//! 1. `sha256(ledger-export.bin)` must equal the expected digest, the one the fleet compared and
//!    published. The JSON's `digest_sha256` must equal it too.
//! 2. The binary must start with `GhostLedgerExport/v1`, its network and its height (the stable
//!    prefix of the format), and must end with the genesis table exactly as the JSON lists it
//!    followed by the 96-byte totals block. The rows are therefore covered by the digest; nothing
//!    between the prefix and the rows (the source checkpoint, the rate, the miner list) is read,
//!    so the table does not depend on which source the export was taken from.
//! 3. The JSON's network must equal the binary's, and must be a node pool network.
//! 4. Rows strictly ascending by script, no empty script, every amount at most `i128::MAX` face
//!    units. Units are taken as they are: the export already converted work to `2^-32` sat.
//! 5. **`queue_since`**: every row owed at least the payout floor ([`PAYOUT_FLOOR_FACE`](crate::node_pool_constants::PAYOUT_FLOOR_FACE)) gets
//!    `queue_since = H`, the export's height (the freeze height); rows below the floor get none.
//!    Derived, not a parameter: every node reading the same digest builds the same table and the
//!    same `table_root`, with nothing to mistype.
//!
//! The result's [`GenesisExport::table_root`](crate::node_pool_genesis_export::GenesisExport::table_root) is the digest a node pins
//! (`genesis_table_digest`, [`crate::node_pool_network::NetworkStart::check_table`]).

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::canonical_payout::{table_root, Balance, Table};
use crate::node_pool_constants::PAYOUT_FLOOR_FACE;
use crate::node_pool_network::NodePoolNetwork;

/// The export binary's magic, its first bytes.
pub const LEDGER_MAGIC: &[u8] = b"GhostLedgerExport/v1";

/// The export binary's file name in the export directory.
pub const EXPORT_BIN: &str = "ledger-export.bin";

/// The export JSON's file name in the export directory.
pub const EXPORT_JSON: &str = "ledger-export.json";

/// Bytes after the genesis rows: six `u128` totals.
const TOTALS_LEN: usize = 6 * 16;

/// What is read from the JSON: only what is needed, so the rest of the format can change.
#[derive(serde::Deserialize)]
struct ExportJson {
    digest_sha256: String,
    network: String,
    genesis_table: Vec<ExportRow>,
}

#[derive(serde::Deserialize)]
struct ExportRow {
    script_hex: String,
    face_units: String,
}

/// An export, checked and turned into a genesis table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisExport {
    /// sha256 of `ledger-export.bin`.
    pub digest: [u8; 32],
    /// The network as the export names it.
    pub network_name: String,
    /// That network.
    pub network: NodePoolNetwork,
    /// The export's height: the freeze height.
    pub height: u64,
    /// The `queue_since` given to rows at or above the floor (= `height`).
    pub queue_since: u32,
    /// The genesis table.
    pub table: Table,
    /// Its `table_root`.
    pub table_root: [u8; 32],
}

fn take<'a>(b: &'a [u8], at: &mut usize, n: usize, what: &str) -> Result<&'a [u8], String> {
    let end = at
        .checked_add(n)
        .filter(|e| *e <= b.len())
        .ok_or_else(|| format!("{EXPORT_BIN} ends inside {what}"))?;
    let s = &b[*at..end];
    *at = end;
    Ok(s)
}

/// 64 hex characters as 32 bytes.
pub fn hex32(s: &str, what: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s.trim()).map_err(|e| format!("{what}: {e}"))?;
    v.try_into().map_err(|_| format!("{what}: not 32 bytes"))
}

/// The rows as the binary encodes them: `u32 n`, then per row `u16 len || script || u128 face`.
pub fn encode_rows(rows: &[(Vec<u8>, u128)]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let n = u32::try_from(rows.len()).map_err(|_| "too many genesis rows".to_string())?;
    out.extend_from_slice(&n.to_be_bytes());
    for (s, f) in rows {
        let len = u16::try_from(s.len()).map_err(|_| format!("script of {} bytes", s.len()))?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(s);
        out.extend_from_slice(&f.to_be_bytes());
    }
    Ok(out)
}

/// Build the genesis table from the export's rows: check 4 and the `queue_since` rule (5).
pub fn genesis_table(rows: &[(Vec<u8>, u128)], queue_since: u32) -> Result<Table, String> {
    let mut t = Table::new();
    let mut prev: Option<&Vec<u8>> = None;
    for (script, face) in rows {
        if script.is_empty() {
            return Err("a genesis row has an empty script".to_string());
        }
        if prev.is_some_and(|p| p >= script) {
            return Err(format!(
                "genesis rows are not strictly ascending by script at {}",
                hex::encode(script)
            ));
        }
        prev = Some(script);
        let owed = i128::try_from(*face).map_err(|_| {
            format!(
                "{} owes {face} face units, above i128::MAX",
                hex::encode(script)
            )
        })?;
        t.insert(
            script.clone(),
            Balance {
                owed,
                queue_since: (owed >= PAYOUT_FLOOR_FACE).then_some(queue_since),
            },
        );
    }
    Ok(t)
}

/// Check an export against `expected` (checks 1-5) and build its table.
pub fn parse_export(bin: &[u8], json: &[u8], expected: &[u8; 32]) -> Result<GenesisExport, String> {
    let digest: [u8; 32] = Sha256::digest(bin).into();
    if &digest != expected {
        return Err(format!(
            "{EXPORT_BIN} has sha256 {}, not the expected {}: this is not the published export",
            hex::encode(digest),
            hex::encode(expected)
        ));
    }
    let j: ExportJson =
        serde_json::from_slice(json).map_err(|e| format!("{EXPORT_JSON} does not parse: {e}"))?;
    if &hex32(&j.digest_sha256, "digest_sha256")? != expected {
        return Err(format!(
            "{EXPORT_JSON} names digest {}, not the expected {}: the two files are not one export",
            j.digest_sha256.trim(),
            hex::encode(expected)
        ));
    }

    let mut at = 0usize;
    if take(bin, &mut at, LEDGER_MAGIC.len(), "the magic")? != LEDGER_MAGIC {
        return Err(format!(
            "{EXPORT_BIN} does not start with GhostLedgerExport/v1"
        ));
    }
    let len = u16::from_be_bytes(
        take(bin, &mut at, 2, "the network")?
            .try_into()
            .unwrap_or([0; 2]),
    );
    let network_name = std::str::from_utf8(take(bin, &mut at, len as usize, "the network")?)
        .map_err(|_| format!("{EXPORT_BIN}: the network is not UTF-8"))?
        .to_string();
    let height = u64::from_be_bytes(
        take(bin, &mut at, 8, "the height")?
            .try_into()
            .unwrap_or([0; 8]),
    );
    if j.network != network_name {
        return Err(format!(
            "{EXPORT_JSON} says network {:?} and {EXPORT_BIN} says {network_name:?}",
            j.network
        ));
    }
    let network = NodePoolNetwork::parse(&network_name).map_err(|e| format!("the export's {e}"))?;
    let queue_since = u32::try_from(height)
        .map_err(|_| format!("the export's height {height} does not fit a Bitcoin height"))?;

    let mut rows = Vec::with_capacity(j.genesis_table.len());
    for r in &j.genesis_table {
        let script = hex::decode(r.script_hex.trim())
            .map_err(|e| format!("genesis row script_hex {:?}: {e}", r.script_hex))?;
        let face: u128 = r
            .face_units
            .trim()
            .parse()
            .map_err(|e| format!("genesis row face_units {:?}: {e}", r.face_units))?;
        rows.push((script, face));
    }
    let enc = encode_rows(&rows)?;
    let tail = enc.len() + TOTALS_LEN;
    if bin.len() < at + tail || bin[bin.len() - tail..bin.len() - TOTALS_LEN] != enc[..] {
        return Err(format!(
            "the genesis table in {EXPORT_JSON} ({} rows) is not the one in {EXPORT_BIN}: the \
             JSON's rows must be exactly the rows the digest covers",
            rows.len()
        ));
    }
    let table = genesis_table(&rows, queue_since)?;
    Ok(GenesisExport {
        digest,
        network_name,
        network,
        height,
        queue_since,
        table_root: table_root(&table),
        table,
    })
}

/// Read and check the export in `dir`.
pub fn read_export(dir: &Path, expected: &[u8; 32]) -> Result<GenesisExport, String> {
    let read = |name: &str| {
        let p = dir.join(name);
        std::fs::read(&p).map_err(|e| format!("cannot read {}: {e}", p.display()))
    };
    parse_export(&read(EXPORT_BIN)?, &read(EXPORT_JSON)?, expected)
}

/// An export in the byte layout `ghost-mining --np-export` writes, with filler where the checks
/// above do not look (checkpoint, rate, miners) and `rows` and the totals where they do; the JSON
/// lists `json_rows`. Returns `(bin, json, sha256(bin))`. For tests of every reader.
#[doc(hidden)]
pub fn sample_export(
    network: &str,
    height: u64,
    rows: &[(Vec<u8>, u128)],
    json_rows: &[(Vec<u8>, u128)],
) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let mut b = Vec::new();
    b.extend_from_slice(LEDGER_MAGIC);
    b.extend_from_slice(&(network.len() as u16).to_be_bytes());
    b.extend_from_slice(network.as_bytes());
    b.extend_from_slice(&height.to_be_bytes());
    b.extend_from_slice(&1_700_000_000i64.to_be_bytes()); // cutoff_ts
    b.extend_from_slice(&[0x11; 96]); // ledger_root, adopted_root, canonical_payout_sha256
    b.extend_from_slice(&1u32.to_be_bytes()); // one node
    b.extend_from_slice(&[0x22; 32]);
    b.extend_from_slice(&5i32.to_be_bytes());
    for v in [1u128, 1, 1_000_000, 1u128 << 32] {
        b.extend_from_slice(&v.to_be_bytes()); // rate
    }
    b.extend_from_slice(&(rows.len() as u32).to_be_bytes()); // miners: one per row
    for (i, (s, f)) in rows.iter().enumerate() {
        let addr = format!("addr{i}");
        b.extend_from_slice(&(addr.len() as u16).to_be_bytes());
        b.extend_from_slice(addr.as_bytes());
        b.extend_from_slice(&(s.len() as u16).to_be_bytes());
        b.extend_from_slice(s);
        b.extend_from_slice(&(i as u128 + 1).to_be_bytes());
        b.extend_from_slice(&f.to_be_bytes());
    }
    b.extend_from_slice(&encode_rows(rows).unwrap_or_default());
    let total: u128 = rows.iter().map(|r| r.1).sum();
    for v in [3u128, total, 0, 0, 1, total] {
        b.extend_from_slice(&v.to_be_bytes());
    }
    let digest: [u8; 32] = Sha256::digest(&b).into();
    let json = serde_json::json!({
        "format": "ghost-ledger-export/v1",
        "digest_sha256": hex::encode(digest),
        "network": network,
        "checkpoint": { "height": height },
        "genesis_table": json_rows.iter().map(|(s, f)| serde_json::json!({
            "script_hex": hex::encode(s),
            "face_units": f.to_string(),
        })).collect::<Vec<_>>(),
    });
    (
        b,
        serde_json::to_vec_pretty(&json).unwrap_or_default(),
        digest,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_pool_constants::FACE_PER_SAT;

    fn rows() -> Vec<(Vec<u8>, u128)> {
        let mut r = vec![
            (vec![0x00, 0x14, 0xAA], 5_000 * FACE_PER_SAT as u128 + 7),
            (vec![0x51, 0x20, 0xBB], PAYOUT_FLOOR_FACE as u128),
            (vec![0x51, 0x20, 0xCC], 999 * FACE_PER_SAT as u128),
        ];
        r.sort();
        r
    }

    #[test]
    fn a_sample_export_parses_to_its_rows_with_queue_since_at_the_floor() {
        let (bin, json, d) = sample_export("regtest", 974_500, &rows(), &rows());
        let e = parse_export(&bin, &json, &d).unwrap();
        assert_eq!(e.network, NodePoolNetwork::Regtest);
        assert_eq!((e.height, e.queue_since), (974_500, 974_500));
        assert_eq!(e.table.len(), 3);
        assert_eq!(e.table_root, table_root(&e.table));
        for (s, f) in rows() {
            let b = e.table[&s];
            assert_eq!(b.owed, f as i128);
            assert_eq!(b.queue_since.is_some(), b.owed >= PAYOUT_FLOOR_FACE);
        }
    }

    #[test]
    fn a_wrong_digest_or_disagreeing_files_are_refused() {
        let (bin, json, d) = sample_export("regtest", 7, &rows(), &rows());
        let mut other = d;
        other[0] ^= 1;
        assert!(parse_export(&bin, &json, &other)
            .unwrap_err()
            .contains("not the published export"));
        let mut fewer = rows();
        fewer.pop();
        let (bin, json, d) = sample_export("regtest", 7, &rows(), &fewer);
        assert!(parse_export(&bin, &json, &d)
            .unwrap_err()
            .contains("not the one in"));
        assert!(parse_export(&bin, b"{", &d)
            .unwrap_err()
            .contains("does not parse"));
    }
}
