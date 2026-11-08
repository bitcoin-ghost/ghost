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
//| FILE: job.rs                                                                                                         |
//|======================================================================================================================|

//! A mining job as the miner receives it, turned back into the coinbase it would hash.
//!
//! An SV1 `mining.notify` carries the coinbase in two halves around the extranonce. The auditor
//! fills the extranonce with its subscription's `extranonce1` and zeros for `extranonce2`: the
//! outputs, and the BIP34 height sit outside the extranonce, so the bytes it
//! fills in change nothing that is checked.

use bitcoin::consensus::deserialize;
use bitcoin::Transaction;
use serde_json::Value;

/// One job, decoded.
#[derive(Debug, Clone)]
pub struct Job {
    /// The job id the node gave it.
    pub job_id: String,
    /// The header's `prev_hash`, internal byte order.
    pub prev_hash: [u8; 32],
    /// The coinbase the miner would hash (non-witness serialization), extranonce filled.
    pub coinbase: Transaction,
    /// Its serialized size, the bytes the miner's firmware must hold.
    pub coinbase_bytes: usize,
    /// Merkle branch from the coinbase txid to the header's merkle root, internal byte order.
    pub merkle_branch: Vec<[u8; 32]>,
    /// Header version.
    pub version: u32,
    /// Header bits.
    pub bits: u32,
    /// Header time.
    pub time: u32,
    /// The share difficulty in force when the job arrived, if the node sent one.
    pub difficulty: Option<f64>,
}

/// An SV1 `prev_hash` (each 32-bit word of the internal byte order written big-endian) back to
/// internal byte order.
pub fn sv1_prev_hash(s: &str) -> Result<[u8; 32], String> {
    let b: [u8; 32] = hex::decode(s)
        .map_err(|e| format!("prev_hash: {e}"))?
        .try_into()
        .map_err(|_| "prev_hash is not 32 bytes".to_string())?;
    let mut out = [0u8; 32];
    for (o, i) in out.chunks_mut(4).zip(b.chunks(4)) {
        o.copy_from_slice(&[i[3], i[2], i[1], i[0]]);
    }
    Ok(out)
}

/// The SV1 encoding of an internal-order `prev_hash` ([`sv1_prev_hash`] reversed).
pub fn to_sv1_prev_hash(h: &[u8; 32]) -> String {
    let mut out = [0u8; 32];
    for (o, i) in out.chunks_mut(4).zip(h.chunks(4)) {
        o.copy_from_slice(&[i[3], i[2], i[1], i[0]]);
    }
    hex::encode(out)
}

/// A hash in display byte order (as block explorers and `bitcoin-cli` print it).
pub fn display_hex(h: &[u8; 32]) -> String {
    let mut be = *h;
    be.reverse();
    hex::encode(be)
}

fn str_at<'a>(p: &'a [Value], i: usize, what: &str) -> Result<&'a str, String> {
    p.get(i)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("mining.notify has no {what}"))
}

fn hex_u32(s: &str, what: &str) -> Result<u32, String> {
    u32::from_str_radix(s, 16).map_err(|e| format!("{what}: {e}"))
}

impl Job {
    /// Decode `mining.notify` params `[job_id, prev_hash, coinb1, coinb2, merkle_branch, version,
    /// nbits, ntime, clean_jobs]` for a subscription with `extranonce1` and an `extranonce2`
    /// of `extranonce2_size` bytes.
    pub fn from_sv1_notify(
        params: &[Value],
        extranonce1: &[u8],
        extranonce2_size: usize,
        difficulty: Option<f64>,
    ) -> Result<Job, String> {
        let job_id = str_at(params, 0, "job id")?.to_string();
        let prev_hash = sv1_prev_hash(str_at(params, 1, "prev_hash")?)?;
        let coinb1 =
            hex::decode(str_at(params, 2, "coinb1")?).map_err(|e| format!("coinb1: {e}"))?;
        let coinb2 =
            hex::decode(str_at(params, 3, "coinb2")?).map_err(|e| format!("coinb2: {e}"))?;
        let merkle_branch = params
            .get(4)
            .and_then(Value::as_array)
            .ok_or("mining.notify has no merkle branch")?
            .iter()
            .map(|v| {
                let s = v.as_str().ok_or("merkle branch entry is not a string")?;
                hex::decode(s)
                    .map_err(|e| format!("merkle branch: {e}"))?
                    .try_into()
                    .map_err(|_| "merkle branch entry is not 32 bytes".to_string())
            })
            .collect::<Result<Vec<[u8; 32]>, String>>()?;
        let version = hex_u32(str_at(params, 5, "version")?, "version")?;
        let bits = hex_u32(str_at(params, 6, "nbits")?, "nbits")?;
        let time = hex_u32(str_at(params, 7, "ntime")?, "ntime")?;
        let mut raw = coinb1;
        raw.extend_from_slice(extranonce1);
        raw.extend(std::iter::repeat_n(0u8, extranonce2_size));
        raw.extend_from_slice(&coinb2);
        let coinbase: Transaction =
            deserialize(&raw).map_err(|e| format!("the coinbase does not parse: {e}"))?;
        Ok(Job {
            job_id,
            prev_hash,
            coinbase,
            coinbase_bytes: raw.len(),
            merkle_branch,
            version,
            bits,
            time,
            difficulty,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prev_hash_word_order_round_trips() {
        let mut h = [0u8; 32];
        for (i, b) in h.iter_mut().enumerate() {
            *b = i as u8;
        }
        let s = to_sv1_prev_hash(&h);
        assert!(s.starts_with("03020100"), "{s}");
        assert_eq!(sv1_prev_hash(&s).unwrap(), h);
        assert!(sv1_prev_hash("00").is_err());
        assert_eq!(
            display_hex(&h),
            "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
        );
    }
}
