//! Weight, sigop and coinbase-size limits for the blocks this node builds.
//!
//! `getblocktemplate` fills a template up to `weightlimit` minus ghostd's `blockreservedweight`
//! (8,000 WU by default). That reserve is all the room left for the header, the transaction count
//! and the coinbase, so a coinbase larger than about 1.9 KB on a full template makes a block
//! ghostd rejects as `bad-blk-weight` (measured, W0.2). The checks here count every byte:
//!
//! - [`block_weight`](crate::block_limits::block_weight): the weight of an assembled block, header and transaction count included.
//!   Used by the submit paths. LIVE: it can only refuse a block ghostd would reject anyway.
//! - [`assess`](crate::block_limits::assess) / [`trim_to_fit`](crate::block_limits::trim_to_fit) / [`check_built_coinbase`](crate::block_limits::check_built_coinbase): the template-time checks, against
//!   the template's own limits, the operator's `target_weight` and what the SV2 pool said it adds
//!   to the coinbase (`CoinbaseOutputConstraints`). Below `NODE_POOL_ACTIVATION_HEIGHT` they only
//!   warn; at and above it a template is trimmed to leave room for the largest coinbase, and a
//!   job that still does not fit, or whose coinbase is above `MAX_COINBASE_BYTES`, is refused.

use ghost_common::node_pool_constants::MAX_COINBASE_BYTES;
use ghost_common::rpc::{BlockTemplate, TemplateTransaction};
use std::sync::atomic::{AtomicU64, Ordering};

/// Consensus maximum block weight (BIP141).
pub const MAX_BLOCK_WEIGHT: u64 = 4_000_000;

/// Consensus maximum sigop cost of a block (BIP141).
pub const MAX_BLOCK_SIGOPS_COST: u64 = 80_000;

/// Weight of one non-witness byte.
pub const WITNESS_SCALE_FACTOR: u64 = 4;

/// Bytes in a block header.
pub const BLOCK_HEADER_BYTES: u64 = 80;

/// Witness bytes a segwit coinbase adds: marker and flag, stack count, item length, 32-byte
/// nonce. Each weighs 1 WU.
pub const COINBASE_WITNESS_BYTES: u64 = 36;

/// Widest extranonce any of our paths fills in: SV2, 4 pool bytes plus 16 client bytes. SV1 uses
/// 8, so counting 20 is conservative for both.
pub const MAX_EXTRANONCE_BYTES: u64 = 20;

/// Length of a Bitcoin CompactSize encoding of `n`.
pub fn compact_size_len(n: u64) -> u64 {
    match n {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// Weight of the parts of a block that are neither the coinbase nor a transaction: the 80-byte
/// header and the transaction count, `tx_count` including the coinbase.
pub fn block_overhead_weight(tx_count: u64) -> u64 {
    (BLOCK_HEADER_BYTES + compact_size_len(tx_count)) * WITNESS_SCALE_FACTOR
}

/// Weight of an assembled block. `tx_count` includes the coinbase; `txs_weight` is the summed
/// weight of the other transactions.
///
/// The submit paths used to count only the coinbase and the transactions, leaving out the header
/// (320 WU) and the transaction count (4 to 20 WU), so a block up to 340 WU over the limit passed
/// the check and was rejected by ghostd instead.
pub fn block_weight(
    tx_count: usize,
    coinbase_non_witness_len: usize,
    coinbase_witness_len: usize,
    txs_weight: u64,
) -> anyhow::Result<u64> {
    // SEC-BLOCK-2: a witness serialization shorter than the stripped one is malformed.
    let witness_extra = coinbase_witness_len
        .checked_sub(coinbase_non_witness_len)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Invalid coinbase: witness serialization ({} bytes) shorter than non-witness ({} bytes)",
                coinbase_witness_len,
                coinbase_non_witness_len
            )
        })?;
    let coinbase_weight =
        coinbase_non_witness_len as u64 * WITNESS_SCALE_FACTOR + witness_extra as u64;
    Ok(block_overhead_weight(tx_count as u64) + coinbase_weight + txs_weight)
}

/// What the SV2 pool told us it adds to each coinbase (`CoinbaseOutputConstraints`). Several
/// clients may connect; the largest value any of them sent is kept, so the room left is enough
/// for all of them.
#[derive(Debug, Default)]
pub struct CoinbaseOutputReserve {
    size: AtomicU64,
    sigops: AtomicU64,
}

impl CoinbaseOutputReserve {
    /// Record one client's constraints.
    pub fn note(&self, max_additional_size: u32, max_additional_sigops: u16) {
        self.size
            .fetch_max(u64::from(max_additional_size), Ordering::Relaxed);
        self.sigops
            .fetch_max(u64::from(max_additional_sigops), Ordering::Relaxed);
    }

    /// Bytes of outputs the pool may add.
    pub fn size(&self) -> u64 {
        self.size.load(Ordering::Relaxed)
    }

    /// Sigop cost the pool's outputs may add. The message carries a sigop count; each legacy
    /// sigop costs 4.
    pub fn sigop_cost(&self) -> u64 {
        self.sigops.load(Ordering::Relaxed) * WITNESS_SCALE_FACTOR
    }
}

/// The limits one block must meet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockLimits {
    /// Most weight the whole block may have, header and coinbase included.
    pub weight: u64,
    /// Most sigop cost the whole block may have.
    pub sigop_cost: u64,
}

impl BlockLimits {
    /// The tightest of the template's own limits, the consensus maxima and the operator's
    /// `target_weight`. A zero limit in the template means "not given".
    pub fn for_template(template: &BlockTemplate, target_weight: u64) -> Self {
        let nonzero = |v: u64, default: u64| if v == 0 { default } else { v };
        Self {
            weight: nonzero(template.weightlimit, MAX_BLOCK_WEIGHT)
                .min(nonzero(target_weight, MAX_BLOCK_WEIGHT))
                .min(MAX_BLOCK_WEIGHT),
            sigop_cost: nonzero(template.sigoplimit, MAX_BLOCK_SIGOPS_COST)
                .min(MAX_BLOCK_SIGOPS_COST),
        }
    }
}

/// The size and sigop cost of a coinbase, as the block will carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinbaseFootprint {
    /// Non-witness bytes, extranonce and the pool's added outputs included.
    pub non_witness_bytes: u64,
    /// Sigop cost of the scriptSig and the outputs.
    pub sigop_cost: u64,
}

impl CoinbaseFootprint {
    /// The coinbase this node built, plus the widest extranonce and what the SV2 pool adds.
    ///
    /// `coinbase1` is version, input count, prevout, scriptSig length and the scriptSig up to the
    /// extranonce; `coinbase2` is the rest. `outputs` is the outputs alone, concatenated, as
    /// sent to the pool. `None` if `outputs` does not parse.
    pub fn from_parts(
        coinbase1: &[u8],
        coinbase2: &[u8],
        outputs: &[u8],
        reserve: &CoinbaseOutputReserve,
    ) -> Option<Self> {
        // version 4 + input count 1 + prevout 36 + scriptSig length 1.
        let script_sig = coinbase1.get(42..).unwrap_or(&[]);
        let sig_sigops = bitcoin::Script::from_bytes(script_sig).count_sigops_legacy() as u64;
        let out_sigops = output_sigops(outputs)?;
        Some(Self {
            non_witness_bytes: coinbase1.len() as u64
                + MAX_EXTRANONCE_BYTES
                + coinbase2.len() as u64
                + reserve.size(),
            sigop_cost: (sig_sigops + out_sigops) * WITNESS_SCALE_FACTOR + reserve.sigop_cost(),
        })
    }

    /// The largest coinbase the node pool can build: `MAX_COINBASE_BYTES`, whose payee scripts
    /// (P2SH, P2WPKH, P2WSH, P2TR), treasury and commitments carry no sigops, plus whatever the
    /// SV2 pool reserves.
    pub fn ceiling(reserve: &CoinbaseOutputReserve) -> Self {
        Self {
            non_witness_bytes: MAX_COINBASE_BYTES as u64,
            sigop_cost: reserve.sigop_cost(),
        }
    }

    fn weight(&self) -> u64 {
        self.non_witness_bytes * WITNESS_SCALE_FACTOR + COINBASE_WITNESS_BYTES
    }
}

/// Legacy sigops in concatenated serialized outputs (value, CompactSize length, script).
fn output_sigops(mut outputs: &[u8]) -> Option<u64> {
    let mut sigops = 0u64;
    while !outputs.is_empty() {
        let rest = outputs.get(8..)?;
        let (len, header) = match *rest.first()? {
            n @ 0..=0xfc => (u64::from(n), 1),
            0xfd => (
                u64::from(u16::from_le_bytes(rest.get(1..3)?.try_into().ok()?)),
                3,
            ),
            0xfe => (
                u64::from(u32::from_le_bytes(rest.get(1..5)?.try_into().ok()?)),
                5,
            ),
            0xff => (u64::from_le_bytes(rest.get(1..9)?.try_into().ok()?), 9),
        };
        let end = header + usize::try_from(len).ok()?;
        let script = rest.get(header..end)?;
        sigops += bitcoin::Script::from_bytes(script).count_sigops_legacy() as u64;
        outputs = &rest[end..];
    }
    Some(sigops)
}

/// A block's weight and sigop cost against its limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fit {
    pub limits: BlockLimits,
    pub weight: u64,
    pub sigop_cost: u64,
    pub coinbase_bytes: u64,
}

impl Fit {
    pub fn over_weight(&self) -> bool {
        self.weight > self.limits.weight
    }

    pub fn over_sigops(&self) -> bool {
        self.sigop_cost > self.limits.sigop_cost
    }

    pub fn over_coinbase_ceiling(&self) -> bool {
        self.coinbase_bytes > MAX_COINBASE_BYTES as u64
    }

    pub fn ok(&self) -> bool {
        !self.over_weight() && !self.over_sigops() && !self.over_coinbase_ceiling()
    }
}

/// Weigh a block of `coinbase` followed by `txs`.
pub fn assess(
    limits: BlockLimits,
    coinbase: CoinbaseFootprint,
    txs: &[TemplateTransaction],
) -> Fit {
    Fit {
        limits,
        weight: block_overhead_weight(txs.len() as u64 + 1)
            + coinbase.weight()
            + txs.iter().map(|t| t.weight).sum::<u64>(),
        sigop_cost: coinbase.sigop_cost + txs.iter().map(|t| t.sigops).sum::<u64>(),
        coinbase_bytes: coinbase.non_witness_bytes,
    }
}

/// Drop transactions from the tail of `txs` until a block with `coinbase` fits `limits`, and
/// return how many were dropped. The template order puts every parent before its children, so a
/// prefix never loses a parent it needs. If the coinbase alone does not fit, every transaction
/// goes and the caller's own check refuses the job.
pub fn trim_to_fit(
    limits: BlockLimits,
    coinbase: CoinbaseFootprint,
    txs: &mut Vec<TemplateTransaction>,
) -> usize {
    let mut weight = coinbase.weight();
    let mut sigops = coinbase.sigop_cost;
    let mut keep = txs.len();
    for (i, tx) in txs.iter().enumerate() {
        weight += tx.weight;
        sigops += tx.sigops;
        if block_overhead_weight(i as u64 + 2) + weight > limits.weight
            || sigops > limits.sigop_cost
        {
            keep = i;
            break;
        }
    }
    let removed = txs.len() - keep;
    txs.truncate(keep);
    removed
}

/// At and above activation, trim `txs` so the largest coinbase the node pool can build still
/// fits. Below it, does nothing. Returns how many transactions were dropped.
pub fn make_room_for_coinbase(
    height: u64,
    activation: u64,
    template: &BlockTemplate,
    target_weight: u64,
    reserve: &CoinbaseOutputReserve,
    txs: &mut Vec<TemplateTransaction>,
) -> usize {
    if height < activation {
        return 0;
    }
    let limits = BlockLimits::for_template(template, target_weight);
    let removed = trim_to_fit(limits, CoinbaseFootprint::ceiling(reserve), txs);
    if removed > 0 {
        tracing::warn!(
            height,
            removed,
            limit = limits.weight,
            "dropped transactions to leave room for the coinbase; is ghostd's \
             blockreservedweight below 90000?"
        );
    }
    removed
}

/// Check a built coinbase against the template's limits and the coinbase ceiling. Below
/// `activation` a breach is logged and the job goes out as before; at and above it the job is
/// refused.
#[allow(clippy::too_many_arguments)]
pub fn check_built_coinbase(
    height: u64,
    activation: u64,
    template: &BlockTemplate,
    target_weight: u64,
    reserve: &CoinbaseOutputReserve,
    coinbase1: &[u8],
    coinbase2: &[u8],
    outputs: &[u8],
    txs: &[TemplateTransaction],
) -> anyhow::Result<()> {
    let limits = BlockLimits::for_template(template, target_weight);
    let fit = CoinbaseFootprint::from_parts(coinbase1, coinbase2, outputs, reserve)
        .map(|cb| assess(limits, cb, txs));
    let problem = match fit {
        None => Some("the coinbase outputs do not parse".to_string()),
        Some(f) if f.ok() => None,
        Some(f) => Some(format!(
            "block weight {} of {}, sigop cost {} of {}, coinbase {} B of {} B",
            f.weight,
            f.limits.weight,
            f.sigop_cost,
            f.limits.sigop_cost,
            f.coinbase_bytes,
            MAX_COINBASE_BYTES
        )),
    };
    let Some(problem) = problem else {
        return Ok(());
    };
    if height < activation {
        tracing::warn!(height, %problem, "built block would exceed its limits");
        return Ok(());
    }
    tracing::error!(height, %problem, "refusing a job whose block would exceed its limits");
    Err(anyhow::anyhow!("block limits exceeded: {problem}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx(weight: u64, sigops: u64) -> TemplateTransaction {
        TemplateTransaction {
            data: String::new(),
            txid: String::new(),
            hash: String::new(),
            depends: vec![],
            fee: 0,
            sigops,
            weight,
        }
    }

    fn template(weightlimit: u64, sigoplimit: u64) -> BlockTemplate {
        serde_json::from_value(serde_json::json!({
            "version": 0x2000_0000u32, "rules": [], "vbavailable": {}, "vbrequired": 0,
            "previousblockhash": "00", "transactions": [], "coinbaseaux": {},
            "coinbasevalue": 0, "longpollid": null, "target": "00", "mintime": 0,
            "mutable": [], "noncerange": "00000000ffffffff", "sigoplimit": sigoplimit,
            "sizelimit": 4_000_000, "weightlimit": weightlimit, "curtime": 0, "bits": "1d00ffff",
            "height": 1, "default_witness_commitment": null
        }))
        .expect("template json")
    }

    fn output(script: &[u8]) -> Vec<u8> {
        let mut o = 1_000u64.to_le_bytes().to_vec();
        o.push(script.len() as u8);
        o.extend_from_slice(script);
        o
    }

    fn p2tr() -> Vec<u8> {
        [&[0x51, 0x20][..], &[7u8; 32]].concat()
    }

    fn p2pkh() -> Vec<u8> {
        [&[0x76, 0xa9, 0x14][..], &[7u8; 20], &[0x88, 0xac]].concat()
    }

    #[test]
    fn compact_size_boundaries() {
        assert_eq!(compact_size_len(0xfc), 1);
        assert_eq!(compact_size_len(0xfd), 3);
        assert_eq!(compact_size_len(0xffff), 3);
        assert_eq!(compact_size_len(0x1_0000), 5);
        assert_eq!(compact_size_len(u64::MAX), 9);
    }

    /// The header and the transaction count are part of the block's weight.
    #[test]
    fn block_weight_counts_the_header_and_tx_count() {
        // 1 tx (the coinbase alone): header 320 + count 4 + coinbase 100*4 + 36.
        assert_eq!(block_weight(1, 100, 136, 0).unwrap(), 320 + 4 + 400 + 36);
        // 300 txs: the count takes 3 bytes, 12 WU.
        assert_eq!(
            block_weight(300, 100, 136, 1_000).unwrap(),
            320 + 12 + 436 + 1_000
        );
    }

    /// The case the old check let through: coinbase plus transactions at exactly 4,000,000 WU,
    /// so the real block, with its header, is 324 WU over and ghostd rejects it.
    #[test]
    fn block_at_the_limit_before_the_header_is_over_after_it() {
        let coinbase_weight = 1_000 * 4 + 36;
        let txs_weight = MAX_BLOCK_WEIGHT - coinbase_weight;
        let old = coinbase_weight + txs_weight;
        assert!(old <= MAX_BLOCK_WEIGHT, "the old check passed it");
        let new = block_weight(2, 1_000, 1_036, txs_weight).unwrap();
        assert_eq!(new, MAX_BLOCK_WEIGHT + 324);
        assert!(new > MAX_BLOCK_WEIGHT, "the new check refuses it");
    }

    #[test]
    fn block_weight_refuses_a_short_witness_serialization() {
        let e = block_weight(1, 100, 99, 0).unwrap_err().to_string();
        assert!(e.contains("shorter than non-witness"), "{e}");
    }

    #[test]
    fn limits_take_the_tightest_and_ignore_zero() {
        let t = template(4_000_000, 80_000);
        assert_eq!(
            BlockLimits::for_template(&t, 3_992_000),
            BlockLimits {
                weight: 3_992_000,
                sigop_cost: 80_000
            }
        );
        let t = template(3_000_000, 40_000);
        assert_eq!(
            BlockLimits::for_template(&t, 4_000_000),
            BlockLimits {
                weight: 3_000_000,
                sigop_cost: 40_000
            }
        );
        let t = template(0, 0);
        assert_eq!(
            BlockLimits::for_template(&t, 0),
            BlockLimits {
                weight: MAX_BLOCK_WEIGHT,
                sigop_cost: MAX_BLOCK_SIGOPS_COST
            }
        );
        // Nothing above consensus, whatever the template or the operator says.
        let t = template(9_000_000, 900_000);
        assert_eq!(
            BlockLimits::for_template(&t, 9_000_000),
            BlockLimits {
                weight: MAX_BLOCK_WEIGHT,
                sigop_cost: MAX_BLOCK_SIGOPS_COST
            }
        );
    }

    #[test]
    fn reserve_keeps_the_largest_constraints() {
        let r = CoinbaseOutputReserve::default();
        assert_eq!((r.size(), r.sigop_cost()), (0, 0));
        r.note(31, 1);
        r.note(10, 0);
        assert_eq!((r.size(), r.sigop_cost()), (31, 4));
        r.note(100, 2);
        assert_eq!((r.size(), r.sigop_cost()), (100, 8));
    }

    #[test]
    fn footprint_counts_extranonce_reserve_and_sigops() {
        let r = CoinbaseOutputReserve::default();
        r.note(31, 1);
        // 42 fixed bytes, then a scriptSig with one OP_CHECKSIG (0xac) in it.
        let mut coinbase1 = vec![0u8; 42];
        coinbase1.extend_from_slice(&[0x01, 0x05, 0xac]);
        let outputs = [output(&p2tr()), output(&p2pkh()), output(&p2pkh())].concat();
        let coinbase2 = vec![0u8; 60];
        let f = CoinbaseFootprint::from_parts(&coinbase1, &coinbase2, &outputs, &r).unwrap();
        assert_eq!(f.non_witness_bytes, 45 + 20 + 60 + 31);
        // scriptSig 1 + two P2PKH 2 = 3 legacy sigops = 12, plus the pool's 4.
        assert_eq!(f.sigop_cost, 12 + 4);
    }

    #[test]
    fn payee_classes_carry_no_sigops() {
        let p2sh = [&[0xa9, 0x14][..], &[1u8; 20], &[0x87]].concat();
        let p2wpkh = [&[0x00, 0x14][..], &[1u8; 20]].concat();
        let p2wsh = [&[0x00, 0x20][..], &[1u8; 32]].concat();
        let outputs = [
            output(&p2sh),
            output(&p2wpkh),
            output(&p2wsh),
            output(&p2tr()),
        ]
        .concat();
        assert_eq!(output_sigops(&outputs), Some(0));
        assert_eq!(output_sigops(&output(&p2pkh())), Some(1));
    }

    #[test]
    fn malformed_outputs_do_not_parse() {
        let mut o = output(&p2tr());
        o.truncate(o.len() - 1);
        assert_eq!(output_sigops(&o), None);
        assert_eq!(output_sigops(&[0u8; 7]), None);
        assert_eq!(output_sigops(&[]), Some(0));
    }

    #[test]
    fn assess_counts_every_part() {
        let limits = BlockLimits {
            weight: 10_000,
            sigop_cost: 100,
        };
        let cb = CoinbaseFootprint {
            non_witness_bytes: 500,
            sigop_cost: 4,
        };
        let f = assess(limits, cb, &[tx(1_000, 10), tx(2_000, 20)]);
        assert_eq!(f.weight, 324 + 2_036 + 3_000);
        assert_eq!(f.sigop_cost, 34);
        assert!(f.ok());
        let f = assess(limits, cb, &[tx(7_700, 0)]);
        assert!(f.over_weight() && !f.ok());
        let f = assess(limits, cb, &[tx(10, 97)]);
        assert!(f.over_sigops() && !f.ok());
    }

    /// The W0.2 case: a full template under the default 8,000 WU reserve has no room for a
    /// 2.25 KB coinbase.
    #[test]
    fn default_reserve_cannot_carry_a_2_25_kb_coinbase() {
        let limits = BlockLimits {
            weight: MAX_BLOCK_WEIGHT,
            sigop_cost: MAX_BLOCK_SIGOPS_COST,
        };
        let txs = vec![tx(MAX_BLOCK_WEIGHT - 8_000, 0)];
        let small = CoinbaseFootprint {
            non_witness_bytes: 1_830,
            sigop_cost: 0,
        };
        let large = CoinbaseFootprint {
            non_witness_bytes: 2_250,
            sigop_cost: 0,
        };
        assert!(assess(limits, small, &txs).ok());
        assert!(assess(limits, large, &txs).over_weight());
    }

    /// Under the node pool's 90,000 WU reserve the ceiling coinbase fits a full template.
    #[test]
    fn node_pool_reserve_carries_the_ceiling_coinbase() {
        use ghost_common::node_pool_constants::NODE_POOL_BLOCK_RESERVED_WEIGHT;
        let limits = BlockLimits {
            weight: MAX_BLOCK_WEIGHT,
            sigop_cost: MAX_BLOCK_SIGOPS_COST,
        };
        // Many transactions, so the count takes 3 bytes.
        let per = (MAX_BLOCK_WEIGHT - NODE_POOL_BLOCK_RESERVED_WEIGHT) / 1_000;
        let mut txs = vec![tx(per, 0); 1_000];
        let r = CoinbaseOutputReserve::default();
        let ceiling = CoinbaseFootprint::ceiling(&r);
        assert!(assess(limits, ceiling, &txs).ok());
        assert_eq!(trim_to_fit(limits, ceiling, &mut txs), 0);
        assert_eq!(txs.len(), 1_000);
    }

    #[test]
    fn trim_drops_from_the_tail_until_it_fits() {
        let limits = BlockLimits {
            weight: 10_000,
            sigop_cost: 1_000,
        };
        let cb = CoinbaseFootprint {
            non_witness_bytes: 500,
            sigop_cost: 0,
        };
        // Fixed: 324 + 2,036 = 2,360, so 7,640 WU is left.
        let mut txs: Vec<_> = (0..10).map(|i| tx(1_000 + i, 0)).collect();
        let removed = trim_to_fit(limits, cb, &mut txs);
        assert_eq!(removed, 3);
        assert_eq!(txs.len(), 7);
        assert_eq!(
            txs.last().unwrap().weight,
            1_006,
            "the head is kept, in order"
        );
        assert!(assess(limits, cb, &txs).ok());

        // Sigops bind too.
        let mut txs = vec![tx(10, 400); 5];
        assert_eq!(trim_to_fit(limits, cb, &mut txs), 3);

        // Nothing to drop when it fits.
        let mut txs = vec![tx(10, 1); 5];
        assert_eq!(trim_to_fit(limits, cb, &mut txs), 0);

        // A coinbase that cannot fit on its own empties the template.
        let huge = CoinbaseFootprint {
            non_witness_bytes: 3_000,
            sigop_cost: 0,
        };
        let mut txs = vec![tx(10, 1); 5];
        assert_eq!(trim_to_fit(limits, huge, &mut txs), 5);
        assert!(assess(limits, huge, &txs).over_weight());
    }

    #[test]
    fn coinbase_ceiling() {
        let limits = BlockLimits {
            weight: MAX_BLOCK_WEIGHT,
            sigop_cost: MAX_BLOCK_SIGOPS_COST,
        };
        let at = CoinbaseFootprint {
            non_witness_bytes: MAX_COINBASE_BYTES as u64,
            sigop_cost: 0,
        };
        let over = CoinbaseFootprint {
            non_witness_bytes: at.non_witness_bytes + 1,
            ..at
        };
        assert!(assess(limits, at, &[]).ok());
        let f = assess(limits, over, &[]);
        assert!(f.over_coinbase_ceiling() && !f.over_weight() && !f.ok());
    }

    /// A built coinbase of `outputs` P2TR outputs, split as the template builder splits it.
    fn built(outputs: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let coinbase1 = vec![0u8; 42 + 30];
        let outs = output(&p2tr()).repeat(outputs);
        let mut coinbase2 = vec![0u8; 4 + 1];
        coinbase2.extend_from_slice(&outs);
        coinbase2.extend_from_slice(&[0u8; 4]);
        (coinbase1, coinbase2, outs)
    }

    #[test]
    fn built_coinbase_warns_below_activation_and_refuses_at_it() {
        let t = template(MAX_BLOCK_WEIGHT, MAX_BLOCK_SIGOPS_COST);
        let r = CoinbaseOutputReserve::default();
        let full = vec![tx(MAX_BLOCK_WEIGHT - 8_000, 0)];
        let check = |height, outputs: usize, txs: &[TemplateTransaction]| {
            let (c1, c2, outs) = built(outputs);
            check_built_coinbase(height, 100, &t, MAX_BLOCK_WEIGHT, &r, &c1, &c2, &outs, txs)
        };
        // Small coinbase on a full template: fine either side.
        assert!(check(99, 3, &full).is_ok());
        assert!(check(100, 3, &full).is_ok());
        // 44 outputs on a full template under the default reserve: over weight.
        assert!(
            check(99, 44, &full).is_ok(),
            "below activation it only warns"
        );
        assert!(check(100, 44, &full).is_err(), "at activation it refuses");
        // 600 outputs is above the 22 KB ceiling even on an empty template.
        assert!(check(99, 600, &[]).is_ok());
        let e = check(100, 600, &[]).unwrap_err().to_string();
        assert!(e.contains("coinbase"), "{e}");
        // Unparseable outputs are refused at activation.
        let (c1, c2, _) = built(1);
        assert!(check_built_coinbase(100, 100, &t, 0, &r, &c1, &c2, &[1, 2, 3], &[]).is_err());
    }

    #[test]
    fn make_room_only_at_activation() {
        let t = template(MAX_BLOCK_WEIGHT, MAX_BLOCK_SIGOPS_COST);
        let r = CoinbaseOutputReserve::default();
        let full: Vec<_> = (0..100)
            .map(|_| tx((MAX_BLOCK_WEIGHT - 8_000) / 100, 0))
            .collect();
        let mut below = full.clone();
        assert_eq!(make_room_for_coinbase(99, 100, &t, 0, &r, &mut below), 0);
        assert_eq!(below.len(), 100);
        let mut at = full;
        let removed = make_room_for_coinbase(100, 100, &t, 0, &r, &mut at);
        assert!(removed > 0);
        let limits = BlockLimits::for_template(&t, 0);
        assert!(assess(limits, CoinbaseFootprint::ceiling(&r), &at).ok());
    }

    /// The template path passes this constant as `activation`; until a release arms it, every
    /// gated branch above stays unreachable on a real chain.
    #[test]
    fn node_pool_is_dark() {
        assert_eq!(
            ghost_common::node_pool_constants::NODE_POOL_ACTIVATION_HEIGHT,
            u64::MAX
        );
    }
}
