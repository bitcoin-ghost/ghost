//! Ghost Solo: the coinbase rule every job pays, and the constants around it.
//!
//! The pool is a solo pool. A miner's username is its Bitcoin address, and a block found on its
//! job pays, in this order:
//!
//! 1. the treasury, [`TREASURY_SCRIPT`](crate::solo::TREASURY_SCRIPT): exactly `subsidy / 200` (0.5% of the subsidy, never of
//!    the fees);
//! 2. the miner's own payout script: everything else, `subsidy - subsidy / 200 + fees`;
//! 3. the witness commitment, as the template provider hands it over.
//!
//! Nothing else. [`solo_outputs`](crate::solo::solo_outputs) builds the first two;
//! [`check_solo_outputs`](crate::solo::check_solo_outputs) checks a whole
//! coinbase against the rule (pool_sv2's post-submit alarm and `ghost-audit` use it).
//!
//! The subsidy halves every 210,000 blocks on mainnet and signet and every 150 on regtest
//! ([`Halving`](crate::solo::Halving)). Pure: no I/O.

/// Treasury base is `subsidy / TREASURY_DIVISOR`, 0.5% of the subsidy.
pub const TREASURY_DIVISOR: u64 = 200;

/// Bitcoin subsidy before the first halving, in sats.
pub const INITIAL_SUBSIDY_SATS: u64 = 5_000_000_000;

/// Blocks per subsidy era on mainnet, signet and testnet.
pub const HALVING_INTERVAL: u32 = 210_000;

/// Regtest's halving interval (Core's regtest `nSubsidyHalvingInterval`).
pub const REGTEST_HALVING_INTERVAL: u32 = 150;

/// The treasury output script, the first output of every coinbase. The same on every network
/// (regtest and signet included): the P2WPKH of `bc1qgxg5ywk835c9fp6arz6d6x50xpk6y0ualt900k`,
/// decided 2026-11-07.
pub const TREASURY_SCRIPT: [u8; 22] = [
    0x00, 0x14, 0x41, 0x91, 0x42, 0x3a, 0xc7, 0x8d, 0x30, 0x54, 0x87, 0x5d, 0x18, 0xb4, 0xdd, 0x1a,
    0x8f, 0x30, 0x6d, 0xa2, 0x3f, 0x9d,
];

/// The Ghost SV2 extension (`0x4748`, "GH"): the translator negotiates it with pool_sv2 to bind a
/// channel it opened on `mining.subscribe` to the miner's payout address once the miner
/// authorises ([`PAYEE_TLV_FIELD_TYPE`]).
pub const AGENT_TLV_EXTENSION_TYPE: u16 = 0x4748;

/// Field type of the miner's user agent inside [`AGENT_TLV_EXTENSION_TYPE`]. The translator still
/// sends it at channel open; pool_sv2 no longer reads it.
pub const AGENT_TLV_FIELD_TYPE: u8 = 0x01;

/// Field type of the payee identity inside [`AGENT_TLV_EXTENSION_TYPE`]: on an `UpdateChannel`,
/// the authorised miner's `address.worker`, which binds a provisional channel to its payee.
pub const PAYEE_TLV_FIELD_TYPE: u8 = 0x02;

/// Ceiling on a coinbase this pool builds, non-witness bytes. A solo coinbase is about 250 bytes;
/// the ceiling is kept as the block template's reserve is sized from it
/// ([`BLOCK_RESERVED_WEIGHT`]).
pub const MAX_COINBASE_BYTES: usize = 22_000;

/// `blockreservedweight` ghostd is given: the weight `getblocktemplate` leaves free for the
/// header, the transaction count and the coinbase. Far more than a solo coinbase needs; kept so
/// a node's configuration does not have to change.
pub const BLOCK_RESERVED_WEIGHT: u64 = 90_000;

// The reserve must hold the largest coinbase the ceiling allows, plus the 80-byte header, a
// 5-byte transaction count and the 36 witness bytes of a segwit coinbase.
const _: () = assert!((MAX_COINBASE_BYTES as u64) * 4 + 36 + (80 + 5) * 4 <= BLOCK_RESERVED_WEIGHT);

/// The subsidy schedule of a Bitcoin network: blocks between halvings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Halving(u32);

impl Halving {
    /// Mainnet, signet and testnet: every 210,000 blocks.
    pub const MAINNET: Halving = Halving(HALVING_INTERVAL);
    /// Regtest: every 150 blocks.
    pub const REGTEST: Halving = Halving(REGTEST_HALVING_INTERVAL);

    /// Blocks between halvings.
    pub fn interval(self) -> u32 {
        self.0
    }

    /// The subsidy era of height `h`: how many halvings have happened by it.
    pub fn era(self, h: u32) -> u32 {
        h / self.0
    }
}

/// Bitcoin block subsidy at height `h` on schedule `halving`, in sats.
pub fn subsidy(h: u32, halving: Halving) -> u64 {
    let n = halving.era(h);
    if n >= 64 {
        0
    } else {
        INITIAL_SUBSIDY_SATS >> n
    }
}

/// The treasury's cut at height `h`: `subsidy / 200`, rounded down.
pub fn treasury_cut(h: u32, halving: Halving) -> u64 {
    subsidy(h, halving) / TREASURY_DIVISOR
}

/// `(treasury, miner)` of a block at height `h` whose transactions pay `fees`: the treasury takes
/// `subsidy / 200` and the miner everything else.
pub fn split(h: u32, halving: Halving, fees: u64) -> (u64, u64) {
    let s = subsidy(h, halving);
    let t = s / TREASURY_DIVISOR;
    (t, s - t + fees)
}

/// The networks the pool runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SoloNetwork {
    /// Bitcoin mainnet.
    Mainnet,
    /// Signet.
    Signet,
    /// A local regtest chain.
    Regtest,
}

impl SoloNetwork {
    /// Parse a configured name: `mainnet` (also `bitcoin` and `main`), `signet` or `regtest`.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "mainnet" | "bitcoin" | "main" => Ok(Self::Mainnet),
            "signet" => Ok(Self::Signet),
            "regtest" => Ok(Self::Regtest),
            other => Err(format!(
                "network {other:?} is not one the pool runs on (mainnet, signet or regtest)"
            )),
        }
    }

    /// The name the config and the logs use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Signet => "signet",
            Self::Regtest => "regtest",
        }
    }

    /// The matching `bitcoin` crate network, for address encoding and checks.
    pub fn bitcoin_network(self) -> bitcoin::Network {
        match self {
            Self::Mainnet => bitcoin::Network::Bitcoin,
            Self::Signet => bitcoin::Network::Signet,
            Self::Regtest => bitcoin::Network::Regtest,
        }
    }

    /// The network's subsidy schedule: regtest halves every 150 blocks, mainnet and signet every
    /// 210,000.
    pub fn halving(self) -> Halving {
        match self {
            Self::Mainnet | Self::Signet => Halving::MAINNET,
            Self::Regtest => Halving::REGTEST,
        }
    }
}

impl std::fmt::Display for SoloNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The four payout script classes a miner may use. P2PKH is refused: each P2PKH output costs 4
/// sigops, and the class bound keeps every coinbase's size and sigops known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayeeScriptClass {
    /// `OP_HASH160 <20> OP_EQUAL`, 23 bytes.
    P2sh,
    /// `OP_0 <20>`, 22 bytes.
    P2wpkh,
    /// `OP_0 <32>`, 34 bytes.
    P2wsh,
    /// `OP_1 <32>`, 34 bytes.
    P2tr,
}

/// Longest accepted payee script, in bytes (P2WSH and P2TR).
pub const MAX_PAYEE_SCRIPT_LEN: usize = 34;

/// The class of a payout script, or `None` if the pool refuses it. Exact template match.
pub fn payee_script_class(s: &[u8]) -> Option<PayeeScriptClass> {
    match (s.len(), s.first(), s.get(1)) {
        (23, Some(0xa9), Some(0x14)) if s[22] == 0x87 => Some(PayeeScriptClass::P2sh),
        (22, Some(0x00), Some(0x14)) => Some(PayeeScriptClass::P2wpkh),
        (34, Some(0x00), Some(0x20)) => Some(PayeeScriptClass::P2wsh),
        (34, Some(0x51), Some(0x20)) => Some(PayeeScriptClass::P2tr),
        _ => None,
    }
}

/// One coinbase output: `(value in sats, scriptPubKey)`.
pub type CoinbaseOutput = (u64, Vec<u8>);

/// The coinbase outputs of a solo job at height `h` whose template pays `fees`, for the miner
/// paid by `miner_script`, without the witness commitment (the template's own output, which the
/// job builder appends): the treasury, then the miner.
pub fn solo_outputs(
    h: u32,
    halving: Halving,
    fees: u64,
    miner_script: &[u8],
) -> [CoinbaseOutput; 2] {
    let (treasury, miner) = split(h, halving, fees);
    [
        (treasury, TREASURY_SCRIPT.to_vec()),
        (miner, miner_script.to_vec()),
    ]
}

/// Whether `script` is a witness commitment (`OP_RETURN PUSH36 aa21a9ed || 32 bytes`).
pub fn is_witness_commitment(script: &[u8]) -> bool {
    script.len() == 38 && script.starts_with(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed])
}

/// What a coinbase paid, once [`check_solo_outputs`] accepted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoloPayout {
    /// Sats to the treasury.
    pub treasury: u64,
    /// Sats to the miner.
    pub miner: u64,
    /// The fees the coinbase implies: everything above the subsidy.
    pub fees: u64,
}

/// Check a coinbase's outputs against the solo rule for the miner paid by `miner_script` at
/// height `h`: the treasury output first, paying exactly `subsidy / 200`; the miner output
/// second, paying everything above that (`subsidy - subsidy / 200 + fees`, so never less than
/// `subsidy - subsidy / 200`); then at most one zero-value witness commitment. Nothing else.
///
/// With `fees` given (the template's, when the checker knows it), the miner must be paid exactly
/// `subsidy - subsidy / 200 + fees`.
pub fn check_solo_outputs(
    outputs: &[CoinbaseOutput],
    h: u32,
    halving: Halving,
    miner_script: &[u8],
    fees: Option<u64>,
) -> Result<SoloPayout, String> {
    let s = subsidy(h, halving);
    let want_treasury = s / TREASURY_DIVISOR;
    let (paying, rest) = match outputs {
        [t, m, rest @ ..] => ((t, m), rest),
        _ => {
            return Err(format!(
                "the coinbase has {} output(s); a solo coinbase pays the treasury and the miner",
                outputs.len()
            ))
        }
    };
    let ((tv, ts), (mv, ms)) = paying;
    if ts.as_slice() != TREASURY_SCRIPT.as_slice() {
        return Err(format!("output 0 pays {}, not the treasury", hex_of(ts)));
    }
    if *tv != want_treasury {
        return Err(format!(
            "the treasury is paid {tv} sats; the rule is subsidy / 200 = {want_treasury}"
        ));
    }
    if ms.as_slice() != miner_script {
        return Err(format!(
            "output 1 pays {}, not the miner's {}",
            hex_of(ms),
            hex_of(miner_script)
        ));
    }
    let floor = s - want_treasury;
    if *mv < floor {
        return Err(format!(
            "the miner is paid {mv} sats, less than subsidy - subsidy / 200 = {floor}"
        ));
    }
    let implied_fees = mv - floor;
    if let Some(f) = fees {
        if implied_fees != f {
            return Err(format!(
                "the miner is paid {mv} sats; with {f} sats of fees the rule is {}",
                floor + f
            ));
        }
    }
    match rest {
        [] => {}
        [(0, w)] if is_witness_commitment(w) => {}
        _ => {
            return Err(format!(
                "the coinbase carries {} output(s) after the miner's; only the witness \
                 commitment may follow",
                rest.len()
            ))
        }
    }
    Ok(SoloPayout {
        treasury: *tv,
        miner: *mv,
        fees: implied_fees,
    })
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const P2WPKH: [u8; 22] = [
        0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    ];

    fn witness() -> Vec<u8> {
        let mut w = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        w.extend([0x11; 32]);
        w
    }

    #[test]
    fn the_treasury_takes_half_a_percent_of_the_subsidy_and_no_fees() {
        // Today's era on mainnet: 3.125 BTC.
        let h = 960_000;
        assert_eq!(subsidy(h, Halving::MAINNET), 312_500_000);
        assert_eq!(treasury_cut(h, Halving::MAINNET), 1_562_500);
        let [t, m] = solo_outputs(h, Halving::MAINNET, 4_321, &P2WPKH);
        assert_eq!(t, (1_562_500, TREASURY_SCRIPT.to_vec()));
        assert_eq!(m, (312_500_000 - 1_562_500 + 4_321, P2WPKH.to_vec()));
        assert_eq!(t.0 + m.0, subsidy(h, Halving::MAINNET) + 4_321);
    }

    #[test]
    fn the_subsidy_halves_per_network() {
        assert_eq!(subsidy(0, Halving::MAINNET), 5_000_000_000);
        assert_eq!(subsidy(209_999, Halving::MAINNET), 5_000_000_000);
        assert_eq!(subsidy(210_000, Halving::MAINNET), 2_500_000_000);
        assert_eq!(subsidy(149, Halving::REGTEST), 5_000_000_000);
        assert_eq!(subsidy(150, Halving::REGTEST), 2_500_000_000);
        assert_eq!(subsidy(150 * 64, Halving::REGTEST), 0);
        assert_eq!(SoloNetwork::Regtest.halving(), Halving::REGTEST);
        assert_eq!(SoloNetwork::Signet.halving(), Halving::MAINNET);
        // Rounding is the treasury's loss, never the miner's: the cut floors.
        let h = 150 * 10; // 5e9 >> 10 = 4,882,812 sats
        assert_eq!(subsidy(h, Halving::REGTEST), 4_882_812);
        assert_eq!(treasury_cut(h, Halving::REGTEST), 24_414);
        assert_eq!(split(h, Halving::REGTEST, 0), (24_414, 4_858_398));
    }

    #[test]
    fn the_treasury_script_is_the_published_address() {
        // bc1qgxg5ywk835c9fp6arz6d6x50xpk6y0ualt900k
        let a: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
            "bc1qgxg5ywk835c9fp6arz6d6x50xpk6y0ualt900k"
                .parse()
                .unwrap();
        assert_eq!(
            a.assume_checked().script_pubkey().as_bytes(),
            TREASURY_SCRIPT.as_slice()
        );
    }

    #[test]
    fn a_coinbase_that_follows_the_rule_is_accepted() {
        let h = 960_000;
        let [t, m] = solo_outputs(h, Halving::MAINNET, 777, &P2WPKH);
        let outs = vec![t.clone(), m.clone(), (0, witness())];
        let p = check_solo_outputs(&outs, h, Halving::MAINNET, &P2WPKH, Some(777)).unwrap();
        assert_eq!((p.treasury, p.miner, p.fees), (t.0, m.0, 777));
        // Fees unknown to the checker: implied from the miner's output.
        let p = check_solo_outputs(&outs, h, Halving::MAINNET, &P2WPKH, None).unwrap();
        assert_eq!(p.fees, 777);
        // No witness commitment (a template with no segwit transactions) is fine too.
        assert!(check_solo_outputs(&[t, m], h, Halving::MAINNET, &P2WPKH, None).is_ok());
    }

    #[test]
    fn every_way_off_the_rule_is_refused() {
        let h = 960_000;
        let [t, m] = solo_outputs(h, Halving::MAINNET, 1_000, &P2WPKH);
        let w = (0, witness());
        let check =
            |o: &[CoinbaseOutput]| check_solo_outputs(o, h, Halving::MAINNET, &P2WPKH, None);
        // A treasury short by a sat, or over by one.
        assert!(check(&[(t.0 - 1, t.1.clone()), (m.0 + 1, m.1.clone())]).is_err());
        assert!(check(&[(t.0 + 1, t.1.clone()), (m.0 - 1, m.1.clone())]).is_err());
        // Outputs swapped, or another payee.
        assert!(check(&[m.clone(), t.clone()]).is_err());
        let mut other = P2WPKH;
        other[2] ^= 1;
        assert!(check(&[t.clone(), (m.0, other.to_vec())]).is_err());
        // The miner paid less than the subsidy's share.
        let floor = subsidy(h, Halving::MAINNET) - t.0;
        assert!(check(&[t.clone(), (floor - 1, m.1.clone())]).is_err());
        // A third payee, a second witness commitment, or a commitment carrying value.
        assert!(check(&[t.clone(), m.clone(), (1, P2WPKH.to_vec())]).is_err());
        assert!(check(&[t.clone(), m.clone(), w.clone(), w.clone()]).is_err());
        assert!(check(&[t.clone(), m.clone(), (1, witness())]).is_err());
        // Fees the checker knows that the miner was not paid.
        assert!(check_solo_outputs(
            &[t.clone(), m.clone()],
            h,
            Halving::MAINNET,
            &P2WPKH,
            Some(999)
        )
        .is_err());
        // Too few outputs.
        assert!(check(&[t]).is_err());
    }

    #[test]
    fn payee_classes() {
        assert_eq!(payee_script_class(&P2WPKH), Some(PayeeScriptClass::P2wpkh));
        let mut p2sh = vec![0xa9, 0x14];
        p2sh.extend([0; 20]);
        p2sh.push(0x87);
        assert_eq!(payee_script_class(&p2sh), Some(PayeeScriptClass::P2sh));
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend([0; 32]);
        assert_eq!(payee_script_class(&p2tr), Some(PayeeScriptClass::P2tr));
        // P2PKH is refused.
        let mut p2pkh = vec![0x76, 0xa9, 0x14];
        p2pkh.extend([0; 20]);
        p2pkh.extend([0x88, 0xac]);
        assert_eq!(payee_script_class(&p2pkh), None);
    }

    #[test]
    fn networks_parse() {
        assert_eq!(SoloNetwork::parse("Bitcoin").unwrap(), SoloNetwork::Mainnet);
        assert_eq!(
            SoloNetwork::parse(" regtest ").unwrap(),
            SoloNetwork::Regtest
        );
        assert!(SoloNetwork::parse("testnet4").is_err());
        assert_eq!(SoloNetwork::Signet.to_string(), "signet");
    }
}
