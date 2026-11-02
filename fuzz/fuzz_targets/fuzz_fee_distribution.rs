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
//| FILE: fuzz_fee_distribution.rs                                                                                       |
//|======================================================================================================================|

//! Fuzz target for the treasury fee schedule
//!
//! Tests that the treasury state never panics and that the fee split always sums to
//! 10000 bps.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use chrono::{DateTime, TimeZone, Utc};
use ghost_reconciliation::fee_distribution::TreasuryState;

#[derive(Arbitrary, Debug)]
struct FuzzFeeInput {
    treasury_balance: u64,
    threshold_timestamp: Option<i64>,
    reference_timestamp: i64,
}

fuzz_target!(|input: FuzzFeeInput| {
    // Build treasury state
    let threshold_at = input.threshold_timestamp.and_then(|ts| {
        // Clamp to valid range to avoid chrono panics
        let clamped = ts.clamp(-8_000_000_000, 8_000_000_000);
        Utc.timestamp_opt(clamped, 0).single()
    });
    let treasury = TreasuryState::from_stored(input.treasury_balance, threshold_at);

    // Reference time — clamp to valid range
    let ref_ts = input.reference_timestamp.clamp(-8_000_000_000, 8_000_000_000);
    let reference_time: DateTime<Utc> = match Utc.timestamp_opt(ref_ts, 0).single() {
        Some(t) => t,
        None => return,
    };

    // Treasury methods must not panic
    let _ = treasury.threshold_reached();
    let _ = treasury.years_since_threshold(reference_time);
    let (t_bps, n_bps) = treasury.get_fee_split_bps(reference_time);

    // Fee split must sum to 10000 bps
    assert_eq!(t_bps + n_bps, 10000, "fee split must sum to 10000 bps");

    let _ = treasury.decay_year(reference_time);
});
