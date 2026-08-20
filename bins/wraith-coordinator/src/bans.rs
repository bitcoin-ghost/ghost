//! Outpoint cooldowns for round disruption.
//!
//! A participant who registers an input and then never signs kills the
//! round for everyone. Bonds punished that by taking money; this replaces
//! them with something that needs no escrow and no L2 (#699).
//!
//! ## What a ban costs, and to whom
//!
//! The banned thing is the **outpoint**, not the key and not the address.
//! An attacker who wants to disrupt again must obtain a fresh coin, which
//! means making an on-chain transaction — a real cost, paid to miners,
//! scaling with how hard they push. An honest participant whose laptop
//! died mid-round loses the use of that one coin for the cooldown, and
//! nothing else: not their wallet, not their other coins, not their
//! ability to join the next round with a different input.
//!
//! Descendants are deliberately not banned. Following the coin would mean
//! walking the chain on every registration, and it would catch whoever
//! honestly receives a payment out of a banned coin — someone who did
//! nothing and has no way to know.
//!
//! ## Lifetime
//!
//! In memory, like every other coordinator store. A restart clears the
//! list. That is a real gap and a known one: persistence is a decision
//! for the coordinator as a whole — sessions, inputs and outputs are all
//! equally volatile — not something to solve for this list alone.

use std::collections::HashMap;
use std::sync::Mutex;

use bitcoin::OutPoint;
use tracing::{debug, info};

/// How long a disrupting outpoint stays unusable.
///
/// One hour: long enough that sustained disruption needs a steady supply
/// of fresh on-chain coins, short enough that an honest crash-and-retry
/// is an inconvenience rather than losing the coin for the day.
pub const DISRUPTION_BAN_SECS: u64 = 3_600;

/// Outpoints in cooldown, with the unix second each becomes usable again.
#[derive(Debug, Default)]
pub struct BanList {
    entries: Mutex<HashMap<OutPoint, u64>>,
}

impl BanList {
    pub fn new() -> Self {
        Self::default()
    }

    /// Put `outpoint` in cooldown for [`DISRUPTION_BAN_SECS`] from `now`.
    ///
    /// Re-banning an outpoint already in cooldown extends it rather than
    /// shortening it — a coin that disrupts twice does not get to reset
    /// its clock by disrupting at a convenient moment.
    pub fn ban(&self, outpoint: OutPoint, now: u64) -> u64 {
        let until = now.saturating_add(DISRUPTION_BAN_SECS);
        let mut entries = self.entries.lock().expect("ban list poisoned");
        let entry = entries.entry(outpoint).or_insert(until);
        if *entry < until {
            *entry = until;
        }
        let until = *entry;
        info!(%outpoint, until, "outpoint banned for round disruption");
        until
    }

    /// `Some(until)` while `outpoint` is in cooldown, `None` otherwise.
    ///
    /// Expiry is judged here rather than by a sweeper, so a stalled
    /// background task can never leave a coin banned past its time.
    pub fn banned_until(&self, outpoint: &OutPoint, now: u64) -> Option<u64> {
        let entries = self.entries.lock().expect("ban list poisoned");
        match entries.get(outpoint) {
            Some(&until) if until > now => Some(until),
            _ => None,
        }
    }

    /// Drop entries whose cooldown has passed. Purely to bound memory —
    /// [`banned_until`](Self::banned_until) is already correct without it.
    pub fn sweep_expired(&self, now: u64) -> usize {
        let mut entries = self.entries.lock().expect("ban list poisoned");
        let before = entries.len();
        entries.retain(|_, &mut until| until > now);
        let dropped = before - entries.len();
        if dropped > 0 {
            debug!(dropped, remaining = entries.len(), "ban cooldowns expired");
        }
        dropped
    }

    /// How many outpoints are currently recorded, expired or not.
    pub fn len(&self) -> usize {
        self.entries.lock().expect("ban list poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn outpoint(n: u8) -> OutPoint {
        OutPoint {
            txid: bitcoin::Txid::from_str(&format!("{n:02x}").repeat(32)).unwrap(),
            vout: 0,
        }
    }

    #[test]
    fn an_unknown_outpoint_is_not_banned() {
        let bans = BanList::new();
        assert_eq!(bans.banned_until(&outpoint(1), 1_000), None);
    }

    #[test]
    fn a_banned_outpoint_is_refused_until_its_cooldown_passes() {
        let bans = BanList::new();
        let until = bans.ban(outpoint(2), 1_000);
        assert_eq!(until, 1_000 + DISRUPTION_BAN_SECS);
        assert_eq!(bans.banned_until(&outpoint(2), 1_000), Some(until));
        // One second before expiry: still banned.
        assert_eq!(bans.banned_until(&outpoint(2), until - 1), Some(until));
        // At expiry: usable again.
        assert_eq!(bans.banned_until(&outpoint(2), until), None);
    }

    #[test]
    fn a_ban_only_ever_extends() {
        // Or a coin that disrupts twice could reset its own clock by
        // choosing when to do it.
        let bans = BanList::new();
        let first = bans.ban(outpoint(3), 10_000);
        let second = bans.ban(outpoint(3), 9_000);
        assert_eq!(second, first, "an earlier ban must not shorten a later one");
        let third = bans.ban(outpoint(3), 11_000);
        assert!(third > first, "a later ban must extend the cooldown");
    }

    #[test]
    fn banning_one_coin_does_not_ban_another() {
        let bans = BanList::new();
        bans.ban(outpoint(4), 1_000);
        assert!(bans.banned_until(&outpoint(5), 1_000).is_none());
    }

    #[test]
    fn sweeping_drops_only_expired_entries() {
        let bans = BanList::new();
        bans.ban(outpoint(6), 1_000);
        bans.ban(outpoint(7), 5_000);
        assert_eq!(bans.len(), 2);
        assert_eq!(bans.sweep_expired(1_000 + DISRUPTION_BAN_SECS), 1);
        assert_eq!(bans.len(), 1);
        assert!(bans.banned_until(&outpoint(7), 5_000).is_some());
    }

    #[test]
    fn sweeping_is_not_what_makes_expiry_correct() {
        // A stalled sweeper must not be able to keep a coin banned.
        let bans = BanList::new();
        let until = bans.ban(outpoint(8), 1_000);
        assert_eq!(bans.banned_until(&outpoint(8), until + 10_000), None);
        assert_eq!(bans.len(), 1, "still recorded, just no longer banned");
    }
}
