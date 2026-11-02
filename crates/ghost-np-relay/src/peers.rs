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
//| FILE: peers.rs                                                                                                       |
//|======================================================================================================================|

//! Per-peer limits and ban scores, and the address book.
//!
//! Membership is open: any node that completes the handshake on the same genesis is a peer.
//! Nothing here asks who a peer is. What it does instead:
//!
//! - **Rate limits** per message class, as token buckets. A message over its bucket is dropped
//!   and costs nothing: being fast is not being wrong.
//! - **Ban scores** for data that is invalid whoever looks at it: an undecodable frame, a share
//!   whose work or tag does not check, an anchor or batch that breaks a rule. Late or stale data
//!   (an old job height, an anchor on a fork, a share already included) never scores. At
//!   [`BAN_THRESHOLD`] the peer is dropped and its address refused for [`BAN_SECS`].

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use crate::wire::MsgType;

/// Score at which a peer is banned.
pub const BAN_THRESHOLD: u32 = 100;
/// How long a ban lasts.
pub const BAN_SECS: u64 = 24 * 3_600;

/// Ban scores.
pub mod penalty {
    /// A frame that does not decode, or breaks its type's caps: the peer does not speak the
    /// protocol.
    pub const MALFORMED: u32 = 100;
    /// A network share that fails a check whose result does not depend on any chain view.
    pub const INVALID_SHARE: u32 = 20;
    /// An anchor or batch that breaks a rule.
    pub const INVALID_ANCHOR: u32 = 50;
    /// A batch whose ids do not hash to the anchor's committed root.
    pub const BAD_BATCH_ROOT: u32 = 50;
    /// An anchor built on an invalid anchor.
    pub const INVALID_DESCENDANT: u32 = 20;
}

/// A token bucket: `rate` tokens a second up to `burst`.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    tokens: f64,
    rate: f64,
    burst: f64,
    last_ms: u64,
}

impl TokenBucket {
    /// A full bucket.
    pub fn new(rate: f64, burst: f64, now_ms: u64) -> Self {
        TokenBucket {
            tokens: burst,
            rate,
            burst,
            last_ms: now_ms,
        }
    }

    /// Take one token if there is one.
    pub fn allow(&mut self, now_ms: u64) -> bool {
        let dt = now_ms.saturating_sub(self.last_ms) as f64 / 1_000.0;
        self.last_ms = now_ms.max(self.last_ms);
        self.tokens = (self.tokens + dt * self.rate).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// `(per second, burst)` for a message type. Sized well above honest traffic: about 256 network
/// shares and one anchor and batch per 54 s at target, and one `Shares` message per 64 bodies.
pub fn limits_for(t: MsgType) -> (f64, f64) {
    use MsgType::*;
    match t {
        Hello => (0.0, 1.0),
        Share => (100.0, 500.0),
        Anchor | Batch => (5.0, 100.0),
        GetShares => (5.0, 50.0),
        Shares | GetBatch | GetAnchor | NotFound => (20.0, 200.0),
        Tip => (2.0, 20.0),
        GetAddr | Addr => (0.1, 4.0),
    }
}

/// One connected peer's limits and score.
#[derive(Debug, Clone, Default)]
pub struct PeerState {
    /// Accumulated ban score.
    pub score: u32,
    buckets: HashMap<MsgType, TokenBucket>,
    /// Messages dropped by rate limits.
    pub dropped: u64,
}

impl PeerState {
    /// Whether a message of type `t` is within the peer's limits.
    pub fn admit(&mut self, t: MsgType, now_ms: u64) -> bool {
        let (rate, burst) = limits_for(t);
        let ok = self
            .buckets
            .entry(t)
            .or_insert_with(|| TokenBucket::new(rate, burst, now_ms))
            .allow(now_ms);
        if !ok {
            self.dropped += 1;
        }
        ok
    }

    /// Add `n` to the score. Returns whether the peer is now banned.
    pub fn penalize(&mut self, n: u32) -> bool {
        self.score = self.score.saturating_add(n);
        self.score >= BAN_THRESHOLD
    }
}

/// Where an address came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrSource {
    /// From this node's configuration: always kept.
    Configured,
    /// Learned from a peer.
    Learned,
}

#[derive(Debug, Clone)]
struct AddrInfo {
    source: AddrSource,
    failures: u32,
    next_try: u64,
}

/// Most learned addresses kept.
pub const MAX_LEARNED_ADDRS: usize = 1_024;

/// Known peer addresses and banned IPs.
#[derive(Debug, Default)]
pub struct AddrBook {
    addrs: HashMap<SocketAddr, AddrInfo>,
    banned: HashMap<IpAddr, u64>,
}

impl AddrBook {
    /// Add an address. Learned addresses beyond the cap are ignored.
    pub fn add(&mut self, a: SocketAddr, source: AddrSource) {
        if a.port() == 0 || a.ip().is_unspecified() {
            return;
        }
        let learned = self
            .addrs
            .values()
            .filter(|i| i.source == AddrSource::Learned)
            .count();
        match self.addrs.get_mut(&a) {
            Some(i) if source == AddrSource::Configured => i.source = source,
            Some(_) => {}
            None if source == AddrSource::Learned && learned >= MAX_LEARNED_ADDRS => {}
            None => {
                self.addrs.insert(
                    a,
                    AddrInfo {
                        source,
                        failures: 0,
                        next_try: 0,
                    },
                );
            }
        }
    }

    /// A dial to `a` failed: back off, and forget a learned address after repeated failures.
    pub fn failed(&mut self, a: &SocketAddr, now: u64) {
        if let Some(i) = self.addrs.get_mut(a) {
            i.failures += 1;
            i.next_try = now + (5u64 << i.failures.min(8));
            if i.source == AddrSource::Learned && i.failures >= 8 {
                self.addrs.remove(a);
            }
        }
    }

    /// A connection to `a` succeeded.
    pub fn succeeded(&mut self, a: &SocketAddr) {
        if let Some(i) = self.addrs.get_mut(a) {
            i.failures = 0;
            i.next_try = 0;
        }
    }

    /// Ban an IP until `now + BAN_SECS`.
    pub fn ban(&mut self, ip: IpAddr, now: u64) {
        self.banned.insert(ip, now + BAN_SECS);
    }

    /// Whether an IP is banned now.
    pub fn is_banned(&mut self, ip: &IpAddr, now: u64) -> bool {
        match self.banned.get(ip) {
            Some(until) if *until > now => true,
            Some(_) => {
                self.banned.remove(ip);
                false
            }
            None => false,
        }
    }

    /// Addresses worth dialling now, configured first.
    pub fn candidates(&mut self, now: u64) -> Vec<SocketAddr> {
        let mut v: Vec<(bool, SocketAddr)> = self
            .addrs
            .iter()
            .filter(|(_, i)| i.next_try <= now)
            .map(|(a, i)| (i.source != AddrSource::Configured, *a))
            .collect();
        v.retain(|(_, a)| !self.banned.get(&a.ip()).is_some_and(|until| *until > now));
        v.sort();
        v.into_iter().map(|(_, a)| a).collect()
    }

    /// Up to `n` addresses to tell a peer about.
    pub fn sample(&self, n: usize) -> Vec<SocketAddr> {
        let mut v: Vec<SocketAddr> = self
            .addrs
            .iter()
            .filter(|(_, i)| i.failures == 0)
            .map(|(a, _)| *a)
            .collect();
        v.sort();
        v.truncate(n);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_drop_bursts_and_refill() {
        let mut p = PeerState::default();
        let (_, burst) = limits_for(MsgType::Tip);
        for _ in 0..burst as usize {
            assert!(p.admit(MsgType::Tip, 0));
        }
        assert!(!p.admit(MsgType::Tip, 0));
        assert_eq!(p.dropped, 1);
        // Two a second: one second later two more pass.
        assert!(p.admit(MsgType::Tip, 1_000));
        assert!(p.admit(MsgType::Tip, 1_000));
        assert!(!p.admit(MsgType::Tip, 1_000));
        // Classes are independent, and no drop ever adds to the score.
        assert!(p.admit(MsgType::Share, 1_000));
        assert_eq!(p.score, 0);
    }

    #[test]
    fn scores_ban_at_the_threshold() {
        let mut p = PeerState::default();
        assert!(!p.penalize(penalty::INVALID_ANCHOR));
        assert!(p.penalize(penalty::INVALID_ANCHOR));
        let mut q = PeerState::default();
        assert!(q.penalize(penalty::MALFORMED));
    }

    #[test]
    fn address_book_bans_backs_off_and_caps() {
        let mut b = AddrBook::default();
        let c: SocketAddr = "10.0.0.1:8566".parse().unwrap();
        let l: SocketAddr = "10.0.0.2:8566".parse().unwrap();
        b.add(c, AddrSource::Configured);
        b.add(l, AddrSource::Learned);
        b.add("0.0.0.0:1".parse().unwrap(), AddrSource::Learned);
        assert_eq!(b.candidates(0), vec![c, l]);
        b.failed(&l, 0);
        assert_eq!(b.candidates(0), vec![c]);
        assert_eq!(b.candidates(1_000), vec![c, l]);
        b.ban(c.ip(), 0);
        assert!(b.is_banned(&c.ip(), 10));
        assert_eq!(b.candidates(1_000), vec![l]);
        assert!(!b.is_banned(&c.ip(), BAN_SECS + 1));
        for _ in 0..8 {
            b.failed(&l, 0);
        }
        assert_eq!(
            b.sample(10),
            vec![c],
            "a learned address that keeps failing is forgotten"
        );
        for i in 0..(MAX_LEARNED_ADDRS + 10) {
            let a = SocketAddr::from(([10, 1, (i >> 8) as u8, i as u8], 1));
            b.add(a, AddrSource::Learned);
        }
        assert_eq!(b.sample(usize::MAX).len(), MAX_LEARNED_ADDRS + 1);
    }
}
