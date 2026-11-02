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
//| FILE: discover.rs                                                                                                    |
//|======================================================================================================================|

//! Discovery for open listing (W2.10): which nodes exist, learned from the relays themselves.
//!
//! There is no roster, no approval and no signed list. Every relay already gossips the peer
//! addresses it knows (`GetAddr` / `Addr`, bounded on the wire to
//! [`ghost_np_relay::wire::MAX_ADDRS`] per message and rate-limited per peer). The lister crawls
//! that gossip from a few seed relays ([`crate::discover::crawl`]): it asks each relay it reaches
//! for its addresses, adds the relay's own listen address from its `Hello`, and repeats on what it
//! learned, up to [`crate::discover::Limits::max_crawl`] relays a round. Anyone can run a node and
//! will be found once any relay the crawl reaches knows its address.
//!
//! Gossip is untrusted input, so every address passes [`crate::discover::admissible`] (a literal
//! IP and a non-zero port, never a host name that would make the lister resolve names an
//! attacker picks; and, unless test networks are allowed, a publicly routable IP) and the
//! [`crate::discover::Candidates`] caps: at most
//! [`crate::discover::Limits::max_candidates`] in all and
//! [`crate::discover::Limits::max_per_ip`] per IP, so one host cannot flood the candidate set
//! with ports. Being a candidate means only that the node will be probed; listing is decided by
//! the probe ([`crate::listing`]).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use ghost_np_relay::client::Session;

/// Discovery limits.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Most candidates kept in all.
    pub max_candidates: usize,
    /// Most candidates on one IP.
    pub max_per_ip: usize,
    /// Most relays contacted in one crawl.
    pub max_crawl: usize,
    /// Relays contacted at once.
    pub concurrency: usize,
    /// Deadline for each relay contacted.
    pub timeout: Duration,
    /// Accept private, loopback and other non-routable addresses (regtest and tests only).
    pub allow_private: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_candidates: 1_024,
            max_per_ip: 2,
            max_crawl: 256,
            concurrency: 8,
            timeout: Duration::from_secs(10),
            allow_private: false,
        }
    }
}

fn routable_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || o[0] == 0
        // 100.64.0.0/10, shared address space (carrier-grade NAT).
        || (o[0] == 100 && (o[1] & 0xC0) == 64)
        // 198.18.0.0/15, benchmarking; 240.0.0.0/4, reserved.
        || (o[0] == 198 && (o[1] & 0xFE) == 18)
        || o[0] >= 240)
}

fn routable_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return routable_v4(v4);
    }
    let s = ip.segments();
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // fc00::/7 unique local, fe80::/10 link local, 2001:db8::/32 documentation.
        || (s[0] & 0xFE00) == 0xFC00
        || (s[0] & 0xFFC0) == 0xFE80
        || (s[0] == 0x2001 && s[1] == 0x0DB8))
}

/// Whether an address may become a candidate: a non-zero port on a usable IP, and a publicly
/// routable one unless `allow_private`.
pub fn admissible(a: &SocketAddr, allow_private: bool) -> bool {
    let ip = a.ip();
    if a.port() == 0 || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    if let IpAddr::V4(v4) = ip {
        if v4.is_broadcast() {
            return false;
        }
    }
    allow_private
        || match ip {
            IpAddr::V4(v4) => routable_v4(v4),
            IpAddr::V6(v6) => routable_v6(v6),
        }
}

/// Parse one gossiped address: a literal `ip:port` only. Host names are refused, never resolved.
pub fn parse_gossiped(s: &str) -> Option<SocketAddr> {
    s.trim().parse::<SocketAddr>().ok()
}

/// The candidate set, with its caps.
#[derive(Debug, Clone, Default)]
pub struct Candidates {
    set: BTreeSet<SocketAddr>,
    per_ip: BTreeMap<IpAddr, usize>,
}

/// Why an address was not added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// Not [`admissible`].
    Inadmissible,
    /// Already a candidate.
    Known,
    /// [`Limits::max_candidates`] reached.
    Full,
    /// [`Limits::max_per_ip`] reached for its IP.
    IpFull,
}

impl Candidates {
    /// Add `a` within `limits`.
    pub fn add(&mut self, a: SocketAddr, limits: &Limits) -> Result<(), Refused> {
        if !admissible(&a, limits.allow_private) {
            return Err(Refused::Inadmissible);
        }
        if self.set.contains(&a) {
            return Err(Refused::Known);
        }
        if self.set.len() >= limits.max_candidates {
            return Err(Refused::Full);
        }
        let n = self.per_ip.entry(a.ip()).or_insert(0);
        if *n >= limits.max_per_ip {
            return Err(Refused::IpFull);
        }
        *n += 1;
        self.set.insert(a);
        Ok(())
    }

    /// Whether `a` is a candidate.
    pub fn contains(&self, a: &SocketAddr) -> bool {
        self.set.contains(a)
    }

    /// Every candidate, sorted.
    pub fn iter(&self) -> impl Iterator<Item = &SocketAddr> {
        self.set.iter()
    }

    /// How many.
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

/// What one relay told the crawl.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reply {
    /// The relay's own listen address (the IP reached, its `Hello` listen port), if it listens.
    pub own: Option<SocketAddr>,
    /// The addresses it gossiped, unparsed.
    pub gossiped: Vec<String>,
}

/// Ask one relay for its addresses. `None` if it could not be reached or is not on `genesis`.
pub async fn ask(relay: SocketAddr, genesis: [u8; 32], timeout: Duration) -> Option<Reply> {
    let agent = format!("ghost-audit-list/{}", env!("CARGO_PKG_VERSION"));
    let mut s = Session::open(relay, genesis, &agent, timeout).await.ok()?;
    let own = (s.hello.listen_port != 0).then(|| SocketAddr::new(relay.ip(), s.hello.listen_port));
    let gossiped = s.addrs(timeout).await.unwrap_or_default();
    Some(Reply { own, gossiped })
}

/// Crawl relay gossip from `seeds` (and `known`, earlier candidates), adding every admissible
/// address to `found` within `limits`. Returns how many relays answered.
///
/// `ask` is the per-relay request ([`ask`] in production), a parameter so the crawl's limits can
/// be tested without sockets.
pub async fn crawl<F, Fut>(
    seeds: &[SocketAddr],
    known: &[SocketAddr],
    found: &mut Candidates,
    limits: &Limits,
    ask: F,
) -> usize
where
    F: Fn(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = Option<Reply>> + Send + 'static,
{
    let mut queue: VecDeque<SocketAddr> = VecDeque::new();
    let mut queued: BTreeSet<SocketAddr> = BTreeSet::new();
    for a in seeds.iter().chain(known) {
        if queued.insert(*a) {
            queue.push_back(*a);
        }
    }
    let mut contacted = 0usize;
    let mut answered = 0usize;
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        while tasks.len() < limits.concurrency.max(1) && contacted < limits.max_crawl {
            let Some(a) = queue.pop_front() else { break };
            contacted += 1;
            tasks.spawn(ask(a));
        }
        let Some(done) = tasks.join_next().await else {
            break;
        };
        let Ok(Some(reply)) = done else { continue };
        answered += 1;
        let learned = reply
            .own
            .into_iter()
            .chain(reply.gossiped.iter().filter_map(|s| parse_gossiped(s)));
        for a in learned {
            let _ = found.add(a, limits);
            if found.contains(&a) && queued.insert(a) {
                queue.push_back(a);
            }
        }
    }
    answered
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn only_literal_routable_addresses_are_admitted() {
        for ok in ["203.0.114.7:8566", "8.8.8.8:1", "[2a01:4f8::1]:8566"] {
            assert!(admissible(&sa(ok), false), "{ok}");
        }
        for bad in [
            "10.0.0.1:8566",
            "192.168.1.1:8566",
            "127.0.0.1:8566",
            "169.254.0.1:8566",
            "100.64.0.1:8566",
            "192.0.2.1:8566",
            "0.0.0.0:8566",
            "224.0.0.1:8566",
            "255.255.255.255:8566",
            "250.0.0.1:8566",
            "203.0.114.7:0",
            "[::1]:8566",
            "[fd00::1]:8566",
            "[fe80::1]:8566",
            "[2001:db8::1]:8566",
            "[::ffff:10.0.0.1]:8566",
        ] {
            assert!(!admissible(&sa(bad), false), "{bad}");
        }
        // Test networks may allow private addresses, never port 0 or unspecified.
        assert!(admissible(&sa("127.0.0.1:8566"), true));
        assert!(!admissible(&sa("127.0.0.1:0"), true));
        assert!(!admissible(&sa("0.0.0.0:1"), true));
        // Host names are never resolved.
        assert_eq!(parse_gossiped("pool.example.org:8566"), None);
        assert_eq!(parse_gossiped(" 8.8.8.8:8566 "), Some(sa("8.8.8.8:8566")));
    }

    #[test]
    fn candidates_are_capped_in_all_and_per_ip() {
        let limits = Limits {
            max_candidates: 5,
            max_per_ip: 2,
            ..Limits::default()
        };
        let mut c = Candidates::default();
        assert_eq!(c.add(sa("8.8.8.8:1"), &limits), Ok(()));
        assert_eq!(c.add(sa("8.8.8.8:1"), &limits), Err(Refused::Known));
        assert_eq!(c.add(sa("8.8.8.8:2"), &limits), Ok(()));
        assert_eq!(c.add(sa("8.8.8.8:3"), &limits), Err(Refused::IpFull));
        assert_eq!(c.add(sa("10.0.0.1:3"), &limits), Err(Refused::Inadmissible));
        for i in 1..=3u8 {
            assert_eq!(c.add(SocketAddr::from(([9, 9, 9, i], 1)), &limits), Ok(()));
        }
        assert_eq!(c.add(sa("9.9.9.9:1"), &limits), Err(Refused::Full));
        assert_eq!(c.len(), 5);
    }

    /// A fake network: each relay gossips a fixed list.
    fn net(map: Vec<(&str, Vec<String>)>) -> BTreeMap<SocketAddr, Vec<String>> {
        map.into_iter().map(|(a, v)| (sa(a), v)).collect()
    }

    #[tokio::test]
    async fn the_crawl_follows_gossip_within_its_limits() {
        // seed -> a, b; a -> c; c -> d (and junk); b gossips 100 ports of one host.
        let mut flood: Vec<String> = (1..=100).map(|p| format!("7.7.7.7:{p}")).collect();
        flood.push("not an address".into());
        flood.push("evil.example:8566".into());
        let n = std::sync::Arc::new(net(vec![
            (
                "1.1.1.1:8566",
                vec!["2.2.2.2:8566".into(), "3.3.3.3:8566".into()],
            ),
            ("2.2.2.2:8566", vec!["4.4.4.4:8566".into()]),
            ("3.3.3.3:8566", flood),
            (
                "4.4.4.4:8566",
                vec!["5.5.5.5:8566".into(), "10.0.0.5:8566".into()],
            ),
            ("5.5.5.5:8566", vec![]),
        ]));
        let ask = |n: std::sync::Arc<BTreeMap<SocketAddr, Vec<String>>>| {
            move |a: SocketAddr| {
                let n = n.clone();
                async move {
                    n.get(&a).map(|g| Reply {
                        own: Some(a),
                        gossiped: g.clone(),
                    })
                }
            }
        };
        let limits = Limits {
            max_per_ip: 2,
            ..Limits::default()
        };
        let mut found = Candidates::default();
        let answered = crawl(
            &[sa("1.1.1.1:8566")],
            &[],
            &mut found,
            &limits,
            ask(n.clone()),
        )
        .await;
        let got: Vec<String> = found.iter().map(|a| a.to_string()).collect();
        assert_eq!(
            got,
            vec![
                "1.1.1.1:8566",
                "2.2.2.2:8566",
                "3.3.3.3:8566",
                "4.4.4.4:8566",
                "5.5.5.5:8566",
                "7.7.7.7:1",
                "7.7.7.7:2"
            ],
            "the flood is cut to 2 per IP; private and named addresses are refused"
        );
        // 5 real relays answered; the 2 admitted flood ports were asked and did not answer.
        assert_eq!(answered, 5);

        // The crawl contacts at most max_crawl relays.
        let mut found = Candidates::default();
        let limits = Limits {
            max_crawl: 2,
            concurrency: 1,
            ..limits
        };
        let answered = crawl(&[sa("1.1.1.1:8566")], &[], &mut found, &limits, ask(n)).await;
        assert_eq!(answered, 2);
        assert!(!found.contains(&sa("5.5.5.5:8566")));
    }
}
