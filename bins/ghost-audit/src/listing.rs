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
//| FILE: listing.rs                                                                                                     |
//|======================================================================================================================|

//! Open listing (W2.10): who is listed, and the files the website and DNS are generated from.
//!
//! Any node with a valid advert that passes the public probe ([`crate::probe`]) is listed, and
//! nothing else decides it: no roster, no approval, no signed list, no key. The lister
//! (`ghost-audit list`) finds candidates from relay gossip ([`crate::discover`]), probes each one
//! every round, keeps a short history per node ([`crate::listing::ListState`]) and applies
//! [`crate::listing::Policy`]:
//!
//! - **listed** after [`Policy::list_after`] `pass` probes within the last [`Policy::window`],
//!   the latest of them a pass, and no `fail` anywhere in that window; after a delisting, only
//!   passes since then count;
//! - **delisted** after [`Policy::delist_after`] probes in a row that were not a pass (a `fail` or
//!   `unmeasured`), or at once after [`Policy::delist_after_fail`] `fail`s in a row (default 1:
//!   a node that served one bad job is off the list at the next write).
//!
//! `unmeasured` never counts as a pass: a node that cannot be measured is never listed by it,
//! and a listed node that stops answering falls off after `delist_after` rounds.
//!
//! Outputs are generated, never edited: [`crate::listing::render_node_list`] (`node-list.json`,
//! schema [`LIST_SCHEMA`]) and [`crate::listing::render_dns`] (a zone-file fragment of A/AAAA
//! records). Both sort everything, so two runs over the same state differ only in the time
//! stamp, and a diff of either file shows exactly which nodes came and went.

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

/// Schema of `node-list.json`.
pub const LIST_SCHEMA: &str = "ghost-audit/node-list/v1";
/// Schema of the lister's state file.
pub const STATE_SCHEMA: &str = "ghost-audit/list-state/v1";
/// First line of the DNS fragment.
pub const DNS_SCHEMA: &str = "ghost-audit/dns/v1";

/// One probe's outcome, as listing reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The probe passed: `listable`.
    Pass,
    /// The node did something wrong.
    Fail,
    /// It could not be measured. Never a pass.
    Unmeasured,
}

/// When to list and delist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Policy {
    /// Passes needed within the window to be listed.
    pub list_after: usize,
    /// Probes of history kept and looked at.
    pub window: usize,
    /// Non-pass probes in a row that delist a listed node.
    pub delist_after: usize,
    /// `fail` probes in a row that delist a listed node.
    pub delist_after_fail: usize,
    /// Seconds between rounds (reported only).
    pub interval_secs: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            list_after: 3,
            window: 6,
            delist_after: 3,
            delist_after_fail: 1,
            interval_secs: 600,
        }
    }
}

impl Policy {
    /// Refuse a policy that could never list or delist.
    pub fn check(&self) -> Result<(), String> {
        if self.list_after == 0 || self.delist_after == 0 || self.delist_after_fail == 0 {
            return Err(
                "--list-after, --delist-after and --delist-after-fail must be at least 1".into(),
            );
        }
        if self.window < self.list_after {
            return Err(format!(
                "--window {} is shorter than --list-after {}: nothing could ever be listed",
                self.window, self.list_after
            ));
        }
        Ok(())
    }
}

/// What a node's relay port advertised at its last probe.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvertInfo {
    /// SV1 stratum port, 0 for none.
    pub sv1_port: u16,
    /// SV2 port, 0 for none.
    pub sv2_port: u16,
    /// SV2 authority key, empty for none.
    pub sv2_authority_key: String,
    /// The relay's user agent.
    pub user_agent: Option<String>,
    /// The node id its job stamps carry, hex.
    pub node_id: Option<String>,
    /// Its relay protocol version.
    pub protocol_version: Option<u16>,
}

/// One probe, as kept in history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeRecord {
    /// Unix seconds.
    pub at: u64,
    /// Its outcome.
    pub outcome: Outcome,
    /// Reason codes (empty on a pass).
    pub reasons: Vec<String>,
}

/// One candidate node, keyed by its relay address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    /// Its relay address.
    pub relay: SocketAddr,
    /// When discovery last saw it.
    pub last_seen: u64,
    /// Its last advert, if any.
    pub advert: Option<AdvertInfo>,
    /// The last [`Policy::window`] probes, oldest first.
    pub history: VecDeque<ProbeRecord>,
    /// Since when it is listed; `None` when it is not.
    pub listed_since: Option<u64>,
    /// When it was last delisted. Only passes after it count towards listing it again.
    #[serde(default)]
    pub delisted_at: Option<u64>,
}

/// What a probe changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// Nothing.
    None,
    /// The node was listed.
    Listed,
    /// The node was delisted.
    Delisted,
}

impl Candidate {
    fn new(relay: SocketAddr, now: u64) -> Self {
        Candidate {
            relay,
            last_seen: now,
            advert: None,
            history: VecDeque::new(),
            listed_since: None,
            delisted_at: None,
        }
    }

    fn streak(&self, f: impl Fn(Outcome) -> bool) -> usize {
        self.history
            .iter()
            .rev()
            .take_while(|r| f(r.outcome))
            .count()
    }

    /// Record a probe and apply `policy`.
    pub fn record(&mut self, rec: ProbeRecord, policy: &Policy) -> Transition {
        let at = rec.at;
        self.history.push_back(rec);
        while self.history.len() > policy.window.max(1) {
            self.history.pop_front();
        }
        if self.listed_since.is_some() {
            let fails = self.streak(|o| o == Outcome::Fail);
            let non_pass = self.streak(|o| o != Outcome::Pass);
            if fails >= policy.delist_after_fail || non_pass >= policy.delist_after {
                self.listed_since = None;
                self.delisted_at = Some(at);
                return Transition::Delisted;
            }
            return Transition::None;
        }
        let latest_pass = self.history.back().map(|r| r.outcome) == Some(Outcome::Pass);
        let passes = self
            .history
            .iter()
            .filter(|r| r.outcome == Outcome::Pass && self.delisted_at.is_none_or(|d| r.at > d))
            .count();
        let any_fail = self.history.iter().any(|r| r.outcome == Outcome::Fail);
        if latest_pass && passes >= policy.list_after && !any_fail {
            self.listed_since = Some(at);
            return Transition::Listed;
        }
        Transition::None
    }

    /// Probe counts in the window: `(pass, fail, unmeasured)`.
    pub fn counts(&self) -> (usize, usize, usize) {
        let n = |o| self.history.iter().filter(|r| r.outcome == o).count();
        (n(Outcome::Pass), n(Outcome::Fail), n(Outcome::Unmeasured))
    }
}

/// The lister's state: every candidate and its history. Saved between rounds so a restart keeps
/// the hysteresis.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListState {
    /// Candidates by relay address.
    pub candidates: BTreeMap<SocketAddr, Candidate>,
}

#[derive(Serialize, Deserialize)]
struct StateFile {
    schema: String,
    candidates: Vec<Candidate>,
}

impl ListState {
    /// Discovery saw `relay` at `now`. A new candidate is added only below `max` candidates.
    pub fn observe(&mut self, relay: SocketAddr, now: u64, max: usize) {
        if let Some(c) = self.candidates.get_mut(&relay) {
            c.last_seen = now;
        } else if self.candidates.len() < max {
            self.candidates.insert(relay, Candidate::new(relay, now));
        }
    }

    /// Record a probe of `relay`.
    pub fn record(
        &mut self,
        relay: SocketAddr,
        advert: Option<AdvertInfo>,
        rec: ProbeRecord,
        policy: &Policy,
    ) -> Transition {
        let c = self
            .candidates
            .entry(relay)
            .or_insert_with(|| Candidate::new(relay, rec.at));
        if advert.is_some() {
            c.advert = advert;
        }
        c.record(rec, policy)
    }

    /// Drop unlisted candidates discovery has not seen for `secs`.
    pub fn forget_older_than(&mut self, now: u64, secs: u64) -> usize {
        let before = self.candidates.len();
        self.candidates
            .retain(|_, c| c.listed_since.is_some() || c.last_seen.saturating_add(secs) >= now);
        before - self.candidates.len()
    }

    /// Listed nodes, sorted by relay address.
    pub fn listed(&self) -> impl Iterator<Item = &Candidate> {
        self.candidates
            .values()
            .filter(|c| c.listed_since.is_some())
    }

    /// The state file's JSON.
    pub fn to_json(&self) -> String {
        let f = StateFile {
            schema: STATE_SCHEMA.into(),
            candidates: self.candidates.values().cloned().collect(),
        };
        let mut s = serde_json::to_string_pretty(&f).unwrap_or_default();
        s.push('\n');
        s
    }

    /// Read a state file.
    pub fn from_json(s: &str) -> Result<ListState, String> {
        let f: StateFile = serde_json::from_str(s).map_err(|e| format!("state file: {e}"))?;
        if f.schema != STATE_SCHEMA {
            return Err(format!(
                "state file: schema {} is not {STATE_SCHEMA}",
                f.schema
            ));
        }
        Ok(ListState {
            candidates: f.candidates.into_iter().map(|c| (c.relay, c)).collect(),
        })
    }
}

/// What `node-list.json` says about the run that wrote it.
#[derive(Debug, Clone)]
pub struct ListMeta {
    /// Unix seconds.
    pub generated_at: u64,
    /// `mainnet`, `signet` or `regtest`.
    pub network: String,
    /// The share chain's genesis anchor, hex.
    pub genesis_anchor: String,
    /// The policy applied.
    pub policy: Policy,
}

#[derive(Serialize)]
struct Recent {
    probes: usize,
    pass: usize,
    fail: usize,
    unmeasured: usize,
    pass_rate: f64,
}

#[derive(Serialize)]
struct ListedNode {
    relay: String,
    host: String,
    relay_port: u16,
    sv1: Option<String>,
    sv1_port: Option<u16>,
    sv2: Option<String>,
    sv2_port: Option<u16>,
    sv2_authority_key: Option<String>,
    node_id: Option<String>,
    user_agent: Option<String>,
    protocol_version: Option<u16>,
    region: Option<String>,
    listed_since: u64,
    last_probe: Option<u64>,
    last_verdict: Option<Outcome>,
    reasons: Vec<String>,
    recent: Recent,
}

#[derive(Serialize)]
struct NodeList {
    schema: &'static str,
    generated_at: String,
    generated_at_unix: u64,
    network: String,
    genesis_anchor: String,
    policy: Policy,
    candidates: usize,
    listed: usize,
    nodes: Vec<ListedNode>,
}

/// RFC 3339, UTC, whole seconds.
pub fn rfc3339(secs: u64) -> String {
    chrono::DateTime::from_timestamp(i64::try_from(secs).unwrap_or(i64::MAX), 0)
        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

fn nonzero(p: u16) -> Option<u16> {
    (p != 0).then_some(p)
}

/// `node-list.json`: every listed node, sorted by relay address; the fields are documented in
/// `ghost-web/docs/node-pool.md` ("Being listed"). `region` is always `null`: nothing the probe
/// measures says where a node is, and a self-declared one would be unchecked.
pub fn render_node_list(state: &ListState, meta: &ListMeta) -> String {
    let nodes: Vec<ListedNode> = state
        .listed()
        .map(|c| {
            let ip = c.relay.ip();
            let a = c.advert.clone().unwrap_or_default();
            let sv1 = nonzero(a.sv1_port);
            let sv2 = nonzero(a.sv2_port);
            let (pass, fail, unmeasured) = c.counts();
            let probes = c.history.len();
            let last = c.history.back();
            ListedNode {
                relay: c.relay.to_string(),
                host: ip.to_string(),
                relay_port: c.relay.port(),
                sv1: sv1.map(|p| format!("stratum+tcp://{}", SocketAddr::new(ip, p))),
                sv1_port: sv1,
                sv2: sv2.map(|p| SocketAddr::new(ip, p).to_string()),
                sv2_port: sv2,
                sv2_authority_key: (sv2.is_some() && !a.sv2_authority_key.is_empty())
                    .then(|| a.sv2_authority_key.clone()),
                node_id: a.node_id.clone(),
                user_agent: a.user_agent.clone(),
                protocol_version: a.protocol_version,
                region: None,
                listed_since: c.listed_since.unwrap_or(0),
                last_probe: last.map(|r| r.at),
                last_verdict: last.map(|r| r.outcome),
                reasons: last.map(|r| r.reasons.clone()).unwrap_or_default(),
                recent: Recent {
                    probes,
                    pass,
                    fail,
                    unmeasured,
                    pass_rate: if probes == 0 {
                        0.0
                    } else {
                        (pass as f64 * 1000.0 / probes as f64).round() / 1000.0
                    },
                },
            }
        })
        .collect();
    let doc = NodeList {
        schema: LIST_SCHEMA,
        generated_at: rfc3339(meta.generated_at),
        generated_at_unix: meta.generated_at,
        network: meta.network.clone(),
        genesis_anchor: meta.genesis_anchor.clone(),
        policy: meta.policy,
        candidates: state.candidates.len(),
        listed: nodes.len(),
        nodes,
    };
    let mut s = serde_json::to_string_pretty(&doc).unwrap_or_default();
    s.push('\n');
    s
}

/// What the DNS fragment holds.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// The owner name, as written (relative to the zone's origin, or absolute with a final dot).
    pub name: String,
    /// TTL, seconds.
    pub ttl: u32,
    /// Only listed nodes whose SV1 port is this one go in: a DNS name carries an IP, not a port,
    /// so a miner pointed at the name uses this port on whichever IP it gets.
    pub sv1_port: u16,
    /// Most records written.
    pub max_records: usize,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            name: "pool".into(),
            ttl: 300,
            sv1_port: 3333,
            max_records: 32,
        }
    }
}

/// A zone-file fragment: one A or AAAA record per listed IP whose SV1 port is
/// [`DnsConfig::sv1_port`], sorted. Over [`DnsConfig::max_records`], the IPs kept are those with
/// the best recent pass rate, then the longest listed, then the lowest address, so the choice is
/// deterministic. Files only: this never calls a DNS provider.
pub fn render_dns(state: &ListState, cfg: &DnsConfig, generated_at: u64) -> String {
    // One entry per IP: its best node's rank.
    let mut by_ip: BTreeMap<IpAddr, (usize, u64)> = BTreeMap::new();
    let mut listed = 0usize;
    for c in state.listed() {
        listed += 1;
        if c.advert.as_ref().map(|a| a.sv1_port) != Some(cfg.sv1_port) {
            continue;
        }
        let (pass, ..) = c.counts();
        let rank = (
            pass * 1000 / c.history.len().max(1),
            c.listed_since.unwrap_or(u64::MAX),
        );
        by_ip
            .entry(c.relay.ip())
            .and_modify(|r| {
                if rank.0 > r.0 || (rank.0 == r.0 && rank.1 < r.1) {
                    *r = rank
                }
            })
            .or_insert(rank);
    }
    let mut ranked: Vec<(IpAddr, (usize, u64))> = by_ip.into_iter().collect();
    ranked.sort_by(|a, b| {
        b.1 .0
            .cmp(&a.1 .0)
            .then(a.1 .1.cmp(&b.1 .1))
            .then(a.0.cmp(&b.0))
    });
    let eligible = ranked.len();
    ranked.truncate(cfg.max_records);
    let mut ips: Vec<IpAddr> = ranked.into_iter().map(|(ip, _)| ip).collect();
    ips.sort();
    let mut s = format!(
        "; {DNS_SCHEMA}: generated by ghost-audit list at {}. Do not edit by hand.\n\
         ; {listed} listed, {eligible} on SV1 port {}, {} written (at most {}).\n",
        rfc3339(generated_at),
        cfg.sv1_port,
        ips.len(),
        cfg.max_records
    );
    if ips.is_empty() {
        s.push_str("; No records: publishing this fragment leaves the name with no address.\n");
    }
    for ip in ips {
        let t = if ip.is_ipv4() { "A" } else { "AAAA" };
        s.push_str(&format!("{} {} IN {t} {ip}\n", cfg.name, cfg.ttl));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn rec(at: u64, o: Outcome) -> ProbeRecord {
        ProbeRecord {
            at,
            outcome: o,
            reasons: match o {
                Outcome::Pass => vec![],
                Outcome::Fail => vec!["job_wrong_treasury".into()],
                Outcome::Unmeasured => vec!["stratum_unreachable".into()],
            },
        }
    }

    fn run(c: &mut Candidate, p: &Policy, seq: &[Outcome]) -> Vec<Transition> {
        let start = c.history.back().map_or(0, |r| r.at + 1);
        seq.iter()
            .enumerate()
            .map(|(i, o)| c.record(rec(start + i as u64, *o), p))
            .collect()
    }

    use Outcome::{Fail as F, Pass as P, Unmeasured as U};
    use Transition::{Delisted as D, Listed as L, None as N};

    #[test]
    fn listing_needs_n_passes_and_the_latest_a_pass() {
        let p = Policy::default();
        let mut c = Candidate::new(sa("8.8.8.8:8566"), 0);
        assert_eq!(run(&mut c, &p, &[P, P]), vec![N, N]);
        assert_eq!(run(&mut c, &p, &[P]), vec![L]);
        assert_eq!(c.listed_since, Some(2));
        // Passes need not be consecutive, but the listing probe must be one.
        let mut c = Candidate::new(sa("8.8.8.8:8566"), 0);
        assert_eq!(run(&mut c, &p, &[P, U, P, U, P]), vec![N, N, N, N, L]);
        let mut c = Candidate::new(sa("8.8.8.8:8566"), 0);
        assert_eq!(run(&mut c, &p, &[P, P, P]).last(), Some(&L));
    }

    #[test]
    fn unmeasured_never_counts_as_a_pass() {
        let p = Policy::default();
        let mut c = Candidate::new(sa("8.8.8.8:8566"), 0);
        assert!(run(&mut c, &p, &[U; 50]).iter().all(|t| *t == N));
        assert_eq!(c.listed_since, None);
        // Two passes among unmeasured are still two.
        assert!(run(&mut c, &p, &[P, U, U, P, U, U]).iter().all(|t| *t == N));
        assert_eq!(c.counts(), (2, 0, 4));
    }

    #[test]
    fn a_node_that_fails_is_never_listed_while_the_fail_is_in_the_window() {
        let p = Policy::default();
        let mut c = Candidate::new(sa("8.8.8.8:8566"), 0);
        // One fail among passes: the next window-1 probes cannot list it.
        assert_eq!(run(&mut c, &p, &[F, P, P, P, P, P]), vec![N, N, N, N, N, N]);
        // The fail has aged out of the 6-probe window: listed.
        assert_eq!(run(&mut c, &p, &[P]), vec![L]);
        // A node that always fails is never listed.
        let mut c = Candidate::new(sa("8.8.8.8:8566"), 0);
        assert!(run(&mut c, &p, &[F; 30]).iter().all(|t| *t == N));
        let mut c = Candidate::new(sa("8.8.8.8:8566"), 0);
        assert!(run(&mut c, &p, &[P, F].repeat(20)).iter().all(|t| *t == N));
    }

    #[test]
    fn delisting_has_hysteresis_and_a_fail_is_immediate() {
        let p = Policy::default();
        let mut c = Candidate::new(sa("8.8.8.8:8566"), 0);
        run(&mut c, &p, &[P, P, P]);
        assert!(c.listed_since.is_some());
        // Two unmeasured then a pass: still listed.
        assert_eq!(run(&mut c, &p, &[U, U, P]), vec![N, N, N]);
        // Three non-passes in a row delist.
        assert_eq!(run(&mut c, &p, &[U, U, U]), vec![N, N, D]);
        // Relisting needs list_after passes again, all after the delisting.
        assert_eq!(run(&mut c, &p, &[P, P]), vec![N, N]);
        assert_eq!(run(&mut c, &p, &[P]), vec![L]);
        // One fail delists at once.
        assert_eq!(run(&mut c, &p, &[F]), vec![D]);
        // A looser policy keeps a node through one fail.
        let loose = Policy {
            delist_after_fail: 2,
            ..Policy::default()
        };
        let mut c = Candidate::new(sa("8.8.8.8:8566"), 0);
        run(&mut c, &loose, &[P, P, P]);
        assert_eq!(run(&mut c, &loose, &[F, P, F, F]), vec![N, N, N, D]);
    }

    #[test]
    fn history_is_bounded_by_the_window() {
        let p = Policy::default();
        let mut c = Candidate::new(sa("8.8.8.8:8566"), 0);
        run(&mut c, &p, &[P; 100]);
        assert_eq!(c.history.len(), p.window);
        assert!(Policy {
            window: 2,
            ..Policy::default()
        }
        .check()
        .is_err());
        assert!(Policy {
            delist_after: 0,
            ..Policy::default()
        }
        .check()
        .is_err());
        assert!(Policy::default().check().is_ok());
    }

    fn listed_state() -> ListState {
        let p = Policy::default();
        let mut s = ListState::default();
        let nodes = [
            ("9.9.9.9:8566", 3333, 34255, "key9"),
            ("1.2.3.4:8566", 3333, 0, ""),
            ("[2a01:4f8::1]:8566", 3333, 34255, "key6"),
            ("5.6.7.8:9000", 4000, 34255, "key5"),
        ];
        for (i, (a, v1, v2, k)) in nodes.iter().enumerate() {
            s.observe(sa(a), 100, 1024);
            for t in 0..3u64 {
                s.record(
                    sa(a),
                    Some(AdvertInfo {
                        sv1_port: *v1,
                        sv2_port: *v2,
                        sv2_authority_key: k.to_string(),
                        user_agent: Some("ghost-np-relay/1.11.43".into()),
                        node_id: Some(format!("{i:064x}")),
                        protocol_version: Some(1),
                    }),
                    rec(1_000 + t, P),
                    &p,
                );
            }
        }
        // An unlisted candidate: never appears in either output.
        s.observe(sa("4.4.4.4:8566"), 100, 1024);
        s.record(sa("4.4.4.4:8566"), None, rec(1_000, U), &p);
        s
    }

    fn meta() -> ListMeta {
        ListMeta {
            generated_at: 1_793_620_800,
            network: "regtest".into(),
            genesis_anchor: "8d".repeat(32),
            policy: Policy::default(),
        }
    }

    #[test]
    fn the_node_list_has_the_documented_schema() {
        let s = listed_state();
        let v: serde_json::Value = serde_json::from_str(&render_node_list(&s, &meta())).unwrap();
        assert_eq!(v["schema"], LIST_SCHEMA);
        assert_eq!(v["generated_at"], "2026-11-02T12:00:00Z");
        assert_eq!(v["generated_at_unix"], 1_793_620_800u64);
        assert_eq!(v["network"], "regtest");
        assert_eq!(v["candidates"], 5);
        assert_eq!(v["listed"], 4);
        assert_eq!(v["policy"]["list_after"], 3);
        let nodes = v["nodes"].as_array().unwrap();
        let relays: Vec<&str> = nodes.iter().map(|n| n["relay"].as_str().unwrap()).collect();
        assert_eq!(
            relays,
            vec![
                "1.2.3.4:8566",
                "5.6.7.8:9000",
                "9.9.9.9:8566",
                "[2a01:4f8::1]:8566"
            ],
            "sorted by address, IPv4 first; the unlisted candidate is absent"
        );
        let n = &nodes[2];
        let keys: Vec<&str> = n.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        let mut want = vec![
            "relay",
            "host",
            "relay_port",
            "sv1",
            "sv1_port",
            "sv2",
            "sv2_port",
            "sv2_authority_key",
            "node_id",
            "user_agent",
            "protocol_version",
            "region",
            "listed_since",
            "last_probe",
            "last_verdict",
            "reasons",
            "recent",
        ];
        want.sort();
        let mut got = keys.clone();
        got.sort();
        assert_eq!(got, want);
        assert_eq!(n["host"], "9.9.9.9");
        assert_eq!(n["sv1"], "stratum+tcp://9.9.9.9:3333");
        assert_eq!(n["sv2"], "9.9.9.9:34255");
        assert_eq!(n["sv2_authority_key"], "key9");
        assert_eq!(n["region"], serde_json::Value::Null);
        assert_eq!(n["listed_since"], 1_002);
        assert_eq!(n["last_verdict"], "pass");
        assert_eq!(n["recent"]["pass_rate"], 1.0);
        assert_eq!(n["recent"]["probes"], 3);
        // No SV2 port: no SV2 endpoint and no key.
        assert_eq!(nodes[0]["sv2"], serde_json::Value::Null);
        assert_eq!(nodes[0]["sv2_authority_key"], serde_json::Value::Null);
        // IPv6 endpoints are bracketed.
        assert_eq!(nodes[3]["sv1"], "stratum+tcp://[2a01:4f8::1]:3333");
        assert_eq!(nodes[3]["host"], "2a01:4f8::1");
    }

    #[test]
    fn outputs_are_deterministic() {
        let a = listed_state();
        // The same nodes recorded in another order give byte-identical files.
        let mut b = ListState::default();
        for (k, c) in a.candidates.iter().rev() {
            b.candidates.insert(*k, c.clone());
        }
        assert_eq!(render_node_list(&a, &meta()), render_node_list(&b, &meta()));
        let d = DnsConfig::default();
        assert_eq!(render_dns(&a, &d, 5), render_dns(&b, &d, 5));
        // And the state round-trips through its file.
        let back = ListState::from_json(&a.to_json()).unwrap();
        assert_eq!(back, a);
        assert_eq!(back.to_json(), a.to_json());
        assert!(ListState::from_json("{\"schema\":\"x\",\"candidates\":[]}").is_err());
    }

    #[test]
    fn the_dns_fragment_is_a_sorted_record_list() {
        let s = listed_state();
        let out = render_dns(&s, &DnsConfig::default(), 1_793_620_800);
        let records: Vec<&str> = out.lines().filter(|l| !l.starts_with(';')).collect();
        assert_eq!(
            records,
            vec![
                "pool 300 IN A 1.2.3.4",
                "pool 300 IN A 9.9.9.9",
                "pool 300 IN AAAA 2a01:4f8::1",
            ],
            "only SV1 port 3333 nodes; 5.6.7.8 serves SV1 on 4000"
        );
        assert!(out.starts_with(
            "; ghost-audit/dns/v1: generated by ghost-audit list at 2026-11-02T12:00:00Z."
        ));
        assert!(out.contains("; 4 listed, 3 on SV1 port 3333, 3 written (at most 32).\n"));
        // Every record line is `<name> <ttl> IN <A|AAAA> <ip>` with an IP of its type.
        for r in &records {
            let f: Vec<&str> = r.split(' ').collect();
            assert_eq!(f.len(), 5);
            let ip: IpAddr = f[4].parse().unwrap();
            assert_eq!(f[3], if ip.is_ipv4() { "A" } else { "AAAA" });
        }
        // The cap keeps the best-ranked IPs, written sorted.
        let mut s2 = s.clone();
        let p = Policy::default();
        s2.record(sa("9.9.9.9:8566"), None, rec(2_000, U), &p);
        let d = DnsConfig {
            name: "pool.example.org.".into(),
            ttl: 60,
            max_records: 2,
            ..DnsConfig::default()
        };
        let out = render_dns(&s2, &d, 0);
        let records: Vec<&str> = out.lines().filter(|l| !l.starts_with(';')).collect();
        assert_eq!(
            records,
            vec![
                "pool.example.org. 60 IN A 1.2.3.4",
                "pool.example.org. 60 IN AAAA 2a01:4f8::1",
            ]
        );
        // Nothing listed: comments only, saying so.
        let out = render_dns(&ListState::default(), &DnsConfig::default(), 0);
        assert!(out.lines().all(|l| l.starts_with(';')));
        assert!(out.contains("no address"));
    }

    #[test]
    fn candidates_are_capped_and_stale_ones_forgotten() {
        let mut s = ListState::default();
        for i in 0..10u8 {
            s.observe(SocketAddr::from(([8, 8, 8, i], 1)), 0, 5);
        }
        assert_eq!(s.candidates.len(), 5);
        let p = Policy::default();
        for t in 0..3 {
            s.record(SocketAddr::from(([8, 8, 8, 0], 1)), None, rec(t, P), &p);
        }
        s.observe(SocketAddr::from(([8, 8, 8, 1], 1)), 1_000, 5);
        // Unlisted and unseen for over 500 s: forgotten. The listed one stays.
        assert_eq!(s.forget_older_than(1_000, 500), 3);
        assert_eq!(s.candidates.len(), 2);
    }
}
