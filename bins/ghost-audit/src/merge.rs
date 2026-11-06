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
//| FILE: merge.rs                                                                                                       |
//|======================================================================================================================|

//! Merged listing (W2.10): several listers' `node-list.json` combined into one, by majority.
//!
//! Anyone can run a lister ([`crate::lister`]), and one lister's list is that lister's claim.
//! `ghost-audit merge` takes the lists of a configured set of listers and lists a node only when a
//! **strict majority of the configured listers** list it, with the same endpoints:
//!
//! - **The majority is of the configured listers, not of those that answered.** A lister that
//!   cannot be reached, or whose list is malformed, of another schema, network or genesis, or
//!   stale, votes for nothing. So an outage can only shrink the merged list, never let fewer
//!   listers decide it. With fewer valid lists than a majority nothing could be listed at all:
//!   that is [`crate::merge::NoQuorum`], and nothing is written or pushed, so an outage of most
//!   listers leaves the last published list and DNS in place rather than publishing an empty
//!   one.
//! - **A vote is for a node and its endpoints**: its relay address, its SV1 and SV2 ports and its
//!   SV2 authority key. Listers that saw different adverts split their votes, so the merged list
//!   carries only endpoints a majority probed.
//! - Every input is checked before it votes ([`crate::merge::merge`]): the schema
//!   ([`crate::listing::LIST_SCHEMA`]), the network, the genesis anchor (the configured one, or
//!   the one a majority of the configured listers carry), its age, and every listed node's fields
//!   against its relay address, so a lister cannot list one host under another's name.
//!
//! The output has `node-list.json`'s schema, so the website reads it unchanged, with a `votes`
//! count on each node and a `merge` object saying which listers voted. Both outputs are sorted and
//! written atomically ([`crate::lister::write_atomic`]).
//!
//! **DNS push** ([`crate::merge::publish_dns`]) is provider-agnostic: after writing the fragment,
//! if its records differ from the ones last pushed (kept beside it as `<fragment>.pushed`), a
//! configured hook command runs with the fragment's path; no provider SDK is linked. The push is
//! recorded only when the hook exits 0, so a failed push is retried on the next run.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

use crate::lister::write_atomic;
use crate::listing::{
    dns_records, render_dns_entries, rfc3339, DnsConfig, DnsEntry, Endpoints, ListedNode, Outcome,
    Recent, LIST_SCHEMA,
};

/// Largest list read from one lister.
pub const MAX_LIST_BYTES: usize = 4 * 1024 * 1024;
/// How far ahead of this clock a list's time stamp may be.
pub const MAX_FUTURE_SECS: u64 = 600;

/// What fetching one lister's list gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// Its bytes.
    Body(Vec<u8>),
    /// It could not be read: no vote.
    Unreachable(String),
    /// It was read but cannot be a list (too large): no vote.
    Malformed(String),
}

/// Whether `source` is fetched over HTTP rather than read as a file.
pub fn is_url(source: &str) -> bool {
    source.starts_with("http://") || source.starts_with("https://")
}

/// `source` as printed and written: a URL without its user, password or query, which could carry
/// a credential; a path unchanged.
pub fn display_source(source: &str) -> String {
    if !is_url(source) {
        return source.to_string();
    }
    match reqwest::Url::parse(source) {
        Ok(mut u) => {
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.set_query(None);
            u.set_fragment(None);
            u.to_string()
        }
        Err(_) => "<an unparsable URL>".to_string(),
    }
}

/// Read one lister's list: an `http://` or `https://` URL (status 200 only, no redirects), or a
/// file. At most [`MAX_LIST_BYTES`].
pub async fn fetch(source: &str, timeout: Duration) -> Fetched {
    let too_large = || Fetched::Malformed(format!("larger than {MAX_LIST_BYTES} bytes"));
    if !is_url(source) {
        let path = Path::new(source);
        match tokio::fs::metadata(path).await {
            Ok(m) if m.len() > MAX_LIST_BYTES as u64 => return too_large(),
            Ok(_) => {}
            Err(e) => return Fetched::Unreachable(e.to_string()),
        }
        return match tokio::fs::read(path).await {
            Ok(b) if b.len() > MAX_LIST_BYTES => too_large(),
            Ok(b) => Fetched::Body(b),
            Err(e) => Fetched::Unreachable(e.to_string()),
        };
    }
    let client = match reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(e) => return Fetched::Unreachable(e.without_url().to_string()),
    };
    let mut resp = match client.get(source).send().await {
        Ok(r) => r,
        Err(e) => return Fetched::Unreachable(e.without_url().to_string()),
    };
    if resp.status() != reqwest::StatusCode::OK {
        return Fetched::Unreachable(format!("HTTP {}", resp.status().as_u16()));
    }
    if resp
        .content_length()
        .is_some_and(|n| n > MAX_LIST_BYTES as u64)
    {
        return too_large();
    }
    let mut body = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(c)) => {
                if body.len() + c.len() > MAX_LIST_BYTES {
                    return too_large();
                }
                body.extend_from_slice(&c);
            }
            Ok(None) => return Fetched::Body(body),
            Err(e) => return Fetched::Unreachable(e.without_url().to_string()),
        }
    }
}

/// What became of one lister's list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    /// It voted.
    Ok,
    /// It could not be read.
    Unreachable,
    /// It is not a valid list.
    Malformed,
    /// Its schema is not [`LIST_SCHEMA`].
    WrongSchema,
    /// It is for another network.
    WrongNetwork,
    /// It is on another share-chain genesis.
    WrongGenesis,
    /// It is older than the maximum age, or dated ahead of this clock.
    Stale,
}

impl SourceStatus {
    /// The word printed for it.
    pub fn label(self) -> &'static str {
        match self {
            SourceStatus::Ok => "ok",
            SourceStatus::Unreachable => "unreachable",
            SourceStatus::Malformed => "malformed",
            SourceStatus::WrongSchema => "wrong schema",
            SourceStatus::WrongNetwork => "wrong network",
            SourceStatus::WrongGenesis => "wrong genesis",
            SourceStatus::Stale => "stale",
        }
    }
}

/// One lister, as the merge saw it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceReport {
    /// Where its list came from ([`display_source`]).
    pub source: String,
    /// What became of it. Only [`SourceStatus::Ok`] votes.
    pub status: SourceStatus,
    /// Why, when it did not vote.
    pub detail: Option<String>,
    /// Nodes it lists, when it voted.
    pub listed: Option<usize>,
    /// When it was generated, when that could be read.
    pub generated_at_unix: Option<u64>,
}

/// What the merge checks inputs against.
#[derive(Debug, Clone)]
pub struct MergeConfig {
    /// The network every input must be for (`mainnet`, `signet`, `regtest`).
    pub network: String,
    /// The genesis anchor every input must carry, hex. `None`: the one a majority of the
    /// configured listers carry.
    pub genesis_anchor: Option<String>,
    /// A list generated longer ago than this does not vote.
    pub max_age_secs: u64,
    /// Unix seconds now.
    pub now: u64,
}

/// A merged node: the node as the majority listed it, and its votes.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MergedNode {
    #[serde(flatten)]
    pub(crate) node: ListedNode,
    /// Listers that listed it with these endpoints.
    pub votes: usize,
}

impl MergedNode {
    /// Its relay address, as listed.
    pub fn relay(&self) -> &str {
        &self.node.relay
    }
}

/// The merged list.
#[derive(Debug, Clone, PartialEq)]
pub struct Merged {
    /// The network.
    pub network: String,
    /// The share-chain genesis every voting list carries, hex.
    pub genesis_anchor: String,
    /// The listing policy, when every voting list applied the same one.
    pub policy: Option<serde_json::Value>,
    /// Listers configured.
    pub configured: usize,
    /// Listers whose lists voted.
    pub voting: usize,
    /// Votes a node needs: a strict majority of `configured`.
    pub threshold: usize,
    /// Distinct relays listed by any voting lister.
    pub candidates: usize,
    /// Nodes listed, sorted by relay address.
    pub nodes: Vec<MergedNode>,
    /// Every lister, sorted by source.
    pub sources: Vec<SourceReport>,
}

/// Fewer valid lists than a majority of the configured listers: nothing can be listed, and
/// nothing is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoQuorum {
    /// Listers configured.
    pub configured: usize,
    /// Lists that could vote.
    pub voting: usize,
    /// Votes a node needs.
    pub threshold: usize,
    /// Every lister, sorted by source.
    pub sources: Vec<SourceReport>,
}

impl std::fmt::Display for NoQuorum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no quorum: {} of {} listers gave a valid list and a node needs {} votes, so nothing \
             could be listed; nothing was written or pushed",
            self.voting, self.configured, self.threshold
        )
    }
}

/// Votes needed of `configured` listers: a strict majority.
pub fn threshold(configured: usize) -> usize {
    configured / 2 + 1
}

#[derive(serde::Deserialize)]
struct InList {
    generated_at_unix: u64,
    network: String,
    genesis_anchor: String,
    #[serde(default)]
    policy: Option<serde_json::Value>,
    nodes: Vec<ListedNode>,
}

type Reject = (SourceStatus, String);

fn malformed(why: impl Into<String>) -> Reject {
    (SourceStatus::Malformed, why.into())
}

fn port(p: Option<u16>, what: &str) -> Result<Option<u16>, Reject> {
    match p {
        Some(0) => Err(malformed(format!("{what} 0"))),
        p => Ok(p),
    }
}

/// One listed node's fields checked against its relay address: everything a miner or the DNS is
/// pointed at must be derived from the relay's IP exactly as `ghost-audit list` derives it.
fn check_node(n: &ListedNode) -> Result<VoteKey, Reject> {
    let relay: SocketAddr = n
        .relay
        .parse()
        .map_err(|_| malformed(format!("node relay {:?} is not an IP:port", n.relay)))?;
    if relay.port() == 0 || n.host != relay.ip().to_string() || n.relay_port != relay.port() {
        return Err(malformed(format!(
            "node {}: host or relay_port does not match the relay address",
            n.relay
        )));
    }
    let sv1 = port(n.sv1_port, "sv1_port")?;
    let sv2 = port(n.sv2_port, "sv2_port")?;
    let key = n.sv2_authority_key.clone().unwrap_or_default();
    let e = Endpoints::of(relay, sv1, sv2, &key);
    if e.sv1 != n.sv1 || e.sv2 != n.sv2 || e.sv2_authority_key != n.sv2_authority_key {
        return Err(malformed(format!(
            "node {}: its endpoints are not its relay IP with its ports",
            n.relay
        )));
    }
    if sv1.is_none() && sv2.is_none() {
        return Err(malformed(format!("node {}: no stratum port", n.relay)));
    }
    let r = &n.recent;
    if r.pass + r.fail + r.unmeasured != r.probes {
        return Err(malformed(format!(
            "node {}: recent counts do not add up",
            n.relay
        )));
    }
    Ok(VoteKey {
        relay,
        sv1_port: sv1,
        sv2_port: sv2,
        sv2_authority_key: e.sv2_authority_key,
    })
}

fn parse_list(body: &[u8]) -> Result<(InList, Vec<VoteKey>), Reject> {
    let text = std::str::from_utf8(body).map_err(|_| malformed("not UTF-8"))?;
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| malformed(format!("not JSON: {e}")))?;
    match v.get("schema").and_then(|s| s.as_str()) {
        Some(LIST_SCHEMA) => {}
        Some(other) => {
            return Err((
                SourceStatus::WrongSchema,
                format!("schema {other:?}, not {LIST_SCHEMA}"),
            ))
        }
        None => {
            return Err((
                SourceStatus::WrongSchema,
                format!("no schema, not {LIST_SCHEMA}"),
            ))
        }
    }
    let mut list: InList = serde_json::from_value(v).map_err(|e| malformed(e.to_string()))?;
    let g = list.genesis_anchor.to_ascii_lowercase();
    if g.len() != 64 || !g.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(malformed("genesis_anchor is not 64 hex characters"));
    }
    list.genesis_anchor = g;
    let mut keys = Vec::with_capacity(list.nodes.len());
    let mut seen = BTreeSet::new();
    for n in &list.nodes {
        let k = check_node(n)?;
        if !seen.insert(k.relay) {
            return Err(malformed(format!("node {} is listed twice", k.relay)));
        }
        keys.push(k);
    }
    Ok((list, keys))
}

/// What a vote is for: a node and the endpoints it was probed on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct VoteKey {
    relay: SocketAddr,
    sv1_port: Option<u16>,
    sv2_port: Option<u16>,
    sv2_authority_key: Option<String>,
}

/// The value most voters give, `None` only when none gives one; a tie goes to the smallest.
fn most_common<T: Ord + Clone>(values: impl Iterator<Item = Option<T>>) -> Option<T> {
    let mut counts: BTreeMap<T, usize> = BTreeMap::new();
    for v in values.flatten() {
        *counts.entry(v).or_insert(0) += 1;
    }
    let best = counts.values().copied().max()?;
    counts.into_iter().find(|(_, n)| *n == best).map(|(v, _)| v)
}

fn verdict_rank(o: Option<Outcome>) -> u8 {
    match o {
        Some(Outcome::Pass) => 0,
        Some(Outcome::Fail) => 1,
        Some(Outcome::Unmeasured) => 2,
        None => 3,
    }
}

fn merged_node(key: &VoteKey, voters: &[&ListedNode], threshold: usize) -> MergedNode {
    let e = Endpoints::of(
        key.relay,
        key.sv1_port,
        key.sv2_port,
        key.sv2_authority_key.as_deref().unwrap_or(""),
    );
    let mut since: Vec<u64> = voters.iter().map(|n| n.listed_since).collect();
    since.sort_unstable();
    // Listed by a majority since the threshold-th lister listed it.
    let listed_since = since[threshold.min(since.len()).max(1) - 1];
    let latest = voters
        .iter()
        .min_by(|a, b| {
            b.last_probe
                .cmp(&a.last_probe)
                .then(verdict_rank(a.last_verdict).cmp(&verdict_rank(b.last_verdict)))
                .then(a.reasons.cmp(&b.reasons))
        })
        .copied();
    let sum = |f: fn(&Recent) -> usize| voters.iter().map(|n| f(&n.recent)).sum::<usize>();
    MergedNode {
        node: ListedNode {
            relay: key.relay.to_string(),
            host: key.relay.ip().to_string(),
            relay_port: key.relay.port(),
            sv1: e.sv1,
            sv1_port: key.sv1_port,
            sv2: e.sv2,
            sv2_port: key.sv2_port,
            sv2_authority_key: e.sv2_authority_key,
            node_id: most_common(voters.iter().map(|n| n.node_id.clone())),
            user_agent: most_common(voters.iter().map(|n| n.user_agent.clone())),
            protocol_version: most_common(voters.iter().map(|n| n.protocol_version)),
            region: None,
            listed_since,
            last_probe: latest.and_then(|n| n.last_probe),
            last_verdict: latest.and_then(|n| n.last_verdict),
            reasons: latest.map(|n| n.reasons.clone()).unwrap_or_default(),
            recent: Recent::of(sum(|r| r.pass), sum(|r| r.fail), sum(|r| r.unmeasured)),
        },
        votes: voters.len(),
    }
}

/// Merge the lists of the configured listers: `inputs` holds one `(source, fetched)` per
/// configured lister, in any order. A node is listed when at least [`threshold`] of them
/// (`inputs.len()`, not the number that answered) list it with the same endpoints.
pub fn merge(inputs: &[(String, Fetched)], cfg: &MergeConfig) -> Result<Merged, NoQuorum> {
    let configured = inputs.len();
    let t = threshold(configured);
    let mut order: Vec<usize> = (0..configured).collect();
    order.sort_by(|a, b| inputs[*a].0.cmp(&inputs[*b].0));

    let mut sources: Vec<SourceReport> = Vec::with_capacity(configured);
    // Index into `sources` and the list, for lists that pass every check but the genesis.
    let mut parsed: Vec<(usize, InList, Vec<VoteKey>)> = Vec::new();
    for i in order {
        let (source, fetched) = &inputs[i];
        let mut report = SourceReport {
            source: source.clone(),
            status: SourceStatus::Ok,
            detail: None,
            listed: None,
            generated_at_unix: None,
        };
        let outcome = match fetched {
            Fetched::Unreachable(why) => Err((SourceStatus::Unreachable, why.clone())),
            Fetched::Malformed(why) => Err(malformed(why.clone())),
            Fetched::Body(b) => parse_list(b),
        };
        let checked = outcome.and_then(|(list, keys)| {
            report.generated_at_unix = Some(list.generated_at_unix);
            if list.network != cfg.network {
                return Err((
                    SourceStatus::WrongNetwork,
                    format!("network {:?}, not {:?}", list.network, cfg.network),
                ));
            }
            if list.generated_at_unix > cfg.now.saturating_add(MAX_FUTURE_SECS) {
                return Err((
                    SourceStatus::Stale,
                    format!(
                        "generated {} s ahead of this clock",
                        list.generated_at_unix - cfg.now
                    ),
                ));
            }
            let age = cfg.now.saturating_sub(list.generated_at_unix);
            if age > cfg.max_age_secs {
                return Err((
                    SourceStatus::Stale,
                    format!(
                        "generated {age} s ago, over the maximum age of {} s",
                        cfg.max_age_secs
                    ),
                ));
            }
            Ok((list, keys))
        });
        match checked {
            Ok((list, keys)) => parsed.push((sources.len(), list, keys)),
            Err((status, why)) => {
                report.status = status;
                report.detail = Some(why);
            }
        }
        sources.push(report);
    }

    // Too few valid lists for any node to reach a majority, whatever their genesis.
    if parsed.len() < t {
        for (idx, list, _) in &parsed {
            sources[*idx].listed = Some(list.nodes.len());
        }
        return Err(NoQuorum {
            configured,
            voting: parsed.len(),
            threshold: t,
            sources,
        });
    }
    // The genesis: the configured one, or the one a majority of the configured listers carry.
    let genesis = match &cfg.genesis_anchor {
        Some(g) => Some(g.to_ascii_lowercase()),
        None => {
            let mut count: BTreeMap<&str, usize> = BTreeMap::new();
            for (_, l, _) in &parsed {
                *count.entry(l.genesis_anchor.as_str()).or_insert(0) += 1;
            }
            count
                .into_iter()
                .find(|(_, n)| *n >= t)
                .map(|(g, _)| g.to_string())
        }
    };
    let mut voting: Vec<(InList, Vec<VoteKey>)> = Vec::new();
    for (idx, list, keys) in parsed {
        let r = &mut sources[idx];
        match &genesis {
            Some(g) if *g == list.genesis_anchor => {
                r.listed = Some(list.nodes.len());
                voting.push((list, keys));
            }
            Some(g) => {
                r.status = SourceStatus::WrongGenesis;
                r.detail = Some(format!(
                    "genesis {}…, not {}…",
                    &list.genesis_anchor[..16],
                    &g[..g.len().min(16)]
                ));
            }
            None => {
                r.status = SourceStatus::WrongGenesis;
                r.detail = Some(format!(
                    "genesis {}…: no genesis is carried by {t} of {configured} listers",
                    &list.genesis_anchor[..16]
                ));
            }
        }
    }
    let Some(genesis) = genesis.filter(|_| voting.len() >= t) else {
        return Err(NoQuorum {
            configured,
            voting: voting.len(),
            threshold: t,
            sources,
        });
    };

    let mut votes: BTreeMap<VoteKey, Vec<&ListedNode>> = BTreeMap::new();
    let mut relays: BTreeSet<SocketAddr> = BTreeSet::new();
    for (list, keys) in &voting {
        for (n, k) in list.nodes.iter().zip(keys) {
            relays.insert(k.relay);
            votes.entry(k.clone()).or_default().push(n);
        }
    }
    let nodes: Vec<MergedNode> = votes
        .iter()
        .filter(|(_, v)| v.len() >= t)
        .map(|(k, v)| merged_node(k, v, t))
        .collect();
    let first = voting[0].0.policy.clone();
    let policy = voting
        .iter()
        .all(|(l, _)| l.policy == first)
        .then_some(first)
        .flatten();
    Ok(Merged {
        network: cfg.network.clone(),
        genesis_anchor: genesis,
        policy,
        configured,
        voting: voting.len(),
        threshold: t,
        candidates: relays.len(),
        nodes,
        sources,
    })
}

#[derive(Serialize)]
struct MergeInfo<'a> {
    configured: usize,
    voting: usize,
    threshold: usize,
    sources: &'a [SourceReport],
}

#[derive(Serialize)]
struct MergedList<'a> {
    schema: &'static str,
    generated_at: String,
    generated_at_unix: u64,
    network: &'a str,
    genesis_anchor: &'a str,
    policy: &'a Option<serde_json::Value>,
    candidates: usize,
    listed: usize,
    nodes: &'a [MergedNode],
    merge: MergeInfo<'a>,
}

/// The merged `node-list.json`: schema [`LIST_SCHEMA`], the fields `ghost-audit list` writes,
/// plus `votes` on each node and a `merge` object (listers configured and voting, the threshold
/// and every lister's status). Sorted, so two runs over the same inputs differ only in the time
/// stamp.
pub fn render_merged(m: &Merged, generated_at: u64) -> String {
    let doc = MergedList {
        schema: LIST_SCHEMA,
        generated_at: rfc3339(generated_at),
        generated_at_unix: generated_at,
        network: &m.network,
        genesis_anchor: &m.genesis_anchor,
        policy: &m.policy,
        candidates: m.candidates,
        listed: m.nodes.len(),
        nodes: &m.nodes,
        merge: MergeInfo {
            configured: m.configured,
            voting: m.voting,
            threshold: m.threshold,
            sources: &m.sources,
        },
    };
    let mut s = serde_json::to_string_pretty(&doc).unwrap_or_default();
    s.push('\n');
    s
}

/// The DNS fragment of the merged list, ranked as [`crate::listing::render_dns`] ranks a lister's.
pub fn render_merged_dns(m: &Merged, cfg: &DnsConfig, generated_at: u64) -> String {
    let entries: Vec<DnsEntry> = m
        .nodes
        .iter()
        .filter_map(|n| {
            let relay: SocketAddr = n.node.relay.parse().ok()?;
            Some(DnsEntry {
                ip: relay.ip(),
                sv1_port: n.node.sv1_port,
                pass_permille: n.node.recent.pass * 1000 / n.node.recent.probes.max(1),
                listed_since: n.node.listed_since,
            })
        })
        .collect();
    render_dns_entries(&entries, cfg, generated_at, "merge")
}

/// The command run when the DNS records change.
#[derive(Debug, Clone)]
pub struct Hook {
    /// The program, run directly (no shell).
    pub program: PathBuf,
    /// Its arguments, before the fragment's path.
    pub args: Vec<String>,
    /// Longest it may run; it is killed after.
    pub timeout: Duration,
    /// The DNS owner name the fragment's records are for.
    pub name: String,
}

/// What [`publish_dns`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushOutcome {
    /// The fragment was written; no hook is configured.
    NoHook,
    /// The records are the ones last pushed: the hook was not run.
    Unchanged,
    /// The hook ran and exited 0; the push is recorded.
    Pushed,
    /// The hook failed; nothing is recorded, so the next run tries again.
    Failed(String),
}

/// Where the records last pushed are kept: `<fragment>.pushed`.
pub fn pushed_path(fragment: &Path) -> PathBuf {
    let mut p = fragment.as_os_str().to_owned();
    p.push(".pushed");
    PathBuf::from(p)
}

fn joined(r: &BTreeSet<String>) -> String {
    r.iter().cloned().collect::<Vec<_>>().join("\n")
}

/// Write the fragment to `out` atomically and, if a hook is configured and the records differ
/// from those last pushed, run it as `<program> <args…> <out>` with the environment:
///
/// - `GHOST_DNS_FRAGMENT`: the fragment's path (also its last argument);
/// - `GHOST_DNS_NAME`: the owner name its records are for;
/// - `GHOST_DNS_OLD_RECORDS` and `GHOST_DNS_NEW_RECORDS`: the records last pushed and the new
///   ones, one `<name> <ttl> IN <A|AAAA> <ip>` per line, sorted;
/// - `GHOST_DNS_FIRST_PUSH`: `1` when nothing was pushed before (the old records are then unknown,
///   not empty), else `0`.
///
/// Its stdin is closed and its output goes to this process's. The push is recorded (the fragment
/// copied to [`pushed_path`]) only when it exits 0 within its timeout.
pub async fn publish_dns(
    out: &Path,
    fragment: &str,
    hook: Option<&Hook>,
) -> Result<PushOutcome, String> {
    write_atomic(out, fragment).map_err(|e| format!("{}: {e}", out.display()))?;
    let Some(hook) = hook else {
        return Ok(PushOutcome::NoHook);
    };
    let pushed = pushed_path(out);
    let old = match std::fs::read_to_string(&pushed) {
        Ok(s) => Some(dns_records(&s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("{}: {e}", pushed.display())),
    };
    let new = dns_records(fragment);
    if old.as_ref() == Some(&new) {
        return Ok(PushOutcome::Unchanged);
    }
    let mut cmd = tokio::process::Command::new(&hook.program);
    cmd.args(&hook.args)
        .arg(out)
        .env("GHOST_DNS_FRAGMENT", out)
        .env("GHOST_DNS_NAME", &hook.name)
        .env(
            "GHOST_DNS_OLD_RECORDS",
            old.as_ref().map(joined).unwrap_or_default(),
        )
        .env("GHOST_DNS_NEW_RECORDS", joined(&new))
        .env(
            "GHOST_DNS_FIRST_PUSH",
            if old.is_none() { "1" } else { "0" },
        )
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return Ok(PushOutcome::Failed(format!(
                "{} did not start: {e}",
                hook.program.display()
            )))
        }
    };
    let status = match tokio::time::timeout(hook.timeout, child.wait()).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Ok(PushOutcome::Failed(e.to_string())),
        Err(_) => {
            let _ = child.kill().await;
            return Ok(PushOutcome::Failed(format!(
                "{} ran over {} s and was killed",
                hook.program.display(),
                hook.timeout.as_secs()
            )));
        }
    };
    if !status.success() {
        return Ok(PushOutcome::Failed(format!(
            "{} exited {status}",
            hook.program.display()
        )));
    }
    write_atomic(&pushed, fragment).map_err(|e| format!("{}: {e}", pushed.display()))?;
    Ok(PushOutcome::Pushed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listing::{render_node_list, AdvertInfo, ListMeta, ListState, Policy, ProbeRecord};

    const G: &str = "8d8cd561340ff83e99410e115619d64ad94516264d3e5cd6a991109c69f1229c";
    const NOW: u64 = 1_793_620_800;

    /// A node: relay, SV1 port, SV2 port, SV2 key.
    type N<'a> = (&'a str, u16, u16, &'a str);

    /// A real `ghost-audit list` output listing `nodes`, generated at `at`.
    fn list_at(nodes: &[N], at: u64, network: &str, genesis: &str) -> Vec<u8> {
        let p = Policy::default();
        let mut s = ListState::default();
        for (i, (relay, v1, v2, key)) in nodes.iter().enumerate() {
            let a: SocketAddr = relay.parse().unwrap();
            s.observe(a, 100, 1024);
            for t in 0..3u64 {
                s.record(
                    a,
                    Some(AdvertInfo {
                        sv1_port: *v1,
                        sv2_port: *v2,
                        sv2_authority_key: key.to_string(),
                        user_agent: Some("ghost-np-relay/2.0.0".into()),
                        node_id: Some(format!("{i:064x}")),
                        protocol_version: Some(1),
                    }),
                    ProbeRecord {
                        at: 1_000 + t,
                        outcome: Outcome::Pass,
                        reasons: vec![],
                    },
                    &p,
                );
            }
        }
        render_node_list(
            &s,
            &ListMeta {
                generated_at: at,
                network: network.into(),
                genesis_anchor: genesis.into(),
                policy: p,
            },
        )
        .into_bytes()
    }

    fn list(nodes: &[N]) -> Fetched {
        Fetched::Body(list_at(nodes, NOW - 60, "regtest", G))
    }

    fn cfg() -> MergeConfig {
        MergeConfig {
            network: "regtest".into(),
            genesis_anchor: None,
            max_age_secs: 3_600,
            now: NOW,
        }
    }

    fn inputs(v: Vec<Fetched>) -> Vec<(String, Fetched)> {
        v.into_iter()
            .enumerate()
            .map(|(i, f)| (format!("lister-{i}"), f))
            .collect()
    }

    fn relays(m: &Merged) -> Vec<String> {
        m.nodes.iter().map(|n| n.node.relay.clone()).collect()
    }

    const X: N = ("1.1.1.1:8566", 3333, 0, "");
    const Y: N = ("2.2.2.2:8566", 3333, 34255, "keyY");
    const Z: N = ("3.3.3.3:8566", 3333, 0, "");
    const W: N = ("4.4.4.4:8566", 3333, 0, "");

    #[test]
    fn a_node_needs_a_strict_majority_of_the_configured_listers() {
        let m = merge(
            &inputs(vec![list(&[X, Y]), list(&[X]), list(&[Y, Z])]),
            &cfg(),
        )
        .unwrap();
        assert_eq!((m.configured, m.voting, m.threshold), (3, 3, 2));
        assert_eq!(relays(&m), ["1.1.1.1:8566", "2.2.2.2:8566"]);
        assert_eq!(m.candidates, 3);
        assert!(m.nodes.iter().all(|n| n.votes == 2));
        // One lister of one: its list.
        let m = merge(&inputs(vec![list(&[Z])]), &cfg()).unwrap();
        assert_eq!((m.threshold, relays(&m)), (1, vec!["3.3.3.3:8566".into()]));
    }

    #[test]
    fn a_tie_is_not_a_majority() {
        // Four listers: two votes is a tie, three is a majority.
        let m = merge(
            &inputs(vec![list(&[X, Y]), list(&[X, Y]), list(&[Y]), list(&[Z])]),
            &cfg(),
        )
        .unwrap();
        assert_eq!(m.threshold, 3);
        assert_eq!(relays(&m), ["2.2.2.2:8566"]);
        // Two listers: both must agree.
        let m = merge(&inputs(vec![list(&[X, Y]), list(&[Y])]), &cfg()).unwrap();
        assert_eq!(relays(&m), ["2.2.2.2:8566"]);
    }

    #[test]
    fn an_unreachable_lister_votes_for_nothing_and_can_only_shrink_the_list() {
        let down = || Fetched::Unreachable("connection refused".into());
        // Three configured, one down: a node needs both of the others.
        let m = merge(&inputs(vec![list(&[X, Y]), list(&[X]), down()]), &cfg()).unwrap();
        assert_eq!((m.configured, m.voting, m.threshold), (3, 2, 2));
        assert_eq!(relays(&m), ["1.1.1.1:8566"]);
        let s = m
            .sources
            .iter()
            .find(|s| s.status == SourceStatus::Unreachable)
            .unwrap();
        assert_eq!(s.detail.as_deref(), Some("connection refused"));
        assert_eq!(s.listed, None);
        // Two of three down: nothing could reach a majority. No quorum, nothing written.
        let e = merge(&inputs(vec![list(&[X, Y]), down(), down()]), &cfg()).unwrap_err();
        assert_eq!((e.configured, e.voting, e.threshold), (3, 1, 2));
        assert!(e.to_string().contains("nothing was written or pushed"));
    }

    #[test]
    fn malformed_and_wrong_inputs_are_skipped_by_name() {
        let good = list(&[X]);
        let mut tampered: serde_json::Value =
            serde_json::from_slice(&list_at(&[Y], NOW, "regtest", G)).unwrap();
        tampered["nodes"][0]["host"] = "9.9.9.9".into();
        let mut redirected: serde_json::Value =
            serde_json::from_slice(&list_at(&[Y], NOW, "regtest", G)).unwrap();
        redirected["nodes"][0]["sv1"] = "stratum+tcp://9.9.9.9:3333".into();
        let mut twice: serde_json::Value =
            serde_json::from_slice(&list_at(&[Y], NOW, "regtest", G)).unwrap();
        let n = twice["nodes"][0].clone();
        twice["nodes"].as_array_mut().unwrap().push(n);
        let mut schema: serde_json::Value =
            serde_json::from_slice(&list_at(&[X], NOW, "regtest", G)).unwrap();
        schema["schema"] = "ghost-audit/node-list/v2".into();
        let body = |v: serde_json::Value| Fetched::Body(v.to_string().into_bytes());
        let cases: Vec<(Fetched, SourceStatus, &str)> = vec![
            (
                Fetched::Body(b"not json".to_vec()),
                SourceStatus::Malformed,
                "not JSON",
            ),
            (
                Fetched::Body(vec![0xff, 0xfe]),
                SourceStatus::Malformed,
                "not UTF-8",
            ),
            (
                Fetched::Body(b"{}".to_vec()),
                SourceStatus::WrongSchema,
                "no schema",
            ),
            (body(schema), SourceStatus::WrongSchema, "node-list/v2"),
            (
                body(tampered),
                SourceStatus::Malformed,
                "does not match the relay",
            ),
            (body(redirected), SourceStatus::Malformed, "endpoints"),
            (body(twice), SourceStatus::Malformed, "listed twice"),
            (
                Fetched::Body(list_at(&[X], NOW, "signet", G)),
                SourceStatus::WrongNetwork,
                "signet",
            ),
            (
                Fetched::Body(list_at(&[X], NOW - 7_200, "regtest", G)),
                SourceStatus::Stale,
                "over the maximum age",
            ),
            (
                Fetched::Body(list_at(&[X], NOW + 3_600, "regtest", G)),
                SourceStatus::Stale,
                "ahead of this clock",
            ),
            (
                Fetched::Body(list_at(&[X], NOW, "regtest", &"ab".repeat(32))),
                SourceStatus::WrongGenesis,
                "genesis abababab",
            ),
            (
                Fetched::Malformed("larger than 4194304 bytes".into()),
                SourceStatus::Malformed,
                "larger",
            ),
        ];
        for (bad, status, words) in cases {
            // Two good lists and the bad one: the bad one is named, the good ones decide.
            let m = merge(&inputs(vec![good.clone(), good.clone(), bad]), &cfg()).unwrap();
            let r = &m.sources[2];
            assert_eq!(r.status, status, "{r:?}");
            assert!(
                r.detail.as_deref().unwrap_or("").contains(words),
                "{words:?} in {r:?}"
            );
            assert_eq!((m.voting, relays(&m)), (2, vec!["1.1.1.1:8566".into()]));
        }
    }

    #[test]
    fn listers_that_saw_other_endpoints_split_their_votes() {
        let y_other_port: N = ("2.2.2.2:8566", 4444, 34255, "keyY");
        let y_other_key: N = ("2.2.2.2:8566", 3333, 34255, "keyQ");
        let m = merge(
            &inputs(vec![
                list(&[Y]),
                list(&[y_other_port]),
                list(&[y_other_key]),
            ]),
            &cfg(),
        )
        .unwrap();
        assert!(m.nodes.is_empty(), "{:?}", relays(&m));
        assert_eq!(m.candidates, 1);
        let m = merge(
            &inputs(vec![list(&[Y]), list(&[y_other_port]), list(&[Y])]),
            &cfg(),
        )
        .unwrap();
        assert_eq!(m.nodes.len(), 1);
        assert_eq!(m.nodes[0].node.sv1_port, Some(3333));
        assert_eq!(m.nodes[0].votes, 2);
    }

    #[test]
    fn the_genesis_is_the_majoritys_or_the_configured_one() {
        let other = "ab".repeat(32);
        let on = |g: &str| Fetched::Body(list_at(&[X], NOW, "regtest", g));
        let m = merge(&inputs(vec![on(G), on(G), on(&other)]), &cfg()).unwrap();
        assert_eq!(m.genesis_anchor, G);
        assert_eq!(m.sources[2].status, SourceStatus::WrongGenesis);
        // Configured: the other one, held by one lister of three. No quorum.
        let c = MergeConfig {
            genesis_anchor: Some(other.to_ascii_uppercase()),
            ..cfg()
        };
        assert!(merge(&inputs(vec![on(G), on(G), on(&other)]), &c).is_err());
        // Three listers on three genesis anchors: none has a majority.
        let e = merge(
            &inputs(vec![on(G), on(&other), on(&"cd".repeat(32))]),
            &cfg(),
        )
        .unwrap_err();
        assert_eq!(e.voting, 0);
        assert!(e
            .sources
            .iter()
            .all(|s| s.status == SourceStatus::WrongGenesis));
    }

    #[test]
    fn the_output_is_deterministic_and_has_the_list_schema() {
        let a = vec![
            ("http://b.example/".to_string(), list(&[W, X, Y])),
            ("http://a.example/".to_string(), list(&[Y, X])),
            ("/var/lib/c.json".to_string(), list(&[X, Z, W])),
        ];
        let mut b = a.clone();
        b.reverse();
        let ma = merge(&a, &cfg()).unwrap();
        let mb = merge(&b, &cfg()).unwrap();
        assert_eq!(render_merged(&ma, NOW), render_merged(&mb, NOW));
        let d = DnsConfig::default();
        assert_eq!(
            render_merged_dns(&ma, &d, NOW),
            render_merged_dns(&mb, &d, NOW)
        );
        let v: serde_json::Value = serde_json::from_str(&render_merged(&ma, NOW)).unwrap();
        assert_eq!(v["schema"], LIST_SCHEMA);
        assert_eq!(v["network"], "regtest");
        assert_eq!(v["genesis_anchor"], G);
        assert_eq!(v["listed"], 3);
        assert_eq!(v["candidates"], 4);
        assert_eq!(v["policy"]["list_after"], 3);
        let relays: Vec<&str> = v["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["relay"].as_str().unwrap())
            .collect();
        assert_eq!(relays, ["1.1.1.1:8566", "2.2.2.2:8566", "4.4.4.4:8566"]);
        let x = &v["nodes"][0];
        assert_eq!(x["votes"], 3);
        assert_eq!(x["sv1"], "stratum+tcp://1.1.1.1:3333");
        assert_eq!(x["recent"]["probes"], 9);
        assert_eq!(x["recent"]["pass_rate"], 1.0);
        assert_eq!(x["listed_since"], 1_002);
        let y = &v["nodes"][1];
        assert_eq!(y["sv2"], "2.2.2.2:34255");
        assert_eq!(y["sv2_authority_key"], "keyY");
        let sources: Vec<&str> = v["merge"]["sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["source"].as_str().unwrap())
            .collect();
        assert_eq!(
            sources,
            ["/var/lib/c.json", "http://a.example/", "http://b.example/"]
        );
        assert_eq!(v["merge"]["threshold"], 2);
        assert_eq!(v["merge"]["voting"], 3);
        // A merged list is a valid input to another merge.
        let again = merge(
            &inputs(vec![Fetched::Body(render_merged(&ma, NOW).into_bytes())]),
            &cfg(),
        )
        .unwrap();
        assert_eq!(again.nodes.len(), 3);
        // The DNS fragment says which command wrote it.
        let dns = render_merged_dns(&ma, &d, NOW);
        assert!(dns.contains("generated by ghost-audit merge at"));
        assert_eq!(
            dns_records(&dns).into_iter().collect::<Vec<_>>(),
            [
                "pool 300 IN A 1.1.1.1",
                "pool 300 IN A 2.2.2.2",
                "pool 300 IN A 4.4.4.4"
            ]
        );
    }

    #[test]
    fn sources_are_shown_without_credentials() {
        assert_eq!(
            display_source(
                "https://user:secret@lister.example:8080/api/v1/node-pool/node-list?key=k#x"
            ),
            "https://lister.example:8080/api/v1/node-pool/node-list"
        );
        assert_eq!(display_source("/var/lib/x.json"), "/var/lib/x.json");
    }

    #[tokio::test]
    async fn files_are_read_within_the_size_cap() {
        let dir =
            std::env::temp_dir().join(format!("ghost-audit-merge-fetch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("list.json");
        std::fs::write(&p, b"{}").unwrap();
        let s = p.to_str().unwrap();
        assert_eq!(
            fetch(s, Duration::from_secs(1)).await,
            Fetched::Body(b"{}".to_vec())
        );
        std::fs::write(&p, vec![b' '; MAX_LIST_BYTES + 1]).unwrap();
        assert!(matches!(
            fetch(s, Duration::from_secs(1)).await,
            Fetched::Malformed(_)
        ));
        let missing = dir.join("missing.json");
        assert!(matches!(
            fetch(missing.to_str().unwrap(), Duration::from_secs(1)).await,
            Fetched::Unreachable(_)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_hook_runs_only_when_the_records_change() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("ghost-audit-merge-hook-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("calls");
        let script = dir.join("hook.sh");
        let fail_flag = dir.join("fail");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\n\
                 {{ echo \"arg=$1 first=$GHOST_DNS_FIRST_PUSH name=$GHOST_DNS_NAME\"; \
                 echo \"old=$(echo \"$GHOST_DNS_OLD_RECORDS\" | tr '\\n' ',')\"; \
                 echo \"new=$(echo \"$GHOST_DNS_NEW_RECORDS\" | tr '\\n' ',')\"; }} >> {log}\n\
                 [ -e {fail} ] && exit 7\n\
                 exit 0\n",
                log = log.display(),
                fail = fail_flag.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let hook = Hook {
            program: script.clone(),
            args: vec![],
            timeout: Duration::from_secs(10),
            name: "pool".into(),
        };
        let out = dir.join("pool.zone");
        let frag = |at: &str, ips: &[&str]| {
            let mut s = format!("; ghost-audit/dns/v1: generated at {at}\n");
            for ip in ips {
                s.push_str(&format!("pool 300 IN A {ip}\n"));
            }
            s
        };
        let calls = || {
            std::fs::read_to_string(&log)
                .unwrap_or_default()
                .lines()
                .filter(|l| l.starts_with("arg="))
                .count()
        };

        // No hook: written, nothing run.
        assert_eq!(
            publish_dns(&out, &frag("t0", &["1.1.1.1"]), None)
                .await
                .unwrap(),
            PushOutcome::NoHook
        );
        assert!(!pushed_path(&out).exists());
        // First push.
        assert_eq!(
            publish_dns(&out, &frag("t1", &["1.1.1.1"]), Some(&hook))
                .await
                .unwrap(),
            PushOutcome::Pushed
        );
        assert_eq!(calls(), 1);
        let l = std::fs::read_to_string(&log).unwrap();
        assert!(
            l.contains(&format!("arg={} first=1 name=pool", out.display())),
            "{l}"
        );
        assert!(l.contains("new=pool 300 IN A 1.1.1.1,"), "{l}");
        // Same records, new header: not run.
        assert_eq!(
            publish_dns(&out, &frag("t2", &["1.1.1.1"]), Some(&hook))
                .await
                .unwrap(),
            PushOutcome::Unchanged
        );
        assert_eq!(calls(), 1);
        assert!(std::fs::read_to_string(&out).unwrap().contains("t2"));
        // Changed: run, with the old and new records.
        assert_eq!(
            publish_dns(&out, &frag("t3", &["2.2.2.2", "1.1.1.1"]), Some(&hook))
                .await
                .unwrap(),
            PushOutcome::Pushed
        );
        assert_eq!(calls(), 2);
        let l = std::fs::read_to_string(&log).unwrap();
        assert!(l.contains("first=0"), "{l}");
        assert!(l.contains("old=pool 300 IN A 1.1.1.1,"), "{l}");
        assert!(
            l.contains("new=pool 300 IN A 1.1.1.1,pool 300 IN A 2.2.2.2,"),
            "{l}"
        );
        // A failing hook records nothing, so the next run tries again.
        std::fs::write(&fail_flag, b"").unwrap();
        let f = publish_dns(&out, &frag("t4", &["3.3.3.3"]), Some(&hook))
            .await
            .unwrap();
        assert!(
            matches!(f, PushOutcome::Failed(ref w) if w.contains("exited")),
            "{f:?}"
        );
        assert_eq!(calls(), 3);
        assert!(std::fs::read_to_string(pushed_path(&out))
            .unwrap()
            .contains("t3"));
        std::fs::remove_file(&fail_flag).unwrap();
        assert_eq!(
            publish_dns(&out, &frag("t5", &["3.3.3.3"]), Some(&hook))
                .await
                .unwrap(),
            PushOutcome::Pushed
        );
        assert_eq!(calls(), 4);
        // A hook that cannot start fails the push and records nothing.
        let missing = Hook {
            program: dir.join("no-such-hook"),
            ..hook.clone()
        };
        let f = publish_dns(&out, &frag("t6", &["4.4.4.4"]), Some(&missing))
            .await
            .unwrap();
        assert!(
            matches!(f, PushOutcome::Failed(ref w) if w.contains("did not start")),
            "{f:?}"
        );
        // A hook over its timeout is killed and fails the push.
        let slow = dir.join("slow.sh");
        std::fs::write(&slow, "#!/bin/sh\nsleep 30\n").unwrap();
        std::fs::set_permissions(&slow, std::fs::Permissions::from_mode(0o755)).unwrap();
        let slow = Hook {
            program: slow,
            timeout: Duration::from_millis(300),
            ..hook.clone()
        };
        let f = publish_dns(&out, &frag("t7", &["4.4.4.4"]), Some(&slow))
            .await
            .unwrap();
        assert!(
            matches!(f, PushOutcome::Failed(ref w) if w.contains("killed")),
            "{f:?}"
        );
        assert!(std::fs::read_to_string(pushed_path(&out))
            .unwrap()
            .contains("t5"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
