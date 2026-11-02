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
//| FILE: lister.rs                                                                                                      |
//|======================================================================================================================|

//! One round of open listing (W2.10): discover, probe, record.
//!
//! [`crate::lister::run_round`] crawls relay gossip for candidates ([`crate::discover::crawl`]),
//! probes every candidate ([`crate::lister::NodeProber`]) a bounded number at a time, and records
//! each outcome in the [`crate::listing::ListState`], which applies the listing policy.
//! `ghost-audit list` runs rounds on a schedule and writes the generated files after each.
//!
//! The live prober ([`crate::lister::LiveProber`]) reads the node's mining advert from its relay
//! port (`GetAdvert`: the stratum ports, on the IP the relay was reached at) and then runs the
//! public probe ([`crate::probe::probe`]) on the advertised SV1 port. A relay that advertises no
//! SV1 port cannot be probed, since the probe speaks SV1, and is `unmeasured`: never listed.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use ghost_np_relay::client::{ClientError, Session};

use crate::check::ShareChainData;
use crate::discover::{crawl, Candidates, Limits, Reply};
use crate::listing::{AdvertInfo, ListState, Outcome, Policy, ProbeRecord, Transition};
use crate::probe::{probe, ProbeConfig, ProbeVerdict};

/// One node's probe, as listing records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeProbe {
    /// The outcome.
    pub outcome: Outcome,
    /// Reason codes: the probe's ([`crate::probe::ProbeReport::reasons`]) or the advert's.
    pub reasons: Vec<String>,
    /// What the relay advertised, if it answered.
    pub advert: Option<AdvertInfo>,
    /// Unix seconds when it finished.
    pub at: u64,
}

/// Probes one candidate.
#[async_trait]
pub trait NodeProber: Send + Sync {
    /// Probe the node whose relay port is `relay`.
    async fn probe_node(&self, relay: SocketAddr) -> NodeProbe;
}

/// Unix seconds now.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The production prober: advert, then [`probe`].
pub struct LiveProber {
    /// The share chain's genesis.
    pub genesis: [u8; 32],
    /// The address the probe logs in with.
    pub address: String,
    /// Its payout script.
    pub payee: Vec<u8>,
    /// User agent for `mining.subscribe`.
    pub user_agent: String,
    /// Jobs judged per probe.
    pub jobs: usize,
    /// How long to retry a job the prober cannot judge yet.
    pub wait: Duration,
    /// Deadline per connection and per job.
    pub timeout: Duration,
    /// The prober's own share chain.
    pub data: Arc<dyn ShareChainData>,
}

fn verdict(outcome: Outcome, reason: &str, advert: Option<AdvertInfo>) -> NodeProbe {
    NodeProbe {
        outcome,
        reasons: vec![reason.to_string()],
        advert,
        at: now_secs(),
    }
}

#[async_trait]
impl NodeProber for LiveProber {
    async fn probe_node(&self, relay: SocketAddr) -> NodeProbe {
        let agent = format!("ghost-audit-list/{}", env!("CARGO_PKG_VERSION"));
        let mut s = match Session::open(relay, self.genesis, &agent, self.timeout).await {
            Ok(s) => s,
            Err(ClientError::Genesis { .. }) => {
                return verdict(Outcome::Fail, "relay_genesis", None)
            }
            Err(ClientError::Version { .. }) => {
                return verdict(Outcome::Fail, "relay_protocol_version", None)
            }
            Err(ClientError::NoHello) | Err(ClientError::Wire(_)) => {
                return verdict(Outcome::Fail, "relay_not_a_relay", None)
            }
            Err(_) => return verdict(Outcome::Unmeasured, "relay_unreachable", None),
        };
        let mut info = AdvertInfo {
            user_agent: Some(s.hello.user_agent.clone()),
            protocol_version: Some(s.hello.version),
            ..AdvertInfo::default()
        };
        match s.advert(self.timeout).await {
            Ok(a) => {
                info.sv1_port = a.sv1_port;
                info.sv2_port = a.sv2_port;
                info.sv2_authority_key = a.sv2_authority_key;
            }
            Err(ClientError::NoAdvert) => {
                return verdict(Outcome::Unmeasured, "advert_none", Some(info))
            }
            Err(_) => return verdict(Outcome::Unmeasured, "advert_unanswered", Some(info)),
        }
        drop(s);
        if info.sv1_port == 0 {
            return verdict(Outcome::Unmeasured, "advert_no_sv1", Some(info));
        }
        let cfg = ProbeConfig {
            stratum: SocketAddr::new(relay.ip(), info.sv1_port).to_string(),
            relay,
            genesis: self.genesis,
            address: self.address.clone(),
            payee: self.payee.clone(),
            user_agent: self.user_agent.clone(),
            jobs: self.jobs,
            wait: self.wait,
            timeout: self.timeout,
        };
        let r = probe(&cfg, self.data.as_ref()).await;
        info.node_id = r.advert.node_id.clone();
        NodeProbe {
            outcome: match r.verdict {
                ProbeVerdict::Pass => Outcome::Pass,
                ProbeVerdict::Fail => Outcome::Fail,
                ProbeVerdict::Unmeasured => Outcome::Unmeasured,
            },
            reasons: r.reasons,
            advert: Some(info),
            at: r.checked_at,
        }
    }
}

/// A round's settings.
#[derive(Debug, Clone)]
pub struct RoundConfig {
    /// Relays the crawl starts from.
    pub seeds: Vec<SocketAddr>,
    /// Discovery limits.
    pub limits: Limits,
    /// The listing policy.
    pub policy: Policy,
    /// Nodes probed at once.
    pub probe_concurrency: usize,
    /// Unlisted candidates discovery has not seen for this long are forgotten.
    pub forget_after_secs: u64,
}

/// What a round did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoundReport {
    /// Relays that answered the crawl.
    pub answered: usize,
    /// Candidates after the round.
    pub candidates: usize,
    /// Nodes probed.
    pub probed: usize,
    /// Probe outcomes: pass, fail, unmeasured.
    pub outcomes: (usize, usize, usize),
    /// Nodes listed this round.
    pub listed: Vec<SocketAddr>,
    /// Nodes delisted this round.
    pub delisted: Vec<SocketAddr>,
    /// Candidates forgotten.
    pub forgotten: usize,
}

/// Run one round on `state`: crawl from `cfg.seeds` with `ask` (production:
/// [`crate::discover::ask`]), forget stale candidates, then probe every candidate with `prober`.
pub async fn run_round<A, Fut>(
    state: &mut ListState,
    cfg: &RoundConfig,
    ask: A,
    prober: Arc<dyn NodeProber>,
    now: u64,
) -> RoundReport
where
    A: Fn(SocketAddr) -> Fut,
    Fut: std::future::Future<Output = Option<Reply>> + Send + 'static,
{
    let mut report = RoundReport::default();
    // Existing candidates count against the caps first, so the crawl adds only within them.
    let known: Vec<SocketAddr> = state.candidates.keys().copied().collect();
    let mut found = Candidates::default();
    for a in &known {
        let _ = found.add(*a, &cfg.limits);
    }
    report.answered = crawl(&cfg.seeds, &known, &mut found, &cfg.limits, ask).await;
    for a in found.iter() {
        state.observe(*a, now, cfg.limits.max_candidates);
    }
    report.forgotten = state.forget_older_than(now, cfg.forget_after_secs);

    let todo: Vec<SocketAddr> = state.candidates.keys().copied().collect();
    let mut queue = todo.into_iter();
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        while tasks.len() < cfg.probe_concurrency.max(1) {
            let Some(a) = queue.next() else { break };
            let p = prober.clone();
            tasks.spawn(async move { (a, p.probe_node(a).await) });
        }
        let Some(done) = tasks.join_next().await else {
            break;
        };
        let Ok((relay, p)) = done else { continue };
        report.probed += 1;
        match p.outcome {
            Outcome::Pass => report.outcomes.0 += 1,
            Outcome::Fail => report.outcomes.1 += 1,
            Outcome::Unmeasured => report.outcomes.2 += 1,
        }
        let rec = ProbeRecord {
            at: p.at,
            outcome: p.outcome,
            reasons: p.reasons,
        };
        match state.record(relay, p.advert, rec, &cfg.policy) {
            Transition::Listed => report.listed.push(relay),
            Transition::Delisted => report.delisted.push(relay),
            Transition::None => {}
        }
    }
    report.listed.sort();
    report.delisted.sort();
    report.candidates = state.candidates.len();
    report
}

/// Write `content` to `path` atomically (a temporary file beside it, then a rename), so a reader
/// never sees half a file.
pub fn write_atomic(path: &std::path::Path, content: &str) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    std::fs::write(&tmp, content)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// Scripted outcomes per node; a node with no script is unreachable.
    struct Scripted(Mutex<BTreeMap<SocketAddr, Vec<Outcome>>>);

    #[async_trait]
    impl NodeProber for Scripted {
        async fn probe_node(&self, relay: SocketAddr) -> NodeProbe {
            let o = self
                .0
                .lock()
                .unwrap()
                .get_mut(&relay)
                .and_then(|v| (!v.is_empty()).then(|| v.remove(0)))
                .unwrap_or(Outcome::Unmeasured);
            NodeProbe {
                outcome: o,
                reasons: if o == Outcome::Pass {
                    vec![]
                } else {
                    vec!["x".into()]
                },
                advert: Some(AdvertInfo {
                    sv1_port: 3333,
                    ..AdvertInfo::default()
                }),
                at: 0,
            }
        }
    }

    #[tokio::test]
    async fn rounds_list_honest_nodes_and_never_a_failing_one() {
        let honest = sa("1.1.1.1:8566");
        let cheat = sa("2.2.2.2:8566");
        let flaky = sa("3.3.3.3:8566");
        let gossip: Arc<BTreeMap<SocketAddr, Vec<String>>> = Arc::new(
            [
                (honest, vec![cheat.to_string(), flaky.to_string()]),
                (cheat, vec![]),
                (flaky, vec![]),
            ]
            .into_iter()
            .collect(),
        );
        let ask = move |a: SocketAddr| {
            let g = gossip.clone();
            async move {
                g.get(&a).map(|v| Reply {
                    own: Some(a),
                    gossiped: v.clone(),
                })
            }
        };
        use Outcome::{Fail as F, Pass as P, Unmeasured as U};
        let prober = Arc::new(Scripted(Mutex::new(
            [
                (honest, vec![P; 10]),
                (cheat, vec![P, P, F, P, P, P, P, F, P, P]),
                (flaky, vec![P, U, U, U, P, U, P, U, U, U]),
            ]
            .into_iter()
            .collect(),
        )));
        let cfg = RoundConfig {
            seeds: vec![honest],
            limits: Limits::default(),
            policy: Policy::default(),
            probe_concurrency: 2,
            forget_after_secs: 3_600,
        };
        let mut state = ListState::default();
        let mut listed_per_round = Vec::new();
        for round in 0..10u64 {
            let r = run_round(&mut state, &cfg, ask.clone(), prober.clone(), round).await;
            assert_eq!(r.candidates, 3);
            assert_eq!(r.probed, 3);
            listed_per_round.push(state.listed().map(|c| c.relay).collect::<Vec<_>>());
        }
        // The honest node is listed from its third pass on. The cheat fails in rounds 3 and 8,
        // so a fail is always inside its 6-probe window when it has 3 passes: never listed. The
        // flaky node never has 3 passes in a window ending in a pass: unmeasured is not a pass.
        assert_eq!(listed_per_round[1], Vec::<SocketAddr>::new());
        for r in &listed_per_round[2..] {
            assert_eq!(r, &vec![honest], "{listed_per_round:?}");
        }
    }

    #[test]
    fn writes_are_atomic() {
        let dir = std::env::temp_dir().join(format!("ghost-audit-list-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("node-list.json");
        write_atomic(&p, "a").unwrap();
        write_atomic(&p, "b").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "b");
        assert!(!dir.join("node-list.json.tmp").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
