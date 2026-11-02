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
//| FILE: probe.rs                                                                                                       |
//|======================================================================================================================|

//! The public prober: does a node advertise correctly and serve canonical jobs?
//!
//! Open listing (W2.10) lists any node with a valid advert that passes an outside probe. This is
//! that probe, as a library call ([`probe`](crate::probe::probe)) and a CLI command
//! (`ghost-audit probe`), with a verdict in JSON ([`ProbeReport`](crate::probe::ProbeReport)).
//! It checks, from outside:
//!
//! - **the advert**: the node's relay port answers `Hello` on this share chain's genesis and
//!   protocol version, and discloses its job stamps;
//! - **the jobs**: its stratum port accepts a probe payout address and serves jobs that pay the
//!   canonical coinbase and credit that address ([`crate::check`]), judged against the prober's
//!   own share chain.
//!
//! The verdict is `pass` only when the advert is right and every job seen passed, with at least
//! the number of jobs asked for. A wrong advert or any failed job is `fail`. Anything that could
//! not be measured (a port that does not answer, too few jobs, a job the prober's share chain
//! could not judge yet) is `unmeasured`: not listed, and not condemned either. Only `pass` is
//! `listable`. Like the auditor, the prober submits nothing.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use ghost_np_relay::client::{ClientError, Session};

use crate::check::{JobReport, ShareChainData, Verdict};
use crate::sv1::{Sv1Config, Sv1Error};
use crate::{audit_jobs, AuditTarget, RelayStamps};

/// The schema name every report carries; bump it when a field changes meaning.
pub const PROBE_SCHEMA: &str = "ghost-audit/probe/v1";

/// What to probe.
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    /// The node's SV1 stratum port, `host:port`.
    pub stratum: String,
    /// The node's relay port.
    pub relay: SocketAddr,
    /// The share chain's genesis anchor.
    pub genesis: [u8; 32],
    /// The address the probe logs in with.
    pub address: String,
    /// Its payout script.
    pub payee: Vec<u8>,
    /// User agent for `mining.subscribe`.
    pub user_agent: String,
    /// Jobs to judge.
    pub jobs: usize,
    /// How long to retry a job the prober cannot judge yet.
    pub wait: Duration,
    /// Deadline for each connection and each job.
    pub timeout: Duration,
}

/// The overall verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeVerdict {
    /// The advert is right and every job passed.
    Pass,
    /// The advert is wrong or a job failed.
    Fail,
    /// Something could not be measured. Not a pass.
    Unmeasured,
}

/// The node probed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeNode {
    /// Stratum endpoint.
    pub stratum: String,
    /// Relay endpoint.
    pub relay: String,
}

/// What the relay port said.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AdvertCheck {
    /// The relay port completed a handshake.
    pub reachable: bool,
    /// Its protocol version.
    pub protocol_version: Option<u16>,
    /// Whether its genesis is this share chain's.
    pub genesis_match: Option<bool>,
    /// The port it tells peers to dial, 0 for none.
    pub listen_port: Option<u16>,
    /// Its user agent.
    pub user_agent: Option<String>,
    /// Its best anchor, hex.
    pub tip: Option<String>,
    /// Whether it disclosed job stamps.
    pub stamps_served: Option<bool>,
    /// The node id its stamps carry, hex.
    pub node_id: Option<String>,
    /// What went wrong, if anything.
    pub error: Option<String>,
}

/// What the stratum port did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct StratumCheck {
    /// It accepted the connection and the probe's payout address.
    pub reachable: bool,
    /// Jobs judged.
    pub jobs_seen: usize,
    /// What went wrong, if anything.
    pub error: Option<String>,
}

/// Job verdict counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// PASS.
    pub pass: usize,
    /// FAIL.
    pub fail: usize,
    /// UNCHECKED.
    pub unchecked: usize,
}

/// The machine-readable verdict. Field names and the reason codes are the contract with open
/// listing; see [`PROBE_SCHEMA`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProbeReport {
    /// [`PROBE_SCHEMA`].
    pub schema: &'static str,
    /// The node probed.
    pub node: ProbeNode,
    /// The verdict.
    pub verdict: ProbeVerdict,
    /// Whether open listing may list the node: `verdict == pass`.
    pub listable: bool,
    /// Every reason the verdict is not `pass`, as codes (`relay_genesis`, `job_tag_not_binding`,
    /// ...). Empty on a pass.
    pub reasons: Vec<String>,
    /// Unix seconds when the probe finished.
    pub checked_at: u64,
    /// The relay port.
    pub advert: AdvertCheck,
    /// The stratum port.
    pub stratum: StratumCheck,
    /// One report per job judged.
    pub jobs: Vec<JobReport>,
    /// Counts.
    pub summary: Summary,
}

async fn check_advert(cfg: &ProbeConfig) -> (AdvertCheck, Vec<(ProbeVerdict, String)>) {
    let mut a = AdvertCheck::default();
    let mut issues = Vec::new();
    let agent = format!("ghost-audit-probe/{}", env!("CARGO_PKG_VERSION"));
    match Session::open(cfg.relay, cfg.genesis, &agent, cfg.timeout).await {
        Ok(mut s) => {
            a.reachable = true;
            a.protocol_version = Some(s.hello.version);
            a.genesis_match = Some(true);
            a.listen_port = Some(s.hello.listen_port);
            a.user_agent = Some(s.hello.user_agent.clone());
            a.tip = Some(hex::encode(s.hello.tip));
            match s.stamps(cfg.timeout).await {
                Ok(st) => {
                    a.stamps_served = Some(true);
                    a.node_id = Some(hex::encode(st.node_id));
                }
                Err(ClientError::NoStamps) => {
                    a.stamps_served = Some(false);
                    issues.push((ProbeVerdict::Fail, "relay_no_job_stamps".into()));
                }
                Err(e) => {
                    a.error = Some(e.to_string());
                    issues.push((ProbeVerdict::Unmeasured, "relay_stamps_unanswered".into()));
                }
            }
        }
        Err(e) => {
            a.error = Some(e.to_string());
            match e {
                ClientError::Version { theirs, .. } => {
                    a.reachable = true;
                    a.protocol_version = Some(theirs);
                    issues.push((ProbeVerdict::Fail, "relay_protocol_version".into()));
                }
                ClientError::Genesis { .. } => {
                    a.reachable = true;
                    a.genesis_match = Some(false);
                    issues.push((ProbeVerdict::Fail, "relay_genesis".into()));
                }
                ClientError::NoHello | ClientError::Wire(_) => {
                    a.reachable = true;
                    issues.push((ProbeVerdict::Fail, "relay_not_a_relay".into()));
                }
                _ => issues.push((ProbeVerdict::Unmeasured, "relay_unreachable".into())),
            }
        }
    }
    (a, issues)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Probe one node against the prober's own share chain `data`.
pub async fn probe(cfg: &ProbeConfig, data: &dyn ShareChainData) -> ProbeReport {
    let (advert, mut issues) = check_advert(cfg).await;
    let mut stratum = StratumCheck::default();
    let mut jobs = Vec::new();
    // A node on another share chain, or not a relay, is not worth judging jobs for.
    let advert_failed = issues.iter().any(|(v, _)| *v == ProbeVerdict::Fail);
    if !advert_failed {
        let target = AuditTarget {
            stratum: Sv1Config {
                addr: cfg.stratum.clone(),
                username: cfg.address.clone(),
                password: "x".into(),
                user_agent: cfg.user_agent.clone(),
                timeout: cfg.timeout,
            },
            payee: cfg.payee.clone(),
            jobs: cfg.jobs.max(1),
            wait: cfg.wait,
            job_timeout: cfg.timeout,
        };
        let stamps = RelayStamps {
            addr: cfg.relay,
            genesis: cfg.genesis,
            timeout: cfg.timeout,
        };
        let mut seen = Vec::new();
        let r = audit_jobs(&target, &stamps, data, |j| seen.push(j.clone())).await;
        stratum.jobs_seen = seen.len();
        jobs = seen;
        match r {
            Ok(_) => stratum.reachable = true,
            Err(e) => {
                stratum.reachable =
                    !matches!(e, Sv1Error::Io(_) | Sv1Error::Timeout(_)) || !jobs.is_empty();
                let code = match &e {
                    Sv1Error::Refused(_) => {
                        issues.push((ProbeVerdict::Fail, "stratum_refused_payee".into()));
                        None
                    }
                    Sv1Error::Protocol(_) => {
                        issues.push((ProbeVerdict::Fail, "stratum_protocol".into()));
                        None
                    }
                    _ if jobs.is_empty() => Some("stratum_unreachable"),
                    _ => Some("too_few_jobs"),
                };
                if let Some(c) = code {
                    issues.push((ProbeVerdict::Unmeasured, c.into()));
                }
                stratum.error = Some(e.to_string());
            }
        }
    }
    let mut summary = Summary::default();
    for j in &jobs {
        match j.verdict {
            Verdict::Pass => summary.pass += 1,
            Verdict::Fail => {
                summary.fail += 1;
                let code = j
                    .reason
                    .map(|r| {
                        serde_json::to_value(r)
                            .ok()
                            .and_then(|v| v.as_str().map(str::to_string))
                            .unwrap_or_default()
                    })
                    .unwrap_or_default();
                issues.push((ProbeVerdict::Fail, format!("job_{code}")));
            }
            Verdict::Unchecked => {
                summary.unchecked += 1;
                issues.push((ProbeVerdict::Unmeasured, "job_unchecked".into()));
            }
        }
    }
    let verdict = if issues.iter().any(|(v, _)| *v == ProbeVerdict::Fail) {
        ProbeVerdict::Fail
    } else if !issues.is_empty() {
        ProbeVerdict::Unmeasured
    } else {
        ProbeVerdict::Pass
    };
    let mut reasons: Vec<String> = Vec::new();
    for (_, r) in issues {
        if !reasons.contains(&r) {
            reasons.push(r);
        }
    }
    ProbeReport {
        schema: PROBE_SCHEMA,
        node: ProbeNode {
            stratum: cfg.stratum.clone(),
            relay: cfg.relay.to_string(),
        },
        verdict,
        listable: verdict == ProbeVerdict::Pass,
        reasons,
        checked_at: now_secs(),
        advert,
        stratum,
        jobs,
        summary,
    }
}
