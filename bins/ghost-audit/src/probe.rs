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
//! that probe, as a library call ([`crate::probe::probe`]) and a CLI command
//! (`ghost-audit probe`), with a verdict in JSON ([`crate::probe::ProbeReport`]).
//! It checks, from outside:
//!
//! - **the advert**: the node's relay port answers `Hello` on this share chain's genesis and
//!   protocol version, and discloses its job stamps (its mining advert, the ports it serves, is
//!   read and reported);
//! - **the SV1 jobs**, when the node serves SV1: its stratum port accepts a probe payout address
//!   and serves jobs that pay the canonical coinbase and credit that address ([`crate::check`]),
//!   judged against the prober's own share chain;
//! - **the SV2 jobs**, when the node serves SV2: its SV2 port proves the advertised authority key
//!   in the Noise handshake, and the jobs on an extended and a standard channel pass the same
//!   checks ([`crate::audit_sv2_jobs`]).
//!
//! A node may treat SV1 and SV2 miners differently, so every protocol it serves is probed and
//! each must pass on its own. The verdict is `pass` only when the advert is right and, on every
//! protocol probed, every job seen passed, with at least the number of jobs asked for. A wrong
//! advert, a wrong authority key or any failed job on either protocol is `fail`. Anything that
//! could not be measured (a port that does not answer, too few jobs, a job the prober's share
//! chain could not judge yet, no stratum port at all) is `unmeasured`: not listed, and not
//! condemned either. Only `pass` is `listable`. Like the auditor, the prober submits nothing.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use ghost_np_relay::client::{ClientError, Session};
use ghost_np_relay::wire::NodeAdvert;

use crate::check::{JobReport, ShareChainData, Verdict};
use crate::sv1::{Sv1Config, Sv1Error};
use crate::sv2::{Sv2Config, Sv2Device, Sv2Error};
use crate::{audit_jobs, audit_sv2_jobs, AuditTarget, RelayStamps, Sv2Target};

/// The schema name every report carries; bump it when a field changes meaning.
pub const PROBE_SCHEMA: &str = "ghost-audit/probe/v2";

/// A node's SV2 port and the key its Noise certificate must be signed by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sv2Endpoint {
    /// `host:port`.
    pub addr: String,
    /// The authority public key, base58check, as the node advertises it.
    pub authority_key: String,
}

/// What to probe.
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    /// The node's SV1 stratum port, `host:port`; `None` if it serves no SV1.
    pub stratum: Option<String>,
    /// The node's SV2 port and authority key; `None` if it serves no SV2.
    pub sv2: Option<Sv2Endpoint>,
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
    /// The device fields of the SV2 `SetupConnection`.
    pub sv2_device: Sv2Device,
    /// The hash rate the SV2 channels declare, H/s.
    pub sv2_hash_rate: f32,
    /// Jobs to judge on each protocol (on SV2, on each channel).
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
    /// SV1 stratum endpoint, if probed.
    pub stratum: Option<String>,
    /// SV2 endpoint, if probed.
    pub sv2: Option<String>,
    /// The SV2 authority key the handshake was checked against, if probed.
    pub sv2_authority_key: Option<String>,
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
    /// The SV1 port its mining advert names, 0 for none; `None` if it sent no advert.
    pub sv1_port: Option<u16>,
    /// The SV2 port its mining advert names, 0 for none.
    pub sv2_port: Option<u16>,
    /// The SV2 authority key its mining advert names, empty for none.
    pub sv2_authority_key: Option<String>,
    /// What went wrong, if anything.
    pub error: Option<String>,
}

/// What a stratum port (SV1 or SV2) did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct StratumCheck {
    /// It accepted the connection and the probe's payout address.
    pub reachable: bool,
    /// Jobs judged.
    pub jobs_seen: usize,
    /// What went wrong, if anything.
    pub error: Option<String>,
}

/// Job verdict counts, over both protocols.
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
    /// `sv2_authority_key`, `sv2_job_standard_job_not_canonical`, ...). SV2 codes carry an
    /// `sv2_` prefix. Empty on a pass.
    pub reasons: Vec<String>,
    /// Unix seconds when the probe finished.
    pub checked_at: u64,
    /// The relay port.
    pub advert: AdvertCheck,
    /// The SV1 stratum port, if probed.
    pub stratum: Option<StratumCheck>,
    /// The SV2 port, if probed.
    pub sv2: Option<StratumCheck>,
    /// One report per SV1 job judged.
    pub jobs: Vec<JobReport>,
    /// One report per SV2 job judged; ids `ext-<n>` (extended channel) and `std-<n>`
    /// (standard channel).
    pub jobs_sv2: Vec<JobReport>,
    /// Counts.
    pub summary: Summary,
}

type Issues = Vec<(ProbeVerdict, String)>;

/// Read a node's mining advert from its relay port.
pub async fn read_advert(
    relay: SocketAddr,
    genesis: [u8; 32],
    timeout: Duration,
) -> Result<NodeAdvert, ClientError> {
    let agent = format!("ghost-audit-probe/{}", env!("CARGO_PKG_VERSION"));
    let mut s = Session::open(relay, genesis, &agent, timeout).await?;
    s.advert(timeout).await
}

async fn check_advert(cfg: &ProbeConfig) -> (AdvertCheck, Issues) {
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
            if let Ok(ad) = s.advert(cfg.timeout).await {
                a.sv1_port = Some(ad.sv1_port);
                a.sv2_port = Some(ad.sv2_port);
                a.sv2_authority_key = Some(ad.sv2_authority_key);
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

fn stamps_of(cfg: &ProbeConfig) -> RelayStamps {
    RelayStamps {
        addr: cfg.relay,
        genesis: cfg.genesis,
        timeout: cfg.timeout,
    }
}

async fn probe_sv1(
    cfg: &ProbeConfig,
    addr: &str,
    data: &dyn ShareChainData,
) -> (StratumCheck, Vec<JobReport>, Issues) {
    let mut c = StratumCheck::default();
    let mut issues = Vec::new();
    let target = AuditTarget {
        stratum: Sv1Config {
            addr: addr.to_string(),
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
    let mut jobs = Vec::new();
    let r = audit_jobs(&target, &stamps_of(cfg), data, |j| jobs.push(j.clone())).await;
    c.jobs_seen = jobs.len();
    match r {
        Ok(_) => c.reachable = true,
        Err(e) => {
            c.reachable = !matches!(e, Sv1Error::Io(_) | Sv1Error::Timeout(_)) || !jobs.is_empty();
            match &e {
                Sv1Error::Refused(_) => {
                    issues.push((ProbeVerdict::Fail, "stratum_refused_payee".into()))
                }
                Sv1Error::Protocol(_) => {
                    issues.push((ProbeVerdict::Fail, "stratum_protocol".into()))
                }
                _ if jobs.is_empty() => {
                    issues.push((ProbeVerdict::Unmeasured, "stratum_unreachable".into()))
                }
                _ => issues.push((ProbeVerdict::Unmeasured, "too_few_jobs".into())),
            }
            c.error = Some(e.to_string());
        }
    }
    (c, jobs, issues)
}

async fn probe_sv2(
    cfg: &ProbeConfig,
    ep: &Sv2Endpoint,
    data: &dyn ShareChainData,
) -> (StratumCheck, Vec<JobReport>, Issues) {
    let mut c = StratumCheck::default();
    let mut issues = Vec::new();
    let target = Sv2Target {
        node: Sv2Config {
            addr: ep.addr.clone(),
            authority_key: ep.authority_key.clone(),
            username: cfg.address.clone(),
            device: cfg.sv2_device.clone(),
            nominal_hash_rate: cfg.sv2_hash_rate,
            timeout: cfg.timeout,
        },
        payee: cfg.payee.clone(),
        jobs: cfg.jobs.max(1),
        wait: cfg.wait,
        job_timeout: cfg.timeout,
    };
    let mut jobs = Vec::new();
    let r = audit_sv2_jobs(&target, &stamps_of(cfg), data, |j| jobs.push(j.clone())).await;
    c.jobs_seen = jobs.len();
    match r {
        Ok(_) => c.reachable = true,
        Err(e) => {
            c.reachable = !matches!(
                e,
                Sv2Error::Io(_) | Sv2Error::Timeout(_) | Sv2Error::BadKey(_)
            ) || !jobs.is_empty();
            let (v, code) = match &e {
                Sv2Error::BadKey(_) => (ProbeVerdict::Fail, "sv2_bad_authority_key"),
                Sv2Error::WrongKey(_) => (ProbeVerdict::Fail, "sv2_authority_key"),
                Sv2Error::Refused(_) => (ProbeVerdict::Fail, "sv2_refused"),
                Sv2Error::Protocol(_) => (ProbeVerdict::Fail, "sv2_protocol"),
                _ if jobs.is_empty() => (ProbeVerdict::Unmeasured, "sv2_unreachable"),
                _ => (ProbeVerdict::Unmeasured, "sv2_too_few_jobs"),
            };
            issues.push((v, code.into()));
            c.error = Some(e.to_string());
        }
    }
    (c, jobs, issues)
}

fn job_issues(jobs: &[JobReport], prefix: &str, summary: &mut Summary, issues: &mut Issues) {
    for j in jobs {
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
                issues.push((ProbeVerdict::Fail, format!("{prefix}job_{code}")));
            }
            Verdict::Unchecked => {
                summary.unchecked += 1;
                issues.push((ProbeVerdict::Unmeasured, format!("{prefix}job_unchecked")));
            }
        }
    }
}

/// Probe one node against the prober's own share chain `data`: its advert, then every stratum
/// protocol in `cfg` (both at once).
pub async fn probe(cfg: &ProbeConfig, data: &dyn ShareChainData) -> ProbeReport {
    let (advert, mut issues) = check_advert(cfg).await;
    let (mut stratum, mut sv2) = (None, None);
    let (mut jobs, mut jobs_sv2) = (Vec::new(), Vec::new());
    // A node on another share chain, or not a relay, is not worth judging jobs for.
    let advert_failed = issues.iter().any(|(v, _)| *v == ProbeVerdict::Fail);
    if !advert_failed && cfg.stratum.is_none() && cfg.sv2.is_none() {
        issues.push((ProbeVerdict::Unmeasured, "no_stratum".into()));
    } else if !advert_failed {
        let v1 = async {
            match &cfg.stratum {
                Some(a) => Some(probe_sv1(cfg, a, data).await),
                None => None,
            }
        };
        let v2 = async {
            match &cfg.sv2 {
                Some(ep) => Some(probe_sv2(cfg, ep, data).await),
                None => None,
            }
        };
        let (r1, r2) = tokio::join!(v1, v2);
        if let Some((c, j, i)) = r1 {
            stratum = Some(c);
            jobs = j;
            issues.extend(i);
        }
        if let Some((c, j, i)) = r2 {
            sv2 = Some(c);
            jobs_sv2 = j;
            issues.extend(i);
        }
    }
    let mut summary = Summary::default();
    job_issues(&jobs, "", &mut summary, &mut issues);
    job_issues(&jobs_sv2, "sv2_", &mut summary, &mut issues);
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
            sv2: cfg.sv2.as_ref().map(|e| e.addr.clone()),
            sv2_authority_key: cfg.sv2.as_ref().map(|e| e.authority_key.clone()),
            relay: cfg.relay.to_string(),
        },
        verdict,
        listable: verdict == ProbeVerdict::Pass,
        reasons,
        checked_at: now_secs(),
        advert,
        stratum,
        sv2,
        jobs,
        jobs_sv2,
        summary,
    }
}
