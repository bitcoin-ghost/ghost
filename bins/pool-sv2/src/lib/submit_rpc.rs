//! Sending a found block to other Bitcoin nodes over JSON-RPC `submitblock`.
//!
//! The local node gets every block first, through the template provider. When `[solo]
//! submit_rpc` lists more nodes (the operator's second node), the whole block is assembled from
//! the template provider's transactions and sent to each of them at once, in parallel, after the
//! local submission and never in its way. Each answer is logged and kept with the block.
//!
//! Credentials come from `[solo] submit_rpc_auth_file` (or the environment variable
//! `GHOST_SOLO_SUBMIT_RPC_AUTH_FILE`), never from the config itself, and are never logged. The
//! file holds one entry per line, `#` comments and blank lines ignored:
//!
//! ```text
//! http://10.0.0.2:8332 user:password    # for that endpoint only
//! user:password                          # for every endpoint without its own line
//! ```
//!
//! A Bitcoin Core `.cookie` file (`__cookie__:<hex>`) is a valid file: one line for every node.

use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use serde::Serialize;
use tracing::{info, warn};

/// Longest a node may take to answer `submitblock`.
pub const SUBMIT_TIMEOUT: Duration = Duration::from_secs(30);

/// How often every node's reachability is checked (`getblockchaininfo`).
pub const HEALTH_INTERVAL: Duration = Duration::from_secs(60);

/// Longest a node may take to answer the reachability check.
pub const HEALTH_TIMEOUT: Duration = Duration::from_secs(10);

/// Longest error message kept from a check.
const HEALTH_ERROR_MAX: usize = 200;

/// What the last reachability check of one node found. Shown in `/api/v1/pool/status`
/// `submit_nodes[]`; it never carries credentials (the node is its `scheme://host:port` label,
/// and errors are the transport's or the node's own message, with no URL).
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct NodeHealth {
    /// The node, `scheme://host:port`.
    pub node: String,
    /// It answered the last check; `null` until it has been checked once.
    pub reachable: Option<bool>,
    /// When it was last checked, unix seconds.
    pub last_checked_at: Option<u64>,
    /// When it last answered, unix seconds.
    pub last_ok_at: Option<u64>,
    /// Its block height at that answer (`blocks`).
    pub height: Option<u64>,
    /// Why the last check failed; `null` when it answered.
    pub error: Option<String>,
}

/// The environment variable that names the credentials file when the config does not.
pub const AUTH_FILE_ENV: &str = "GHOST_SOLO_SUBMIT_RPC_AUTH_FILE";

/// One node to send blocks to.
#[derive(Clone)]
pub struct Endpoint {
    url: String,
    label: String,
    auth: Option<(String, String)>,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the credentials.
        f.debug_struct("Endpoint")
            .field("node", &self.label)
            .field("auth", &self.auth.is_some())
            .finish()
    }
}

/// The other nodes found blocks go to.
pub struct SubmitTargets {
    endpoints: Vec<Endpoint>,
    client: reqwest::Client,
    health: Mutex<Vec<NodeHealth>>,
}

/// `scheme://host:port` of a URL: what is logged, with no credentials or path.
pub fn label_of(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
    let rest = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = rest.rsplit_once('@').map_or(rest, |(_, h)| h);
    format!("{scheme}://{host}")
}

/// A `user:password` pair.
pub type Credentials = (String, String);

/// A credentials file: per-endpoint credentials (keyed by `scheme://host:port`), and the default.
pub type AuthEntries = (Vec<(String, Credentials)>, Option<Credentials>);

/// Parse a credentials file: `(per-endpoint, default)`.
pub fn parse_auth(text: &str) -> AuthEntries {
    let mut per = vec![];
    let mut default = None;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut words = line.split_whitespace();
        let (first, second) = (words.next(), words.next());
        let pair = |s: &str| {
            s.split_once(':')
                .map(|(u, p)| (u.to_string(), p.to_string()))
        };
        match (first, second) {
            (Some(url), Some(cred)) => {
                if let Some(c) = pair(cred) {
                    per.push((label_of(url), c));
                }
            }
            (Some(cred), None) => {
                if let Some(c) = pair(cred) {
                    default = Some(c);
                }
            }
            _ => {}
        }
    }
    (per, default)
}

impl SubmitTargets {
    /// No other nodes.
    pub fn none() -> SubmitTargets {
        SubmitTargets {
            endpoints: vec![],
            client: reqwest::Client::new(),
            health: Mutex::new(vec![]),
        }
    }

    /// The nodes `urls`, with credentials from `auth_file` (or [`AUTH_FILE_ENV`]). A URL that
    /// carries `user:password@` uses those. A credentials file that cannot be read is an error:
    /// a node that refuses every block for want of a password is worse than one not configured.
    pub fn new(urls: &[String], auth_file: Option<&Path>) -> Result<SubmitTargets, String> {
        let env_file = std::env::var_os(AUTH_FILE_ENV).map(std::path::PathBuf::from);
        let file = auth_file.map(Path::to_path_buf).or(env_file);
        let (per, default) = match (&file, urls.is_empty()) {
            (Some(f), false) => {
                let text = std::fs::read_to_string(f).map_err(|e| {
                    format!(
                        "[solo] submit_rpc_auth_file {}: cannot be read: {e}",
                        f.display()
                    )
                })?;
                parse_auth(&text)
            }
            _ => (vec![], None),
        };
        let mut endpoints = vec![];
        for url in urls {
            let url = url.trim();
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(format!(
                    "[solo] submit_rpc entry {:?} is not an http:// or https:// URL",
                    label_of(url)
                ));
            }
            let label = label_of(url);
            let (scheme, rest) = url.split_once("://").expect("checked above");
            let (inline, bare) = match rest.split_once('@') {
                Some((cred, host)) => (
                    cred.split_once(':')
                        .map(|(u, p)| (u.to_string(), p.to_string())),
                    format!("{scheme}://{host}"),
                ),
                None => (None, url.to_string()),
            };
            let auth = inline
                .or_else(|| {
                    per.iter()
                        .find(|(l, _)| *l == label)
                        .map(|(_, c)| c.clone())
                })
                .or_else(|| default.clone());
            endpoints.push(Endpoint {
                url: bare,
                label,
                auth,
            });
        }
        let client = reqwest::Client::builder()
            .timeout(SUBMIT_TIMEOUT)
            .build()
            .map_err(|e| format!("submit_rpc HTTP client: {e}"))?;
        let health = endpoints
            .iter()
            .map(|e| NodeHealth {
                node: e.label.clone(),
                ..Default::default()
            })
            .collect();
        Ok(SubmitTargets {
            endpoints,
            client,
            health: Mutex::new(health),
        })
    }

    /// What the last reachability check of every node found, in the configured order.
    pub fn health(&self) -> Vec<NodeHealth> {
        self.health
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Check every node at once with `getblockchaininfo` (at most [`HEALTH_TIMEOUT`] each) and
    /// record what each answered at `now`.
    pub async fn check_health(&self, now: u64) {
        let body = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "ghost-solo-health",
            "method": "getblockchaininfo",
            "params": [],
        });
        let tasks: Vec<_> = self
            .endpoints
            .iter()
            .map(|e| {
                let e = e.clone();
                let client = self.client.clone();
                let body = body.clone();
                tokio::spawn(async move {
                    let mut req = client.post(&e.url).json(&body).timeout(HEALTH_TIMEOUT);
                    if let Some((u, p)) = &e.auth {
                        req = req.basic_auth(u, Some(p));
                    }
                    match req.send().await {
                        Ok(resp) => {
                            let status = resp.status();
                            match resp.json::<serde_json::Value>().await {
                                Ok(v) => health_verdict(&v),
                                Err(_) => Err(format!("HTTP {status}, not a JSON-RPC answer")),
                            }
                        }
                        Err(err) => Err(err.without_url().to_string()),
                    }
                })
            })
            .collect();
        let mut results = Vec::with_capacity(tasks.len());
        for t in tasks {
            results.push(match t.await {
                Ok(r) => r,
                Err(e) => Err(format!("check task failed: {e}")),
            });
        }
        let mut health = self.health.lock().unwrap_or_else(|p| p.into_inner());
        for (h, r) in health.iter_mut().zip(results) {
            record_health(h, r, now);
        }
    }

    /// Check every node now and then every [`HEALTH_INTERVAL`], for as long as the pool runs.
    /// Changes of reachability are logged.
    pub fn spawn_health_checks(self: &Arc<Self>) {
        if self.endpoints.is_empty() {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            let mut every = tokio::time::interval(HEALTH_INTERVAL);
            every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                every.tick().await;
                let before = me.health();
                me.check_health(crate::miner_stats::now_secs()).await;
                for (old, new) in before.iter().zip(me.health()) {
                    if old.reachable == new.reachable {
                        continue;
                    }
                    match new.reachable {
                        Some(true) => info!(
                            node = %new.node,
                            height = ?new.height,
                            "SOLO: submit node reachable"
                        ),
                        _ => warn!(
                            node = %new.node,
                            error = ?new.error,
                            "SOLO: submit node NOT reachable: found blocks may not reach it"
                        ),
                    }
                }
            }
        });
    }

    /// Whether there are no other nodes.
    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    /// The nodes, as logged.
    pub fn labels(&self) -> Vec<String> {
        self.endpoints.iter().map(|e| e.label.clone()).collect()
    }

    /// Send `block_hex` to every node at once; each node's answer, in the configured order.
    pub async fn submit_block(&self, block_hex: &str) -> Vec<(String, Result<(), String>)> {
        let body = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "ghost-solo",
            "method": "submitblock",
            "params": [block_hex],
        });
        let tasks: Vec<_> = self
            .endpoints
            .iter()
            .map(|e| {
                let e = e.clone();
                let client = self.client.clone();
                let body = body.clone();
                tokio::spawn(async move {
                    let mut req = client.post(&e.url).json(&body);
                    if let Some((u, p)) = &e.auth {
                        req = req.basic_auth(u, Some(p));
                    }
                    let result = match req.send().await {
                        Ok(resp) => {
                            let status = resp.status();
                            match resp.json::<serde_json::Value>().await {
                                Ok(v) => submit_verdict(&v),
                                Err(_) => Err(format!("HTTP {status}, not a JSON-RPC answer")),
                            }
                        }
                        Err(err) => Err(err.without_url().to_string()),
                    };
                    (e.label, result)
                })
            })
            .collect();
        let mut out = Vec::with_capacity(tasks.len());
        for t in tasks {
            match t.await {
                Ok(r) => out.push(r),
                Err(e) => out.push(("?".to_string(), Err(format!("submit task failed: {e}")))),
            }
        }
        out
    }
}

/// A `getblockchaininfo` answer: the node's height, or why not.
pub fn health_verdict(v: &serde_json::Value) -> Result<u64, String> {
    if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
        return Err(err
            .get("message")
            .and_then(|m| m.as_str())
            .map_or_else(|| err.to_string(), str::to_string));
    }
    v.get("result")
        .and_then(|r| r.get("blocks"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "the answer carries no block height".to_string())
}

/// Record one check's outcome at `now`.
pub fn record_health(h: &mut NodeHealth, result: Result<u64, String>, now: u64) {
    h.last_checked_at = Some(now);
    match result {
        Ok(height) => {
            h.reachable = Some(true);
            h.last_ok_at = Some(now);
            h.height = Some(height);
            h.error = None;
        }
        Err(mut e) => {
            if e.len() > HEALTH_ERROR_MAX {
                let mut cut = HEALTH_ERROR_MAX;
                while !e.is_char_boundary(cut) {
                    cut -= 1;
                }
                e.truncate(cut);
            }
            h.reachable = Some(false);
            h.error = Some(e);
        }
    }
}

/// A `submitblock` answer: `null` result is acceptance, a string the rejection reason
/// (`duplicate` included: that node already had it), an error object a failure.
pub fn submit_verdict(v: &serde_json::Value) -> Result<(), String> {
    if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
        return Err(err
            .get("message")
            .and_then(|m| m.as_str())
            .map_or_else(|| err.to_string(), str::to_string));
    }
    match v.get("result") {
        Some(serde_json::Value::Null) | None => Ok(()),
        Some(serde_json::Value::String(s)) => Err(s.clone()),
        Some(other) => Err(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_never_carry_credentials_or_paths() {
        assert_eq!(
            label_of("http://u:p@10.0.0.2:8332/wallet/x"),
            "http://10.0.0.2:8332"
        );
        assert_eq!(
            label_of("https://node.example:443"),
            "https://node.example:443"
        );
        assert_eq!(label_of("10.0.0.2:8332"), "http://10.0.0.2:8332");
    }

    #[test]
    fn auth_lines_per_endpoint_and_default() {
        let (per, default) = parse_auth(
            "# comment\nhttp://10.0.0.2:8332 alice:s3cret\n\n__cookie__:abcd  # cookie\n",
        );
        assert_eq!(
            per,
            vec![(
                "http://10.0.0.2:8332".to_string(),
                ("alice".to_string(), "s3cret".to_string())
            )]
        );
        assert_eq!(
            default,
            Some(("__cookie__".to_string(), "abcd".to_string()))
        );
    }

    #[test]
    fn endpoints_take_their_own_then_the_default_credentials() {
        let dir = std::env::temp_dir().join(format!("solo-auth-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("auth");
        std::fs::write(&f, "http://a:1 ua:pa\nud:pd\n").unwrap();
        let t = SubmitTargets::new(
            &[
                "http://a:1".to_string(),
                "http://b:2".to_string(),
                "http://ui:pi@c:3".to_string(),
            ],
            Some(&f),
        )
        .unwrap();
        let auth: Vec<_> = t
            .endpoints
            .iter()
            .map(|e| e.auth.clone().unwrap())
            .collect();
        assert_eq!(auth[0], ("ua".into(), "pa".into()));
        assert_eq!(auth[1], ("ud".into(), "pd".into()));
        assert_eq!(auth[2], ("ui".into(), "pi".into()));
        assert_eq!(t.endpoints[2].url, "http://c:3");
        assert_eq!(t.labels(), vec!["http://a:1", "http://b:2", "http://c:3"]);
        // Debug never shows a password.
        assert!(!format!("{:?}", t.endpoints).contains("pa"));
        assert!(SubmitTargets::new(&["ftp://x".to_string()], None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A stand-in node answering every request with `answer` and recording the authorization
    /// header it was sent.
    async fn fake_node(answer: &'static str) -> (String, Arc<Mutex<Vec<Option<String>>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(vec![]));
        let s = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut c, _)) = l.accept().await else {
                    return;
                };
                // Read the whole request (headers, then content-length bytes of body).
                let mut buf = vec![];
                let mut chunk = [0u8; 4096];
                loop {
                    let n = c.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some(end) = text.find("\r\n\r\n") {
                        let len = text[..end]
                            .lines()
                            .find_map(|l| {
                                let l = l.to_ascii_lowercase();
                                l.strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        if buf.len() >= end + 4 + len {
                            break;
                        }
                    }
                }
                let req = String::from_utf8_lossy(&buf).to_string();
                let auth = req
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                    .map(|l| l.to_string());
                s.lock().unwrap().push(auth);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{answer}",
                    answer.len()
                );
                let _ = c.write_all(resp.as_bytes()).await;
            }
        });
        (url, seen)
    }

    #[tokio::test]
    async fn health_checks_record_height_and_errors_without_credentials() {
        let (up, seen) =
            fake_node(r#"{"result":{"chain":"regtest","blocks":321},"error":null}"#).await;
        // A port nothing listens on.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let down = format!("http://{}", l.local_addr().unwrap());
        drop(l);
        let up_auth = up.replace("http://", "http://alice:s3cret@");
        let down_auth = down.replace("http://", "http://bob:hunter2@");
        let t = SubmitTargets::new(&[up_auth, down_auth], None).unwrap();
        let before = t.health();
        assert_eq!(before.len(), 2);
        assert_eq!(before[0].reachable, None, "unknown until checked");
        assert_eq!(before[0].node, up);

        t.check_health(1_000).await;
        let h = t.health();
        assert_eq!(h[0].reachable, Some(true));
        assert_eq!(h[0].height, Some(321));
        assert_eq!(h[0].last_ok_at, Some(1_000));
        assert_eq!(h[0].error, None);
        assert_eq!(h[1].reachable, Some(false));
        assert_eq!(h[1].last_checked_at, Some(1_000));
        assert_eq!(h[1].last_ok_at, None);
        assert!(h[1].error.is_some());
        // The node got its credentials; the report never carries them.
        assert!(seen.lock().unwrap()[0]
            .as_deref()
            .unwrap()
            .contains("Basic"));
        let json = serde_json::to_string(&h).unwrap();
        for secret in ["alice", "s3cret", "bob", "hunter2"] {
            assert!(!json.contains(secret), "{json}");
        }

        // A later failure keeps the last good answer's time and height.
        let mut x = h[0].clone();
        record_health(&mut x, Err("x".repeat(500)), 2_000);
        assert_eq!(x.reachable, Some(false));
        assert_eq!(x.last_ok_at, Some(1_000));
        assert_eq!(x.height, Some(321));
        assert_eq!(x.last_checked_at, Some(2_000));
        assert!(x.error.as_ref().unwrap().len() <= 200);
    }

    #[test]
    fn health_answers() {
        assert_eq!(
            health_verdict(&serde_json::json!({"result": {"blocks": 7}, "error": null})),
            Ok(7)
        );
        assert_eq!(
            health_verdict(
                &serde_json::json!({"result": null, "error": {"code": -28, "message": "Loading block index..."}})
            ),
            Err("Loading block index...".to_string())
        );
        assert!(health_verdict(&serde_json::json!({"result": {}})).is_err());
    }

    #[test]
    fn submitblock_answers() {
        assert_eq!(
            submit_verdict(&serde_json::json!({"result": null, "error": null})),
            Ok(())
        );
        assert_eq!(
            submit_verdict(&serde_json::json!({"result": "duplicate", "error": null})),
            Err("duplicate".to_string())
        );
        assert_eq!(
            submit_verdict(
                &serde_json::json!({"result": null, "error": {"code": -1, "message": "bad"}})
            ),
            Err("bad".to_string())
        );
    }
}
