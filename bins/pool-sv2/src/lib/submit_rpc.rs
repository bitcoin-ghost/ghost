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

use std::{path::Path, time::Duration};

/// Longest a node may take to answer `submitblock`.
pub const SUBMIT_TIMEOUT: Duration = Duration::from_secs(30);

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
}

/// `scheme://host:port` of a URL: what is logged, with no credentials or path.
pub fn label_of(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("http", url));
    let rest = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = rest.rsplit_once('@').map_or(rest, |(_, h)| h);
    format!("{scheme}://{host}")
}

/// Parse a credentials file: `(per-endpoint, default)`.
pub fn parse_auth(text: &str) -> (Vec<(String, (String, String))>, Option<(String, String)>) {
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
        Ok(SubmitTargets { endpoints, client })
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
        assert_eq!(label_of("http://u:p@10.0.0.2:8332/wallet/x"), "http://10.0.0.2:8332");
        assert_eq!(label_of("https://node.example:443"), "https://node.example:443");
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
        let auth: Vec<_> = t.endpoints.iter().map(|e| e.auth.clone().unwrap()).collect();
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
            submit_verdict(&serde_json::json!({"result": null, "error": {"code": -1, "message": "bad"}})),
            Err("bad".to_string())
        );
    }
}
