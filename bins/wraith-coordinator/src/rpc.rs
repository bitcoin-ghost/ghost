//! Minimal bitcoind JSON-RPC client.
//!
//! Extracted from `GhostdBroadcaster` when `GhostdUtxoSource` needed the
//! same connection: the coordinator talks to exactly one node, so the
//! transport, the auth header and the request/response shapes are shared
//! and each caller maps `RpcError` onto its own error type.
//!
//! Deliberately small — this is not a general bitcoind client. It sends
//! a method and params and hands back the `result` value.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Transport- and protocol-level failures. Callers decide what each one
/// means for them: a `Rpc` error is the node refusing the call, which
/// for `sendrawtransaction` is a rejected transaction but for `gettxout`
/// means the node is unhappy with the request itself.
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("node unreachable: {0}")]
    Transport(String),
    #[error("code {code}: {message}")]
    Rpc { code: i32, message: String },
    #[error("malformed RPC response: {0}")]
    Malformed(String),
}

#[derive(Clone)]
pub struct RpcClient {
    endpoint: String,
    auth_header: String,
    agent: ureq::Agent,
}

impl std::fmt::Debug for RpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the auth header — it carries the RPC password.
        f.debug_struct("RpcClient")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl RpcClient {
    /// Construct from an RPC URL + (user, password). The pair is
    /// base64-encoded into the Authorization header once, at
    /// construction, rather than on every call.
    pub fn new(endpoint: impl Into<String>, user: &str, password: &str) -> Self {
        use base64::Engine;
        let creds = format!("{user}:{password}");
        let encoded = base64::engine::general_purpose::STANDARD.encode(creds);
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            .build();
        Self {
            endpoint: endpoint.into(),
            auth_header: format!("Basic {encoded}"),
            agent,
        }
    }

    /// Read bitcoind's `.cookie` file and build from its contents. The
    /// cookie is `__cookie__:<random>`; split on the first colon.
    pub fn from_cookie(
        endpoint: impl Into<String>,
        cookie_path: impl AsRef<std::path::Path>,
    ) -> Result<Self, RpcError> {
        let raw = std::fs::read_to_string(cookie_path.as_ref())
            .map_err(|e| RpcError::Transport(format!("cookie read: {e}")))?;
        let raw = raw.trim();
        let (user, password) = raw
            .split_once(':')
            .ok_or_else(|| RpcError::Transport("malformed cookie file".into()))?;
        Ok(Self::new(endpoint, user, password))
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Call `method` and return its `result`. A JSON `null` result is
    /// returned as `Value::Null` rather than an error — `gettxout`
    /// answers "no such unspent output" that way.
    pub fn call(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value, RpcError> {
        let body = RpcRequest {
            jsonrpc: "1.0",
            id: "wraith-coordinator",
            method,
            params,
        };

        let resp = self
            .agent
            .post(&self.endpoint)
            .set("Authorization", &self.auth_header)
            .send_json(&body);

        let resp = match resp {
            Ok(r) => r,
            // A non-2xx status still carries a JSON body with the RPC
            // error in it, which is more informative than the status.
            Err(ureq::Error::Status(_, response)) => response,
            Err(ureq::Error::Transport(t)) => {
                let kind = t.kind();
                return Err(RpcError::Transport(format!("{kind:?}: {t}")));
            }
        };
        let status = resp.status();
        let parsed: RpcResponse = resp
            .into_json()
            .map_err(|e| RpcError::Malformed(format!("parse: {e}")))?;

        if let Some(err) = parsed.error {
            return Err(RpcError::Rpc {
                code: err.code,
                message: err.message,
            });
        }

        parsed.result.ok_or_else(|| {
            RpcError::Malformed(format!("RPC {status} returned neither result nor error"))
        })
    }
}

#[derive(Serialize)]
struct RpcRequest<'a> {
    jsonrpc: &'a str,
    id: &'a str,
    method: &'a str,
    params: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct RpcResponse {
    result: Option<serde_json::Value>,
    error: Option<RpcErrorBody>,
}

#[derive(Deserialize, Debug)]
struct RpcErrorBody {
    code: i32,
    message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_renders_the_auth_header() {
        let c = RpcClient::new("http://127.0.0.1:8332", "user", "hunter2");
        let rendered = format!("{c:?}");
        assert!(rendered.contains("127.0.0.1:8332"));
        assert!(!rendered.contains("hunter2"));
        // The base64 of `user:hunter2` must not leak either.
        assert!(!rendered.contains("dXNlcjpodW50ZXIy"));
    }

    #[test]
    fn cookie_files_split_on_the_first_colon_only() {
        let dir = std::env::temp_dir().join("wraith-rpc-cookie-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(".cookie");
        // A password containing a colon must survive intact.
        std::fs::write(&path, "__cookie__:abc:def\n").unwrap();
        let c = RpcClient::from_cookie("http://127.0.0.1:8332", &path).unwrap();
        assert_eq!(c.endpoint(), "http://127.0.0.1:8332");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_malformed_cookie_is_rejected() {
        let dir = std::env::temp_dir().join("wraith-rpc-cookie-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(".cookie-bad");
        std::fs::write(&path, "no-colon-here").unwrap();
        assert!(RpcClient::from_cookie("http://127.0.0.1:8332", &path).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
