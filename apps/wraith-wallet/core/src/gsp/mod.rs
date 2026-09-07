//! GSP client (REST + WebSocket).
//!
//! Phase 1: WebSocket Ping/Pong probe + REST registration / session creation +
//! long-lived authenticated session task (`session` submodule).
//!
//! Reuses message types from `ghost-gsp-proto` so the wire format stays in sync with the server.

pub mod session;
pub use session::{
    spawn_session, spawn_session_with_bech32, BalanceSnapshot, SessionHandle, SessionPhase,
    SessionStatus,
};

use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use ghost_gsp_proto::{
    ClientMessage, RegisterRequest, RegisterResponse, ServerMessage, SessionRequest,
    SessionResponse, SessionToken, WalletId, WalletProof,
};
use tokio_tungstenite::tungstenite::Message;

#[derive(Debug, thiserror::Error)]
pub enum GspError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("server returned unexpected message: {0}")]
    Unexpected(String),
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("server returned error: {0}")]
    Server(String),
    #[error("missing field in response: {0}")]
    MissingField(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingResult {
    /// GSP server's wall-clock at response time (unix milliseconds).
    pub server_time: i64,
    /// Round-trip time in milliseconds, if the server echoed our timestamp.
    pub round_trip_ms: Option<i64>,
}

pub struct GspClient {
    /// Ordered list of WebSocket URLs. Tried in sequence on single-shot calls
    /// (ping/register/create_session) and rotated across by the persistent
    /// session task on reconnect.
    ws_urls: Vec<String>,
    /// HTTP base URLs derived 1:1 from `ws_urls`.
    /// e.g. `ws://host:port/ws/v1` → `http://host:port`.
    http_bases: Vec<String>,
    http: reqwest::Client,
    /// SOCKS5 proxy for WebSocket connections, if configured.
    ///
    /// Held separately from `http`: a `reqwest::Proxy` lives inside that
    /// client and cannot be read back out, so a WebSocket opened alongside it
    /// would have gone direct — which is how the ping below used to leak.
    ws_proxy: Option<String>,
}

impl GspClient {
    pub fn new(ws_url: impl Into<String>) -> Self {
        Self::with_urls(vec![ws_url.into()])
    }

    pub fn with_urls(ws_urls: Vec<String>) -> Self {
        Self::with_urls_and_proxy(ws_urls, None).expect("default reqwest client always builds")
    }

    /// Same as `with_urls` but routes traffic through the given SOCKS5 proxy
    /// (e.g. `socks5h://127.0.0.1:9050` for Tor).
    ///
    /// REST and every WebSocket this client opens honour it: `tokio-tungstenite`
    /// has no proxy support of its own, so `session::ws_connect` does
    /// the SOCKS5 handshake and hands it the resulting socket.
    ///
    /// **`wss://` over a proxy is refused, not silently downgraded.** The TLS
    /// layer on top of a SOCKS5 socket is not wired yet, so a Tor user on a TLS
    /// endpoint gets an error rather than a direct connection — the right
    /// failure direction, but it does mean Tor plus `wss` is unavailable. Use
    /// `ws://` to an onion service.
    ///
    /// ⚠ This doc once said the persistent session ignored the proxy. It had
    /// not been true for some time, and it was believed because it was written
    /// down. Prefer reading `ws_connect`.
    pub fn with_urls_and_proxy(
        ws_urls: Vec<String>,
        proxy_url: Option<&str>,
    ) -> Result<Self, GspError> {
        let urls = if ws_urls.is_empty() {
            vec!["ws://127.0.0.1:8900/ws/v1".to_string()]
        } else {
            ws_urls
        };
        let http_bases = urls.iter().map(|u| derive_http_base(u)).collect();
        let mut builder = reqwest::Client::builder();
        if let Some(p) = proxy_url {
            let proxy =
                reqwest::Proxy::all(p).map_err(|e| GspError::Transport(format!("proxy: {e}")))?;
            builder = builder.proxy(proxy);
        }
        let http = builder
            .build()
            .map_err(|e| GspError::Transport(format!("http client: {e}")))?;
        Ok(Self {
            ws_urls: urls,
            http_bases,
            http,
            ws_proxy: proxy_url.map(|p| p.to_string()),
        })
    }

    /// Parse a comma-separated WS URL list. Trims whitespace and drops empties.
    pub fn parse_urls(s: &str) -> Vec<String> {
        s.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// Read-only access to the configured WS URLs (in failover order).
    pub fn ws_urls(&self) -> &[String] {
        &self.ws_urls
    }

    /// Open a WebSocket, send `Ping`, wait for `Pong`, close. Single-shot.
    ///
    /// Tries each configured WS URL in order; first successful Pong wins.
    pub async fn ping(&self) -> Result<PingResult, GspError> {
        let mut last_err: Option<GspError> = None;
        for url in &self.ws_urls {
            match self.try_ping(url).await {
                Ok(r) => return Ok(r),
                Err(e) => {
                    tracing::debug!(url = %url, error = %e, "gsp ping endpoint failed, trying next");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| GspError::Transport("no endpoints configured".into())))
    }

    async fn try_ping(&self, ws_url: &str) -> Result<PingResult, GspError> {
        // Bound the connect at 5 s; tokio-tungstenite's connect_async would
        // otherwise inherit the OS-default socket timeout (60+ s on Linux)
        // when the host is unroutable, which blocks doctor for far longer
        // than is useful. 5 s comfortably covers any real LAN / internet
        // handshake.
        // Through the proxy when one is configured. This used to call
        // `connect_async` directly, so a Tor user's health check dialled the
        // GSP from their own address — a short connection, but one that runs
        // on a timer and reveals exactly what the proxy is there to hide.
        let (mut ws, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            super::gsp::session::ws_connect(ws_url, self.ws_proxy.as_deref()),
        )
        .await
        .map_err(|_| GspError::Transport(format!("connect to {ws_url}: timed out after 5s")))?
        .map_err(GspError::Transport)?;

        let sent_ts = now_unix_ms();
        let request = ClientMessage::Ping {
            timestamp: Some(sent_ts),
        };
        let payload =
            serde_json::to_string(&request).map_err(|e| GspError::Encoding(e.to_string()))?;

        ws.send(Message::Text(payload))
            .await
            .map_err(|e| GspError::Transport(e.to_string()))?;

        loop {
            let frame = ws
                .next()
                .await
                .ok_or_else(|| GspError::Transport("connection closed before Pong".into()))?
                .map_err(|e| GspError::Transport(e.to_string()))?;

            let text = match frame {
                Message::Text(t) => t,
                Message::Close(_) => {
                    return Err(GspError::Transport("server closed before Pong".into()));
                }
                _ => continue,
            };

            let parsed: ServerMessage = serde_json::from_str(text.as_ref())
                .map_err(|e| GspError::Encoding(e.to_string()))?;

            if let ServerMessage::Pong {
                timestamp: echoed,
                server_time,
            } = parsed
            {
                let _ = ws.close(None).await;
                let round_trip_ms = echoed.map(|_| (now_unix_ms() - sent_ts).max(0));
                return Ok(PingResult {
                    server_time,
                    round_trip_ms,
                });
            }

            return Err(GspError::Unexpected(format!("{parsed:?}")));
        }
    }

    /// `POST /api/v1/register` — register the wallet identified by the proof's pubkey.
    /// Tries each configured HTTP base in order; first 2xx wins.
    pub async fn register(
        &self,
        proof: WalletProof,
        display_name: Option<String>,
    ) -> Result<WalletId, GspError> {
        let body = RegisterRequest {
            proof,
            display_name,
        };
        let mut last_err: Option<GspError> = None;
        for base in &self.http_bases {
            let url = format!("{base}/api/v1/register");
            match self.try_register(&url, &body).await {
                Ok(id) => return Ok(id),
                Err(GspError::Transport(t)) => {
                    tracing::debug!(url = %url, error = %t, "register endpoint transport failed, trying next");
                    last_err = Some(GspError::Transport(t));
                }
                // 4xx server errors aren't a failover signal — surface immediately.
                Err(other) => return Err(other),
            }
        }
        Err(last_err.unwrap_or_else(|| GspError::Transport("no endpoints configured".into())))
    }

    async fn try_register(&self, url: &str, body: &RegisterRequest) -> Result<WalletId, GspError> {
        let resp = self
            .http
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(|e| GspError::Transport(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| GspError::Encoding(e.to_string()))?;
        if !status.is_success() {
            return Err(GspError::Server(extract_error(&text, status)));
        }
        let body: RegisterResponse =
            serde_json::from_str(&text).map_err(|e| GspError::Encoding(e.to_string()))?;
        if !body.success {
            return Err(GspError::Server(body.error.unwrap_or_else(|| {
                format!("register failed with status {status}")
            })));
        }
        body.wallet_id.ok_or(GspError::MissingField("wallet_id"))
    }

    /// `POST /api/v1/session` — create a session, returning the JWT.
    /// Tries each configured HTTP base in order on transport failure.
    pub async fn create_session(
        &self,
        proof: WalletProof,
        session_nonce: Option<String>,
    ) -> Result<SessionToken, GspError> {
        let body = SessionRequest {
            proof,
            session_nonce,
        };
        let mut last_err: Option<GspError> = None;
        for base in &self.http_bases {
            let url = format!("{base}/api/v1/session");
            match self.try_create_session(&url, &body).await {
                Ok(t) => return Ok(t),
                Err(GspError::Transport(t)) => {
                    tracing::debug!(url = %url, error = %t, "session endpoint transport failed, trying next");
                    last_err = Some(GspError::Transport(t));
                }
                Err(other) => return Err(other),
            }
        }
        Err(last_err.unwrap_or_else(|| GspError::Transport("no endpoints configured".into())))
    }

    async fn try_create_session(
        &self,
        url: &str,
        body: &SessionRequest,
    ) -> Result<SessionToken, GspError> {
        let resp = self
            .http
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(|e| GspError::Transport(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| GspError::Encoding(e.to_string()))?;
        if !status.is_success() {
            return Err(GspError::Server(extract_error(&text, status)));
        }
        let body: SessionResponse =
            serde_json::from_str(&text).map_err(|e| GspError::Encoding(e.to_string()))?;
        if !body.success {
            return Err(GspError::Server(
                body.error
                    .unwrap_or_else(|| format!("session failed with status {status}")),
            ));
        }
        body.token.ok_or(GspError::MissingField("token"))
    }
}

/// Pull a useful message out of an error response. Handles both
/// the structured `{"error": {"code", "message"}, "success": false}` shape
/// the GSP returns on 4xx, and any unstructured plaintext fallback.
fn extract_error(text: &str, status: reqwest::StatusCode) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        if let Some(msg) = v.pointer("/error/message").and_then(|m| m.as_str()) {
            return msg.to_string();
        }
        if let Some(code) = v.pointer("/error/code").and_then(|c| c.as_str()) {
            return code.to_string();
        }
        if let Some(s) = v.pointer("/error").and_then(|m| m.as_str()) {
            return s.to_string();
        }
    }
    if text.is_empty() {
        format!("status {status}")
    } else {
        format!("status {status}: {text}")
    }
}

fn derive_http_base(ws_url: &str) -> String {
    let (scheme, rest) = if let Some(r) = ws_url.strip_prefix("wss://") {
        ("https", r)
    } else if let Some(r) = ws_url.strip_prefix("ws://") {
        ("http", r)
    } else {
        // Already an http(s) URL? trim any trailing path.
        let r = ws_url
            .trim_start_matches("http://")
            .trim_start_matches("https://");
        let s = if ws_url.starts_with("https://") {
            "https"
        } else {
            "http"
        };
        (s, r)
    };
    let host_and_port = rest.split('/').next().unwrap_or(rest);
    format!("{scheme}://{host_and_port}")
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_http_base_strips_path() {
        assert_eq!(
            derive_http_base("ws://127.0.0.1:8900/ws/v1"),
            "http://127.0.0.1:8900"
        );
        assert_eq!(
            derive_http_base("wss://gsp.example.com/ws/v1"),
            "https://gsp.example.com"
        );
        assert_eq!(
            derive_http_base("ws://localhost:9000"),
            "http://localhost:9000"
        );
    }
}

#[cfg(test)]
mod proxy_tests {
    use super::*;

    /// The proxy must be kept, not just handed to `reqwest`.
    ///
    /// This is the shape of the bug it replaces: the proxy went into the HTTP
    /// client and nowhere else, and a `reqwest::Proxy` cannot be read back out
    /// — so every WebSocket opened alongside it went direct with nothing in
    /// the type system to say so.
    #[test]
    fn a_proxied_client_keeps_the_proxy_for_websockets() {
        let c = GspClient::with_urls_and_proxy(
            vec!["ws://127.0.0.1:8900/ws/v1".into()],
            Some("socks5h://127.0.0.1:9050"),
        )
        .expect("builds");
        assert_eq!(
            c.ws_proxy.as_deref(),
            Some("socks5h://127.0.0.1:9050"),
            "a WebSocket opened by this client must be able to find the proxy"
        );
    }

    #[test]
    fn an_unproxied_client_has_no_proxy() {
        let c = GspClient::with_urls(vec!["ws://127.0.0.1:8900/ws/v1".into()]);
        assert!(c.ws_proxy.is_none());
    }

    /// `wss` through a proxy is refused rather than silently going direct.
    ///
    /// The wrong failure here would be a downgrade: a Tor user on a TLS
    /// endpoint quietly connecting from their own address. An error is the
    /// safe direction even though it means the combination is unavailable.
    #[tokio::test]
    async fn wss_through_a_proxy_is_refused_not_downgraded() {
        let err = super::session::ws_connect(
            "wss://example.invalid:443/ws/v1",
            Some("socks5h://127.0.0.1:9050"),
        )
        .await
        .expect_err("wss over a proxy is not supported");
        assert!(
            err.contains("wss-over-tor not yet supported"),
            "it must say why, not just fail: {err}"
        );
    }
}
