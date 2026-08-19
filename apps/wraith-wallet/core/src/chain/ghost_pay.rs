//! Ghost-pay REST client.

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

use super::{ChainClient, ChainError, ChainStatus};

/// REST client for ghost-pay. Holds one or more base URLs and tries them in
/// order on each request — a failure on the first URL automatically falls
/// over to the next.
pub struct GhostPayClient {
    base_urls: Vec<String>,
    http: Client,
    /// Optional shared secret used for the `X-Internal-Auth` bypass
    /// on ghost-pay's authenticated routes. When set, every request
    /// sends this header and ghost-pay accepts the call without
    /// HMAC. The wallet uses this for endpoints behind
    /// `authenticated_routes` (e.g. `/api/v1/utxos/scan`). When
    /// None, only public routes are reachable.
    internal_secret: Option<String>,
}

impl GhostPayClient {
    /// Construct from a single base URL.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_urls(vec![base_url.into()])
    }

    /// Construct from a list of base URLs. They will be tried in order on
    /// each request until one succeeds.
    pub fn with_urls(base_urls: Vec<String>) -> Self {
        Self::with_urls_and_proxy(base_urls, None).expect("default reqwest client always builds")
    }

    /// Same as `with_urls` but routes every request through a SOCKS5 proxy
    /// (e.g. `socks5h://127.0.0.1:9050` for Tor). Pass `None` for direct
    /// connections.
    ///
    /// `socks5h://` (note the `h`) does DNS through the proxy — preferred
    /// for Tor so hostnames don't leak to your local resolver.
    pub fn with_urls_and_proxy(
        base_urls: Vec<String>,
        proxy_url: Option<&str>,
    ) -> Result<Self, ChainError> {
        let urls = if base_urls.is_empty() {
            vec!["http://127.0.0.1:8800".to_string()]
        } else {
            base_urls
        };
        // Bounded timeouts on every request:
        //   * connect_timeout = 5 s — TCP handshake to a non-routable IP
        //     would otherwise hang on the OS-default socket timeout
        //     (60+ s on Linux). 5 s comfortably covers any real LAN /
        //     internet round-trip.
        //   * timeout = 15 s — overall request budget once connected,
        //     matches the daemon's other reqwest clients.
        let mut builder = Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(15));
        if let Some(p) = proxy_url {
            let proxy =
                reqwest::Proxy::all(p).map_err(|e| ChainError::Transport(format!("proxy: {e}")))?;
            builder = builder.proxy(proxy);
        }
        let http = builder
            .build()
            .map_err(|e| ChainError::Transport(format!("http client: {e}")))?;
        Ok(Self {
            base_urls: urls,
            http,
            internal_secret: None,
        })
    }

    /// Attach an `X-Internal-Auth` shared secret. After this, calls
    /// to ghost-pay's authenticated routes will bypass HMAC and use
    /// the bearer header. Without it, those routes return 401.
    pub fn with_internal_secret(mut self, secret: impl Into<String>) -> Self {
        self.internal_secret = Some(secret.into());
        self
    }

    /// Parse a comma-separated URL list, trimming whitespace and dropping
    /// empty entries.
    pub fn parse_urls(s: &str) -> Vec<String> {
        s.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    }

    fn endpoint(&self, base_url: &str, path: &str) -> String {
        format!("{}{}", base_url.trim_end_matches('/'), path)
    }
}

#[async_trait]
impl ChainClient for GhostPayClient {
    async fn status(&self) -> Result<ChainStatus, ChainError> {
        let mut last_err: Option<ChainError> = None;
        for base in &self.base_urls {
            match self.try_status(base).await {
                Ok(s) => return Ok(s),
                Err(e) => {
                    tracing::debug!(url = %base, error = %e, "ghost-pay endpoint failed, trying next");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| ChainError::Transport("no endpoints configured".into())))
    }

    async fn scan_utxos(
        &self,
        addresses: &[String],
        min_confirmations: u32,
    ) -> Result<ScanUtxosResponse, ChainError> {
        // Concrete impl is on the inherent block; trait method just
        // forwards. Splitting the two means the inherent method is
        // still discoverable by callers that hold a concrete
        // `GhostPayClient` and want full type info.
        GhostPayClient::scan_utxos(self, addresses, min_confirmations).await
    }

    async fn broadcast_tx(&self, tx_hex: &str) -> Result<String, ChainError> {
        GhostPayClient::broadcast_tx(self, tx_hex).await
    }
}

/// One UTXO row from `POST /api/v1/utxos/scan`. Mirrors ghost-pay's
/// `ScannedUtxo` shape; kept separate so the wallet doesn't depend on
/// ghost-pay internals.
#[derive(Debug, Clone, Deserialize)]
pub struct ScannedL1Utxo {
    pub txid: String,
    pub vout: u32,
    pub amount_sats: u64,
    pub scriptpubkey_hex: String,
    pub address: Option<String>,
    pub confirmations: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScanUtxosResponse {
    pub utxos: Vec<ScannedL1Utxo>,
    pub total_sats: u64,
    pub chain_height: u32,
}

impl GhostPayClient {
    /// Scan ghost-pay's bitcoind UTXO set for outputs matching any of
    /// `addresses`. Authenticated route — fails with `Backend(...)`
    /// 401 unless `with_internal_secret(...)` was set on the client.
    ///
    /// The call is bounded by ghost-pay (max 1024 addresses per
    /// request) but is still expensive: bitcoind walks the full
    /// chain UTXO set on each invocation. Mainnet round-trips in
    /// 5-15 s; signet/regtest under 1 s. Caller should chunk and
    /// surface progress accordingly.
    pub async fn scan_utxos(
        &self,
        addresses: &[String],
        min_confirmations: u32,
    ) -> Result<ScanUtxosResponse, ChainError> {
        let mut last_err: Option<ChainError> = None;
        for base in &self.base_urls {
            match self
                .try_scan_utxos(base, addresses, min_confirmations)
                .await
            {
                Ok(r) => return Ok(r),
                Err(e) => {
                    tracing::debug!(url = %base, error = %e, "ghost-pay scan_utxos failed, trying next");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| ChainError::Transport("no endpoints configured".into())))
    }

    /// Broadcast a fully-signed Bitcoin transaction via ghost-pay's
    /// `POST /api/v1/tx/broadcast`. Authenticated; fails with
    /// `Backend(...)` 401 unless `with_internal_secret(...)` was set.
    /// On success, returns the txid that bitcoind accepted.
    pub async fn broadcast_tx(&self, tx_hex: &str) -> Result<String, ChainError> {
        let mut last_err: Option<ChainError> = None;
        for base in &self.base_urls {
            match self.try_broadcast_tx(base, tx_hex).await {
                Ok(txid) => return Ok(txid),
                Err(e) => {
                    tracing::debug!(
                        url = %base,
                        error = %e,
                        "ghost-pay broadcast_tx failed, trying next"
                    );
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| ChainError::Transport("no endpoints configured".into())))
    }

    /// `GET /api/v1/pool/coordinator` — the node's decentralised-coordinator
    /// election view, relayed by ghost-pay (the wallet never hits the node's pool
    /// API directly; wallet hard rule). Returns the raw election JSON; the daemon
    /// resolves which seat owns a given (tier, epoch) shard from it. ghost-pay
    /// returns the inert `{"enabled": false}` shape when the node has the feature
    /// off or is unreachable, so the wallet falls back to a manual coordinator URL.
    pub async fn coordinator_election(&self) -> Result<serde_json::Value, ChainError> {
        let mut last_err: Option<ChainError> = None;
        for base in &self.base_urls {
            match self.try_coordinator_election(base).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    tracing::debug!(url = %base, error = %e, "ghost-pay coordinator_election failed, trying next");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| ChainError::Transport("no endpoints configured".into())))
    }

    async fn try_coordinator_election(
        &self,
        base_url: &str,
    ) -> Result<serde_json::Value, ChainError> {
        let url = self.endpoint(base_url, "/api/v1/pool/coordinator");
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| ChainError::Transport(e.to_string()))?
            .error_for_status()
            .map_err(|e| ChainError::Backend(e.to_string()))?;
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| ChainError::Malformed(e.to_string()))
    }

    async fn try_broadcast_tx(&self, base_url: &str, tx_hex: &str) -> Result<String, ChainError> {
        let url = self.endpoint(base_url, "/api/v1/tx/broadcast");
        let mut req = self.http.post(&url).json(&serde_json::json!({
            "tx_hex": tx_hex,
        }));
        if let Some(secret) = &self.internal_secret {
            req = req.header("X-Internal-Auth", secret);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ChainError::Transport(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            // ghost-pay forwards bitcoind's error string verbatim,
            // so the caller can show the operator's node's actual
            // rejection reason ("min relay fee not met", etc.).
            let detail = resp.text().await.unwrap_or_default();
            return Err(ChainError::Backend(format!(
                "ghost-pay broadcast returned {}: {}",
                status, detail
            )));
        }
        #[derive(Deserialize)]
        struct BroadcastResp {
            txid: String,
        }
        let body: BroadcastResp = resp
            .json()
            .await
            .map_err(|e| ChainError::Malformed(e.to_string()))?;
        Ok(body.txid)
    }

    async fn try_scan_utxos(
        &self,
        base_url: &str,
        addresses: &[String],
        min_confirmations: u32,
    ) -> Result<ScanUtxosResponse, ChainError> {
        let url = self.endpoint(base_url, "/api/v1/utxos/scan");
        let mut req = self.http.post(&url).json(&serde_json::json!({
            "addresses": addresses,
            "min_confirmations": min_confirmations,
        }));
        if let Some(secret) = &self.internal_secret {
            req = req.header("X-Internal-Auth", secret);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ChainError::Transport(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().await.unwrap_or_default();
            return Err(ChainError::Backend(format!(
                "ghost-pay returned {}: {}",
                status, detail
            )));
        }
        resp.json::<ScanUtxosResponse>()
            .await
            .map_err(|e| ChainError::Malformed(e.to_string()))
    }

    /// Fetch the registered Ghost Glyph for `ghost_id` via
    /// `GET /api/v1/glyph/{ghost_id}`. Public route. Returns the raw
    /// `GlyphInfoResponse` JSON; the daemon narrows it into a typed
    /// struct. A 404 (no glyph yet) surfaces as `ChainError::Backend`.
    pub async fn get_glyph(&self, ghost_id: &str) -> Result<serde_json::Value, ChainError> {
        let mut last_err: Option<ChainError> = None;
        for base in &self.base_urls {
            match self.try_get_glyph(base, ghost_id).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    tracing::debug!(url = %base, error = %e, "ghost-pay get_glyph failed, trying next");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| ChainError::Transport("no endpoints configured".into())))
    }

    /// Check whether a glyph bitmap is unclaimed via
    /// `GET /api/v1/glyph/check/{bitmap_hash_hex}`. Public route.
    /// Returns the raw `{ "available": bool }` JSON.
    pub async fn check_glyph(
        &self,
        bitmap_hash_hex: &str,
    ) -> Result<serde_json::Value, ChainError> {
        let mut last_err: Option<ChainError> = None;
        for base in &self.base_urls {
            match self.try_check_glyph(base, bitmap_hash_hex).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    tracing::debug!(url = %base, error = %e, "ghost-pay check_glyph failed, trying next");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| ChainError::Transport("no endpoints configured".into())))
    }

    /// Claim a glyph bitmap for `ghost_id` via
    /// `POST /api/v1/glyph/claim`. Authenticated route — attaches the
    /// `X-Internal-Auth` header when `with_internal_secret(...)` was
    /// set, otherwise ghost-pay returns 401. Returns the raw
    /// `GlyphClaimResponse` JSON.
    pub async fn claim_glyph(
        &self,
        ghost_id: &str,
        pixels: &[u8],
    ) -> Result<serde_json::Value, ChainError> {
        let mut last_err: Option<ChainError> = None;
        for base in &self.base_urls {
            match self.try_claim_glyph(base, ghost_id, pixels).await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    tracing::debug!(url = %base, error = %e, "ghost-pay claim_glyph failed, trying next");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| ChainError::Transport("no endpoints configured".into())))
    }

    async fn try_get_glyph(
        &self,
        base_url: &str,
        ghost_id: &str,
    ) -> Result<serde_json::Value, ChainError> {
        let url = self.endpoint(base_url, &format!("/api/v1/glyph/{ghost_id}"));
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| ChainError::Transport(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().await.unwrap_or_default();
            return Err(ChainError::Backend(format!(
                "ghost-pay glyph returned {}: {}",
                status, detail
            )));
        }
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| ChainError::Malformed(e.to_string()))
    }

    async fn try_check_glyph(
        &self,
        base_url: &str,
        bitmap_hash_hex: &str,
    ) -> Result<serde_json::Value, ChainError> {
        let url = self.endpoint(base_url, &format!("/api/v1/glyph/check/{bitmap_hash_hex}"));
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| ChainError::Transport(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().await.unwrap_or_default();
            return Err(ChainError::Backend(format!(
                "ghost-pay glyph check returned {}: {}",
                status, detail
            )));
        }
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| ChainError::Malformed(e.to_string()))
    }

    async fn try_claim_glyph(
        &self,
        base_url: &str,
        ghost_id: &str,
        pixels: &[u8],
    ) -> Result<serde_json::Value, ChainError> {
        let url = self.endpoint(base_url, "/api/v1/glyph/claim");
        let mut req = self.http.post(&url).json(&serde_json::json!({
            "ghost_id": ghost_id,
            "pixels": pixels,
        }));
        if let Some(secret) = &self.internal_secret {
            req = req.header("X-Internal-Auth", secret);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ChainError::Transport(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let detail = resp.text().await.unwrap_or_default();
            return Err(ChainError::Backend(format!(
                "ghost-pay glyph claim returned {}: {}",
                status, detail
            )));
        }
        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| ChainError::Malformed(e.to_string()))
    }

    async fn try_status(&self, base_url: &str) -> Result<ChainStatus, ChainError> {
        let url = self.endpoint(base_url, "/api/v1/status");
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| ChainError::Transport(e.to_string()))?
            .error_for_status()
            .map_err(|e| ChainError::Backend(e.to_string()))?;
        let body: StatusBody = resp
            .json()
            .await
            .map_err(|e| ChainError::Malformed(e.to_string()))?;
        Ok(ChainStatus {
            backend_version: body.version,
            network: body.network,
            has_keys: body.has_keys,
            lock_count: body.lock_count,
            active_sessions: body.active_sessions,
            chain_height: body.chain_height,
            chain_headers: body.chain_headers,
            chain_verification_progress: body.chain_verification_progress,
            chain_initial_block_download: body.chain_initial_block_download,
            l2_height: body.l2_height,
            l2_epoch: body.l2_epoch,
        })
    }
}

#[derive(Deserialize)]
struct StatusBody {
    version: String,
    has_keys: bool,
    lock_count: u64,
    #[serde(default)]
    active_sessions: u64,
    network: String,
    #[serde(default)]
    chain_height: Option<u64>,
    #[serde(default)]
    chain_headers: Option<u64>,
    #[serde(default)]
    chain_verification_progress: Option<f64>,
    #[serde(default)]
    chain_initial_block_download: Option<bool>,
    #[serde(default)]
    l2_height: Option<u64>,
    #[serde(default)]
    l2_epoch: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_urls_strips_and_drops_empties() {
        assert_eq!(
            GhostPayClient::parse_urls("http://a, http://b ,, http://c"),
            vec!["http://a", "http://b", "http://c"]
        );
        assert!(GhostPayClient::parse_urls("").is_empty());
        assert!(GhostPayClient::parse_urls(" , , ").is_empty());
    }

    #[test]
    fn parses_ghost_pay_status_body() {
        let json = r#"{
            "version": "1.8.0",
            "has_keys": true,
            "lock_count": 3,
            "active_sessions": 0,
            "network": "signet"
        }"#;
        let body: StatusBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.version, "1.8.0");
        assert_eq!(body.network, "signet");
        assert!(body.has_keys);
        assert_eq!(body.lock_count, 3);
        assert_eq!(body.active_sessions, 0);
    }
}
