//! HTTP client wrapper with timing, retries, and cluster helpers.

use std::time::{Duration, Instant};

use reqwest::Client;
use serde_json::Value;

use super::config::ClusterConfig;

pub struct RequestResult {
    pub status: Option<u16>,
    pub latency: Duration,
    pub node_ip: String,
    pub error: Option<String>,
    pub body: Option<String>,
}

pub struct ClusterClient {
    client: Client,
    pub config: ClusterConfig,
}

impl ClusterClient {
    pub fn new(config: ClusterConfig) -> Self {
        let client = Client::builder()
            .timeout(config.http_timeout)
            .pool_max_idle_per_host(10)
            .build()
            .expect("failed to build reqwest client");
        Self { client, config }
    }

    /// Single GET request with timing.
    pub async fn get(&self, ip: &str, endpoint: &str) -> RequestResult {
        let url = self.config.url(ip, endpoint);
        let start = Instant::now();

        match self.client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                let latency = start.elapsed();
                RequestResult {
                    status: Some(status),
                    latency,
                    node_ip: ip.to_string(),
                    error: if status >= 400 {
                        Some(format!("HTTP {}", status))
                    } else {
                        None
                    },
                    body: Some(body),
                }
            }
            Err(e) => RequestResult {
                status: None,
                latency: start.elapsed(),
                node_ip: ip.to_string(),
                error: Some(e.to_string()),
                body: None,
            },
        }
    }

    /// GET with retries and exponential backoff.
    pub async fn get_with_retry(&self, ip: &str, endpoint: &str) -> RequestResult {
        let mut last_result = self.get(ip, endpoint).await;
        for attempt in 1..=self.config.retry_count {
            if last_result.error.is_none() {
                return last_result;
            }
            let backoff = self.config.retry_backoff * attempt;
            tokio::time::sleep(backoff).await;
            last_result = self.get(ip, endpoint).await;
        }
        last_result
    }

    /// GET the same endpoint on all nodes concurrently.
    pub async fn get_all_nodes(&self, endpoint: &str) -> Vec<RequestResult> {
        let mut handles = Vec::new();
        for ip in self.config.all_ips() {
            let client = self.client.clone();
            let url = self.config.url(ip, endpoint);
            let timeout = self.config.http_timeout;
            let ip_owned = ip.to_string();
            handles.push(tokio::spawn(async move {
                let start = Instant::now();
                let temp_client = Client::builder().timeout(timeout).build().unwrap_or(client);
                match temp_client.get(&url).send().await {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let body = resp.text().await.unwrap_or_default();
                        RequestResult {
                            status: Some(status),
                            latency: start.elapsed(),
                            node_ip: ip_owned,
                            error: if status >= 400 {
                                Some(format!("HTTP {}", status))
                            } else {
                                None
                            },
                            body: Some(body),
                        }
                    }
                    Err(e) => RequestResult {
                        status: None,
                        latency: start.elapsed(),
                        node_ip: ip_owned,
                        error: Some(e.to_string()),
                        body: None,
                    },
                }
            }));
        }

        let mut results = Vec::new();
        for h in handles {
            if let Ok(r) = h.await {
                results.push(r);
            }
        }
        results
    }

    /// GET and parse JSON response.
    pub async fn get_json(&self, ip: &str, endpoint: &str) -> Result<Value, String> {
        let result = self.get(ip, endpoint).await;
        if let Some(err) = result.error {
            return Err(err);
        }
        let body = result.body.ok_or("empty body")?;
        serde_json::from_str(&body).map_err(|e| format!("JSON parse error: {}", e))
    }

    /// Poll until /health returns 200 or timeout.
    pub async fn wait_for_node_healthy(&self, ip: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            let result = self.get(ip, "/health").await;
            if result.error.is_none() && result.status == Some(200) {
                return true;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        false
    }

    /// Get block height from /api/v1/node/status.
    pub async fn get_block_height(&self, ip: &str) -> Result<u64, String> {
        let json = self.get_json(ip, "/api/v1/node/status").await?;
        // Try common field names
        json.get("height")
            .or_else(|| json.get("block_height"))
            .or_else(|| json.get("best_height"))
            .and_then(|v| v.as_u64())
            .ok_or_else(|| format!("no height field in response: {}", json))
    }

    /// Get peer count from /api/v1/network/peers.
    pub async fn get_peer_count(&self, ip: &str) -> Result<usize, String> {
        let json = self.get_json(ip, "/api/v1/network/peers").await?;
        // Response might be an array of peers or an object with a count
        if let Some(arr) = json.as_array() {
            return Ok(arr.len());
        }
        if let Some(count) = json.get("count").or_else(|| json.get("peer_count")) {
            return count
                .as_u64()
                .map(|c| c as usize)
                .ok_or_else(|| "peer count not a number".to_string());
        }
        // Maybe it's an object with a "peers" array
        if let Some(peers) = json.get("peers").and_then(|v| v.as_array()) {
            return Ok(peers.len());
        }
        Err(format!("cannot extract peer count from: {}", json))
    }

    /// Probe an endpoint: returns (status_code, optional parsed JSON body).
    /// Used by endpoint coverage tests to check route existence (not-404).
    pub async fn probe_endpoint(&self, ip: &str, endpoint: &str) -> (u16, Option<Value>) {
        let result = self.get_with_retry(ip, endpoint).await;
        let status = result.status.unwrap_or(0);
        let json = result
            .body
            .as_deref()
            .and_then(|b| serde_json::from_str(b).ok());
        (status, json)
    }

    /// Fire `count` sequential requests with `interval` between each.
    /// Returns the full list of RequestResults for rate limiter characterization.
    pub async fn timed_sequential_requests(
        &self,
        ip: &str,
        endpoint: &str,
        count: usize,
        interval: Duration,
    ) -> Vec<super::client::RequestResult> {
        let mut results = Vec::with_capacity(count);
        for _ in 0..count {
            results.push(self.get(ip, endpoint).await);
            if !interval.is_zero() {
                tokio::time::sleep(interval).await;
            }
        }
        results
    }
}
