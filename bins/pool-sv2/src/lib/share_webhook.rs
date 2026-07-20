//! Share webhook module for sending share notifications to external services.
//!
//! This module provides non-blocking webhook notifications for valid shares,
//! implementing batching for efficiency at high share volumes.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::config::ShareWebhookConfig;

/// Channel capacity for share notifications (bounded to prevent unbounded memory growth)
const CHANNEL_CAPACITY: usize = 10_000;

/// Data for a single share notification
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShareData {
    /// Timestamp in milliseconds since epoch
    pub timestamp_ms: u64,
    /// Share hash as hex string
    pub share_hash: String,
    /// Share work/difficulty value
    pub share_work: f64,
    /// Channel ID the share was submitted on
    pub channel_id: u32,
    /// Sequence number from the share submission
    pub sequence_number: u32,
    /// Job ID the share was submitted for
    pub job_id: u32,
    /// Downstream client ID
    pub downstream_id: usize,
    /// Whether this share found a block
    pub is_block: bool,
    /// User identity string (format: <payout_address>.<worker_name>)
    /// Used to identify the miner's payout address
    pub user_identity: String,
    /// Raw 80-byte block header as hex, the PoW preimage for `share_hash`
    /// (`sha256d(header) == share_hash`). Lets a decentralised pool re-verify
    /// a gossiped share's proof-of-work independently instead of trusting the
    /// origin's numeric claim. Optional for backward compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
}

/// Batch of shares to send to the webhook endpoint
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShareBatch {
    /// Pool/server ID
    pub pool_id: u16,
    /// Sequence number for this batch
    pub batch_seq: u64,
    /// Array of shares in this batch
    pub shares: Vec<ShareData>,
}

/// Clone-able handle for sending shares to the webhook worker
#[derive(Clone)]
pub struct ShareWebhookSender {
    sender: mpsc::Sender<ShareData>,
}

impl ShareWebhookSender {
    /// Send a share notification (non-blocking, best effort)
    ///
    /// If the channel is full, the share is dropped and logged.
    /// This ensures mining is never blocked by webhook operations.
    pub fn send(&self, share: ShareData) {
        if let Err(e) = self.sender.try_send(share) {
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    warn!("Share webhook channel full, dropping share notification");
                }
                mpsc::error::TrySendError::Closed(_) => {
                    debug!("Share webhook channel closed");
                }
            }
        }
    }
}

/// Worker task that batches shares and sends them to the webhook endpoint
pub struct ShareWebhookWorker {
    receiver: mpsc::Receiver<ShareData>,
    config: ShareWebhookConfig,
    pool_id: u16,
    batch_seq: AtomicU64,
    client: reqwest::Client,
}

impl ShareWebhookWorker {
    /// Create a new webhook worker and sender pair
    pub fn new(config: ShareWebhookConfig, pool_id: u16) -> (ShareWebhookSender, Self) {
        let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        let worker = ShareWebhookWorker {
            receiver,
            config,
            pool_id,
            batch_seq: AtomicU64::new(0),
            client,
        };

        let sender = ShareWebhookSender { sender };

        (sender, worker)
    }

    /// Run the webhook worker loop
    ///
    /// This task accumulates shares and sends batches when either:
    /// - `batch_size` shares have been accumulated
    /// - `batch_timeout_ms` has elapsed since the first share in the batch
    pub async fn run(
        mut self,
        cancellation_token: bitcoin_core_sv2::template_distribution_protocol::CancellationToken,
    ) {
        info!(
            url = %self.config.url,
            batch_size = self.config.batch_size,
            batch_timeout_ms = self.config.batch_timeout_ms,
            "Share webhook worker started"
        );

        let mut batch: Vec<ShareData> = Vec::with_capacity(self.config.batch_size);
        let batch_timeout = Duration::from_millis(self.config.batch_timeout_ms);

        loop {
            // If we have shares, use a timeout; otherwise wait indefinitely
            let timeout_future = if !batch.is_empty() {
                tokio::time::sleep(batch_timeout)
            } else {
                // Create a future that will never complete (we'll break out via recv or shutdown)
                tokio::time::sleep(Duration::from_secs(86400 * 365)) // ~1 year
            };

            tokio::select! {
                biased;

                // Check for shutdown signal
                _ = cancellation_token.cancelled() => {
                    info!("Share webhook worker shutting down");
                    if !batch.is_empty() {
                        self.send_batch(&mut batch).await;
                    }
                    break;
                }

                // Receive shares from the channel
                share = self.receiver.recv() => {
                    match share {
                        Some(share) => {
                            batch.push(share);

                            // Send batch if we've reached the batch size
                            if batch.len() >= self.config.batch_size {
                                self.send_batch(&mut batch).await;
                            }
                        }
                        None => {
                            // Channel closed
                            info!("Share webhook channel closed");
                            if !batch.is_empty() {
                                self.send_batch(&mut batch).await;
                            }
                            break;
                        }
                    }
                }

                // Timeout - send partial batch
                _ = timeout_future, if !batch.is_empty() => {
                    debug!(shares = batch.len(), "Batch timeout reached, sending partial batch");
                    self.send_batch(&mut batch).await;
                }
            }
        }
    }

    /// Send a batch of shares to the webhook endpoint
    async fn send_batch(&self, batch: &mut Vec<ShareData>) {
        if batch.is_empty() {
            return;
        }

        let batch_seq = self.batch_seq.fetch_add(1, Ordering::Relaxed);
        let share_count = batch.len();

        let payload = ShareBatch {
            pool_id: self.pool_id,
            batch_seq,
            shares: std::mem::take(batch),
        };

        let mut attempts = 0;
        let max_retries = self.config.max_retries;

        loop {
            attempts += 1;

            match self
                .client
                .post(&self.config.url)
                .json(&payload)
                .send()
                .await
            {
                Ok(response) => {
                    if response.status().is_success() {
                        debug!(batch_seq, share_count, "Share batch sent successfully");
                        return;
                    } else {
                        warn!(
                            batch_seq,
                            status = %response.status(),
                            attempt = attempts,
                            "Share batch request failed with status"
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        batch_seq,
                        error = %e,
                        attempt = attempts,
                        "Share batch request failed"
                    );
                }
            }

            if attempts > max_retries {
                error!(
                    batch_seq,
                    share_count, max_retries, "Share batch dropped after max retries"
                );
                return;
            }

            // Exponential backoff: 100ms, 200ms, 400ms, ...
            let backoff = Duration::from_millis(100 * (1 << (attempts - 1)));
            tokio::time::sleep(backoff).await;
        }
    }
}

/// Get current timestamp in milliseconds
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_data_serialization() {
        let share = ShareData {
            timestamp_ms: 1706000000000,
            share_hash: "abc123".to_string(),
            share_work: 1000.5,
            channel_id: 1,
            sequence_number: 42,
            job_id: 100,
            downstream_id: 5,
            is_block: false,
            user_identity: "bc1qtest.worker1".to_string(),
            header: None,
        };

        let json = serde_json::to_string(&share).unwrap();
        println!("Serialized ShareData: {}", json);

        // Verify all fields are present
        assert!(
            json.contains("\"user_identity\":"),
            "user_identity missing from JSON"
        );
        assert!(
            json.contains("\"channel_id\":"),
            "channel_id missing from JSON"
        );
        assert!(json.contains("\"is_block\":"), "is_block missing from JSON");
        assert!(
            json.contains("bc1qtest.worker1"),
            "user_identity value missing"
        );
    }
}
