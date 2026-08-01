//! Share webhook module for sending share notifications to external services.
//!
//! This module provides non-blocking webhook notifications for valid shares,
//! implementing batching for efficiency at high share volumes.

use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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
    /// The full extranonce this share was mined with, as hex.
    ///
    /// The one part of the coinbase the pool cannot infer from the job alone, and therefore the
    /// one part a validator needs in order to rebuild it. Without this the skeleton is a shape
    /// with a hole in it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extranonce: Option<String>,
    /// Content address of the coinbase skeleton this share was mined against, as hex.
    ///
    /// Names the coinbase rather than carrying it: at 200 payees a coinbase is ~29 KB, so shipping
    /// one per share would be ~10 GB a day. The skeleton itself travels once per job (see
    /// [`ShareBatch::skeletons`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skeleton_id: Option<String>,
}

/// A coinbase skeleton, carried once for the job rather than once per share.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SkeletonData {
    /// Content address, matching the `skeleton_id` on the shares that reference it.
    pub skeleton_id: String,
    /// Serialized coinbase up to where the extranonce begins, hex.
    pub coinbase_prefix: String,
    /// Serialized coinbase from where the extranonce ends, hex.
    pub coinbase_suffix: String,
    /// Sibling hashes folding the coinbase txid up to the header merkle root, hex.
    pub merkle_path: Vec<String>,
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
    /// Skeletons first referenced by this batch.
    ///
    /// Sent with the batch rather than on a separate channel so it inherits the retry and
    /// back-pressure the share path already has: a skeleton that arrived by some other route while
    /// the share path was failing would name shares that never turned up.
    ///
    /// Empty on most batches — a job lasts ~30 s and batches flush every ~2 s, so roughly one
    /// batch in fifteen carries one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skeletons: Vec<SkeletonData>,
}

/// How many recently-sent skeleton ids to remember, so a skeleton travels once per job rather than
/// once per share.
///
/// A job lasts ~30 s and several channels may reference the same one, so a few dozen is ample.
/// Bounded rather than unbounded because this lives for the process lifetime; if an id falls out
/// the skeleton is simply re-sent, which costs bytes and never correctness.
const RECENT_SKELETONS: usize = 64;

/// What travels on the webhook channel.
enum WebhookItem {
    Share(Box<ShareData>),
    Skeleton(Box<SkeletonData>),
}

/// Clone-able handle for sending shares to the webhook worker
#[derive(Clone)]
pub struct ShareWebhookSender {
    sender: mpsc::Sender<WebhookItem>,
    /// Ids already sent, so the same skeleton is not repeated for every share of a job.
    recent_skeletons: Arc<Mutex<(HashSet<String>, VecDeque<String>)>>,
}

impl ShareWebhookSender {
    /// Send a coinbase skeleton, unless it has been sent recently.
    ///
    /// Deduplicated here rather than at the call site because every channel referencing a job
    /// would otherwise send the same skeleton, and there is no natural place upstream that knows
    /// what the others have already done.
    ///
    /// Best-effort like shares: a dropped skeleton means the shares naming it cannot be verified
    /// until it is re-sent, which is a gap in evidence rather than a lost share.
    pub fn send_skeleton(&self, skeleton: SkeletonData) {
        {
            let mut seen = match self.recent_skeletons.lock() {
                Ok(g) => g,
                // A poisoned lock means another thread panicked mid-update. Sending anyway is the
                // safe direction: a duplicate skeleton is wasted bytes, a missing one is a share
                // that cannot be proved.
                Err(p) => p.into_inner(),
            };
            if seen.0.contains(&skeleton.skeleton_id) {
                return;
            }
            seen.0.insert(skeleton.skeleton_id.clone());
            seen.1.push_back(skeleton.skeleton_id.clone());
            while seen.1.len() > RECENT_SKELETONS {
                if let Some(evicted) = seen.1.pop_front() {
                    seen.0.remove(&evicted);
                }
            }
        }

        if let Err(e) = self
            .sender
            .try_send(WebhookItem::Skeleton(Box::new(skeleton)))
        {
            match e {
                mpsc::error::TrySendError::Full(_) => {
                    warn!("Share webhook channel full, dropping coinbase skeleton");
                }
                mpsc::error::TrySendError::Closed(_) => {
                    debug!("Share webhook channel closed");
                }
            }
        }
    }
}

impl ShareWebhookSender {
    /// Send a share notification (non-blocking, best effort)
    ///
    /// If the channel is full, the share is dropped and logged.
    /// This ensures mining is never blocked by webhook operations.
    pub fn send(&self, share: ShareData) {
        if let Err(e) = self.sender.try_send(WebhookItem::Share(Box::new(share))) {
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
    receiver: mpsc::Receiver<WebhookItem>,
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

        let sender = ShareWebhookSender {
            sender,
            recent_skeletons: Arc::new(Mutex::new((HashSet::new(), VecDeque::new()))),
        };

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
        // Skeletons wait for the next batch so they never arrive after the shares naming them.
        let mut skeletons: Vec<SkeletonData> = Vec::new();
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
                        self.send_batch(&mut batch, &mut skeletons).await;
                    }
                    break;
                }

                // Receive shares from the channel
                item = self.receiver.recv() => {
                    match item {
                        Some(WebhookItem::Share(share)) => {
                            batch.push(*share);

                            // Send batch if we've reached the batch size
                            if batch.len() >= self.config.batch_size {
                                self.send_batch(&mut batch, &mut skeletons).await;
                            }
                        }
                        // Held back rather than sent immediately, so a skeleton always travels in
                        // the same request as (or ahead of) the shares naming it. Arriving after
                        // them would leave those shares briefly unverifiable for no reason.
                        Some(WebhookItem::Skeleton(skeleton)) => skeletons.push(*skeleton),
                        None => {
                            // Channel closed
                            info!("Share webhook channel closed");
                            if !batch.is_empty() {
                                self.send_batch(&mut batch, &mut skeletons).await;
                            }
                            break;
                        }
                    }
                }

                // Timeout - send partial batch
                _ = timeout_future, if !batch.is_empty() => {
                    debug!(shares = batch.len(), "Batch timeout reached, sending partial batch");
                    self.send_batch(&mut batch, &mut skeletons).await;
                }
            }
        }
    }

    /// Send a batch of shares to the webhook endpoint
    async fn send_batch(&self, batch: &mut Vec<ShareData>, skeletons: &mut Vec<SkeletonData>) {
        if batch.is_empty() {
            return;
        }

        let batch_seq = self.batch_seq.fetch_add(1, Ordering::Relaxed);
        let share_count = batch.len();

        let payload = ShareBatch {
            pool_id: self.pool_id,
            batch_seq,
            shares: std::mem::take(batch),
            skeletons: std::mem::take(skeletons),
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
            extranonce: None,
            skeleton_id: None,
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
