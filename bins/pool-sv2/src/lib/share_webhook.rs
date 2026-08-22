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

use ghost_common::internal_auth::{now_secs, InternalAuthKey};

use crate::config::ShareWebhookConfig;
use crate::error::PoolErrorKind;

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
    /// The power-of-two difficulty tier (`log2`) this share's job COMMITTED to in its coinbase
    /// (SHARE_TIER_BIND). Populated from the job's build-time label
    /// (`StandardChannel/ExtendedChannel::job_tier_log2`) whenever per-tier jobs are active —
    /// i.e. `[share_tier_binding]` is configured AND the template height is at/above the
    /// activation height. `None` below the gate (the only shipped state), and
    /// `skip_serializing_if` keeps those payloads byte-identical to the pre-tier wire format.
    /// When `Some`, `share_work` is exactly `2^tier_log2` — ghost-pool's verifier enforces that
    /// equality at/above its gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier_log2: Option<u32>,
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
    /// The validated share-webhook secret (H-13).
    ///
    /// Not an `Option`: a secret that will not parse is refused by [`ShareWebhookWorker::new`],
    /// which propagates to `PoolSv2::start` and stops the process. An earlier version of this
    /// only logged and carried on with `None`, which produced the worst outcome available — the
    /// pool started, miners connected, SV2 acknowledged every share, and `send_batch` discarded
    /// 100% of the work before it ever reached the HTTP call, leaving one line at boot as the
    /// only evidence. A config fault must not be survivable by the process that has the config.
    secret: InternalAuthKey,
    /// Consecutive batches rejected for a bad signature, so the log says whether the loss is
    /// ongoing rather than something that happened once at boot.
    auth_failures: AtomicU64,
    pool_id: u16,
    batch_seq: AtomicU64,
    client: reqwest::Client,
    /// The sender's "already sent" memory, shared so a failed delivery can be un-remembered.
    ///
    /// Without this the dedup is a one-way door: a skeleton marked sent and then lost in a failed
    /// POST is never offered again, and every share of that job names a skeleton the other side
    /// will never hold. Nothing would repair it, because nothing would know.
    recent_skeletons: Arc<Mutex<(HashSet<String>, VecDeque<String>)>>,
}

impl ShareWebhookWorker {
    /// Create a new webhook worker and sender pair.
    ///
    /// # Errors
    ///
    /// Fails when `share_webhook.secret` is not a usable internal-API secret. This is deliberately
    /// fatal to startup: an unsigned or wrongly-signed batch is rejected by ghost-pool, so a pool
    /// that starts without a valid secret cannot report a single share. Failing here costs a
    /// restart; failing later costs every share mined until somebody notices.
    ///
    /// The rule applied is `InternalAuthKey`'s, which is the same code ghost-pool verifies with —
    /// so "this secret is acceptable" cannot mean two different things on the two ends of the
    /// socket.
    pub fn new(
        config: ShareWebhookConfig,
        pool_id: u16,
    ) -> Result<(ShareWebhookSender, Self), PoolErrorKind> {
        let secret = InternalAuthKey::from_hex(&config.secret).map_err(|e| {
            PoolErrorKind::ShareWebhookConfig(format!(
                "share_webhook.secret is unusable ({e}). It must be the co-located ghost-pool's \
                 [network] internal_api_secret — at least 32 bytes of hex, generated with \
                 `openssl rand -hex 32`. Without it every share batch is rejected."
            ))
        })?;

        let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        let recent_skeletons = Arc::new(Mutex::new((HashSet::new(), VecDeque::new())));

        let worker = ShareWebhookWorker {
            receiver,
            config,
            secret,
            pool_id,
            batch_seq: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
            client,
            recent_skeletons: Arc::clone(&recent_skeletons),
        };

        let sender = ShareWebhookSender {
            sender,
            recent_skeletons,
        };

        Ok((sender, worker))
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

    /// Un-remember skeletons whose delivery failed, so the next share re-announces them.
    ///
    /// This is what makes the gap self-healing instead of permanent. `announce` runs for **every**
    /// share, and is suppressed only by the dedup memory — so clearing an id is enough: the very
    /// next share of that job offers the skeleton again, with no retry queue and nothing to track.
    fn forget_skeletons(&self, skeletons: &[SkeletonData]) {
        if skeletons.is_empty() {
            return;
        }
        let mut seen = match self.recent_skeletons.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        for s in skeletons {
            seen.0.remove(&s.skeleton_id);
            seen.1.retain(|id| id != &s.skeleton_id);
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

        // Serialise ONCE and send those exact bytes. The HMAC covers the body, so re-serialising
        // per attempt (or letting `reqwest::json` serialise separately from what we signed) would
        // risk signing bytes other than the ones sent — serde_json is stable here, but "the two
        // will surely agree" is precisely the assumption that produces an unreproducible signature
        // failure at 3am.
        let body = match serde_json::to_vec(&payload) {
            Ok(b) => b,
            Err(e) => {
                error!(batch_seq, error = %e, "Share batch could not be serialised; dropped");
                self.forget_skeletons(&payload.skeletons);
                return;
            }
        };

        let mut attempts = 0;
        let max_retries = self.config.max_retries;

        loop {
            attempts += 1;

            // Signed per attempt, not once: the timestamp is inside the MAC and ghost-pool only
            // accepts a 30-second window, so a batch that backs off past that window would fail
            // authentication for ever if it carried the original stamp.
            let timestamp = now_secs();
            let signature = self.secret.sign(timestamp, &body);

            match self
                .client
                .post(&self.config.url)
                .header("Content-Type", "application/json")
                .header("X-Ghost-Timestamp", timestamp.to_string())
                .header("X-Ghost-Signature", signature)
                .body(body.clone())
                .send()
                .await
            {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        // Reset so the counter reads "consecutive", not "ever" — an operator
                        // needs to know whether the loss is still happening.
                        self.auth_failures.store(0, Ordering::Relaxed);
                        debug!(batch_seq, share_count, "Share batch sent successfully");
                        return;
                    }

                    // An authentication failure is PERMANENT, and must not be drained through a
                    // retry budget sized for a refused connection. Retrying cannot help — the
                    // secret, the clock or the deploy order is wrong — so three attempts and
                    // ~700 ms later the batch would simply be destroyed, and the operator would
                    // see a "failed after max retries" line indistinguishable from ghost-pool
                    // being briefly down. Before H-13 this endpoint could not fail auth at all,
                    // so this is a loss channel the signing requirement introduced; it deserves
                    // its own unmistakable message rather than the generic one.
                    //
                    // Whole-fleet triggers: pool_sv2 restarted with a secret ghost-pool does not
                    // share, a rotation applied to one side only, or clock drift past the 30 s
                    // window. Every one of them discards 100% of shares until it is fixed.
                    if is_auth_failure(status) {
                        error!(
                            batch_seq,
                            share_count,
                            status = %status,
                            consecutive = self.auth_failures.fetch_add(1, Ordering::Relaxed) + 1,
                            "SHARE LOSS: ghost-pool REJECTED this batch's signature. Every share \
                             is being discarded. Check that share_webhook.secret matches \
                             ghost-pool's [network] internal_api_secret and that both clocks are \
                             NTP-synchronised, then restart. Not retried — retrying cannot fix a \
                             credential."
                        );
                        self.forget_skeletons(&payload.skeletons);
                        return;
                    }

                    warn!(
                        batch_seq,
                        status = %status,
                        attempt = attempts,
                        "Share batch request failed with status"
                    );
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
                    share_count,
                    skeletons = payload.skeletons.len(),
                    max_retries,
                    "Share batch dropped after max retries"
                );
                // The shares are gone, but the skeletons must not be treated as delivered: the
                // shares that come next still name them. Forgetting them here is what lets the
                // next share re-announce, and is the difference between a gap that closes in one
                // batch and one that lasts the rest of the job.
                self.forget_skeletons(&payload.skeletons);
                return;
            }

            // Exponential backoff: 100ms, 200ms, 400ms, ...
            let backoff = Duration::from_millis(100 * (1 << (attempts - 1)));
            tokio::time::sleep(backoff).await;
        }
    }
}

/// Is this status a refusal of our credentials rather than a transport or server problem?
///
/// Only 401 and 403 — the two ghost-pool's share-ingest middleware returns for a bad signature
/// and for an off-box peer. A 5xx is the server having a bad day and IS worth retrying; treating
/// it as permanent would throw away shares over a restart.
fn is_auth_failure(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN
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

    fn a_secret() -> String {
        hex::encode((0u8..32).map(|i| i.wrapping_add(0x42)).collect::<Vec<u8>>())
    }

    fn a_pair() -> (ShareWebhookSender, ShareWebhookWorker) {
        a_worker_with_secret(&a_secret()).expect("a valid secret must build a worker")
    }

    fn a_worker_with_secret(
        secret: &str,
    ) -> Result<(ShareWebhookSender, ShareWebhookWorker), PoolErrorKind> {
        ShareWebhookWorker::new(
            crate::config::ShareWebhookConfig {
                // Port 0 never accepts, so every send fails — which is the case under test.
                url: "http://127.0.0.1:1/never".to_string(),
                secret: secret.to_string(),
                batch_size: 1,
                batch_timeout_ms: 1000,
                max_retries: 0,
            },
            1,
        )
    }

    fn a_skeleton(id: &str) -> SkeletonData {
        SkeletonData {
            skeleton_id: id.to_string(),
            coinbase_prefix: "00".to_string(),
            coinbase_suffix: "01".to_string(),
            merkle_path: vec![],
        }
    }

    /// A skeleton travels once per job, not once per share — otherwise ~29 KB rides along with
    /// every share and the whole point of content-addressing is lost.
    #[test]
    fn a_skeleton_is_offered_only_once_while_delivery_is_working() {
        let (sender, mut worker) = a_pair();
        sender.send_skeleton(a_skeleton("aa"));
        sender.send_skeleton(a_skeleton("aa"));
        sender.send_skeleton(a_skeleton("bb"));

        let mut ids = Vec::new();
        while let Ok(item) = worker.receiver.try_recv() {
            if let WebhookItem::Skeleton(s) = item {
                ids.push(s.skeleton_id);
            }
        }
        assert_eq!(ids, vec!["aa".to_string(), "bb".to_string()]);
    }

    /// H-13, the two halves of the share-webhook signature meeting.
    ///
    /// The emitter here and the verifier in ghost-pool have to agree on bytes that appear
    /// nowhere on the wire: the timestamp is hashed as LITTLE-ENDIAN u64, and hashed BEFORE the
    /// body. Nothing in either function signature says so, and getting it wrong produces a pool
    /// that mines happily while every batch is rejected `401` — silent, and paid for in miners'
    /// work. That is the exact shape of the outage this endpoint already caused once.
    ///
    /// Both ends now call `InternalAuthKey`, so this drives the REAL verifier. A test that
    /// recomputed the MAC would agree with a wrong implementation just as readily.
    #[test]
    fn a_signed_batch_verifies_against_the_pool_side_verifier() {
        let key = InternalAuthKey::from_hex(&a_secret()).unwrap();
        let body = br#"{"pool_id":1,"batch_seq":1,"shares":[]}"#;
        let ts = now_secs();

        let signature = key.sign(ts, body);
        assert!(
            key.verify(&signature, ts, body).is_ok(),
            "ghost-pool must accept the signature this emitter produces"
        );

        // Negative controls, so the assertion above cannot be passing for a trivial reason.
        assert!(
            key.verify(&signature, ts, b"tampered body").is_err(),
            "the signature must cover the body"
        );
        let mut other = (0u8..32).map(|i| i.wrapping_add(0x42)).collect::<Vec<u8>>();
        other[0] ^= 0xff;
        let other = InternalAuthKey::new(&other).unwrap();
        assert!(
            key.verify(&other.sign(ts, body), ts, body).is_err(),
            "a different secret must not verify"
        );
    }

    /// An unusable secret must STOP THE PROCESS, not log and carry on.
    ///
    /// Carrying on is the worst outcome available: the pool starts, miners connect, SV2
    /// acknowledges every share, and `send_batch` discards 100% of the work before the HTTP call
    /// — with one line at boot as the only evidence. The failure has to reach `PoolSv2::start`.
    #[test]
    fn an_unusable_secret_refuses_to_build_the_worker() {
        // Positive control first: a good secret must still build, or every case below is
        // passing for the wrong reason.
        assert!(a_worker_with_secret(&a_secret()).is_ok());

        for (secret, why) in [
            ("", "empty"),
            ("0011", "too short"),
            (&"zz".repeat(32), "not hex"),
            (&hex::encode([7u8; 32]), "no entropy — one repeated byte"),
        ] {
            assert!(
                matches!(
                    a_worker_with_secret(secret),
                    Err(PoolErrorKind::ShareWebhookConfig(_))
                ),
                "a {why} secret must refuse to build the worker"
            );
        }
    }

    /// The emitter must accept exactly what the verifier accepts.
    ///
    /// `InternalAuthKey` takes a secret of 32 bytes OR LONGER and uses the first 32. An emitter
    /// that demanded exactly 32 would leave an operator with a 96-hex secret running a ghost-pool
    /// that authenticates and a pool_sv2 that refuses to start — a disagreement about the same
    /// config value, on two ends of a loopback socket.
    #[test]
    fn a_longer_secret_is_accepted_because_the_verifier_accepts_it() {
        let long = hex::encode((0u8..96).map(|i| i.wrapping_add(0x42)).collect::<Vec<u8>>());
        assert!(
            a_worker_with_secret(&long).is_ok(),
            "a 96-byte secret must build here, because ghost-pool accepts it"
        );
    }

    /// Every `[share_webhook]` section shipped in this repo must still load.
    ///
    /// `secret` is mandatory with no `serde` default, so adding it to the code silently invalidated
    /// every config that did not have it — and one of them, `pool-sv2.toml.example`, is the file
    /// the regtest README tells people to copy. The README was updated to explain the new key and
    /// the file it points at was not, which no amount of care at review time reliably catches.
    ///
    /// Discovered by walking rather than by a hardcoded list, so a config added later is covered
    /// without anyone remembering to add it here. Deserialised with the REAL loader the binary
    /// uses, so this fails for any future mandatory field too, not just this one.
    #[test]
    fn every_shipped_share_webhook_config_still_loads() {
        use ext_config::{Config, File, FileFormat};

        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name();
                // `target` is build output and `.git` is enormous; neither ships configs.
                if name == "target" || name == ".git" || name == "node_modules" {
                    continue;
                }
                if path.is_dir() {
                    walk(&path, out);
                } else if std::fs::read_to_string(&path)
                    .is_ok_and(|c| c.contains("[share_webhook]"))
                {
                    out.push(path);
                }
            }
        }

        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("bins/pool-sv2 must sit two levels below the repo root")
            .to_path_buf();

        let mut configs = Vec::new();
        walk(&repo_root, &mut configs);
        configs.retain(|p| {
            p.extension().is_some_and(|e| e == "toml" || e == "example")
                || p.to_string_lossy().ends_with(".toml.example")
        });

        // Positive control: if the walk finds nothing, every assertion below is vacuous and this
        // test would keep passing while the configs rotted.
        assert!(
            configs.len() >= 3,
            "expected to find the shipped share_webhook configs, found {:?}",
            configs
        );

        for path in configs {
            let loaded: ShareWebhookConfig = Config::builder()
                .add_source(File::new(
                    path.to_str().expect("config path must be UTF-8"),
                    FileFormat::Toml,
                ))
                .build()
                .and_then(|settings| settings.get::<ShareWebhookConfig>("share_webhook"))
                .unwrap_or_else(|e| panic!("{} does not load: {e}", path.display()));

            // A file carrying a literal secret must carry a USABLE one. Deployment templates
            // (`${INTERNAL_API_SECRET}`) are filled in by the installer, so only their presence
            // can be checked here.
            if !loaded.secret.contains("${") {
                assert!(
                    InternalAuthKey::from_hex(&loaded.secret).is_ok(),
                    "{} carries a literal secret that pool_sv2 would refuse at startup",
                    path.display()
                );
            }
        }
    }

    /// A `401` is a permanent credential failure, not a transient one, and must not be drained
    /// through the retry budget.
    ///
    /// Retrying cannot fix a wrong secret, a one-sided rotation, or a clock past the 30 s window
    /// — it just spends ~700 ms and then destroys the batch with a message indistinguishable
    /// from "ghost-pool was briefly down". Before H-13 this endpoint could not fail auth at all,
    /// so this is a loss channel the signing requirement introduced.
    ///
    /// Asserts the OUTCOME — how many times the batch is actually put on the wire — rather than
    /// the predicate, because a correct `is_auth_failure` wired into nothing would still pass.
    #[tokio::test]
    async fn an_auth_failure_is_not_retried_but_a_server_error_is() {
        use std::sync::atomic::AtomicUsize;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        /// Accept connections, reply with `status`, and count how many arrived.
        async fn serve(status: &'static str) -> (String, Arc<AtomicUsize>) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/shares", listener.local_addr().unwrap());
            let hits = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&hits);
            tokio::spawn(async move {
                loop {
                    let Ok((mut socket, _)) = listener.accept().await else {
                        return;
                    };
                    counter.fetch_add(1, Ordering::SeqCst);
                    let mut buf = [0u8; 4096];
                    let _ = socket.read(&mut buf).await;
                    let _ = socket
                        .write_all(
                            format!(
                                "HTTP/1.1 {status}
Content-Length: 0
Connection: close

"
                            )
                            .as_bytes(),
                        )
                        .await;
                    let _ = socket.shutdown().await;
                }
            });
            (url, hits)
        }

        async fn deliveries_attempted(status: &'static str, max_retries: u32) -> usize {
            let (url, hits) = serve(status).await;
            let (_sender, worker) = ShareWebhookWorker::new(
                crate::config::ShareWebhookConfig {
                    url,
                    secret: a_secret(),
                    batch_size: 1,
                    batch_timeout_ms: 1000,
                    max_retries,
                },
                1,
            )
            .unwrap();
            let mut batch = vec![ShareData {
                timestamp_ms: 0,
                share_hash: "aa".to_string(),
                share_work: 1.0,
                channel_id: 1,
                sequence_number: 1,
                job_id: 1,
                downstream_id: 1,
                is_block: false,
                user_identity: "bc1q.w".to_string(),
                header: None,
                extranonce: None,
                skeleton_id: None,
                tier_log2: None,
            }];
            worker.send_batch(&mut batch, &mut Vec::new()).await;
            hits.load(Ordering::SeqCst)
        }

        // Positive control: a 500 IS transient, so the retry budget must still be spent — 1
        // attempt plus 2 retries. Without this, a `send_batch` that gave up on everything would
        // pass the assertion below.
        assert_eq!(
            deliveries_attempted("500 Internal Server Error", 2).await,
            3,
            "a server error must still consume the retry budget"
        );

        // The fix: one attempt, then stop. Same budget, permanent failure.
        assert_eq!(
            deliveries_attempted("401 Unauthorized", 2).await,
            1,
            "an auth failure must not be retried"
        );
        assert_eq!(
            deliveries_attempted("403 Forbidden", 2).await,
            1,
            "an off-box rejection must not be retried either"
        );
    }

    /// **The self-healing property.**
    ///
    /// A skeleton marked delivered and then lost in a failed POST would never be offered again,
    /// and every subsequent share of that job would name a skeleton the other side will never
    /// hold — permanently, with nothing able to notice. Forgetting it on failure means the very
    /// next share re-announces it, because `announce` runs per share and is suppressed only by
    /// this memory.
    #[tokio::test]
    async fn a_failed_delivery_lets_the_next_share_re_announce() {
        let (sender, worker) = a_pair();

        sender.send_skeleton(a_skeleton("aa"));
        // Suppressed: as far as the sender knows, "aa" is on its way.
        sender.send_skeleton(a_skeleton("aa"));

        // Delivery fails and the batch is dropped.
        let mut batch = vec![ShareData {
            timestamp_ms: 0,
            share_hash: "h".to_string(),
            share_work: 1.0,
            channel_id: 1,
            sequence_number: 1,
            job_id: 1,
            downstream_id: 1,
            is_block: false,
            user_identity: "u".to_string(),
            header: None,
            extranonce: None,
            skeleton_id: Some("aa".to_string()),
            tier_log2: None,
        }];
        let mut skeletons = vec![a_skeleton("aa")];
        worker.send_batch(&mut batch, &mut skeletons).await;

        // The next share offers it again, rather than referencing something nobody holds.
        sender.send_skeleton(a_skeleton("aa"));
        let mut reannounced = false;
        let mut rx = worker.receiver;
        while let Ok(item) = rx.try_recv() {
            if let WebhookItem::Skeleton(s) = item {
                if s.skeleton_id == "aa" {
                    reannounced = true;
                }
            }
        }
        assert!(
            reannounced,
            "a skeleton lost in a failed delivery must be offered again, or the gap is permanent"
        );
    }

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
            tier_log2: None,
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
