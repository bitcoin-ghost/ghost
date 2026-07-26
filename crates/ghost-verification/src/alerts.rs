//! Operator alert delivery.
//!
//! Turns a node event into a message and delivers it to every channel the
//! operator has enabled in `[alerts]` (pool.toml). Three transports, all plain
//! HTTPS via `reqwest`:
//!
//! * **Telegram** — `POST https://api.telegram.org/bot<token>/sendMessage`
//! * **Push**     — `POST <webhook_url>` with `{title, message}` (ntfy-style)
//! * **Email**    — `POST <webhook_url>` with `{to, subject, body}` to an
//!   operator-supplied mail relay / transactional-email HTTP API.
//!
//! Secrets (the Telegram bot token) are never logged: only channel names and
//! coarse success/failure land in traces.
//!
//! ## Wiring automatic event triggers
//!
//! [`dispatch_event`] is the single entry point the node calls when a watched
//! event fires. It gates on the master switch + the per-event flag, builds the
//! message, and fans out to [`deliver`]. The config + persistence + HTTP
//! endpoints + a real test-send are complete and wired; automatic event
//! triggers are NOT yet wired into the live pipeline — that is deliberately
//! left for a follow-up so this PR stays scoped. To wire an event, hold an
//! `AlertsConfig` (read `VerificationState::full_node_config`) and call
//! `dispatch_event`. The intended trigger sites are:
//!
//! * `NodeOffline`      — health monitor in `ghost-consensus` when a peer/self
//!   crosses the unhealthy threshold.
//! * `CapabilityDrift`  — `ghost-verification` qualification when a capability
//!   regresses qualified→drift.
//! * `LowDisk`          — the resource sampler that already backs the dashboard
//!   resource endpoint.
//! * `RestartNeeded`    — wherever `VerificationState::request_restart` is set.
//! * `PeerCountDrop`    — the mesh peer-count callback in `bins/ghost-pool`.
//! * `BlockFound`       — the `block_found_fn` callback in `bins/ghost-pool`.

use ghost_common::config::AlertsConfig;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// A watched node event. `label`/`title` produce operator-facing copy; the
/// caller supplies a free-form `detail` string at the trigger site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlertEvent {
    /// Node became unreachable / unhealthy.
    NodeOffline,
    /// A verified capability regressed from qualified to drift/failing.
    CapabilityDrift,
    /// Free disk fell below the low-disk threshold.
    LowDisk,
    /// A change or update needs a node restart to apply.
    RestartNeeded,
    /// Connected peer count dropped.
    PeerCountDrop,
    /// This node found a block.
    BlockFound,
    /// A Bitcoin chain reorg was detected (a block disconnected from the tip).
    ReorgDetected,
    /// The node is behind the network tip (stale tip / lagging local height).
    BehindTip,
    /// A newer node release is available than the one installed.
    UpdateAvailable,
    /// The mempool is near its capacity (usage close to `maxmempool`).
    MempoolCongestion,
    /// The fee environment spiked (fee rate crossed a threshold or jumped
    /// sharply versus the recent baseline).
    FeeSpike,
    /// A burst of consecutive failed dashboard login attempts was detected.
    FailedLogin,
    /// A service restarted repeatedly in a short window — a crash loop. Distinct
    /// from `NodeOffline`: the node answers, but something under it keeps dying,
    /// which is exactly the shape the hourly OOM had before it was diagnosed.
    ServiceRestartLoop,
}

impl AlertEvent {
    /// Whether this event is enabled in the operator's `[alerts.events]` set.
    pub fn is_enabled(self, cfg: &AlertsConfig) -> bool {
        let e = &cfg.events;
        match self {
            AlertEvent::NodeOffline => e.node_offline,
            AlertEvent::CapabilityDrift => e.capability_drift,
            AlertEvent::LowDisk => e.low_disk,
            AlertEvent::RestartNeeded => e.restart_needed,
            AlertEvent::PeerCountDrop => e.peer_count_drop,
            AlertEvent::BlockFound => e.block_found,
            AlertEvent::ReorgDetected => e.reorg_detected,
            AlertEvent::BehindTip => e.behind_tip,
            AlertEvent::UpdateAvailable => e.update_available,
            AlertEvent::MempoolCongestion => e.mempool_congestion,
            AlertEvent::FeeSpike => e.fee_spike,
            AlertEvent::FailedLogin => e.failed_login,
            AlertEvent::ServiceRestartLoop => e.service_restart_loop,
        }
    }

    /// Short human title used in the alert subject / push title.
    pub fn title(self) -> &'static str {
        match self {
            AlertEvent::NodeOffline => "Node offline",
            AlertEvent::CapabilityDrift => "Capability drift",
            AlertEvent::LowDisk => "Low disk space",
            AlertEvent::RestartNeeded => "Restart needed",
            AlertEvent::PeerCountDrop => "Peer count dropped",
            AlertEvent::BlockFound => "Block found",
            AlertEvent::ReorgDetected => "Chain reorg detected",
            AlertEvent::BehindTip => "Node behind tip",
            AlertEvent::UpdateAvailable => "Update available",
            AlertEvent::MempoolCongestion => "Mempool congestion",
            AlertEvent::FeeSpike => "Fee spike",
            AlertEvent::FailedLogin => "Failed login attempts",
            AlertEvent::ServiceRestartLoop => "Service restart loop",
        }
    }
}

/// A ready-to-send alert.
#[derive(Debug, Clone)]
pub struct AlertMessage {
    pub title: String,
    pub body: String,
}

impl AlertMessage {
    /// Build a message for an event with an operator-facing detail line.
    pub fn for_event(event: AlertEvent, node_id: &str, detail: &str) -> Self {
        let short = if node_id.len() > 12 {
            &node_id[..12]
        } else {
            node_id
        };
        let title = format!("[Ghost {short}] {}", event.title());
        let body = if detail.is_empty() {
            format!("{} on node {node_id}.", event.title())
        } else {
            format!("{} on node {node_id}.\n\n{detail}", event.title())
        };
        Self { title, body }
    }
}

/// Per-channel delivery outcome. `attempted` is false when the channel is
/// disabled or unconfigured; secrets never appear in `detail`.
#[derive(Debug, Clone, Serialize)]
pub struct ChannelResult {
    pub channel: &'static str,
    pub attempted: bool,
    pub success: bool,
    pub detail: String,
}

impl ChannelResult {
    fn skipped(channel: &'static str, why: &str) -> Self {
        Self {
            channel,
            attempted: false,
            success: false,
            detail: why.to_string(),
        }
    }
    fn ok(channel: &'static str) -> Self {
        Self {
            channel,
            attempted: true,
            success: true,
            detail: "delivered".to_string(),
        }
    }
    fn fail(channel: &'static str, why: String) -> Self {
        Self {
            channel,
            attempted: true,
            success: false,
            detail: why,
        }
    }
}

fn http_client() -> reqwest::Client {
    // A plain client with a bounded timeout; normal CA validation applies to
    // the public HTTPS endpoints (api.telegram.org, operator webhooks). Defend
    // against a missing process-wide rustls provider (idempotent install).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default()
}

/// Deliver a message to every enabled + configured channel. Returns one
/// [`ChannelResult`] per known channel (including skipped ones) so callers /
/// the test-send endpoint can report exactly what happened.
pub async fn deliver(cfg: &AlertsConfig, msg: &AlertMessage) -> Vec<ChannelResult> {
    let client = http_client();
    let mut out = Vec::with_capacity(3);
    out.push(deliver_telegram(&client, cfg, msg).await);
    out.push(deliver_push(&client, cfg, msg).await);
    out.push(deliver_email(&client, cfg, msg).await);
    out
}

/// The node's single entry point when a watched event fires. Gates on the
/// master switch and the per-event flag, then delivers. Returns `None` when
/// the event is suppressed (feature off, or this event disabled).
pub async fn dispatch_event(
    cfg: &AlertsConfig,
    event: AlertEvent,
    node_id: &str,
    detail: &str,
) -> Option<Vec<ChannelResult>> {
    if !cfg.enabled || !event.is_enabled(cfg) {
        return None;
    }
    let msg = AlertMessage::for_event(event, node_id, detail);
    Some(deliver(cfg, &msg).await)
}

/// Debouncing dispatcher that owns the self node id and a live view of the
/// operator's `AlertsConfig`, so trigger sites can fire watched events without
/// re-reading config or open-coding their own anti-spam. One shared instance
/// (`Arc<AlertDispatcher>`) is cloned into every trigger site.
///
/// Three fire modes suit the shapes the trigger sites actually have:
///
/// * [`AlertDispatcher::fire_edge`] — edge-triggered: dispatches only when a
///   condition (keyed by an arbitrary sub-key, e.g. a peer id or capability
///   name) first becomes true, and re-arms when it clears. For level signals
///   that persist across polling ticks (low disk, capability drift, a peer
///   staying offline). Without this, a periodic check re-fires every tick.
/// * [`AlertDispatcher::fire_rate_limited`] — dispatches at most once per
///   `min_interval` per event. For repeating conditions with no natural
///   "cleared" edge (a dropping peer count).
/// * [`AlertDispatcher::fire`] — dispatches unconditionally. For naturally
///   discrete one-shot events (block found, restart requested).
///
/// The config closure is evaluated on every dispatch so live edits to
/// `[alerts]` (via the config API, which mutates `full_node_config`) take
/// effect immediately — no stale startup snapshot.
pub struct AlertDispatcher {
    node_id: String,
    config: Box<dyn Fn() -> AlertsConfig + Send + Sync>,
    /// Currently-active edge conditions, keyed by `(event, sub-key)`.
    edges: parking_lot::Mutex<HashSet<(AlertEvent, String)>>,
    /// Last dispatch instant per event, for rate limiting.
    rate: parking_lot::Mutex<HashMap<AlertEvent, Instant>>,
}

impl AlertDispatcher {
    /// Build a dispatcher for this node. `config` is called on every dispatch
    /// to read the current `[alerts]` config (wire it to the live
    /// `full_node_config` so operator edits apply without a restart).
    pub fn new(node_id: String, config: impl Fn() -> AlertsConfig + Send + Sync + 'static) -> Self {
        Self {
            node_id,
            config: Box::new(config),
            edges: parking_lot::Mutex::new(HashSet::new()),
            rate: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Update the edge state for `(event, key)` and report whether a dispatch
    /// should happen now (i.e. the condition *just* became active). Pure — no
    /// I/O — so the debounce is unit-testable on its own.
    fn arm_edge(&self, event: AlertEvent, key: &str, active: bool) -> bool {
        let mut edges = self.edges.lock();
        if active {
            // `insert` returns true only if it was not already present, i.e.
            // this is the rising edge.
            edges.insert((event, key.to_string()))
        } else {
            edges.remove(&(event, key.to_string()));
            false
        }
    }

    /// Update the rate-limit clock for `event`; report whether `min_interval`
    /// has elapsed since the last dispatch. Pure — no I/O.
    fn arm_rate(&self, event: AlertEvent, min_interval: Duration) -> bool {
        let mut rate = self.rate.lock();
        let now = Instant::now();
        match rate.get(&event) {
            Some(&last) if now.duration_since(last) < min_interval => false,
            _ => {
                rate.insert(event, now);
                true
            }
        }
    }

    /// Edge-triggered dispatch. Fires once when `active` first becomes true for
    /// `(event, key)`, and re-arms when `active` returns to false. Returns
    /// whether an alert was actually delivered.
    pub async fn fire_edge(
        &self,
        event: AlertEvent,
        key: &str,
        active: bool,
        detail: &str,
    ) -> bool {
        if !self.arm_edge(event, key, active) {
            return false;
        }
        dispatch_event(&(self.config)(), event, &self.node_id, detail)
            .await
            .is_some()
    }

    /// Rate-limited dispatch. Fires at most once per `min_interval` per event.
    pub async fn fire_rate_limited(
        &self,
        event: AlertEvent,
        min_interval: Duration,
        detail: &str,
    ) -> bool {
        if !self.arm_rate(event, min_interval) {
            return false;
        }
        dispatch_event(&(self.config)(), event, &self.node_id, detail)
            .await
            .is_some()
    }

    /// Unconditional dispatch for naturally-discrete events.
    pub async fn fire(&self, event: AlertEvent, detail: &str) -> bool {
        dispatch_event(&(self.config)(), event, &self.node_id, detail)
            .await
            .is_some()
    }

    /// Whether the edge condition for `(event, key)` is currently marked active.
    /// Read-only introspection for diagnostics and for tests that assert a
    /// trigger site reached `fire_edge`.
    pub fn is_edge_active(&self, event: AlertEvent, key: &str) -> bool {
        self.edges.lock().contains(&(event, key.to_string()))
    }
}

async fn deliver_telegram(
    client: &reqwest::Client,
    cfg: &AlertsConfig,
    msg: &AlertMessage,
) -> ChannelResult {
    const CH: &str = "telegram";
    let tg = &cfg.channels.telegram;
    if !tg.enabled {
        return ChannelResult::skipped(CH, "channel disabled");
    }
    let token = match tg.bot_token.as_deref().filter(|t| !t.is_empty()) {
        Some(t) => t,
        None => return ChannelResult::skipped(CH, "no bot token configured"),
    };
    let chat_id = match tg.chat_id.as_deref().filter(|c| !c.is_empty()) {
        Some(c) => c,
        None => return ChannelResult::skipped(CH, "no chat id configured"),
    };
    let url = format!("https://api.telegram.org/bot{token}/sendMessage");
    let text = format!("{}\n\n{}", msg.title, msg.body);
    let body = serde_json::json!({ "chat_id": chat_id, "text": text });
    // NB: `url` embeds the secret token — never log it.
    debug!(channel = CH, "sending alert");
    match client.post(&url).json(&body).send().await {
        Ok(resp) if resp.status().is_success() => ChannelResult::ok(CH),
        Ok(resp) => {
            let status = resp.status();
            // Telegram error bodies do not contain the token, but keep the log
            // coarse regardless.
            warn!(channel = CH, %status, "alert delivery failed");
            ChannelResult::fail(CH, format!("telegram API returned {status}"))
        }
        Err(e) => {
            warn!(channel = CH, "alert delivery transport error");
            ChannelResult::fail(CH, format!("request failed: {}", transport_detail(&e)))
        }
    }
}

async fn deliver_push(
    client: &reqwest::Client,
    cfg: &AlertsConfig,
    msg: &AlertMessage,
) -> ChannelResult {
    const CH: &str = "push";
    let push = &cfg.channels.push;
    if !push.enabled {
        return ChannelResult::skipped(CH, "channel disabled");
    }
    let url = match push.webhook_url.as_deref().filter(|u| !u.is_empty()) {
        Some(u) => u,
        None => return ChannelResult::skipped(CH, "no webhook url configured"),
    };
    let body = serde_json::json!({ "title": msg.title, "message": msg.body });
    debug!(channel = CH, "sending alert");
    post_generic(client, CH, url, &body).await
}

async fn deliver_email(
    client: &reqwest::Client,
    cfg: &AlertsConfig,
    msg: &AlertMessage,
) -> ChannelResult {
    const CH: &str = "email";
    let email = &cfg.channels.email;
    if !email.enabled {
        return ChannelResult::skipped(CH, "channel disabled");
    }
    let url = match email.webhook_url.as_deref().filter(|u| !u.is_empty()) {
        Some(u) => u,
        None => return ChannelResult::skipped(CH, "no webhook url configured"),
    };
    let to = match email.to_address.as_deref().filter(|a| !a.is_empty()) {
        Some(a) => a,
        None => return ChannelResult::skipped(CH, "no destination address configured"),
    };
    let body = serde_json::json!({ "to": to, "subject": msg.title, "body": msg.body });
    debug!(channel = CH, "sending alert");
    post_generic(client, CH, url, &body).await
}

async fn post_generic(
    client: &reqwest::Client,
    channel: &'static str,
    url: &str,
    body: &serde_json::Value,
) -> ChannelResult {
    match client.post(url).json(body).send().await {
        Ok(resp) if resp.status().is_success() => ChannelResult::ok(channel),
        Ok(resp) => {
            let status = resp.status();
            warn!(channel, %status, "alert delivery failed");
            ChannelResult::fail(channel, format!("webhook returned {status}"))
        }
        Err(e) => {
            warn!(channel, "alert delivery transport error");
            ChannelResult::fail(channel, format!("request failed: {}", transport_detail(&e)))
        }
    }
}

/// Reqwest error text can echo the request URL (which, for Telegram, embeds the
/// bot token). Strip it to a coarse cause so a secret can't leak into an API
/// response or log.
fn transport_detail(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "timed out"
    } else if e.is_connect() {
        "connection failed"
    } else if e.is_request() {
        "invalid request"
    } else {
        "network error"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::config::{AlertChannels, AlertEvents, TelegramChannel};

    fn base() -> AlertsConfig {
        AlertsConfig {
            enabled: true,
            channels: AlertChannels::default(),
            events: AlertEvents::default(),
        }
    }

    #[tokio::test]
    async fn dispatch_suppressed_when_master_off() {
        let mut cfg = base();
        cfg.enabled = false;
        let r = dispatch_event(&cfg, AlertEvent::BlockFound, "node", "").await;
        assert!(r.is_none());
    }

    #[tokio::test]
    async fn dispatch_suppressed_when_event_off() {
        let mut cfg = base();
        cfg.events.block_found = false;
        let r = dispatch_event(&cfg, AlertEvent::BlockFound, "node", "").await;
        assert!(r.is_none());
    }

    #[tokio::test]
    async fn disabled_channels_are_skipped_not_attempted() {
        let cfg = base(); // all channels default-disabled
        let results = deliver(
            &cfg,
            &AlertMessage::for_event(AlertEvent::BlockFound, "n", "d"),
        )
        .await;
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| !r.attempted));
    }

    #[tokio::test]
    async fn telegram_without_token_is_skipped() {
        let mut cfg = base();
        cfg.channels.telegram = TelegramChannel {
            enabled: true,
            bot_token: None,
            chat_id: Some("1".into()),
        };
        let results = deliver(
            &cfg,
            &AlertMessage::for_event(AlertEvent::BlockFound, "n", "d"),
        )
        .await;
        let tg = results.iter().find(|r| r.channel == "telegram").unwrap();
        assert!(!tg.attempted);
        assert!(tg.detail.contains("token"));
    }

    #[test]
    fn message_never_empty_body() {
        let m = AlertMessage::for_event(AlertEvent::LowDisk, "abcdef0123456789", "");
        assert!(m.title.contains("Low disk"));
        assert!(!m.body.is_empty());
    }

    /// A config that is on and enables one event, with all channels disabled —
    /// so `dispatch_event` returns `Some` (it fired) but no network I/O happens
    /// (every channel is skipped). Lets us assert the trigger→dispatch wiring
    /// deterministically without HTTP.
    fn enabled_for(pick: impl Fn(&mut AlertEvents)) -> impl Fn() -> AlertsConfig {
        move || {
            let mut c = base();
            // Start from all-off so the test only exercises the event we pick.
            let mut events = AlertEvents {
                node_offline: false,
                capability_drift: false,
                low_disk: false,
                restart_needed: false,
                peer_count_drop: false,
                block_found: false,
                reorg_detected: false,
                behind_tip: false,
                update_available: false,
                mempool_congestion: false,
                fee_spike: false,
                failed_login: false,
                service_restart_loop: false,
            };
            pick(&mut events);
            c.events = events;
            c
        }
    }

    #[tokio::test]
    async fn edge_fires_once_then_suppresses_until_rearmed() {
        let d = AlertDispatcher::new("node".into(), enabled_for(|e| e.low_disk = true));
        // Rising edge -> dispatched.
        assert!(d.fire_edge(AlertEvent::LowDisk, "/", true, "d").await);
        // Still active -> suppressed (no spam).
        assert!(!d.fire_edge(AlertEvent::LowDisk, "/", true, "d").await);
        // Condition clears -> no dispatch, re-arms.
        assert!(!d.fire_edge(AlertEvent::LowDisk, "/", false, "d").await);
        // Rising edge again -> dispatched.
        assert!(d.fire_edge(AlertEvent::LowDisk, "/", true, "d").await);
    }

    #[tokio::test]
    async fn edge_keys_are_independent() {
        let d = AlertDispatcher::new("node".into(), enabled_for(|e| e.node_offline = true));
        // Two different peers offline -> two independent alerts.
        assert!(
            d.fire_edge(AlertEvent::NodeOffline, "peerA", true, "d")
                .await
        );
        assert!(
            d.fire_edge(AlertEvent::NodeOffline, "peerB", true, "d")
                .await
        );
        // Re-reporting peerA -> suppressed.
        assert!(
            !d.fire_edge(AlertEvent::NodeOffline, "peerA", true, "d")
                .await
        );
    }

    #[tokio::test]
    async fn edge_respects_master_and_event_flags() {
        // Master off -> never dispatches even on a rising edge.
        let d = AlertDispatcher::new("node".into(), || {
            let mut c = base();
            c.enabled = false;
            c
        });
        assert!(!d.fire_edge(AlertEvent::LowDisk, "/", true, "d").await);

        // Master on but this event disabled -> no dispatch.
        let d = AlertDispatcher::new("node".into(), enabled_for(|e| e.block_found = true));
        assert!(!d.fire_edge(AlertEvent::LowDisk, "/", true, "d").await);
    }

    #[tokio::test]
    async fn rate_limit_suppresses_within_window() {
        let d = AlertDispatcher::new("node".into(), enabled_for(|e| e.peer_count_drop = true));
        assert!(
            d.fire_rate_limited(AlertEvent::PeerCountDrop, Duration::from_secs(60), "d")
                .await
        );
        // Second call inside the window -> suppressed.
        assert!(
            !d.fire_rate_limited(AlertEvent::PeerCountDrop, Duration::from_secs(60), "d")
                .await
        );
        // A zero window always allows.
        assert!(
            d.fire_rate_limited(AlertEvent::PeerCountDrop, Duration::from_secs(0), "d")
                .await
        );
    }

    #[tokio::test]
    async fn fire_unconditional_dispatches_each_call() {
        let d = AlertDispatcher::new("node".into(), enabled_for(|e| e.block_found = true));
        assert!(d.fire(AlertEvent::BlockFound, "block 1").await);
        assert!(d.fire(AlertEvent::BlockFound, "block 2").await);
    }

    #[tokio::test]
    async fn mempool_congestion_respects_enable_flag() {
        // Enabled → edge dispatches on the rising edge.
        let d = AlertDispatcher::new("node".into(), enabled_for(|e| e.mempool_congestion = true));
        assert!(
            d.fire_edge(AlertEvent::MempoolCongestion, "mempool", true, "90% full")
                .await
        );
        // A different event enabled, congestion disabled → no dispatch.
        let d = AlertDispatcher::new("node".into(), enabled_for(|e| e.fee_spike = true));
        assert!(
            !d.fire_edge(AlertEvent::MempoolCongestion, "mempool", true, "90% full")
                .await
        );
    }

    #[tokio::test]
    async fn fee_spike_respects_enable_flag() {
        let d = AlertDispatcher::new("node".into(), enabled_for(|e| e.fee_spike = true));
        assert!(
            d.fire_rate_limited(AlertEvent::FeeSpike, Duration::from_secs(60), "120 sat/vB")
                .await
        );
        let d = AlertDispatcher::new("node".into(), enabled_for(|e| e.block_found = true));
        assert!(
            !d.fire_rate_limited(AlertEvent::FeeSpike, Duration::from_secs(60), "120 sat/vB")
                .await
        );
    }

    #[tokio::test]
    async fn failed_login_respects_enable_flag() {
        let d = AlertDispatcher::new("node".into(), enabled_for(|e| e.failed_login = true));
        assert!(
            d.fire_rate_limited(
                AlertEvent::FailedLogin,
                Duration::from_secs(60),
                "5 attempts"
            )
            .await
        );
        let d = AlertDispatcher::new("node".into(), enabled_for(|e| e.node_offline = true));
        assert!(
            !d.fire_rate_limited(
                AlertEvent::FailedLogin,
                Duration::from_secs(60),
                "5 attempts"
            )
            .await
        );
    }

    #[test]
    fn new_event_titles_are_set() {
        assert_eq!(AlertEvent::MempoolCongestion.title(), "Mempool congestion");
        assert_eq!(AlertEvent::FeeSpike.title(), "Fee spike");
        assert_eq!(AlertEvent::FailedLogin.title(), "Failed login attempts");
    }
}
