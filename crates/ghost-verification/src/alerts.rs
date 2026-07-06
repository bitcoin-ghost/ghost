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
use std::time::Duration;
use tracing::{debug, warn};

/// A watched node event. `label`/`title` produce operator-facing copy; the
/// caller supplies a free-form `detail` string at the trigger site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        let short = if node_id.len() > 12 { &node_id[..12] } else { node_id };
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
        Self { channel, attempted: false, success: false, detail: why.to_string() }
    }
    fn ok(channel: &'static str) -> Self {
        Self { channel, attempted: true, success: true, detail: "delivered".to_string() }
    }
    fn fail(channel: &'static str, why: String) -> Self {
        Self { channel, attempted: true, success: false, detail: why }
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
        let results = deliver(&cfg, &AlertMessage::for_event(AlertEvent::BlockFound, "n", "d")).await;
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| !r.attempted));
    }

    #[tokio::test]
    async fn telegram_without_token_is_skipped() {
        let mut cfg = base();
        cfg.channels.telegram = TelegramChannel { enabled: true, bot_token: None, chat_id: Some("1".into()) };
        let results = deliver(&cfg, &AlertMessage::for_event(AlertEvent::BlockFound, "n", "d")).await;
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
}
