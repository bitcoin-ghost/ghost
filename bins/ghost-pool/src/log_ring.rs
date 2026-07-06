//! A `tracing` layer that mirrors every emitted event into ghost-verification's
//! in-process log ring buffer (`ghost_verification::log_buffer`), which backs the
//! dashboard `GET /api/v1/logs` endpoint.
//!
//! Installing this alongside the console `fmt` layer means the dashboard shows
//! ghost-pool's own structured log tail (real message + target + level per line)
//! without shelling out to `journalctl`.

use std::time::{SystemTime, UNIX_EPOCH};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

/// Layer that captures each event's level, target, message and structured
/// fields into the shared ring buffer.
pub struct LogRingLayer;

impl<S: Subscriber> Layer<S> for LogRingLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let level = match *meta.level() {
            Level::ERROR => "error",
            Level::WARN => "warn",
            Level::INFO => "info",
            Level::DEBUG => "debug",
            Level::TRACE => "trace",
        };

        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        ghost_verification::log_buffer::push(
            timestamp_ms,
            level,
            meta.target().to_string(),
            visitor.into_message(),
        );
    }
}

/// Collects the event's `message` field plus any structured key/value fields
/// into a single human-readable string (`message key1=v1 key2=v2`).
#[derive(Default)]
struct FieldVisitor {
    message: String,
    fields: String,
}

impl FieldVisitor {
    fn append_field(&mut self, name: &str, value: String) {
        if !self.fields.is_empty() {
            self.fields.push(' ');
        }
        self.fields.push_str(name);
        self.fields.push('=');
        self.fields.push_str(&value);
    }

    fn into_message(self) -> String {
        match (self.message.is_empty(), self.fields.is_empty()) {
            (false, false) => format!("{} {}", self.message, self.fields),
            (false, true) => self.message,
            (true, false) => self.fields,
            (true, true) => String::new(),
        }
    }
}

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let rendered = format!("{value:?}");
        if field.name() == "message" {
            self.message = rendered;
        } else {
            self.append_field(field.name(), rendered);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.append_field(field.name(), value.to_string());
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.append_field(field.name(), value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.append_field(field.name(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.append_field(field.name(), value.to_string());
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.append_field(field.name(), value.to_string());
    }
}
