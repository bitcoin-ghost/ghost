// Operator alerts — email / push / Telegram notifications for node events.
// Config is persisted to pool.toml `[alerts]` by ghost-pool; these calls route
// through the HMAC-signed proxy like the reaper config.
import { fetchApi } from "./client";

// Which node events fire an alert. Keys mirror the Rust `AlertEvents` fields.
export interface AlertEvents {
  node_offline: boolean;
  capability_drift: boolean;
  low_disk: boolean;
  restart_needed: boolean;
  peer_count_drop: boolean;
  block_found: boolean;
}

export interface EmailChannel {
  enabled: boolean;
  // HTTP webhook that accepts `{to, subject, body}` and sends the mail.
  webhook_url?: string | null;
  to_address?: string | null;
}

export interface PushChannel {
  enabled: boolean;
  // Generic / ntfy-style webhook that receives `{title, message}`.
  webhook_url?: string | null;
}

// The bot token is a secret: the GET API redacts it and returns only
// `bot_token_set`. On save, send `bot_token` ONLY when the operator enters a
// new one — an empty/omitted token preserves the stored credential.
export interface TelegramChannel {
  enabled: boolean;
  chat_id?: string | null;
  bot_token?: string | null;
  bot_token_set?: boolean;
}

export interface AlertChannels {
  email: EmailChannel;
  push: PushChannel;
  telegram: TelegramChannel;
}

export interface AlertsConfig {
  enabled: boolean;
  channels: AlertChannels;
  events: AlertEvents;
}

export interface AlertsResponse extends AlertsConfig {
  message?: string;
}

export interface AlertsSaveResponse extends AlertsConfig {
  success: boolean;
  persisted: boolean;
  message: string;
}

export interface AlertTestChannelResult {
  channel: string;
  attempted: boolean;
  success: boolean;
  detail: string;
}

export interface AlertTestResponse {
  success: boolean;
  attempted: number;
  succeeded: number;
  results: AlertTestChannelResult[];
  message: string;
}

export const ALERTS_DEFAULTS: AlertsConfig = {
  enabled: false,
  channels: {
    email: { enabled: false, webhook_url: "", to_address: "" },
    push: { enabled: false, webhook_url: "" },
    telegram: { enabled: false, chat_id: "", bot_token: "", bot_token_set: false },
  },
  events: {
    node_offline: true,
    capability_drift: true,
    low_disk: true,
    restart_needed: true,
    peer_count_drop: true,
    block_found: true,
  },
};

export async function getAlerts(): Promise<AlertsResponse> {
  return fetchApi<AlertsResponse>("/api/v1/config/alerts");
}

export async function setAlerts(config: AlertsConfig): Promise<AlertsSaveResponse> {
  // Never send the redaction-only helper flag back to the node, and drop an
  // empty bot_token so the backend preserves the stored secret.
  const telegram: TelegramChannel = { ...config.channels.telegram };
  delete telegram.bot_token_set;
  if (!telegram.bot_token) {
    delete telegram.bot_token;
  }
  const payload: AlertsConfig = {
    ...config,
    channels: { ...config.channels, telegram },
  };
  return fetchApi<AlertsSaveResponse>("/api/v1/config/alerts", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function sendTestAlert(): Promise<AlertTestResponse> {
  return fetchApi<AlertTestResponse>("/api/v1/alerts/test", {
    method: "POST",
  });
}
