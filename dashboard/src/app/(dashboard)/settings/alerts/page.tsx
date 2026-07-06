"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { Toggle } from "@/components/ui/Toggle";
import { useToast } from "@/components/ui/Toast";
import {
  useAlertsConfig,
  useSetAlerts,
  useSendTestAlert,
} from "@/hooks/queries/useAlertsQueries";
import {
  ALERTS_DEFAULTS,
  type AlertsConfig,
  type AlertsResponse,
  type AlertEvents,
  type AlertTestResponse,
} from "@/lib/api/alerts";
import { SettingsSection, ToggleRow } from "../shared";

// Human labels + descriptions for each watched event.
const EVENT_META: { key: keyof AlertEvents; label: string; description: string }[] = [
  { key: "node_offline", label: "Node offline / unhealthy", description: "The node stopped responding or failed its health checks." },
  { key: "capability_drift", label: "Capability drift", description: "A verified capability regressed from qualified to failing." },
  { key: "low_disk", label: "Low disk space", description: "Free disk fell below the safe threshold." },
  { key: "restart_needed", label: "Restart needed", description: "A change or update needs a node restart to apply." },
  { key: "peer_count_drop", label: "Peer count drop", description: "Connected mesh peers were lost (possible partition)." },
  { key: "block_found", label: "Block found", description: "This node found a block." },
  { key: "reorg_detected", label: "Chain reorg detected", description: "A Bitcoin block was disconnected from the tip (chain reorganisation)." },
  { key: "behind_tip", label: "Node behind tip", description: "The node fell behind the network — a stale tip or a lagging local height." },
  { key: "update_available", label: "Update available", description: "A newer node release is available than the one installed." },
];

export default function AlertsSettingsPage() {
  const { data, isLoading } = useAlertsConfig();
  const setAlerts = useSetAlerts();
  const sendTest = useSendTestAlert();
  const { success, error } = useToast();

  // Local form state. The Telegram bot token is never returned by the API
  // (redacted), so it starts blank; `tokenSaved` tells the operator one is on
  // file so they know they can leave the field empty.
  const [form, setForm] = useState<AlertsConfig>(ALERTS_DEFAULTS);
  const [tokenSaved, setTokenSaved] = useState(false);
  const [testResult, setTestResult] = useState<AlertTestResponse | null>(null);

  // Hydrate the form from server data once per distinct response (React's
  // "adjust state while rendering" pattern — guarded by the previous response
  // so it runs only when a new one arrives, never in a loop). The redacted bot
  // token is never populated; `tokenSaved` records whether one is stored.
  const [hydratedFrom, setHydratedFrom] = useState<AlertsResponse | null>(null);
  if (data && hydratedFrom !== data) {
    setHydratedFrom(data);
    setForm({
      enabled: data.enabled,
      channels: {
        email: {
          enabled: data.channels.email.enabled,
          webhook_url: data.channels.email.webhook_url ?? "",
          to_address: data.channels.email.to_address ?? "",
        },
        push: {
          enabled: data.channels.push.enabled,
          webhook_url: data.channels.push.webhook_url ?? "",
        },
        telegram: {
          enabled: data.channels.telegram.enabled,
          chat_id: data.channels.telegram.chat_id ?? "",
          bot_token: "",
        },
      },
      events: { ...data.events },
    });
    setTokenSaved(Boolean(data.channels.telegram.bot_token_set));
  }

  const patch = (updater: (f: AlertsConfig) => AlertsConfig) => setForm(updater);

  const handleSave = async () => {
    try {
      const res = await setAlerts.mutateAsync(form);
      setTestResult(null);
      if (res.persisted) {
        success("Alerts saved", "Your alerting settings were persisted.");
        // A freshly entered token is now stored; clear the field + mark saved.
        if (form.channels.telegram.bot_token) {
          setTokenSaved(true);
          patch((f) => ({
            ...f,
            channels: { ...f.channels, telegram: { ...f.channels.telegram, bot_token: "" } },
          }));
        }
      } else {
        error("Not persisted", res.message);
      }
    } catch (err) {
      error("Save failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleTest = async () => {
    try {
      const res = await sendTest.mutateAsync();
      setTestResult(res);
      if (res.success) {
        success("Test sent", res.message);
      } else {
        error("Test incomplete", res.message);
      }
    } catch (err) {
      error("Test failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  if (isLoading) {
    return <div className="text-gray-400 text-sm">Loading alert settings…</div>;
  }

  return (
    <div className="space-y-6">
      <SettingsSection
        title="Operator Alerts"
        subtitle="Get notified when your node needs attention — email, push, or Telegram."
      >
        <ToggleRow
          label="Enable alerts"
          description="Master switch. When off, no alert is delivered on any channel."
          enabled={form.enabled}
          onChange={(v) => patch((f) => ({ ...f, enabled: v }))}
          badge={<Badge variant={form.enabled ? "success" : "default"}>{form.enabled ? "On" : "Off"}</Badge>}
        />
      </SettingsSection>

      {/* Channels */}
      <Card>
        <CardHeader title="Channels" subtitle="Enable one or more delivery channels and enter their details." />
        <div className="space-y-4">
          {/* Email */}
          <div className="p-4 bg-gray-800/50 rounded-lg space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-gray-100 font-medium">Email</div>
                <div className="text-sm text-gray-400">
                  POSTs <code className="text-orange-400">{"{to, subject, body}"}</code> to your mail-relay webhook.
                </div>
              </div>
              <Toggle
                label="Enable email"
                enabled={form.channels.email.enabled}
                onChange={(v) =>
                  patch((f) => ({ ...f, channels: { ...f.channels, email: { ...f.channels.email, enabled: v } } }))
                }
              />
            </div>
            {form.channels.email.enabled && (
              <div className="grid gap-3 sm:grid-cols-2">
                <Input
                  label="Webhook URL"
                  placeholder="https://mail-relay.example/send"
                  value={form.channels.email.webhook_url ?? ""}
                  onChange={(e) =>
                    patch((f) => ({ ...f, channels: { ...f.channels, email: { ...f.channels.email, webhook_url: e.target.value } } }))
                  }
                />
                <Input
                  label="Destination address"
                  placeholder="ops@example.com"
                  value={form.channels.email.to_address ?? ""}
                  onChange={(e) =>
                    patch((f) => ({ ...f, channels: { ...f.channels, email: { ...f.channels.email, to_address: e.target.value } } }))
                  }
                />
              </div>
            )}
          </div>

          {/* Push */}
          <div className="p-4 bg-gray-800/50 rounded-lg space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-gray-100 font-medium">Push</div>
                <div className="text-sm text-gray-400">
                  POSTs <code className="text-orange-400">{"{title, message}"}</code> to an ntfy-style webhook.
                </div>
              </div>
              <Toggle
                label="Enable push"
                enabled={form.channels.push.enabled}
                onChange={(v) =>
                  patch((f) => ({ ...f, channels: { ...f.channels, push: { ...f.channels.push, enabled: v } } }))
                }
              />
            </div>
            {form.channels.push.enabled && (
              <Input
                label="Webhook URL"
                placeholder="https://ntfy.sh/my-ghost-node"
                value={form.channels.push.webhook_url ?? ""}
                onChange={(e) =>
                  patch((f) => ({ ...f, channels: { ...f.channels, push: { ...f.channels.push, webhook_url: e.target.value } } }))
                }
              />
            )}
          </div>

          {/* Telegram */}
          <div className="p-4 bg-gray-800/50 rounded-lg space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-gray-100 font-medium">Telegram</div>
                <div className="text-sm text-gray-400">Delivers via the Telegram Bot API.</div>
              </div>
              <Toggle
                label="Enable Telegram"
                enabled={form.channels.telegram.enabled}
                onChange={(v) =>
                  patch((f) => ({ ...f, channels: { ...f.channels, telegram: { ...f.channels.telegram, enabled: v } } }))
                }
              />
            </div>
            {form.channels.telegram.enabled && (
              <div className="grid gap-3 sm:grid-cols-2">
                <Input
                  label="Bot token"
                  type="password"
                  placeholder={tokenSaved ? "•••••••• (saved — leave blank to keep)" : "123456:ABC-DEF..."}
                  value={form.channels.telegram.bot_token ?? ""}
                  onChange={(e) =>
                    patch((f) => ({ ...f, channels: { ...f.channels, telegram: { ...f.channels.telegram, bot_token: e.target.value } } }))
                  }
                  helperText={tokenSaved ? "A token is stored. Enter a new one to replace it." : "From @BotFather. Stored securely, never shown again."}
                />
                <Input
                  label="Chat ID"
                  placeholder="987654321"
                  value={form.channels.telegram.chat_id ?? ""}
                  onChange={(e) =>
                    patch((f) => ({ ...f, channels: { ...f.channels, telegram: { ...f.channels.telegram, chat_id: e.target.value } } }))
                  }
                />
              </div>
            )}
          </div>
        </div>
      </Card>

      {/* Events */}
      <SettingsSection title="Events" subtitle="Choose which node events send an alert.">
        {EVENT_META.map((ev) => (
          <ToggleRow
            key={ev.key}
            label={ev.label}
            description={ev.description}
            enabled={form.events[ev.key]}
            onChange={(v) => patch((f) => ({ ...f, events: { ...f.events, [ev.key]: v } }))}
          />
        ))}
      </SettingsSection>

      {/* Actions */}
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="primary" onClick={handleSave} loading={setAlerts.isPending}>
          Save changes
        </Button>
        <Button variant="outline" onClick={handleTest} loading={sendTest.isPending}>
          Send test alert
        </Button>
        <span className="text-xs text-gray-500">
          Test delivers to every enabled + configured channel. Save first so a newly entered token is applied.
        </span>
      </div>

      {/* Test results */}
      {testResult && (
        <Card>
          <CardHeader title="Test result" subtitle={testResult.message} />
          <div className="space-y-2">
            {testResult.results.map((r) => (
              <div key={r.channel} className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg">
                <span className="text-gray-100 capitalize">{r.channel}</span>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-gray-400">{r.detail}</span>
                  <Badge variant={!r.attempted ? "default" : r.success ? "success" : "error"}>
                    {!r.attempted ? "Skipped" : r.success ? "Delivered" : "Failed"}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
