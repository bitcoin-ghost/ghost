"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader } from "@/components/ui/Card";
import { CopyButton } from "@/components/ui/CopyButton";
import { Input } from "@/components/ui/Input";
import { useToast } from "@/components/ui/Toast";
import { useBackupOffsite, useBackupOffsiteAction } from "@/hooks/queries/useBackupOffsiteQueries";
import type { OffsiteKind, OffsiteState } from "@/lib/api/backupOffsite";
import { validateOffsiteSetting, DEFAULT_KEEP } from "@/lib/backupOffsite";

function formatIso(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

/**
 * Nightly database backups (ghost-backup.timer → /var/backups/ghost/db) and the
 * OPTIONAL off-node destination for a copy of them (#1016).
 *
 * Off by default and never required: a node with nothing configured backs up
 * exactly as before, on its own disk. An operator who wants a copy elsewhere
 * picks a local directory on ANOTHER filesystem (a mounted USB drive, an NFS
 * share) or an SFTP server. For SFTP the node generates its own key pair; only
 * the PUBLIC key is ever shown, for the operator to add to the server's
 * authorized_keys. "Test" writes and removes a probe file and pins the server's
 * host key on first success; the nightly copy then requires that exact key.
 *
 * A failed off-node copy never fails or undoes the local backup — it is shown
 * under "Last off-node copy" below.
 */
export function NightlyBackupsCard() {
  const { data, isLoading, error: loadError } = useBackupOffsite();
  const act = useBackupOffsiteAction();
  const { success, error } = useToast();

  const [kind, setKind] = useState<OffsiteKind>("local");
  const [target, setTarget] = useState("");
  const [port, setPort] = useState("22");
  const [keep, setKeep] = useState(String(DEFAULT_KEEP));
  const [testOutcome, setTestOutcome] = useState<{ ok: boolean; text: string } | null>(null);

  // Hydrate the form once per distinct server response (same pattern as ScheduledBackupsCard).
  const [hydratedFrom, setHydratedFrom] = useState<OffsiteState | null>(null);
  if (data && hydratedFrom !== data) {
    setHydratedFrom(data);
    if (data.enabled && data.kind) {
      setKind(data.kind);
      setTarget(data.target ?? "");
      setPort(String(data.port ?? 22));
      setKeep(String(data.keep));
    }
  }

  const enabled = data?.enabled ?? false;
  const last = data?.last_result ?? null;
  const local = data?.local;
  const busy = act.isPending;

  const handleSave = async () => {
    const body = {
      kind,
      target: target.trim(),
      keep: Number(keep),
      ...(kind === "ssh" ? { port: Number(port) } : {}),
    };
    const v = validateOffsiteSetting(body);
    if (!v.ok) {
      error("Invalid destination", v.error);
      return;
    }
    try {
      const res = await act.mutateAsync({ action: "set", ...body });
      setTestOutcome(null);
      success(
        "Off-node backups on",
        kind === "ssh"
          ? "Add the public key below to the server, then press Test to pin its host key."
          : (res.result.message ?? "Saved."),
      );
    } catch (err) {
      error("Save failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleDisable = async () => {
    try {
      await act.mutateAsync({ action: "disable" });
      setTestOutcome(null);
      success("Off-node backups off", "Nightly backups stay on this node only.");
    } catch (err) {
      error("Disable failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleKeygen = async () => {
    try {
      await act.mutateAsync({ action: "keygen" });
    } catch (err) {
      error("Key generation failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleTest = async () => {
    try {
      const res = await act.mutateAsync({ action: "test" });
      const ok = res.result.ok;
      const text = ok ? (res.result.message ?? "Destination reachable.") : (res.result.error ?? "Test failed.");
      setTestOutcome({ ok, text });
      if (ok) success("Destination works", text);
      else error("Test failed", text);
    } catch (err) {
      error("Test failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  return (
    <Card>
      <CardHeader
        title="Nightly Database Backups"
        subtitle="Verified, gzipped copies of ghost.db taken every night at 03:00 UTC, with an optional copy off this node."
      />

      <div className="space-y-6">
        {loadError && (
          <p className="text-sm text-[color:var(--red)]">
            {loadError instanceof Error ? loadError.message : "Could not read the backup state."}
          </p>
        )}

        {/* Local nightly backups */}
        <div className="p-4 bg-[var(--surface)]/50 rounded-lg border border-[color:var(--rule-strong)]">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-sm font-medium text-[color:var(--dim)]">On this node</h4>
            {local?.timer === "enabled" ? (
              <Badge variant="success">Timer enabled</Badge>
            ) : (
              <Badge variant="warning">Timer {local?.timer ?? "unknown"}</Badge>
            )}
          </div>
          <div className="text-sm text-[color:var(--dim)] space-y-1">
            <div className="break-all">Directory: {local?.dir ?? "/var/backups/ghost/db"}</div>
            <div>
              Newest: {local?.newest ? `${local.newest} · ${formatIso(local.newest_time)}` : "none yet"}
            </div>
            <div>Copies kept: {local?.count ?? 0}</div>
          </div>
        </div>

        {/* Off-node destination */}
        <div className="flex items-center justify-between p-4 bg-[var(--surface)]/50 rounded-lg">
          <div className="pr-4">
            <div className="flex items-center gap-2">
              <span className="text-[color:var(--fg)] font-medium">Off-node copy</span>
              <Badge variant={enabled ? "success" : "default"}>{enabled ? "On" : "Off"}</Badge>
            </div>
            <p className="text-sm text-[color:var(--dim)]">
              Optional, off by default. Copies each night&apos;s backups to a drive or server you
              control, and keeps the newest N there. A failed copy never affects the backup on
              this node. The network does not provide or pay for this storage.
            </p>
            {data?.conf_error && (
              <p className="text-sm text-[color:var(--red)] mt-1 break-all">
                The saved setting is invalid and copies nothing: {data.conf_error}
              </p>
            )}
          </div>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1">
            <label className="block text-sm font-medium text-[color:var(--dim)]">Destination type</label>
            <select
              value={kind}
              onChange={(e) => setKind(e.target.value as OffsiteKind)}
              disabled={busy}
              className="w-full px-3 py-2 text-sm bg-[var(--surface)] border border-[color:var(--rule-strong)] rounded-lg text-[color:var(--fg)] focus:outline-none focus:ring-2 focus:ring-orange-500 focus:border-transparent disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <option value="local">Local directory (USB drive, NFS share)</option>
              <option value="ssh">Remote server over SSH (SFTP)</option>
            </select>
            <p className="text-xs text-[color:var(--fainter)]">
              {kind === "local"
                ? "Must be on a different filesystem from this node's disk — the same disk is refused."
                : "Uses a dedicated key pair generated on this node."}
            </p>
          </div>

          <Input
            label="Copies to keep there"
            type="number"
            min={1}
            max={365}
            value={keep}
            disabled={busy}
            onChange={(e) => setKeep(e.target.value)}
            helperText="Older copies at the destination beyond this count are deleted after each run."
          />

          <Input
            label={kind === "local" ? "Directory" : "Target (user@host:/path)"}
            value={target}
            disabled={busy}
            placeholder={kind === "local" ? "/mnt/backup-drive/ghost" : "backup@nas.example.org:/srv/ghost"}
            onChange={(e) => setTarget(e.target.value)}
            helperText="Letters, digits and . _ - / only. No spaces."
            className="sm:col-span-2"
          />

          {kind === "ssh" && (
            <Input
              label="SSH port"
              type="number"
              min={1}
              max={65535}
              value={port}
              disabled={busy}
              onChange={(e) => setPort(e.target.value)}
            />
          )}
        </div>

        {kind === "ssh" && (
          <div className="p-4 bg-[var(--surface)]/50 rounded-lg border border-[color:var(--rule-strong)] space-y-2">
            <div className="flex items-center justify-between">
              <h4 className="text-sm font-medium text-[color:var(--dim)]">This node&apos;s backup public key</h4>
              {enabled && data?.kind === "ssh" && (
                <Badge variant={data.host_key_pinned ? "success" : "warning"}>
                  {data.host_key_pinned ? "Host key pinned" : "Host key not pinned — press Test"}
                </Badge>
              )}
            </div>
            {data?.public_key ? (
              <>
                <code className="block text-xs break-all p-2 rounded bg-[var(--surface)] text-[color:var(--fg)]">
                  {data.public_key}
                </code>
                <div className="flex items-center gap-3">
                  <CopyButton text={data.public_key} label="Copy public key" />
                  <span className="text-xs text-[color:var(--fainter)]">
                    Add this line to <code>~/.ssh/authorized_keys</code> of the backup account on the
                    server. The private key never leaves this node.
                  </span>
                </div>
              </>
            ) : (
              <div className="flex items-center gap-3">
                <Button variant="outline" size="sm" onClick={handleKeygen} loading={busy}>
                  Generate key
                </Button>
                <span className="text-xs text-[color:var(--fainter)]">
                  Creates a key pair for backups only. Saving an SSH destination also creates it.
                </span>
              </div>
            )}
          </div>
        )}

        {/* Last off-node run */}
        <div className="p-4 bg-[var(--surface)]/50 rounded-lg border border-[color:var(--rule-strong)]">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-sm font-medium text-[color:var(--dim)]">Last off-node copy</h4>
            {last?.result === "ok" && <Badge variant="success">Success</Badge>}
            {last?.result === "failed" && <Badge variant="error">Failed</Badge>}
            {!last && <Badge variant="default">Never run</Badge>}
          </div>
          <div className="text-sm text-[color:var(--dim)] space-y-1">
            <div>Time: {formatIso(last?.time)}</div>
            {last?.files && <div className="break-all">Files: {last.files}</div>}
            {last?.error && <div className="text-[color:var(--red)] break-all">Error: {last.error}</div>}
            {testOutcome && (
              <div className={`break-all ${testOutcome.ok ? "text-[color:var(--green)]" : "text-[color:var(--red)]"}`}>
                Test: {testOutcome.text}
              </div>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Button variant="primary" onClick={handleSave} loading={busy} disabled={isLoading}>
            Save destination
          </Button>
          <Button variant="outline" onClick={handleTest} loading={busy} disabled={isLoading || !enabled}>
            Test
          </Button>
          <Button variant="ghost" onClick={handleDisable} loading={busy} disabled={isLoading || !enabled}>
            Disable
          </Button>
          <span className="text-xs text-[color:var(--fainter)]">
            Test checks the SAVED destination. Backups are database copies; store them somewhere only you can read.
          </span>
        </div>
      </div>
    </Card>
  );
}
