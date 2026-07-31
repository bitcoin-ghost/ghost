"use client";

import { useEffect, useMemo, useState } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { Toggle } from "@/components/ui/Toggle";
import { ConfirmDialog } from "@/components/ui/Dialog";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { getMaxConnections, type MaxConnectionsStatus } from "@/lib/api/config";
import { useToast } from "@/components/ui/Toast";
import {
  useDaemonSettings,
  useSetDaemonSettings,
  type DaemonSettings,
} from "@/hooks/queries/useConfigQueries";

// The networks ghostd's -onlynet accepts (mirrors GetNetworkNames()).
const ONLYNET_OPTIONS = ["ipv4", "ipv6", "onion", "i2p", "cjdns"] as const;

// Local form state: numeric flags are held as strings so an empty box means
// "unset" (clears the flag → ghostd default). Booleans are plain toggles.
interface FormState {
  maxMempoolMb: string;
  mempoolExpiryHours: string;
  // ON = full RBF (ghostd default, any tx replaceable). OFF = opt out → only
  // BIP125-signalling txs replaceable (first-seen-safe for the rest).
  fullRbf: boolean;
  maxConnections: string;
  maxUploadTargetMb: string;
  dbcacheMb: string;
  blockFilterIndex: boolean;
  peerBlockFilters: boolean;
  onlynet: string[];
  i2pSam: string;
  i2pAcceptIncoming: boolean;
}

const EMPTY_FORM: FormState = {
  maxMempoolMb: "",
  mempoolExpiryHours: "",
  fullRbf: true, // ghostd default is full RBF on
  maxConnections: "",
  maxUploadTargetMb: "",
  dbcacheMb: "",
  blockFilterIndex: false,
  peerBlockFilters: false,
  onlynet: [],
  i2pSam: "",
  i2pAcceptIncoming: false,
};

function fromSettings(s: DaemonSettings | undefined): FormState {
  if (!s) return EMPTY_FORM;
  const num = (v: number | null | undefined) => (v === null || v === undefined ? "" : String(v));
  return {
    maxMempoolMb: num(s.max_mempool_mb),
    mempoolExpiryHours: num(s.mempool_expiry_hours),
    // Full RBF is on unless the operator explicitly opted out (full_rbf===false).
    fullRbf: s.full_rbf !== false,
    maxConnections: num(s.max_connections),
    maxUploadTargetMb: s.max_upload_target_mb ?? "",
    dbcacheMb: num(s.dbcache_mb),
    blockFilterIndex: s.block_filter_index ?? false,
    peerBlockFilters: s.peer_block_filters ?? false,
    onlynet: s.onlynet ?? [],
    i2pSam: s.i2p_sam ?? "",
    i2pAcceptIncoming: s.i2p_accept_incoming ?? false,
  };
}

// A blank field → null (clears the flag). A filled numeric field → the parsed
// integer. The backend validates ranges/enum and rejects nonsense with a 400.
function toSettings(f: FormState): DaemonSettings {
  const optNum = (v: string): number | null => {
    const t = v.trim();
    if (t === "") return null;
    const n = Number(t);
    return Number.isFinite(n) ? Math.trunc(n) : null;
  };
  const optStr = (v: string): string | null => {
    const t = v.trim();
    return t === "" ? null : t;
  };
  return {
    max_mempool_mb: optNum(f.maxMempoolMb),
    mempool_expiry_hours: optNum(f.mempoolExpiryHours),
    // ON → null (leave ghostd at its full-RBF default, emit no flag).
    // OFF → false (opt out → -mempoolfullrbf=0).
    full_rbf: f.fullRbf ? null : false,
    max_connections: optNum(f.maxConnections),
    max_upload_target_mb: optStr(f.maxUploadTargetMb),
    dbcache_mb: optNum(f.dbcacheMb),
    block_filter_index: f.blockFilterIndex,
    peer_block_filters: f.peerBlockFilters,
    onlynet: f.onlynet,
    i2p_sam: optStr(f.i2pSam),
    i2p_accept_incoming: f.i2pAcceptIncoming,
  };
}

// A labelled numeric/text field row, matching the settings card layout.
function FieldRow({
  label,
  description,
  value,
  onChange,
  placeholder,
  type = "text",
  unit,
  inputMode,
}: {
  label: string;
  description: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
  unit?: string;
  inputMode?: "numeric" | "text";
}) {
  return (
    <div className="flex items-center justify-between gap-4 p-3 bg-[var(--surface)]/50 rounded-lg">
      <div className="flex-1 min-w-0">
        <div className="text-[color:var(--fg)] font-medium">{label}</div>
        <div className="text-sm text-[color:var(--dim)]">{description}</div>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        <Input
          type={type}
          inputMode={inputMode}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder ?? "default"}
          className="w-28 text-right"
        />
        {unit && <span className="text-[color:var(--dim)] text-sm w-10">{unit}</span>}
      </div>
    </div>
  );
}

// ghostd reserves a fixed outbound set (8 full-relay + 2 block-relay + 1 feeler)
// for eclipse/partition resistance — these are protocol constants, not knobs.
// Only the total (`-maxconnections`) is tunable; inbound capacity is whatever is
// left after the reserved outbound. This control sets the total and shows the
// fixed-outbound / variable-inbound split as a two-tone bar.
// 8 full-relay + 2 block-relay-only + 1 feeler. Matches RESERVED_OUTBOUND in
// crates/ghost-verification/src/maxconnections.rs — the two must not drift.
const OUTBOUND_RESERVED = 11;
const MAXCONN_DEFAULT = 125; // ghostd DEFAULT_MAX_PEER_CONNECTIONS
const MAXCONN_SLIDER_MIN = 11;
const MAXCONN_SLIDER_MAX = 1000;

function PeerConnectionsField({
  value,
  onChange,
  disabled,
  live,
}: {
  value: string;
  onChange: (v: string) => void;
  disabled?: boolean;
  live?: MaxConnectionsStatus | null;
}) {
  const isDefault = value.trim() === "";
  const parsed = parseInt(value, 10);
  const total = isDefault || Number.isNaN(parsed) ? MAXCONN_DEFAULT : Math.max(1, parsed);
  const outbound = Math.min(OUTBOUND_RESERVED, total);
  const inbound = Math.max(0, total - outbound);
  const sliderVal = Math.min(MAXCONN_SLIDER_MAX, Math.max(MAXCONN_SLIDER_MIN, total));
  // Gradient segments across the slider track (0..MAXCONN_SLIDER_MAX):
  // reserved outbound (muted) → inbound (accent) → unused track.
  const outPct = (Math.min(outbound, MAXCONN_SLIDER_MAX) / MAXCONN_SLIDER_MAX) * 100;
  const totPct = (sliderVal / MAXCONN_SLIDER_MAX) * 100;

  return (
    <div className="p-3 bg-[var(--surface)]/50 rounded-lg space-y-3">
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="text-[color:var(--fg)] font-medium">Peer connections</div>
          <div className="text-sm text-[color:var(--dim)]">
            Total automatic peers (<code>-maxconnections</code>). Outbound is
            protocol-fixed at {OUTBOUND_RESERVED}; the remainder is inbound capacity.
            Blank = ghostd default ({MAXCONN_DEFAULT}).
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <Input
            type="number"
            inputMode="numeric"
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder={String(MAXCONN_DEFAULT)}
            className="w-24 text-right"
            disabled={disabled}
          />
        </div>
      </div>

      <input
        type="range"
        className="ow-range w-full"
        min={MAXCONN_SLIDER_MIN}
        max={MAXCONN_SLIDER_MAX}
        step={1}
        value={sliderVal}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        aria-label="Maximum peer connections"
        style={{
          background: `linear-gradient(to right, var(--dim) 0%, var(--dim) ${outPct}%, var(--accent) ${outPct}%, var(--accent) ${totPct}%, var(--rule-strong) ${totPct}%, var(--rule-strong) 100%)`,
        }}
      />

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
        <span className="text-[color:var(--fg)]">
          Total <b>{total}</b>
          {isDefault && <span className="text-[color:var(--dim)]"> (default)</span>}
        </span>
        <span className="text-[color:var(--dim)]">
          <span
            className="inline-block w-2 h-2 rounded-sm align-middle mr-1"
            style={{ background: "var(--accent)" }}
          />
          Inbound {inbound}
        </span>
        <span className="text-[color:var(--dim)]">
          <span
            className="inline-block w-2 h-2 rounded-sm align-middle mr-1"
            style={{ background: "var(--dim)" }}
          />
          Outbound {outbound} (reserved)
        </span>
        {!isDefault && (
          <button
            type="button"
            onClick={() => onChange("")}
            disabled={disabled}
            className="ml-auto text-[color:var(--dim)] hover:text-[color:var(--fg)] underline underline-offset-2 cursor-pointer disabled:cursor-not-allowed"
          >
            Reset to default
          </button>
        )}
      </div>

      {/* Live inbound usage (#499). The configured total says nothing about whether the
          node is actually full; a node at its inbound ceiling stops accepting peers
          silently and drops out of public crawler listings (#497, #498, #572). */}
      {live && live.connections_in != null && (
        <div
          className={
            "rounded-md px-3 py-2 text-xs " +
            (live.near_ceiling
              ? "bg-[color:var(--warn-bg,rgba(200,120,0,0.12))] text-[color:var(--warn,#c87800)]"
              : "text-[color:var(--dim)]")
          }
        >
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span>
              In use <b>{live.connections_in}</b> / {live.inbound_capacity} inbound
              {live.inbound_utilisation != null && (
                <> ({Math.round(live.inbound_utilisation * 100)}%)</>
              )}
            </span>
            <span>
              Outbound {live.connections_out ?? "-"} of {live.reserved_outbound} reserved
            </span>
          </div>
          {live.near_ceiling && (
            <div className="mt-1">
              This node is at or near its inbound ceiling and is refusing new peers. Crawlers
              that cannot connect record it unreachable and drop it from public listings.
              {live.recommended_max != null && (
                <> Memory on this node supports up to <b>{live.recommended_max}</b>.</>
              )}
            </div>
          )}
          {live.ambiguous && (
            <div className="mt-1">
              <code>maxconnections</code> is set more than once in <code>bitcoin.conf</code>;
              this control will not overwrite an ambiguous file.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ToggleFieldRow({
  label,
  description,
  enabled,
  onChange,
  disabled = false,
  badge,
}: {
  label: string;
  description: string;
  enabled: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  badge?: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-4 p-3 bg-[var(--surface)]/50 rounded-lg">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-[color:var(--fg)] font-medium">{label}</span>
          {badge}
        </div>
        <div className="text-sm text-[color:var(--dim)]">{description}</div>
      </div>
      <Toggle enabled={enabled} onChange={onChange} label={label} disabled={disabled} />
    </div>
  );
}

export default function DaemonSettingsPage() {
  const { data, isLoading } = useDaemonSettings();
  const setDaemon = useSetDaemonSettings();
  const { success, error } = useToast();

  const [form, setForm] = useState<FormState>(EMPTY_FORM);
  const [confirmOpen, setConfirmOpen] = useState(false);
  // Live peer-connection state (#499). Polled rather than read from the config, because the
  // question "is this node full?" cannot be answered by the configured value alone.
  const [maxConn, setMaxConn] = useState<MaxConnectionsStatus | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = () =>
      getMaxConnections()
        .then((r) => {
          if (!cancelled) setMaxConn(r);
        })
        .catch(() => {
          // Non-fatal: the widget simply shows no live figures.
          if (!cancelled) setMaxConn(null);
        });
    load();
    const t = setInterval(load, 30_000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  // Seed the form once the current settings load / change.
  const loaded = data?.settings;
  useEffect(() => {
    setForm(fromSettings(loaded));
  }, [loaded]);

  const applyState = data?.ghostd_apply?.state;
  const applyMessage = data?.ghostd_apply?.message;

  // Client-side guard mirroring the backend's BIP157 dependency, so we can warn
  // inline before the operator even opens the confirm dialog.
  const bip157Invalid = form.peerBlockFilters && !form.blockFilterIndex;
  const i2pIncomingInvalid = form.i2pAcceptIncoming && form.i2pSam.trim() === "";

  const patch = (p: Partial<FormState>) => setForm((f) => ({ ...f, ...p }));

  const toggleNet = (net: string) =>
    setForm((f) => ({
      ...f,
      onlynet: f.onlynet.includes(net)
        ? f.onlynet.filter((n) => n !== net)
        : [...f.onlynet, net],
    }));

  const canApply = useMemo(
    () => !bip157Invalid && !i2pIncomingInvalid && !setDaemon.isPending,
    [bip157Invalid, i2pIncomingInvalid, setDaemon.isPending]
  );

  const handleApply = async () => {
    try {
      const res = await setDaemon.mutateAsync(toSettings(form));
      setConfirmOpen(false);
      success("Applying", res.message ?? "ghostd is restarting to apply the new launch flags.");
    } catch (err) {
      setConfirmOpen(false);
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader
          title="Daemon / Node"
          subtitle="ghostd launch flags for this node. Every setting here is read only at startup, so applying any change restarts ghostd (and briefly bounces the pool)."
        />
        <div className="flex items-center gap-2 text-sm text-[color:var(--dim)]">
          <span>Last apply:</span>
          {applyState ? (
            <Badge
              variant={
                applyState === "applied"
                  ? "success"
                  : applyState === "failed"
                  ? "error"
                  : applyState === "applying"
                  ? "warning"
                  : "default"
              }
            >
              {applyState}
            </Badge>
          ) : (
            <Badge variant="default">idle</Badge>
          )}
          {applyMessage && <span className="text-[color:var(--fainter)] truncate">{applyMessage}</span>}
        </div>
      </Card>

      {isLoading ? (
        <Card>
          <p className="text-[color:var(--dim)] text-sm">Loading daemon settings…</p>
        </Card>
      ) : (
        <SectionErrorBoundary section="Daemon settings">
          {/* Mempool */}
          <Card>
            <CardHeader title="Mempool" subtitle="Transaction pool size and expiry (-maxmempool / -mempoolexpiry)." />
            <div className="space-y-3">
              <FieldRow
                label="Max mempool size"
                description="Keep the transaction memory pool below this size. Blank = ghostd default."
                value={form.maxMempoolMb}
                onChange={(v) => patch({ maxMempoolMb: v })}
                type="number"
                inputMode="numeric"
                unit="MB"
              />
              <FieldRow
                label="Mempool expiry"
                description="Drop transactions older than this. Blank = ghostd default."
                value={form.mempoolExpiryHours}
                onChange={(v) => patch({ mempoolExpiryHours: v })}
                type="number"
                inputMode="numeric"
                unit="hrs"
              />
              <ToggleFieldRow
                label="Full RBF"
                description={
                  form.fullRbf
                    ? "ON (default): every unconfirmed transaction is replaceable by a higher-fee conflict, regardless of BIP125 signalling."
                    : "OFF: only transactions that signal BIP125 opt-in replaceability can be replaced. Non-signalling first-seen transactions are protected (-mempoolfullrbf=0)."
                }
                enabled={form.fullRbf}
                onChange={(v) => patch({ fullRbf: v })}
              />
            </div>
          </Card>

          {/* Connectivity */}
          <Card>
            <CardHeader title="Connectivity" subtitle="Peer connection and upload limits (-maxconnections / -maxuploadtarget)." />
            <div className="space-y-3">
              <PeerConnectionsField
                value={form.maxConnections}
                onChange={(v) => patch({ maxConnections: v })}
                live={maxConn}
              />
              <FieldRow
                label="Max upload target / 24h"
                description="Outbound traffic ceiling. Number with optional unit k/K/m/M/g/G/t/T (0 = no limit). Blank = ghostd default."
                value={form.maxUploadTargetMb}
                onChange={(v) => patch({ maxUploadTargetMb: v })}
                placeholder="e.g. 500M"
              />
            </div>
          </Card>

          {/* Performance */}
          <Card>
            <CardHeader title="Performance" subtitle="Database cache size (-dbcache)." />
            <div className="space-y-3">
              <FieldRow
                label="Database cache"
                description="UTXO/db cache in megabytes. Larger speeds up sync at the cost of RAM. Blank = ghostd default."
                value={form.dbcacheMb}
                onChange={(v) => patch({ dbcacheMb: v })}
                type="number"
                inputMode="numeric"
                unit="MB"
              />
            </div>
          </Card>

          {/* Indexes / BIP157 */}
          <Card>
            <CardHeader title="Indexes (BIP157)" subtitle="Compact block filters for light clients (-blockfilterindex / -peerblockfilters)." />
            <div className="space-y-3">
              <ToggleFieldRow
                label="Block filter index"
                description="Build the basic block-filter index. Enabling triggers a one-time index build over the whole chain, which takes time and disk."
                enabled={form.blockFilterIndex}
                onChange={(v) => patch({ blockFilterIndex: v, peerBlockFilters: v ? form.peerBlockFilters : false })}
              />
              <ToggleFieldRow
                label="Serve compact filters (peer block filters)"
                description="Serve BIP157 compact block filters to connecting light clients. Requires the block filter index above."
                enabled={form.peerBlockFilters}
                onChange={(v) => patch({ peerBlockFilters: v })}
                disabled={!form.blockFilterIndex}
              />
              {bip157Invalid && (
                <p className="text-xs text-[color:var(--red)] px-1">
                  Peer block filters need the block filter index enabled too.
                </p>
              )}
            </div>
          </Card>

          {/* Privacy networking */}
          <Card>
            <CardHeader title="Privacy networking" subtitle="Restrict outbound networks and reach I2P peers (-onlynet / -i2psam)." />
            <div className="space-y-3">
              <div className="p-3 bg-[var(--surface)]/50 rounded-lg">
                <div className="text-[color:var(--fg)] font-medium">Only connect via networks</div>
                <div className="text-sm text-[color:var(--dim)] mb-3">
                  Restrict automatic outbound connections to the selected networks. None selected = no restriction.
                </div>
                <div className="flex flex-wrap gap-2">
                  {ONLYNET_OPTIONS.map((net) => {
                    const on = form.onlynet.includes(net);
                    return (
                      <button
                        key={net}
                        type="button"
                        onClick={() => toggleNet(net)}
                        className={`px-3 py-1 rounded-lg text-sm border transition-colors ${
                          on
                            ? "bg-[var(--accent)] text-white border-[var(--accent)]"
                            : "bg-transparent text-[color:var(--dim)] border-[var(--rule-strong)] hover:bg-[var(--surface)]"
                        }`}
                      >
                        {net}
                      </button>
                    );
                  })}
                </div>
              </div>
              <FieldRow
                label="I2P SAM proxy"
                description="host:port of an I2P SAM proxy to reach I2P peers. Blank = I2P disabled."
                value={form.i2pSam}
                onChange={(v) => patch({ i2pSam: v, i2pAcceptIncoming: v.trim() === "" ? false : form.i2pAcceptIncoming })}
                placeholder="127.0.0.1:7656"
              />
              <ToggleFieldRow
                label="Accept inbound I2P connections"
                description="Allow inbound I2P connections through the SAM proxy. Requires an I2P SAM proxy above."
                enabled={form.i2pAcceptIncoming}
                onChange={(v) => patch({ i2pAcceptIncoming: v })}
                disabled={form.i2pSam.trim() === ""}
              />
              {i2pIncomingInvalid && (
                <p className="text-xs text-[color:var(--red)] px-1">
                  Accepting inbound I2P needs an I2P SAM proxy address.
                </p>
              )}
            </div>
          </Card>

          {/* Apply */}
          <Card>
            <div className="flex items-center justify-between gap-4">
              <div className="text-sm text-[color:var(--dim)]">
                Applying these changes restarts ghostd and briefly bounces ghost-pool.
              </div>
              <Button
                variant="primary"
                disabled={!canApply}
                loading={setDaemon.isPending}
                onClick={() => setConfirmOpen(true)}
              >
                Apply &amp; restart
              </Button>
            </div>
          </Card>
        </SectionErrorBoundary>
      )}

      <ConfirmDialog
        isOpen={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        onConfirm={handleApply}
        title="Apply daemon settings & restart ghostd?"
        message="ghostd will restart with the new launch flags and ghost-pool will bounce once it settles. Mining pauses for a few seconds during the restart. Continue?"
        confirmLabel="Apply & restart"
        variant="danger"
        loading={setDaemon.isPending}
      />
    </div>
  );
}
