"use client";

import { useEffect, useState } from "react";
import {
  RefreshCw,
  Blocks,
  Layers,
  HardDrive,
  Hash,
  Clock,
  CheckCircle2,
  Loader2,
  GitBranch,
  ShieldCheck,
  AlertTriangle,
} from "lucide-react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { StatCard } from "@/components/ui/StatCard";
import { ProgressBar } from "@/components/ui/ProgressBar";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { useBlockchainStatus, useChainHealth } from "@/hooks/queries";
import type {
  BlockchainStatus,
  ChainHealthResponse,
  ChainTipStatus,
  ChainReorgEvent,
} from "@/types/api";

// ─── formatting helpers ──────────────────────────────────────────────────────

const DASH = "—";

function isNum(n: number | null | undefined): n is number {
  return typeof n === "number" && Number.isFinite(n);
}

function formatCount(n: number | null | undefined): string {
  return isNum(n) ? n.toLocaleString() : DASH;
}

function formatBytes(n: number | null | undefined): string {
  if (!isNum(n)) return DASH;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatPercent(fraction: number | null | undefined): string {
  if (!isNum(fraction)) return DASH;
  const pct = fraction * 100;
  if (pct >= 99.995 && pct < 100) return "100.00%";
  return `${pct.toFixed(2)}%`;
}

// Relative "N minutes ago" from a unix-seconds timestamp. `now` is passed in so
// the whole page ticks off a single clock and re-renders once per second.
function formatRelative(unixSecs: number | null | undefined, now: number): string {
  if (!isNum(unixSecs)) return DASH;
  const diff = Math.max(0, Math.floor(now / 1000) - unixSecs);
  if (diff < 5) return "just now";
  if (diff < 60) return `${diff}s ago`;
  const mins = Math.floor(diff / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ${mins % 60}m ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ${hours % 24}h ago`;
}

function formatAbsolute(unixSecs: number | null | undefined): string {
  if (!isNum(unixSecs)) return DASH;
  return new Date(unixSecs * 1000).toLocaleString();
}

function truncateHash(hash: string | null | undefined): string {
  if (!hash) return DASH;
  if (hash.length <= 20) return hash;
  return `${hash.slice(0, 10)}…${hash.slice(-10)}`;
}

// ─── derived view ────────────────────────────────────────────────────────────

interface SyncView {
  blocks: number | null;
  headers: number | null;
  blocksRemaining: number | null;
  // Preferred sync percentage: Core's verificationprogress, falling back to a
  // block/header ratio when progress isn't reported.
  syncFraction: number | null;
  ibd: boolean | null;
  caughtUp: boolean;
  verifying: boolean;
}

function deriveView(data: BlockchainStatus | undefined): SyncView {
  const blocks = data?.blocks ?? null;
  const headers = data?.headers ?? null;

  const blocksRemaining =
    isNum(blocks) && isNum(headers) ? Math.max(0, headers - blocks) : null;

  let syncFraction: number | null = data?.verification_progress ?? null;
  if (!isNum(syncFraction) && isNum(blocks) && isNum(headers) && headers > 0) {
    syncFraction = Math.min(1, blocks / headers);
  }

  const ibd = data?.initial_block_download ?? null;
  // Caught up: not in IBD and the block tip has reached the header tip.
  const caughtUp = ibd === false && blocksRemaining === 0;
  // Verification/reindex is "in progress" when validation hasn't reached the tip.
  const verifying = isNum(syncFraction) && syncFraction < 0.99995;

  return { blocks, headers, blocksRemaining, syncFraction, ibd, caughtUp, verifying };
}

// ─── page ────────────────────────────────────────────────────────────────────

export default function SyncPage() {
  const { data, isLoading, isError, error } = useBlockchainStatus({ refetchInterval: 10_000 });
  const chainHealth = useChainHealth({ refetchInterval: 30_000 });

  // Single ticking clock so relative times stay live between polls.
  const [now, setNow] = useState<number>(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const unavailable = data?.available === false;
  const view = deriveView(data);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="node"
        title="Sync"
        subtitle="Chain and synchronisation status for this node, straight from ghostd's getblockchaininfo."
        actions={<SyncBadge isLoading={isLoading} unavailable={unavailable} view={view} />}
      />

      {isError && (
        <Card>
          <p style={{ color: "var(--dim)", fontSize: "14px" }}>
            Failed to load sync status: {error instanceof Error ? error.message : "unknown error"}
          </p>
        </Card>
      )}

      {unavailable && !isLoading && (
        <Card>
          <p style={{ color: "var(--dim)", fontSize: "14px" }}>
            The node&apos;s Bitcoin RPC is not reachable, so chain details are unavailable. Values
            below show <span className="font-mono">{DASH}</span> until the daemon responds.
          </p>
        </Card>
      )}

      {/* Headline stats */}
      <SectionErrorBoundary section="Sync overview">
        {isLoading ? (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <SkeletonCard key={i} />
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard
              label="Sync progress"
              value={formatPercent(view.syncFraction)}
              icon={<RefreshCw size={16} strokeWidth={1.75} />}
              sublabel={
                isNum(view.blocksRemaining)
                  ? view.blocksRemaining === 0
                    ? "fully caught up"
                    : `${formatCount(view.blocksRemaining)} blocks remaining`
                  : undefined
              }
              tooltip="Bitcoin Core's verificationprogress (fraction of the estimated chain validated), with blocks remaining = header height − block height."
            />
            <StatCard
              label="Block height"
              value={formatCount(view.blocks)}
              icon={<Blocks size={16} strokeWidth={1.75} />}
              sublabel="validated tip"
              tooltip="Height of the fully-validated block tip (getblockchaininfo.blocks)."
            />
            <StatCard
              label="Header height"
              value={formatCount(view.headers)}
              icon={<Layers size={16} strokeWidth={1.75} />}
              sublabel="best known header"
              tooltip="Height of the best known header (getblockchaininfo.headers). Ahead of the block height while blocks are still downloading."
            />
            <StatCard
              label="Size on disk"
              value={formatBytes(data?.size_on_disk)}
              icon={<HardDrive size={16} strokeWidth={1.75} />}
              sublabel={data?.pruned ? "pruned" : "full chain"}
              tooltip="Estimated size of the block and undo files on disk (getblockchaininfo.size_on_disk)."
            />
          </div>
        )}
      </SectionErrorBoundary>

      {/* Sync progress detail */}
      <SectionErrorBoundary section="Synchronisation">
        <Card>
          <CardHeader
            title="Synchronisation"
            subtitle="How far this node has caught up with the network tip."
          />
          {isLoading ? (
            <div className="space-y-4">
              <div className="h-2.5 rounded-full" style={{ background: "var(--rule)" }} />
            </div>
          ) : (
            <div className="space-y-5">
              <ProgressBar
                value={isNum(view.syncFraction) ? view.syncFraction * 100 : 0}
                max={100}
                color={view.caughtUp ? "green" : "orange"}
                size="lg"
                label="Chain sync"
                sublabel={formatPercent(view.syncFraction)}
              />

              {view.verifying && (
                <ProgressBar
                  value={isNum(view.syncFraction) ? view.syncFraction * 100 : 0}
                  max={100}
                  color="blue"
                  size="md"
                  label="Reindex / verification progress"
                  sublabel={formatPercent(view.syncFraction)}
                />
              )}

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Field
                  label="State"
                  value={
                    view.ibd === null ? DASH : view.ibd ? "Initial block download" : "Caught up"
                  }
                />
                <Field label="Blocks remaining" value={formatCount(view.blocksRemaining)} />
                <Field
                  label="Network"
                  value={data?.chain ? String(data.chain) : data?.network ?? DASH}
                />
              </div>
            </div>
          )}
        </Card>
      </SectionErrorBoundary>

      {/* Chain tip */}
      <SectionErrorBoundary section="Chain tip">
        <Card>
          <CardHeader
            title="Chain tip"
            subtitle="The most recent block this node has accepted."
          />
          {isLoading ? (
            <div className="space-y-3">
              <div className="h-4 w-2/3 rounded" style={{ background: "var(--rule)" }} />
              <div className="h-4 w-1/2 rounded" style={{ background: "var(--rule)" }} />
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-4">
              <Field
                label="Tip hash"
                icon={<Hash size={14} strokeWidth={1.75} />}
                value={truncateHash(data?.best_block_hash)}
                title={data?.best_block_hash ?? undefined}
                mono
              />
              <Field
                label="Last block time"
                icon={<Clock size={14} strokeWidth={1.75} />}
                value={formatRelative(data?.tip_time, now)}
                sub={formatAbsolute(data?.tip_time)}
              />
              <Field
                label="Median time (11-block)"
                value={formatAbsolute(data?.median_time)}
              />
              <Field
                label="Difficulty"
                value={isNum(data?.difficulty) ? data!.difficulty!.toLocaleString() : DASH}
              />
            </div>
          )}
        </Card>
      </SectionErrorBoundary>

      {/* Chain health: reorgs + tip-lag */}
      <SectionErrorBoundary section="Chain health">
        <ChainHealthSection
          data={chainHealth.data}
          isLoading={chainHealth.isLoading}
          isError={chainHealth.isError}
          now={now}
        />
      </SectionErrorBoundary>
    </div>
  );
}

// ─── chain health ────────────────────────────────────────────────────────────

// Human-readable tip status, keyed off the derived `status` label from the API.
function tipStatusLabel(tip: ChainTipStatus): string {
  switch (tip.status) {
    case "at_tip":
      return "At tip";
    case "behind":
      return `Behind by ${formatCount(tip.behind_by)} block${tip.behind_by === 1 ? "" : "s"}`;
    case "stale": {
      const mins = Math.floor(tip.tip_age_secs / 60);
      return `Stale — no block in ${formatCount(mins)} min`;
    }
    default:
      return DASH;
  }
}

function TipStatusBadge({ tip }: { tip: ChainTipStatus | null }) {
  if (!tip) return <Badge variant="default">Awaiting first check</Badge>;
  if (tip.status === "at_tip") {
    return (
      <Badge variant="success">
        <ShieldCheck size={13} strokeWidth={2} className="mr-1" />
        {tipStatusLabel(tip)}
      </Badge>
    );
  }
  if (tip.status === "behind") {
    return (
      <Badge variant="warning">
        <AlertTriangle size={13} strokeWidth={2} className="mr-1" />
        {tipStatusLabel(tip)}
      </Badge>
    );
  }
  return (
    <Badge variant="error">
      <AlertTriangle size={13} strokeWidth={2} className="mr-1" />
      {tipStatusLabel(tip)}
    </Badge>
  );
}

// One-line summary of the most recent reorg: time · depth · old→new tip.
function reorgSummary(ev: ChainReorgEvent, now: number): string {
  const when = formatRelative(ev.unix_time, now);
  const oldTip = truncateHash(ev.old_tip_hash);
  const newTip = isNum(ev.new_tip_height) ? `height ${formatCount(ev.new_tip_height)}` : "new tip";
  return `${when} · depth ${formatCount(ev.depth)} · ${oldTip} → ${newTip}`;
}

function ChainHealthSection({
  data,
  isLoading,
  isError,
  now,
}: {
  data: ChainHealthResponse | undefined;
  isLoading: boolean;
  isError: boolean;
  now: number;
}) {
  const tip = data?.tip ?? null;
  const reorgs = data?.reorgs ?? [];
  const count24h = data?.reorg_count_24h ?? 0;
  const lastReorg = reorgs[0];
  const stable = count24h === 0;

  return (
    <Card>
      <CardHeader
        title="Chain health"
        subtitle="Tip-lag against the network and any recent chain reorganisations this node has seen."
        action={<TipStatusBadge tip={tip} />}
      />

      {isError ? (
        <p style={{ color: "var(--dim)", fontSize: "14px" }}>
          Chain-health data is unavailable right now.
        </p>
      ) : isLoading ? (
        <div className="space-y-3">
          <div className="h-4 w-2/3 rounded" style={{ background: "var(--rule)" }} />
          <div className="h-4 w-1/2 rounded" style={{ background: "var(--rule)" }} />
        </div>
      ) : (
        <div className="space-y-5">
          {/* Tip detail */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Field
              label="Tip status"
              value={tip ? tipStatusLabel(tip) : "Awaiting first check"}
            />
            <Field
              label="Local height"
              value={tip && isNum(tip.local_height) ? formatCount(tip.local_height) : DASH}
              sub={
                tip && tip.best_peer_height > 0
                  ? `best peer ${formatCount(tip.best_peer_height)}`
                  : "no peer height reported"
              }
            />
            <Field
              label="Tip age"
              value={
                tip && isNum(tip.tip_age_secs)
                  ? `${formatCount(Math.floor(tip.tip_age_secs / 60))}m ${tip.tip_age_secs % 60}s`
                  : DASH
              }
              sub="since local height last advanced"
            />
          </div>

          {/* Reorg summary */}
          <div
            className="rounded-lg p-4"
            style={{
              background: stable ? "var(--card-2, var(--rule))" : undefined,
              border: "1px solid var(--rule)",
            }}
          >
            <div className="flex items-center gap-2" style={{ marginBottom: "6px" }}>
              <GitBranch size={15} strokeWidth={1.75} style={{ color: "var(--dim)" }} />
              <span style={{ color: "var(--fg)", fontSize: "14px", fontWeight: 500 }}>
                Reorgs (last 24h)
              </span>
              <Badge variant={stable ? "success" : "warning"}>{formatCount(count24h)}</Badge>
            </div>
            {stable ? (
              <p style={{ color: "var(--dim)", fontSize: "13px" }}>
                None in the last 24 hours — a stable, single chain is the normal, healthy state.
              </p>
            ) : (
              <p style={{ color: "var(--dim)", fontSize: "13px" }}>
                {formatCount(count24h)} chain reorganisation{count24h === 1 ? "" : "s"} recorded in
                the last 24 hours.
              </p>
            )}
          </div>

          {/* Last reorg */}
          <Field
            label="Last reorg"
            value={lastReorg ? reorgSummary(lastReorg, now) : "None recently"}
            sub={lastReorg ? formatAbsolute(lastReorg.unix_time) : undefined}
          />

          {/* Recent reorgs list */}
          {reorgs.length > 0 && (
            <div>
              <div
                style={{ color: "var(--dim)", fontSize: "12px", marginBottom: "6px" }}
              >
                Recent reorgs
              </div>
              <ul className="space-y-1.5">
                {reorgs.map((ev, i) => (
                  <li
                    key={`${ev.unix_time}-${ev.old_tip_hash}-${i}`}
                    className="flex items-center gap-2 font-mono"
                    style={{ color: "var(--fg)", fontSize: "13px" }}
                  >
                    <GitBranch size={13} strokeWidth={1.75} style={{ color: "var(--fainter)" }} />
                    <span>{reorgSummary(ev, now)}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

// ─── small presentational pieces ─────────────────────────────────────────────

function SyncBadge({
  isLoading,
  unavailable,
  view,
}: {
  isLoading: boolean;
  unavailable: boolean;
  view: SyncView;
}) {
  if (isLoading) return null;
  if (unavailable) return <Badge variant="default">RPC unavailable</Badge>;

  if (view.caughtUp) {
    return (
      <Badge variant="success">
        <CheckCircle2 size={13} strokeWidth={2} className="mr-1" />
        Caught up
      </Badge>
    );
  }

  if (view.ibd) {
    return (
      <Badge variant="warning">
        <Loader2 size={13} strokeWidth={2} className="mr-1 animate-spin" />
        Initial block download
      </Badge>
    );
  }

  return (
    <Badge variant="info">
      <Loader2 size={13} strokeWidth={2} className="mr-1 animate-spin" />
      Syncing
    </Badge>
  );
}

function Field({
  label,
  value,
  sub,
  sublabel,
  icon,
  mono,
  title,
}: {
  label: string;
  value: string;
  sub?: string;
  sublabel?: string;
  icon?: React.ReactNode;
  mono?: boolean;
  title?: string;
}) {
  return (
    <div>
      <div
        className="flex items-center gap-1.5"
        style={{ color: "var(--dim)", fontSize: "12px", marginBottom: "3px" }}
      >
        {icon}
        <span>{label}</span>
      </div>
      <div
        className={mono ? "font-mono break-all" : ""}
        style={{ color: "var(--fg)", fontSize: "14px" }}
        title={title}
      >
        {value}
      </div>
      {(sub || sublabel) && (
        <div style={{ color: "var(--fainter)", fontSize: "12px", marginTop: "2px" }}>
          {sub ?? sublabel}
        </div>
      )}
    </div>
  );
}
