"use client";

import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { StatCard } from "@/components/ui/StatCard";
import { StatusDot } from "@/components/ui/StatusDot";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { PageHeader } from "@/components/ui/PageHeader";
import { useHazeStatus, useCheckpointStatus } from "@/hooks/queries/useHazeQueries";

const BYTES_PER_GB = 1024 * 1024 * 1024;

function formatBytes(bytes: number | undefined | null): string {
  if (bytes == null || !Number.isFinite(bytes)) return "--";
  const gb = bytes / BYTES_PER_GB;
  if (gb >= 1000) return `${(gb / 1024).toFixed(2)} TB`;
  if (gb >= 1) return `${gb.toFixed(2)} GB`;
  const mb = bytes / (1024 * 1024);
  if (mb >= 1) return `${mb.toFixed(1)} MB`;
  const kb = bytes / 1024;
  if (kb >= 1) return `${kb.toFixed(0)} KB`;
  return `${bytes} B`;
}

function shortHash(hash: string | undefined | null): string {
  if (!hash) return "--";
  if (hash.length <= 20) return hash;
  return `${hash.slice(0, 10)}…${hash.slice(-8)}`;
}

/** Human-readable storage role from the node's own flags. */
function roleOf(mode: string, pruned: boolean): { label: string; variant: "success" | "info" | "warning" | "default"; blurb: string } {
  switch (mode) {
    case "hazed":
      return {
        label: pruned ? "Hazed · pruned" : "Hazed",
        variant: "success",
        blurb: "Validates fully; arbitrary content stripped in RAM before disk. Serves stripped blocks and answers wallet queries — hosts no embedded data.",
      };
    case "full_archive":
      return {
        label: "Full Archive",
        variant: "info",
        blurb: "Keeps complete, unstripped blocks and the full witness. Can serve any historical block and build signed UTXO snapshots — accepts the storage and legal cost of doing so.",
      };
    case "standard":
      return {
        label: pruned ? "Standard · pruned" : "Standard",
        variant: "warning",
        blurb: "A normal Bitcoin node — full blocks, no haze stripping and no haze metadata.",
      };
    default:
      return { label: "Unknown", variant: "default", blurb: "Ghost Core did not report a storage mode." };
  }
}

export default function ZeroSyncPage() {
  const { data: haze, isLoading: hazeLoading, error: hazeError } = useHazeStatus();
  const { data: ckpt, isLoading: ckptLoading } = useCheckpointStatus();

  const mode = haze?.mode ?? "unknown";
  const pruned = haze?.pruned ?? false;
  const role = roleOf(mode, pruned);

  const downloading = ckpt?.downloading ?? false;
  const serving = (ckpt?.serving ?? false) && (ckpt?.available ?? false);
  const hasSnapshot = serving && (ckpt?.height ?? 0) > 0;
  const pct =
    ckpt?.percent_complete != null
      ? ckpt.percent_complete
      : ckpt?.chunks_total
        ? ((ckpt.chunks_received ?? 0) / ckpt.chunks_total) * 100
        : null;

  const canServe: { label: string; on: boolean; note: string }[] = [
    { label: "Full blocks", on: mode !== "hazed" && !pruned, note: "Complete historical blocks to any peer" },
    { label: "Stripped blocks", on: mode === "hazed", note: "Structural blocks to hazed peers" },
    { label: "Signed UTXO snapshot", on: hasSnapshot && (ckpt?.signed ?? false), note: "Fast bootstrap for new nodes" },
    { label: "Light-client filters", on: false, note: "BIP158 + merkle proofs — planned (GSP serving layer)" },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="zero-sync"
        title="Fast sync & serve"
        subtitle="Bootstrap a node in minutes from a signed UTXO snapshot, and see what this node can serve to peers and wallets — witness-free."
        actions={
          haze && (
            <div className="flex items-center gap-2">
              <StatusDot
                status={downloading ? "warning" : hasSnapshot ? "online" : "warning"}
                label={downloading ? "Bootstrapping" : hasSnapshot ? "Serving snapshot" : "No snapshot"}
                pulse={downloading}
              />
              <Badge variant={role.variant}>{role.label}</Badge>
            </div>
          )
        }
      />

      {/* Snapshot bootstrap — the zero-sync core */}
      <SectionErrorBoundary section="Snapshot bootstrap">
        {ckptLoading || hazeLoading ? (
          <SkeletonCard />
        ) : hazeError ? (
          <Card>
            <div className="p-4 bg-[var(--surface)] border border-[color:var(--red)] rounded-lg">
              <p className="text-[color:var(--red)] text-sm">
                Unable to reach Ghost Core. Ensure <code>ghostd</code> is running and the Haze RPCs are available.
              </p>
            </div>
          </Card>
        ) : downloading ? (
          <Card>
            <CardHeader
              title="Bootstrapping from a signed UTXO snapshot"
              subtitle="This node is syncing the current UTXO set in chunks, then it validates forward"
              action={<Badge variant="warning">In progress</Badge>}
            />
            <div className="space-y-3">
              <div className="flex items-baseline justify-between">
                <span className="text-2xl font-bold text-[color:var(--fg)]">
                  {pct != null ? `${pct.toFixed(1)}%` : "--"}
                </span>
                <span className="font-mono text-sm text-[color:var(--dim)]">
                  {(ckpt?.chunks_received ?? 0).toLocaleString()} / {(ckpt?.chunks_total ?? 0).toLocaleString()} chunks
                </span>
              </div>
              <div className="h-2.5 w-full rounded-full bg-[var(--rule-strong)] overflow-hidden">
                <div
                  className="h-full rounded-full transition-[width] duration-500"
                  style={{ width: `${pct ?? 0}%`, background: "var(--accent)" }}
                />
              </div>
            </div>
          </Card>
        ) : hasSnapshot ? (
          <Card>
            <CardHeader
              title="Serving a signed UTXO snapshot"
              subtitle="A fresh node can adopt this snapshot and validate forward — sync in minutes, not hours"
              action={ckpt?.signed ? <Badge variant="success">Signed</Badge> : <Badge variant="warning">Unsigned</Badge>}
            />
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <StatCard label="Snapshot height" value={(ckpt?.height ?? 0).toLocaleString()} sublabel="block of the UTXO set" tooltip="The block height the served UTXO snapshot commits to." />
              <StatCard label="UTXOs" value={(ckpt?.utxo_count ?? 0).toLocaleString()} sublabel="entries in the set" tooltip="Number of unspent outputs in the served snapshot." />
              <StatCard label="Chunks" value={(ckpt?.total_chunks ?? 0).toLocaleString()} sublabel="2 MB each, hashed" tooltip="The snapshot is served as content-hashed chunks over P2P." />
              <StatCard label="Snapshot block" value={shortHash(ckpt?.block_hash)} sublabel="commitment hash" tooltip={ckpt?.block_hash ?? "—"} />
            </div>
          </Card>
        ) : (
          <Card>
            <div className="text-xs uppercase tracking-wider text-[color:var(--accent)] font-semibold mb-2">
              No snapshot on this node
            </div>
            <div className="text-2xl md:text-3xl font-bold text-[color:var(--fg)] leading-tight max-w-3xl">
              Fast bootstrap needs a signed UTXO snapshot.
            </div>
            <p className="text-[color:var(--dim)] text-sm mt-3 max-w-2xl leading-relaxed">
              A signed UTXO snapshot lets a new node adopt the current ledger and validate forward — syncing in
              minutes instead of hours, without downloading the whole chain. Full Archive nodes build these; hazed
              nodes fetch and re-serve them. None is present on this node right now.
            </p>
          </Card>
        )}
      </SectionErrorBoundary>

      {/* Storage role */}
      <Card>
        <CardHeader title="This node's storage role" subtitle="Derived from the node's own storage mode" action={<Badge variant={role.variant}>{role.label}</Badge>} />
        <p className="text-[color:var(--dim)] text-sm leading-relaxed max-w-2xl">{role.blurb}</p>
        {mode === "hazed" && (
          <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mt-4">
            <StatCard label="Content kept off disk" value={formatBytes(haze?.bytes_stripped)} sublabel="cumulative, arbitrary data" tooltip="Non-consensus bytes stripped before ever touching disk." />
            <StatCard label="Structural archive" value={formatBytes((haze?.structural_archive_size_gb ?? 0) * BYTES_PER_GB)} sublabel="stripped blocks on disk" tooltip="On-disk size of the .gsb (Ghost Stripped Block) archive." />
            <StatCard label="Blocks stripped" value={(haze?.blocks_stripped ?? 0).toLocaleString()} sublabel="processed by Exorcism" tooltip="Blocks run through the Exorcism strip pipeline." />
          </div>
        )}
      </Card>

      {/* What this node can serve */}
      <Card>
        <CardHeader title="What this node can serve" subtitle="Capabilities available to peers and wallets, from the current role" />
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {canServe.map((c) => (
            <div key={c.label} className="flex items-start gap-3 p-3 rounded-lg bg-[var(--surface)] border border-[color:var(--rule-strong)]">
              <StatusDot status={c.on ? "online" : "unknown"} />
              <div>
                <div className="text-[color:var(--fg)] text-sm font-medium flex items-center gap-2">
                  {c.label}
                  {c.on ? <Badge variant="success">Available</Badge> : <Badge variant="default">Off</Badge>}
                </div>
                <div className="text-xs text-[color:var(--dim)] mt-0.5">{c.note}</div>
              </div>
            </div>
          ))}
        </div>
        <p className="t-caption text-[color:var(--fainter)] mt-3">
          Filters + merkle-proof serving (the light-client backbone) is the next serving-layer build — it runs on the
          economic graph a hazed node already keeps. Trustless bootstrap today rests on the signed checkpoint; recursive
          validity proofs are the planned trust anchor beyond it.
        </p>
      </Card>
    </div>
  );
}
