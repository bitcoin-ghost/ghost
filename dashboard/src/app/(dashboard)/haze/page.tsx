"use client";

import { useMemo, useState } from "react";
import { StatusRow } from "@/components/ui/StatusRow";
import { Card, CardHeader } from "@/components/ui/Card";
import { ConfirmDialog } from "@/components/ui/Dialog";
import { PageHeader } from "@/components/ui/PageHeader";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { StatusDot } from "@/components/ui/StatusDot";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { useToast } from "@/components/ui/Toast";
import {
  useHazeStatus,
  useLegalPacket,
  useCheckpointStatus,
} from "@/hooks/queries/useHazeQueries";
import { useConfigureHaze } from "@/hooks/queries/useConfigQueries";
import type { LegalPacket } from "@/types/api";

// --- Constants ---

// A full (unstripped) block averages ~1.6 MB near the chain tip. Used only to
// estimate the full-archive baseline the hazed node avoids storing.
const FULL_BLOCK_BYTES = 1.6 * 1024 * 1024;
const BYTES_PER_GB = 1024 * 1024 * 1024;

// --- Helpers ---

/** Human-readable byte size. Renders "--" for missing/non-finite input. */
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

/** GB (as reported by ghostd, base-1024) → bytes. */
function gbToBytes(gb: number | undefined | null): number {
  if (gb == null || !Number.isFinite(gb)) return 0;
  return gb * BYTES_PER_GB;
}

function getModeLabel(mode: string): string {
  switch (mode) {
    case "hazed":
      return "Hazed";
    case "full_archive":
      return "Full Archive";
    case "standard":
      return "Standard";
    default:
      return "Unknown";
  }
}

function getModeBadgeVariant(
  mode: string,
): "success" | "warning" | "info" | "default" {
  switch (mode) {
    case "hazed":
      return "success";
    case "full_archive":
      return "info";
    case "standard":
      return "warning";
    default:
      return "default";
  }
}

function shortHash(hash: string | undefined | null): string {
  if (!hash) return "--";
  if (hash.length <= 20) return hash;
  return `${hash.slice(0, 10)}…${hash.slice(-10)}`;
}

/** Render the Legal Compliance Packet as a readable court-ready text document. */
function renderLegalText(packet: LegalPacket): string {
  const line = (label: string, value: unknown): string =>
    `${label.padEnd(30, " ")}: ${value ?? "—"}`;
  const yn = (v: boolean | undefined): string =>
    v === undefined ? "—" : v ? "Yes" : "No";

  return [
    "==============================================================",
    "  GHOST HAZE — LEGAL COMPLIANCE PACKET",
    "  Cryptographic, court-ready proof of non-persistence",
    "==============================================================",
    "",
    packet.legal_summary ?? "",
    "",
    "--------------------------------------------------------------",
    "  ATTESTATION",
    "--------------------------------------------------------------",
    line("Ghost Core version", packet.ghost_core_version),
    line("Haze specification version", packet.specification_version),
    line("Node mode", packet.node_mode),
    line("Exorcism active", yn(packet.exorcism_active)),
    line("Haze status", packet.haze_status),
    line("Arbitrary content on disk", yn(packet.hazeable_content_on_disk)),
    line("Blocks stripped", packet.blocks_stripped),
    line("Chain tip height", packet.chain_tip),
    line("Structural archive size", `${packet.structural_archive_size_gb ?? "—"} GB`),
    "",
    "--------------------------------------------------------------",
    "  CHECKPOINT ANCHOR",
    "--------------------------------------------------------------",
    line("Checkpoint height", packet.checkpoint_height),
    line("Checkpoint hash", packet.checkpoint_hash),
    "",
    "--------------------------------------------------------------",
    "  CONVERSION",
    "--------------------------------------------------------------",
    line("Conversion method", packet.conversion_method),
    line("Conversion date", packet.conversion_date),
    "",
    line("Packet generated at", packet.generated_at),
    "==============================================================",
    "",
  ].join("\n");
}

function downloadLegalPacket(packet: LegalPacket, format: "txt" | "json"): void {
  const tag = packet.chain_tip ?? "node";
  const isJson = format === "json";
  const content = isJson
    ? JSON.stringify(packet, null, 2)
    : renderLegalText(packet);
  const blob = new Blob([content], {
    type: isJson ? "application/json" : "text/plain;charset=utf-8",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `ghost-haze-legal-pack-${tag}.${format}`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// The field types Ghost Haze's own classifier strips before a block hits disk.
// This is haze::field_classifier in ghostd — NOT the BUDS policy system.
const STRIPPED_FIELDS: { title: string; body: string }[] = [
  {
    title: "Witness data",
    body: "Where inscriptions live. Taproot witness envelopes carrying images, text, and arbitrary files are removed once the signature has been validated.",
  },
  {
    title: "scriptSig",
    body: "Legacy input unlocking scripts. Their signatures are checked during validation, then the raw bytes are dropped from the stored block.",
  },
  {
    title: "OP_RETURN payloads",
    body: "The classic data-carrier output. The provably-unspendable payload bytes are stripped; the output's existence and value stay accounted for.",
  },
  {
    title: "Coinbase scriptSig",
    body: "The miner's free-form input field, frequently abused to embed arbitrary content. Its non-consensus bytes are removed after height validation.",
  },
];

// --- Page ---

export default function HazePage() {
  const {
    data: haze,
    isLoading: hazeLoading,
    error: hazeError,
  } = useHazeStatus();
  const { data: legal, isLoading: legalLoading } = useLegalPacket();
  const { data: checkpoint, isLoading: checkpointLoading } =
    useCheckpointStatus();
  const configureHaze = useConfigureHaze();
  const toast = useToast();

  const mode = haze?.mode ?? "unknown";
  // A node is "actively hazing" when the Exorcist is stripping incoming blocks.
  // The legal packet is only generated in that state, so it is the ground truth.
  const active = Boolean(haze?.exorcism_active) || mode === "hazed";
  const legalAvailable = legal?.available === true;

  // Retroactive-conversion state. The Exorcist reports COMPLETE / IN_PROGRESS
  // in the legal packet; blocks_stripped vs chain_tip gives a progress bar for
  // the (long, resumable) batch job that strips an already-synced node.
  const conversionState: "complete" | "in_progress" | "none" = legalAvailable
    ? legal?.haze_status === "IN_PROGRESS"
      ? "in_progress"
      : "complete"
    : "none";
  const conversionInProgress = conversionState === "in_progress";
  const convBlocks = haze?.blocks_stripped ?? 0;
  const convTip = haze?.chain_tip ?? 0;
  const convPercent =
    convTip > 0 ? Math.min(100, (convBlocks / convTip) * 100) : null;

  const savings = useMemo(() => {
    const strippedBytes = haze?.bytes_stripped ?? 0;
    const structuralBytes = gbToBytes(haze?.structural_archive_size_gb);
    const tip = haze?.chain_tip ?? 0;
    const fullArchiveBytes = tip > 0 ? tip * FULL_BLOCK_BYTES : 0;
    // Percentage the on-disk structural archive is smaller than a full archive.
    const percentSmaller =
      fullArchiveBytes > 0 && structuralBytes > 0 && fullArchiveBytes > structuralBytes
        ? (1 - structuralBytes / fullArchiveBytes) * 100
        : null;
    return { strippedBytes, structuralBytes, fullArchiveBytes, percentSmaller };
  }, [haze?.bytes_stripped, haze?.structural_archive_size_gb, haze?.chain_tip]);

  // Selecting Hazed from a node that already holds blocks (standard / full
  // archive) is a one-time, long, irreversible retroactive conversion — gate it
  // behind an explicit confirmation.
  const [confirmConvert, setConfirmConvert] = useState(false);

  const doSetMode = async (target: "hazed" | "full_archive" | "standard") => {
    try {
      await configureHaze.mutateAsync(target);
      toast.success("Ghost Haze updated", `Storage mode set to ${getModeLabel(target)}`);
    } catch (e) {
      toast.error(
        "Failed to update Haze mode",
        e instanceof Error ? e.message : "Ghost Core did not accept the change.",
      );
    }
  };

  const handleSetMode = async (target: "hazed" | "full_archive" | "standard") => {
    if (target === mode) return;
    const retroactive =
      target === "hazed" && (mode === "standard" || mode === "full_archive");
    if (retroactive) {
      setConfirmConvert(true);
      return;
    }
    await doSetMode(target);
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <PageHeader
        eyebrow="haze"
        title="Storage privacy layer."
        subtitle="Strip arbitrary embedded content before it ever touches your disk — while keeping full validation and UTXO integrity."
        actions={
          haze && (
            <div className="flex items-center gap-2">
              <StatusDot
                status={active ? "online" : "warning"}
                label={active ? "Exorcism active" : "Not hazing"}
                pulse={active}
              />
              <Badge variant={getModeBadgeVariant(mode)}>{getModeLabel(mode)}</Badge>
            </div>
          )
        }
      />

      {/* 1. HERO — Storage saved */}
      <SectionErrorBoundary section="Storage Savings">
        {hazeLoading ? (
          <SkeletonCard />
        ) : hazeError ? (
          <Card>
            <div className="p-4 bg-[var(--surface)] border border-[color:var(--red)] rounded-lg">
              <p className="text-[color:var(--red)] text-sm">
                Unable to reach Ghost Core. Ensure <code>ghostd</code> is running and the
                Haze RPCs are available.
              </p>
            </div>
          </Card>
        ) : active ? (
          <div
            className="rounded-lg p-8 border"
            style={{
              borderColor: "color-mix(in srgb, var(--green) 40%, transparent)",
              background:
                "linear-gradient(135deg, color-mix(in srgb, var(--green) 12%, var(--surface)) 0%, var(--surface) 70%)",
            }}
          >
            <div className="text-xs uppercase tracking-wider text-[color:var(--green)] font-semibold mb-2">
              Arbitrary data kept off your disk
            </div>
            <div className="text-5xl md:text-6xl font-bold text-[color:var(--fg)] leading-none">
              {formatBytes(savings.strippedBytes)}
            </div>
            <p className="text-[color:var(--dim)] text-sm mt-3 max-w-2xl leading-relaxed">
              Ghost Exorcism has removed{" "}
              <span className="text-[color:var(--fg)] font-medium">
                {formatBytes(savings.strippedBytes)}
              </span>{" "}
              of non-consensus content across{" "}
              <span className="text-[color:var(--fg)] font-medium">
                {(haze?.blocks_stripped ?? 0).toLocaleString()}
              </span>{" "}
              blocks — inscriptions, spam and data-carrier payloads that never reached your
              disk.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-6">
              <div className="rounded-lg p-4 bg-[var(--surface)] border border-[color:var(--rule)]">
                <div className="text-xs text-[color:var(--dim)] mb-1">Structural archive on disk</div>
                <div className="text-2xl font-bold text-[color:var(--fg)]">
                  {formatBytes(savings.structuralBytes)}
                </div>
              </div>
              <div className="rounded-lg p-4 bg-[var(--surface)] border border-[color:var(--rule)]">
                <div className="text-xs text-[color:var(--dim)] mb-1">Full-archive estimate</div>
                <div className="text-2xl font-bold text-[color:var(--fg)]">
                  {savings.fullArchiveBytes > 0 ? formatBytes(savings.fullArchiveBytes) : "--"}
                </div>
                <div className="t-caption text-[color:var(--fainter)] mt-0.5">
                  {(haze?.chain_tip ?? 0).toLocaleString()} blocks × ~1.6 MB
                </div>
              </div>
              <div className="rounded-lg p-4 bg-[var(--surface)] border border-[color:var(--rule)]">
                <div className="text-xs text-[color:var(--dim)] mb-1">Chain footprint</div>
                <div className="text-2xl font-bold text-[color:var(--green)]">
                  {savings.percentSmaller != null
                    ? `${savings.percentSmaller.toFixed(1)}% smaller`
                    : "--"}
                </div>
              </div>
            </div>
          </div>
        ) : (
          // Inactive: value proposition + enable path (no fabricated numbers).
          <div
            className="rounded-lg p-8 border"
            style={{
              borderColor: "color-mix(in srgb, var(--accent) 35%, transparent)",
              background:
                "linear-gradient(135deg, color-mix(in srgb, var(--accent) 10%, var(--surface)) 0%, var(--surface) 70%)",
            }}
          >
            <div className="text-xs uppercase tracking-wider text-[color:var(--accent)] font-semibold mb-2">
              Haze is not active on this node
            </div>
            <div className="text-3xl md:text-4xl font-bold text-[color:var(--fg)] leading-tight max-w-3xl">
              Keep inscriptions, spam and arbitrary payloads off your disk.
            </div>
            <p className="text-[color:var(--dim)] text-sm mt-3 max-w-2xl leading-relaxed">
              In Hazed mode, Ghost Exorcism strips non-consensus fields from every block
              before it is written — you keep full validation and UTXO integrity while
              shrinking your on-disk footprint and never persisting embedded content. Enable
              it to start measuring your savings and generate a court-ready Legal Pack.
            </p>
            <div className="mt-6">
              <Button
                variant="primary"
                onClick={() => handleSetMode("hazed")}
                loading={configureHaze.isPending}
              >
                Enable Haze
              </Button>
            </div>
          </div>
        )}
      </SectionErrorBoundary>

      {/* 2. ⭐ Legal Pack — centerpiece */}
      <SectionErrorBoundary section="Legal Pack">
        <Card>
          <CardHeader
            title="Legal Compliance Pack"
            subtitle="Cryptographic, court-ready proof this node does not persist arbitrary embedded content"
            action={
              legalAvailable ? (
                <Badge variant="success">Available</Badge>
              ) : (
                <Badge variant="default">Enable Haze to generate</Badge>
              )
            }
          />
          {legalLoading ? (
            <SkeletonCard />
          ) : legalAvailable && legal ? (
            <div className="space-y-5">
              {/* Court-ready summary */}
              {legal.legal_summary && (
                <div className="p-4 rounded-lg bg-[var(--surface)] border border-[color:var(--green)]">
                  <p className="text-[color:var(--fg)] text-sm leading-relaxed whitespace-pre-line">
                    {legal.legal_summary}
                  </p>
                </div>
              )}

              {/* Headline attestation: arbitrary content on disk */}
              <div className="flex items-center gap-3 p-4 rounded-lg bg-[var(--surface)] border border-[color:var(--rule-strong)]">
                {legal.hazeable_content_on_disk ? (
                  <svg
                    className="w-8 h-8 text-[color:var(--red)] flex-shrink-0"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    strokeWidth={2}
                  >
                    <circle cx="12" cy="12" r="9" />
                    <path strokeLinecap="round" d="M15 9l-6 6M9 9l6 6" />
                  </svg>
                ) : (
                  <svg
                    className="w-8 h-8 text-[color:var(--green)] flex-shrink-0"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    strokeWidth={2}
                  >
                    <circle cx="12" cy="12" r="9" />
                    <path strokeLinecap="round" strokeLinejoin="round" d="M8.5 12.5l2.5 2.5 4.5-5" />
                  </svg>
                )}
                <div>
                  <div className="text-[color:var(--fg)] font-medium text-sm">
                    Arbitrary content on disk:{" "}
                    <span
                      className={
                        legal.hazeable_content_on_disk
                          ? "text-[color:var(--red)]"
                          : "text-[color:var(--green)]"
                      }
                    >
                      {legal.hazeable_content_on_disk ? "Present" : "None"}
                    </span>
                  </div>
                  <p className="text-[color:var(--dim)] text-xs mt-0.5">
                    {legal.hazeable_content_on_disk
                      ? "Legacy full-block files were detected on disk."
                      : "No blk*.dat files — only stripped structural blocks are stored."}
                  </p>
                </div>
              </div>

              {/* Attestation grid */}
              <div className="divide-y divide-[var(--rule)]">
                <StatusRow label="Ghost Core version">
                  <span className="font-mono text-sm text-[color:var(--fg)]">
                    {legal.ghost_core_version ?? "--"}
                  </span>
                </StatusRow>
                <StatusRow label="Haze specification">
                  <span className="font-mono text-sm text-[color:var(--fg)]">
                    {legal.specification_version ?? "--"}
                  </span>
                </StatusRow>
                <StatusRow label="Node mode">
                  <Badge variant="success">{legal.node_mode ?? "--"}</Badge>
                </StatusRow>
                <StatusRow label="Haze status">
                  <Badge variant={legal.haze_status === "COMPLETE" ? "success" : "warning"}>
                    {legal.haze_status ?? "--"}
                  </Badge>
                </StatusRow>
                <StatusRow label="Blocks stripped">
                  <span className="font-mono text-sm text-[color:var(--fg)]">
                    {(legal.blocks_stripped ?? 0).toLocaleString()}
                  </span>
                </StatusRow>
                <StatusRow label="Checkpoint height">
                  <span className="font-mono text-sm text-[color:var(--fg)]">
                    {legal.checkpoint_height ? legal.checkpoint_height.toLocaleString() : "None"}
                  </span>
                </StatusRow>
                <StatusRow label="Checkpoint hash">
                  <span
                    className="font-mono text-xs text-[color:var(--fg)]"
                    title={legal.checkpoint_hash ?? undefined}
                  >
                    {shortHash(legal.checkpoint_hash)}
                  </span>
                </StatusRow>
                <StatusRow label="Conversion method">
                  <span className="font-mono text-sm text-[color:var(--fg)]">
                    {legal.conversion_method ?? "--"}
                  </span>
                </StatusRow>
                <StatusRow label="Conversion date">
                  <span className="font-mono text-sm text-[color:var(--fg)]">
                    {legal.conversion_date ?? "--"}
                  </span>
                </StatusRow>
                <StatusRow label="Generated at">
                  <span className="font-mono text-sm text-[color:var(--fg)]">
                    {legal.generated_at ?? "--"}
                  </span>
                </StatusRow>
              </div>

              {/* Download */}
              <div className="flex flex-wrap items-center gap-3 pt-2">
                <Button variant="primary" onClick={() => downloadLegalPacket(legal, "txt")}>
                  <svg
                    className="w-4 h-4 mr-2"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    strokeWidth={2}
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3"
                    />
                  </svg>
                  Download Legal Pack (.txt)
                </Button>
                <Button variant="outline" onClick={() => downloadLegalPacket(legal, "json")}>
                  Download JSON
                </Button>
              </div>
            </div>
          ) : (
            <div className="p-4 rounded-lg bg-[var(--surface)] border border-[color:var(--rule-strong)]">
              <p className="text-[color:var(--dim)] text-sm leading-relaxed">
                The Legal Compliance Pack is a signed, court-ready proof that your node does
                not persist arbitrary embedded content. It is generated once{" "}
                <span className="text-[color:var(--fg)] font-medium">Haze is enabled</span> and
                the Exorcist is stripping blocks.
                {legal?.reason && (
                  <span className="block mt-2 text-xs text-[color:var(--fainter)]">
                    Ghost Core: {legal.reason}
                  </span>
                )}
              </p>
            </div>
          )}
        </Card>
      </SectionErrorBoundary>

      {/* 3. What Haze keeps off your disk */}
      <Card>
        <CardHeader
          title="What Haze keeps off your disk"
          subtitle="Non-consensus fields removed by Ghost Haze's own field classifier"
        />
        <p className="text-[color:var(--dim)] text-sm leading-relaxed mb-4">
          Ghost Haze uses its own <code className="text-[color:var(--accent)]">field_classifier</code>{" "}
          — distinct from the BUDS policy system — to identify the non-consensus bytes where
          inscriptions and spam live. These are stripped after full validation, so consensus and
          the UTXO set are untouched while the arbitrary payloads never reach disk.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {STRIPPED_FIELDS.map((f) => (
            <div
              key={f.title}
              className="p-3 bg-[var(--surface)] rounded-lg border border-[color:var(--rule-strong)]"
            >
              <div className="flex items-center gap-2 mb-1.5">
                <span className="text-[color:var(--accent)] font-mono text-xs font-bold">✕</span>
                <span className="text-[color:var(--fg)] text-sm font-medium">{f.title}</span>
              </div>
              <p className="text-[color:var(--dim)] text-xs leading-relaxed">{f.body}</p>
            </div>
          ))}
        </div>
      </Card>

      {/* 4. Checkpoints & trust */}
      <SectionErrorBoundary section="Checkpoints">
        <Card>
          <CardHeader
            title="Checkpoints & trust"
            subtitle="Signed UTXO checkpoints are the trust anchor for a hazed node"
            action={
              checkpoint && (
                <StatusDot
                  status={
                    checkpoint.serving
                      ? "online"
                      : checkpoint.downloading
                        ? "warning"
                        : "offline"
                  }
                  label={
                    checkpoint.serving
                      ? "Serving"
                      : checkpoint.downloading
                        ? "Downloading"
                        : "Idle"
                  }
                  pulse={checkpoint.downloading}
                />
              )
            }
          />
          {checkpointLoading ? (
            <SkeletonCard />
          ) : checkpoint?.available === false ? (
            <div className="p-4 rounded-lg bg-[var(--surface)] border border-[color:var(--rule-strong)]">
              <p className="text-[color:var(--dim)] text-sm">
                Checkpoint status is unavailable.
                {checkpoint?.reason && (
                  <span className="block mt-1 text-xs text-[color:var(--fainter)]">
                    {checkpoint.reason}
                  </span>
                )}
              </p>
            </div>
          ) : checkpoint?.serving ? (
            <div className="divide-y divide-[var(--rule)]">
              <StatusRow label="Role">
                <Badge variant="success">Serving checkpoint</Badge>
              </StatusRow>
              <StatusRow label="Height">
                <span className="font-mono text-sm text-[color:var(--fg)]">
                  {checkpoint.height?.toLocaleString() ?? "--"}
                </span>
              </StatusRow>
              <StatusRow label="Block hash">
                <span
                  className="font-mono text-xs text-[color:var(--fg)]"
                  title={checkpoint.block_hash ?? undefined}
                >
                  {shortHash(checkpoint.block_hash)}
                </span>
              </StatusRow>
              <StatusRow label="UTXO count">
                <span className="font-mono text-sm text-[color:var(--fg)]">
                  {checkpoint.utxo_count?.toLocaleString() ?? "--"}
                </span>
              </StatusRow>
              <StatusRow label="Signed manifest">
                <Badge variant={checkpoint.signed ? "success" : "warning"}>
                  {checkpoint.signed ? "Signed" : "Unsigned"}
                </Badge>
              </StatusRow>
            </div>
          ) : checkpoint?.downloading ? (
            <div className="divide-y divide-[var(--rule)]">
              <StatusRow label="Role">
                <Badge variant="warning">Downloading checkpoint</Badge>
              </StatusRow>
              <StatusRow label="Target height">
                <span className="font-mono text-sm text-[color:var(--fg)]">
                  {checkpoint.height?.toLocaleString() ?? "--"}
                </span>
              </StatusRow>
              <StatusRow label="Progress">
                <span className="font-mono text-sm text-[color:var(--fg)]">
                  {checkpoint.chunks_received ?? 0} / {checkpoint.chunks_total ?? "--"} chunks
                  {checkpoint.percent_complete != null &&
                    ` (${checkpoint.percent_complete.toFixed(1)}%)`}
                </span>
              </StatusRow>
            </div>
          ) : (
            <div className="p-4 rounded-lg bg-[var(--surface)] border border-[color:var(--rule-strong)]">
              <p className="text-[color:var(--dim)] text-sm">
                This node is neither serving nor downloading a checkpoint. It is validating the
                chain from its local structural archive.
              </p>
            </div>
          )}
        </Card>
      </SectionErrorBoundary>

      {/* 5. The Exorcism pipeline */}
      <Card collapsible defaultCollapsed>
        <CardHeader
          title="The Exorcism pipeline"
          subtitle="How Ghost Haze strips blocks before they hit disk"
        />
        <div className="space-y-5">
          <p className="text-[color:var(--dim)] text-sm leading-relaxed">
            Ghost Haze classifies and strips non-consensus data from blocks before writing them
            to disk. Hazed nodes retain full transaction validity and UTXO integrity while
            ensuring no arbitrary embedded content is persisted locally.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="p-3 bg-[var(--surface)] rounded-lg border border-[color:var(--rule-strong)]">
              <div className="flex items-center gap-2 mb-1.5">
                <span className="text-[color:var(--accent)] font-mono text-xs font-bold">1</span>
                <span className="text-[color:var(--fg)] text-sm font-medium">Field Classification</span>
              </div>
              <p className="text-[color:var(--dim)] text-xs leading-relaxed">
                Ghost Haze&apos;s own <code className="text-[color:var(--accent)]">field_classifier</code>{" "}
                (not BUDS) marks each non-consensus field — witness data, scriptSig, OP_RETURN
                payloads and coinbase scriptSig — as strippable once validated.
              </p>
            </div>
            <div className="p-3 bg-[var(--surface)] rounded-lg border border-[color:var(--rule-strong)]">
              <div className="flex items-center gap-2 mb-1.5">
                <span className="text-[color:var(--accent)] font-mono text-xs font-bold">2</span>
                <span className="text-[color:var(--fg)] text-sm font-medium">Block Stripping</span>
              </div>
              <p className="text-[color:var(--dim)] text-xs leading-relaxed">
                Non-consensus data is stripped at the validation layer, before the block is
                written to disk. Consensus-critical fields remain untouched.
              </p>
            </div>
            <div className="p-3 bg-[var(--surface)] rounded-lg border border-[color:var(--rule-strong)]">
              <div className="flex items-center gap-2 mb-1.5">
                <span className="text-[color:var(--accent)] font-mono text-xs font-bold">3</span>
                <span className="text-[color:var(--fg)] text-sm font-medium">GSB Storage</span>
              </div>
              <p className="text-[color:var(--dim)] text-xs leading-relaxed">
                Stripped blocks are stored in Ghost Stripped Block (
                <code className="text-[color:var(--accent)]">.gsb</code>) format — a compact
                representation that preserves everything needed for chain validation.
              </p>
            </div>
            <div className="p-3 bg-[var(--surface)] rounded-lg border border-[color:var(--rule-strong)]">
              <div className="flex items-center gap-2 mb-1.5">
                <span className="text-[color:var(--accent)] font-mono text-xs font-bold">4</span>
                <span className="text-[color:var(--fg)] text-sm font-medium">UTXO Preservation</span>
              </div>
              <p className="text-[color:var(--dim)] text-xs leading-relaxed">
                All financial data and UTXO set integrity are preserved. Your node fully
                validates the chain, spends coins, and participates in consensus with no embedded
                content on disk.
              </p>
            </div>
          </div>

          <div className="p-3 bg-[var(--surface)] rounded-lg border border-[color:var(--rule-strong)]">
            <h4 className="text-[color:var(--fg)] font-medium text-sm mb-1">The Exorcist</h4>
            <p className="text-[color:var(--dim)] text-xs leading-relaxed">
              The Exorcist is the component that performs the actual stripping. It runs inside
              Ghost Core (<code className="text-[color:var(--accent)]">ghostd</code>) at the block
              acceptance layer, intercepting blocks before they are serialized to disk.
            </p>
            <div className="mt-2 p-2 bg-[var(--surface)] rounded border border-[color:var(--rule-strong)]">
              <div className="text-xs text-[color:var(--dim)] leading-relaxed">
                <span className="text-[color:var(--accent)] font-medium">Mode A (Active Stripping):</span>{" "}
                the Exorcist strips classified content before the block is written. Blocks arrive
                from the network, get stripped in memory, and only the clean version is persisted.
              </div>
            </div>
          </div>
        </div>
      </Card>

      {/* 6a. Retroactive conversion progress — prominent while running */}
      {conversionInProgress && (
        <Card>
          <CardHeader
            title="Retroactive conversion in progress"
            subtitle="The Exorcist is stripping the blocks this node already holds"
            action={<Badge variant="warning">IN_PROGRESS</Badge>}
          />
          <div className="space-y-3">
            <div className="flex items-baseline justify-between">
              <span className="text-2xl font-bold text-[color:var(--fg)]">
                {convPercent != null ? `${convPercent.toFixed(1)}%` : "--"}
              </span>
              <span className="font-mono text-sm text-[color:var(--dim)]">
                {convBlocks.toLocaleString()} / {convTip.toLocaleString()} blocks
              </span>
            </div>
            <div className="h-2.5 w-full rounded-full bg-[var(--rule-strong)] overflow-hidden">
              <div
                className="h-full rounded-full transition-[width] duration-500"
                style={{
                  width: `${convPercent ?? 0}%`,
                  background: "var(--accent)",
                }}
              />
            </div>
            <p className="text-[color:var(--dim)] text-xs leading-relaxed">
              This is a one-time batch job that rewrites existing block files into stripped
              structural blocks. It is <span className="text-[color:var(--fg)]">resumable</span> —
              if the node restarts, conversion continues from where it left off. Your Legal Pack
              is finalised once it reads <span className="font-mono">COMPLETE</span>.
            </p>
          </div>
        </Card>
      )}

      {/* 6b. Mode control — two programmes: forward vs retroactive */}
      <Card>
        <CardHeader
          title="Storage mode"
          subtitle="Choose how this node stores block data"
          action={
            haze && <Badge variant={getModeBadgeVariant(mode)}>{getModeLabel(mode)}</Badge>
          }
        />

        {/* Explain the two ways to become hazed */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-5">
          <div className="p-3 rounded-lg bg-[var(--surface)] border border-[color:var(--rule-strong)]">
            <div className="text-[color:var(--fg)] text-sm font-medium mb-1">
              Forward — haze from genesis
            </div>
            <p className="text-[color:var(--dim)] text-xs leading-relaxed">
              A <span className="text-[color:var(--fg)]">fresh</span> node can start hazed and strip
              every block as it syncs. Nothing arbitrary is ever written — no conversion needed.
            </p>
          </div>
          <div className="p-3 rounded-lg bg-[var(--surface)] border border-[color:var(--rule-strong)]">
            <div className="text-[color:var(--fg)] text-sm font-medium mb-1">
              Retroactive — convert existing blocks
            </div>
            <p className="text-[color:var(--dim)] text-xs leading-relaxed">
              An <span className="text-[color:var(--fg)]">already-synced</span> full or pruned node
              cannot simply flip to hazed — it must run a one-time, resumable conversion that strips
              the blocks it already holds. This is the only path to haze later.
            </p>
          </div>
        </div>

        {/* Mode options */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {(() => {
            // From a non-hazed node with blocks already on disk, selecting Hazed
            // means a retroactive conversion — not an instant flip.
            const retroactive = mode === "standard" || mode === "full_archive";
            const options = [
              {
                key: "hazed" as const,
                label: "Hazed",
                action: retroactive ? "Convert existing blocks (retroactive)" : undefined,
                desc: retroactive
                  ? "Run the one-time Exorcist conversion to strip existing blocks. Smallest footprint; resumable; no embedded content left on disk."
                  : "Strip non-consensus fields before storage. Smallest footprint, no embedded content on disk.",
              },
              {
                key: "full_archive" as const,
                label: "Full Archive",
                action: undefined,
                desc: "Keep the full archive — complete, unstripped blocks. Maximum data availability for archival serving.",
              },
              {
                key: "standard" as const,
                label: "Standard",
                action: undefined,
                desc: "A normal Bitcoin Core node — full blocks, no stripping and no haze metadata.",
              },
            ];
            return options.map((opt) => {
              const selected = mode === opt.key;
              return (
                <button
                  key={opt.key}
                  type="button"
                  disabled={configureHaze.isPending || selected}
                  onClick={() => handleSetMode(opt.key)}
                  className="text-left rounded-lg p-4 border transition-colors disabled:cursor-default flex flex-col"
                  style={{
                    background: selected
                      ? "color-mix(in srgb, var(--accent) 12%, var(--surface))"
                      : "var(--surface)",
                    borderColor: selected ? "var(--accent)" : "var(--rule-strong)",
                  }}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[color:var(--fg)] text-sm font-medium">{opt.label}</span>
                    {selected && <Badge variant={getModeBadgeVariant(opt.key)}>Active</Badge>}
                  </div>
                  <p className="text-[color:var(--dim)] text-xs leading-relaxed flex-1">{opt.desc}</p>
                  {opt.action && !selected && (
                    <span className="mt-2 inline-block t-caption font-medium text-[color:var(--accent)]">
                      {opt.action} →
                    </span>
                  )}
                </button>
              );
            });
          })()}
        </div>
        <p className="text-[color:var(--fainter)] text-xs mt-3">
          Forward hazing and Full Archive take effect on the next node start. A retroactive
          conversion runs as a background batch job and reports its progress above.
        </p>
      </Card>

      <ConfirmDialog
        isOpen={confirmConvert}
        onClose={() => setConfirmConvert(false)}
        onConfirm={async () => {
          setConfirmConvert(false);
          await doSetMode("hazed");
        }}
        title="Convert existing blocks to Hazed?"
        message="This restarts ghostd to run the one-time Ghost Exorcist conversion of your existing block archive to stripped GSB format. It is a long, resumable batch job and is IRREVERSIBLE — witness, scriptSig, OP_RETURN and coinbase data are permanently stripped from local storage. The node comes back up hazed automatically once it finishes. Continue?"
        confirmLabel="Convert & restart ghostd"
        variant="danger"
        loading={configureHaze.isPending}
      />
    </div>
  );
}
