"use client";

import { useQuery } from "@tanstack/react-query";
import { Card, CardHeader } from "@/components/ui/Card";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { useConfig } from "@/hooks/queries/useConfigQueries";

interface ReaperStats {
  txs_evaluated: number;
  txs_reaped: number;
  txs_accepted: number;
  dead_bytes_total: number;
  last_reaped_unix: number | null;
  by_type: {
    inscription_envelope: number;
    drop_stuffing: number;
    unreachable_code: number;
    fake_pubkey: number;
    fake_pubkey_curve_point: number;
    annex_present: number;
    oversized_op_return: number;
    dust_flood: number;
    excess_witness_data: number;
    excess_stack_items: number;
    legacy_scriptsig_data: number;
  };
}

async function fetchReaperStats(): Promise<ReaperStats | null> {
  const res = await fetch("/api/v1/reaper/status", { credentials: "include" });
  if (!res.ok) return null;
  const data = await res.json();
  // Endpoint returns null when ghost-pool hasn't wired the callback yet.
  return data && typeof data === "object" && "txs_evaluated" in data ? data : null;
}

const DETECTION_VECTORS = [
  {
    key: "inscription_envelope" as const,
    name: "Inscription Envelopes",
    desc: "Detects OP_FALSE OP_IF ... OP_ENDIF witness patterns used by Ordinal inscriptions to embed arbitrary data.",
  },
  {
    key: "drop_stuffing" as const,
    name: "Drop Stuffing",
    desc: "Identifies unreachable OP_DROP sequences that push and immediately discard data, wasting block space.",
  },
  {
    key: "unreachable_code" as const,
    name: "Unreachable Code",
    desc: "Finds dead code paths in witness scripts that can never execute but bloat transaction size.",
  },
  {
    key: "fake_pubkey" as const,
    name: "Fake Pubkeys",
    desc: "Detects invalid or non-functional public keys used as data carriers in multisig outputs.",
  },
  {
    key: "oversized_op_return" as const,
    name: "Oversized OP_RETURN",
    desc: "Flags OP_RETURN outputs exceeding standard relay limits, used for embedding large data payloads.",
  },
  {
    key: "dust_flood" as const,
    name: "Dust-flood (UTXO spam)",
    desc: "Rejects 1-in/1-out transactions whose sole non-OP_RETURN output sits at or below the dust-flood threshold, the signature of UTXO-set flooding spam.",
  },
  {
    key: "annex_present" as const,
    name: "Annex Bloat",
    desc: "Identifies taproot annex fields carrying non-consensus data, exploiting the annex discount.",
  },
  {
    key: "excess_witness_data" as const,
    name: "Excess Witness Data",
    desc: "Catches witness items far exceeding what the script actually consumes during execution.",
  },
  {
    key: "legacy_scriptsig_data" as const,
    name: "Legacy ScriptSig Data",
    desc: "Detects data-carrying patterns in legacy scriptSig fields that serve no signing purpose.",
  },
];

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatPercent(numerator: number, denominator: number): string {
  if (denominator === 0) return "—";
  const pct = (numerator / denominator) * 100;
  return pct < 0.01 ? "<0.01%" : `${pct.toFixed(2)}%`;
}

function formatRelative(unixSecs: number | null): string {
  if (!unixSecs) return "never";
  const ago = Math.floor(Date.now() / 1000) - unixSecs;
  if (ago < 60) return `${ago}s ago`;
  if (ago < 3600) return `${Math.floor(ago / 60)}m ago`;
  if (ago < 86400) return `${Math.floor(ago / 3600)}h ago`;
  return `${Math.floor(ago / 86400)}d ago`;
}

export default function ReaperPage() {
  const { data: config } = useConfig();
  const { data: stats } = useQuery<ReaperStats | null>({
    queryKey: ["reaper-status"],
    queryFn: fetchReaperStats,
    refetchInterval: 10_000,
  });

  const enabled = config?.reaper ?? false;
  const reapRate = stats ? formatPercent(stats.txs_reaped, stats.txs_evaluated) : "—";

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="reaper"
        title="Dead-code policy."
        subtitle="Live counters from your node's template builder. Cumulative since last ghost-pool restart."
      />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard
          label="Mode"
          value={enabled ? "active" : "disabled"}
          sublabel={enabled ? "filtering on" : "configure in /settings/capabilities"}
        />
        <StatCard
          label="TXs evaluated"
          value={stats?.txs_evaluated.toLocaleString() ?? "—"}
          sublabel={stats ? `${stats.txs_accepted.toLocaleString()} accepted` : "no data"}
        />
        <StatCard
          label="TXs reaped"
          value={stats?.txs_reaped.toLocaleString() ?? "—"}
          sublabel={stats ? `${reapRate} of evaluated` : "no data"}
        />
        <StatCard
          label="Dead bytes saved"
          value={stats ? formatBytes(stats.dead_bytes_total) : "—"}
          sublabel={
            stats
              ? `last reap ${formatRelative(stats.last_reaped_unix)}`
              : "no data"
          }
        />
      </div>

      <Card collapsible defaultCollapsed>
        <CardHeader
          title="How It Works"
          subtitle="Dead code detection and mempool filtering"
        />
        <div className="space-y-4">
          <p style={{ color: "var(--dim)", fontSize: "14px", lineHeight: "1.6" }}>
            Ghost Reaper detects non-financial data embedded in transaction witnesses — inscriptions,
            drop stuffing, fake pubkeys, and other dead code patterns. When enabled, your node's template
            builder rejects transactions carrying dead weight before they enter your block, keeping your
            mining capacity focused on real monetary transactions.
          </p>
          <div
            style={{
              padding: "12px",
              background: "var(--accent-weak)",
              border: "1px solid var(--accent)",
              borderRadius: "4px",
            }}
          >
            <p style={{ color: "var(--fg)", fontSize: "14px" }}>
              Nodes running Reaper earn{" "}
              <strong style={{ color: "var(--accent)" }}>+2 capability shares</strong> in the node
              reward pool. Part of the 5-4-3-2-1 system: Archive (+5), Ghost Pay (+4), Public Mining (+3),
              <strong style={{ color: "var(--accent)" }}> Reaper (+2)</strong>, Elder (+1).
            </p>
          </div>
        </div>
      </Card>

      <SectionErrorBoundary section="Detection Vectors">
        <Card>
          <CardHeader
            title="Detection vectors"
            subtitle="Patterns Reaper identifies, with cumulative hit counts"
          />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {DETECTION_VECTORS.map((vector) => {
              const hits = stats?.by_type[vector.key] ?? 0;
              return (
                <div
                  key={vector.name}
                  style={{
                    padding: "14px",
                    border: "1px solid var(--rule)",
                    borderRadius: "4px",
                    background: "var(--bg)",
                  }}
                >
                  <div className="flex items-baseline justify-between mb-1">
                    <div style={{ color: "var(--fg)", fontSize: "14px", fontWeight: 500 }}>
                      {vector.name}
                    </div>
                    <div
                      style={{
                        fontFamily: "var(--font-mono)",
                        fontSize: "13px",
                        color: hits > 0 ? "var(--accent)" : "var(--fainter)",
                      }}
                    >
                      {hits.toLocaleString()}
                    </div>
                  </div>
                  <div style={{ color: "var(--dim)", fontSize: "13px", lineHeight: "1.5" }}>
                    {vector.desc}
                  </div>
                </div>
              );
            })}
          </div>
        </Card>
      </SectionErrorBoundary>

      <Card collapsible defaultCollapsed>
        <CardHeader
          title="Reaper vs mempool policy"
          subtitle="Understanding the distinction"
        />
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div
              style={{
                padding: "16px",
                background: "var(--accent-weak)",
                border: "1px solid var(--accent)",
                borderRadius: "4px",
              }}
            >
              <h4 style={{ color: "var(--accent)", fontWeight: 500, marginBottom: "8px" }}>Reaper</h4>
              <ul style={{ color: "var(--fg)", fontSize: "13px", lineHeight: "1.7", paddingLeft: "20px", listStyle: "disc" }}>
                <li>Specifically targets <strong>dead code</strong> in witness scripts</li>
                <li>Detects inscriptions, drop stuffing, fake pubkeys, annex bloat</li>
                <li>Works at the witness / script level, not transaction-level policy</li>
                <li>Can run alongside any mempool policy</li>
              </ul>
            </div>
            <div
              style={{
                padding: "16px",
                background: "var(--surface)",
                border: "1px solid var(--rule)",
                borderRadius: "4px",
              }}
            >
              <h4 style={{ color: "var(--dim)", fontWeight: 500, marginBottom: "8px" }}>Mempool policy</h4>
              <ul style={{ color: "var(--fg)", fontSize: "13px", lineHeight: "1.7", paddingLeft: "20px", listStyle: "disc" }}>
                <li>Controls accept/reject by <strong>fee rates, sizes, standardness</strong></li>
                <li>Configurable profiles: standard, strict, clean, custom</li>
                <li>Operates at transaction level (size, fee, output type)</li>
                <li>Independent of Reaper — they complement each other</li>
              </ul>
            </div>
          </div>
          <p style={{ color: "var(--dim)", fontSize: "13px" }}>
            <strong style={{ color: "var(--accent)" }}>Key point:</strong> Reaper is NOT a mempool policy.
            You can run Reaper alongside any mempool policy. Mempool policies filter by economic rules;
            Reaper filters by content analysis of witness scripts.
          </p>
        </div>
      </Card>
    </div>
  );
}
