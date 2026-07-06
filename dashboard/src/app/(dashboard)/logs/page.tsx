"use client";

import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { useLogs } from "@/hooks/queries";
import type { LogEntry } from "@/types/api";

const LEVELS = ["all", "error", "warn", "info", "debug", "trace"] as const;
type Level = (typeof LEVELS)[number];

const LEVEL_COLOR: Record<LogEntry["level"], string> = {
  error: "#f85149",
  warn: "#d29922",
  info: "#58a6ff",
  debug: "var(--dim)",
  trace: "var(--fainter)",
};

// Ring-buffer timestamps are Unix seconds; guard for ms just in case.
function formatTs(ts: number): string {
  const ms = ts < 1e12 ? ts * 1000 : ts;
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return "--:--:--";
  return d.toLocaleTimeString(undefined, { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

export default function LogsPage() {
  const [level, setLevel] = useState<Level>("all");
  const [limit] = useState(500);
  const { data, isLoading, isError, error, refetch, isFetching } = useLogs({
    limit,
    level: level === "all" ? undefined : level,
  });

  const entries = data?.entries ?? [];

  const copyAll = () => {
    const text = entries
      .map((e) => `${formatTs(e.timestamp)} ${e.level.toUpperCase().padEnd(5)} ${e.target}  ${e.message}`)
      .join("\n");
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="system"
        title="Logs."
        subtitle="Recent ghost-pool logs from the node's in-memory ring buffer. This is ghost-pool's own output, not the full journald firehose of every binary."
        subtitleFullWidth
      />

      <SectionErrorBoundary section="Logs">
        <Card>
          {/* Controls */}
          <div className="flex items-center justify-between gap-3 flex-wrap" style={{ marginBottom: "12px" }}>
            <div className="flex items-center gap-2 flex-wrap">
              {LEVELS.map((lv) => (
                <button
                  key={lv}
                  onClick={() => setLevel(lv)}
                  style={{
                    padding: "4px 10px",
                    fontSize: "12px",
                    borderRadius: "4px",
                    border: `1px solid ${level === lv ? "var(--accent)" : "var(--rule)"}`,
                    background: level === lv ? "var(--accent-weak)" : "transparent",
                    color: level === lv ? "var(--fg)" : "var(--dim)",
                    cursor: "pointer",
                    textTransform: "uppercase",
                    letterSpacing: "0.04em",
                  }}
                >
                  {lv}
                </button>
              ))}
            </div>
            <div className="flex items-center gap-2">
              <span style={{ color: "var(--fainter)", fontSize: "12px" }}>
                {entries.length} line{entries.length === 1 ? "" : "s"}
              </span>
              <Button variant="ghost" size="sm" onClick={copyAll} disabled={!entries.length}>
                Copy
              </Button>
              <Button variant="primary" size="sm" onClick={() => refetch()} disabled={isFetching}>
                {isFetching ? "Refreshing…" : "Refresh"}
              </Button>
            </div>
          </div>

          {/* Log stream */}
          <div
            style={{
              maxHeight: "70vh",
              overflowY: "auto",
              overflowX: "auto",
              background: "var(--bg)",
              border: "1px solid var(--rule)",
              borderRadius: "4px",
              padding: "10px 12px",
              fontFamily: "var(--font-mono)",
              fontSize: "12px",
              lineHeight: "1.55",
            }}
          >
            {isLoading ? (
              <div style={{ color: "var(--dim)" }}>Loading logs…</div>
            ) : isError ? (
              <div style={{ color: "#f85149" }}>
                Couldn&apos;t load logs{error instanceof Error ? `: ${error.message}` : "."}
              </div>
            ) : entries.length === 0 ? (
              <div style={{ color: "var(--dim)" }}>No log entries in the buffer for this level.</div>
            ) : (
              entries.map((e, i) => (
                <div key={i} style={{ whiteSpace: "pre-wrap", wordBreak: "break-word", display: "flex", gap: "10px" }}>
                  <span style={{ color: "var(--fainter)", flexShrink: 0 }}>{formatTs(e.timestamp)}</span>
                  <span style={{ color: LEVEL_COLOR[e.level] ?? "var(--dim)", flexShrink: 0, width: "44px" }}>
                    {e.level.toUpperCase()}
                  </span>
                  <span style={{ color: "var(--fainter)", flexShrink: 0 }}>{e.target}</span>
                  <span style={{ color: "var(--fg)" }}>{e.message}</span>
                </div>
              ))
            )}
          </div>
        </Card>
      </SectionErrorBoundary>
    </div>
  );
}
