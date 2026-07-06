"use client";

import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { useLogs, useLogUnits } from "@/hooks/queries";
import type { LogEntry, LogUnit } from "@/types/api";

const LEVELS = ["all", "error", "warn", "info", "debug", "trace"] as const;
type Level = (typeof LEVELS)[number];

const DEFAULT_UNIT = "ghost-pool";

const LEVEL_COLOR: Record<LogEntry["level"], string> = {
  error: "#f85149",
  warn: "#d29922",
  info: "#58a6ff",
  debug: "var(--dim)",
  trace: "var(--fainter)",
};

// Fallback selector entry so the page renders before /logs/units resolves.
const FALLBACK_UNITS: LogUnit[] = [
  {
    key: DEFAULT_UNIT,
    label: "Ghost Pool",
    description: "Mining pool node (this process) — in-memory ring buffer",
    source: "ring-buffer",
    available: true,
  },
];

// Ring-buffer timestamps are Unix seconds; journald entries are Unix ms. Guard
// for both by treating anything below ~year-2001-in-ms as seconds.
function formatTs(ts: number): string {
  const ms = ts < 1e12 ? ts * 1000 : ts;
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return "--:--:--";
  return d.toLocaleTimeString(undefined, { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

export default function LogsPage() {
  const [level, setLevel] = useState<Level>("all");
  const [unit, setUnit] = useState<string>(DEFAULT_UNIT);
  const [limit] = useState(500);

  const { data: unitsData } = useLogUnits();
  const units = unitsData?.units?.length ? unitsData.units : FALLBACK_UNITS;

  const { data, isLoading, isError, error, refetch, isFetching } = useLogs({
    limit,
    level: level === "all" ? undefined : level,
    unit,
  });

  const entries = data?.entries ?? [];
  // Honest structured error surfaced by the backend (e.g. journald permission
  // denied) — returned with HTTP 200 so the selector stays usable.
  const structuredError = data?.error ?? null;

  const activeUnit = units.find((u) => u.key === unit);
  const subtitle = activeUnit
    ? `Recent logs for ${activeUnit.label}. ${activeUnit.description}.`
    : "Recent node logs. Select a binary to inspect its output.";

  const copyAll = () => {
    const text = entries
      .map((e) => `${formatTs(e.timestamp)} ${e.level.toUpperCase().padEnd(5)} ${e.target}  ${e.message}`)
      .join("\n");
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="system" title="Logs." subtitle={subtitle} subtitleFullWidth />

      <SectionErrorBoundary section="Logs">
        <Card>
          {/* Binary selector */}
          <div className="flex items-center gap-2 flex-wrap" style={{ marginBottom: "12px" }}>
            {units.map((u) => {
              const active = unit === u.key;
              const disabled = !u.available;
              return (
                <button
                  key={u.key}
                  onClick={() => !disabled && setUnit(u.key)}
                  disabled={disabled}
                  title={disabled ? `${u.label} is not present on this node` : u.description}
                  style={{
                    padding: "5px 12px",
                    fontSize: "12px",
                    borderRadius: "4px",
                    border: `1px solid ${active ? "var(--accent)" : "var(--rule)"}`,
                    background: active ? "var(--accent-weak)" : "transparent",
                    color: disabled ? "var(--fainter)" : active ? "var(--fg)" : "var(--dim)",
                    cursor: disabled ? "not-allowed" : "pointer",
                    opacity: disabled ? 0.5 : 1,
                    fontWeight: active ? 600 : 400,
                  }}
                >
                  {u.label}
                </button>
              );
            })}
          </div>

          {/* Level controls */}
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
            ) : structuredError ? (
              <div style={{ color: "#d29922" }}>{structuredError}</div>
            ) : entries.length === 0 ? (
              <div style={{ color: "var(--dim)" }}>No log entries for this binary at this level.</div>
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
