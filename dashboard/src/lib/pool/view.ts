// Pure helpers for the Ghost Pool pages: formatting and the health reading.
//
// The rule throughout: a value the node did not report is shown as unknown, never as zero or as
// healthy. `UNKNOWN` is the one word for it.

import type { PoolFoundBlock, PoolRates, PoolStatus, PoolSubmitNode } from "@/lib/api/pool";

export const UNKNOWN = "unknown";

export function isNum(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v);
}

export function fmtInt(v: number | null | undefined): string {
  return isNum(v) ? Math.round(v).toLocaleString("en-US") : UNKNOWN;
}

export function fmtSats(v: number | null | undefined): string {
  return isNum(v) ? `${Math.round(v).toLocaleString("en-US")} sats` : UNKNOWN;
}

/** Exact BTC from sats, trailing zeros trimmed to at least one decimal place. */
export function fmtBtc(v: number | null | undefined): string {
  if (!isNum(v)) return UNKNOWN;
  const s = Math.abs(Math.round(v));
  const frac = String(s % 100_000_000).padStart(8, "0").replace(/0+$/, "");
  return `${v < 0 ? "-" : ""}${Math.floor(s / 100_000_000).toLocaleString("en-US")}.${frac || "0"} BTC`;
}

/** First and last `n` characters of a hash or address. */
export function shortHash(h: string | null | undefined, n = 8): string {
  if (!h) return UNKNOWN;
  return h.length <= n * 2 + 1 ? h : `${h.slice(0, n)}…${h.slice(-n)}`;
}

export function fmtDuration(seconds: number | null | undefined): string {
  if (!isNum(seconds) || seconds < 0) return UNKNOWN;
  const d = Math.floor(seconds / 86_400);
  if (d >= 730) return `${Math.round(seconds / (365.25 * 86_400)).toLocaleString("en-US")} years`;
  const h = Math.floor((seconds % 86_400) / 3_600);
  const m = Math.floor((seconds % 3_600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m`;
  return `${Math.floor(seconds)}s`;
}

/** How long ago `unix` was, against `now` (unix seconds). */
export function fmtAgo(unix: number | null | undefined, now: number): string {
  if (!isNum(unix) || unix <= 0) return UNKNOWN;
  const d = now - unix;
  if (d < 0) return "just now";
  return `${fmtDuration(d)} ago`;
}

export function fmtHashrate(hs: number | null | undefined): string {
  if (!isNum(hs)) return UNKNOWN;
  const units: [number, string][] = [
    [1e18, "EH/s"],
    [1e15, "PH/s"],
    [1e12, "TH/s"],
    [1e9, "GH/s"],
    [1e6, "MH/s"],
    [1e3, "KH/s"],
  ];
  for (const [f, u] of units) if (hs >= f) return `${(hs / f).toFixed(2)} ${u}`;
  return `${hs.toFixed(0)} H/s`;
}

/** A share or network difficulty in difficulty-1 units: 4.1e9 -> "4.10 G"; 0 -> "none yet". */
export function fmtDifficulty(d: number | null | undefined): string {
  if (!isNum(d)) return UNKNOWN;
  if (d === 0) return "none yet";
  const units: [number, string][] = [
    [1e18, " E"],
    [1e15, " P"],
    [1e12, " T"],
    [1e9, " G"],
    [1e6, " M"],
    [1e3, " k"],
  ];
  for (const [f, u] of units) if (d >= f) return `${(d / f).toFixed(2)}${u}`;
  return d.toFixed(0);
}

/** The best-known hashrate of a set of rates: the 1 h figure, else 15 min, else 24 h. */
export function bestRate(r: PoolRates | null | undefined): number | null {
  if (!r) return null;
  for (const k of ["1h", "15m", "24h"] as const) if (isNum(r[k])) return r[k];
  return null;
}

/** Mean seconds to a block: `difficulty * 2^32 / hashrate`; null without both. */
export function expectedSeconds(difficulty: number | null | undefined, hashrate: number | null | undefined): number | null {
  if (!isNum(difficulty) || difficulty <= 0 || !isNum(hashrate) || hashrate <= 0) return null;
  return (difficulty * 4_294_967_296) / hashrate;
}

/** The chance of at least one block within `secs`, at a mean wait of `mean`. */
export function chanceWithin(secs: number, mean: number | null): number | null {
  if (!isNum(mean) || mean <= 0) return null;
  return -Math.expm1(-secs / mean);
}

/** A probability in words: "about 1 in 5,500" below 1%, else a percentage. */
export function fmtChance(p: number | null | undefined): string {
  if (!isNum(p)) return UNKNOWN;
  if (p >= 0.995) return "over 99%";
  if (p >= 0.01) return `${(p * 100).toFixed(p >= 0.1 ? 0 : 1)}%`;
  if (p <= 0) return "none";
  const n = 1 / p;
  return `about 1 in ${(n < 1000 ? Math.round(n) : Number(n.toPrecision(2))).toLocaleString("en-US")}`;
}

/** Payout addresses this node's status names: every finder of a found block, newest first. */
export function addressesFromBlocks(blocks: PoolFoundBlock[] | null | undefined): string[] {
  const out: string[] = [];
  for (const b of [...(blocks ?? [])].reverse()) if (b.address && !out.includes(b.address)) out.push(b.address);
  return out;
}

/** The status's other nodes, each as a reachability record. An older pool_sv2 names them as bare
 *  strings: their reachability is then unknown (`reachable: null`). */
export function submitNodes(status: PoolStatus | null | undefined): PoolSubmitNode[] {
  return (status?.submit_nodes ?? []).map((n) =>
    typeof n === "string"
      ? { node: n, reachable: null, last_checked_at: null, last_ok_at: null, height: null, error: null }
      : n,
  );
}

/** One other node's reachability in a few words. */
export function reachabilityText(n: PoolSubmitNode, now: number): string {
  if (n.reachable === true) {
    return `reachable, height ${fmtInt(n.height)}${n.last_ok_at ? `, checked ${fmtAgo(n.last_ok_at, now)}` : ""}`;
  }
  if (n.reachable === false) {
    const last = n.last_ok_at ? `last answered ${fmtAgo(n.last_ok_at, now)}` : "never answered";
    return `NOT reachable: ${n.error ?? "no answer"} (${last})`;
  }
  return "not checked yet";
}

/** What the other nodes said to a found block, in a few words. */
export function submitSummary(b: PoolFoundBlock): string {
  if (!b.submitted.length) return "sent to this node only";
  return b.submitted.map((s) => `${s.node}: ${s.result}`).join(", ");
}

export type Level = "ok" | "warn" | "error" | "unknown";

export interface HealthCheck {
  label: string;
  level: Level;
  detail: string;
}

/** The pool's health, from its status. Without a status every check is unknown and the verdict
 *  is an error: a node whose pool service does not answer is not healthy. */
export function poolHealth(status: PoolStatus | undefined, error: unknown): { level: Level; checks: HealthCheck[] } {
  if (!status) {
    const why = error instanceof Error ? error.message : error ? String(error) : "no answer yet";
    return {
      level: error ? "error" : "unknown",
      checks: [{ label: "Pool service", level: error ? "error" : "unknown", detail: why }],
    };
  }
  const checks: HealthCheck[] = [{ label: "Pool service", level: "ok", detail: "answering" }];
  const bt = status.bitcoin;
  checks.push(
    isNum(bt.job_height)
      ? { label: "Templates", level: "ok", detail: `building jobs at height ${fmtInt(bt.job_height)}` }
      : { label: "Templates", level: "warn", detail: "no template yet: miners have no work" },
  );
  const nodes = submitNodes(status);
  checks.push(
    nodes.length > 0
      ? {
          label: "Backup submission",
          level: "ok",
          detail: `found blocks are also sent to ${nodes.map((n) => n.node).join(", ")}`,
        }
      : {
          label: "Backup submission",
          level: "warn",
          detail: "no other node configured: a found block goes to this node's Bitcoin node only",
        },
  );
  const down = nodes.filter((n) => n.reachable === false);
  if (down.length > 0) {
    checks.push({
      label: "Other node reachable",
      level: "warn",
      detail: `${down.map((n) => n.node).join(", ")} did not answer the last check: ${down[0].error ?? "no answer"}`,
    });
  }
  const bad = status.blocks_found.filter((b) => b.check !== null && b.check !== "ok");
  if (bad.length > 0) {
    checks.push({
      label: "Coinbase check",
      level: "error",
      detail: `${bad.length} found block(s) failed the post-submit coinbase check: ${bad[0].check}`,
    });
  }
  const refused = status.blocks_found.filter((b) =>
    b.submitted.some((s) => s.result !== "accepted" && s.result !== "duplicate" && s.result !== "inconclusive"),
  );
  if (refused.length > 0) {
    checks.push({
      label: "Other node",
      level: "warn",
      detail: `${refused.length} found block(s) were not accepted by another node (see Blocks found)`,
    });
  }
  const level: Level = checks.some((c) => c.level === "error")
    ? "error"
    : checks.some((c) => c.level === "warn")
      ? "warn"
      : "ok";
  return { level, checks };
}

export function errorText(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (error) return String(error);
  return "no answer";
}
