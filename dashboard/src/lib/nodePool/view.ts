// Pure helpers for the node pool pages: formatting, grouping and the health reading.
//
// The rule throughout: a value the node did not report is shown as unknown, never as zero or as
// healthy. `UNKNOWN` is the one word for it.

import type {
  NodePoolStatus,
  NpExpectedWait,
  NpMinerChannel,
  NpRates,
  NpSensing,
} from "@/lib/api/nodePool";

export const UNKNOWN = "unknown";

export function isNum(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v);
}

export function fmtInt(v: number | null | undefined): string {
  return isNum(v) ? v.toLocaleString("en-US") : UNKNOWN;
}

export function fmtSats(v: number | null | undefined): string {
  return isNum(v) ? `${v.toLocaleString("en-US")} sats` : UNKNOWN;
}

/** Units of 2^-32 sat per whole sat. */
const UNITS_PER_SAT = 4294967296;

/** An amount pool_sv2 reports as `{ units, sats }`, in whole sats rounded down, from `units`.
 *  `units` is the exact ledger value (a decimal string); `sats` is an i64 that saturates on a
 *  ledger that large, so it is used only when `units` is missing or not an integer. */
export function fmtAmountSats(a: { units?: string | null; sats?: number | null } | null | undefined): string {
  const units = a?.units;
  if (typeof units === "string" && /^-?\d+$/.test(units)) {
    const u = BigInt(units);
    const per = BigInt(UNITS_PER_SAT);
    let q = u / per; // truncates toward zero
    if (u < BigInt(0) && q * per !== u) q -= BigInt(1);
    return `${q.toLocaleString("en-US")} sats`;
  }
  return fmtSats(a?.sats);
}

export function fmtBtc(v: number | null | undefined): string {
  return isNum(v) ? `${(v / 1e8).toFixed(8)} BTC` : UNKNOWN;
}

/** First and last `n` characters of a hash. */
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

/** The best-known hashrate of a set of rates: the 1 h figure, else 15 min, else 24 h. */
export function bestRate(r: NpRates | null | undefined): number | null {
  if (!r) return null;
  for (const k of ["1h", "15m", "24h"] as const) if (isNum(r[k])) return r[k];
  return null;
}

/** The connected channels of each payee address, in first-seen order. */
export function groupByAddress(
  miners: NpMinerChannel[],
): { address: string; channels: NpMinerChannel[] }[] {
  const out = new Map<string, NpMinerChannel[]>();
  for (const m of miners) {
    const list = out.get(m.address);
    if (list) list.push(m);
    else out.set(m.address, [m]);
  }
  return [...out.entries()].map(([address, channels]) => ({ address, channels }));
}

/** Plain words for where a channel's sensing loop stands. */
export function sensingLabel(kind: string, sensing: NpSensing | null): string {
  if (kind === "standard") return "standard channel: header only, full class";
  if (!sensing) return "not sensed";
  const passed = isNum(sensing.highest_passed) ? `${sensing.highest_passed}` : "none yet";
  if (sensing.settled) return `settled (highest passed ${passed}, ceiling ${sensing.ceiling_class})`;
  return `testing (highest passed ${passed}, ceiling ${sensing.ceiling_class})`;
}

/** The expected wait, in plain words. */
export function waitLabel(w: NpExpectedWait | null | undefined): string {
  if (!w) return UNKNOWN;
  if (!w.known) return w.reason ? `${UNKNOWN}: ${w.reason}` : UNKNOWN;
  const parts: string[] = [];
  if (isNum(w.seconds)) parts.push(`about ${fmtDuration(w.seconds)}`);
  if (isNum(w.blocks_needed)) parts.push(`${w.blocks_needed} pool block${w.blocks_needed === 1 ? "" : "s"}`);
  return parts.length ? parts.join(", ") : UNKNOWN;
}

export type Level = "ok" | "warn" | "error" | "unknown";

export interface HealthCheck {
  label: string;
  level: Level;
  detail: string;
}

/** The node pool's health, from its status. Without a status every check is unknown and the
 *  verdict is an error: a node whose pool service does not answer is not healthy. */
export function nodePoolHealth(
  status: NodePoolStatus | undefined,
  error: unknown,
): { level: Level; checks: HealthCheck[] } {
  if (!status) {
    const why = error instanceof Error ? error.message : error ? String(error) : "no answer yet";
    return {
      level: error ? "error" : "unknown",
      checks: [{ label: "Node pool service", level: error ? "error" : "unknown", detail: why }],
    };
  }
  const checks: HealthCheck[] = [{ label: "Node pool service", level: "ok", detail: "answering" }];
  checks.push(
    status.peers > 0
      ? { label: "Relay peers", level: "ok", detail: `${status.peers} connected` }
      : {
          label: "Relay peers",
          level: "warn",
          detail: "none connected: this node sees only its own shares and anchors",
        },
  );
  const st = status.settlement;
  checks.push(
    st.caught_up
      ? {
          label: "Settlement",
          level: "ok",
          detail: `caught up to Bitcoin ${fmtInt(st.synced_height)}`,
        }
      : {
          label: "Settlement",
          level: "warn",
          detail: `behind: at ${fmtInt(st.synced_height)} of Bitcoin tip ${fmtInt(st.bitcoin_tip)}`,
        },
  );
  if (st.provisional.length > 0) {
    checks.push({
      label: "Provisional blocks",
      level: "warn",
      detail: `${st.provisional.length} retired from their coinbase, waiting for their anchor`,
    });
  }
  if (st.mismatched > 0) {
    checks.push({
      label: "Mismatched blocks",
      level: "error",
      detail: `${st.mismatched} pool block(s) did not pay their anchor's table since start`,
    });
  }
  // Work below the first earning height (genesis + 21) is void: say so as long as it lasts.
  if (status.earning?.earns === false) {
    checks.push({
      label: "Work earns nothing yet",
      level: "warn",
      detail:
        status.earning.notice ??
        `shares are credited from Bitcoin height ${fmtInt(status.earning.first_earning_height)}`,
    });
  }
  if (status.share_chain.unseen_anchors > 0) {
    checks.push({
      label: "Share-chain sync",
      level: "warn",
      detail: `${status.share_chain.unseen_anchors} anchor(s) held without their batch`,
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
